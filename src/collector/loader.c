// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
#define _GNU_SOURCE
#include <elf.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <inttypes.h>
#include <limits.h>
#include <math.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include "pqc_trace.h"
#include "pqc_trace.skel.h"

static volatile sig_atomic_t stop_tracing = 0;

struct collector_ctx {
	FILE *out_fp;
	const char *binary_path;
	const char *output_path;
	uint64_t seq;
	bool kex_only;
	bool quiet_stdout;
};

static void handle_signal(int sig)
{
	(void)sig;
	stop_tracing = 1;
}

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	if (level == LIBBPF_DEBUG)
		return 0;
	return vfprintf(stderr, format, args);
}

static const char *func_id_to_name(__u32 func_id)
{
	switch (func_id) {
	case FUNC_KEX_KEM_MLKEM768X25519_DEC:
		return "kex_kem_mlkem768x25519_dec";
	case FUNC_SSHBUF_NEW:
		return "sshbuf_new";
	case FUNC_SSHBUF_RESET:
		return "sshbuf_reset";
	case FUNC_SSHBUF_FREE:
		return "sshbuf_free";
	default:
		return "unknown";
	}
}

static const char *classify_zeroization_state(const struct pqc_event *ev, bool high_entropy_residue)
{
	if (!ev->zero_check_valid)
		return "UNCHECKED";
	if (ev->is_zeroed)
		return "ZEROED";
	if (high_entropy_residue)
		return "HIGH_ENTROPY_RESIDUE";
	return "PARTIAL_RESIDUE";
}

static void compute_entropy_stats(const struct pqc_event *ev,
				  uint32_t *unique_bytes_out,
				  double *shannon_bpb_out,
				  bool *high_entropy_out)
{
	uint32_t unique_bytes = 0;
	double entropy = 0.0;

	if (!ev->zero_check_valid || ev->frame_scanned_bytes == 0) {
		*unique_bytes_out = 0;
		*shannon_bpb_out = 0.0;
		*high_entropy_out = false;
		return;
	}

	double total = (double)ev->frame_scanned_bytes;
	for (size_t b = 0; b < 256; b++) {
		uint16_t count = ev->byte_freq[b];
		if (count == 0)
			continue;
		unique_bytes++;
		double p = (double)count / total;
		entropy -= p * log2(p);
	}

	*unique_bytes_out = unique_bytes;
	*shannon_bpb_out = entropy;
	*high_entropy_out = (ev->nonzero_bytes > 0) &&
			    (entropy >= 1.0 || ev->high_entropy_chunks > 0 || unique_bytes >= 64U);
}

static void sanitize_json_str(const char *src, char *dst, size_t dst_sz)
{
	size_t j = 0;

	if (dst_sz == 0)
		return;

	for (size_t i = 0; src[i] != '\0' && j + 1 < dst_sz; i++) {
		unsigned char c = (unsigned char)src[i];

		if (c == '"' || c == '\\') {
			if (j + 2 >= dst_sz)
				break;
			dst[j++] = '\\';
			dst[j++] = (char)c;
		} else if (c >= 0x20 && c < 0x7f) {
			dst[j++] = (char)c;
		}
	}
	dst[j] = '\0';
}

/*
 * Reads .note.gnu.build-id from an ELF64 binary and formats the path
 * /usr/lib/debug/.build-id/<xx>/<yyyy...>.debug used by Debian dbgsym packages.
 */
static int find_debuginfo_by_build_id(int fd, const Elf64_Ehdr *ehdr,
				      char *debug_path, size_t debug_path_sz)
{
	for (uint16_t i = 0; i < ehdr->e_phnum; i++) {
		Elf64_Phdr phdr;
		off_t ph_off = (off_t)(ehdr->e_phoff + (size_t)i * sizeof(phdr));

		if (pread(fd, &phdr, sizeof(phdr), ph_off) != (ssize_t)sizeof(phdr))
			continue;
		if (phdr.p_type != PT_NOTE || phdr.p_filesz == 0 || phdr.p_filesz > 4096)
			continue;

		uint8_t note_buf[4096];
		if (pread(fd, note_buf, phdr.p_filesz, (off_t)phdr.p_offset) != (ssize_t)phdr.p_filesz)
			continue;

		size_t off = 0;
		while (off + sizeof(Elf64_Nhdr) <= phdr.p_filesz) {
			const Elf64_Nhdr *nhdr = (const Elf64_Nhdr *)(note_buf + off);
			size_t namesz_aligned = (nhdr->n_namesz + 3U) & ~3U;
			size_t descsz_aligned = (nhdr->n_descsz + 3U) & ~3U;
			const char *name = (const char *)(note_buf + off + sizeof(*nhdr));
			const uint8_t *desc = note_buf + off + sizeof(*nhdr) + namesz_aligned;

			if (off + sizeof(*nhdr) + namesz_aligned + descsz_aligned > phdr.p_filesz)
				break;

			if (nhdr->n_type == NT_GNU_BUILD_ID &&
			    nhdr->n_namesz == 4 && memcmp(name, "GNU", 4) == 0 &&
			    nhdr->n_descsz >= 2 && nhdr->n_descsz <= 64) {
				int n = snprintf(debug_path, debug_path_sz,
						 "/usr/lib/debug/.build-id/%02x/", desc[0]);
				if (n < 0 || (size_t)n >= debug_path_sz)
					return -1;
				size_t pos = (size_t)n;
				for (uint32_t b = 1; b < nhdr->n_descsz; b++) {
					if (pos + 3 >= debug_path_sz)
						return -1;
					snprintf(debug_path + pos, debug_path_sz - pos, "%02x", desc[b]);
					pos += 2;
				}
				if (pos + 7 >= debug_path_sz)
					return -1;
				snprintf(debug_path + pos, debug_path_sz - pos, ".debug");
				return 0;
			}
			off += sizeof(*nhdr) + namesz_aligned + descsz_aligned;
		}
	}
	return -1;
}

/*
 * Searches SHT_SYMTAB / SHT_DYNSYM in an ELF64 file for sym_name and returns st_value.
 */
static int find_symbol_vaddr_in_elf(const char *elf_path, const char *sym_name, uint64_t *vaddr_out)
{
	int fd = open(elf_path, O_RDONLY);
	if (fd < 0)
		return -1;

	Elf64_Ehdr ehdr;
	if (pread(fd, &ehdr, sizeof(ehdr), 0) != (ssize_t)sizeof(ehdr) ||
	    memcmp(ehdr.e_ident, ELFMAG, SELFMAG) != 0 ||
	    ehdr.e_ident[EI_CLASS] != ELFCLASS64) {
		close(fd);
		return -1;
	}

	int found = -1;
	for (uint16_t i = 0; i < ehdr.e_shnum && found != 0; i++) {
		Elf64_Shdr shdr;
		off_t sh_off = (off_t)(ehdr.e_shoff + (size_t)i * sizeof(shdr));

		if (pread(fd, &shdr, sizeof(shdr), sh_off) != (ssize_t)sizeof(shdr))
			continue;
		if ((shdr.sh_type != SHT_SYMTAB && shdr.sh_type != SHT_DYNSYM) ||
		    shdr.sh_entsize != sizeof(Elf64_Sym) || shdr.sh_link >= ehdr.e_shnum)
			continue;

		Elf64_Shdr str_shdr;
		off_t str_sh_off = (off_t)(ehdr.e_shoff + (size_t)shdr.sh_link * sizeof(str_shdr));
		if (pread(fd, &str_shdr, sizeof(str_shdr), str_sh_off) != (ssize_t)sizeof(str_shdr) ||
		    str_shdr.sh_size == 0 || str_shdr.sh_size > (64U * 1024U * 1024U))
			continue;

		char *strtab = malloc(str_shdr.sh_size);
		if (!strtab)
			continue;
		if (pread(fd, strtab, str_shdr.sh_size, (off_t)str_shdr.sh_offset) != (ssize_t)str_shdr.sh_size) {
			free(strtab);
			continue;
		}

		size_t num_syms = shdr.sh_size / sizeof(Elf64_Sym);
		for (size_t s = 0; s < num_syms; s++) {
			Elf64_Sym sym;
			off_t sym_off = (off_t)(shdr.sh_offset + s * sizeof(sym));
			if (pread(fd, &sym, sizeof(sym), sym_off) != (ssize_t)sizeof(sym))
				break;
			if (sym.st_name >= str_shdr.sh_size || sym.st_value == 0)
				continue;
			if (strcmp(strtab + sym.st_name, sym_name) == 0) {
				*vaddr_out = sym.st_value;
				found = 0;
				break;
			}
		}
		free(strtab);
	}

	close(fd);
	return found;
}

/*
 * Resolves a symbol in binary_path (supporting stripped Debian binaries with
 * separate openssh-server-dbgsym debuginfo or static disassembly vaddr fallback)
 * to a file offset suitable for uprobe attachment.
 */
static int resolve_uprobe_offset(const char *binary_path, const char *sym_name,
				 uint64_t fallback_vaddr, size_t *offset_out)
{
	int fd = open(binary_path, O_RDONLY);
	if (fd < 0)
		return -errno;

	Elf64_Ehdr ehdr;
	if (pread(fd, &ehdr, sizeof(ehdr), 0) != (ssize_t)sizeof(ehdr) ||
	    memcmp(ehdr.e_ident, ELFMAG, SELFMAG) != 0 ||
	    ehdr.e_ident[EI_CLASS] != ELFCLASS64) {
		close(fd);
		return -EINVAL;
	}

	uint64_t vaddr = 0;
	if (find_symbol_vaddr_in_elf(binary_path, sym_name, &vaddr) != 0) {
		char debug_path[PATH_MAX];
		if (find_debuginfo_by_build_id(fd, &ehdr, debug_path, sizeof(debug_path)) == 0)
			find_symbol_vaddr_in_elf(debug_path, sym_name, &vaddr);
	}
	if (vaddr == 0)
		vaddr = fallback_vaddr;

	for (uint16_t i = 0; i < ehdr.e_phnum; i++) {
		Elf64_Phdr phdr;
		off_t ph_off = (off_t)(ehdr.e_phoff + (size_t)i * sizeof(phdr));

		if (pread(fd, &phdr, sizeof(phdr), ph_off) != (ssize_t)sizeof(phdr))
			continue;
		if (phdr.p_type != PT_LOAD || !(phdr.p_flags & PF_X))
			continue;
		if (vaddr >= phdr.p_vaddr && vaddr < phdr.p_vaddr + phdr.p_memsz) {
			*offset_out = (size_t)(vaddr - phdr.p_vaddr + phdr.p_offset);
			close(fd);
			return 0;
		}
	}

	close(fd);
	*offset_out = (size_t)vaddr;
	return 0;
}

static struct bpf_link *attach_probe_with_fallback(struct bpf_program *prog,
						   const char *binary_path,
						   const char *sym_name,
						   uint64_t fallback_vaddr,
						   bool is_retprobe)
{
	LIBBPF_OPTS(bpf_uprobe_opts, opts,
		.func_name = sym_name,
		.retprobe  = is_retprobe,
	);
	struct bpf_link *link;

	link = bpf_program__attach_uprobe_opts(prog, -1, binary_path, 0, &opts);
	if (!libbpf_get_error(link))
		return link;

	size_t file_offset = 0;
	int err = resolve_uprobe_offset(binary_path, sym_name, fallback_vaddr, &file_offset);
	if (err != 0) {
		errno = -err;
		return NULL;
	}

	opts.func_name = NULL;
	opts.retprobe  = is_retprobe;
	link = bpf_program__attach_uprobe_opts(prog, -1, binary_path, file_offset, &opts);
	if (libbpf_get_error(link))
		return NULL;

	return link;
}

static int ensure_parent_dir(const char *filepath)
{
	char tmp[PATH_MAX];
	size_t len = strlen(filepath);

	if (len == 0 || len >= sizeof(tmp))
		return -EINVAL;

	memcpy(tmp, filepath, len + 1);
	char *slash = strrchr(tmp, '/');
	if (!slash || slash == tmp)
		return 0;

	*slash = '\0';
	for (char *p = tmp + 1; *p; p++) {
		if (*p == '/') {
			*p = '\0';
			if (mkdir(tmp, 0755) != 0 && errno != EEXIST)
				return -errno;
			*p = '/';
		}
	}
	if (mkdir(tmp, 0755) != 0 && errno != EEXIST)
		return -errno;

	return 0;
}

static int handle_event(void *ctx, void *data, size_t data_sz)
{
	struct collector_ctx *cctx = (struct collector_ctx *)ctx;
	const struct pqc_event *ev = (const struct pqc_event *)data;
	char safe_comm[TASK_COMM_LEN * 2 + 1];
	char json_line[1536];

	if (data_sz < sizeof(*ev))
		return 0;

	if (cctx->kex_only && !ev->in_kex_dec)
		return 0;

	cctx->seq++;
	sanitize_json_str(ev->comm, safe_comm, sizeof(safe_comm));

	int64_t sp_delta = (int64_t)(ev->sp_exit - ev->sp_entry);
	uint32_t zero_bytes = (ev->frame_scanned_bytes >= ev->nonzero_bytes) ?
			      (ev->frame_scanned_bytes - ev->nonzero_bytes) : 0;
	double nonzero_pct = (ev->frame_scanned_bytes > 0) ?
			     (100.0 * (double)ev->nonzero_bytes / (double)ev->frame_scanned_bytes) : 0.0;
	uint32_t unique_bytes = 0;
	double shannon_bpb = 0.0;
	bool high_entropy_residue = false;

	compute_entropy_stats(ev, &unique_bytes, &shannon_bpb, &high_entropy_residue);

	int n = snprintf(json_line, sizeof(json_line),
		"{\"seq\":%" PRIu64 ","
		"\"binary\":\"%s\","
		"\"func\":\"%s\","
		"\"pid\":%u,"
		"\"tid\":%u,"
		"\"comm\":\"%s\","
		"\"entry_ts_ns\":%" PRIu64 ","
		"\"exit_ts_ns\":%" PRIu64 ","
		"\"delta_ns\":%" PRIu64 ","
		"\"sp_entry\":\"0x%" PRIx64 "\","
		"\"sp_exit\":\"0x%" PRIx64 "\","
		"\"sp_delta_bytes\":%" PRId64 ","
		"\"stack_frame_base\":\"0x%" PRIx64 "\","
		"\"stack_frame_size_bytes\":%" PRIu64 ","
		"\"stack_frame_size_hex\":\"0x%" PRIx64 "\","
		"\"sshbuf_ptr\":\"0x%" PRIx64 "\","
		"\"heap_lifetime_ns\":%" PRIu64 ","
		"\"ret_code\":%" PRId64 ","
		"\"in_kex_dec\":%s,"
		"\"zeroization\":{"
		"\"checked\":%s,"
		"\"state\":\"%s\","
		"\"is_zeroed\":%s,"
		"\"scratch_buffers_zeroed\":%s,"
		"\"high_entropy_residue\":%s,"
		"\"was_reset\":%s,"
		"\"scanned_bytes\":%u,"
		"\"nonzero_bytes\":%u,"
		"\"zero_bytes\":%u,"
		"\"nonzero_pct\":%.2f,"
		"\"nonzero_qwords\":%u,"
		"\"set_bits\":%u,"
		"\"unique_byte_values\":%u,"
		"\"high_entropy_chunks_256b\":%u,"
		"\"shannon_entropy_bits_per_byte\":%.3f,"
		"\"first_dirty_offset\":\"0x%x\","
		"\"last_dirty_offset\":\"0x%x\""
		"},"
		"\"key_material_redacted\":true}",
		cctx->seq,
		cctx->binary_path,
		func_id_to_name(ev->func_id),
		ev->pid,
		ev->tid,
		safe_comm,
		(uint64_t)ev->entry_ts_ns,
		(uint64_t)ev->exit_ts_ns,
		(uint64_t)ev->delta_ns,
		(uint64_t)ev->sp_entry,
		(uint64_t)ev->sp_exit,
		sp_delta,
		(uint64_t)ev->stack_frame_base,
		(uint64_t)ev->stack_frame_size,
		(uint64_t)ev->stack_frame_size,
		(uint64_t)ev->sshbuf_ptr,
		(uint64_t)ev->heap_lifetime_ns,
		(int64_t)ev->ret_code,
		ev->in_kex_dec ? "true" : "false",
		ev->zero_check_valid ? "true" : "false",
		classify_zeroization_state(ev, high_entropy_residue),
		ev->is_zeroed ? "true" : "false",
		ev->scratch_zeroed ? "true" : "false",
		high_entropy_residue ? "true" : "false",
		ev->was_reset ? "true" : "false",
		ev->frame_scanned_bytes,
		ev->nonzero_bytes,
		zero_bytes,
		nonzero_pct,
		ev->nonzero_qwords,
		ev->set_bits,
		unique_bytes,
		ev->high_entropy_chunks,
		shannon_bpb,
		ev->first_dirty_offset,
		ev->last_dirty_offset);

	if (n < 0 || (size_t)n >= sizeof(json_line))
		return 0;

	if (cctx->out_fp) {
		fprintf(cctx->out_fp, "%s\n", json_line);
		fflush(cctx->out_fp);
	}
	if (!cctx->quiet_stdout) {
		fprintf(stdout, "%s\n", json_line);
		fflush(stdout);
	}

	return 0;
}

static const char *resolve_default_output_path(void)
{
	struct stat st;

	if (stat("results", &st) == 0 && S_ISDIR(st.st_mode))
		return "results/pqc_telemetry.json";
	if (stat("../results", &st) == 0 && S_ISDIR(st.st_mode))
		return "../results/pqc_telemetry.json";
	return DEFAULT_OUTPUT_PATH;
}

static void print_usage(const char *prog)
{
	fprintf(stderr,
		"Usage: %s [-b binary_path] [-o json_output] [-k] [-q] [-h]\n"
		"  -b <path>  Target binary (default: %s)\n"
		"  -o <path>  Output JSON telemetry path (default: %s)\n"
		"  -k         Record only events inside active kex_kem_mlkem768x25519_dec\n"
		"  -q         Quiet mode (write only to JSON file, suppress stdout)\n"
		"  -h         Display this help message\n",
		prog, DEFAULT_BINARY_PATH, DEFAULT_OUTPUT_PATH);
}

int main(int argc, char **argv)
{
	struct collector_ctx cctx = {
		.out_fp       = NULL,
		.binary_path  = DEFAULT_BINARY_PATH,
		.output_path  = resolve_default_output_path(),
		.seq          = 0,
		.kex_only     = false,
		.quiet_stdout = false,
	};
	struct pqc_trace_bpf *skel = NULL;
	struct bpf_link *enc_uprobe_link = NULL;
	struct bpf_link *enc_uretprobe_link = NULL;
	struct ring_buffer *rb = NULL;
	int err = 0;
	int opt;

	while ((opt = getopt(argc, argv, "b:o:kqh")) != -1) {
		switch (opt) {
		case 'b':
			cctx.binary_path = optarg;
			break;
		case 'o':
			cctx.output_path = optarg;
			break;
		case 'k':
			cctx.kex_only = true;
			break;
		case 'q':
			cctx.quiet_stdout = true;
			break;
		case 'h':
			print_usage(argv[0]);
			return 0;
		default:
			print_usage(argv[0]);
			return 1;
		}
	}

	if (access(cctx.binary_path, R_OK) != 0) {
		fprintf(stderr, "Error: cannot access target binary '%s': %s\n",
			cctx.binary_path, strerror(errno));
		return 1;
	}

	err = ensure_parent_dir(cctx.output_path);
	if (err != 0) {
		fprintf(stderr, "Error: failed to create directory for '%s': %s\n",
			cctx.output_path, strerror(-err));
		return 1;
	}

	cctx.out_fp = fopen(cctx.output_path, "a");
	if (!cctx.out_fp) {
		fprintf(stderr, "Error: failed to open output JSON file '%s': %s\n",
			cctx.output_path, strerror(errno));
		return 1;
	}

	libbpf_set_print(libbpf_print_fn);

	signal(SIGINT, handle_signal);
	signal(SIGTERM, handle_signal);

	skel = pqc_trace_bpf__open_and_load();
	if (!skel) {
		fprintf(stderr, "Error: failed to open and load BPF skeleton\n");
		err = 1;
		goto cleanup;
	}

	struct {
		struct bpf_program *prog;
		struct bpf_link **link_slot;
		const char *sym_name;
		uint64_t fallback_vaddr;
		bool is_retprobe;
	} probes[] = {
		{
			skel->progs.uprobe_kex_kem_mlkem768x25519_dec,
			&skel->links.uprobe_kex_kem_mlkem768x25519_dec,
			"kex_kem_mlkem768x25519_dec",
			MLKEM768_DEC_VADDR,
			false,
		},
		{
			skel->progs.uretprobe_kex_kem_mlkem768x25519_dec,
			&skel->links.uretprobe_kex_kem_mlkem768x25519_dec,
			"kex_kem_mlkem768x25519_dec",
			MLKEM768_DEC_VADDR,
			true,
		},
		{
			skel->progs.uprobe_kex_kem_mlkem768x25519_dec,
			&enc_uprobe_link,
			"kex_kem_mlkem768x25519_enc",
			MLKEM768_ENC_VADDR,
			false,
		},
		{
			skel->progs.uretprobe_kex_kem_mlkem768x25519_dec,
			&enc_uretprobe_link,
			"kex_kem_mlkem768x25519_enc",
			MLKEM768_ENC_VADDR,
			true,
		},
		{
			skel->progs.uprobe_sshbuf_new,
			&skel->links.uprobe_sshbuf_new,
			"sshbuf_new",
			SSHBUF_NEW_VADDR,
			false,
		},
		{
			skel->progs.uretprobe_sshbuf_new,
			&skel->links.uretprobe_sshbuf_new,
			"sshbuf_new",
			SSHBUF_NEW_VADDR,
			true,
		},
		{
			skel->progs.uprobe_sshbuf_reset,
			&skel->links.uprobe_sshbuf_reset,
			"sshbuf_reset",
			SSHBUF_RESET_VADDR,
			false,
		},
		{
			skel->progs.uretprobe_sshbuf_reset,
			&skel->links.uretprobe_sshbuf_reset,
			"sshbuf_reset",
			SSHBUF_RESET_VADDR,
			true,
		},
		{
			skel->progs.uprobe_sshbuf_free,
			&skel->links.uprobe_sshbuf_free,
			"sshbuf_free",
			SSHBUF_FREE_VADDR,
			false,
		},
		{
			skel->progs.uretprobe_sshbuf_free,
			&skel->links.uretprobe_sshbuf_free,
			"sshbuf_free",
			SSHBUF_FREE_VADDR,
			true,
		},
	};

	for (size_t i = 0; i < sizeof(probes) / sizeof(probes[0]); i++) {
		*probes[i].link_slot = attach_probe_with_fallback(
			probes[i].prog,
			cctx.binary_path,
			probes[i].sym_name,
			probes[i].fallback_vaddr,
			probes[i].is_retprobe);

		if (!*probes[i].link_slot) {
			fprintf(stderr, "Error: failed to attach %s on %s:%s: %s\n",
				probes[i].is_retprobe ? "uretprobe" : "uprobe",
				cctx.binary_path,
				probes[i].sym_name,
				strerror(errno));
			err = 1;
			goto cleanup;
		}
	}

	rb = ring_buffer__new(bpf_map__fd(skel->maps.events), handle_event, &cctx, NULL);
	if (!rb) {
		fprintf(stderr, "Error: failed to initialize BPF ring buffer\n");
		err = 1;
		goto cleanup;
	}

	fprintf(stderr,
		"[pqc_trace] Attached uprobes/uretprobes to %s\n"
		"[pqc_trace] Logging redacted JSON telemetry to %s (Ctrl+C to stop)\n",
		cctx.binary_path, cctx.output_path);

	while (!stop_tracing) {
		err = ring_buffer__poll(rb, 100);
		if (err == -EINTR) {
			err = 0;
			break;
		}
		if (err < 0) {
			fprintf(stderr, "Error polling ring buffer: %d\n", err);
			break;
		}
	}

	fprintf(stderr, "[pqc_trace] Detaching probes. Total events logged: %" PRIu64 "\n",
		cctx.seq);

cleanup:
	ring_buffer__free(rb);
	bpf_link__destroy(enc_uprobe_link);
	bpf_link__destroy(enc_uretprobe_link);
	pqc_trace_bpf__destroy(skel);
	if (cctx.out_fp)
		fclose(cctx.out_fp);
	return err < 0 ? 1 : err;
}
