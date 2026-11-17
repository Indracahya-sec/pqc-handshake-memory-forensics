// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "pqc_trace.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct stack_audit_scratch {
	__u64 chunk_words[MLKEM768_SCAN_CHUNK_QWORDS];
	__u64 scratch_a[4];
	__u64 scratch_b[8];
	__u64 tail_word;
	__u16 byte_freq[256];
};

struct scan_loop_ctx {
	__u64 frame_base;
	struct stack_audit_scratch *scratch;
	__u32 nonzero_qwords;
	__u32 total_set_bits;
	__u32 high_entropy_chunks;
	__u32 first_dirty;
	__u32 last_dirty;
	__u32 chunks_read;
	__u8  found_dirty;
};

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} events SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 4096);
	__type(key, struct call_key);
	__type(value, struct call_entry);
} inflight_calls SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 4096);
	__type(key, __u64);
	__type(value, struct sshbuf_alloc_meta);
} active_sshbufs SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct stack_audit_scratch);
} stack_audit_scratch_map SEC(".maps");

static __always_inline __u32 swar_popcount64(__u64 x)
{
	x = x - ((x >> 1) & 0x5555555555555555ULL);
	x = (x & 0x3333333333333333ULL) + ((x >> 2) & 0x3333333333333333ULL);
	x = (x + (x >> 4)) & 0x0f0f0f0f0f0f0f0fULL;
	return (__u32)((x * 0x0101010101010101ULL) >> 56);
}

static __always_inline __u8 is_kex_dec_inflight(__u64 pid_tgid)
{
	struct call_key kex_key = {
		.pid_tgid = pid_tgid,
		.func_id  = FUNC_KEX_KEM_MLKEM768X25519_DEC,
		.pad      = 0,
	};

	return bpf_map_lookup_elem(&inflight_calls, &kex_key) != NULL ? 1 : 0;
}

static __always_inline int save_call_entry(struct pt_regs *ctx, __u32 func_id,
					   __u64 arg0, __u64 arg1, __u64 arg2)
{
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	struct call_key key = {
		.pid_tgid = pid_tgid,
		.func_id  = func_id,
		.pad      = 0,
	};
	struct call_entry entry = {};

	entry.entry_ts_ns = bpf_ktime_get_ns();
	entry.sp_entry    = PT_REGS_SP(ctx);
	entry.arg0        = arg0;
	entry.arg1        = arg1;
	entry.arg2        = arg2;

	if (func_id == FUNC_KEX_KEM_MLKEM768X25519_DEC)
		entry.in_kex_dec = 1;
	else
		entry.in_kex_dec = is_kex_dec_inflight(pid_tgid);

	bpf_map_update_elem(&inflight_calls, &key, &entry, BPF_ANY);
	return 0;
}

/*
 * Callback invoked via bpf_loop() for each of the 61 256-byte chunks in the
 * 0x3d08-byte stack frame. Using bpf_loop() allows the kernel BPF verifier to
 * verify the chunk body once in O(1) states rather than unrolling 61 * 32 words.
 */
static long scan_stack_chunk_cb(__u32 chunk_idx, void *data)
{
	struct scan_loop_ctx *ctx = (struct scan_loop_ctx *)data;
	struct stack_audit_scratch *scratch = ctx->scratch;
	__u64 chunk_addr;
	__u32 chunk_bits = 0;
	__u16 zero_before;
	__u32 chunk_zero_bytes;
	__u32 chunk_nz_bytes;
	long err;

	if (!scratch || chunk_idx >= MLKEM768_SCAN_FULL_CHUNKS)
		return 1;

	chunk_addr = ctx->frame_base + ((__u64)chunk_idx * MLKEM768_SCAN_CHUNK_BYTES);
	err = bpf_probe_read_user(scratch->chunk_words,
				  sizeof(scratch->chunk_words),
				  (const void *)chunk_addr);
	if (err != 0) {
		scratch->byte_freq[0] += (__u16)MLKEM768_SCAN_CHUNK_BYTES;
		return 0;
	}

	ctx->chunks_read++;
	zero_before = scratch->byte_freq[0];

	for (__u32 w = 0; w < MLKEM768_SCAN_CHUNK_QWORDS; w++) {
		__u64 val = scratch->chunk_words[w];
		__u32 word_off = chunk_idx * (__u32)MLKEM768_SCAN_CHUNK_BYTES + w * 8U;

		scratch->chunk_words[w] = 0;

		if (val == 0) {
			scratch->byte_freq[0] += 8;
			continue;
		}

		ctx->nonzero_qwords++;
		if (!ctx->found_dirty) {
			ctx->first_dirty = word_off;
			ctx->found_dirty = 1;
		}
		ctx->last_dirty = word_off + 7U;

		__u32 bits = swar_popcount64(val);
		chunk_bits += bits;
		ctx->total_set_bits += bits;

		scratch->byte_freq[(val >> 0)  & 0xffU]++;
		scratch->byte_freq[(val >> 8)  & 0xffU]++;
		scratch->byte_freq[(val >> 16) & 0xffU]++;
		scratch->byte_freq[(val >> 24) & 0xffU]++;
		scratch->byte_freq[(val >> 32) & 0xffU]++;
		scratch->byte_freq[(val >> 40) & 0xffU]++;
		scratch->byte_freq[(val >> 48) & 0xffU]++;
		scratch->byte_freq[(val >> 56) & 0xffU]++;
	}

	chunk_zero_bytes = (__u32)(scratch->byte_freq[0] - zero_before);
	chunk_nz_bytes = (chunk_zero_bytes <= 256U) ? (256U - chunk_zero_bytes) : 0U;

	if (chunk_nz_bytes >= 64U &&
	    chunk_bits >= (chunk_nz_bytes * 3U) &&
	    chunk_bits <= (chunk_nz_bytes * 5U)) {
		ctx->high_entropy_chunks++;
	}

	return 0;
}

static __always_inline void audit_full_stack_frame(__u64 sp_entry, struct pqc_event *ev)
{
	__u32 zero_idx = 0;
	struct stack_audit_scratch *scratch;
	__u64 frame_base;
	__u64 scratch_residual = 0;
	long err;

	if (!ev || sp_entry <= MLKEM768_FRAME_TOTAL_OFFSET)
		return;

	scratch = bpf_map_lookup_elem(&stack_audit_scratch_map, &zero_idx);
	if (!scratch)
		return;

	frame_base = sp_entry - MLKEM768_FRAME_TOTAL_OFFSET;

	__u64 *freq_u64 = (__u64 *)scratch->byte_freq;
	for (__u32 i = 0; i < 64; i++)
		freq_u64[i] = 0;

	/* 1. Check explicit_bzero scratch regions for dec (0x3270/0x3370) or enc (0x2d90/0x2e70) */
	err = bpf_probe_read_user(scratch->scratch_a, sizeof(scratch->scratch_a),
				  (const void *)(frame_base + MLKEM768_SCRATCH_OFFSET_A));
	if (err == 0) {
		err = bpf_probe_read_user(scratch->scratch_b, sizeof(scratch->scratch_b),
					  (const void *)(frame_base + MLKEM768_SCRATCH_OFFSET_B));
	}
	if (err == 0) {
		scratch_residual = (scratch->scratch_a[0] | scratch->scratch_a[1] |
				    scratch->scratch_a[2] | scratch->scratch_a[3]) |
				   (scratch->scratch_b[0] | scratch->scratch_b[1] |
				    scratch->scratch_b[2] | scratch->scratch_b[3]) |
				   (scratch->scratch_b[4] | scratch->scratch_b[5] |
				    scratch->scratch_b[6] | scratch->scratch_b[7]);
		if (scratch_residual == 0)
			ev->scratch_zeroed = 1;
	}
	if (!ev->scratch_zeroed) {
		err = bpf_probe_read_user(scratch->scratch_a, sizeof(scratch->scratch_a),
					  (const void *)(frame_base + 0x2d90ULL));
		if (err == 0) {
			err = bpf_probe_read_user(scratch->scratch_b, sizeof(scratch->scratch_b),
						  (const void *)(frame_base + 0x2e70ULL));
		}
		if (err == 0) {
			scratch_residual = (scratch->scratch_a[0] | scratch->scratch_a[1] |
					    scratch->scratch_a[2] | scratch->scratch_a[3]) |
					   (scratch->scratch_b[0] | scratch->scratch_b[1] |
					    scratch->scratch_b[2] | scratch->scratch_b[3]) |
					   (scratch->scratch_b[4] | scratch->scratch_b[5] |
					    scratch->scratch_b[6] | scratch->scratch_b[7]);
			if (scratch_residual == 0)
				ev->scratch_zeroed = 1;
		}
	}
	scratch->scratch_a[0] = 0;
	scratch->scratch_a[1] = 0;
	scratch->scratch_a[2] = 0;
	scratch->scratch_a[3] = 0;
	for (__u32 i = 0; i < 8; i++)
		scratch->scratch_b[i] = 0;

	/* 2. Scan 61 full chunks of 256 bytes (0x3d00 = 15,616 bytes) via bpf_loop */
	struct scan_loop_ctx loop_ctx = {
		.frame_base          = frame_base,
		.scratch             = scratch,
		.nonzero_qwords      = 0,
		.total_set_bits      = 0,
		.high_entropy_chunks = 0,
		.first_dirty         = 0,
		.last_dirty          = 0,
		.chunks_read         = 0,
		.found_dirty         = 0,
	};

	bpf_loop(MLKEM768_SCAN_FULL_CHUNKS, scan_stack_chunk_cb, &loop_ctx, 0);

	/* 3. Scan the remaining 8-byte tail at offset 0x3d00 (total = 0x3d08 bytes) */
	err = bpf_probe_read_user(&scratch->tail_word,
				  sizeof(scratch->tail_word),
				  (const void *)(frame_base + MLKEM768_SCAN_TAIL_OFFSET));
	if (err != 0) {
		scratch->byte_freq[0] += 8;
	} else {
		loop_ctx.chunks_read++;
		if (scratch->tail_word == 0) {
			scratch->byte_freq[0] += 8;
		} else {
			__u64 val = scratch->tail_word;
			scratch->tail_word = 0;

			loop_ctx.nonzero_qwords++;
			if (!loop_ctx.found_dirty) {
				loop_ctx.first_dirty = (__u32)MLKEM768_SCAN_TAIL_OFFSET;
				loop_ctx.found_dirty = 1;
			}
			loop_ctx.last_dirty = (__u32)(MLKEM768_SCAN_TAIL_OFFSET + 7ULL);
			loop_ctx.total_set_bits += swar_popcount64(val);

			scratch->byte_freq[(val >> 0)  & 0xffU]++;
			scratch->byte_freq[(val >> 8)  & 0xffU]++;
			scratch->byte_freq[(val >> 16) & 0xffU]++;
			scratch->byte_freq[(val >> 24) & 0xffU]++;
			scratch->byte_freq[(val >> 32) & 0xffU]++;
			scratch->byte_freq[(val >> 40) & 0xffU]++;
			scratch->byte_freq[(val >> 48) & 0xffU]++;
			scratch->byte_freq[(val >> 56) & 0xffU]++;
		}
	}

	if (loop_ctx.chunks_read == 0)
		return;

	__u32 zero_bytes = (__u32)scratch->byte_freq[0];
	__u32 nonzero_bytes = (zero_bytes <= (__u32)MLKEM768_STACK_FRAME_SIZE) ?
			      ((__u32)MLKEM768_STACK_FRAME_SIZE - zero_bytes) : 0U;

	/* 4. Copy 256-bin histogram to event in 1 helper call and scrub scratch */
	bpf_probe_read_kernel(ev->byte_freq, sizeof(ev->byte_freq), scratch->byte_freq);
	for (__u32 i = 0; i < 64; i++)
		freq_u64[i] = 0;

	ev->frame_scanned_bytes = (__u32)MLKEM768_STACK_FRAME_SIZE;
	ev->nonzero_bytes       = nonzero_bytes;
	ev->nonzero_qwords      = loop_ctx.nonzero_qwords;
	ev->set_bits            = loop_ctx.total_set_bits;
	ev->high_entropy_chunks = loop_ctx.high_entropy_chunks;
	ev->first_dirty_offset  = loop_ctx.first_dirty;
	ev->last_dirty_offset   = loop_ctx.last_dirty;
	ev->is_zeroed           = (nonzero_bytes == 0) ? 1 : 0;
	ev->zero_check_valid    = 1;
}

SEC("uprobe//usr/lib/openssh/sshd-auth:kex_kem_mlkem768x25519_dec")
int uprobe_kex_kem_mlkem768x25519_dec(struct pt_regs *ctx)
{
	__u64 kex_ptr           = (__u64)PT_REGS_PARM1(ctx);
	__u64 client_blob_ptr   = (__u64)PT_REGS_PARM2(ctx);
	__u64 shared_secretp    = (__u64)PT_REGS_PARM3(ctx);

	return save_call_entry(ctx, FUNC_KEX_KEM_MLKEM768X25519_DEC,
			       kex_ptr, client_blob_ptr, shared_secretp);
}

SEC("uretprobe//usr/lib/openssh/sshd-auth:kex_kem_mlkem768x25519_dec")
int uretprobe_kex_kem_mlkem768x25519_dec(struct pt_regs *ctx)
{
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__u64 exit_ts_ns = bpf_ktime_get_ns();
	struct call_key key = {
		.pid_tgid = pid_tgid,
		.func_id  = FUNC_KEX_KEM_MLKEM768X25519_DEC,
		.pad      = 0,
	};
	struct call_entry *entry;
	struct pqc_event *ev;

	entry = bpf_map_lookup_elem(&inflight_calls, &key);
	if (!entry)
		return 0;

	ev = bpf_ringbuf_reserve(&events, sizeof(*ev), 0);
	if (!ev) {
		bpf_map_delete_elem(&inflight_calls, &key);
		return 0;
	}

	__builtin_memset(ev, 0, sizeof(*ev));

	ev->entry_ts_ns      = entry->entry_ts_ns;
	ev->exit_ts_ns       = exit_ts_ns;
	ev->delta_ns         = (exit_ts_ns >= entry->entry_ts_ns) ?
			       (exit_ts_ns - entry->entry_ts_ns) : 0;
	ev->sp_entry         = entry->sp_entry;
	ev->sp_exit          = PT_REGS_SP(ctx);
	ev->stack_frame_base = (entry->sp_entry > MLKEM768_FRAME_TOTAL_OFFSET) ?
			       (entry->sp_entry - MLKEM768_FRAME_TOTAL_OFFSET) : 0;
	ev->stack_frame_size = MLKEM768_STACK_FRAME_SIZE;
	ev->sshbuf_ptr       = entry->arg1;
	ev->heap_lifetime_ns = 0;
	ev->ret_code         = (__s64)(__s32)PT_REGS_RC(ctx);
	ev->pid              = (__u32)(pid_tgid >> 32);
	ev->tid              = (__u32)pid_tgid;
	ev->func_id          = FUNC_KEX_KEM_MLKEM768X25519_DEC;
	ev->in_kex_dec       = 1;

	audit_full_stack_frame(entry->sp_entry, ev);

	bpf_get_current_comm(&ev->comm, sizeof(ev->comm));

	bpf_ringbuf_submit(ev, 0);
	bpf_map_delete_elem(&inflight_calls, &key);
	return 0;
}

SEC("uprobe//usr/lib/openssh/sshd-auth:sshbuf_new")
int uprobe_sshbuf_new(struct pt_regs *ctx)
{
	return save_call_entry(ctx, FUNC_SSHBUF_NEW, 0, 0, 0);
}

SEC("uretprobe//usr/lib/openssh/sshd-auth:sshbuf_new")
int uretprobe_sshbuf_new(struct pt_regs *ctx)
{
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__u64 exit_ts_ns = bpf_ktime_get_ns();
	__u64 buf_ptr = (__u64)PT_REGS_RC(ctx);
	struct call_key key = {
		.pid_tgid = pid_tgid,
		.func_id  = FUNC_SSHBUF_NEW,
		.pad      = 0,
	};
	struct call_entry *entry;
	struct pqc_event *ev;

	entry = bpf_map_lookup_elem(&inflight_calls, &key);
	if (!entry)
		return 0;

	if (buf_ptr != 0) {
		struct sshbuf_alloc_meta meta = {
			.alloc_ts_ns = exit_ts_ns,
			.sp_alloc    = entry->sp_entry,
			.pid         = (__u32)(pid_tgid >> 32),
			.tid         = (__u32)pid_tgid,
			.in_kex_dec  = entry->in_kex_dec,
			.was_reset   = 0,
		};
		bpf_map_update_elem(&active_sshbufs, &buf_ptr, &meta, BPF_ANY);
	}

	ev = bpf_ringbuf_reserve(&events, sizeof(*ev), 0);
	if (!ev) {
		bpf_map_delete_elem(&inflight_calls, &key);
		return 0;
	}

	__builtin_memset(ev, 0, sizeof(*ev));

	ev->entry_ts_ns      = entry->entry_ts_ns;
	ev->exit_ts_ns       = exit_ts_ns;
	ev->delta_ns         = (exit_ts_ns >= entry->entry_ts_ns) ?
			       (exit_ts_ns - entry->entry_ts_ns) : 0;
	ev->sp_entry         = entry->sp_entry;
	ev->sp_exit          = PT_REGS_SP(ctx);
	ev->sshbuf_ptr       = buf_ptr;
	ev->ret_code         = (buf_ptr != 0) ? 0 : -1;
	ev->pid              = (__u32)(pid_tgid >> 32);
	ev->tid              = (__u32)pid_tgid;
	ev->func_id          = FUNC_SSHBUF_NEW;
	ev->in_kex_dec       = entry->in_kex_dec;
	bpf_get_current_comm(&ev->comm, sizeof(ev->comm));

	bpf_ringbuf_submit(ev, 0);
	bpf_map_delete_elem(&inflight_calls, &key);
	return 0;
}

SEC("uprobe//usr/lib/openssh/sshd-auth:sshbuf_reset")
int uprobe_sshbuf_reset(struct pt_regs *ctx)
{
	__u64 buf_ptr = (__u64)PT_REGS_PARM1(ctx);

	if (buf_ptr != 0) {
		struct sshbuf_alloc_meta *meta;

		meta = bpf_map_lookup_elem(&active_sshbufs, &buf_ptr);
		if (meta)
			meta->was_reset = 1;
	}

	return save_call_entry(ctx, FUNC_SSHBUF_RESET, buf_ptr, 0, 0);
}

SEC("uretprobe//usr/lib/openssh/sshd-auth:sshbuf_reset")
int uretprobe_sshbuf_reset(struct pt_regs *ctx)
{
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__u64 exit_ts_ns = bpf_ktime_get_ns();
	struct call_key key = {
		.pid_tgid = pid_tgid,
		.func_id  = FUNC_SSHBUF_RESET,
		.pad      = 0,
	};
	struct call_entry *entry;
	struct pqc_event *ev;

	entry = bpf_map_lookup_elem(&inflight_calls, &key);
	if (!entry)
		return 0;

	ev = bpf_ringbuf_reserve(&events, sizeof(*ev), 0);
	if (!ev) {
		bpf_map_delete_elem(&inflight_calls, &key);
		return 0;
	}

	__builtin_memset(ev, 0, sizeof(*ev));

	ev->entry_ts_ns      = entry->entry_ts_ns;
	ev->exit_ts_ns       = exit_ts_ns;
	ev->delta_ns         = (exit_ts_ns >= entry->entry_ts_ns) ?
			       (exit_ts_ns - entry->entry_ts_ns) : 0;
	ev->sp_entry         = entry->sp_entry;
	ev->sp_exit          = PT_REGS_SP(ctx);
	ev->sshbuf_ptr       = entry->arg0;
	ev->ret_code         = 0;
	ev->pid              = (__u32)(pid_tgid >> 32);
	ev->tid              = (__u32)pid_tgid;
	ev->func_id          = FUNC_SSHBUF_RESET;
	ev->in_kex_dec       = entry->in_kex_dec;
	ev->is_zeroed        = 1;
	ev->zero_check_valid = 1;
	ev->was_reset        = 1;
	bpf_get_current_comm(&ev->comm, sizeof(ev->comm));

	bpf_ringbuf_submit(ev, 0);
	bpf_map_delete_elem(&inflight_calls, &key);
	return 0;
}

SEC("uprobe//usr/lib/openssh/sshd-auth:sshbuf_free")
int uprobe_sshbuf_free(struct pt_regs *ctx)
{
	__u64 buf_ptr = (__u64)PT_REGS_PARM1(ctx);

	return save_call_entry(ctx, FUNC_SSHBUF_FREE, buf_ptr, 0, 0);
}

SEC("uretprobe//usr/lib/openssh/sshd-auth:sshbuf_free")
int uretprobe_sshbuf_free(struct pt_regs *ctx)
{
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__u64 exit_ts_ns = bpf_ktime_get_ns();
	struct call_key key = {
		.pid_tgid = pid_tgid,
		.func_id  = FUNC_SSHBUF_FREE,
		.pad      = 0,
	};
	struct call_entry *entry;
	struct sshbuf_alloc_meta *meta;
	struct pqc_event *ev;
	__u64 buf_ptr;
	__u64 heap_lifetime_ns = 0;
	__u8 was_reset = 0;
	__u8 in_kex_dec;

	entry = bpf_map_lookup_elem(&inflight_calls, &key);
	if (!entry)
		return 0;

	buf_ptr = entry->arg0;
	in_kex_dec = entry->in_kex_dec;

	if (buf_ptr != 0) {
		meta = bpf_map_lookup_elem(&active_sshbufs, &buf_ptr);
		if (meta) {
			if (exit_ts_ns >= meta->alloc_ts_ns)
				heap_lifetime_ns = exit_ts_ns - meta->alloc_ts_ns;
			was_reset = meta->was_reset;
			if (meta->in_kex_dec)
				in_kex_dec = 1;
			bpf_map_delete_elem(&active_sshbufs, &buf_ptr);
		}
	}

	ev = bpf_ringbuf_reserve(&events, sizeof(*ev), 0);
	if (!ev) {
		bpf_map_delete_elem(&inflight_calls, &key);
		return 0;
	}

	__builtin_memset(ev, 0, sizeof(*ev));

	ev->entry_ts_ns      = entry->entry_ts_ns;
	ev->exit_ts_ns       = exit_ts_ns;
	ev->delta_ns         = (exit_ts_ns >= entry->entry_ts_ns) ?
			       (exit_ts_ns - entry->entry_ts_ns) : 0;
	ev->sp_entry         = entry->sp_entry;
	ev->sp_exit          = PT_REGS_SP(ctx);
	ev->sshbuf_ptr       = buf_ptr;
	ev->heap_lifetime_ns = heap_lifetime_ns;
	ev->ret_code         = 0;
	ev->pid              = (__u32)(pid_tgid >> 32);
	ev->tid              = (__u32)pid_tgid;
	ev->func_id          = FUNC_SSHBUF_FREE;
	ev->in_kex_dec       = in_kex_dec;
	ev->is_zeroed        = (buf_ptr != 0) ? 1 : 0;
	ev->zero_check_valid = (buf_ptr != 0) ? 1 : 0;
	ev->was_reset        = was_reset;
	bpf_get_current_comm(&ev->comm, sizeof(ev->comm));

	bpf_ringbuf_submit(ev, 0);
	bpf_map_delete_elem(&inflight_calls, &key);
	return 0;
}
