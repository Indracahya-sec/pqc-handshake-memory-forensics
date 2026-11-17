// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
#ifndef PQC_TRACE_H
#define PQC_TRACE_H

#ifndef __VMLINUX_H__
#include <linux/types.h>
#endif

#define DEFAULT_BINARY_PATH "/usr/lib/openssh/sshd-auth"
#define DEFAULT_OUTPUT_PATH "results/pqc_telemetry.json"

#ifndef TASK_COMM_LEN
#define TASK_COMM_LEN 16
#endif

/*
 * Static analysis constants for OpenSSH 10.0p2 (/usr/lib/openssh/sshd-auth)
 * derived from docs/kex_mlkem_disasm.txt:
 *
 * kex_kem_mlkem768x25519_dec prologue:
 *   push %r15..%rbx               -> 6 * 8 = 0x30 bytes
 *   sub  $0x1000, %rsp (x3)       -> 0x3000 bytes (stack clash page probes)
 *   sub  $0xd08,  %rsp            -> 0x0d08 bytes
 *   Total local stack allocation  -> 0x3d08 bytes (15,624 bytes)
 *   Total offset from entry %rsp  -> 0x3d38 bytes (15,672 bytes)
 *
 * Full 0x3d08-byte stack frame decomposition for constant-bounded BPF reads:
 *   61 chunks * 256 bytes         -> 0x3d00 bytes (15,616 bytes)
 *   1 tail word * 8 bytes         -> 0x0008 bytes (8 bytes)
 *   Total scanned                 -> 0x3d08 bytes (15,624 bytes)
 */
#define MLKEM768_DEC_VADDR           0x000a32d0ULL
#define MLKEM768_ENC_VADDR           0x000a2bc0ULL
#define SSHBUF_NEW_VADDR             0x000471a0ULL
#define SSHBUF_RESET_VADDR           0x000476d0ULL
#define SSHBUF_FREE_VADDR            0x00047430ULL

#define MLKEM768_STACK_FRAME_SIZE    0x3d08ULL
#define MLKEM768_SAVED_REGS_SIZE     0x0030ULL
#define MLKEM768_FRAME_TOTAL_OFFSET  (MLKEM768_STACK_FRAME_SIZE + MLKEM768_SAVED_REGS_SIZE)

#define MLKEM768_SCAN_CHUNK_BYTES    256ULL
#define MLKEM768_SCAN_CHUNK_QWORDS   32ULL
#define MLKEM768_SCAN_FULL_CHUNKS    61ULL
#define MLKEM768_SCAN_TAIL_OFFSET    0x3d00ULL
#define MLKEM768_SCAN_TAIL_BYTES     8ULL

/* log2(15624) * 1000 = 13931.49 -> 13931 millibits */
#define MLKEM768_LOG2_FRAME_MILLI    13931ULL

/*
 * Ephemeral stack buffers within kex_kem_mlkem768x25519_dec frame
 * initialized via movaps %xmm0 and passed to cleanup block at +5298 (0xa4782):
 *   0x3270(%rsp): 32-byte intermediate buffer (%rbp)
 *   0x3370(%rsp): 64-byte shared secret digest buffer (%rbx)
 */
#define MLKEM768_SCRATCH_OFFSET_A    0x3270ULL
#define MLKEM768_SCRATCH_SIZE_A      32ULL
#define MLKEM768_SCRATCH_OFFSET_B    0x3370ULL
#define MLKEM768_SCRATCH_SIZE_B      64ULL

enum pqc_func_id {
	FUNC_KEX_KEM_MLKEM768X25519_DEC = 1,
	FUNC_SSHBUF_NEW                 = 2,
	FUNC_SSHBUF_RESET               = 3,
	FUNC_SSHBUF_FREE                = 4,
};

struct call_key {
	__u64 pid_tgid;
	__u32 func_id;
	__u32 pad;
};

struct call_entry {
	__u64 entry_ts_ns;
	__u64 sp_entry;
	__u64 arg0;
	__u64 arg1;
	__u64 arg2;
	__u8  in_kex_dec;
	__u8  pad[7];
};

struct sshbuf_alloc_meta {
	__u64 alloc_ts_ns;
	__u64 sp_alloc;
	__u32 pid;
	__u32 tid;
	__u8  in_kex_dec;
	__u8  was_reset;
	__u8  pad[6];
};

/*
 * Telemetry record exported via BPF_MAP_TYPE_RINGBUF.
 * Strictly excludes raw cryptographic key bytes or memory dumps.
 */
struct pqc_event {
	__u64 entry_ts_ns;
	__u64 exit_ts_ns;
	__u64 delta_ns;
	__u64 sp_entry;
	__u64 sp_exit;
	__u64 stack_frame_base;
	__u64 stack_frame_size;
	__u64 sshbuf_ptr;
	__u64 heap_lifetime_ns;
	__s64 ret_code;
	__u32 pid;
	__u32 tid;
	__u32 func_id;
	__u32 frame_scanned_bytes;
	__u32 nonzero_bytes;
	__u32 nonzero_qwords;
	__u32 set_bits;
	__u32 high_entropy_chunks;
	__u32 first_dirty_offset;
	__u32 last_dirty_offset;
	__u8  in_kex_dec;
	__u8  is_zeroed;
	__u8  scratch_zeroed;
	__u8  zero_check_valid;
	__u8  was_reset;
	__u8  pad[3];
	__u16 byte_freq[256];
	char  comm[TASK_COMM_LEN];
};

#endif /* PQC_TRACE_H */
