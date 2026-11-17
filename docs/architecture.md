# Arsitektur Lab & Alur Telemetri eBPF CO-RE (`mlkem768x25519-sha256`)

## 1. Topologi Lab Terisolasi

| Komponen | Spesifikasi Teknis | Peran |
| :--- | :--- | :--- |
| **Control Host** | Linux Workstation (`x86_64`) | Pengembang kode sumber, repositori Git, dan pemicu 20 sesi benchmark SSH ([run_benchmark.sh](file:///home/indra/projects/pqc-handshake-memory-forensics/scripts/run_benchmark.sh)) |
| **Jaringan Lab** | VirtualBox Host-Only (`vboxnet0`), Subnet `192.168.56.0/24` | Kanal komunikasi terisolasi penuh (NAT Adapter 1 dinonaktifkan / *air-gapped*) |
| **Target VM** | Debian 13 (Trixie), Hostname `pqc-indra`, IP `192.168.56.10` | Lingkungan kompilasi CO-RE (`clang`, `bpftool`, `libbpf-dev`) dan eksekusi target `/usr/lib/openssh/sshd-auth` |
| **Snapshot Baseline** | `clean-pqc-lab` |の状態 dasar dengan `/sys/kernel/btf/vmlinux` dan `openssh-server-dbgsym` terpasang |

---

## 2. Pemisahan Hak Istimewa OpenSSH 10.0p2 (`sshd-auth`)

Pada OpenSSH 10.0p2, proses pertukaran kunci (*Key Exchange* / KEX) tidak dijalankan di dalam daemon utama `/usr/sbin/sshd` maupun `/usr/lib/openssh/sshd-session`, melainkan didelegasikan ke biner khusus pra-autentikasi **`/usr/lib/openssh/sshd-auth`**:

1. Klien menghubungi `192.168.56.10:22` dengan `-o KexAlgorithms=mlkem768x25519-sha256`.
2. `/usr/sbin/sshd` melakukan `fork()` + `execve()` terhadap `/usr/lib/openssh/sshd-auth` untuk menangani negosiasi KEX dan autentikasi pengguna.
3. `sshd-auth` menerima *blob* klien sebesar `0x460` (1.120) byte dan memanggil `kex_kem_mlkem768x25519_dec` (`0x000a32d0`).
4. Implementasi kriptografi menggunakan kode bawaan OpenSSH (`kexmlkem768x25519.c` + header *inlined* `libcrux_mlkem768_sha3.h`), bukan pustaka eksternal `libcrypto` OpenSSL.

---

## 3. Arsitektur Instrumen eBPF CO-RE

Instrumen dibagi menjadi ruang kernel ([pqc_trace.bpf.c](file:///home/indra/projects/pqc-handshake-memory-forensics/src/ebpf/pqc_trace.bpf.c)) dan kolektor ruang pengguna ([loader.c](file:///home/indra/projects/pqc-handshake-memory-forensics/src/collector/loader.c)) yang dihubungkan oleh `BPF_MAP_TYPE_RINGBUF`:

1. **`inflight_calls` (`BPF_MAP_TYPE_HASH`)**:
   - Menyimpan konteks saat `uprobe` masuk (`entry_ts_ns`, `sp_entry`, argumen pointer `%rdi`/`%rsi`/`%rdx`, serta flag `in_kex_dec`) menggunakan kunci komposit `{ pid_tgid, func_id }` agar pemanggilan `sshbuf_new`, `sshbuf_reset`, dan `sshbuf_free` di dalam `kex_kem_mlkem768x25519_dec` tidak menimpa state fungsi induk.
2. **`active_sshbufs` (`BPF_MAP_TYPE_HASH`)**:
   - Melacak alamat *heap* `struct sshbuf *` yang dikembalikan oleh `uretprobe/sshbuf_new`, mencatat apakah `uprobe/sshbuf_reset` dipanggil terhadap buffer tersebut (`was_reset = 1`), dan menghitung total umur alokasi (`heap_lifetime_ns`) saat `uretprobe/sshbuf_free` selesai.
3. **`stack_audit_scratch_map` (`BPF_MAP_TYPE_PERCPU_ARRAY`)**:
   - Menyediakan memori kerja *per-CPU* di ruang kernel untuk memindai seluruh `0x3d08` byte (61 blok $\times$ 256 byte + 8 byte ekor) *stack frame* `kex_kem_mlkem768x25519_dec` saat `uretprobe` keluar menggunakan `bpf_probe_read_user()` berukuran konstan, menghitung statistik entropi Shannon dan jumlah byte tak-nol, lalu segera mengenolkan kembali buffer *scratch* di kernel sebelum mengirim metadata ke `events` (`BPF_MAP_TYPE_RINGBUF`).

