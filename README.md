# Post-Quantum Cryptography Handshake Memory Forensics (`pqc-handshake-memory-forensics`)

Evaluasi forensik siklus hidup memori, waktu eksekusi tingkat nanodetik, alokasi *stack frame* (`0x3d08` byte) & *heap* (`struct sshbuf`), serta efektivitas *post-handshake zeroization* pada pertukaran kunci hibrida **ML-KEM-768 + X25519** (`kex_kem_mlkem768x25519_dec`) di **OpenSSH 10.0p2** (`/usr/lib/openssh/sshd-auth`) menggunakan instrumen **eBPF CO-RE (`libbpf`)** dan analisis biner statis/dinamis.

---

## 1. Ringkasan Temuan Utama

1. **Target Biner & Backend Kriptografi**:
   - Operasi dekapsulasi dijalankan di dalam proses pra-autentikasi terpisah **`/usr/lib/openssh/sshd-auth`** menggunakan implementasi bawaan OpenSSH (`kexmlkem768x25519.c` dan header *inlined* `libcrux_mlkem768_sha3.h`), bukan `libcrypto` OpenSSL.
2. **Alokasi Stack Frame `0x3d08` Byte (15.624 Byte) & Celah Zeroization**:
   - Prolog `kex_kem_mlkem768x25519_dec` (`0x000a32d0`) menyimpan 6 register *callee-saved* (`0x30` byte) dan mengalokasikan `0x3d08` byte di *stack* melalui tiga tahap *stack-clash page probe* (`sub $0x1000, %rsp; orq $0x0, (%rsp)`) ditambah `sub $0xd08, %rsp`.
   - Blok pembersihan pada keluar fungsi (`0x000a4782`) hanya memanggil `explicit_bzero()` pada dua *scratch buffer* lokal milik `kexmlkem768x25519.c`:
     - `0x3270(%rsp)` sebesar **32 byte** (`%rbp`)
     - `0x3370(%rsp)` sebesar **64 byte** (`%rbx`)
   - Sisa **15.528 byte** (**99,38%** dari *stack frame* `0x3d08` byte) yang menampung struktur *by-value* `libcrux_mlkem768_sha3.h` (koefisien polinomial NTT/invNTT, *state* sponge Keccak-f[1600], dan variabel re-enkripsi Fujisaki-Okamoto) dilepaskan melalui `add $0x3d08, %rsp` (`0x000a47f2`) tanpa *zeroization*, meninggalkan residu berentropi tinggi di bawah `%rsp`.
3. **Siklus Hidup Heap `struct sshbuf` & Scrubbing Register**:
   - Buffer *heap* yang dialokasikan oleh `sshbuf_new` (`0x000471a0`) untuk menampung 64 byte gabungan *shared secret* (`ML-KEM-768 || X25519`) dibersihkan dengan benar melalui `sshbuf_reset` (`0x000476d0` pada `+5594`) sebelum dikemas ulang menjadi digest akhir `K`, dan kepemilikannya dipindahkan ke `*shared_secretp` (`0x88(%rsp)` disetel ke `0x0` sebelum `sshbuf_free` pada `+5382`).
   - Epilog fungsi (`0x000a4806`..`0x000a4849`) mengenolkan GPR *caller-saved* (`%edx`, `%ecx`, `%esi`, `%edi`, `%r8d`..`%r11d`) serta register SIMD `%xmm0`..`%xmm11` (`pxor`), tetapi tidak menyentuh `%xmm12`..`%xmm15`.

---

## 2. Tabel Ringkasan Metrik & Parameter Forensik

| Parameter / Metrik | Nilai / Karakteristik Terverifikasi | Sumber Bukti |
| :--- | :--- | :--- |
| **Biner Target** | `/usr/lib/openssh/sshd-auth` (PIE `x86_64`) | [kex_mlkem_disasm.txt](file:///home/indra/projects/pqc-handshake-memory-forensics/docs/kex_mlkem_disasm.txt) |
| **Alamat Fungsi `kex_kem_mlkem768x25519_dec` / `_enc`** | `0x000a32d0` (`+0` .. `+5730`) / `0x000a2bc0` (`+0` .. `+1800`) | [kex_mlkem_disasm.txt](file:///home/indra/projects/pqc-handshake-memory-forensics/docs/kex_mlkem_disasm.txt#L1-L218) |
| **Alamat Fungsi `sshbuf_new` / `reset` / `free`** | `0x000471a0` / `0x000476d0` / `0x00047430` | [kex_mlkem_disasm.txt](file:///home/indra/projects/pqc-handshake-memory-forensics/docs/kex_mlkem_disasm.txt#L80-L180) |
| **Ukuran Payload KEX Klien (`client_blob`)** | `0x460` byte (`1.120` B = `1.088` B ML-KEM-768 CT + `32` B X25519 PubKey) | `cmp $0x460, %rax` (`+216`) |
| **Alokasi Stack Frame Lokal** | `0x3d08` byte (`15.624` byte) | `sub $0x1000,%rsp` ($\times 3$) + `sub $0xd08,%rsp` (`+14`..`+50`) |
| **Total Pergeseran `%rsp` dari Entry (`sp_entry`)** | `0x3d38` byte (`15.672` B = `0x3d08` frame + `0x30` saved regs) | `sp_entry - 0x3d38` (`stack_frame_base`) |
| **Pergeseran `%rsp` Exit terhadap Entry (`sp_exit - sp_entry`)** | `+8` byte (`20/20` sesi konsisten) | [benchmark_metrics.json](file:///home/indra/projects/pqc-handshake-memory-forensics/results/benchmark_metrics.json) |
| **Latensi Eksekusi KEX (`delta_ns`, $N=20$)** | `min`: `2.336,04 µs`, `median`: `3.564,51 µs`, `mean`: `4.061,22 µs`, `max`: `9.036,05 µs` | [benchmark_metrics.json](file:///home/indra/projects/pqc-handshake-memory-forensics/results/benchmark_metrics.json) |
| **Siklus Hidup `sshbuf` di Dalam KEX ($N=20$)** | `sshbuf_new`: `40` (`2/sesi`), `sshbuf_reset`: `20` (`1/sesi`), `sshbuf_free`: `40` (`2/sesi`) | [benchmark_metrics.json](file:///home/indra/projects/pqc-handshake-memory-forensics/results/benchmark_metrics.json) |
| **Wilayah Stack yang Diberi `explicit_bzero`** | `96` byte (`0x3270(%rsp)` [32 B] + `0x3370(%rsp)` [64 B]) — `20/20` terverifikasi `true` | `zeroization.scratch_buffers_zeroed = true` |
| **Residu Stack Frame `0x3d08` Byte ($N=20$)** | Rata-rata `11.808,0 / 15.624` byte tak-nol (`75,58%`), `1.773` qwords, `54/61` blok 256B berentropi tinggi | `zeroization.state = "HIGH_ENTROPY_RESIDUE"` |
| **Entropi Shannon Stack Frame ($N=20$)** | `min`: `6,723`, `median`: `6,733`, `mean`: `6,737`, `max`: `6,760` bits/byte (`256/256` nilai byte unik) | [benchmark_metrics.json](file:///home/indra/projects/pqc-handshake-memory-forensics/results/benchmark_metrics.json) |
| **Pembersihan Register SIMD saat Exit** | `%xmm0` .. `%xmm11` (`pxor`), `%xmm12` .. `%xmm15` tidak dibersihkan | [kex_mlkem_disasm.txt](file:///home/indra/projects/pqc-handshake-memory-forensics/docs/kex_mlkem_disasm.txt#L200-L216) |

---

## 3. Struktur Repositori

```text
pqc-handshake-memory-forensics/
├── README.md                 # Ringkasan eksekutif, tabel metrik, dan panduan reproduksi lab
├── docs/
│   ├── architecture.md       # Topologi lab & arsitektur telemetri eBPF CO-RE
│   ├── kex_mlkem_disasm.txt  # Dump disassembly GDB untuk kex_kem_mlkem768x25519_dec
│   ├── static-analysis.md    # Pemetaan offset stack 0x3d08 byte, register, dan alur sshbuf
│   └── remediation.md        # Panduan hardening kompiler & pola explicit_bzero()
├── src/
│   ├── Makefile              # Build vmlinux.h, objek BPF CO-RE, skeleton, dan biner loader
│   ├── ebpf/
│   │   ├── pqc_trace.h       # Definisi konstanta offset, struktur map, dan pqc_event
│   │   └── pqc_trace.bpf.c   # Program kernel uprobe/uretprobe & pengaudit stack 0x3d08 byte
│   └── collector/
│       └── loader.c          # Konsumen ring buffer user-space & penulis log JSON teredaksi
├── scripts/
│   └── run_benchmark.sh      # Skrip pemicu 20 koneksi SSH mlkem768x25519-sha256 dari host
└── results/
    └── benchmark_metrics.json # Output telemetri JSON dari 20 sesi benchmark
```

---

## 4. Cara Reproduksi Lab

### Prasyarat Lingkungan
- **Host**: Arch Linux (`x86_64`) dengan `openssh`, `python3`, dan antarmuka VirtualBox Host-Only `vboxnet0`.
- **Target VM**: Debian 13 (`pqc-indra`, IP `192.168.56.10` pada *snapshot* `clean-pqc-lab`) dengan `/sys/kernel/btf/vmlinux`, `clang`, `llvm`, `libbpf-dev`, `bpftool`, dan `openssh-server-dbgsym`.

### Langkah 1: Konfigurasi Autentikasi Kunci SSH ke Target VM
Agar ke-20 sesi benchmark terisolasi berjalan tanpa interupsi kata sandi, daftarkan kunci publik host ke `indra@192.168.56.10`:

```bash
ssh-copy-id -i ~/.ssh/id_ed25519_silentium.pub indra@192.168.56.10
```

### Langkah 2: Menjalankan Benchmark Otomatis End-to-End (Direkomendasikan)
Jalankan [scripts/run_benchmark.sh](file:///home/indra/projects/pqc-handshake-memory-forensics/scripts/run_benchmark.sh) dari mesin host Arch Linux. Skrip ini secara otomatis menyinkronkan `src/` ke `indra@192.168.56.10:~/work/src`, mengompilasi instrumen dengan `make`, menjalankan `loader` dengan `sudo`, memicu 20 sesi SSH terisolasi (`-o KexAlgorithms=mlkem768x25519-sha256`), menarik log JSON ke `results/benchmark_metrics.json`, dan mencetak ringkasan statistik:

```bash
./scripts/run_benchmark.sh
```

Opsi tambahan pada `run_benchmark.sh`:
- `-k`: Hanya mencatat event yang terjadi di dalam rentang eksekusi aktif `kex_kem_mlkem768x25519_dec`.
- `-i <path_key>`: Menentukan file kunci privat SSH secara eksplisit.
- `--no-deploy`: Melewati langkah sinkronisasi `src/` dan kompilasi ulang `make` di VM.

### Langkah 3: Kompilasi & Eksekusi Manual di Dalam VM (Opsional)
Jika ingin menjalankan kolektor secara manual di dalam VM `pqc-indra`:

```bash
# 1. Kirim kode sumber dari host ke VM
scp -r src indra@192.168.56.10:~/work/

# 2. Masuk ke VM dan kompilasi instrumen eBPF CO-RE
ssh indra@192.168.56.10
cd ~/work/src
make clean all

# 3. Jalankan kolektor telemetri
sudo ./loader -b /usr/lib/openssh/sshd-auth -o ../results/pqc_telemetry.json
```

---

## 5. Dokumentasi Lanjutan

- **[docs/architecture.md](file:///home/indra/projects/pqc-handshake-memory-forensics/docs/architecture.md)**: Topologi lab, arsitektur proses `sshd-auth`, dan desain peta eBPF (`inflight_calls`, `active_sshbufs`, `stack_audit_scratch_map`).
- **[docs/static-analysis.md](file:///home/indra/projects/pqc-handshake-memory-forensics/docs/static-analysis.md)**: Analisis instruksi demi instruksi atas `kex_kem_mlkem768x25519_dec` dan pemetaan tata letak *stack frame* `0x3d08` byte.
- **[docs/remediation.md](file:///home/indra/projects/pqc-handshake-memory-forensics/docs/remediation.md)**: Rekomendasi *compiler hardening* (`-fzero-call-used-regs=all`, `-ftrivial-auto-var-init=zero`, `__attribute__((strub("internal")))`) dan pola `explicit_bzero()` untuk `libcrux_mlkem768_sha3.h`.

