# Analisis Statis: `kex_kem_mlkem768x25519_dec` (`/usr/lib/openssh/sshd-auth`)

Dokumen ini memetakan alokasi *stack frame*, siklus hidup buffer *heap* (`struct sshbuf`), serta mekanisme *zeroization* memori dan register pada fungsi dekapsulasi hibrida **ML-KEM-768 + X25519** (`kex_kem_mlkem768x25519_dec`) di OpenSSH 10.0p2 berdasarkan hasil *disassembly* pada [kex_mlkem_disasm.txt](file:///home/indra/projects/pqc-handshake-memory-forensics/docs/kex_mlkem_disasm.txt).

---

## 1. Identitas Simbol & Offset Biner

| Simbol | Alamat Virtual (`vaddr`) | Peran dalam Siklus Hidup KEX |
| :--- | :--- | :--- |
| `kex_kem_mlkem768x25519_dec` | `0x000a32d0` (`+0` .. `+5730`) | Dekapsulasi ciphertext ML-KEM-768 (`libcrux`), ECDH X25519, dan derivasi *shared secret* hibrida |
| `sshbuf_new` | `0x000471a0` | Alokasi struktur `struct sshbuf` di *heap* untuk menampung *shared secret* sementara |
| `sshbuf_len` | `0x000479a0` | Validasi ukuran *blob* klien (`0x460` = 1.120 byte) |
| `sshbuf_ptr` | `0x00047af0` | Pengambilan pointer data mentah dari `client_blob` |
| `sshbuf_put` | `0x00051190` | Penyalinan 32-byte *shared secret* ML-KEM-768 ke *heap* `sshbuf` |
| `kexc25519_shared_key_ext` | `0x0008e080` | Komputasi *shared secret* X25519 (32 byte) dan penambahan ke `sshbuf` |
| `ssh_digest_buffer` | `0x00084a90` | Hashing SHA-256 atas gabungan `ML-KEM-768 (32B) || X25519 (32B)` ke buffer *stack* |
| `sshbuf_reset` | `0x000476d0` | Pembersihan (`explicit_bzero` internal) dan pengosongan isi `sshbuf` sebelum pengemasan akhir |
| `sshbuf_put_string` | `0x000518f0` | Pengemasan digest 32-byte menjadi format string protokol SSH (`K`) |
| `sshbuf_free` | `0x00047430` | Dealokasi `sshbuf` disertai `explicit_bzero` internal pada jalur keluar/gagal |

---

## 2. Anatomi Prolog & Tata Letak Stack Frame (`0x3d08` Byte)

Pada saat `kex_kem_mlkem768x25519_dec` dipanggil (`0x000a32d0`), prolog fungsi mengalokasikan ruang *stack* dengan proteksi *stack-clash* bertahap per halaman (4.096 byte):

```text
0x000a32d0 <+0>:   endbr64
0x000a32d4 <+4>:   push   %r15 .. %rbx     # 6 register callee-saved = 0x30 (48) byte
0x000a32de <+14>:  sub    $0x1000,%rsp
0x000a32e5 <+21>:  orq    $0x0,(%rsp)      # Probe halaman stack ke-1
0x000a32ea <+26>:  sub    $0x1000,%rsp
0x000a32f1 <+33>:  orq    $0x0,(%rsp)      # Probe halaman stack ke-2
0x000a32f6 <+38>:  sub    $0x1000,%rsp
0x000a32fd <+45>:  orq    $0x0,(%rsp)      # Probe halaman stack ke-3
0x000a3302 <+50>:  sub    $0xd08,%rsp      # Sisa alokasi frame = 0xd08 (3.336) byte
```

- **Ukuran *Stack Frame* Lokal**: `0x3000 + 0x0d08 = 0x3d08` byte (**15.624 byte**).
- **Total Pergeseran `%rsp` dari Entry (`sp_entry`)**: `0x3d08 + 0x30 = 0x3d38` byte (**15.672 byte**), sehingga basis frame aktif berada pada `frame_base = sp_entry - 0x3d38`.

### Peta Offset Memori di Dalam `0x3d08` Stack Frame

| Offset dari `%rsp` Aktif | Ukuran | Instruksi Referensi | Fungsi & Keterangan Forensik |
| :--- | :--- | :--- | :--- |
| `0x0000(%rsp)` .. `0x0057(%rsp)` | 88 B | *Inlined* `libcrux` | Argumen tumpukan & *spill slots* sementara |
| `0x0058(%rsp)` | 8 B | `+115`: `mov %rdi,0x58(%rsp)` | Salinan pointer `struct kex *kex` |
| `0x0088(%rsp)` | 8 B | `+252`: `mov %rax,0x88(%rsp)` | Pointer *heap* `struct sshbuf *buf` hasil `sshbuf_new` |
| `0x0090(%rsp)` | 8 B | `+236`: `mov %rax,0x90(%rsp)` | Pointer buffer mentah `client_blob` (`u_char *`) |
| `0x0098(%rsp)` | 8 B | `+66`: `mov %rdi,0x98(%rsp)` | Pointer `struct kex *kex` (`%rdi`) |
| `0x00a0(%rsp)` | 8 B | `+88`: `mov %rdx,0xa0(%rsp)` | Pointer keluaran `struct sshbuf **shared_secretp` (`%rdx`) |
| `0x00a8(%rsp)` .. `0x326f(%rsp)` | 12.744 B | `+263` .. `+4641` (`libcrux`) | **Wilayah Kerja `libcrux_mlkem768_sha3.h`**: Polinomial NTT/invNTT ($\mathbb{Z}_{3329}[X]/(X^{256}+1)$), *state* Keccak-f[1600], dekripsi IND-CPA, dan re-enkripsi Fujisaki-Okamoto |
| `0x3270(%rsp)` .. `0x328f(%rsp)` | 32 B | `+127`..`+135`: `movaps %xmm0` | Buffer sementara 32-byte (`%rbp`); diinisialisasi nol dengan SIMD dan dibersihkan pada blok *cleanup* (`+5298`) |
| `0x3290(%rsp)` .. `0x336f(%rsp)` | 224 B | *Inlined* `libcrux` | Struktur *return-by-value* antara `libcrux` dan `kexmlkem768x25519.c` |
| `0x3370(%rsp)` .. `0x33af(%rsp)` | 64 B | `+143`..`+186`: `movaps %xmm0` | Buffer digest gabungan `ssh_digest_buffer` (`%rbx`); diinisialisasi nol dan dibersihkan pada blok *cleanup* (`+5298`) |
| `0x33b0(%rsp)` .. `0x3cf7(%rsp)` | 2.376 B | *Inlined* `libcrux` | Buffer matriks publik $\hat{A}$, vektor rahasia/error, dan *sponge state* SHA3/SHAKE |
| `0x3cf8(%rsp)` .. `0x3cff(%rsp)` | 8 B | `+105`: `mov %rbx,0x3cf8(%rsp)` | *Stack canary* TLS (`%fs:0x28`), diverifikasi pada `+5395` sebelum `ret` |
| `0x3d00(%rsp)` .. `0x3d07(%rsp)` | 8 B | *Alignment padding* | Perataan 16-byte ABI System V AMD64 sebelum `add $0x3d08,%rsp` |

---

## 3. Alur Eksekusi & Siklus Hidup `sshbuf`

1. **Validasi Ciphertext Hibrida (`+208` .. `+222`)**:
   - Memanggil `sshbuf_len(client_blob)` (`0x000a33a3`) dan membandingkan hasilnya terhadap `0x460` (**1.120 byte** = 1.088 byte ciphertext ML-KEM-768 + 32 byte kunci publik X25519).
   - Jika panjang tidak tepat `0x460` (`jne 0xa48f0`), fungsi menetapkan kode galat `%r12d = 0xffffffeb` (`-21` / `SSH_ERR_INVALID_FORMAT`) dan melompat ke blok pembersihan `0xa4782`.
2. **Alokasi & Pengisian `sshbuf` di Heap (`+247` .. `+5656`)**:
   - `0x000a33c7 <+247>`: Memanggil `sshbuf_new()` dan menyimpan pointer ke `0x88(%rsp)` serta `%r14`.
   - `0x000a4772 <+5282>`: Setelah dekapsulasi `libcrux` selesai, menyalin 32 byte *shared secret* ML-KEM-768 ke `%r14` via `sshbuf_put()`.
   - `0x000a4867 <+5527>` .. `0x000a4875 <+5541>`: Menggeser pointer `client_blob` sebesar `+0x440` (1.088 byte) untuk menunjuk ke kunci publik X25519 klien, lalu memanggil `kexc25519_shared_key_ext()` yang menambahkan 32 byte *shared secret* X25519 ke `%r14` (total 64 byte di dalam `sshbuf`).
   - `0x000a4897 <+5575>`: Menghitung digest SHA-256 atas 64 byte di `%r14` menggunakan `ssh_digest_buffer()` dan menulis hasilnya ke buffer *stack* `0x3370(%rsp)` (`%rbx`).
   - `0x000a48aa <+5594>`: Memanggil `sshbuf_reset(%r14)` yang menjalankan `explicit_bzero` internal atas 64 byte *shared secret* mentah di *heap* sebelum buffer `%r14` digunakan ulang.
   - `0x000a48c4 <+5620>`: Mengemas digest di `%rbx` menjadi format string SSH ke `%r14` melalui `sshbuf_put_string()`.
   - `0x000a48d4 <+5636>` .. `0x000a48e8 <+5656>`: Menyerahkan kepemilikan `%r14` ke `*shared_secretp` dan mengenolkan `0x88(%rsp)` (`movq $0x0, 0x88(%rsp)`) sebelum melompat ke `0xa4782`.
3. **Dealokasi `sshbuf_free` (`+5374` .. `+5382`)**:
   - Pada `0x000a47ce <+5374>`, nilai `0x88(%rsp)` dimuat ke `%rdi` dan diteruskan ke `call 0x47430 <sshbuf_free>`.
   - Pada jalur sukses, `0x88(%rsp)` bernilai `NULL` (`0x0`) karena kepemilikan `sshbuf` telah dipindahkan ke `*shared_secretp` (yang nantinya dibebaskan oleh pemanggil KEX setelah derivasi kunci sesi selesai). Pada jalur gagal, `0x88(%rsp)` masih berisi pointer aktif sehingga `sshbuf_free` langsung membersihkan dan membebaskan buffer tersebut.

---

## 4. Evaluasi Zeroization: Kesenjangan antara Scratch Buffer, Stack `libcrux`, dan Register

### A. Pembersihan Register pada Epilog (`+5430` .. `+5502`)
Biner dikompilasi dengan *flag* pembersihan register *caller-saved* (`-fzero-call-used-regs=used`), terlihat tepat sebelum instruksi `ret` (`0x000a484e`):
- **Register GPR yang dinolkan**: `%edx`, `%ecx`, `%esi`, `%edi`, `%r8d`, `%r9d`, `%r10d`, `%r11d` (melalui instruksi `xor`).
- **Register SIMD yang dinolkan**: `%xmm0` s.d. `%xmm11` (melalui instruksi `pxor` pada `0x000a480e` .. `0x000a4849`).
- **Keterbatasan**: `%xmm12` s.d. `%xmm15` tidak ikut dibersihkan karena kompiler hanya mengenolkan register yang ditandai terpakai langsung oleh fungsi pembungkus.

### B. Residu Berentropi Tinggi pada Stack Frame `0x3d08` Byte
- Pada blok keluar (`0x000a4782`), pembersihan eksplisit (`explicit_bzero`) hanya mencakup **96 byte** variabel lokal milik `kexmlkem768x25519.c`:
  1. `0x3270(%rsp)` (32 byte)
  2. `0x3370(%rsp)` (64 byte)
- Sebaliknya, fungsi-fungsi `libcrux_mlkem768_sha3.h` yang di-*inline* ke dalam `kex_kem_mlkem768x25519_dec` mengembalikan struktur C berukuran besar *by-value* di *stack* (`0x00a8(%rsp)` .. `0x326f(%rsp)` dan `0x33b0(%rsp)` .. `0x3cf7(%rsp)`).
- Saat `0x000a47f2 <+5410>: add $0x3d08, %rsp` dieksekusi, sekitar **15.528 byte** sisa *stack frame* dilepaskan begitu saja tanpa *zeroization*, meninggalkan residu koefisien polinomial NTT, *state* internal Keccak-f[1600], dan produk antara dekapsulasi ML-KEM-768 di bawah `%rsp`.

