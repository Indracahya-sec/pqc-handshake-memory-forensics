# Panduan Remediasi: Hardening Kompilasi & Zeroization Eksplisit ML-KEM-768

Dokumen ini merumuskan langkah mitigasi teknis untuk menutup celah residu memori pada *stack frame* `0x3d08` byte (`15.624` byte) dan register vektor pada implementasi `kex_kem_mlkem768x25519_dec` (`/usr/lib/openssh/sshd-auth`).

---

## 1. Ringkasan Akar Masalah

1. **Inlining Struktur `libcrux` *By-Value* Tanpa *Stack Scrubbing***:
   - Implementasi `libcrux_mlkem768_sha3.h` yang di-*inline* ke dalam `kex_kem_mlkem768x25519_dec` menggunakan struktur C berukuran besar di *stack* untuk menyimpan polinomial ring $\mathbb{Z}_{3329}[X]/(X^{256}+1)$, *state* sponge Keccak-f[1600] (200 byte per instans), serta tuple hasil dekapsulasi.
   - Fungsi pembungkus `kex_kem_mlkem768x25519_dec` hanya memanggil `explicit_bzero()` pada buffer lokal miliknya sendiri (`0x3270(%rsp)` sebesar 32 byte dan `0x3370(%rsp)` sebesar 64 byte), sehingga 99,38% dari *stack frame* (`15.528` dari `15.624` byte) tidak dibersihkan saat `add $0x3d08, %rsp`.
2. **Pembersihan Register Vektor Parsial (`%xmm0`..`%xmm11`)**:
   - Epilog pada `0x000a480e`..`0x000a4849` hanya mengenolkan `%xmm0`–`%xmm11` (`-fzero-call-used-regs=used`), menyisakan `%xmm12`–`%xmm15` tanpa pembersihan eksplisit pada batas keluar fungsi.

---

## 2. Remediasi Tingkat Kode Sumber (`explicit_bzero`)

### A. Pembersihan State Internal `libcrux_mlkem768_sha3.h`
Pada kode sumber `kexmlkem768x25519.c` dan header `libcrux_mlkem768_sha3.h`, setiap struktur sementara yang menampung kunci dekapsulasi terurai (*unpacked private key*), polinomial NTT, *sponge state* SHA3/SHAKE, serta *shared secret* antara wajib dibersihkan menggunakan `explicit_bzero()` sebelum fungsi kembali:

```c
/* Contoh pola remediasi pada wrapper dekapsulasi di kexmlkem768x25519.c */
int
kex_kem_mlkem768x25519_dec(struct kex *kex, const struct sshbuf *client_blob,
    struct sshbuf **shared_secretp)
{
	/* ... deklarasi variabel lokal ... */
	struct libcrux_mlkem768_dec_ctx {
		uint8_t dec_shared[crypto_kem_mlkem768_BYTES];
		uint8_t c25519_shared[CURVE25519_SIZE];
		uint8_t concat_digest[SSH_DIGEST_MAX_LENGTH];
	} ctx;

	explicit_bzero(&ctx, sizeof(ctx));

	/* ... proses dekapsulasi & derivasi ... */

out:
	/* Wajib membersihkan seluruh konteks stack lokal sebelum keluar */
	explicit_bzero(&ctx, sizeof(ctx));
	sshbuf_free(buf);
	return r;
}
```

Untuk fungsi-fungsi internal di `libcrux_mlkem768_sha3.h` yang mengalokasikan *sponge state* Keccak dan vektor polinomial di *stack*:

```c
/* Di dalam fungsi ind_cca_decapsulate / ind_cpa_decrypt pada libcrux_mlkem768_sha3.h */
static inline void
libcrux_mlkem768_decapsulate_sane(const uint8_t *private_key,
    const uint8_t *ciphertext, uint8_t *shared_secret_out)
{
	libcrux_ml_kem_mlkem768_MlKem768KeyPairUnpacked unpacked_kp;
	libcrux_ml_kem_ind_cca_instantiations_portable_DecapsWorkspace ws;

	/* Jalankan operasi dekapsulasi menggunakan workspace terpusat */
	libcrux_mlkem768_decapsulate_with_ws(&unpacked_kp, ciphertext,
	    shared_secret_out, &ws);

	/* Bersihkan seluruh workspace polinomial & state Keccak sebelum return */
	explicit_bzero(&unpacked_kp, sizeof(unpacked_kp));
	explicit_bzero(&ws, sizeof(ws));
}
```

### B. Pembersihan Stack Frame Otomatis dengan Atribut `strub` (GCC 14+)
Pada toolchain Debian 13 (GCC 14+), fungsi `kex_kem_mlkem768x25519_dec` dapat diberi atribut `__attribute__((strub("internal")))` (*stack scrubbing*) agar kompiler secara otomatis menyisipkan *watermark* stack dan mengenolkan seluruh wilayah *stack frame* (`0x3d08` byte) yang digunakan oleh fungsi maupun sub-fungsi yang di-*inline* sebelum instruksi `ret`:

```c
__attribute__((strub("internal")))
int
kex_kem_mlkem768x25519_dec(struct kex *kex, const struct sshbuf *client_blob,
    struct sshbuf **shared_secretp);
```

---

## 3. Hardening Flag Kompiler (`CFLAGS` / `LDFLAGS`)

Terapkan *flag* kompilasi berikut saat membangun `/usr/lib/openssh/sshd-auth` pada paket OpenSSH:

| Flag Kompiler | Efek pada Biner `sshd-auth` | Tujuan Keamanan |
| :--- | :--- | :--- |
| `-fzero-call-used-regs=all` | Mengenolkan **seluruh** register *caller-saved* (GPR `%rax`..`%r11` dan seluruh register vektor `%xmm0`..`%xmm15` / `%ymm0`..`%ymm15`) sebelum `ret` | Mencegah kebocoran *state* polinomial/SHA3 melalui `%xmm12`–`%xmm15` yang terlewat oleh mode `=used` |
| `-ftrivial-auto-var-init=zero` | Menginisialisasi seluruh variabel otomatis/lokal di *stack* (termasuk *padding* struktur C) menjadi `0x00` saat alokasi | Menghilangkan *uninitialized stack reads* dan memastikan area *padding* struktur `libcrux` bebas dari sampah memori sebelumnya |
| `-fstack-clash-protection` | Mempertahankan *probing* halaman `sub $0x1000,%rsp; orq $0x0,(%rsp)` pada alokasi frame besar (`0x3d08` byte) | Mencegah lompatan *stack pointer* melewati *stack guard page* |
| `-fstack-protector-strong` | Mempertahankan verifikasi *canary* `%fs:0x28` di `0x3cf8(%rsp)` sebelum dealokasi frame | Mendeteksi korupsi *stack buffer* sebelum eksekusi `ret` |
| `-fno-builtin-memset` | Mencegah optimasi *dead-store elimination* (DSE) menghapus pemanggilan pembersihan memori | Menjamin instruksi pengenolan memori tetap dieksekusi di tingkat *machine code* |

### Konfigurasi Build OpenSSH yang Direkomendasikan

```bash
./configure \
    --with-CFLAGS="-O2 -fzero-call-used-regs=all -ftrivial-auto-var-init=zero -fstack-clash-protection -fstack-protector-strong" \
    --with-LDFLAGS="-Wl,-z,relro,-z,now"
make
```

---

## 4. Verifikasi Pasca-Remediasi dengan Instrumen eBPF CO-RE

Setelah menerapkan patch `explicit_bzero()` / `strub("internal")` dan membangun ulang `sshd-auth`, jalankan kembali kolektor eBPF dan skrip benchmark untuk memverifikasi bahwa residu *stack frame* `0x3d08` byte telah hilang:

```bash
./scripts/run_benchmark.sh
```

Kriteria kelulusan pada `results/benchmark_metrics.json` untuk setiap event `"func": "kex_kem_mlkem768x25519_dec"`:
- `"zeroization.state"`: `"ZEROED"`
- `"zeroization.is_zeroed"`: `true`
- `"zeroization.scratch_buffers_zeroed"`: `true`
- `"zeroization.high_entropy_residue"`: `false`
- `"zeroization.nonzero_bytes"`: `0` (dari `15624` byte yang dipindai)
- `"zeroization.shannon_entropy_bits_per_byte"`: `0.000`

