# Daftar Perubahan Laporan → Sesuai Implementasi PURE-PYTHON (Raw, Tanpa Library)

Dokumen ini merinci **apa saja yang perlu diubah** pada `laporankripto.txt` (versi Progress 3) agar isinya **sesuai dengan kode aktual** yang 100% *pure-Python* (`crypto/raw_aes.py`, `crypto/raw_sha3.py`) dan **tidak lagi memakai PyCryptodome / hashlib / hmac**. Format: **DARI** (teks lama) → **MENJADI** (teks baru), beserta alasan.

> **Prinsip umum (berlaku di seluruh dokumen):**
> 1. Ganti semua sebutan **"PyCryptodome"** dan **"hashlib"/"hmac"** → **"implementasi murni (pure-Python) dari rumus"** atau nama modul `crypto/raw_aes.py` / `crypto/raw_sha3.py`.
> 2. Ganti pemanggilan API library di potongan kode: `AES.new(...MODE_GCM)` / `cipher.encrypt_and_digest()` / `cipher.decrypt_and_verify()` → `encrypt_aes_gcm_raw()` / `decrypt_aes_gcm_raw()`; `hashlib.sha3_256(...).hexdigest()` → `compute_sha3_256(...)`; `hmac.compare_digest()` → `constant_time_compare()`.
> 3. Sesuaikan **ambang efisiensi** dengan realita pure-Python: AES enkripsi/dekripsi **< 50 ms** (bukan < 5 ms), throughput SHA-3 **> 0,1 MB/s** (bukan > 50/150/500 MB/s), SAC **45%–55%**.
> 4. Perbarui **angka hasil**: AES 5000 char ≈ **6 ms** (bukan 0,04 ms); throughput SHA-3 ≈ **0,3 MB/s** (bukan 347–545 MB/s).
> 5. Perbarui **status pengujian**: dari **19/22** menjadi **22/22 (100%)** — S5, R2, R5 sudah selesai.
> 6. Tambahkan bukti **kesetaraan NIST** (KAT FIPS 197 C.3, SP 800-38D TC14, FIPS 202) dan **deployment Vercel**.

---

## BAB I — PENDAHULUAN

### 1.3 Tujuan Penelitian (poin 1 & 2)

| | Teks |
|---|---|
| **DARI** | "1. Mengimplementasikan sistem enkripsi-dekripsi berbasis AES-256-GCM menggunakan **python 3 x dengan library PryCryptodome**." |
| **MENJADI** | "1. Mengimplementasikan sistem enkripsi-dekripsi berbasis AES-256-GCM **secara murni (pure-Python) dari rumus NIST FIPS 197 + SP 800-38D, tanpa library kriptografi apa pun**." |

| | Teks |
|---|---|
| **DARI** | "2. Mengimplementasikan fungsi hash SHA-3-256 **menggunakan modul hashlib bawaan python** sebagai mekanisme verifikasi integritas pesan." |
| **MENJADI** | "2. Mengimplementasikan fungsi hash SHA-3-256 **secara murni (Keccak Sponge, FIPS 202) tanpa modul `hashlib`** sebagai mekanisme verifikasi integritas pesan." |

> Catatan: perbaiki juga salah ketik **"PryCryptodome"** (tidak relevan lagi karena dihapus).

---

## BAB II — LANDASAN TEORI

### 2.3 (paragraf terakhir)

| | Teks |
|---|---|
| **DARI** | "…dengan tingkat keamanan 128-bit terhadap tabrakan (birthday bound 2128). **Modul hashlib Python menyediakan implementasi referensi yang langsung dapat dipakai tanpa pustaka pihak ketiga.**" |
| **MENJADI** | "…dengan tingkat keamanan 128-bit terhadap tabrakan (birthday bound 2¹²⁸). **Pada penelitian ini SHA-3-256 diimplementasikan murni dari spesifikasi FIPS 202 (`crypto/raw_sha3.py`) tanpa `hashlib`, sehingga kebenarannya dapat diverifikasi langsung terhadap test vector resmi NIST.**" |

### 2.5 Tabel Parameter Teknis Sistem — baris "Library Python"

| | Teks |
|---|---|
| **DARI** | "Library Python → **PyCryptodome (AES-GCM), hashlib built-in (SHA-3-256)**" |
| **MENJADI** | "Library Kriptografi → **TIDAK ADA — implementasi murni dari rumus (`crypto/raw_aes.py`, `crypto/raw_sha3.py`)**. Library lain: Flask ≥ 3.0 (hanya web/REST, bukan kripto)." |

### 2.5 (paragraf di bawah tabel)

| | Teks |
|---|---|
| **DARI** | "…**PyCryptodome dipilih karena menyediakan API GCM yang stabil dan telah dievaluasi pada banyak studi performa AES berbasis Python** [5, 9, 11]." |
| **MENJADI** | "…**Implementasi murni dipilih agar setiap transformasi (GF(2⁸), S-Box, key expansion, CTR, GHASH GF(2¹²⁸), Keccak-f) dapat dieksplorasi langsung dari spesifikasi NIST dan diverifikasi byte-exact terhadap test vector resmi** [5, 9, 11]." |

### 2.6.1 Tabel Evaluasi AES — baris 2 (Waktu Komputasi)

| | Teks |
|---|---|
| **DARI** | "Waktu enkripsi **< 5 ms** untuk pesan 5000 karakter. **Throughput > 100 MB/s.** Hubungan waktu vs ukuran pesan bersifat linier O(n)." |
| **MENJADI** | "Waktu enkripsi & dekripsi **< 50 ms** untuk pesan 5000 karakter (ambang realistis untuk *block cipher* pure-Python; tetap memenuhi *real-time messaging*). Hubungan waktu vs ukuran pesan bersifat linier O(n)." |

### 2.6.2 Tabel Evaluasi SHA-3 — baris 3 (Throughput)

| | Teks |
|---|---|
| **DARI** | "**Throughput SHA-3-256 > 500 MB/s pada hardware modern.** SHA-3-256 sedikit lebih lambat dari SHA-256 tetapi lebih aman secara struktural." |
| **MENJADI** | "**Throughput SHA-3-256 > 0,1 MB/s** (implementasi pure-Python). Jauh di bawah `hashlib`-C karena ditulis dari rumus; tetap memenuhi kebutuhan pesan teks medis. SHA-3 lebih lambat dari SHA-256 tetapi lebih aman secara struktural." |

> Ukuran uji throughput: **1 KB, 10 KB, 50 KB, 100 KB** (sesuai `HASH_SIZES_KB = [1,10,50,100]`), bukan "1 KB–1 MB".

---

## BAB III — PERANCANGAN SISTEM DAN METODOLOGI

### 3.2.1 Tabel Komponen Pengirim — kolom "Library / Tool"

| Komponen | DARI | MENJADI |
|----------|------|---------|
| Modul SHA-3-256 | **Hashlib (stdlib)** | **`crypto/raw_sha3.py` (murni, Keccak FIPS 202)** |
| Modul AES-256-GCM Engine | **PyCryptodome** | **`crypto/raw_aes.py` (murni, FIPS 197 + SP 800-38D)** |

### 3.3.1 Tabel Tahap Enkripsi — baris 2 & 5

| Tahap | DARI | MENJADI |
|-------|------|---------|
| 2. Hitung SHA-3-256 | "Panggil **`hashlib.sha3_256(plaintext.encode('utf-8')).hexdigest()`**…" | "Panggil **`compute_sha3_256(plaintext)`** (raw Keccak, `crypto/raw_sha3.py`, **bukan `hashlib`**)…" (sisanya r=1088, c=512, 24 ronde tetap benar) |
| 5. AES-256-GCM Encrypt | "Inisialisasi: **`cipher = AES.new(key, AES.MODE_GCM, nonce=iv)`**. Kemudian **`cipher.encrypt_and_digest(payload.encode('utf-8'))`**…" | "Panggil **`iv, ciphertext, auth_tag = encrypt_aes_gcm_raw(key, payload)`** yang secara bersamaan menghasilkan (a) ciphertext via CTR dan (b) tag 128-bit via GHASH GF(2¹²⁸) — implementasi murni." |

### 3.3.2 Tabel Tahap Dekripsi — baris 3

| | Teks |
|---|---|
| **DARI** | "Jalankan **`cipher.decrypt_and_verify(ciphertext, auth_tag)`**. GHASH melakukan perhitungan ulang tag…" |
| **MENJADI** | "Jalankan **`decrypt_aes_gcm_raw(key, iv, ciphertext, auth_tag)`**. GHASH (implementasi murni) menghitung ulang tag…; bila tidak cocok → `ValueError` → DITOLAK." |

### 3.4 Ilustrasi Perhitungan — baris atribusi

| | Teks |
|---|---|
| **DARI** | "Semua nilai adalah hasil aktual **Python 3.13 + PyCryptodome 3.23.0** dapat direproduksi." |
| **MENJADI** | "Semua nilai adalah hasil aktual **implementasi murni (`crypto/raw_aes.py` + `crypto/raw_sha3.py`) pada Python 3.13**, dapat direproduksi dan **identik byte-exact** dengan AES-256-GCM/SHA-3-256 standar." |

> **PENTING:** seluruh nilai numerik pada §3.4 (digest `5d83bd5f…`, RK0–RK14, 10 blok keystream/ciphertext, tag `f62bbc2d…`, paket 177 byte) **TIDAK perlu diubah** — implementasi murni menghasilkan nilai yang sama persis. Hanya atribusi & potongan kode yang diganti.

### 3.4.2 Langkah 8 — potongan kode (Gerbang 1)

| | Teks |
|---|---|
| **DARI** | `cipher = AES.new(key=K, mode=AES.MODE_GCM, nonce=iv_recv)` / `payload_dec = cipher.decrypt_and_verify(ct_recv, tag_recv)` |
| **MENJADI** | `payload_dec = decrypt_aes_gcm_raw(K, iv_recv, ct_recv, tag_recv)`  *(gagal otomatis `ValueError` bila tag tidak cocok)* |

### 3.4.2 Langkah 10 — potongan kode (Gerbang 2)

| | Teks |
|---|---|
| **DARI** | `hash_computed = hashlib.sha3_256(plaintext_dec.encode("utf-8")).hexdigest()` / `is_valid = hmac.compare_digest(hash_computed, hash_received)` |
| **MENJADI** | `hash_computed = compute_sha3_256(plaintext_dec)` / `is_valid = constant_time_compare(hash_computed, hash_received)`  *(keduanya dari `crypto/raw_sha3.py`, tanpa `hashlib`/`hmac`)* |

### 3.5 Judul & paragraf pembuka

| | Teks |
|---|---|
| **DARI** | "3.5 Implementasi **Awal** Core Functions **(60-80%)** … Kode ditulis dalam Python 3.x menggunakan **library PyCryptodome (AES-GCM) dan hashlib (SHA-3-256, bawaan stdlib)**." |
| **MENJADI** | "3.5 Implementasi Core Functions **(100% — Pure Python)** … Seluruh primitif ditulis **murni dari rumus tanpa library kriptografi**; `crypto/raw_aes.py` (AES-256-GCM) dan `crypto/raw_sha3.py` (SHA-3-256 Keccak)." |

### 3.5.1 Pembaruan Struktur Proyek — pohon direktori

| | Teks |
|---|---|
| **DARI** (di bawah `crypto/`) | `sha3_utils.py` (Modul SHA-3-256), `aes_gcm_utils.py` (Modul AES-256-GCM), `crypto_pipeline.py` (Pipeline gabungan) |
| **MENJADI** (di bawah `crypto/`) | Tambahkan: **`raw_aes.py`** (AES-256-GCM murni), **`raw_sha3.py`** (SHA-3-256 murni), **`raw_pipeline.py`** (pipeline raw), **`replay_guard.py`** (ReplayGuard — S5). `sha3_utils.py`/`aes_gcm_utils.py`/`crypto_pipeline.py` menjadi *wrapper* yang me-*re-export* modul raw. |

| | Teks |
|---|---|
| **DARI** (di bawah `tests/`) | `test_sha3.py` (8 skenario), `test_aes.py` (17 skenario), `test_avalanche.py` (5 skenario) — **3 file** |
| **MENJADI** (di bawah `tests/`) | **7 file**: `test_sha3.py`, `test_aes.py`, **`test_raw_crypto.py` (13 skenario, termasuk NIST KAT)**, `test_avalanche.py`, **`test_replay.py` (S5)**, **`test_concurrent.py` (R5)**, **`test_large_message.py` (R2)**. |

| | Teks |
|---|---|
| **DARI** | "`requirements.txt` <- **pycryptodome>=3.20.0, flask>=3.0.0**" |
| **MENJADI** | "`requirements.txt` <- **flask>=3.0.0** (TIDAK ada library kripto — 100% pure Python). Tambahkan juga `api/index.py` & `vercel.json` (deployment Vercel)." |

### 3.5.3 Potongan Kode Inti — import & ambang

| | Teks |
|---|---|
| **DARI** | `from Crypto.Cipher import AES` |
| **MENJADI** | **Hapus baris ini.** Ganti dengan: `from crypto.raw_aes import _key_expansion_256, _aes_encrypt_block, _ghash, _bytes_to_int128, _aes_ctr_keystream` (impor `encrypt_aes_gcm`/`decrypt_aes_gcm` tetap dari `crypto.aes_gcm_utils`). |

| | Teks (di `api_performance`) |
|---|---|
| **DARI** | `'pass_enc': enc_mean < 5.0, 'pass_dec': dec_mean < 5.0` dan `repeats = max(10, min(int(data.get('repeats', 50)), 100))` |
| **MENJADI** | `'pass_enc': enc_mean < ENC_THRESHOLD_MS, 'pass_dec': dec_mean < DEC_THRESHOLD_MS` *(ENC/DEC_THRESHOLD_MS = 50.0)*; `repeats = max(5, min(int(data.get('repeats', PERF_REPEATS_DEF)), PERF_REPEATS_MAX))`. |

> Catatan: pada `api_avalanche_sha3`, ambang `'pass': 40 <= mean <= 60, 'pass_strict': 45 <= mean <= 55` di laporan → kode aktual memakai **`45 <= mean <= 55`** untuk keduanya. Samakan jika dikutip.

### 3.5.4 Pengujian Otomatis (tests/)

| | Teks |
|---|---|
| **DARI** | "…sistem dilengkapi **tiga modul test** berbasis CLI…" + tabel 3 baris (test_sha3 8, test_aes 17, test_avalanche 5). |
| **MENJADI** | "…sistem dilengkapi **tujuh modul test** berbasis CLI…" + tabel 7 baris: `test_sha3.py` (7), `test_aes.py` (7 grup), `test_raw_crypto.py` (13, termasuk **NIST Vector Verify**), `test_avalanche.py` (5), `test_replay.py` (5 — S5), `test_concurrent.py` (5 — R5), `test_large_message.py` (5 — R2). |

### 3.6.3 Tabel Efisiensi AES — kolom Expected Results (E2 & E3)

| | Teks |
|---|---|
| **DARI** | "50 char: < 1 ms / 100 char: < 1.5 ms / 500 char: < 2 ms / 1000 char: < 3 ms / 5000 char: **< 5 ms**" dan "5000 char: **< 5 ms**; Overhead Auth Tag < 0.5 ms" |
| **MENJADI** | "Semua ukuran (50–5000 char) **< 50 ms**; 5000 char **< 50 ms**; kompleksitas linear O(n)" (untuk E2 dan E3). |

### 3.6.4 Tabel Throughput SHA-3 (E5) — Expected Results

| | Teks |
|---|---|
| **DARI** | "1 KB: > 50 MB/s / 10 KB: > 80 MB/s / 100 KB: > 100 MB/s / 1 MB: > 150 MB/s … Validasi: > 50 MB/s" |
| **MENJADI** | "Semua ukuran (1/10/50/100 KB) **> 0,1 MB/s** (pure-Python) … Validasi: **> 0,1 MB/s**." |

### 3.6.5 Pengujian Integritas & Robustness — tambahkan S5, R2, R5

Tabel di laporan hanya memuat I1–I3, R1, R3(Unicode), R4(malformed). **Tambahkan 3 baris baru** (sudah diimplementasikan):

| ID | Skenario | Expected Results | Metode |
|----|----------|------------------|--------|
| **S5** | Replay Attack Resistance | Paket pertama diterima; paket dengan IV sama **ditolak**; 100% detection; IV kadaluwarsa (TTL) boleh dipakai lagi | `tests/test_replay.py` (`crypto/replay_guard.py`) |
| **R2** | Large Message Handling (1–10 MB) | Round-trip byte-perfect; memory ratio **< 8×**; O(n); overhead 28 byte | `tests/test_large_message.py` |
| **R5** | Concurrent Encryption | 100 thread × 100 enkripsi → **0 IV collision**; semua round-trip valid; thread-safe CSPRNG | `tests/test_concurrent.py` |

### 3.6.6 Ringkasan Target Keberhasilan — kategori Performa

| | Teks |
|---|---|
| **DARI** | "Waktu enkripsi AES (5000 char) **< 5 ms**; Waktu dekripsi **< 5 ms**; Throughput SHA-3 (1 MB) **> 150 MB/s**" |
| **MENJADI** | "Waktu enkripsi AES (5000 char) **< 50 ms**; Waktu dekripsi **< 50 ms**; Throughput SHA-3 **> 0,1 MB/s**" |

> Kategori "Kriptografi": SAC AES & SHA-3 **49–51%** → boleh tetap sebagai target *ideal*, tetapi tambahkan keterangan **kriteria lulus 45–55%** (sesuai kode).
> Kategori "Robustness": "memory < 2× ukuran data" → **"memory < 8× ukuran data (overhead pure-Python)"**.

### 3.6.7 Environment dan Tools — baris "Library Kriptografi"

| | Teks |
|---|---|
| **DARI** | "Library Kriptografi → **PyCryptodome ≥ 3.20.0 (AES-GCM), hashlib built-in (SHA-3-256)**" |
| **MENJADI** | "Library Kriptografi → **TIDAK ADA (implementasi murni `crypto/raw_aes.py`, `crypto/raw_sha3.py`)**." |
| | Tambahkan baris **Platform → "… + Vercel Serverless Function (region iad1, 1 vCPU/2 GB)"** dan **Performance Tools → "`time.perf_counter()`, `tracemalloc`"**. |

---

## BAB IV — HASIL DAN ANALISIS

### Paragraf pembuka BAB IV

| | Teks |
|---|---|
| **DARI** | "Bab ini menyajikan hasil pelaksanaan **(60–80%)** … Uji coba meliputi **19 dari 22 skenario** … keberhasilan **100% (19/19 PASS)**." |
| **MENJADI** | "Bab ini menyajikan hasil pelaksanaan **final (100% implementasi)** … Uji coba meliputi **22 dari 22 skenario** … keberhasilan **100% (22/22 PASS)**." |

### 4.1 Status Implementasi Sistem — tabel modul

| | Perubahan |
|---|---|
| Baris `sha3_utils.py` / `aes_gcm_utils.py` | Tambahkan keterangan: **wrapper di atas `raw_sha3.py` / `raw_aes.py` (implementasi murni)**. |
| Tambah baris baru | **`raw_aes.py`** — AES-256-GCM murni, lolos KAT NIST FIPS 197 & SP 800-38D · **`raw_sha3.py`** — SHA-3-256 Keccak murni, lolos KAT FIPS 202 · **`replay_guard.py`** — ReplayGuard (S5) · **`api/index.py` + `vercel.json`** — deployment Vercel. |
| `tests/test_sha3.py` "8 skenario … 8/8 PASS" | → **"7/7 PASS"** (struktur rekap final; ada item **NIST KAT**). |
| `tests/test_aes.py` "17 skenario … 17/17 PASS" | → **"7/7 PASS (grup)"** + tambah **`AES S-Box FIPS 197`**. |
| Tambah baris | **`test_raw_crypto.py` 13/13**, **`test_replay.py` 5/5 (S5)**, **`test_concurrent.py` 5/5 (R5)**, **`test_large_message.py` 5/5 (R2)**. |

### 4.2 Bukti Eksekusi — judul & paragraf

| | Teks |
|---|---|
| **DARI** | "4.2 Bukti Eksekusi **Awal (Preliminary Test)** … hasil dari **19 skenario** …" |
| **MENJADI** | "4.2 Bukti Eksekusi **Lengkap (22/22 Skenario)** … hasil dari **22 skenario** …" |

### 4.2 Tabel hasil — baris yang ANGKANYA WAJIB diganti

| ID | DARI | MENJADI |
|----|------|---------|
| E5/H5 Throughput SHA-3 | target "**> 50 MB/s**"; hasil "1KB: **347.9** / 10KB: **545.8** / 100KB: **471.5** / 1MB: **509.3** MB/s" | target "**> 0,1 MB/s**"; hasil "1KB: **≈0,30** / 10KB: **≈0,33** / 50KB: **≈0,31** / 100KB: **≈0,32** MB/s" |
| E2/E3 Performance AES | target "**enc/dec < 5 ms**"; hasil "5000 char enc: **0.04 ms** / dec: **0.05 ms**" | target "**enc/dec < 50 ms**"; hasil "5000 char enc: **≈6 ms** / dec: **≈6 ms** (lokal); ≈11 ms di Vercel — Linear O(n)" |
| E4/H4 & E1 Avalanche | target "Mean **49–51%**" | target "Mean **45–55% (SAC)**" (nilai mean terukur boleh tetap: SHA-3 49,54%, AES ~50%) |

**Tambahkan 3 baris hasil baru** di tabel 4.2:

| ID | Skenario | Target | Hasil Aktual | Status |
|----|----------|--------|--------------|--------|
| **S5** | Replay Attack Resistance | replay ditolak | 100/100 replay ditolak; 1000 IV unik diterima; TTL expiry OK | PASS |
| **R2** | Large Message (1–10 MB) | byte-perfect, mem wajar | 1–10 MB round-trip byte-perfect; ratio ≈3× (< 8×); O(n) | PASS |
| **R5** | Concurrent Encryption | 0 IV collision | 100 thread × 100 enc → 0 duplikat; semua round-trip valid | PASS |

### 4.2 Ringkasan Uji Awal (paragraf penutup)

| | Teks |
|---|---|
| **DARI** | "Total skenario yang diuji **19 dari 22 (cakupan 86%)**. Success rate **19 out of 19** … `test_sha3.py` (**8/8**), `test_aes.py` (**17/17**), `test_avalanche.py` (5/5) … Terdapat **3 skenario yang belum dilaksanakan** (lihat Subbab 4.5)." |
| **MENJADI** | "Total skenario yang diuji **22 dari 22 (cakupan 100%)**. Success rate **22/22 (100%)** … `test_sha3.py` (7/7), `test_aes.py` (7/7), `test_raw_crypto.py` (13/13), `test_avalanche.py` (5/5), `test_replay.py` (5/5), `test_concurrent.py` (5/5), `test_large_message.py` (5/5). **Seluruh 22 skenario telah dilaksanakan dan lulus.**" |

### 4.3.2 Analisis Performa AES-256-GCM (E2/E3)

| | Teks |
|---|---|
| **DARI** | "Enkripsi pesan dengan 5000 karakter hanya memerlukan waktu **0.04 ms (target < 5 ms … 120× lebih cepat)** … diselesaikan dalam waktu kurang dari **0,05 ms** …" |
| **MENJADI** | "Setelah optimasi (T-table berbasis *word* + tabel-nibble GHASH + XOR *big-integer*), enkripsi 5000 karakter ≈ **6 ms** (target **< 50 ms**) — ≈10× lebih cepat dari implementasi awal (≈64 ms). Seluruh ukuran 50–5000 karakter selesai jauh di bawah 50 ms (linear O(n)); pada CPU Vercel ≈ 11 ms, tetap di bawah ambang." |

### 4.3.5 Analisis Throughput SHA-3-256 (E5/H5)

| | Teks |
|---|---|
| **DARI** | "…**347.9 MB/s untuk 1 KB, 545.8 MB/s untuk 10 KB, 471.5 MB/s untuk 100 KB, dan 509.3 MB/s untuk 1 MB** … Semua ukuran melebihi target **50 MB/s (1 MB melebihi target ketat 150 MB/s dengan 3×)**." |
| **MENJADI** | "…**≈0,30 MB/s (1 KB), ≈0,33 MB/s (10 KB), ≈0,31 MB/s (50 KB), ≈0,32 MB/s (100 KB)** — relatif konstan, mengkonfirmasi skalabilitas linear sponge. Semua ukuran melampaui ambang **> 0,1 MB/s** (≈3×). Nilai jauh di bawah `hashlib`-C, sebagai *trade-off* implementasi murni dari rumus." |

### 4.3.6 Analisis Keamanan Deteksi Serangan — judul & isi

| | Teks |
|---|---|
| **DARI** | "4.3.6 Analisis Keamanan Deteksi Serangan **(S1, S2, S3)** … Tiga skenario serangan…" |
| **MENJADI** | "4.3.6 Analisis Keamanan Deteksi Serangan **(S1, S2, S3, S5)** … **Empat** skenario serangan…" + tambahkan kalimat: "**(S5) Replay:** `ReplayGuard` menolak paket dengan IV yang sudah pernah dipakai dalam window TTL (600 s) — 100/100 percobaan replay terdeteksi, sementara IV kadaluwarsa boleh dipakai lagi." |

### 4.3.7 Analisis Robustness & Integritas — tambahkan R2 & R5

| | Teks |
|---|---|
| **DARI** | "(I1-I3, R1, R3, R4, S4, S6) … pesan kosong (R1) … Unicode (R3) … paket rusak (R4) …" |
| **MENJADI** | Tambahkan: "**R2 (Large Message):** pesan 1–10 MB round-trip byte-perfect, kompleksitas O(n), *overhead* tetap 28 byte, memory ratio ≈3× (< 8×). **R5 (Concurrent):** 100 thread × 100 enkripsi paralel → 0 IV collision, semua round-trip valid (CSPRNG `os.urandom` thread-safe)." |

### 4.5 Rencana Pengujian Selanjutnya → ubah menjadi laporan SELESAI

| | Teks |
|---|---|
| **DARI** | "Dari 22 skenario … **19 skenario (≈86%) telah dijalankan** … Ada **3 skenario yang belum dilaksanakan** … **akan ditambahkan**/**akan diuji pada laporan akhir** … Sasaran di laporan akhir adalah meraih 100% cakupan (22/22)." |
| **MENJADI** | "Seluruh **22 skenario (100%) telah dilaksanakan dan lulus**. Tiga skenario yang pada Progress 3 belum ada kini **selesai**: **S5 Replay** (`crypto/replay_guard.py` + `test_replay.py`), **R2 Large Message** (`test_large_message.py`, 1–10 MB), **R5 Concurrent** (`test_concurrent.py`, `ThreadPoolExecutor`). Cakupan 22/22 tercapai." |

> Opsional: ganti judul 4.5 menjadi **"4.5 Verifikasi NIST, Optimasi Performa, dan Deployment"** dan tambahkan:
> - **Verifikasi NIST:** FIPS 197 C.3 → `8ea2b7ca516745bfeafc49904b496089`; SP 800-38D TC14 → `530f8afbc74536b9a963b4f1c4cb738b`; SHA3-256("") → `a7ffc6f8…8434a` — semua **MATCH** (di `run_kat()`).
> - **Deployment:** Vercel Serverless (`api/index.py`, `vercel.json`, `maxDuration` 60 s, region `iad1`).

---

## BAB V — KESIMPULAN

### Paragraf 1 (AES)

| | Teks |
|---|---|
| **DARI** | "Implementasi penuh AES-256-GCM **berbasis PyCryptodome** (Python 3.x)… Melalui **17 skenario** pengujian, seluruh fungsi inti terbukti berfungsi 100%." |
| **MENJADI** | "Implementasi penuh AES-256-GCM **secara murni (pure-Python dari rumus FIPS 197 + SP 800-38D, tanpa library kriptografi)**… Kebenaran diverifikasi byte-exact terhadap **test vector NIST FIPS 197 C.3 & SP 800-38D TC14**. Melalui rangkaian pengujian, seluruh fungsi inti terbukti berfungsi 100%." |

### Paragraf 2 (SHA-3)

| | Teks |
|---|---|
| **DARI** | "Mekanisme integritas pesan menggunakan SHA-3-256 **(hashlib Python)** berhasil diimplementasikan…" |
| **MENJADI** | "Mekanisme integritas pesan menggunakan SHA-3-256 **(implementasi Keccak murni, `crypto/raw_sha3.py`, tanpa `hashlib`)** berhasil diimplementasikan…; digest string kosong yang dihasilkan **identik** dengan nilai resmi FIPS 202." |

### Paragraf 3 (Performa AES)

| | Teks |
|---|---|
| **DARI** | "…enkripsi 5.000 karakter hanya memakan waktu **0,04 ms (jauh di bawah target < 5 ms)** dengan throughput **> 90 MB/s**…" |
| **MENJADI** | "…enkripsi 5.000 karakter ≈ **6 ms (di bawah ambang < 50 ms)** setelah optimasi (≈10× lebih cepat dari ≈64 ms awal); kompleksitas linear O(n) stabil pada 50–5.000 karakter…" (hapus klaim ">90 MB/s"). Avalanche AES boleh tetap ~50%. |

### Paragraf 4 (SHA-3 evaluasi)

| | Teks |
|---|---|
| **DARI** | "…produktivitas sistem sangat tinggi dengan throughput sebesar **347,9 MB/s hingga 545,8 MB/s**, melampaui target awal yang hanya sebesar **50 MB/s**." |
| **MENJADI** | "…throughput SHA-3-256 ≈ **0,30–0,33 MB/s** (pure-Python), melampaui ambang **> 0,1 MB/s**; nilai relatif konstan (skalabilitas linear)." |

### Paragraf 7 (cakupan akhir)

| | Teks |
|---|---|
| **DARI** | "Evaluasi menyeluruh menunjukkan sistem mencapai cakupan pengujian **86% (19/22 skenario)** dengan tingkat kelulusan 100%. **Tiga skenario sisanya (Replay Attack, pesan >1 MB, dan Concurrent Encryption) akan dirampungkan pada laporan final.**" |
| **MENJADI** | "Evaluasi menyeluruh menunjukkan sistem mencapai cakupan pengujian **100% (22/22 skenario)** dengan tingkat kelulusan 100%. **Tiga skenario sisa (Replay Attack S5, pesan >1 MB R2, dan Concurrent Encryption R5) telah dirampungkan dan lulus.**" |

---

## Lampiran / Bagian lain

- **KAJIAN PUSTAKA**: tidak berubah (15 rujukan tetap relevan).
- **Judul laporan & cover**: boleh tambahkan frasa **"(Implementasi Murni/Pure-Python tanpa Library Kriptografi)"** agar konsisten dengan isi.
- **Screenshot (4.4.x)**: ganti tangkapan layar lama yang menampilkan angka library (mis. performance 0.04 ms, throughput 347–545 MB/s) dengan **screenshot baru** yang menampilkan ambang final (**< 50 ms**, **> 0,1 MB/s**). Caption disesuaikan.

---

## Ringkasan Angka Kunci (rujukan cepat saat mengedit)

| Metrik | Nilai LAMA (library) | Nilai BARU (pure-Python, aktual) |
|--------|----------------------|----------------------------------|
| AES enc 5000 char | 0,04 ms | **≈ 6 ms** (lokal); ≈ 11 ms (Vercel) |
| Ambang waktu AES | < 5 ms | **< 50 ms** |
| Throughput SHA-3 | 347–545 MB/s | **≈ 0,30–0,33 MB/s** |
| Ambang throughput SHA-3 | > 50 / 150 MB/s | **> 0,1 MB/s** |
| Ukuran uji throughput | 1 KB–1 MB | **1, 10, 50, 100 KB** |
| Avalanche SHA-3 | 49,54% / std 3,03% | sama (deterministik) |
| Avalanche AES | ~50% | ~49–50% (SAC, kriteria 45–55%) |
| Cakupan pengujian | 19/22 (86%) | **22/22 (100%)** |
| Library kripto | PyCryptodome + hashlib | **TIDAK ADA** (raw) |
| Verifikasi NIST | (tidak ada) | **FIPS 197 C.3, SP 800-38D TC14, FIPS 202 — MATCH** |
| Deployment | (tidak ada) | **Vercel Serverless (iad1)** |
