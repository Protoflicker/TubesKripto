# LAPORAN PROGRESS 2 - TUGAS BESAR KRIPTOGRAFI
## IMPLEMENTASI AES-256-GCM DAN SHA-3-256 UNTUK KEAMANAN PESAN PADA APLIKASI SECURE MESSAGING E-HEALTH ANTARA DOKTER DAN PASIEN

[![Python Version](https://img.shields.io/badge/Python-3.10%20%7C%203.11%20%7C%203.12%20%7C%203.13-blue.svg)](https://www.python.org)
[![Security](https://img.shields.io/badge/Security-AES--256--GCM%20%2B%20SHA--3--256-orange.svg)](#)
[![Dependencies](https://img.shields.io/badge/Crypto-100%25%20Pure%20Python%20(tanpa%20library)-green.svg)](#)
[![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux%20%7C%20macOS%20%7C%20Vercel-lightgrey.svg)](#)
[![Group](https://img.shields.io/badge/Kelompok-7-purple.svg)](#)

### Kelompok 7
* Febrian Valentino Nugroho (123140034)
* Anselmus Herpin Hasugian (123140020)
* Adi Septriansyah (123140021)
* Ola Anggela Rosita (123140042)
* Vebri Yanti (123140056)
* M. Irsyad Ali. KM (123140110)

**PROGRAM STUDI TEKNIK INFORMATIKA**
**FAKULTAS TEKNOLOGI INDUSTRI**
**INSTITUT TEKNOLOGI SUMATERA**
**2026**

---

## Daftar Isi
1. [Pendahuluan](#1-pendahuluan)
2. [Landasan Teori](#2-landasan-teori)
3. [Parameter Teknis Sistem](#3-parameter-teknis-sistem)
4. [Arsitektur Sistem End-to-End](#4-arsitektur-sistem-end-to-end)
5. [Perancangan Alur Kerja (Flowchart)](#5-perancangan-alur-kerja-flowchart)
6. [Panduan Instalasi dan Pengoperasian](#6-panduan-instalasi-dan-pengoperasian)
7. [Rencana Evaluasi](#7-rencana-evaluasi)
8. [Kajian Pustaka](#8-kajian-pustaka)

---

## 1. Pendahuluan

Digitalisasi kesehatan telah melahirkan era telemedicine dan e-health yang memfasilitasi pertukaran informasi medis secara daring. Meski mencakup data sensitif seperti rekam medis dan resep yang dilindungi oleh UU No. 27 Tahun 2022 (PDP), banyak platform komunikasi klinis saat ini masih minim pengamanan kriptografis. Hal ini menimbulkan risiko serius terhadap ancaman penyadapan, serangan man-in-the-middle, serta manipulasi data.

Kerahasiaan (confidentiality) dan integritas (integrity) merupakan dua pilar utama yang wajib dipenuhi dalam sistem komunikasi medis. Aspek kerahasiaan menjamin privasi informasi hanya bagi pihak resmi, sedangkan integritas menjaga keaslian data agar tidak berubah selama pengiriman. Kegagalan dalam mengimplementasikan keduanya dapat mengubah saluran komunikasi kesehatan menjadi titik rawan kebocoran data yang mengancam nyawa pasien serta kredibilitas institusi.

Sebagai standar industri global, Advanced Encryption Standard dalam mode Galois/Counter Mode (AES-256-GCM) merupakan algoritma enkripsi simetris yang sangat kredibel. Berdasarkan spesifikasi NIST dalam FIPS 197 dan SP 800-38D, algoritma ini menerapkan mekanisme Authenticated Encryption with Associated Data (AEAD) yang mampu menjalankan fungsi kerahasiaan sekaligus otentikasi dalam satu proses terpadu. Melalui perpaduan Counter Mode (CTR) dan fungsi GHASH, AES-256-GCM menghasilkan ciphertext serta authentication tag 128-bit untuk memvalidasi integritas data.

SHA-3 hadir sebagai standar fungsi hash kriptografis modern yang membawa perubahan arsitektur signifikan dibanding generasi sebelumnya. Berbeda dengan pendahulunya, SHA-1 dan SHA-2 yang menggunakan struktur Merkle-Damgard, SHA-3 menerapkan Sponge Construction. Inovasi ini memberikan ketahanan fundamental yang lebih kuat terhadap serangan length extension serta kriptanalisis diferensial. Dengan algoritma SHA-3-256, input data apa pun akan diolah menjadi message digest 256-bit yang bersifat deterministik dan memenuhi Strict Avalanche Criterion (SAC), di mana perubahan minimal pada input akan mengakibatkan perubahan signifikan pada setengah dari bit output-nya.

Proyek ini menerapkan sistem keamanan berlapis pada aplikasi e-health messaging berbasis Python dengan mengintegrasikan algoritma AES-256-GCM dan SHA-3-256. Dalam alurnya, pengirim menghasilkan hash SHA-3-256 dari plaintext yang kemudian digabungkan ke dalam payload sebelum disandikan sepenuhnya dengan AES-256-GCM. Di sisi penerima, proses dekripsi diikuti dengan ekstraksi pesan serta kalkulasi ulang hash untuk verifikasi integritas. Arsitektur ini menciptakan perlindungan ganda: Authentication Tag dari AES-GCM menjamin keamanan selama transmisi, sementara SHA-3-256 berfungsi sebagai audit trail integritas jangka panjang bagi data yang telah diterima.

---

## 2. Landasan Teori

### Kriptografi Modern
Kriptografi modern dapat dipahami sebagai konvergensi antara teori bilangan, aljabar abstrak, dan rekayasa perangkat lunak untuk melindungi informasi digital. Cabang besar yang umum diadopsi adalah kriptografi simetris dan fungsi hash kriptografis. Kombinasi simetris dan hash terbukti efektif untuk melindungi pertukaran pesan. Pendekatan berlapis semacam ini memberikan keseimbangan antara forward security dan kompleksitas implementasi yang masih realistis bagi tim pengembang.

### Advanced Encryption Standard (AES-256-GCM)
AES adalah cipher blok berbasis jaringan substitusi-permutasi yang beroperasi pada blok 128-bit. Varian AES-256 menggunakan 14 ronde dengan empat transformasi inti: SubBytes, ShiftRows, MixColumns, dan AddRoundKey yang secara kolektif menghasilkan efek difusi dan konfusi tinggi. Mode GCM (Galois/Counter Mode) memperluas AES menjadi skema AEAD dengan menggabungkan Counter Mode dan fungsi otentikasi GHASH di atas field GF(2^128). Hal ini mampu berjalan dengan efisiensi tinggi pada arsitektur perangkat keras dan perangkat lunak modern.

### Fungsi Hash Kriptografis - SHA-3-256 (Keccak)
SHA-3 dibakukan NIST pada FIPS 202 berdasarkan pemenang kompetisi Keccak. Yang membedakannya dari SHA-2 adalah Sponge Construction dengan permutasi Keccak-f[1600]: input diserap (absorbing) ke state 1600-bit, lalu digest diperas keluar (squeezing) sepanjang yang diinginkan. Konstruksi ini menutup celah length-extension yang melekat pada keluarga Merkle-Damgard. SHA-3-256 mencatat rata-rata perubahan bit paling stabil di kisaran 49.9% - 50.1% (Strict Avalanche Criterion), menjadikannya ideal untuk verifikasi integritas pada data berukuran heterogen.

---

## 3. Parameter Teknis Sistem

Sistem dikonfigurasi dengan spesifikasi teknis dan algoritma teruji untuk menjamin kepatuhan penuh terhadap standar industri:

| Parameter | Nilai / Keterangan |
| --- | --- |
| Aturan Kombinasi | Kriptografi Simetris + Fungsi Hash |
| Algoritma Simetris | AES-256-GCM (AEAD) |
| Panjang Kunci AES | 256 bit (32 byte) |
| Mode Operasi | GCM (Galois/Counter Mode) - NIST SP 800-38D |
| IV (Initialization Vector) | 96 bit (12 byte), dibangkitkan acak kriptografis per sesi |
| Authentication Tag | 128 bit (16 byte) |
| Algoritma Hash | SHA-3-256 (Keccak-based Sponge - FIPS 202) |
| Panjang Digest SHA-3-256 | 256 bit (32 byte) |
| Jenis Pesan | Teks (Text) - Bahasa Indonesia / Inggris |
| Bahasa Pemrograman | Python 3.x |
| Library Python | PyCryptodome (AES-GCM), hashlib built-in (SHA-3-256) |
| Sumber Keacakan | os.urandom / secrets (CSPRNG OS) |
| Domain Aplikasi | Aplikasi secure messaging e-health dokter-pasien |

---

## 4. Arsitektur Sistem End-to-End

Arsitektur sistem terdiri atas tiga tingkat pokok yang terhubung secara logis: Tingkat Pengirim (Dokter), Saluran Transmisi yang Terenkripsi, dan Tingkat Penerima (Pasien).

Berikut adalah gambaran arsitektur sistem secara visual:

![Arsitektur Sistem](Assets/arsitektursistem.png)

![Arsitektur Detail Sistem Enkripsi dan Dekripsi](<Assets/arsitektur sistem enkripisi & deksripi   .png>)

### Komponen Lapisan Pengirim (Dokter)

| Komponen | Library / Tool | Fungsi dalam Sistem |
| --- | --- | --- |
| Modul Input | Python built-in | Antarmuka bagi dokter untuk mengetik pesan medis dalam format teks biasa dengan encoding UTF-8. |
| Modul SHA-3-256 | Hashlib (stdlib) | Menghitung hash 256-bit dari teks asli dengan menggunakan Konstruksi Spons Keccak. |
| Modul Payload Builder | Python built-in | Menggabungkan plaintext, pemisah '\|\|HASH\|\|', dan hash SHA-3-256 menjadi satu payload string. |
| Modul AES-256-GCM Engine | PyCryptodome | Membangkitkan IV 96-bit secara acak kriptografis (CSPRNG), mengenkripsi payload, dan membuat Auth Tag 128-bit. |
| Modul Packet Builder | Python built-in | Menyusun paket transmisi dengan format biner tetap: IV (12 byte) + Auth Tag (16 byte) + Ciphertext (N byte). |

### Komponen Lapisan Penerima (Pasien)

| Komponen | Gerbang Keamanan | Fungsi dan Mekanisme Deteksi |
| --- | --- | --- |
| Modul Packet Parser | - | Memisahkan paket biner yang diterima menjadi IV (12 byte), Auth Tag (16 byte), dan Ciphertext. |
| Modul AES-256-GCM Decrypt | Gerbang 1 (Auth Tag) | Mendekripsi ciphertext. Memverifikasi Auth Tag secara atomik via GHASH. Jika modifikasi terdeteksi, melempar ValueError dan proses dihentikan. |
| Modul Payload Splitter | - | Membagi payload hasil dekripsi berdasarkan pemisah '\|\|HASH\|\|' menjadi plaintext dan hash yang diterima. |
| Modul SHA-3-256 Verifier | Gerbang 2 (Hash) | Menghitung ulang hash SHA-3-256 dari plaintext hasil dekripsi dan membandingkannya secara constant-time dengan hash yang diterima. |
| Modul Output | - | Menampilkan pesan medis kepada pasien jika kedua gerbang keamanan lolos. Jika tidak, proses ditolak dengan pesan kesalahan. |

---

## 5. Perancangan Alur Kerja (Flowchart)

Alur kerja kriptografi sistem dibagi menjadi dua proses utama: proses enkripsi di sisi pengirim (dokter) dan proses dekripsi di sisi penerima (pasien).

### Flowchart Proses Enkripsi (Pengirim)

Berikut adalah visualisasi alur enkripsi di pihak dokter:

![Flowchart Enkripsi](<Assets/flowchart enkripsis pengirim dokter.jpeg>)

### Flowchart Proses Dekripsi (Penerima)

Berikut adalah visualisasi alur dekripsi di pihak pasien:

![Flowchart Dekripsi](<Assets/flowchart deksripsi penerima pasien.png>)

### Rincian Langkah Enkripsi (6 Tahap)

1. **Input Plaintext**: Dokter menginput pesan medis. Pesan diubah menjadi byte menggunakan codec UTF-8 untuk mendukung karakter multibahasa dan simbol medis khusus.
2. **Hitung SHA-3-256**: Menghitung digest SHA-3-256 dari plaintext menggunakan algoritma Keccak-f[1600] (r = 1088 bit, c = 512 bit) untuk menghasilkan string heksadesimal 64 karakter.
3. **Susun Payload**: Menggabungkan plaintext dan digest dengan separator deterministik: `payload = plaintext + '||HASH||' + digest`.
4. **Bangkitkan IV 96-bit**: Menghasilkan IV 96-bit (12 byte) unik per sesi menggunakan `os.urandom()` (CSPRNG OS). IV tidak boleh diulang untuk kunci yang sama.
5. **AES-256-GCM Encrypt**: Melakukan enkripsi payload menggunakan mode CTR untuk menghasilkan ciphertext, serta GHASH untuk menghasilkan Auth Tag 128-bit (16 byte).
6. **Susun Paket Output**: Menggabungkan komponen biner: `paket = IV (12 byte) + Auth Tag (16 byte) + Ciphertext`.

### Rincian Langkah Dekripsi (5 Tahap + 2 Keputusan)

1. **Terima Paket**: Penerima menerima paket byte biner dari jaringan.
2. **Urai Paket**: Memotong paket berdasarkan offset tetap: `IV = packet[:12]`, `Auth Tag = packet[12:28]`, dan `Ciphertext = packet[28:]`.
3. **[Keputusan 1] AES-GCM Decrypt + Verifikasi Auth Tag**: Mendekripsi ciphertext dan memverifikasi Auth Tag secara bersamaan. Jika ciphertext atau tag dimodifikasi, GHASH mendeteksi ketidakcocokan, memicu ValueError, dan menolak pesan (mencegah serangan MITM).
4. **Pisah Payload**: Memecah payload yang sukses didekripsi menggunakan pemisah `||HASH||` menjadi plaintext dan hash yang dikirimkan.
5. **[Keputusan 2] Verifikasi SHA-3-256**: Menghitung ulang hash SHA-3-256 dari plaintext hasil dekripsi dan membandingkannya secara byte-per-byte dengan hash yang dikirimkan. Jika tidak cocok, integritas pesan rusak dan pesan ditolak.

---

## 6. Panduan Instalasi dan Pengoperasian

### Prasyarat
* Python 3.10 atau versi terbaru
* Pustaka `flask` (untuk antarmuka web). Operasi kriptografi AES-GCM & SHA-3
  diimplementasikan 100% pure Python sehingga **tidak** memerlukan library kriptografi eksternal.

### Langkah 1 - Clone Repository
```bash
git clone https://github.com/forkaton/TubesKriptografi.git
cd TubesKriptografi
```

### Langkah 2 - Instalasi Dependensi
```bash
pip install -r requirements.txt
```

### Langkah 3 - Konfigurasi Terminal (Sistem Operasi Windows)
Secara default, terminal Windows menggunakan encoding CP1252. Agar simbol khusus (seperti tanda centang dan garis pembatas) dapat tercetak dengan benar tanpa menyebabkan error, jalankan perintah berikut:

**PowerShell:**
```powershell
$env:PYTHONIOENCODING="utf-8"
```

**Command Prompt (CMD):**
```cmd
set PYTHONIOENCODING=utf-8
```

### Langkah 4 - Menjalankan Demo Utama
Menjalankan skrip demo e-health messaging terpadu (Skenario Transmisi Normal, Deteksi Serangan MITM, Deteksi Kunci Salah, dan Uji Avalanche Effect):
```bash
python demo.py
```

### Langkah 5 - Menjalankan Pengujian Avalanche Effect & Statistik
Untuk menjalankan evaluasi performa dan ketahanan statistik sistem:
```bash
python tests/test_avalanche.py
```

### Langkah 6 - Deployment ke Vercel (Opsional)
Aplikasi web (`app.py`) dapat di-hosting gratis di [Vercel](https://vercel.com) sebagai
serverless function. Repositori sudah menyertakan konfigurasi `vercel.json` dan
`.vercelignore`, serta `requirements.txt` yang ramping (hanya `flask`, karena seluruh
kriptografi adalah pure Python tanpa library eksternal).

**Cara deploy (via dashboard):**
1. Push repositori ke GitHub/GitLab.
2. Di Vercel, pilih **Add New → Project**, lalu impor repositori ini.
3. Vercel otomatis mendeteksi `vercel.json` dan runtime Python — klik **Deploy**.

**Cara deploy (via CLI):**
```bash
npm i -g vercel
vercel        # preview deployment
vercel --prod # production deployment
```

**Catatan tentang performa di serverless.** Fungsi serverless Vercel memiliki batas waktu
eksekusi (default ~10 detik). **Ambang/kriteria lulus dibuat IDENTIK** di lokal maupun
Vercel — enkripsi/dekripsi `< 50 ms` dan throughput hash `> 0.1 MB/s` — tidak dilonggarkan.

Karena implementasi 100% pure Python, aplikasi mendeteksi lingkungan Vercel (env var
`VERCEL`) dan **hanya memperkecil beban uji** (jumlah iterasi/repeats/pasangan), **bukan
kriteria lulus**. Tujuannya semata-mata agar setiap endpoint selesai sebelum batas waktu
fungsi; jika uji beban penuh (mis. 10.000–50.000 hash pure-Python) dipaksakan, fungsi akan
*timeout* dan tidak mengembalikan hasil sama sekali. Nilai waktu/throughput per-operasi
tidak dipengaruhi oleh jumlah repeats, sehingga kriteria tetap diuji secara adil.

> ⚠️ **Perhatian:** karena kriteria waktu/throughput bergantung pada kecepatan CPU, uji
> `Performance` (baris 5000 char) dan `Throughput SHA-3` (ukuran kecil) **bisa saja**
> menunjukkan GAGAL bila CPU instance Vercel lebih lambat dari PC Anda. Uji yang
> CPU-independen (Avalanche/SAC dan Collision = 0) dijamin tetap LULUS. Jika ingin ambang
> waktu/throughput dilonggarkan khusus di serverless, ubah konstanta `ENC_THRESHOLD_MS`,
> `DEC_THRESHOLD_MS`, dan `HASH_MIN_MBS` di blok `if ON_VERCEL:` pada `app.py`.

---

## 7. Rencana Evaluasi

### Evaluasi AES-256-GCM

| No | Parameter Uji | Target / Hasil yang Diharapkan |
| --- | --- | --- |
| 1 | Avalanche Effect AES | Mengubah 1 bit pada plaintext atau kunci, lalu menghitung persentase perubahan bit pada ciphertext. Rata-rata perubahan bit harus berada di kisaran 49% - 51% (memenuhi Strict Avalanche Criterion). |
| 2 | Waktu Komputasi Enkripsi & Dekripsi | Mengukur durasi komputasi (milidetik) untuk pesan berukuran 50, 100, 500, 1000, dan 5000 karakter. Target waktu enkripsi adalah kurang dari 5 ms untuk data berukuran 5000 karakter. |

### Evaluasi SHA-3-256

| No | Parameter Uji | Target / Hasil yang Diharapkan |
| --- | --- | --- |
| 1 | Collision Resistance Test | Menguji 10.000 pasang pesan acak untuk mendeteksi kolisi hash. Target yang diharapkan adalah nol kolisi (Zero Collision), sesuai batas kekuatan birthday bound 2^128. |
| 2 | Avalanche Effect Hash | Mengubah 1 bit pada input pesan dan mengukur persentase perubahan bit pada output digest. Rata-rata perubahan harus berkisar di sekitar ~50% (~128 bit berubah dari 256 bit). |
| 3 | Kecepatan Hashing (Throughput) | Mengukur kecepatan hashing (MB/s) untuk input 1 KB, 10 KB, 100 KB, dan 1 MB. Target throughput SHA-3-256 adalah lebih dari 500 MB/s pada CPU modern. |

---

## 8. Kajian Pustaka

[1] Soni, A., Sahay, S.K., dan Mehta, P. (2025). "AESHA3: Efficient and Secure Sub-Key Generation for AES Using SHA-3." Dalam: Broadband Communications, Networks, and Systems. BROADNETS 2024. Lecture Notes ICST, Vol.601, Springer. DOI: 10.1007/978-3-031-81168-5_5

[2] Cibik, P. et al. (2024). "Pushing AES-256-GCM to Limits: Design, Implementation and Real FPGA Tests." Applied Cryptography and Network Security Workshops (ACNS 2024). LNCS Vol.14586, Springer. DOI: 10.1007/978-3-031-61486-6_18

[3] Nik-Lah, N.A. et al. (2022). "Developing a New Collision-Resistant Hashing Algorithm." Mathematics, MDPI, Vol.10, No.15, Article 2769. DOI: 10.3390/math10152769

[4] Ata, O. et al. (2025). "Implementation of Secure End-to-End Encrypted Chat Application Using Diffie-Hellman Key Exchange and AES-256 in a Microservice Architecture." Engineering Proceedings, MDPI, Vol.107, No.1, Article 98. DOI: 10.3390/engproc2025107098

[5] Goel, A., Baliyan, H., Tyagi, S., dan Bansal, N. (2024). "End to End Encryption of Chat Using Advanced Encryption Standard-256." International Journal of Science and Research Archive (IJSRA), Vol.12, No.01, pp.2018-2025.

[6] Alhumrani, M.A. et al. (2025). "A panoramic survey of the advanced encryption standard: from architecture to security analysis, key management, real-world applications, and post-quantum challenges." International Journal of Information Security, Springer. DOI: 10.1007/s10207-025-01116-x

[7] Upadhyay, D., Gaikwad, N., Zaman, M., dan Sampalli, S. (2022). "Investigating the Avalanche Effect of Various Cryptographically Secure Hash Functions and Hash-Based Applications." IEEE Access, Vol.10. DOI: 10.1109/ACCESS.2022.3199993

[8] Penulis Kolektif. (2025). "Computational Analysis of Cryptographic Hash Function Performance and Security." AI Agents for Science Workshop (agents4science 2025). OpenReview.

[9] Erigbe, S.O. dan Erigbe, P.A. (2025). "Evaluation of AES-256 Encryption and Machine Learning for Securing GSM Communications Against Sniffing Attacks." Egyptian Informatics Journal, Elsevier. DOI: 10.1016/j.eij.2025.100550

[10] Hongal, R. et al. (2024). "Investigation of Crypto-Algorithms for Stability Assessment." Procedia Computer Science, Elsevier, Vol.237, pp.389-396. DOI: 10.1016/j.procs.2024.05.333

[11] S. Ricci, P. Dobias, L. Malina, J. Hajny and P. Jedlicka, "Hybrid Keys in Practice: Combining Classical, Quantum and Post-Quantum Cryptography," in IEEE Access, vol. 12, pp. 23206-23219, 2024, doi: 10.1109/ACCESS.2024.3364520.

[12] Fathurrozi, A. dan Selviyani. (2021). "Penerapan Algoritma Advanced Encryption Standard (AES-256) dengan Mode CBC dan Secure Hash Algorithm (SHA-256) untuk Pengamanan Data File." Journal of Information and Information Security (JIFORTY), Vol.2, No.2, pp.227-238.

[13] Utama, F.P. et al. (2023). "Implementasi Algoritma AES 256 CBC, BASE 64, dan SHA 256 dalam Pengamanan dan Validasi Data Ujian Online." Jurnal Teknologi Informasi dan Ilmu Komputer (JTIIK), Universitas Brawijaya, Vol.10, No.5. DOI: 10.25126/jtiik.2023106558

[14] Saharan, M. et al. (2024). "Secure End-to-End Chat Application: A Comprehensive Guide." Review of Computer Engineering Studies, Vol.11, No.3. DOI: 10.0410/cata/b5599df45a989f8e2a7ca627c8b5b625

[15] Penulis. (2024). "Implementasi Teknik Kriptografi dengan Metode AES 256 untuk Keamanan File." INTEC: Information Technology Education Journal, Universitas Negeri Makassar, Vol.3, No.3, pp.84-87.
