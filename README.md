# 🔐 Sistem E-Health Secure Messaging
### AES-256-GCM + SHA-3-256 — Kelompok 7 Kriptografi Genap 2026 — ITERA

Sistem kriptografi untuk pengiriman pesan medis yang aman menggunakan enkripsi **AES-256-GCM** (kerahasiaan + autentikasi) dikombinasikan dengan hashing **SHA-3-256** (integritas). Proyek ini dibangun untuk membuktikan ketahanan sistem terhadap serangan **Man-in-the-Middle (MITM)** dan pemalsuan data.

---

## 📁 Struktur Proyek

```
ehealth_crypto/
├── crypto/
│   ├── __init__.py           # Python package marker
│   ├── sha3_utils.py         # Modul hashing SHA-3-256
│   ├── aes_gcm_utils.py      # Modul enkripsi/dekripsi AES-256-GCM
│   └── crypto_pipeline.py    # Pipeline gabungan SHA-3 + AES-GCM
├── tests/
│   ├── test_sha3.py          # (stub)
│   ├── test_aes.py           # (stub)
│   └── test_avalanche.py     # Evaluasi Avalanche Effect & Collision Resistance
├── demo.py                   # Demo 3 skenario utama + bonus
├── test_sha3_script.py       # Verifikasi cepat SHA-3-256
└── requirements.txt          # Dependensi: pycryptodome>=3.20.0
```

---

## ⚙️ Prasyarat

- **Python 3.10 atau lebih baru** (direkomendasikan Python 3.12 / 3.13)
- **Git**
- Koneksi internet (untuk install dependensi pertama kali)

Cek versi Python kamu:
```bash
python --version
```

---

## 🚀 Cara Menjalankan (Step by Step)

### Langkah 1 — Clone Repository

```bash
git clone https://github.com/forkaton/TubesKriptografi.git
cd TubesKriptografi
```

### Langkah 2 — Install Dependensi

```bash
pip install -r requirements.txt
```

Verifikasi instalasi berhasil:
```bash
python -c "from Crypto.Cipher import AES; print('pycryptodome OK ✓')"
```

### Langkah 3 — Set Encoding (Wajib di Windows)

Jalankan perintah ini **setiap membuka terminal baru** agar karakter ✓ dan — tampil benar:

**PowerShell:**
```powershell
$env:PYTHONIOENCODING="utf-8"
```

**CMD:**
```cmd
set PYTHONIOENCODING=utf-8
```

**Linux / macOS:**
```bash
export PYTHONIOENCODING=utf-8
```

---

## ▶️ Menjalankan Kode

### 1. Verifikasi SHA-3-256 (Tes Dasar)

```bash
python test_sha3_script.py
```

**Output yang diharapkan:**
```
SHA-3-256 MATCH: True
Digest: 5d83bd5fdde7eae383536a48f0fc7f0efa9718c5f3ad8d8564d8b8bdffecea9c
Avalanche Effect: 148/256 bit = 57.81%
SAC OK: True
```

---

### 2. Demo Utama — 3 Skenario Kriptografi

```bash
python demo.py
```

Demo ini menampilkan 3 skenario nyata:

| Skenario | Deskripsi | Hasil |
|---|---|---|
| **Skenario 1** | Transmisi pesan medis normal | Pesan diterima & terverifikasi ✓ |
| **Skenario 2** | Simulasi serangan MITM (bit flip) | Serangan terdeteksi oleh Auth Tag ✓ |
| **Skenario 3** | Dekripsi dengan kunci salah | Ditolak otomatis ✓ |
| **Bonus** | Avalanche Effect SHA-3-256 | ~50% bit berubah untuk 1 karakter berbeda ✓ |

---

### 3. Evaluasi Progress 3 (Pengujian Statistik)

```bash
python tests/test_avalanche.py
```

**Output yang diharapkan:**
```
=== E4: Avalanche Effect SHA-3-256 ===
Iterasi  : 100
Mean     : 49.54% (target: ~50%)
Std Dev  : 3.03%
SAC OK   : True

=== H2: Collision Resistance SHA-3-256 ===
Pasang diuji : 10000
Collision    : 0
Zero Collision: True

=== E1: Avalanche Effect AES-256-GCM ===
Iterasi  : 100
Mean     : 50.13% (target: ~50%)
SAC OK   : True

=== E3: Waktu Komputasi AES-256-GCM ===
     50 karakter: 0.030 ms (target < 5ms)
    100 karakter: 0.031 ms (target < 5ms)
    500 karakter: 0.035 ms (target < 5ms)
   1000 karakter: 0.038 ms (target < 5ms)
   5000 karakter: 0.056 ms (target < 5ms)

=== Semua pengujian selesai ===
```

---

## 🧩 Penjelasan Modul

### `crypto/sha3_utils.py`
| Fungsi | Deskripsi |
|---|---|
| `compute_sha3_256(message)` | Menghasilkan digest SHA-3-256 dari string |
| `verify_sha3_256(message, digest)` | Verifikasi integritas pesan (timing-safe) |
| `compute_avalanche_effect(msg1, msg2)` | Menghitung persentase bit yang berubah antar dua hash |

### `crypto/aes_gcm_utils.py`
| Fungsi | Deskripsi |
|---|---|
| `generate_key()` | Generate kunci AES-256 acak (32 byte) |
| `encrypt_aes_gcm(key, plaintext)` | Enkripsi + hasilkan Auth Tag (returns: iv, ciphertext, tag) |
| `decrypt_aes_gcm(key, iv, ciphertext, tag)` | Dekripsi + verifikasi Auth Tag |
| `build_packet(iv, tag, ciphertext)` | Gabungkan menjadi satu paket bytes |
| `parse_packet(packet)` | Pecah paket menjadi iv, tag, ciphertext |

### `crypto/crypto_pipeline.py`
| Fungsi | Deskripsi |
|---|---|
| `secure_encrypt(key, message)` | Enkripsi penuh: SHA-3 hash + AES-GCM → packet |
| `secure_decrypt(key, packet)` | Dekripsi + verifikasi Auth Tag + verifikasi hash |

---

## 🛡️ Fitur Keamanan

- **Kerahasiaan**: AES-256-GCM mengenkripsi seluruh payload
- **Integritas**: SHA-3-256 memastikan isi pesan tidak berubah
- **Autentikasi**: Auth Tag 128-bit mendeteksi setiap modifikasi ciphertext
- **Anti-replay**: IV/nonce acak 96-bit di setiap sesi enkripsi
- **MITM Detection**: Perubahan 1 bit pun pada paket langsung ditolak

---

## 🐛 Troubleshooting

| Error | Solusi |
|---|---|
| `ModuleNotFoundError: No module named 'Crypto'` | Jalankan `pip install pycryptodome` |
| Karakter `✓` tidak muncul / error encoding | Jalankan `$env:PYTHONIOENCODING="utf-8"` dulu |
| `ModuleNotFoundError: No module named 'crypto'` | Pastikan kamu menjalankan dari folder `TubesKriptografi/`, bukan dari subfolder lain |
| Python < 3.10 | Update Python di https://python.org |

---

## 👥 Kelompok 7 — Kriptografi Genap 2026

Institut Teknologi Sumatera (ITERA)
