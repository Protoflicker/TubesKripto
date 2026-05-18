"""
demo_progress2.py
Demonstrasi Core Function Development — Progress 2
Kelompok 7 — Kriptografi Genap 2026 — ITERA

Fungsionalitas yang ditampilkan:
  1. Input teks → Hash SHA-3-256 (hex)
  2. Enkripsi AES-256-GCM → IV + Auth Tag + Ciphertext
  3. Dekripsi → teks asli kembali
"""
from crypto.sha3_utils    import compute_sha3_256
from crypto.aes_gcm_utils import generate_key, encrypt_aes_gcm, decrypt_aes_gcm

CYAN   = '\033[96m'
GREEN  = '\033[92m'
YELLOW = '\033[93m'
RESET  = '\033[0m'

def garis(judul):
    print(f'\n{YELLOW}{"─"*55}')
    print(f'  {judul}')
    print(f'{"─"*55}{RESET}')

if __name__ == '__main__':
    import sys
    if hasattr(sys.stdout, 'reconfigure'):
        sys.stdout.reconfigure(encoding='utf-8')

    print(f'\n{CYAN}  DEMO CORE FUNCTION — PROGRESS 2')
    print(f'  Kelompok 7 | Kriptografi Genap 2026 | ITERA{RESET}')

    # ── Input teks ─────────────────────────────────────────
    pesan = input(f'\n{CYAN}[INPUT]{RESET} Masukkan teks pesan medis\n> ')

    # ── STEP 1: SHA-3-256 Hashing ──────────────────────────
    garis('STEP 1 — Hashing SHA-3-256')
    digest = compute_sha3_256(pesan)
    print(f'  Input   : {pesan}')
    print(f'  Panjang : {len(pesan)} karakter')
    print(f'{GREEN}  SHA-3   : {digest}{RESET}')
    print(f'  Panjang : {len(digest)*4} bit (256 bit)')

    # ── STEP 2: Enkripsi AES-256-GCM ───────────────────────
    garis('STEP 2 — Enkripsi AES-256-GCM')
    key = generate_key()
    iv, ciphertext, auth_tag = encrypt_aes_gcm(key, pesan)
    print(f'  Key     : {key.hex()[:16]}...{key.hex()[-8:]} ({len(key)} byte / 256 bit)')
    print(f'{GREEN}  IV      : {iv.hex()} ({len(iv)} byte / 96 bit){RESET}')
    print(f'{GREEN}  Auth Tag: {auth_tag.hex()} ({len(auth_tag)} byte / 128 bit){RESET}')
    print(f'{GREEN}  Cipher  : {ciphertext.hex()}{RESET}')
    print(f'  Panjang : {len(ciphertext)} byte ciphertext')

    # ── STEP 3: Dekripsi ───────────────────────────────────
    garis('STEP 3 — Dekripsi AES-256-GCM')
    hasil = decrypt_aes_gcm(key, iv, ciphertext, auth_tag)
    print(f'  Hasil   : {hasil}')
    match = hasil == pesan
    status = f'{GREEN}BERHASIL — teks asli kembali ✓{RESET}' if match else f'\033[91mGAGAL{RESET}'
    print(f'  Status  : {status}')

    print(f'\n{CYAN}  Semua core function berjalan dengan benar.{RESET}\n')
