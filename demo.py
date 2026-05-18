"""
demo.py — Demonstrasi sistem e-health messaging AES-256-GCM + SHA-3-256
Kelompok 7 — Kriptografi Genap 2026 — ITERA
"""
from crypto.aes_gcm_utils   import generate_key
from crypto.crypto_pipeline  import secure_encrypt, secure_decrypt
from crypto.sha3_utils       import compute_avalanche_effect

GREEN  = '\033[92m'
RED    = '\033[91m'
YELLOW = '\033[93m'
CYAN   = '\033[96m'
RESET  = '\033[0m'

def separator(title):
    print(f'\n{YELLOW}{"="*60}')
    print(f'  {title}')
    print(f'{"="*60}{RESET}')

if __name__ == '__main__':
    import sys
    if hasattr(sys.stdout, 'reconfigure'):
        sys.stdout.reconfigure(encoding='utf-8')

    print(f'{CYAN}')
    print('  SISTEM ENKRIPSI E-HEALTH')
    print('  AES-256-GCM + SHA-3-256')
    print(f'  Kelompok 7 — ITERA 2026{RESET}')

    key = generate_key()
    print(f'\n{CYAN}[SETUP]{RESET} Kunci AES-256: {key.hex()[:16]}...{key.hex()[-8:]} ({len(key)} byte)')

    separator('SKENARIO 1 — Transmisi Pesan Valid')
    pesan = 'Pasien: Budi Santoso. Diagnosis: ISPA. Resep: Amoxicillin 500mg, 3x1, 5 hari.'
    print(f'[DOKTER]    Pesan     : {pesan}')
    print(f'[DOKTER]    Panjang   : {len(pesan)} karakter')

    packet = secure_encrypt(key, pesan)
    print(f'[JARINGAN]  Paket     : {len(packet)} byte terenkripsi')
    print(f'[JARINGAN]  Preview   : {packet.hex()[:32]}...')

    result = secure_decrypt(key, packet)
    if result['is_valid']:
        print(f'{GREEN}[PASIEN]    Diterima  : {result["message"]}{RESET}')
        print(f'{GREEN}[PASIEN]    Status    : VALID ✓ (Auth Tag + SHA-3-256 OK){RESET}')
    else:
        print(f'{RED}[PASIEN]    DITOLAK   : {result["error"]}{RESET}')

    separator('SKENARIO 2 — Simulasi Serangan MITM')
    tampered = bytearray(packet)
    tampered[30] ^= 0xFF
    print(f'[PENYERANG] Membalik bit ke-30 ciphertext (XOR 0xFF)')
    result2 = secure_decrypt(key, bytes(tampered))
    if not result2['is_valid']:
        print(f'{RED}[PASIEN]    Status    : {result2["error"]}{RESET}')
        print(f'{GREEN}[SISTEM]    Serangan BERHASIL DIDETEKSI ✓{RESET}')

    separator('SKENARIO 3 — Kunci Salah')
    wrong_key = generate_key()
    result3 = secure_decrypt(wrong_key, packet)
    if not result3['is_valid']:
        print(f'{RED}[PASIEN]    Status    : {result3["error"]}{RESET}')
        print(f'{GREEN}[SISTEM]    Kunci salah BERHASIL DIDETEKSI ✓{RESET}')

    separator('BONUS — Avalanche Effect SHA-3-256')
    pesan2 = pesan.replace('5 hari', '6 hari')
    ae = compute_avalanche_effect(pesan, pesan2)
    print(f'Perubahan input : 1 karakter dari {len(pesan)} ({1/len(pesan)*100:.1f}%)')
    print(f'Bit berubah     : {ae["bits_changed"]} dari 256 bit')
    print(f'Avalanche Effect: {ae["percentage"]}%')
    status = f'{GREEN}TERPENUHI ✓{RESET}' if 40 <= ae['percentage'] <= 60 else f'{RED}TIDAK TERPENUHI{RESET}'
    print(f'Status SAC      : {status}')
