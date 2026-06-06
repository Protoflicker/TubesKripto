"""
tests/test_aes.py
Unit Test AES-256-GCM — Kelompok 7 Kriptografi Genap 2026

Implementasi: Pure Python AES-256-GCM (NIST FIPS 197 + SP 800-38D) tanpa library.
Dapat dijalankan: python tests/test_aes.py
"""
import sys
import os
import time
import random

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

if sys.stdout.encoding and sys.stdout.encoding.lower() != 'utf-8':
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')

from crypto.aes_gcm_utils import (
    generate_key, encrypt_aes_gcm, decrypt_aes_gcm,
    build_packet, parse_packet, IV_SIZE, TAG_SIZE, KEY_SIZE
)
from crypto.sha3_utils import compute_sha3_256, verify_sha3_256
from crypto.crypto_pipeline import secure_encrypt, secure_decrypt
# Pure raw internals untuk fixed-IV test
from crypto.raw_aes import (
    _key_expansion_256, _aes_encrypt_block, _xor_bytes,
    _ghash, _bytes_to_int128, _aes_ctr_keystream, _SBOX
)


def _enc_fixed_iv(key: bytes, pt_bytes: bytes, iv_fixed: bytes) -> bytes:
    """Enkripsi AES-256-GCM dengan IV tetap — pure raw."""
    rk = _key_expansion_256(key)
    H  = _bytes_to_int128(_aes_encrypt_block(b'\x00' * 16, rk))
    ks = _aes_ctr_keystream(key, iv_fixed, 2, len(pt_bytes)) if pt_bytes else b''
    ct = _xor_bytes(pt_bytes, ks) if pt_bytes else b''
    S  = _ghash(H, b'', ct)
    j0 = _aes_ctr_keystream(key, iv_fixed, 1, 16)
    return _xor_bytes(j0, S)


# ─────────────────────────────────────────────────────────────
#  [T5] ROUND-TRIP ENKRIPSI-DEKRIPSI
# ─────────────────────────────────────────────────────────────

def test_roundtrip():
    print('\n=== T5: Round-Trip Enkripsi-Dekripsi AES-256-GCM ===')
    key = generate_key()
    test_cases = [
        'Pasien: Budi Santoso. Diagnosis: ISPA.',
        '',
        'A',
        'Resep: Amoxicillin 500mg, 3x1, 5 hari. TTD: dr. Sari Dewi, Sp.PD.',
        'X' * 500,
    ]
    all_pass = True
    for i, msg in enumerate(test_cases):
        try:
            iv, ct, tag = encrypt_aes_gcm(key, msg)
            dec = decrypt_aes_gcm(key, iv, ct, tag)
            ok  = (dec == msg)
        except Exception as e:
            ok  = False
        all_pass = all_pass and ok
        print(f'  [{"PASS" if ok else "FAIL"}] Case {i+1} (len={len(msg)}): {"COCOK" if ok else "GAGAL"}')
    return all_pass


# ─────────────────────────────────────────────────────────────
#  [T6] VALIDASI KUNCI
# ─────────────────────────────────────────────────────────────

def test_key_validation():
    print('\n=== T6: Validasi Panjang Kunci AES-256 ===')
    msg = 'Pesan uji validasi kunci'
    all_pass = True
    for size in [0, 8, 16, 24, 31, 33, 64]:
        bad_key = os.urandom(size)
        try:
            encrypt_aes_gcm(bad_key, msg)
            ok = False
        except ValueError:
            ok = True
        all_pass = all_pass and ok
        print(f'  [{"PASS" if ok else "FAIL"}] Kunci {size} byte: {"ValueError (ditolak)" if ok else "TIDAK DITOLAK (BUG!)"}')
    valid_key = generate_key()
    try:
        encrypt_aes_gcm(valid_key, msg)
        ok_valid = True
    except Exception:
        ok_valid = False
    print(f'  [{"PASS" if ok_valid else "FAIL"}] Kunci 32 byte (valid): Diterima')
    return all_pass and ok_valid


# ─────────────────────────────────────────────────────────────
#  [T8] AUTH TAG INTEGRITY — MITM SIMULATION
# ─────────────────────────────────────────────────────────────

def test_auth_tag_integrity():
    print('\n=== T8: Auth Tag Integrity — Simulasi MITM Attack ===')
    key = generate_key()
    msg = 'Data medis rahasia: Pasien alergi penisilin!'
    iv, ct, tag = encrypt_aes_gcm(key, msg)
    all_pass = True

    # Tamper ciphertext
    ct_bad = bytes([ct[0] ^ 0xFF] + list(ct[1:]))
    try:
        decrypt_aes_gcm(key, iv, ct_bad, tag)
        ok1 = False
    except ValueError:
        ok1 = True
    all_pass = all_pass and ok1
    print(f'  [{"PASS" if ok1 else "FAIL"}] Modifikasi ciphertext: {"DITOLAK (MAC failed)" if ok1 else "DITERIMA (BUG!)"}')

    # Tamper tag
    tag_bad = bytes([tag[0] ^ 0x01] + list(tag[1:]))
    try:
        decrypt_aes_gcm(key, iv, ct, tag_bad)
        ok2 = False
    except ValueError:
        ok2 = True
    all_pass = all_pass and ok2
    print(f'  [{"PASS" if ok2 else "FAIL"}] Modifikasi auth tag: {"DITOLAK (MAC failed)" if ok2 else "DITERIMA (BUG!)"}')

    # Wrong key
    try:
        decrypt_aes_gcm(generate_key(), iv, ct, tag)
        ok3 = False
    except ValueError:
        ok3 = True
    all_pass = all_pass and ok3
    print(f'  [{"PASS" if ok3 else "FAIL"}] Kunci berbeda: {"DITOLAK (MAC failed)" if ok3 else "DITERIMA (BUG!)"}')

    return all_pass


# ─────────────────────────────────────────────────────────────
#  [E1] AVALANCHE EFFECT AES-256-GCM
# ─────────────────────────────────────────────────────────────

def test_avalanche_aes(iterations: int = 100):
    print(f'\n=== E1: Avalanche Effect AES-256-GCM (n={iterations}) ===')
    plaintext = 'Pasien: Budi Santoso. Diagnosis: ISPA. Resep: Amoxicillin 500mg, 3x1, 5 hari.'
    pt_bytes  = plaintext.encode('utf-8')
    results   = []
    for _ in range(iterations):
        key1 = generate_key()
        key2 = bytearray(key1)
        key2[random.randint(0, KEY_SIZE - 1)] ^= (1 << random.randint(0, 7))
        iv   = os.urandom(IV_SIZE)
        tag1 = _enc_fixed_iv(key1, pt_bytes, iv)
        tag2 = _enc_fixed_iv(bytes(key2), pt_bytes, iv)
        b1   = bin(int(tag1.hex(), 16))[2:].zfill(128)
        b2   = bin(int(tag2.hex(), 16))[2:].zfill(128)
        changed = sum(a != b for a, b in zip(b1, b2))
        results.append(round(changed / 128 * 100, 2))
    mean = sum(results) / len(results)
    std  = (sum((x - mean) ** 2 for x in results) / len(results)) ** 0.5
    ok   = 40.0 <= mean <= 60.0
    print(f'  Iterasi  : {iterations}')
    print(f'  Mean     : {mean:.2f}%  (target: ~50%, 128-bit Auth Tag)')
    print(f'  Std Dev  : {std:.2f}%')
    print(f'  [{"PASS" if ok else "FAIL"}] SAC range 40-60%: {mean:.2f}%')
    return ok


# ─────────────────────────────────────────────────────────────
#  [E2/E3] PERFORMANCE
# ─────────────────────────────────────────────────────────────

def test_performance(repeats: int = 30):
    print(f'\n=== E2/E3: Waktu Enkripsi & Dekripsi AES-256-GCM (repeats={repeats}) ===')
    key   = generate_key()
    sizes = [50, 100, 500, 1000, 5000]
    all_pass = True
    print(f'  {"Ukuran":>8}  {"Enc (ms)":>10}  {"Dec (ms)":>10}  Status')
    print(f'  {"-"*8}  {"-"*10}  {"-"*10}  {"-"*6}')
    for size in sizes:
        msg = 'P' * size
        enc_t, dec_t = [], []
        for _ in range(repeats):
            t0 = time.perf_counter()
            iv, ct, tag = encrypt_aes_gcm(key, msg)
            enc_t.append((time.perf_counter() - t0) * 1000)
            t0 = time.perf_counter()
            decrypt_aes_gcm(key, iv, ct, tag)
            dec_t.append((time.perf_counter() - t0) * 1000)
        enc_m = sum(enc_t) / len(enc_t)
        dec_m = sum(dec_t) / len(dec_t)
        ok = enc_m < 50.0 and dec_m < 50.0  # Pure Python threshold (C library: <5ms)
        all_pass = all_pass and ok
        print(f'  {size:>5} B  {enc_m:>10.3f}  {dec_m:>10.3f}  {"PASS" if ok else "FAIL"}')
    print('  (threshold: <50ms pure Python — <5ms pakai library C)')
    return all_pass


# ─────────────────────────────────────────────────────────────
#  [I2] FORMAT PACKET
# ─────────────────────────────────────────────────────────────

def test_packet_format():
    print('\n=== I2: Format Payload — IV + Auth Tag + Ciphertext ===')
    key = generate_key()
    msg = 'Resep: Amoxicillin 500mg.'
    iv, ct, tag = encrypt_aes_gcm(key, msg)
    packet      = build_packet(iv, tag, ct)
    ok1 = len(iv) == IV_SIZE
    ok2 = len(tag) == TAG_SIZE
    ok3 = (len(packet) - len(ct)) == 28
    p_iv, p_tag, p_ct = parse_packet(packet)
    ok4 = (p_iv == iv and p_tag == tag and p_ct == ct)
    print(f'  [{"PASS" if ok1 else "FAIL"}] IV size = {IV_SIZE} byte (96-bit): {len(iv)} byte')
    print(f'  [{"PASS" if ok2 else "FAIL"}] Auth Tag = {TAG_SIZE} byte (128-bit): {len(tag)} byte')
    print(f'  [{"PASS" if ok3 else "FAIL"}] Overhead = 28 byte: {len(packet) - len(ct)} byte')
    print(f'  [{"PASS" if ok4 else "FAIL"}] Parsing 100% akurat: IV+Tag+CT match')
    return ok1 and ok2 and ok3 and ok4


# ─────────────────────────────────────────────────────────────
#  AES S-BOX VERIFIKASI (FIPS 197)
# ─────────────────────────────────────────────────────────────

def test_sbox():
    print('\n=== AES S-Box Verification (FIPS 197 Table 4) ===')
    ref = {0x00: 0x63, 0x01: 0x7c, 0x53: 0xed, 0xFF: 0x16}
    all_pass = True
    for inp, exp in ref.items():
        ok = _SBOX[inp] == exp
        all_pass = all_pass and ok
        print(f'  [{"PASS" if ok else "FAIL"}] SBOX[0x{inp:02X}] = 0x{_SBOX[inp]:02X} (exp 0x{exp:02X})')
    return all_pass


# ─────────────────────────────────────────────────────────────
#  MAIN
# ─────────────────────────────────────────────────────────────

if __name__ == '__main__':
    import argparse
    p = argparse.ArgumentParser()
    p.add_argument('--quick', action='store_true')
    args = p.parse_args()
    iters   = 50 if args.quick else 100
    repeats = 15 if args.quick else 30

    print('\n' + '=' * 60)
    print('  UNIT TEST AES-256-GCM -- E-Health Crypto Kelompok 7')
    print('  Implementasi: Pure Python AES-256-GCM (FIPS 197 + SP 800-38D)')
    print('=' * 60)

    results = {
        'T5 Round-Trip Enc-Dec'      : test_roundtrip(),
        'T6 Validasi Kunci'          : test_key_validation(),
        'T8 Auth Tag / MITM'         : test_auth_tag_integrity(),
        f'E1 Avalanche AES (n={iters})': test_avalanche_aes(iters),
        f'E2/E3 Performance ({repeats}r)': test_performance(repeats),
        'I2 Format Payload'          : test_packet_format(),
        'AES S-Box FIPS 197'         : test_sbox(),
    }

    print('\n' + '=' * 60)
    print('  REKAP HASIL')
    print('=' * 60)
    passed = sum(v for v in results.values())
    for name, ok in results.items():
        print(f'  [{"PASS" if ok else "FAIL"}]  {name}')
    print(f'\n  Hasil: {passed}/{len(results)} test lulus')
    print('=' * 60)
    sys.exit(0 if passed == len(results) else 1)
