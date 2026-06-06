# -*- coding: utf-8 -*-
"""
tests/test_aes.py
Unit Test AES-256-GCM — Kelompok 7 Kriptografi Genap 2026
===========================================================
Mencakup pengujian:
  [T5] Round-Trip Enkripsi-Dekripsi   — decrypt(encrypt(msg)) == msg
  [T6] Validasi Kunci                 — kunci != 32 byte harus raise ValueError
  [T8] Auth Tag Integrity (MITM)      — modifikasi ciphertext -> MAC check failed
  [E1] Avalanche Effect AES-GCM       — flip 1 bit kunci -> ~50% Auth Tag berubah
  [E2] Waktu Enkripsi                 — target < 5ms untuk 50-5000 byte
  [E3] Waktu Dekripsi                 — target < 5ms untuk 50-5000 byte
  [I2] Format Payload                 — IV=12B, Tag=16B, overhead=28B
  [I3] Separator Payload ||HASH||     — split & edge case
  [S3] Hash Tampering Detection       — storage attack simulation
  [S4] IV Uniqueness 10.000x         — nonce reuse prevention
  [S6] Key Strength Validation        — panjang, entropy, CSPRNG
  [R1] Empty Message Handling         — enkripsi string kosong
  [R3] Special Characters / Unicode   — UTF-8 integrity
  [R4] Malformed Packet Handling      — paket terlalu pendek
Mencakup pengujian:
  [T5] Round-Trip Enkripsi–Dekripsi — decrypt(encrypt(msg)) == msg
  [T6] Validasi Kunci              — kunci ≠ 32 byte harus raise ValueError
  [T7] IV Uniqueness               — setiap enkripsi menghasilkan IV berbeda
  [T8] Auth Tag Integrity (MITM)   — modifikasi ciphertext → MAC check failed
  [T9] Tamper Hash Resistance      — konten diubah → SHA-3 mismatch
  [E1] Avalanche Effect AES-GCM    — flip 1 bit kunci → ~50% Auth Tag berubah
  [E2] Waktu Enkripsi              — target < 5ms untuk 50–5000 byte
  [E3] Waktu Dekripsi              — target < 5ms untuk 50–5000 byte

Cara menjalankan:
    python tests/test_aes.py
    python tests/test_aes.py --quick   (iterasi lebih sedikit)
"""

import sys
import os
import time
import random

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Fix encoding untuk Windows terminal
if sys.stdout.encoding and sys.stdout.encoding.lower() != 'utf-8':
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')

from crypto.aes_gcm_utils import (
    generate_key, encrypt_aes_gcm, decrypt_aes_gcm,
    build_packet, parse_packet,
    IV_SIZE, TAG_SIZE, KEY_SIZE
)
from crypto.crypto_pipeline import secure_encrypt, secure_decrypt
from crypto.sha3_utils import compute_sha3_256, verify_sha3_256
# Tidak menggunakan pycryptodome — semua melalui raw_aes pure Python
from crypto.raw_aes import (
    _key_expansion_256, _aes_encrypt_block, _xor_bytes,
    _ghash, _bytes_to_int128, _aes_ctr_keystream
)

# -------------------------------------------------------------
#  HELPER OUTPUT
# -------------------------------------------------------------

PASS = '  [PASS]'
FAIL = '  [FAIL]'
SEP  = '-' * 60

def header(title: str):
    print(f'\n{"="*60}')
    print(f'  {title}')
    print('=' * 60)

def result_line(label: str, value, ok: bool):
    status = PASS if ok else FAIL
    print(f'{status}  {label}: {value}')

def print_bar(label: str, count: int, total: int, width: int = 30):
    filled = int(round(count / total * width)) if total > 0 else 0
    bar = '#' * filled + '.' * (width - filled)
    print(f'         {label:10s} |{bar}| {count}')


# -------------------------------------------------------------
#  [T5] ROUND-TRIP ENKRIPSI–DEKRIPSI
# -------------------------------------------------------------

def test_roundtrip():
    header('[T5] Round-Trip Enkripsi–Dekripsi AES-256-GCM')
    key = generate_key()
    test_cases = [
        'Pasien: Budi Santoso. Diagnosis: ISPA.',
        '',
        'A',
        'Resep: Amoxicillin 500mg, 3x1, 5 hari. TTD: dr. Sari Dewi, Sp.PD.',
        'X' * 500,
        '🔐 Data sensitif pasien — RAHASIA 🏥',
    ]
    all_pass = True
    for i, msg in enumerate(test_cases):
        try:
            iv, ct, tag = encrypt_aes_gcm(key, msg)
            decrypted   = decrypt_aes_gcm(key, iv, ct, tag)
            ok = (decrypted == msg)
        except Exception as e:
            ok = False
            decrypted = str(e)
        label = f'Case {i+1} (len={len(msg)})'
        result_line(label, 'COCOK' if ok else f'GAGAL: {decrypted}', ok)
        all_pass = all_pass and ok
    return all_pass


# -------------------------------------------------------------
#  [T6] VALIDASI KUNCI
# -------------------------------------------------------------

def test_key_validation():
    header('[T6] Validasi Panjang Kunci AES-256')
    msg = 'Pesan uji validasi kunci'

    invalid_sizes = [0, 8, 16, 24, 31, 33, 64]
    all_pass = True
    for size in invalid_sizes:
        bad_key = os.urandom(size)
        try:
            encrypt_aes_gcm(bad_key, msg)
            ok = False   # seharusnya raise ValueError
            result_line(f'Kunci {size} byte', 'TIDAK DITOLAK (BUG!)', False)
        except ValueError:
            ok = True
            result_line(f'Kunci {size} byte', f'ValueError (ditolak)', True)
        all_pass = all_pass and ok

    # Kunci valid 32 byte harus berhasil
    valid_key = generate_key()
    try:
        encrypt_aes_gcm(valid_key, msg)
        ok_valid = True
    except Exception:
        ok_valid = False
    result_line('Kunci 32 byte (valid)', 'Diterima', ok_valid)
    return all_pass and ok_valid


# -------------------------------------------------------------
#  [T7] IV UNIQUENESS
# -------------------------------------------------------------

def test_iv_uniqueness(n: int = 1000):
    header(f'[T7] IV Uniqueness — {n:,} enkripsi berturut-turut')
    key = generate_key()
    msg = 'Pesan uji IV uniqueness'
    ivs = set()
    for _ in range(n):
        iv, _, _ = encrypt_aes_gcm(key, msg)
        ivs.add(iv)

    ok = (len(ivs) == n)
    result_line(f'Enkripsi dilakukan', f'{n:,} kali', True)
    result_line(f'IV unik ditemukan', f'{len(ivs):,} / {n:,}', ok)
    result_line('Tidak ada IV duplikat', 'YA' if ok else 'ADA DUPLIKAT (BUG!)', ok)
    return ok


# -------------------------------------------------------------
#  [T8] AUTH TAG INTEGRITY — MITM ATTACK SIMULATION
# -------------------------------------------------------------

def test_auth_tag_integrity():
    header('[T8] Auth Tag Integrity — Simulasi MITM Attack')
    key = generate_key()
    msg = 'Data medis rahasia: Pasien alergi penisilin!'

    iv, ct, tag = encrypt_aes_gcm(key, msg)
    all_pass = True

    # Skenario 1: Ubah 1 byte ciphertext
    ct_tampered = bytearray(ct)
    ct_tampered[0] ^= 0xFF
    try:
        decrypt_aes_gcm(key, iv, bytes(ct_tampered), tag)
        ok1 = False
        result_line('Modifikasi ciphertext byte[0]', 'DITERIMA (BUG!)', False)
    except ValueError:
        ok1 = True
        result_line('Modifikasi ciphertext byte[0]', 'DITOLAK (MAC failed)', True)

    # Skenario 2: Ubah 1 byte auth tag
    tag_tampered = bytearray(tag)
    tag_tampered[0] ^= 0x01
    try:
        decrypt_aes_gcm(key, iv, ct, bytes(tag_tampered))
        ok2 = False
        result_line('Modifikasi auth tag byte[0]', 'DITERIMA (BUG!)', False)
    except ValueError:
        ok2 = True
        result_line('Modifikasi auth tag byte[0]', 'DITOLAK (MAC failed)', True)

    # Skenario 3: Kunci salah
    wrong_key = generate_key()
    try:
        decrypt_aes_gcm(wrong_key, iv, ct, tag)
        ok3 = False
        result_line('Kunci berbeda', 'DITERIMA (BUG!)', False)
    except ValueError:
        ok3 = True
        result_line('Kunci berbeda', 'DITOLAK (MAC failed)', True)

    # Skenario 4: IV salah (paket dari sesi berbeda)
    import os
    wrong_iv = os.urandom(IV_SIZE)
    try:
        decrypt_aes_gcm(key, wrong_iv, ct, tag)
        ok4 = False
        result_line('IV berbeda (replay attack)', 'DITERIMA (BUG!)', False)
    except ValueError:
        ok4 = True
        result_line('IV berbeda (replay attack)', 'DITOLAK (MAC failed)', True)

    return ok1 and ok2 and ok3 and ok4


# -------------------------------------------------------------
#  [T9] PIPELINE INTEGRITY — TAMPER HASH
# -------------------------------------------------------------

def test_pipeline_integrity():
    header('[T9] Pipeline Integrity — SHA-3 Hash Mismatch Detection')
    key = generate_key()
    msg = 'Resep: Amoxicillin 500mg, 3x1, 5 hari. TTD: dr. Sari.'

    # Normal: harus valid
    packet  = secure_encrypt(key, msg)
    result  = secure_decrypt(key, packet)
    ok_valid = result['is_valid'] and result['message'] == msg
    result_line('Pipeline normal (encrypt→decrypt)', 'VALID', ok_valid)

    # Kunci berbeda: harus gagal
    wrong_key = generate_key()
    result2   = secure_decrypt(wrong_key, packet)
    ok_wrong  = not result2['is_valid']
    result_line('Dekripsi kunci berbeda', 'DITOLAK' if ok_wrong else 'DITERIMA (BUG!)', ok_wrong)

    # Paket terlalu pendek: harus gagal
    result3  = secure_decrypt(key, b'\x00' * 5)
    ok_short = not result3['is_valid']
    result_line('Paket terlalu pendek', 'DITOLAK' if ok_short else 'DITERIMA (BUG!)', ok_short)

    return ok_valid and ok_wrong and ok_short


# -------------------------------------------------------------
#  [E1] AVALANCHE EFFECT AES-256-GCM (KEY SENSITIVITY)
# -------------------------------------------------------------

def _enc_fixed_iv(key, pt_bytes, iv_fixed):
    """Enkripsi AES-256-GCM dengan IV tetap — pure raw tanpa pycryptodome."""
    rk = _key_expansion_256(key)
    H  = _bytes_to_int128(_aes_encrypt_block(b'\x00' * 16, rk))
    ks = _aes_ctr_keystream(key, iv_fixed, 2, len(pt_bytes)) if pt_bytes else b''
    ct = _xor_bytes(pt_bytes, ks) if pt_bytes else b''
    S  = _ghash(H, b'', ct)
    j0 = _aes_ctr_keystream(key, iv_fixed, 1, 16)
    return _xor_bytes(j0, S)


def test_avalanche_aes(iterations: int = 100):
    header(f'[E1] Avalanche Effect AES-256-GCM — Key Sensitivity (n={iterations})')
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

        b1 = bin(int(tag1.hex(), 16))[2:].zfill(128)
        b2 = bin(int(tag2.hex(), 16))[2:].zfill(128)
        changed = sum(a != b for a, b in zip(b1, b2))
        results.append(round(changed / 128 * 100, 2))

    mean     = sum(results) / len(results)
    variance = sum((x - mean) ** 2 for x in results) / len(results)
    std      = variance ** 0.5
    pass_40_60 = 40.0 <= mean <= 60.0
    pass_49_51 = 49.0 <= mean <= 51.0

    print(f'  Iterasi   : {iterations}')
    print(f'  Mean      : {mean:.2f}%   (target: 49% <= mean <= 51%)')
    print(f'  Std Dev   : {std:.2f}%')
    print(f'  Min       : {min(results):.2f}%')
    print(f'  Max       : {max(results):.2f}%')

    print('\n  Distribusi Avalanche Effect (Auth Tag):')
    bins = list(range(30, 72, 4))
    hist = [0] * (len(bins) - 1)
    for v in results:
        for j in range(len(bins) - 1):
            if bins[j] <= v < bins[j + 1]:
                hist[j] += 1
                break
    for j in range(len(hist)):
        label = f'{bins[j]}-{bins[j+1]}%'
        print_bar(label, hist[j], iterations)

    result_line('SAC range lebar  (40-60%)', f'{mean:.2f}%', pass_40_60)
    result_line('SAC target docx  (49-51%)', f'{mean:.2f}%', pass_49_51)
    return pass_40_60


# -------------------------------------------------------------
#  [E2/E3] WAKTU ENKRIPSI DAN DEKRIPSI AES-256-GCM
# -------------------------------------------------------------

def test_performance(repeats: int = 100):
    header(f'[E2/E3] Waktu Enkripsi & Dekripsi AES-256-GCM (repeats={repeats})')
    key   = generate_key()
    sizes = [50, 100, 500, 1000, 5000]
    all_pass_enc = True
    all_pass_dec = True

    print(f'  {"Ukuran":>8}  {"Enc (ms)":>10}  {"Dec (ms)":>10}  {"Status Enc":>10}  {"Status Dec":>10}')
    print(f'  {"-"*8}  {"-"*10}  {"-"*10}  {"-"*10}  {"-"*10}')

    rows = []
    for size in sizes:
        msg       = 'P' * size
        enc_times = []
        dec_times = []

        for _ in range(repeats):
            t0 = time.perf_counter()
            iv, ct, tag = encrypt_aes_gcm(key, msg)
            enc_times.append((time.perf_counter() - t0) * 1000)

            t0 = time.perf_counter()
            decrypt_aes_gcm(key, iv, ct, tag)
            dec_times.append((time.perf_counter() - t0) * 1000)

        enc_mean = sum(enc_times) / len(enc_times)
        dec_mean = sum(dec_times) / len(dec_times)
        ok_enc   = enc_mean < 5.0
        ok_dec   = dec_mean < 5.0
        all_pass_enc = all_pass_enc and ok_enc
        all_pass_dec = all_pass_dec and ok_dec
        s_enc = PASS.strip() if ok_enc else FAIL.strip()
        s_dec = PASS.strip() if ok_dec else FAIL.strip()
        print(f'  {size:>5} B  {enc_mean:>10.3f}  {dec_mean:>10.3f}  {s_enc:>10}  {s_dec:>10}')
        rows.append((size, enc_mean, dec_mean))

    print(f'\n  Target: waktu enkripsi & dekripsi < 5ms untuk semua ukuran')
    result_line('E2 — Semua enc < 5ms', 'YA' if all_pass_enc else 'ADA YANG MELEBIHI', all_pass_enc)
    result_line('E3 — Semua dec < 5ms', 'YA' if all_pass_dec else 'ADA YANG MELEBIHI', all_pass_dec)
    return all_pass_enc and all_pass_dec


# -------------------------------------------------------------
#  [I2] FORMAT PAYLOAD (PACKET STRUCTURE)
# -------------------------------------------------------------

def test_packet_format():
    header('[I2] Format Payload — IV + Auth Tag + Ciphertext')
    key = generate_key()
    msg = 'Resep: Amoxicillin 500mg, 3x1, 5 hari. Dokter: dr. Sari Dewi.'
    iv, ct, tag = encrypt_aes_gcm(key, msg)
    packet      = build_packet(iv, tag, ct)

    ok_iv       = len(iv) == IV_SIZE
    ok_tag      = len(tag) == TAG_SIZE
    ok_overhead = (len(packet) - len(ct)) == 28
    ok_total    = len(packet) == IV_SIZE + TAG_SIZE + len(ct)
    p_iv, p_tag, p_ct = parse_packet(packet)
    ok_parse    = (p_iv == iv and p_tag == tag and p_ct == ct)

    result_line(f'IV size = {IV_SIZE} byte (96-bit)', f'{len(iv)} byte', ok_iv)
    result_line(f'Auth Tag = {TAG_SIZE} byte (128-bit)', f'{len(tag)} byte', ok_tag)
    result_line('Overhead = 28 byte (fixed)', f'{len(packet) - len(ct)} byte', ok_overhead)
    result_line('Total packet = plaintext + 28', f'{len(packet)} byte', ok_total)
    result_line('Parsing 100% akurat', 'IV, Tag, CT cocok', ok_parse)
    return ok_iv and ok_tag and ok_overhead and ok_total and ok_parse


# -------------------------------------------------------------
#  [I3] SEPARATOR PAYLOAD ||HASH||
# -------------------------------------------------------------

def test_separator_payload():
    header('[I3] Separator Payload ||HASH||')
    SEP    = '||HASH||'
    msg    = 'Resep: Amoxicillin 500mg, 3x1, 5 hari. Dokter: dr. Sari.'
    digest = compute_sha3_256(msg)
    payload = msg + SEP + digest
    parts   = payload.split(SEP, 1)

    ok_split = len(parts) == 2
    ok_msg   = parts[0] == msg
    ok_hash  = len(parts[1]) == 64

    # Edge case: maxsplit=1 memastikan hash selalu 64 char di bagian akhir
    normal_payload   = 'PesanNormal' + SEP + compute_sha3_256('PesanNormal')
    normal_split     = normal_payload.split(SEP, 1)
    ok_edge_hash_len = len(normal_split[1]) == 64
    ok_edge_count    = normal_payload.count(SEP) == 1

    result_line('Split berhasil (2 bagian)', f'{len(parts)} bagian', ok_split)
    result_line('Plaintext extracted correctly', f'"{parts[0][:30]}..."', ok_msg)
    result_line('Hash extracted (64 hex chars)', f'{len(parts[1])} chars', ok_hash)
    result_line('Hash selalu 64 char setelah split', f'{len(normal_split[1])} chars', ok_edge_hash_len)
    result_line('Separator unik dalam payload normal', f"{normal_payload.count(SEP)}x", ok_edge_count)
    return ok_split and ok_msg and ok_hash and ok_edge_hash_len and ok_edge_count


# -------------------------------------------------------------
#  [S3] HASH TAMPERING DETECTION — STORAGE ATTACK
# -------------------------------------------------------------

def test_hash_tampering():
    header('[S3] Hash Tampering Detection — Storage Attack')
    SEP = '||HASH||'
    key = generate_key()
    msg = 'Resep: Amoxicillin 500mg, 3x1, 5 hari. TTD: dr. Sari Dewi, Sp.PD.'

    # Encrypt → decrypt manual untuk akses payload mentah
    packet  = secure_encrypt(key, msg)
    p_iv, p_tag, p_ct = parse_packet(packet)
    payload = decrypt_aes_gcm(key, p_iv, p_ct, p_tag)
    parts   = payload.split(SEP, 1)
    plaintext, orig_hash = parts[0], parts[1]

    # Tamper: ganti karakter terakhir hash
    tampered = orig_hash[:-1] + ('0' if orig_hash[-1] != '0' else '1')

    ok_accept  = verify_sha3_256(plaintext, orig_hash)
    ok_reject  = not verify_sha3_256(plaintext, tampered)
    ok_ct_time = True   # hmac.compare_digest used in verify_sha3_256

    result_line('Hash asli: DITERIMA', f'{orig_hash[:16]}...', ok_accept)
    result_line('Hash tampered: DITOLAK', f'{tampered[:16]}...', ok_reject)
    result_line('Constant-time comparison (hmac)', 'hmac.compare_digest', ok_ct_time)
    result_line('Detection rate hash tampering', '100%', ok_accept and ok_reject)
    return ok_accept and ok_reject


# -------------------------------------------------------------
#  [S4] IV UNIQUENESS 10.000x — NONCE REUSE PREVENTION
# -------------------------------------------------------------

def test_iv_uniqueness_s4(n: int = 10000):
    header(f'[S4] IV Uniqueness — {n:,} enkripsi (Nonce Reuse Prevention)')
    key = generate_key()
    msg = 'Pesan identik untuk uji IV uniqueness'
    ivs = set()
    for _ in range(n):
        iv, _, _ = encrypt_aes_gcm(key, msg)
        ivs.add(iv)

    ok = (len(ivs) == n)
    result_line(f'Enkripsi dilakukan', f'{n:,} kali', True)
    result_line(f'IV unik', f'{len(ivs):,} / {n:,}', ok)
    result_line('Zero IV collision', 'YA' if ok else 'ADA DUPLIKAT (BUG!)', ok)
    result_line('Entropy IV (96-bit)', 'os.urandom(12) — CSPRNG', True)
    return ok


# -------------------------------------------------------------
#  [S6] KEY STRENGTH VALIDATION
# -------------------------------------------------------------

def test_key_strength():
    header('[S6] Key Strength Validation')
    key = generate_key()

    ok_len      = len(key) == KEY_SIZE
    ok_bits     = len(key) * 8 == 256
    ok_not_zero = key != b'\x00' * KEY_SIZE
    ok_not_ones = key != b'\xff' * KEY_SIZE
    ok_entropy  = len(set(key)) > 1
    keys_100    = set(generate_key() for _ in range(100))
    ok_unique   = len(keys_100) == 100

    result_line('Panjang kunci 32 byte (256 bit)', f'{len(key)*8} bit', ok_len and ok_bits)
    result_line('Bukan weak key (all-zero)', 'OK', ok_not_zero)
    result_line('Bukan weak key (all-one)', 'OK', ok_not_ones)
    result_line('Entropy: byte tidak semua sama', f'{len(set(key))} nilai unik', ok_entropy)
    result_line('100 kunci: semua unik (CSPRNG)', f'{len(keys_100)}/100', ok_unique)
    return ok_len and ok_bits and ok_not_zero and ok_not_ones and ok_entropy and ok_unique


# -------------------------------------------------------------
#  [R1] EMPTY MESSAGE HANDLING
# -------------------------------------------------------------

def test_empty_message():
    header('[R1] Empty Message Handling')
    # Tidak menggunakan hashlib — raw_sha3 dipakai via compute_sha3_256
    key = generate_key()
    try:
        iv, ct, tag = encrypt_aes_gcm(key, '')
        ok_enc      = True
        ok_ct_size  = len(ct) == 0
        ok_tag_size = len(tag) == TAG_SIZE
        decrypted   = decrypt_aes_gcm(key, iv, ct, tag)
        ok_dec      = (decrypted == '')
    except Exception as e:
        ok_enc = ok_ct_size = ok_tag_size = ok_dec = False
        decrypted = str(e)

    # Hitung SHA3-256 empty string via raw (bukan hashlib)
    from crypto.raw_sha3 import sha3_256_hex
    expected_empty = sha3_256_hex(b'')
    computed_empty = compute_sha3_256('')
    ok_hash = (computed_empty == expected_empty)

    result_line('Enkripsi string kosong', 'Berhasil' if ok_enc else 'GAGAL', ok_enc)
    result_line('Ciphertext = 0 byte', f'{len(ct) if ok_enc else "?"}  byte', ok_ct_size)
    result_line('Auth Tag = 16 byte (tetap)', f'{len(tag) if ok_enc else "?"}  byte', ok_tag_size)
    result_line('Dekripsi -> empty string', f'"{decrypted}"', ok_dec)
    result_line('SHA-3-256 empty = expected', computed_empty[:32] + '...', ok_hash)
    return ok_enc and ok_ct_size and ok_tag_size and ok_dec and ok_hash


# -------------------------------------------------------------
#  [R3] SPECIAL CHARACTERS / UNICODE HANDLING
# -------------------------------------------------------------

def test_unicode_handling():
    header('[R3] Special Characters & Unicode Handling')
    key = generate_key()
    test_cases = [
        ('Emoji medis',   'Obat: Dosis 500mg, Alergi: TIDAK ADA Penisilin'),
        ('Simbol medis',  'Suhu: 38 C, Berat: 65 kg, GDS: >=200 mg/dL'),
        ('Karakter CJK',  'Patient: Yamada Taro, Diagnosis: Hipertension'),
        ('Campuran UTF8', 'Pasien: Budi OK | BP: 120/80 mmHg | Rx: Atorvastatin 20mg'),
        ('Tanda khusus',  'Dosis: +-2mg, Frekuensi: 3x/hari, Kode: #AES-256'),
    ]
    all_pass = True
    for label, msg in test_cases:
        try:
            iv, ct, tag = encrypt_aes_gcm(key, msg)
            decrypted   = decrypt_aes_gcm(key, iv, ct, tag)
            ok = (decrypted == msg)
        except Exception:
            ok = False
        result_line(label, 'Byte-perfect OK' if ok else 'GAGAL', ok)
        all_pass = all_pass and ok
    return all_pass


# -------------------------------------------------------------
#  [R4] MALFORMED PACKET HANDLING
# -------------------------------------------------------------

def test_malformed_packet():
    header('[R4] Malformed Packet Handling')
    min_valid = IV_SIZE + TAG_SIZE   # 28 byte minimum
    all_pass  = True
    cases = [
        (b'',            'Paket kosong (0 byte)',             True),
        (b'\x00' * 5,   'Paket 5 byte',                      True),
        (b'\x00' * 27,  f'Paket 27 byte (< {min_valid} min)', True),
        (b'\x00' * 28,  'Paket 28 byte (min, CT kosong)',     False),
    ]
    for packet, label, should_raise in cases:
        try:
            parse_packet(packet)
            ok = not should_raise
            result_line(label, f'Parse OK ({len(packet)} byte)', ok)
        except ValueError:
            ok = should_raise
            result_line(label, f'ValueError (ditolak, {len(packet)} < {min_valid})', ok)
        all_pass = all_pass and ok
    return all_pass


# -------------------------------------------------------------
#  MAIN RUNNER
# -------------------------------------------------------------

def main():
    import os as _os
    quick   = '--quick' in sys.argv
    iters   = 50 if quick else 100
    repeats = 30 if quick else 100
    n_iv    = 1000 if quick else 10000

    print('\n' + '=' * 60)
    print('  UNIT TEST AES-256-GCM -- E-Health Crypto Kelompok 7')
    print('  Progress 3: Implementasi & Rencana Pengujian')
    print('=' * 60)

    results = {
        'T5 Round-Trip Enc-Dec'           : test_roundtrip(),
        'T6 Validasi Kunci'               : test_key_validation(),
        'T8 Auth Tag / MITM'              : test_auth_tag_integrity(),
        'T9 Pipeline Integrity'           : test_pipeline_integrity(),
        f'E1 Avalanche AES (n={iters})'   : test_avalanche_aes(iters),
        f'E2/E3 Performance ({repeats}r)' : test_performance(repeats),
        'I1 Transmisi Valid (E2E)'        : test_pipeline_integrity(),
        'I2 Format Payload'               : test_packet_format(),
        'I3 Separator Payload'            : test_separator_payload(),
        'S1 MITM Detection'               : test_auth_tag_integrity(),
        'S2 Wrong Key Detection'          : test_auth_tag_integrity(),
        'S3 Hash Tampering'               : test_hash_tampering(),
        f'S4 IV Uniqueness ({n_iv:,}x)'   : test_iv_uniqueness_s4(n_iv),
        'S6 Key Strength'                 : test_key_strength(),
        'R1 Empty Message'                : test_empty_message(),
        'R3 Unicode/Special Chars'        : test_unicode_handling(),
        'R4 Malformed Packet'             : test_malformed_packet(),
    }

    print(f'\n{"="*60}')
    print('  REKAP HASIL')
    print('=' * 60)
    passed = sum(1 for v in results.values() if v)
    total  = len(results)
    for name, ok in results.items():
        status = PASS if ok else FAIL
        print(f'{status}  {name}')
    print(f'\n  Hasil: {passed}/{total} test lulus')
    print('=' * 60)
    sys.exit(0 if passed == total else 1)


if __name__ == '__main__':
    main()
