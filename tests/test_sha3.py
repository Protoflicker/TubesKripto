# -*- coding: utf-8 -*-
"""
tests/test_sha3.py
Unit Test SHA-3-256 — Kelompok 7 Kriptografi Genap 2026
==========================================================
Mencakup pengujian:
  [T1] Determinisme         — hash yang sama selalu menghasilkan output sama
  [T2] Format Output        — digest harus hex 64 karakter (256 bit)
  [T3] Sensitivitas Input   — 1 karakter berbeda → digest berbeda total
  [T4] Verify Function      — verify_sha3_256 bekerja benar
  [E4] Avalanche Effect     — flip 1 bit input → ~50% bit output berubah
  [H2] Collision Resistance — 10.000 hash unik, nol kolisi
  [E5] Throughput Hashing   — kecepatan hashing (target > 50 MB/s)

Cara menjalankan:
    python tests/test_sha3.py
    python tests/test_sha3.py --quick   (iterasi lebih sedikit)
"""

import sys
import os
import time
import secrets
import hashlib

# Pastikan root proyek ada di path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Fix encoding untuk Windows terminal
if sys.stdout.encoding and sys.stdout.encoding.lower() != 'utf-8':
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')

from crypto.sha3_utils import compute_sha3_256, verify_sha3_256, compute_avalanche_effect

# ─────────────────────────────────────────────────────────────
#  HELPER OUTPUT
# ─────────────────────────────────────────────────────────────

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


# ─────────────────────────────────────────────────────────────
#  [T1] DETERMINISME
# ─────────────────────────────────────────────────────────────

def test_determinism():
    header('[T1] Determinisme SHA-3-256')
    test_cases = [
        'Pasien: Budi Santoso. Diagnosis: ISPA.',
        '',
        'A',
        'Resep: Amoxicillin 500mg, 3x1, 5 hari. Dokter: dr. Sari',
        'a' * 1000,
    ]
    all_pass = True
    for i, msg in enumerate(test_cases):
        h1 = compute_sha3_256(msg)
        h2 = compute_sha3_256(msg)
        ok = (h1 == h2)
        result_line(f'Case {i+1} (len={len(msg)})', 'DETERMINISTIK' if ok else 'GAGAL!', ok)
        all_pass = all_pass and ok

    return all_pass


# ─────────────────────────────────────────────────────────────
#  [T2] FORMAT OUTPUT
# ─────────────────────────────────────────────────────────────

def test_output_format():
    header('[T2] Format Output Digest')
    msg = 'Test format output SHA-3-256'
    digest = compute_sha3_256(msg)

    is_64_chars = len(digest) == 64
    is_hex      = all(c in '0123456789abcdef' for c in digest)
    is_256_bits = len(digest) * 4 == 256

    result_line('Panjang digest (karakter)', f'{len(digest)} karakter', is_64_chars)
    result_line('Format hex lowercase',      digest[:16] + '...', is_hex)
    result_line('Representasi bit',          f'{len(digest)*4} bit', is_256_bits)
    print(f'         Digest: {digest}')

    return is_64_chars and is_hex and is_256_bits


# ─────────────────────────────────────────────────────────────
#  [T3] SENSITIVITAS INPUT (1 KARAKTER BERBEDA)
# ─────────────────────────────────────────────────────────────

def test_input_sensitivity():
    header('[T3] Sensitivitas Input — 1 Karakter Berbeda')
    pairs = [
        ('Hello', 'hello'),
        ('Pasien A', 'Pasien B'),
        ('Resep123', 'Resep124'),
        ('abc', 'abcd'),
        ('Data medis valid', 'Data medis Valid'),
    ]
    all_pass = True
    for msg1, msg2 in pairs:
        h1 = compute_sha3_256(msg1)
        h2 = compute_sha3_256(msg2)
        ok = (h1 != h2)
        result_line(f'"{msg1}" vs "{msg2}"', 'BERBEDA' if ok else 'SAMA (BUG!)', ok)
        all_pass = all_pass and ok
    return all_pass


# ─────────────────────────────────────────────────────────────
#  [T4] FUNGSI VERIFIKASI
# ─────────────────────────────────────────────────────────────

def test_verify_function():
    header('[T4] Fungsi verify_sha3_256()')
    msg     = 'Resep: Amoxicillin 500mg, 3x1, 5 hari.'
    digest  = compute_sha3_256(msg)
    tampered = digest[:-1] + ('0' if digest[-1] != '0' else '1')

    ok_valid    = verify_sha3_256(msg, digest)           # harus True
    ok_tampered = not verify_sha3_256(msg, tampered)    # harus False (ditolak)
    ok_wrong_msg= not verify_sha3_256('pesan lain', digest)  # harus False

    result_line('Verifikasi digest benar', 'DITERIMA (True)', ok_valid)
    result_line('Verifikasi digest tampered', 'DITOLAK (False)', ok_tampered)
    result_line('Verifikasi pesan berbeda', 'DITOLAK (False)', ok_wrong_msg)
    return ok_valid and ok_tampered and ok_wrong_msg


# -------------------------------------------------------------
#  [H3] PRE-IMAGE RESISTANCE SHA-3-256
# -------------------------------------------------------------

def test_preimage_resistance():
    header('[H3] Pre-image Resistance SHA-3-256')
    msg     = 'Pasien: Budi Santoso. Diagnosis: ISPA. Resep: Amoxicillin 500mg.'
    target  = compute_sha3_256(msg)
    attempts = 10000
    found   = False
    t0 = time.perf_counter()
    for i in range(attempts):
        guess = f'brute_{i}_{secrets.token_hex(4)}'
        if compute_sha3_256(guess) == target:
            found = True
            break
    elapsed = (time.perf_counter() - t0) * 1000

    ok = not found
    print(f'  Target digest       : {target[:32]}...')
    print(f'  Percobaan brute     : {attempts:,} input acak')
    print(f'  Waktu               : {elapsed:.1f} ms')
    print(f'  Complexity teoritis : O(2^256) operasi')
    print(f'  Feasibility         : Tidak feasible (2^256 >> usia alam semesta)')
    print(f'  Pre-image ditemukan : {"YA (BUG!)" if found else "TIDAK"}')
    result_line('Pre-image tidak ditemukan (10K attempts)', 'TIDAK ADA', ok)
    return ok


# -------------------------------------------------------------
#  [H4] AVALANCHE EFFECT SHA-3-256
# -------------------------------------------------------------

def test_avalanche_sha3(iterations: int = 100):
    header(f'[H4] Avalanche Effect SHA-3-256 (n={iterations} iterasi)')
    base = 'Pasien: Budi Santoso. Diagnosis: ISPA. Resep: Amoxicillin 500mg, 3x1, 5 hari.'
    results = []

    for i in range(iterations):
        chars = list(base)
        pos = i % len(base)
        chars[pos] = chr(ord(chars[pos]) ^ 1)        # flip 1 bit LSB
        modified = ''.join(chars)
        ae = compute_avalanche_effect(base, modified)
        results.append(ae['percentage'])

    mean     = sum(results) / len(results)
    variance = sum((x - mean) ** 2 for x in results) / len(results)
    std      = variance ** 0.5
    min_val  = min(results)
    max_val  = max(results)
    pass_40_60  = 40.0 <= mean <= 60.0
    pass_45_55  = 45.0 <= mean <= 55.0
    pass_49_51  = 49.0 <= mean <= 51.0   # target dokumen Progress 3

    print(f'  Iterasi   : {iterations}')
    print(f'  Mean      : {mean:.2f}%   (target: 49% ≤ mean ≤ 51%)')
    print(f'  Std Dev   : {std:.2f}%')
    print(f'  Min       : {min_val:.2f}%')
    print(f'  Max       : {max_val:.2f}%')

    # Histogram terminal
    print('\n  Distribusi Avalanche Effect:')
    bins = list(range(40, 62, 2))
    hist = [0] * (len(bins) - 1)
    for v in results:
        for j in range(len(bins) - 1):
            if bins[j] <= v < bins[j + 1]:
                hist[j] += 1
                break
    for j in range(len(hist)):
        label = f'{bins[j]}-{bins[j+1]}%'
        print_bar(label, hist[j], iterations)

    result_line('SAC range lebar  (40–60%)', f'{mean:.2f}%', pass_40_60)
    result_line('SAC range ketat  (45–55%)', f'{mean:.2f}%', pass_45_55)
    result_line('SAC target docx  (49–51%)', f'{mean:.2f}%', pass_49_51)
    return pass_40_60


# ─────────────────────────────────────────────────────────────
#  [H2] COLLISION RESISTANCE
# ─────────────────────────────────────────────────────────────

def test_collision_resistance(pairs: int = 10000):
    header(f'[H2] Collision Resistance SHA-3-256 (n={pairs:,} pasang)')
    seen       = {}
    collisions = 0

    t0 = time.perf_counter()
    for i in range(pairs):
        msg = secrets.token_hex(16 + (i % 48))
        h   = compute_sha3_256(msg)
        if h in seen:
            collisions += 1
            print(f'  [!!] KOLISI DITEMUKAN: "{msg}" == "{seen[h]}"')
        else:
            seen[h] = msg
    elapsed = (time.perf_counter() - t0) * 1000

    ok = (collisions == 0)
    print(f'  Pasang diuji     : {pairs:,}')
    print(f'  Hash unik        : {len(seen):,}')
    print(f'  Kolisi ditemukan : {collisions}')
    print(f'  Waktu total      : {elapsed:.1f} ms')
    print(f'  Security level   : 128-bit collision resistance')
    print(f'  Prob. kolisi     : ≈ 2⁻¹²⁸ per pasang (birthday bound)')
    result_line('Zero collision (10.000 pasang)', f'{collisions} kolisi', ok)
    return ok


# ─────────────────────────────────────────────────────────────
#  [E5] THROUGHPUT SHA-3-256
# ─────────────────────────────────────────────────────────────

def test_hash_throughput(repeats: int = 30):
    header(f'[E5] Throughput Hashing SHA-3-256 (repeats={repeats})')
    sizes_kb = [1, 10, 100, 1024]
    all_pass = True

    print(f'  {"Ukuran":>8}  {"Waktu (ms)":>12}  {"Throughput":>14}  Status')
    print(f'  {"─"*8}  {"─"*12}  {"─"*14}  {"─"*6}')

    for size_kb in sizes_kb:
        data = 'H' * (size_kb * 1024)
        times = []
        for _ in range(repeats):
            t0 = time.perf_counter()
            compute_sha3_256(data)
            times.append(time.perf_counter() - t0)
        mean_s = sum(times) / len(times)
        throughput = (size_kb / 1024) / mean_s if mean_s > 0 else 9999.0
        ok = throughput > 50.0
        all_pass = all_pass and ok
        status = PASS.strip() if ok else FAIL.strip()
        label = f'{size_kb} KB' if size_kb < 1024 else '1 MB'
        print(f'  {label:>8}  {mean_s*1000:>10.3f}ms  {throughput:>12.1f} MB/s  {status}')

    print(f'\n  Target: throughput > 50 MB/s untuk semua ukuran')
    return all_pass


# ─────────────────────────────────────────────────────────────
#  MAIN RUNNER
# ─────────────────────────────────────────────────────────────

def main():
    quick = '--quick' in sys.argv
    iters = 50 if quick else 100
    pairs = 1000 if quick else 10000

    print('\n' + '=' * 60)
    print('  UNIT TEST SHA-3-256 -- E-Health Crypto Kelompok 7')
    print('  Progress 3: Implementasi & Rencana Pengujian')
    print('=' * 60)

    results = {
        'T1 Determinisme'          : test_determinism(),
        'T2 Format Output'         : test_output_format(),
        'T3 Sensitivitas Input'    : test_input_sensitivity(),
        'T4 Verify Function'       : test_verify_function(),
        'H3 Pre-image Resistance'  : test_preimage_resistance(),
        f'H4 Avalanche (n={iters})': test_avalanche_sha3(iters),
        f'H2 Collision (n={pairs})': test_collision_resistance(pairs),
        'H5 Throughput'            : test_hash_throughput(),
    }

    # Rekap
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
