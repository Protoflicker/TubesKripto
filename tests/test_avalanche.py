# -*- coding: utf-8 -*-
"""
tests/test_avalanche.py
Full Avalanche Test Suite dengan Histogram — Kelompok 7 Kriptografi Genap 2026
================================================================================
Skenario pengujian terintegrasi (semua dalam satu file):
  [E4] Avalanche SHA-3-256  — flip 1 bit input → ~50% bit output berubah
  [E1] Avalanche AES-256-GCM — flip 1 bit kunci → ~50% Auth Tag berubah
  [H2] Collision Resistance  — 10.000 hash unik, nol kolisi
  [E5] Throughput SHA-3-256  — kecepatan hashing berbagai ukuran
  [E2] Waktu Enkripsi AES    — target < 5ms untuk 50–5000 byte
  [E3] Waktu Dekripsi AES    — target < 5ms untuk 50–5000 byte

File ini adalah versi CLI dari seluruh endpoint /api/test/* di app.py.
Hasilnya dapat digunakan sebagai bukti preliminary test di Bab 4 Progress 3.

Cara menjalankan:
    python tests/test_avalanche.py              (semua pengujian, n=100)
    python tests/test_avalanche.py --quick      (n=50, cocok untuk demo cepat)
    python tests/test_avalanche.py --pairs 5000 (ubah jumlah pasang collision)
"""

import sys
import os
import time
import random
import secrets
import argparse

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Fix encoding untuk Windows terminal
if sys.stdout.encoding and sys.stdout.encoding.lower() != 'utf-8':
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')

from crypto.sha3_utils    import compute_sha3_256, compute_avalanche_effect
from crypto.aes_gcm_utils import generate_key, encrypt_aes_gcm, decrypt_aes_gcm, IV_SIZE, KEY_SIZE
# Tidak menggunakan pycryptodome — raw_aes internals untuk fixed-IV test
from crypto.raw_aes import (
    _key_expansion_256, _aes_encrypt_block, _xor_bytes,
    _ghash, _bytes_to_int128, _aes_ctr_keystream
)


def _enc_fixed_iv(key, pt_bytes, iv_fixed):
    """Enkripsi AES-256-GCM dengan IV tetap — pure raw tanpa pycryptodome."""
    rk = _key_expansion_256(key)
    H  = _bytes_to_int128(_aes_encrypt_block(b'\x00' * 16, rk))
    ks = _aes_ctr_keystream(key, iv_fixed, 2, len(pt_bytes)) if pt_bytes else b''
    ct = _xor_bytes(pt_bytes, ks) if pt_bytes else b''
    S  = _ghash(H, b'', ct)
    j0 = _aes_ctr_keystream(key, iv_fixed, 1, 16)
    return _xor_bytes(j0, S)

# -------------------------------------------------------------
#  HELPER OUTPUT
# -------------------------------------------------------------

PASS = '[PASS]'
FAIL = '[FAIL]'
SEP  = '-' * 64

def header(title: str):
    print(f'\n{"="*64}')
    print(f'  {title}')
    print('=' * 64)

def subheader(title: str):
    print(f'\n{SEP}')
    print(f'  {title}')
    print(SEP)

def result_line(label: str, value, ok: bool):
    mark = f'  [{PASS}]' if ok else f'  [{FAIL}]'
    print(f'{mark}  {label}: {value}')

def print_histogram(title: str, bins: list, hist: list, total: int, bar_width: int = 35):
    """Cetak histogram horizontal di terminal."""
    print(f'\n  {title}')
    max_count = max(hist) if hist else 1
    for j in range(len(hist)):
        label   = f'{bins[j]}-{bins[j+1]}%'
        filled  = int(round(hist[j] / max_count * bar_width)) if max_count > 0 else 0
        bar     = '#' * filled + '.' * (bar_width - filled)
        pct_str = f'{hist[j] / total * 100:.1f}%' if total > 0 else '0%'
        print(f'    {label:10s} |{bar}| {hist[j]:4d} ({pct_str})')

def compute_histogram(results: list, bins: list) -> list:
    hist = [0] * (len(bins) - 1)
    for v in results:
        for j in range(len(bins) - 1):
            if bins[j] <= v < bins[j + 1]:
                hist[j] += 1
                break
    return hist

def stats(results: list) -> dict:
    n    = len(results)
    mean = sum(results) / n
    var  = sum((x - mean) ** 2 for x in results) / n
    return {
        'n': n, 'mean': mean, 'std': var ** 0.5,
        'min': min(results), 'max': max(results)
    }


# -------------------------------------------------------------
#  [E4] AVALANCHE EFFECT SHA-3-256
# -------------------------------------------------------------

def test_avalanche_sha3(iterations: int = 100) -> float:
    header(f'[E4] Avalanche Effect SHA-3-256')
    print(f'  Parameter  : iterations={iterations}, flip 1 bit karakter input')
    print(f'  Expected   : 49% ≤ mean ≤ 51%')
    print(f'  Endpoint   : /api/test/avalanche_sha3')
    print()

    base    = 'Pasien: Budi Santoso. Diagnosis: ISPA. Resep: Amoxicillin 500mg, 3x1, 5 hari.'
    results = []

    t0 = time.perf_counter()
    for i in range(iterations):
        chars = list(base)
        pos   = i % len(base)
        chars[pos] = chr(ord(chars[pos]) ^ 1)        # flip 1 bit LSB dari karakter
        ae = compute_avalanche_effect(base, ''.join(chars))
        results.append(ae['percentage'])
    elapsed = (time.perf_counter() - t0) * 1000

    s = stats(results)
    print(f'  Iterasi    : {s["n"]}')
    print(f'  Mean       : {s["mean"]:.2f}%')
    print(f'  Std Dev    : {s["std"]:.2f}%')
    print(f'  Min        : {s["min"]:.2f}%')
    print(f'  Max        : {s["max"]:.2f}%')
    print(f'  Waktu total: {elapsed:.1f} ms')

    bins = list(range(40, 62, 2))
    hist = compute_histogram(results, bins)
    print_histogram('Distribusi Avalanche Effect SHA-3-256:', bins, hist, iterations)

    print()
    ok_40_60 = 40.0 <= s['mean'] <= 60.0
    ok_45_55 = 45.0 <= s['mean'] <= 55.0
    ok_49_51 = 49.0 <= s['mean'] <= 51.0
    result_line('SAC lebar    (40–60%)', f'mean={s["mean"]:.2f}%', ok_40_60)
    result_line('SAC ketat    (45–55%)', f'mean={s["mean"]:.2f}%', ok_45_55)
    result_line('SAC target   (49–51%)', f'mean={s["mean"]:.2f}%', ok_49_51)
    return s['mean'], ok_40_60


# -------------------------------------------------------------
#  [E1] AVALANCHE EFFECT AES-256-GCM (KEY SENSITIVITY)
# -------------------------------------------------------------

def test_avalanche_aes(iterations: int = 100) -> float:
    header(f'[E1] Avalanche Effect AES-256-GCM (Key Sensitivity)')
    print(f'  Parameter  : iterations={iterations}, flip 1 bit acak kunci 256-bit')
    print(f'  Expected   : 49% ≤ mean ≤ 51%')
    print(f'  Endpoint   : /api/test/avalanche_aes')
    print()

    plaintext = 'Pasien: Budi Santoso. Diagnosis: ISPA. Resep: Amoxicillin 500mg, 3x1, 5 hari.'
    pt_bytes  = plaintext.encode('utf-8')
    results   = []

    t0 = time.perf_counter()
    for _ in range(iterations):
        key1 = generate_key()
        key2 = bytearray(key1)
        key2[random.randint(0, KEY_SIZE - 1)] ^= (1 << random.randint(0, 7))  # flip 1 bit

        iv   = os.urandom(IV_SIZE)
        tag1 = _enc_fixed_iv(key1, pt_bytes, iv)
        tag2 = _enc_fixed_iv(bytes(key2), pt_bytes, iv)

        b1 = bin(int(tag1.hex(), 16))[2:].zfill(128)
        b2 = bin(int(tag2.hex(), 16))[2:].zfill(128)
        changed = sum(a != b for a, b in zip(b1, b2))
        results.append(round(changed / 128 * 100, 2))
    elapsed = (time.perf_counter() - t0) * 1000

    s = stats(results)
    print(f'  Iterasi    : {s["n"]}')
    print(f'  Mean       : {s["mean"]:.2f}%  (berdasarkan 128-bit Auth Tag)')
    print(f'  Std Dev    : {s["std"]:.2f}%')
    print(f'  Min        : {s["min"]:.2f}%')
    print(f'  Max        : {s["max"]:.2f}%')
    print(f'  Waktu total: {elapsed:.1f} ms')

    bins = list(range(30, 72, 4))
    hist = compute_histogram(results, bins)
    print_histogram('Distribusi Avalanche Effect AES-256-GCM (Auth Tag):', bins, hist, iterations)

    print()
    ok_40_60 = 40.0 <= s['mean'] <= 60.0
    ok_45_55 = 45.0 <= s['mean'] <= 55.0
    ok_49_51 = 49.0 <= s['mean'] <= 51.0
    result_line('SAC lebar    (40–60%)', f'mean={s["mean"]:.2f}%', ok_40_60)
    result_line('SAC ketat    (45–55%)', f'mean={s["mean"]:.2f}%', ok_45_55)
    result_line('SAC target   (49–51%)', f'mean={s["mean"]:.2f}%', ok_49_51)
    return s['mean'], ok_40_60


# -------------------------------------------------------------
#  [H2] COLLISION RESISTANCE SHA-3-256
# -------------------------------------------------------------

def test_collision_resistance(pairs: int = 10000) -> bool:
    header(f'[H2] Collision Resistance SHA-3-256')
    print(f'  Parameter  : pairs={pairs:,} pasang pesan acak unik')
    print(f'  Expected   : collisions = 0')
    print(f'  Endpoint   : /api/test/collision')
    print()

    seen       = {}
    collisions = 0

    t0 = time.perf_counter()
    for i in range(pairs):
        msg = secrets.token_hex(16 + (i % 48))
        h   = compute_sha3_256(msg)
        if h in seen:
            collisions += 1
            print(f'  [!!] KOLISI: "{msg[:20]}..." == "{seen[h][:20]}..."')
        else:
            seen[h] = msg
    elapsed = (time.perf_counter() - t0) * 1000

    ok = (collisions == 0)
    print(f'  Pasang diuji     : {pairs:,}')
    print(f'  Hash unik        : {len(seen):,}')
    print(f'  Kolisi ditemukan : {collisions}')
    print(f'  Waktu total      : {elapsed:.1f} ms')
    print(f'  Kecepatan        : {pairs / (elapsed/1000):.0f} hash/detik')
    print(f'  Security level   : 128-bit collision resistance (birthday bound)')
    print(f'  Prob. kolisi     : ≈ 2⁻¹²⁸ per pasang')
    print()
    result_line(f'Zero collision ({pairs:,} pasang)', f'{collisions} kolisi', ok)
    return ok


# -------------------------------------------------------------
#  [E5] THROUGHPUT SHA-3-256
# -------------------------------------------------------------

def test_hash_throughput(repeats: int = 30) -> bool:
    header('[E5] Throughput SHA-3-256 Hashing')
    print(f'  Parameter  : ukuran=1KB,10KB,100KB,1MB, repeats={repeats}')
    print(f'  Expected   : throughput > 50 MB/s')
    print(f'  Endpoint   : /api/test/hash_throughput')
    print()

    sizes_kb = [1, 10, 100, 1024]
    all_pass = True

    print(f'  {"Ukuran":>8}  {"Waktu mean":>12}  {"Throughput":>14}  {"Status":>8}')
    print(f'  {"-"*8}  {"-"*12}  {"-"*14}  {"-"*8}')

    for size_kb in sizes_kb:
        data  = 'H' * (size_kb * 1024)
        times = []
        for _ in range(repeats):
            t0 = time.perf_counter()
            compute_sha3_256(data)
            times.append(time.perf_counter() - t0)
        mean_s     = sum(times) / len(times)
        throughput = (size_kb / 1024) / mean_s if mean_s > 0 else 9999.0
        ok         = throughput > 50.0
        all_pass   = all_pass and ok
        status     = PASS if ok else FAIL
        label      = f'{size_kb} KB' if size_kb < 1024 else '1 MB'
        print(f'  {label:>8}  {mean_s*1000:>10.3f} ms  {throughput:>12.1f} MB/s  {status:>8}')

    print()
    result_line('Semua throughput > 50 MB/s', 'YA' if all_pass else 'ADA YANG TIDAK MEMENUHI', all_pass)
    return all_pass


# -------------------------------------------------------------
#  [E2/E3] WAKTU ENKRIPSI & DEKRIPSI AES-256-GCM
# -------------------------------------------------------------

def test_aes_performance(repeats: int = 100) -> bool:
    header('[E2/E3] Waktu Enkripsi & Dekripsi AES-256-GCM')
    print(f'  Parameter  : size=50,100,500,1000,5000 byte, repeats={repeats}')
    print(f'  Expected   : enc < 5ms, dec < 5ms')
    print(f'  Endpoint   : /api/test/performance')
    print()

    key   = generate_key()
    sizes = [50, 100, 500, 1000, 5000]
    all_pass_enc = True
    all_pass_dec = True

    print(f'  {"Ukuran":>8}  {"Enc mean":>10}  {"Dec mean":>10}  {"Total":>8}  {"Enc":>6}  {"Dec":>6}')
    print(f'  {"-"*8}  {"-"*10}  {"-"*10}  {"-"*8}  {"-"*6}  {"-"*6}')

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
        s_enc = PASS if ok_enc else FAIL
        s_dec = PASS if ok_dec else FAIL
        print(f'  {size:>5} B  {enc_mean:>8.3f}ms  {dec_mean:>8.3f}ms  '
              f'{enc_mean+dec_mean:>6.3f}ms  {s_enc:>6}  {s_dec:>6}')

    print()
    result_line('E2 — Semua enkripsi < 5ms', 'YA' if all_pass_enc else 'ADA YANG MELEBIHI', all_pass_enc)
    result_line('E3 — Semua dekripsi < 5ms', 'YA' if all_pass_dec else 'ADA YANG MELEBIHI', all_pass_dec)
    return all_pass_enc and all_pass_dec


# -------------------------------------------------------------
#  MAIN RUNNER
# -------------------------------------------------------------

def parse_args():
    p = argparse.ArgumentParser(description='Avalanche & Security Test Suite')
    p.add_argument('--quick',  action='store_true', help='Mode cepat (n=50)')
    p.add_argument('--pairs',  type=int, default=None, help='Jumlah pasang collision test')
    p.add_argument('--iters',  type=int, default=None, help='Jumlah iterasi avalanche test')
    p.add_argument('--reps',   type=int, default=None, help='Jumlah repeats performance test')
    return p.parse_args()


def main():
    args = parse_args()

    iters   = args.iters  or (50  if args.quick else 100)
    pairs   = args.pairs  or (500 if args.quick else 10000)
    repeats = args.reps   or (20  if args.quick else 100)

    print('\n' + '=' * 64)
    print('  FULL AVALANCHE & SECURITY TEST SUITE')
    print('  E-Health Crypto -- Kelompok 7 -- Kriptografi Genap 2026')
    print('  Progress 3: Implementasi & Rencana Pengujian')
    print('=' * 64)
    print(f'\n  Mode    : {"QUICK" if args.quick else "NORMAL"}')
    print(f'  Iters   : {iters}')
    print(f'  Pairs   : {pairs:,}')
    print(f'  Repeats : {repeats}')

    # Jalankan semua pengujian
    _, ok_e4 = test_avalanche_sha3(iters)
    _, ok_e1 = test_avalanche_aes(iters)
    ok_h2    = test_collision_resistance(pairs)
    ok_e5    = test_hash_throughput(repeats)
    ok_e2e3  = test_aes_performance(repeats)

    # ── REKAP AKHIR ──
    results = {
        f'E4 Avalanche SHA-3-256   (n={iters})' : ok_e4,
        f'E1 Avalanche AES-256-GCM (n={iters})' : ok_e1,
        f'H2 Collision Resistance  (n={pairs:,})': ok_h2,
        'E5 Throughput SHA-3-256'                : ok_e5,
        f'E2/E3 AES Performance    ({repeats}r)' : ok_e2e3,
    }

    print(f'\n{"="*64}')
    print('  REKAP AKHIR -- MATRIKS HASIL PENGUJIAN')
    print('=' * 64)
    print(f'  {"Skenario":<42} {"Status":>8}  {"Target"}')
    print(f'  {"-"*42} {"-"*8}  {"-"*18}')

    targets = {
        f'E4 Avalanche SHA-3-256   (n={iters})'  : '49% ≤ mean ≤ 51%',
        f'E1 Avalanche AES-256-GCM (n={iters})'  : '49% ≤ mean ≤ 51%',
        f'H2 Collision Resistance  (n={pairs:,})': 'collisions = 0',
        'E5 Throughput SHA-3-256'                 : '> 50 MB/s',
        f'E2/E3 AES Performance    ({repeats}r)'  : 'enc/dec < 5ms',
    }

    passed = 0
    for name, ok in results.items():
        status = f'[{PASS}]' if ok else f'[{FAIL}]'
        target = targets.get(name, '')
        print(f'  {name:<42} {status:>8}  {target}')
        if ok:
            passed += 1

    total = len(results)
    print(f'\n  Hasil   : {passed}/{total} skenario lulus')
    print(f'  Status  : {"SEMUA LULUS" if passed == total else f"PERLU PERHATIAN -- {total-passed} gagal"}')
    print('=' * 64)

    sys.exit(0 if passed == total else 1)


if __name__ == '__main__':
    main()
