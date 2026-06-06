"""
tests/test_avalanche.py
Evaluasi Avalanche Effect dan Collision Resistance
Kelompok 7 — Kriptografi Genap 2026

Versi ini menggunakan implementasi pure raw Python (tanpa library kriptografi).
Dapat dijalankan mandiri: python tests/test_avalanche.py
Atau melalui web app: python app.py -> /api/test/avalanche_sha3, dll.
"""
import sys
import os
import time
import secrets
import random
import argparse

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Fix encoding Windows terminal
if sys.stdout.encoding and sys.stdout.encoding.lower() != 'utf-8':
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')

from crypto.sha3_utils    import compute_sha3_256, compute_avalanche_effect
from crypto.aes_gcm_utils import generate_key, encrypt_aes_gcm, decrypt_aes_gcm, IV_SIZE, KEY_SIZE
# Pure raw internals untuk fixed-IV avalanche test AES
from crypto.raw_aes import (
    _key_expansion_256, _aes_encrypt_block, _xor_bytes,
    _ghash, _bytes_to_int128, _aes_ctr_keystream
)


def _enc_fixed_iv(key: bytes, pt_bytes: bytes, iv_fixed: bytes) -> bytes:
    """Enkripsi AES-256-GCM dengan IV tetap — pure raw tanpa pycryptodome."""
    rk = _key_expansion_256(key)
    H  = _bytes_to_int128(_aes_encrypt_block(b'\x00' * 16, rk))
    ks = _aes_ctr_keystream(key, iv_fixed, 2, len(pt_bytes)) if pt_bytes else b''
    ct = _xor_bytes(pt_bytes, ks) if pt_bytes else b''
    S  = _ghash(H, b'', ct)
    j0 = _aes_ctr_keystream(key, iv_fixed, 1, 16)
    return _xor_bytes(j0, S)


# ─────────────────────────────────────────────────────────────
#  [E4] AVALANCHE EFFECT SHA-3-256
# ─────────────────────────────────────────────────────────────

def test_avalanche_sha3(iterations: int = 100) -> float:
    print('\n=== E4: Avalanche Effect SHA-3-256 ===')
    base = 'Pasien: Budi Santoso. Diagnosis: ISPA. Resep: Amoxicillin 500mg, 3x1, 5 hari.'
    results = []
    t0 = time.perf_counter()
    for i in range(iterations):
        chars = list(base)
        pos = i % len(base)
        chars[pos] = chr(ord(chars[pos]) ^ 1)
        modified = ''.join(chars)
        ae = compute_avalanche_effect(base, modified)
        results.append(ae['percentage'])
    elapsed = (time.perf_counter() - t0) * 1000

    mean = sum(results) / len(results)
    variance = sum((x - mean) ** 2 for x in results) / len(results)
    std = variance ** 0.5

    print(f'Iterasi   : {iterations}')
    print(f'Mean      : {mean:.2f}% (target: ~50%)')
    print(f'Std Dev   : {std:.2f}%')
    print(f'Min       : {min(results):.2f}%')
    print(f'Max       : {max(results):.2f}%')
    print(f'SAC OK    : {40 <= mean <= 60}')
    print(f'Waktu     : {elapsed:.1f} ms')
    return mean


# ─────────────────────────────────────────────────────────────
#  [H2] COLLISION RESISTANCE SHA-3-256
# ─────────────────────────────────────────────────────────────

def test_collision_resistance(pairs: int = 10000) -> int:
    print('\n=== H2: Collision Resistance SHA-3-256 ===')
    seen = set()
    collisions = 0
    t0 = time.perf_counter()
    for i in range(pairs):
        msg = secrets.token_hex(16 + (i % 32))
        h = compute_sha3_256(msg)
        if h in seen:
            collisions += 1
        seen.add(h)
    elapsed = (time.perf_counter() - t0) * 1000

    print(f'Pasang diuji   : {pairs:,}')
    print(f'Collision       : {collisions}')
    print(f'Zero Collision  : {collisions == 0}')
    print(f'Waktu           : {elapsed:.1f} ms')
    print(f'Security level  : 128-bit collision resistance')
    return collisions


# ─────────────────────────────────────────────────────────────
#  [E1] AVALANCHE EFFECT AES-256-GCM (Key Sensitivity)
# ─────────────────────────────────────────────────────────────

def test_aes_avalanche(iterations: int = 100) -> float:
    print('\n=== E1: Avalanche Effect AES-256-GCM (Key Sensitivity) ===')
    key = generate_key()
    base = 'Pasien: Budi Santoso. Diagnosis: ISPA. Resep: Amoxicillin 500mg, 3x1, 5 hari.'
    pt_bytes = base.encode('utf-8')
    results = []
    t0 = time.perf_counter()
    for i in range(iterations):
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
    elapsed = (time.perf_counter() - t0) * 1000

    mean = sum(results) / len(results)
    variance = sum((x - mean) ** 2 for x in results) / len(results)
    std = variance ** 0.5

    print(f'Iterasi   : {iterations}')
    print(f'Mean      : {mean:.2f}% (target: ~50%, berdasarkan 128-bit Auth Tag)')
    print(f'Std Dev   : {std:.2f}%')
    print(f'Min       : {min(results):.2f}%')
    print(f'Max       : {max(results):.2f}%')
    print(f'SAC OK    : {40 <= mean <= 60}')
    print(f'Waktu     : {elapsed:.1f} ms')
    return mean


# ─────────────────────────────────────────────────────────────
#  [E2/E3] WAKTU ENKRIPSI & DEKRIPSI AES-256-GCM
# ─────────────────────────────────────────────────────────────

def test_performance(repeats: int = 30) -> bool:
    print('\n=== E2/E3: Waktu Komputasi AES-256-GCM ===')
    key   = generate_key()
    sizes = [50, 100, 500, 1000, 5000]
    all_pass = True
    print(f'  {"Ukuran":>8}  {"Enc (ms)":>10}  {"Dec (ms)":>10}  Status')
    print(f'  {"-"*8}  {"-"*10}  {"-"*10}  {"-"*6}')
    for size in sizes:
        msg = 'A' * size
        enc_times, dec_times = [], []
        for _ in range(repeats):
            t0 = time.perf_counter()
            iv, ct, tag = encrypt_aes_gcm(key, msg)
            enc_times.append((time.perf_counter() - t0) * 1000)
            t0 = time.perf_counter()
            decrypt_aes_gcm(key, iv, ct, tag)
            dec_times.append((time.perf_counter() - t0) * 1000)
        enc_mean = sum(enc_times) / len(enc_times)
        dec_mean = sum(dec_times) / len(dec_times)
        ok = enc_mean < 50.0 and dec_mean < 50.0
        all_pass = all_pass and ok
        status = 'PASS' if ok else 'FAIL'
        print(f'  {size:>5} B  {enc_mean:>10.3f}  {dec_mean:>10.3f}  {status}')
    print(f'Target: enc < 50ms, dec < 50ms (Pure Python)')
    return all_pass


# ─────────────────────────────────────────────────────────────
#  [E5] THROUGHPUT SHA-3-256
# ─────────────────────────────────────────────────────────────

def test_hash_throughput(repeats: int = 10) -> bool:
    print('\n=== E5: Throughput SHA-3-256 Hashing ===')
    sizes_kb = [1, 10, 100]
    all_pass = True
    print(f'  {"Ukuran":>8}  {"Waktu (ms)":>12}  {"Throughput":>14}  Status')
    print(f'  {"-"*8}  {"-"*12}  {"-"*14}  {"-"*6}')
    for size_kb in sizes_kb:
        data = 'H' * (size_kb * 1024)
        times = []
        for _ in range(repeats):
            t0 = time.perf_counter()
            compute_sha3_256(data)
            times.append(time.perf_counter() - t0)
        mean_s = sum(times) / len(times)
        throughput = (size_kb / 1024) / mean_s if mean_s > 0 else 0
        # Pure Python lebih lambat dari C — target disesuaikan
        ok = throughput > 0.001
        all_pass = all_pass and ok
        label = f'{size_kb} KB'
        print(f'  {label:>8}  {mean_s*1000:>10.3f} ms  {throughput:>12.4f} MB/s  {"PASS" if ok else "FAIL"}')
    print('(catatan: pure Python ~100-1000x lebih lambat dari C extension)')
    return all_pass


# ─────────────────────────────────────────────────────────────
#  MAIN
# ─────────────────────────────────────────────────────────────

def parse_args():
    p = argparse.ArgumentParser(description='Avalanche & Security Test Suite — Pure Python')
    p.add_argument('--quick', action='store_true', help='Mode cepat (n=30)')
    p.add_argument('--iters', type=int, default=None)
    p.add_argument('--pairs', type=int, default=None)
    p.add_argument('--reps',  type=int, default=None)
    return p.parse_args()


if __name__ == '__main__':
    args = parse_args()
    iters   = args.iters or (30  if args.quick else 100)
    pairs   = args.pairs or (500 if args.quick else 10000)
    repeats = args.reps  or (10  if args.quick else 30)

    print('\n' + '=' * 60)
    print('  AVALANCHE & SECURITY TEST — E-Health Crypto Kelompok 7')
    print('  Implementasi: Pure Python (Keccak FIPS 202 + AES FIPS 197)')
    print('=' * 60)

    sha3_mean  = test_avalanche_sha3(iters)
    collisions = test_collision_resistance(pairs)
    aes_mean   = test_aes_avalanche(iters)
    perf_ok    = test_performance(repeats)
    thr_ok     = test_hash_throughput(repeats)

    print('\n' + '=' * 60)
    print('  REKAP HASIL')
    print('=' * 60)
    results = {
        f'E4 Avalanche SHA-3-256   (n={iters})': 40 <= sha3_mean <= 60,
        f'H2 Collision Resistance  ({pairs:,} pairs)': collisions == 0,
        f'E1 Avalanche AES-256-GCM (n={iters})': 40 <= aes_mean <= 60,
        f'E2/E3 AES Performance    ({repeats}r)': perf_ok,
        'E5 Hash Throughput'                   : thr_ok,
    }
    passed = sum(v for v in results.values())
    for name, ok in results.items():
        print(f'  [{"PASS" if ok else "FAIL"}]  {name}')
    print(f'\n  Hasil: {passed}/{len(results)} lulus')
    print('=' * 60)
    print('\n=== Semua pengujian selesai ===')
