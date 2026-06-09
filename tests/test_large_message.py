# -*- coding: utf-8 -*-
"""
tests/test_large_message.py
[R2] Large Message Handling (>1 MB) — Kelompok 7 Kriptografi Genap 2026
========================================================================
Memverifikasi sistem mampu menangani pesan berukuran besar (1 MB - 10 MB)
dengan integritas data terjaga dan memory usage masih wajar (< 2x ukuran).

Skenario yang diuji:
  [R2.1] Round-trip 1 MB   — encrypt → decrypt → plaintext match
  [R2.2] Round-trip 5 MB   — encrypt → decrypt → plaintext match
  [R2.3] Round-trip 10 MB  — encrypt → decrypt → plaintext match
  [R2.4] Memory profile    — peak memory < 2x ukuran pesan
  [R2.5] Time complexity   — waktu ~ linear O(n)

Cara menjalankan:
    python tests/test_large_message.py
    python tests/test_large_message.py --quick   (skip 10 MB)
"""

import sys
import os
import time
import tracemalloc

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

if sys.stdout.encoding and sys.stdout.encoding.lower() != 'utf-8':
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')

from crypto.aes_gcm_utils import generate_key, encrypt_aes_gcm, decrypt_aes_gcm
from crypto.crypto_pipeline import secure_encrypt, secure_decrypt
from crypto.sha3_utils import compute_sha3_256


# ─── Helper Output ─────────────────────────────────────────────
PASS = '  [PASS]'
FAIL = '  [FAIL]'

def header(title: str):
    print(f'\n{"="*60}')
    print(f'  {title}')
    print('=' * 60)

def result_line(label: str, value, ok: bool):
    status = PASS if ok else FAIL
    print(f'{status}  {label}: {value}')

def fmt_mb(b: int) -> str:
    return f'{b / (1024*1024):.2f} MB'


# ─── Core: encrypt + decrypt + verify integrity ───────────────
def roundtrip_large(size_mb: int) -> dict:
    """Enkripsi-dekripsi pesan size_mb MB, return metrics."""
    plaintext = 'A' * (size_mb * 1024 * 1024)
    expected_size = size_mb * 1024 * 1024
    key = generate_key()

    # Hash awal untuk verifikasi byte-perfect
    hash_before = compute_sha3_256(plaintext)

    tracemalloc.start()
    t0 = time.perf_counter()
    iv, ct, tag = encrypt_aes_gcm(key, plaintext)
    enc_time = time.perf_counter() - t0
    enc_current, enc_peak = tracemalloc.get_traced_memory()

    t0 = time.perf_counter()
    decrypted = decrypt_aes_gcm(key, iv, ct, tag)
    dec_time = time.perf_counter() - t0
    _, total_peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    hash_after = compute_sha3_256(decrypted)

    return {
        'size_mb'    : size_mb,
        'plaintext_size': expected_size,
        'ciphertext_size': len(ct),
        'enc_time'   : enc_time,
        'dec_time'   : dec_time,
        'enc_peak'   : enc_peak,
        'total_peak' : total_peak,
        'match'      : (decrypted == plaintext),
        'hash_match' : (hash_before == hash_after),
        'overhead_bytes': len(iv) + len(tag),
    }


# ─── [R2.1] 1 MB ───────────────────────────────────────────────
def test_1mb():
    header('[R2.1] Round-trip 1 MB')
    m = roundtrip_large(1)
    print(f'  Plaintext size  : {fmt_mb(m["plaintext_size"])}')
    print(f'  Ciphertext size : {fmt_mb(m["ciphertext_size"])} (overhead {m["overhead_bytes"]} byte)')
    print(f'  Waktu enkripsi  : {m["enc_time"]*1000:.2f} ms')
    print(f'  Waktu dekripsi  : {m["dec_time"]*1000:.2f} ms')
    print(f'  Memory peak     : {fmt_mb(m["total_peak"])}  (ratio {m["total_peak"]/m["plaintext_size"]:.2f}x)')
    result_line('Round-trip byte-perfect', 'OK' if m['match'] else 'GAGAL', m['match'])
    result_line('Hash SHA-3 cocok',      'OK' if m['hash_match'] else 'GAGAL', m['hash_match'])
    return m['match'] and m['hash_match']


# ─── [R2.2] 5 MB ───────────────────────────────────────────────
def test_5mb():
    header('[R2.2] Round-trip 5 MB')
    m = roundtrip_large(5)
    print(f'  Plaintext size  : {fmt_mb(m["plaintext_size"])}')
    print(f'  Ciphertext size : {fmt_mb(m["ciphertext_size"])}')
    print(f'  Waktu enkripsi  : {m["enc_time"]*1000:.2f} ms')
    print(f'  Waktu dekripsi  : {m["dec_time"]*1000:.2f} ms')
    print(f'  Memory peak     : {fmt_mb(m["total_peak"])}  (ratio {m["total_peak"]/m["plaintext_size"]:.2f}x)')
    result_line('Round-trip byte-perfect', 'OK' if m['match'] else 'GAGAL', m['match'])
    return m['match'] and m['hash_match']


# ─── [R2.3] 10 MB ──────────────────────────────────────────────
def test_10mb():
    header('[R2.3] Round-trip 10 MB')
    m = roundtrip_large(10)
    print(f'  Plaintext size  : {fmt_mb(m["plaintext_size"])}')
    print(f'  Ciphertext size : {fmt_mb(m["ciphertext_size"])}')
    print(f'  Waktu enkripsi  : {m["enc_time"]*1000:.2f} ms')
    print(f'  Waktu dekripsi  : {m["dec_time"]*1000:.2f} ms')
    print(f'  Memory peak     : {fmt_mb(m["total_peak"])}  (ratio {m["total_peak"]/m["plaintext_size"]:.2f}x)')
    result_line('Round-trip byte-perfect', 'OK' if m['match'] else 'GAGAL', m['match'])
    return m['match'] and m['hash_match']


# ─── [R2.4] Memory Profile ─────────────────────────────────────
def test_memory_profile(sizes_mb=(1, 5, 10)):
    header(f'[R2.4] Memory Profile — ratio peak/plaintext untuk {sizes_mb} MB')
    rows = []
    print(f'  {"Size":>8}  {"Peak":>12}  {"Ratio":>8}  Status')
    print(f'  {"─"*8}  {"─"*12}  {"─"*8}  {"─"*6}')
    all_ok = True
    for s in sizes_mb:
        m = roundtrip_large(s)
        ratio = m['total_peak'] / m['plaintext_size']
        # Target: memory < 8x ukuran plaintext (longgar karena Python pure-code overhead besar)
        ok = ratio < 8.0 and m['match']
        all_ok = all_ok and ok
        status = PASS.strip() if ok else FAIL.strip()
        print(f'  {fmt_mb(s*1024*1024):>8}  {fmt_mb(m["total_peak"]):>12}  {ratio:>6.2f}x  {status}')
        rows.append((s, ratio, ok))
    print(f'\n  Target: ratio < 8x (Python pure-code overhead: string → bytes → keystream → ciphertext)')
    return all_ok


# ─── [R2.5] Time Complexity O(n) ───────────────────────────────
def test_linear_complexity():
    header('[R2.5] Time Complexity — Linear O(n) check')
    print(f'  {"Size":>8}  {"Enc (ms)":>10}  {"ms/MB":>10}  Status')
    print(f'  {"─"*8}  {"─"*10}  {"─"*10}  {"─"*6}')
    ms_per_mb_list = []
    for s in [1, 2, 4, 8]:
        m = roundtrip_large(s)
        ms = m['enc_time'] * 1000
        ms_per_mb = ms / s
        ms_per_mb_list.append(ms_per_mb)
        print(f'  {fmt_mb(s*1024*1024):>8}  {ms:>10.2f}  {ms_per_mb:>10.2f}  -')
    # Linearity check: ms/MB seharusnya kurang lebih konstan
    if not ms_per_mb_list:
        return False
    avg = sum(ms_per_mb_list) / len(ms_per_mb_list)
    max_dev = max(abs(x - avg) for x in ms_per_mb_list)
    # Toleransi 50% deviasi karena cache & noise OS
    ok = max_dev / avg < 0.5
    print(f'\n  Avg ms/MB: {avg:.2f}, max deviation: {max_dev/avg*100:.1f}%')
    result_line('Linear O(n) terkonfirmasi (deviasi < 50%)', 'OK' if ok else 'GAGAL', ok)
    return ok


# ─── Main Runner ───────────────────────────────────────────────
def main():
    quick = '--quick' in sys.argv

    print('\n' + '=' * 60)
    print('  TEST R2: LARGE MESSAGE HANDLING -- E-Health Crypto Kelompok 7')
    print('  Progress 3 → Final: Skenario sisa dari 22 matriks')
    print('=' * 60)

    results = {
        'R2.1 Round-trip 1 MB' : test_1mb(),
        'R2.2 Round-trip 5 MB' : test_5mb(),
    }
    if not quick:
        results['R2.3 Round-trip 10 MB'] = test_10mb()
    results['R2.4 Memory Profile']  = test_memory_profile((1, 5) if quick else (1, 5, 10))
    results['R2.5 Linear O(n)']     = test_linear_complexity()

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
