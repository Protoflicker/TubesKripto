# -*- coding: utf-8 -*-
"""
tests/test_concurrent.py
[R5] Concurrent Encryption — Kelompok 7 Kriptografi Genap 2026
================================================================
Memverifikasi sistem aman pada eksekusi paralel multi-thread:
tidak ada IV collision, tidak ada data race, dan semua hasil
enkripsi tetap konsisten saat banyak thread berjalan bersamaan.

Skenario yang diuji:
  [R5.1] Thread-safe IV generation  — N thread × M enkripsi → 0 IV duplikat
  [R5.2] Concurrent round-trip      — semua thread berhasil enc → dec
  [R5.3] Shared key thread-safety   — kunci sama dipakai N thread
  [R5.4] Concurrent secure_pipeline — pipeline SHA-3 + AES paralel
  [R5.5] Stress test (high load)    — 100 thread × 100 enkripsi

Cara menjalankan:
    python tests/test_concurrent.py
    python tests/test_concurrent.py --quick
"""

import sys
import os
import time
import secrets
from concurrent.futures import ThreadPoolExecutor, as_completed
from threading import Lock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

if sys.stdout.encoding and sys.stdout.encoding.lower() != 'utf-8':
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')

from crypto.aes_gcm_utils import generate_key, encrypt_aes_gcm, decrypt_aes_gcm
from crypto.crypto_pipeline import secure_encrypt, secure_decrypt


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


# ─── [R5.1] Thread-safe IV generation ─────────────────────────
def test_iv_uniqueness_threaded(n_threads: int = 50, enc_per_thread: int = 100):
    header(f'[R5.1] Thread-safe IV Generation — {n_threads} thread × {enc_per_thread} enkripsi')
    key = generate_key()
    msg = 'Pasien identik untuk uji nonce reuse paralel.'

    def worker(_):
        return [encrypt_aes_gcm(key, msg)[0].hex() for _ in range(enc_per_thread)]

    t0 = time.perf_counter()
    all_ivs = []
    with ThreadPoolExecutor(max_workers=n_threads) as ex:
        for ivs in ex.map(worker, range(n_threads)):
            all_ivs.extend(ivs)
    elapsed = time.perf_counter() - t0

    total = n_threads * enc_per_thread
    unique = len(set(all_ivs))
    duplicates = total - unique
    ok = (duplicates == 0)

    print(f'  Total enkripsi   : {total:,}')
    print(f'  IV unik          : {unique:,}')
    print(f'  IV duplikat      : {duplicates}')
    print(f'  Waktu total      : {elapsed*1000:.1f} ms')
    print(f'  Throughput       : {total/elapsed:,.0f} enc/detik')
    result_line('Zero IV collision (CSPRNG thread-safe)',
                f'{duplicates} collision', ok)
    return ok


# ─── [R5.2] Concurrent round-trip ──────────────────────────────
def test_concurrent_roundtrip(n_threads: int = 20, msgs_per_thread: int = 50):
    header(f'[R5.2] Concurrent Round-trip — {n_threads} thread × {msgs_per_thread} enc→dec')
    key = generate_key()

    def worker(tid: int):
        ok_count = 0
        for i in range(msgs_per_thread):
            msg = f'thread-{tid}-msg-{i}-{secrets.token_hex(4)}'
            iv, ct, tag = encrypt_aes_gcm(key, msg)
            decrypted = decrypt_aes_gcm(key, iv, ct, tag)
            if decrypted == msg:
                ok_count += 1
        return ok_count

    t0 = time.perf_counter()
    success_per_thread = []
    with ThreadPoolExecutor(max_workers=n_threads) as ex:
        futures = [ex.submit(worker, tid) for tid in range(n_threads)]
        for fut in as_completed(futures):
            success_per_thread.append(fut.result())
    elapsed = time.perf_counter() - t0

    total = n_threads * msgs_per_thread
    success = sum(success_per_thread)
    ok = (success == total)

    print(f'  Total round-trip : {total:,}')
    print(f'  Sukses           : {success:,}')
    print(f'  Gagal            : {total - success}')
    print(f'  Waktu total      : {elapsed*1000:.1f} ms')
    result_line(f'Semua round-trip valid (100% success rate)',
                f'{success}/{total}', ok)
    return ok


# ─── [R5.3] Shared key thread-safety ──────────────────────────
def test_shared_key_safety(n_threads: int = 30, ops_per_thread: int = 50):
    header(f'[R5.3] Shared Key Thread-Safety — {n_threads} thread share 1 key')
    key = generate_key()
    plaintext = 'Resep: Amoxicillin 500mg, 3x1, 5 hari. Diagnosis: ISPA.'

    errors = []
    error_lock = Lock()

    def worker(tid: int):
        local_errors = 0
        for i in range(ops_per_thread):
            try:
                iv, ct, tag = encrypt_aes_gcm(key, plaintext)
                dec = decrypt_aes_gcm(key, iv, ct, tag)
                if dec != plaintext:
                    local_errors += 1
            except Exception as e:
                local_errors += 1
                with error_lock:
                    errors.append((tid, i, str(e)))
        return local_errors

    t0 = time.perf_counter()
    with ThreadPoolExecutor(max_workers=n_threads) as ex:
        total_errors = sum(ex.map(worker, range(n_threads)))
    elapsed = time.perf_counter() - t0

    total_ops = n_threads * ops_per_thread
    ok = (total_errors == 0)

    print(f'  Total operasi    : {total_ops:,}')
    print(f'  Error (race/decrypt fail) : {total_errors}')
    print(f'  Waktu total      : {elapsed*1000:.1f} ms')
    if errors[:3]:
        print(f'  Sample errors    : {errors[:3]}')
    result_line('Shared key aman dipakai paralel',
                f'{total_errors} error', ok)
    return ok


# ─── [R5.4] Concurrent secure_pipeline ────────────────────────
def test_concurrent_pipeline(n_threads: int = 20, msgs_per_thread: int = 30):
    header(f'[R5.4] Concurrent secure_pipeline — {n_threads} thread × {msgs_per_thread} pipeline lengkap')
    key = generate_key()

    def worker(tid: int):
        ok_count = 0
        for i in range(msgs_per_thread):
            msg = f'Pasien {tid}-{i}: data medis sensitif.'
            packet = secure_encrypt(key, msg)
            res = secure_decrypt(key, packet)
            if res['is_valid'] and res['message'] == msg:
                ok_count += 1
        return ok_count

    t0 = time.perf_counter()
    results = []
    with ThreadPoolExecutor(max_workers=n_threads) as ex:
        for ok_count in ex.map(worker, range(n_threads)):
            results.append(ok_count)
    elapsed = time.perf_counter() - t0

    total = n_threads * msgs_per_thread
    success = sum(results)
    ok = (success == total)

    print(f'  Total pipeline   : {total:,} (SHA-3 + AES-GCM)')
    print(f'  Sukses           : {success:,}')
    print(f'  Throughput       : {total/elapsed:,.0f} pipeline/detik')
    result_line('Pipeline E2E aman paralel', f'{success}/{total}', ok)
    return ok


# ─── [R5.5] Stress test ───────────────────────────────────────
def test_stress(n_threads: int = 100, enc_per_thread: int = 100):
    header(f'[R5.5] Stress Test — {n_threads} thread × {enc_per_thread} enkripsi = {n_threads*enc_per_thread:,} ops')
    key = generate_key()
    msg_template = 'stress-test-payload-' + 'x' * 200

    def worker(tid: int):
        ivs = []
        for i in range(enc_per_thread):
            iv, _, _ = encrypt_aes_gcm(key, f'{msg_template}-{tid}-{i}')
            ivs.append(iv.hex())
        return ivs

    t0 = time.perf_counter()
    all_ivs = []
    with ThreadPoolExecutor(max_workers=n_threads) as ex:
        for ivs in ex.map(worker, range(n_threads)):
            all_ivs.extend(ivs)
    elapsed = time.perf_counter() - t0

    total = n_threads * enc_per_thread
    unique = len(set(all_ivs))
    duplicates = total - unique
    ok = (duplicates == 0)

    print(f'  Total operasi    : {total:,}')
    print(f'  IV unik          : {unique:,}')
    print(f'  IV duplikat      : {duplicates}')
    print(f'  Waktu            : {elapsed*1000:.1f} ms ({total/elapsed:,.0f} enc/detik)')
    result_line('Zero collision pada stress test',
                f'{duplicates} duplikat', ok)
    return ok


# ─── Main Runner ───────────────────────────────────────────────
def main():
    quick = '--quick' in sys.argv

    if quick:
        n_iv, m_iv     = 20, 50
        n_rt, m_rt     = 10, 25
        n_sh, m_sh     = 15, 25
        n_pl, m_pl     = 10, 15
        n_st, m_st     = 30, 30
    else:
        n_iv, m_iv     = 50, 100
        n_rt, m_rt     = 20, 50
        n_sh, m_sh     = 30, 50
        n_pl, m_pl     = 20, 30
        n_st, m_st     = 100, 100

    print('\n' + '=' * 60)
    print('  TEST R5: CONCURRENT ENCRYPTION -- E-Health Crypto Kelompok 7')
    print('  Progress 3 → Final: Skenario sisa dari 22 matriks')
    print('=' * 60)

    results = {
        f'R5.1 Thread-safe IV ({n_iv}×{m_iv})'   : test_iv_uniqueness_threaded(n_iv, m_iv),
        f'R5.2 Concurrent Round-trip ({n_rt}×{m_rt})': test_concurrent_roundtrip(n_rt, m_rt),
        f'R5.3 Shared Key Safety ({n_sh}×{m_sh})': test_shared_key_safety(n_sh, m_sh),
        f'R5.4 Concurrent Pipeline ({n_pl}×{m_pl})': test_concurrent_pipeline(n_pl, m_pl),
        f'R5.5 Stress Test ({n_st}×{m_st})'      : test_stress(n_st, m_st),
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
