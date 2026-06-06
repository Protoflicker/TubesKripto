# -*- coding: utf-8 -*-
"""
tests/test_replay.py
[S5] Replay Attack Resistance — Kelompok 7 Kriptografi Genap 2026
==================================================================
Memverifikasi bahwa sistem dapat mendeteksi dan menolak pesan yang
dikirim ulang (paket dengan IV identik). Mekanisme: IV tracking
in-memory via crypto.replay_guard.ReplayGuard.

Skenario yang diuji:
  [S5.1] First-time accept   — paket pertama dengan IV baru diterima
  [S5.2] Replay rejected     — paket kedua dengan IV sama ditolak
  [S5.3] Detection rate      — 100 pengiriman ulang → 100/100 ditolak
  [S5.4] Unique IVs accepted — 1000 IV unik berturut-turut diterima
  [S5.5] TTL expiry          — IV kadaluwarsa boleh dipakai lagi

Cara menjalankan:
    python tests/test_replay.py
    python tests/test_replay.py --quick
"""

import sys
import os
import time
import secrets

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

if sys.stdout.encoding and sys.stdout.encoding.lower() != 'utf-8':
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')

from crypto.replay_guard import ReplayGuard
from crypto.crypto_pipeline import secure_encrypt, secure_decrypt
from crypto.aes_gcm_utils import generate_key, parse_packet


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


# ─── [S5.1] First-time Accept ─────────────────────────────────
def test_first_time_accept():
    header('[S5.1] First-time Accept — IV baru harus diterima')
    guard = ReplayGuard(ttl_seconds=60)
    accepted = 0
    for i in range(50):
        iv = secrets.token_bytes(12)
        if not guard.is_replay(iv):
            accepted += 1
    ok = (accepted == 50)
    result_line('Paket pertama diterima', f'{accepted}/50', ok)
    print(f'  Cache size setelah uji: {guard.size()}')
    return ok


# ─── [S5.2] Replay Rejected ────────────────────────────────────
def test_replay_rejected():
    header('[S5.2] Replay Rejected — IV sama harus ditolak pada percobaan ke-2')
    guard = ReplayGuard(ttl_seconds=60)
    iv = secrets.token_bytes(12)
    first  = guard.is_replay(iv)   # harus False (belum pernah)
    second = guard.is_replay(iv)   # harus True (replay)
    third  = guard.is_replay(iv)   # harus True (masih replay)

    result_line('Percobaan pertama (IV baru)', 'DITERIMA' if not first else 'DITOLAK (BUG!)', not first)
    result_line('Percobaan kedua (IV sama)',   'DITOLAK' if second else 'DITERIMA (BUG!)', second)
    result_line('Percobaan ketiga (IV sama)',  'DITOLAK' if third else 'DITERIMA (BUG!)', third)
    return (not first) and second and third


# ─── [S5.3] Detection Rate (Pipeline Lengkap) ─────────────────
def test_pipeline_replay_detection(n_replay: int = 100):
    header(f'[S5.3] Pipeline Replay Detection — {n_replay} kali replay paket asli')

    guard = ReplayGuard(ttl_seconds=60)
    key   = generate_key()
    msg   = 'Pasien: Budi Santoso. Diagnosis: ISPA.'

    # Enkripsi 1 paket
    packet = secure_encrypt(key, msg)
    iv, _, _ = parse_packet(packet)

    # Paket pertama: harus diterima + lulus secure_decrypt
    is_replay_1 = guard.is_replay(iv)
    res_1 = secure_decrypt(key, packet)
    ok_first = (not is_replay_1) and res_1['is_valid'] and res_1['message'] == msg

    # Paket sama dikirim ulang n_replay kali: semua harus ditolak
    detected = 0
    for _ in range(n_replay):
        if guard.is_replay(iv):
            detected += 1   # benar — terdeteksi sebagai replay

    detection_rate = detected / n_replay * 100 if n_replay else 0
    ok_replay = (detected == n_replay)

    result_line('Paket pertama (asli) diterima & valid', 'OK' if ok_first else 'GAGAL', ok_first)
    result_line(f'Replay terdeteksi ({n_replay} kali)',
                f'{detected}/{n_replay} ({detection_rate:.1f}%)', ok_replay)
    print(f'  Plaintext recovered: "{res_1["message"][:40]}..."')

    return ok_first and ok_replay


# ─── [S5.4] Unique IVs Accepted ───────────────────────────────
def test_unique_ivs(n: int = 1000):
    header(f'[S5.4] Unique IVs Accepted — {n:,} IV unik berturut-turut')
    guard = ReplayGuard(ttl_seconds=60)
    rejected = 0
    for _ in range(n):
        iv = secrets.token_bytes(12)
        if guard.is_replay(iv):
            rejected += 1
    ok = (rejected == 0)
    result_line(f'{n:,} IV unik diterima semua', f'rejected={rejected}', ok)
    print(f'  Cache size: {guard.size():,}')
    return ok


# ─── [S5.5] TTL Expiry ─────────────────────────────────────────
def test_ttl_expiry():
    header('[S5.5] TTL Expiry — IV expired boleh dipakai ulang')
    guard = ReplayGuard(ttl_seconds=1)   # TTL 1 detik untuk test cepat
    iv = secrets.token_bytes(12)

    first  = guard.is_replay(iv)   # False — pertama kali
    second = guard.is_replay(iv)   # True  — masih dalam TTL

    print(f'  Menunggu TTL expire (1.2 detik)...')
    time.sleep(1.2)

    third  = guard.is_replay(iv)   # False — TTL sudah lewat, dianggap baru

    result_line('Percobaan pertama', 'DITERIMA' if not first else 'DITOLAK (BUG!)', not first)
    result_line('Percobaan kedua (dalam TTL)', 'DITOLAK' if second else 'DITERIMA (BUG!)', second)
    result_line('Percobaan ketiga (setelah TTL)',
                'DITERIMA' if not third else 'DITOLAK (TTL tidak bekerja)', not third)
    return (not first) and second and (not third)


# ─── Main Runner ───────────────────────────────────────────────
def main():
    quick = '--quick' in sys.argv
    n_replay = 20 if quick else 100
    n_unique = 200 if quick else 1000

    print('\n' + '=' * 60)
    print('  TEST S5: REPLAY ATTACK RESISTANCE -- E-Health Crypto Kelompok 7')
    print('  Progress 3 → Final: Skenario sisa dari 22 matriks')
    print('=' * 60)

    results = {
        'S5.1 First-time Accept'              : test_first_time_accept(),
        'S5.2 Replay Rejected'                : test_replay_rejected(),
        f'S5.3 Pipeline Replay ({n_replay}x)' : test_pipeline_replay_detection(n_replay),
        f'S5.4 Unique IVs ({n_unique:,})'     : test_unique_ivs(n_unique),
        'S5.5 TTL Expiry'                     : test_ttl_expiry(),
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
