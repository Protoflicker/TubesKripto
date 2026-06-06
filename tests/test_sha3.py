"""
tests/test_sha3.py
Unit Test SHA-3-256 — Kelompok 7 Kriptografi Genap 2026

Implementasi: Pure Python Keccak-p[1600,24] (NIST FIPS 202) tanpa library.
Dapat dijalankan: python tests/test_sha3.py
"""
import sys
import os
import time
import secrets

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

if sys.stdout.encoding and sys.stdout.encoding.lower() != 'utf-8':
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')

from crypto.sha3_utils import compute_sha3_256, verify_sha3_256, compute_avalanche_effect


# ─────────────────────────────────────────────────────────────
#  [T1] DETERMINISME
# ─────────────────────────────────────────────────────────────

def test_determinism():
    print('\n=== T1: Determinisme SHA-3-256 ===')
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
        all_pass = all_pass and ok
        print(f'  [{"PASS" if ok else "FAIL"}] Case {i+1} (len={len(msg)}): {"DETERMINISTIK" if ok else "GAGAL!"}')
    return all_pass


# ─────────────────────────────────────────────────────────────
#  [T2] FORMAT OUTPUT
# ─────────────────────────────────────────────────────────────

def test_output_format():
    print('\n=== T2: Format Output Digest ===')
    msg = 'Test format output SHA-3-256'
    digest = compute_sha3_256(msg)
    is_64  = len(digest) == 64
    is_hex = all(c in '0123456789abcdef' for c in digest)
    is_256 = len(digest) * 4 == 256
    print(f'  [{"PASS" if is_64 else "FAIL"}] Panjang digest: {len(digest)} karakter (exp 64)')
    print(f'  [{"PASS" if is_hex else "FAIL"}] Format hex lowercase: {digest[:16]}...')
    print(f'  [{"PASS" if is_256 else "FAIL"}] Representasi bit: {len(digest)*4} bit (exp 256)')
    print(f'  Digest: {digest}')
    return is_64 and is_hex and is_256


# ─────────────────────────────────────────────────────────────
#  [T3] SENSITIVITAS INPUT
# ─────────────────────────────────────────────────────────────

def test_input_sensitivity():
    print('\n=== T3: Sensitivitas Input — 1 Karakter Berbeda ===')
    pairs = [
        ('Hello', 'hello'),
        ('Pasien A', 'Pasien B'),
        ('Resep123', 'Resep124'),
        ('abc', 'abcd'),
        ('Data medis valid', 'Data medis Valid'),
    ]
    all_pass = True
    for msg1, msg2 in pairs:
        ok = compute_sha3_256(msg1) != compute_sha3_256(msg2)
        all_pass = all_pass and ok
        print(f'  [{"PASS" if ok else "FAIL"}] "{msg1}" vs "{msg2}": {"BERBEDA" if ok else "SAMA (BUG!)"}')
    return all_pass


# ─────────────────────────────────────────────────────────────
#  [T4] VERIFIKASI
# ─────────────────────────────────────────────────────────────

def test_verify_function():
    print('\n=== T4: Fungsi verify_sha3_256() ===')
    msg     = 'Resep: Amoxicillin 500mg, 3x1, 5 hari.'
    digest  = compute_sha3_256(msg)
    tampered = digest[:-1] + ('0' if digest[-1] != '0' else '1')
    ok1 = verify_sha3_256(msg, digest)
    ok2 = not verify_sha3_256(msg, tampered)
    ok3 = not verify_sha3_256('pesan lain', digest)
    print(f'  [{"PASS" if ok1 else "FAIL"}] Digest benar: DITERIMA (True)')
    print(f'  [{"PASS" if ok2 else "FAIL"}] Digest tampered: DITOLAK (False)')
    print(f'  [{"PASS" if ok3 else "FAIL"}] Pesan berbeda: DITOLAK (False)')
    return ok1 and ok2 and ok3


# ─────────────────────────────────────────────────────────────
#  [H4] AVALANCHE EFFECT
# ─────────────────────────────────────────────────────────────

def test_avalanche_sha3(iterations: int = 100):
    print(f'\n=== H4: Avalanche Effect SHA-3-256 (n={iterations}) ===')
    base = 'Pasien: Budi Santoso. Diagnosis: ISPA. Resep: Amoxicillin 500mg, 3x1, 5 hari.'
    results = []
    for i in range(iterations):
        chars = list(base)
        pos = i % len(base)
        chars[pos] = chr(ord(chars[pos]) ^ 1)
        ae = compute_avalanche_effect(base, ''.join(chars))
        results.append(ae['percentage'])
    mean = sum(results) / len(results)
    std  = (sum((x - mean) ** 2 for x in results) / len(results)) ** 0.5
    ok   = 40.0 <= mean <= 60.0
    print(f'  Iterasi  : {iterations}')
    print(f'  Mean     : {mean:.2f}%   (target: 40-60%)')
    print(f'  Std Dev  : {std:.2f}%')
    print(f'  Min/Max  : {min(results):.2f}% / {max(results):.2f}%')
    print(f'  [{"PASS" if ok else "FAIL"}] SAC dalam range 40-60%: {mean:.2f}%')
    return ok


# ─────────────────────────────────────────────────────────────
#  [H2] COLLISION RESISTANCE
# ─────────────────────────────────────────────────────────────

def test_collision_resistance(pairs: int = 10000):
    print(f'\n=== H2: Collision Resistance SHA-3-256 (n={pairs:,}) ===')
    seen = {}
    collisions = 0
    t0 = time.perf_counter()
    for i in range(pairs):
        msg = secrets.token_hex(16 + (i % 48))
        h   = compute_sha3_256(msg)
        if h in seen:
            collisions += 1
        else:
            seen[h] = msg
    elapsed = (time.perf_counter() - t0) * 1000
    ok = collisions == 0
    print(f'  Pasang diuji : {pairs:,}')
    print(f'  Hash unik    : {len(seen):,}')
    print(f'  Kolisi       : {collisions}')
    print(f'  Waktu        : {elapsed:.1f} ms')
    print(f'  [{"PASS" if ok else "FAIL"}] Zero collision: {ok}')
    return ok


# ─────────────────────────────────────────────────────────────
#  NIST KAT — Known Answer Test
# ─────────────────────────────────────────────────────────────

def test_nist_kat():
    print('\n=== NIST FIPS 202 Known Answer Tests ===')
    # Sumber: NIST FIPS 202 Appendix A
    kat = [
        (b"",    "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a"),
        (b"abc", "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532"),
        (b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
         "41c0dba2a9d6240849100376a8235e2c82e1b9998a999e21db32dd97496d3376"),
    ]
    from crypto.raw_sha3 import sha3_256_hex
    all_pass = True
    for i, (inp, expected) in enumerate(kat):
        got = sha3_256_hex(inp)
        ok  = got == expected
        all_pass = all_pass and ok
        print(f'  [{"PASS" if ok else "FAIL"}] KAT-{i+1} (input={repr(inp)[:20]}): {"COCOK" if ok else "MISMATCH!"}')
    return all_pass


# ─────────────────────────────────────────────────────────────
#  MAIN
# ─────────────────────────────────────────────────────────────

if __name__ == '__main__':
    import argparse
    p = argparse.ArgumentParser()
    p.add_argument('--quick', action='store_true')
    args = p.parse_args()
    iters = 50 if args.quick else 100
    pairs = 1000 if args.quick else 10000

    print('\n' + '=' * 60)
    print('  UNIT TEST SHA-3-256 -- E-Health Crypto Kelompok 7')
    print('  Implementasi: Pure Python Keccak (NIST FIPS 202)')
    print('=' * 60)

    results = {
        'T1 Determinisme'       : test_determinism(),
        'T2 Format Output'      : test_output_format(),
        'T3 Sensitivitas Input' : test_input_sensitivity(),
        'T4 Verify Function'    : test_verify_function(),
        'NIST KAT'              : test_nist_kat(),
        f'H4 Avalanche (n={iters})': test_avalanche_sha3(iters),
        f'H2 Collision (n={pairs})': test_collision_resistance(pairs),
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
