"""
crypto/sha3_utils.py
Modul SHA-3-256 untuk sistem e-health secure messaging.
Implementasi MURNI tanpa library kriptografi — menggunakan raw_sha3.py
yang mengimplementasikan Keccak-p[1600,24] sponge construction dari NIST FIPS 202.
"""
from .raw_sha3 import sha3_256_of_string, sha3_256_hex, constant_time_compare


def compute_sha3_256(message: str) -> str:
    """Hitung SHA-3-256 dari string. Return hexdigest 64 karakter."""
    if not isinstance(message, str):
        raise TypeError('message harus berupa string')
    return sha3_256_of_string(message)


def verify_sha3_256(message: str, expected_digest: str) -> bool:
    """Verifikasi SHA-3-256 digest dengan constant-time comparison."""
    computed = compute_sha3_256(message)
    return constant_time_compare(computed, expected_digest)


def compute_avalanche_effect(msg1: str, msg2: str) -> dict:
    """Hitung avalanche effect antara dua pesan (% bit yang berbeda)."""
    d1 = compute_sha3_256(msg1)
    d2 = compute_sha3_256(msg2)
    bits1 = bin(int(d1, 16))[2:].zfill(256)
    bits2 = bin(int(d2, 16))[2:].zfill(256)
    changed = sum(a != b for a, b in zip(bits1, bits2))
    return {
        'bits_changed': changed,
        'total_bits': 256,
        'percentage': round((changed / 256) * 100.0, 2),
        'digest1': d1,
        'digest2': d2
    }
