"""
crypto/aes_gcm_utils.py
Modul AES-256-GCM untuk sistem e-health secure messaging.
Implementasi MURNI tanpa library kriptografi — menggunakan raw_aes.py
yang mengimplementasikan AES-256 + GCM dari NIST FIPS 197 dan SP 800-38D.
"""
from .raw_aes import (
    encrypt_aes_gcm_raw as encrypt_aes_gcm,
    decrypt_aes_gcm_raw as decrypt_aes_gcm,
    generate_key, build_packet, parse_packet,
    IV_SIZE, TAG_SIZE, KEY_SIZE
)

__all__ = [
    'generate_key', 'encrypt_aes_gcm', 'decrypt_aes_gcm',
    'build_packet', 'parse_packet',
    'IV_SIZE', 'TAG_SIZE', 'KEY_SIZE',
]
