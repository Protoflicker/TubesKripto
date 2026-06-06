"""
crypto/raw_pipeline.py
========================
Pipeline SHA-3-256 + AES-256-GCM MURNI — tanpa library kriptografi.

Menggabungkan raw_sha3.py dan raw_aes.py menjadi satu alur:
  1. Hash pesan dengan SHA-3-256 (raw Keccak)
  2. Enkripsi (pesan + hash) dengan AES-256-GCM (raw FIPS 197 + SP 800-38D)

Tidak ada import dari: hashlib, hmac, pycryptodome, cryptography, dsb.
"""

from .raw_sha3 import sha3_256_of_string, constant_time_compare
from .raw_aes  import (
    encrypt_aes_gcm_raw, decrypt_aes_gcm_raw,
    build_packet, parse_packet, generate_key,
    IV_SIZE, TAG_SIZE, KEY_SIZE
)

SEPARATOR = '||HASH||'


def secure_encrypt_raw(key: bytes, message: str) -> bytes:
    """
    Enkripsi pesan medis dengan SHA-3-256 + AES-256-GCM (pure raw).

    Alur:
      1. digest = SHA3-256(message)       — integritas
      2. payload = message + '||HASH||' + digest
      3. packet  = AES-256-GCM(key, payload) — konfidensialitas + autentikasi

    Return: bytes paket (IV + AuthTag + Ciphertext)
    """
    digest  = sha3_256_of_string(message)
    payload = message + SEPARATOR + digest
    iv, ciphertext, auth_tag = encrypt_aes_gcm_raw(key, payload)
    return build_packet(iv, auth_tag, ciphertext)


def secure_decrypt_raw(key: bytes, packet: bytes) -> dict:
    """
    Dekripsi dan verifikasi paket dengan SHA-3-256 + AES-256-GCM (pure raw).

    Alur:
      1. Parse paket -> IV, AuthTag, Ciphertext
      2. Dekripsi AES-256-GCM (verifikasi auth tag otomatis)
      3. Split payload -> message + hash
      4. Verifikasi SHA-3-256 hash (constant-time compare)

    Return:
        dict dengan keys:
          'message'  : str atau None
          'is_valid' : bool
          'error'    : str atau None
    """
    try:
        iv, auth_tag, ciphertext = parse_packet(packet)
    except ValueError as e:
        return {'message': None, 'is_valid': False, 'error': f'GAGAL PARSE: {e}'}

    try:
        payload = decrypt_aes_gcm_raw(key, iv, ciphertext, auth_tag)
    except ValueError:
        return {'message': None, 'is_valid': False,
                'error': 'GAGAL: Auth Tag tidak cocok — pesan ditolak (indikasi MITM)'}

    if SEPARATOR not in payload:
        return {'message': None, 'is_valid': False,
                'error': 'GAGAL: Format payload tidak valid'}

    message_dec, hash_received = payload.split(SEPARATOR, 1)
    hash_computed = sha3_256_of_string(message_dec)

    if not constant_time_compare(hash_computed, hash_received):
        return {'message': None, 'is_valid': False,
                'error': 'GAGAL: Hash SHA-3-256 tidak cocok — integritas gagal'}

    return {'message': message_dec, 'is_valid': True, 'error': None}
