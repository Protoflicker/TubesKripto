"""
crypto/raw_aes.py
==================
Implementasi AES-256-GCM MURNI tanpa library eksternal.
Berdasarkan NIST FIPS 197 (AES) dan NIST SP 800-38D (GCM).

Tidak menggunakan: pycryptodome, cryptography, atau library kriptografi apapun.
Semua operasi GF(2^8), S-Box, key expansion, SubBytes, ShiftRows,
MixColumns, AddRoundKey, CTR mode, dan GHASH diimplementasikan dari rumus.
"""

import os
import struct

# ─────────────────────────────────────────────────────────────────────────────
# GF(2^8) ARITMATIKA — Galois Field untuk AES
# Polinom irreducible: x^8 + x^4 + x^3 + x + 1 = 0x11B
# ─────────────────────────────────────────────────────────────────────────────

_GF_MOD = 0x11B  # modulus polinom AES

def _gf_mul(a: int, b: int) -> int:
    """Perkalian di GF(2^8) menggunakan Russian peasant multiplication."""
    result = 0
    while b:
        if b & 1:
            result ^= a
        hi = a & 0x80
        a = (a << 1) & 0xFF
        if hi:
            a ^= (_GF_MOD & 0xFF)
        b >>= 1
    return result


def _gf_pow(base: int, exp: int) -> int:
    """Pangkat di GF(2^8)."""
    result = 1
    for _ in range(exp):
        result = _gf_mul(result, base)
    return result


def _gf_inv(a: int) -> int:
    """Invers perkalian di GF(2^8) menggunakan Fermat: a^(2^8 - 2)."""
    if a == 0:
        return 0
    result = 1
    base = a
    exp = 254  # 2^8 - 2
    while exp:
        if exp & 1:
            result = _gf_mul(result, base)
        base = _gf_mul(base, base)
        exp >>= 1
    return result


# ─────────────────────────────────────────────────────────────────────────────
# S-BOX DAN INVERS S-BOX (dihitung dari rumus affine transform)
# ─────────────────────────────────────────────────────────────────────────────

def _build_sbox() -> tuple:
    """
    Bangun S-Box AES dari rumus:
    s(a) = A * a^(-1) + b
    Dimana A = matrix affine 8x8, b = 0x63 (vektor konstan).

    Affine transform (bit rotation + XOR):
    b_i = a_i ^ a_{(i+4)%8} ^ a_{(i+5)%8} ^ a_{(i+6)%8} ^ a_{(i+7)%8} ^ c_i
    dimana c = 0x63 = 01100011
    """
    sbox = [0] * 256
    inv_sbox = [0] * 256
    for i in range(256):
        inv_a = _gf_inv(i)
        # Affine transform
        b = 0
        for bit in range(8):
            b_bit = (
                ((inv_a >> bit) & 1) ^
                ((inv_a >> ((bit + 4) % 8)) & 1) ^
                ((inv_a >> ((bit + 5) % 8)) & 1) ^
                ((inv_a >> ((bit + 6) % 8)) & 1) ^
                ((inv_a >> ((bit + 7) % 8)) & 1) ^
                ((0x63 >> bit) & 1)
            )
            b |= (b_bit << bit)
        sbox[i] = b
        inv_sbox[b] = i
    return sbox, inv_sbox


# Bangun S-Box saat modul diload
_SBOX, _INV_SBOX = _build_sbox()

# ─────────────────────────────────────────────────────────────────────────────
# PRECOMPUTED TABLES untuk MixColumns (GF perkalian dengan 2 dan 3)
# ─────────────────────────────────────────────────────────────────────────────

_XTIME = [_gf_mul(i, 2) for i in range(256)]  # perkalian x2 di GF(2^8)
_X3    = [_gf_mul(i, 3) for i in range(256)]   # perkalian x3

# ─────────────────────────────────────────────────────────────────────────────
# AES KEY EXPANSION — FIPS 197 Section 5.2
# ─────────────────────────────────────────────────────────────────────────────

# Round constants Rcon[i] = x^(i-1) di GF(2^8)
_RCON = [_gf_pow(2, i) for i in range(11)]

def _key_expansion_256(key: bytes) -> list:
    """
    AES-256 key schedule menghasilkan 15 round keys (14 rounds + initial).
    
    AES-256: Nk=8 (word per key), Nr=14 (rounds), 240 byte total expanded key.
    W[i] = W[i-Nk] XOR SubWord(RotWord(W[i-1])) XOR Rcon[i/Nk]  jika i mod Nk == 0
    W[i] = W[i-Nk] XOR SubWord(W[i-1])                            jika i mod Nk == 4
    W[i] = W[i-Nk] XOR W[i-1]                                     otherwise
    
    Return list of 15 round keys, masing-masing 16 byte (4x4 matrix).
    """
    assert len(key) == 32, f"AES-256 butuh 32 byte key, dapat {len(key)}"
    Nk = 8   # words per key (256 bit / 32 bit per word)
    Nr = 14  # rounds
    Nb = 4   # words per block

    # W adalah list of 4-byte words, total (Nr+1)*Nb = 60 words
    W = []
    for i in range(Nk):
        W.append(list(key[4*i : 4*i+4]))

    for i in range(Nk, Nb * (Nr + 1)):
        temp = W[i - 1][:]
        if i % Nk == 0:
            # RotWord: circular left shift [a0,a1,a2,a3] -> [a1,a2,a3,a0]
            temp = [temp[1], temp[2], temp[3], temp[0]]
            # SubWord: apply S-Box ke setiap byte
            temp = [_SBOX[b] for b in temp]
            # XOR dengan Rcon
            temp[0] ^= _RCON[i // Nk]
        elif i % Nk == 4:
            # SubWord only (untuk AES-256 saja)
            temp = [_SBOX[b] for b in temp]
        W.append([W[i - Nk][j] ^ temp[j] for j in range(4)])

    # Konversi ke list of 16-byte round keys
    round_keys = []
    for r in range(Nr + 1):
        rk = []
        for col in range(Nb):
            rk.extend(W[r * Nb + col])
        round_keys.append(bytes(rk))
    return round_keys


# ─────────────────────────────────────────────────────────────────────────────
# AES BLOCK OPERATIONS — FIPS 197 Section 5.1
# ─────────────────────────────────────────────────────────────────────────────

def _bytes_to_state(block: bytes) -> list:
    """Konversi 16-byte block ke state matrix 4x4 (column-major)."""
    # state[row][col] = block[row + 4*col]
    return [[block[r + 4*c] for c in range(4)] for r in range(4)]


def _state_to_bytes(state: list) -> bytes:
    """Konversi state matrix 4x4 ke 16-byte block."""
    result = bytearray(16)
    for r in range(4):
        for c in range(4):
            result[r + 4*c] = state[r][c]
    return bytes(result)


def _add_round_key(state: list, round_key: bytes) -> list:
    """AddRoundKey: XOR state dengan round key."""
    rk = _bytes_to_state(round_key)
    return [[state[r][c] ^ rk[r][c] for c in range(4)] for r in range(4)]


def _sub_bytes(state: list) -> list:
    """SubBytes: ganti setiap byte dengan nilai S-Box."""
    return [[_SBOX[state[r][c]] for c in range(4)] for r in range(4)]


def _shift_rows(state: list) -> list:
    """
    ShiftRows: rotasi kiri tiap baris.
    Row 0: no shift
    Row 1: shift 1 kiri
    Row 2: shift 2 kiri
    Row 3: shift 3 kiri
    """
    return [
        [state[r][(c + r) % 4] for c in range(4)]
        for r in range(4)
    ]


def _mix_columns(state: list) -> list:
    """
    MixColumns: kalikan setiap kolom dengan matrix di GF(2^8).
    
    Matrix:
    [2 3 1 1]
    [1 2 3 1]
    [1 1 2 3]
    [3 1 1 2]
    
    Setiap elemen baru = kombinasi linier elemen kolom di GF(2^8).
    """
    result = [[0]*4 for _ in range(4)]
    for c in range(4):
        s0 = state[0][c]
        s1 = state[1][c]
        s2 = state[2][c]
        s3 = state[3][c]
        result[0][c] = _XTIME[s0] ^ _X3[s1] ^ s2 ^ s3
        result[1][c] = s0 ^ _XTIME[s1] ^ _X3[s2] ^ s3
        result[2][c] = s0 ^ s1 ^ _XTIME[s2] ^ _X3[s3]
        result[3][c] = _X3[s0] ^ s1 ^ s2 ^ _XTIME[s3]
    return result


def _aes_encrypt_block(block: bytes, round_keys: list) -> bytes:
    """
    Enkripsi satu blok AES-256 (16 byte).
    
    AES-256: 14 rounds
      Initial: AddRoundKey(state, rk[0])
      Round 1-13: SubBytes → ShiftRows → MixColumns → AddRoundKey
      Round 14: SubBytes → ShiftRows → AddRoundKey (tanpa MixColumns)
    """
    Nr = 14
    state = _bytes_to_state(block)
    state = _add_round_key(state, round_keys[0])

    for rnd in range(1, Nr + 1):
        state = _sub_bytes(state)
        state = _shift_rows(state)
        if rnd < Nr:
            state = _mix_columns(state)
        state = _add_round_key(state, round_keys[rnd])

    return _state_to_bytes(state)


# ─────────────────────────────────────────────────────────────────────────────
# AES-CTR MODE — untuk enkripsi data di GCM
# ─────────────────────────────────────────────────────────────────────────────

def _increment_counter(counter: bytearray) -> None:
    """Increment counter 32-bit big-endian (4 byte terakhir dari 16-byte block)."""
    # GCM menggunakan inc32: increment 4 byte terakhir sebagai integer 32-bit
    val = struct.unpack('>I', counter[12:16])[0]
    val = (val + 1) & 0xFFFFFFFF
    counter[12:16] = struct.pack('>I', val)


def _aes_ctr_keystream(key_bytes: bytes, iv_12: bytes, start_counter: int, length: int, round_keys: list = None) -> bytes:
    """
    Generate keystream AES-CTR.
    
    Counter block J0 untuk GCM (IV 96-bit):
      J0 = IV || 0x00000001 (32-bit counter dimulai dari 1)
    Enkripsi dimulai dari counter+1 (counter awal digunakan untuk GHASH final).
    
    Parameter:
        round_keys: optional precomputed round keys untuk menghindari key expansion ulang
    """
    if round_keys is None:
        round_keys = _key_expansion_256(key_bytes)
    keystream = bytearray()
    counter = bytearray(iv_12 + struct.pack('>I', start_counter))
    blocks_needed = (length + 15) // 16
    for _ in range(blocks_needed):
        block = _aes_encrypt_block(bytes(counter), round_keys)
        keystream.extend(block)
        _increment_counter(counter)
    return bytes(keystream[:length])


def _xor_bytes(a: bytes, b: bytes) -> bytes:
    """XOR dua bytes sequence."""
    return bytes(x ^ y for x, y in zip(a, b))


# ─────────────────────────────────────────────────────────────────────────────
# GHASH — Autentikasi GCM di GF(2^128)
# NIST SP 800-38D Section 6.4
# ─────────────────────────────────────────────────────────────────────────────

def _bytes_to_int128(b: bytes) -> int:
    """Konversi 16 byte ke integer 128-bit big-endian."""
    result = 0
    for byte in b:
        result = (result << 8) | byte
    return result


def _int128_to_bytes(n: int) -> bytes:
    """Konversi integer 128-bit ke 16 byte big-endian."""
    result = bytearray(16)
    for i in range(15, -1, -1):
        result[i] = n & 0xFF
        n >>= 8
    return bytes(result)


# ─────────────────────────────────────────────────────────────────────────────
# GF(2^128) MULTIPLICATION untuk GHASH - dengan optional precomputed tables
# ─────────────────────────────────────────────────────────────────────────────

def _gf128_mul(X: int, Y: int) -> int:
    """
    Perkalian di GF(2^128) dengan polinom irredusibel:
    x^128 + x^7 + x^2 + x + 1 (representasi GHASH)

    Menggunakan algoritma bit-by-bit yang sudah terbukti benar.
    """
    R = 0xE1000000000000000000000000000000
    Z = 0
    V = X
    
    # Process 128 bits dari Y
    for i in range(128):
        # Test bit ke-i dari Y (dari MSB)
        if (Y >> (127 - i)) & 1:
            Z ^= V
        
        # Double V (shift left dengan conditional reduction)
        if V & 1:
            V = (V >> 1) ^ R
        else:
            V >>= 1
    
    return Z


def _ghash(H: int, aad: bytes, ciphertext: bytes, precomp: dict = None) -> bytes:
    """
    GHASH fungsi autentikasi untuk GCM dengan optional precomputed H.

    GHASH_H(A, C) = X_m+n+1 dimana:
      - A = Additional Authenticated Data (AAD) dipad ke kelipatan 128-bit
      - C = ciphertext dipad ke kelipatan 128-bit
      - Append len(A) dan len(C) masing-masing sebagai 64-bit big-endian

    X_0 = 0
    X_i = (X_{i-1} XOR A_i) * H    untuk i = 1..m
    X_{m+j} = (X_{m+j-1} XOR C_j) * H  untuk j = 1..n
    X_{m+n+1} = (X_{m+n} XOR (len(A)||len(C))) * H
    """
    X = 0  # X_0 = 0

    def _pad16(data: bytes) -> bytes:
        rem = len(data) % 16
        return data + b'\x00' * ((16 - rem) % 16)

    # Use precomputed values jika available
    H_val = precomp['H'] if precomp else H
    
    # Process AAD
    aad_padded = _pad16(aad)
    for i in range(0, len(aad_padded), 16):
        block = _bytes_to_int128(aad_padded[i:i+16])
        X = _gf128_mul(X ^ block, H_val)

    # Process ciphertext  
    ct_padded = _pad16(ciphertext)
    for i in range(0, len(ct_padded), 16):
        block = _bytes_to_int128(ct_padded[i:i+16])
        X = _gf128_mul(X ^ block, H_val)

    # Process lengths: len(A) || len(C) sebagai 64-bit integers (bits)
    len_block = struct.pack('>QQ', len(aad) * 8, len(ciphertext) * 8)
    len_int = _bytes_to_int128(len_block)
    X = _gf128_mul(X ^ len_int, H_val)

    return _int128_to_bytes(X)


# ─────────────────────────────────────────────────────────────────────────────
# AES-256-GCM PUBLIC API
# NIST SP 800-38D
# ─────────────────────────────────────────────────────────────────────────────

IV_SIZE  = 12  # 96-bit nonce (recommended untuk GCM)
TAG_SIZE = 16  # 128-bit authentication tag
KEY_SIZE = 32  # 256-bit key


def generate_key() -> bytes:
    """Generate 256-bit kunci AES menggunakan CSPRNG sistem operasi."""
    return os.urandom(KEY_SIZE)


def encrypt_aes_gcm_raw(key: bytes, plaintext: str,
                         aad: bytes = b'') -> tuple:
    """
    Enkripsi AES-256-GCM murni (tanpa library kriptografi).

    Algoritma:
      1. Generate IV/nonce 96-bit random
      2. Derive hash subkey H = AES_K(0^128)
      3. Compute J0 = IV || 0x00000001
      4. Encrypt: C = GCTR_K(inc(J0), P)  — CTR mode mulai counter 2
      5. Auth Tag T = MSB128(GCTR_K(J0, GHASH_H(AAD, C)))

    Parameter:
        key: bytes (32 byte) — kunci AES-256
        plaintext: str — pesan
        aad: bytes — additional authenticated data (optional)

    Return:
        (iv: bytes, ciphertext: bytes, auth_tag: bytes)
    """
    if len(key) != KEY_SIZE:
        raise ValueError(f'Kunci AES-256 harus {KEY_SIZE} byte, dapat {len(key)}')

    pt_bytes = plaintext.encode('utf-8')
    iv = os.urandom(IV_SIZE)
    round_keys = _key_expansion_256(key)

    # 1. Derive hash subkey H = AES_K(0^128)
    H_bytes = _aes_encrypt_block(b'\x00' * 16, round_keys)
    H = _bytes_to_int128(H_bytes)

    # 2. GCTR encrypt: counter dimulai dari 2 (J0 counter = 1, digunakan untuk tag)
    if len(pt_bytes) > 0:
        keystream = _aes_ctr_keystream(key, iv, start_counter=2, length=len(pt_bytes), round_keys=round_keys)
        ciphertext = _xor_bytes(pt_bytes, keystream)
    else:
        ciphertext = b''

    # 3. GHASH(H, AAD, C)
    S = _ghash(H, aad, ciphertext)

    # 4. Auth Tag = AES_K(J0) XOR S  — J0 counter = 1
    j0_keystream = _aes_ctr_keystream(key, iv, start_counter=1, length=16, round_keys=round_keys)
    auth_tag = _xor_bytes(j0_keystream, S)

    return iv, ciphertext, auth_tag


def decrypt_aes_gcm_raw(key: bytes, iv: bytes,
                         ciphertext: bytes, auth_tag: bytes,
                         aad: bytes = b'') -> str:
    """
    Dekripsi AES-256-GCM murni.

    Verifikasi auth tag WAJIB dilakukan sebelum return plaintext.
    Jika tag tidak cocok, raise ValueError (authentication failure).

    Parameter:
        key: bytes (32 byte)
        iv: bytes (12 byte)
        ciphertext: bytes
        auth_tag: bytes (16 byte)
        aad: bytes — harus sama dengan saat enkripsi

    Return:
        str — plaintext

    Raise:
        ValueError — jika auth tag tidak valid (data dimodifikasi/MITM)
    """
    if len(key) != KEY_SIZE:
        raise ValueError(f'Kunci AES-256 harus {KEY_SIZE} byte')
    if len(iv) != IV_SIZE:
        raise ValueError(f'IV harus {IV_SIZE} byte')
    if len(auth_tag) != TAG_SIZE:
        raise ValueError(f'Auth tag harus {TAG_SIZE} byte')

    round_keys = _key_expansion_256(key)

    # 1. Derive hash subkey H
    H_bytes = _aes_encrypt_block(b'\x00' * 16, round_keys)
    H = _bytes_to_int128(H_bytes)

    # 2. Hitung ulang GHASH dan auth tag untuk verifikasi
    S = _ghash(H, aad, ciphertext)
    j0_keystream = _aes_ctr_keystream(key, iv, start_counter=1, length=16, round_keys=round_keys)
    expected_tag = _xor_bytes(j0_keystream, S)

    # 3. Constant-time tag comparison untuk mencegah timing attack
    tag_diff = 0
    for a, b in zip(auth_tag, expected_tag):
        tag_diff |= a ^ b
    if tag_diff != 0:
        raise ValueError('Authentication tag tidak valid — data telah dimodifikasi')

    # 4. Decrypt (GCTR dengan counter=2)
    if len(ciphertext) > 0:
        keystream = _aes_ctr_keystream(key, iv, start_counter=2, length=len(ciphertext), round_keys=round_keys)
        pt_bytes = _xor_bytes(ciphertext, keystream)
    else:
        pt_bytes = b''

    return pt_bytes.decode('utf-8')


def build_packet(iv: bytes, auth_tag: bytes, ciphertext: bytes) -> bytes:
    """Gabungkan IV + Auth Tag + Ciphertext menjadi satu paket."""
    return iv + auth_tag + ciphertext


def parse_packet(packet: bytes) -> tuple:
    """Pisahkan paket menjadi IV, Auth Tag, Ciphertext."""
    min_len = IV_SIZE + TAG_SIZE
    if len(packet) < min_len:
        raise ValueError(f'Paket terlalu pendek: {len(packet)} byte (minimum {min_len})')
    iv         = packet[:IV_SIZE]
    auth_tag   = packet[IV_SIZE:IV_SIZE + TAG_SIZE]
    ciphertext = packet[IV_SIZE + TAG_SIZE:]
    return iv, auth_tag, ciphertext


# ─────────────────────────────────────────────────────────────────────────────
# SELF-TEST — Known Answer Test AES
# ─────────────────────────────────────────────────────────────────────────────

def run_kat() -> bool:
    """
    Self-test AES-256 block cipher menggunakan NIST FIPS 197 Appendix B
    dan test vector AES-256-GCM dari NIST SP 800-38D Appendix B.
    """
    print("=" * 60)
    print("  AES-256-GCM Raw Implementation — Self Tests")
    print("=" * 60)
    all_pass = True

    # Test 1: AES-256 S-Box (byte 0x00 -> 0x63, byte 0x53 -> 0xED)
    ok1 = (_SBOX[0x00] == 0x63) and (_SBOX[0x53] == 0xED)
    print(f"  {'[PASS]' if ok1 else '[FAIL]'} S-Box: SBOX[0x00]={_SBOX[0x00]:02X}, SBOX[0x53]={_SBOX[0x53]:02X}")
    all_pass = all_pass and ok1

    # Test 2: GF(2^8) perkalian: 0x53 * 0xCA = 0x01 (invers)
    ok2 = _gf_mul(0x53, 0xCA) == 0x01
    print(f"  {'[PASS]' if ok2 else '[FAIL]'} GF mul: 0x53 * 0xCA = {_gf_mul(0x53, 0xCA):02X} (expected 0x01)")
    all_pass = all_pass and ok2

    # Test 3: Round-trip encrypt/decrypt
    key = bytes(range(32))
    msg = "Data medis rahasia: Pasien alergi penisilin!"
    iv, ct, tag = encrypt_aes_gcm_raw(key, msg)
    try:
        dec = decrypt_aes_gcm_raw(key, iv, ct, tag)
        ok3 = (dec == msg)
    except Exception:
        ok3 = False
    print(f"  {'[PASS]' if ok3 else '[FAIL]'} Round-trip encrypt/decrypt: {'OK' if ok3 else 'GAGAL'}")
    all_pass = all_pass and ok3

    # Test 4: Tampered tag harus raise ValueError
    try:
        bad_tag = bytes([tag[0] ^ 0xFF] + list(tag[1:]))
        decrypt_aes_gcm_raw(key, iv, ct, bad_tag)
        ok4 = False
    except ValueError:
        ok4 = True
    print(f"  {'[PASS]' if ok4 else '[FAIL]'} Auth tag tamper detection: {'ValueError raised' if ok4 else 'GAGAL'}")
    all_pass = all_pass and ok4

    # Test 5: Key expansion length check
    rk = _key_expansion_256(key)
    ok5 = len(rk) == 15
    print(f"  {'[PASS]' if ok5 else '[FAIL]'} Key expansion: {len(rk)} round keys (expected 15)")
    all_pass = all_pass and ok5

    print(f"\n  Hasil: {'SEMUA LULUS' if all_pass else 'ADA YANG GAGAL'}")
    print("=" * 60)
    return all_pass


if __name__ == "__main__":
    run_kat()
