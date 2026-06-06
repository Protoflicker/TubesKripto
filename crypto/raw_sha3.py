"""
crypto/raw_sha3.py
===================
Implementasi SHA-3-256 MURNI dari rumus matematika tanpa library eksternal.
Berdasarkan NIST FIPS 202 — SHA-3 Standard (Keccak sponge construction).

Tidak menggunakan: hashlib, hmac, atau library kriptografi apapun.
Semua operasi bitwise, permutasi Keccak-p[1600,24], dan sponge construction
diimplementasikan manual dari spesifikasi resmi.

Referensi:
  - NIST FIPS 202: https://doi.org/10.6028/NIST.FIPS.202
  - Keccak team reference: https://keccak.team/keccak_specs_summary.html
  - The Keccak Reference, Version 3.0

Algoritma:
  SHA3-256 = KECCAK[512](M || 0x06, 256)
  Rate r = 1088 bit = 136 byte
  Capacity c = 512 bit
  Output len = 256 bit = 32 byte
"""

# ─────────────────────────────────────────────────────────────────────────────
# KONSTANTA KECCAK-p[1600, 24]
# ─────────────────────────────────────────────────────────────────────────────

# Round constants RC[ir] untuk iota step — dihitung dari LFSR degree-8 polynomial
# x^8 + x^6 + x^5 + x^4 + 1 atas GF(2), 24 putaran
# Nilai ini adalah hasil dari algoritma rc(t) per FIPS 202 Section 3.2.5
_KECCAK_RC = [
    0x0000000000000001, 0x0000000000008082,
    0x800000000000808A, 0x8000000080008000,
    0x000000000000808B, 0x0000000080000001,
    0x8000000080008081, 0x8000000000008009,
    0x000000000000008A, 0x0000000000000088,
    0x0000000080008009, 0x000000008000000A,
    0x000000008000808B, 0x800000000000008B,
    0x8000000000008089, 0x8000000000008003,
    0x8000000000008002, 0x8000000000000080,
    0x000000000000800A, 0x800000008000000A,
    0x8000000080008081, 0x8000000000008080,
    0x0000000080000001, 0x8000000080008008,
]

# Rotation offsets rho[x][y] untuk rho step — dihitung dari algoritma:
# (x,y) = (1,0), kemudian (y, (2x+3y) mod 5) secara berulang
# Tabel 2 di FIPS 202 Appendix B Table 3
_KECCAK_RHO = [
    [  0, 36,  3, 41, 18 ],
    [  1, 44, 10, 45,  2 ],
    [ 62,  6, 43, 15, 61 ],
    [ 28, 55, 25, 21, 56 ],
    [ 27, 20, 39,  8, 14 ],
]

# Pi permutation — x,y -> (y, 2x+3y mod 5)
# Precomputed untuk efisiensi
_KECCAK_PI_X = [
    [0, 1, 2, 3, 4],
    [1, 2, 3, 4, 0],
    [2, 3, 4, 0, 1],
    [3, 4, 0, 1, 2],
    [4, 0, 1, 2, 3],
]
_KECCAK_PI_Y = [
    [0, 0, 0, 0, 0],
    [2, 2, 2, 2, 2],
    [4, 4, 4, 4, 4],
    [1, 1, 1, 1, 1],
    [3, 3, 3, 3, 3],
]

# Mask 64-bit untuk overflow prevention
_MASK64 = 0xFFFFFFFFFFFFFFFF

# ─────────────────────────────────────────────────────────────────────────────
# HELPER BITWISE
# ─────────────────────────────────────────────────────────────────────────────

def _rot64(val: int, n: int) -> int:
    """Left rotation 64-bit. ROT(a, n) = ((a << n) | (a >> (64-n))) mod 2^64"""
    n &= 63
    return ((val << n) | (val >> (64 - n))) & _MASK64


def _load64_le(data: bytes, offset: int) -> int:
    """Load 8 byte sebagai 64-bit integer little-endian."""
    result = 0
    for i in range(8):
        result |= data[offset + i] << (8 * i)
    return result


def _store64_le(val: int) -> bytes:
    """Store 64-bit integer sebagai 8 byte little-endian."""
    result = bytearray(8)
    for i in range(8):
        result[i] = (val >> (8 * i)) & 0xFF
    return bytes(result)


# ─────────────────────────────────────────────────────────────────────────────
# KECCAK-p[1600, 24] PERMUTATION
# ─────────────────────────────────────────────────────────────────────────────

def _keccak_f1600(state: list) -> list:
    """
    Fungsi permutasi Keccak-f[1600] dengan 24 putaran.

    State adalah 5x5 array dari 64-bit lane (integer Python).
    Setiap putaran terdiri dari 5 step mappings: θ, ρ, π, χ, ι

    Input/output: list[5][5] integer 64-bit
    """
    A = [row[:] for row in state]   # copy state 5x5

    for rnd in range(24):
        # ── Step 1: θ (theta) ──────────────────────────────────────────
        # C[x] = A[x,0] XOR A[x,1] XOR A[x,2] XOR A[x,3] XOR A[x,4]  ∀x
        # D[x] = C[x-1] XOR ROT(C[x+1], 1)                             ∀x
        # A[x,y] = A[x,y] XOR D[x]                                     ∀(x,y)
        C = [
            A[x][0] ^ A[x][1] ^ A[x][2] ^ A[x][3] ^ A[x][4]
            for x in range(5)
        ]
        D = [
            C[(x - 1) % 5] ^ _rot64(C[(x + 1) % 5], 1)
            for x in range(5)
        ]
        A = [
            [A[x][y] ^ D[x] for y in range(5)]
            for x in range(5)
        ]

        # ── Step 2: ρ (rho) + π (pi) ──────────────────────────────────
        # ρ: A[x,y] = ROT(A[x,y], offset[x][y])
        # π: A'[x,y] = A[(x + 3y) mod 5][x]
        # Digabung untuk efisiensi satu pass
        B = [[0] * 5 for _ in range(5)]
        for x in range(5):
            for y in range(5):
                # pi: new position (y, (2x+3y) mod 5)
                new_x = y
                new_y = (2 * x + 3 * y) % 5
                B[new_x][new_y] = _rot64(A[x][y], _KECCAK_RHO[x][y])

        # ── Step 3: χ (chi) ────────────────────────────────────────────
        # A[x,y] = B[x,y] XOR ((NOT B[x+1,y]) AND B[x+2,y])
        A = [
            [
                B[x][y] ^ ((~B[(x + 1) % 5][y] & _MASK64) & B[(x + 2) % 5][y])
                for y in range(5)
            ]
            for x in range(5)
        ]

        # ── Step 4: ι (iota) ───────────────────────────────────────────
        # A[0,0] = A[0,0] XOR RC[ir]
        A[0][0] ^= _KECCAK_RC[rnd]

    return A


# ─────────────────────────────────────────────────────────────────────────────
# KECCAK SPONGE CONSTRUCTION
# ─────────────────────────────────────────────────────────────────────────────

class _KeccakSponge:
    """
    Keccak sponge construction generik.

    Mendukung absorb (input) dan squeeze (output) dengan parameter:
      - rate: ukuran blok dalam byte
      - capacity: ukuran kapasitas dalam bit (tidak digunakan langsung)
      - domain_suffix: padding domain separation byte (0x06 untuk SHA-3)
      - output_length: panjang output dalam byte
    """

    def __init__(self, rate_bytes: int, domain_suffix: int, output_length: int):
        self._rate    = rate_bytes          # rate dalam byte (r/8)
        self._dsfx    = domain_suffix       # domain separation byte
        self._outlen  = output_length       # output dalam byte
        # State: 5x5 lanes, masing-masing 64-bit integer, init 0
        self._state   = [[0] * 5 for _ in range(5)]
        self._buf     = bytearray()         # buffer input yang belum di-absorb

    # ── Absorb phase ──────────────────────────────────────────────────────────

    def _xor_into_state(self, block: bytes) -> None:
        """XOR satu blok rate-bytes ke dalam state lanes."""
        # Keccak state diindeks sebagai lane A[x + 5y], little-endian 64-bit
        for i in range(self._rate // 8):
            x = i % 5
            y = i // 5
            lane = _load64_le(block, i * 8)
            self._state[x][y] ^= lane

    def absorb(self, data: bytes) -> None:
        """Masukkan data ke sponge."""
        self._buf.extend(data)

        # Proses blok rate-sized penuh
        while len(self._buf) >= self._rate:
            block = bytes(self._buf[:self._rate])
            del self._buf[:self._rate]
            self._xor_into_state(block)
            self._state = _keccak_f1600(self._state)

    def _finalize(self) -> None:
        """Padding dan finalisasi absorb phase."""
        # FIPS 202 §B.2: multi-rate padding pad10*1
        # Untuk SHA-3: suffix = 0x06, kemudian 0x00..., kemudian 0x80 di byte akhir rate
        padded = bytearray(self._buf)
        padded.append(self._dsfx)       # domain separation + padding bit 1
        while len(padded) < self._rate:
            padded.append(0x00)
        padded[-1] |= 0x80              # bit 1 terakhir di rate boundary
        self._xor_into_state(bytes(padded))
        self._state = _keccak_f1600(self._state)
        self._buf   = bytearray()

    # ── Squeeze phase ─────────────────────────────────────────────────────────

    def digest(self) -> bytes:
        """Finalize dan squeeze output."""
        self._finalize()
        output = bytearray()
        remaining = self._outlen
        while remaining > 0:
            # Squeeze rate bytes dari state
            to_take = min(remaining, self._rate)
            for i in range((to_take + 7) // 8):
                x = i % 5
                y = i // 5
                lane_bytes = _store64_le(self._state[x][y])
                output.extend(lane_bytes[:min(8, to_take - i * 8)])
            remaining -= to_take
            if remaining > 0:
                self._state = _keccak_f1600(self._state)
        return bytes(output[:self._outlen])


# ─────────────────────────────────────────────────────────────────────────────
# PUBLIC API — SHA-3-256
# ─────────────────────────────────────────────────────────────────────────────

# Parameter SHA-3-256 (FIPS 202):
#   Output = 256 bit = 32 byte
#   Capacity c = 512 bit
#   Rate r = 1600 - 512 = 1088 bit = 136 byte
#   Domain suffix = 0x06 (SHA-3 spesifik, berbeda dari Keccak murni yang 0x01)
_SHA3_256_RATE    = 136   # byte
_SHA3_256_OUTLEN  = 32    # byte
_SHA3_256_DOMAIN  = 0x06  # domain separation SHA-3


def sha3_256_raw(data: bytes) -> bytes:
    """
    Hitung SHA-3-256 dari data bytes.
    Implementasi MURNI tanpa library — hanya bitwise Python.

    Parameter:
        data: bytes — pesan yang akan di-hash

    Return:
        bytes (32 byte / 256 bit) — digest SHA-3-256

    Contoh:
        >>> sha3_256_raw(b"abc").hex()
        '3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532'
    """
    sponge = _KeccakSponge(
        rate_bytes    = _SHA3_256_RATE,
        domain_suffix = _SHA3_256_DOMAIN,
        output_length = _SHA3_256_OUTLEN,
    )
    sponge.absorb(data)
    return sponge.digest()


def sha3_256_hex(data: bytes) -> str:
    """Return SHA-3-256 sebagai string hexadecimal lowercase (64 karakter)."""
    raw = sha3_256_raw(data)
    return ''.join(f'{b:02x}' for b in raw)


def sha3_256_of_string(message: str, encoding: str = 'utf-8') -> str:
    """
    Hitung SHA-3-256 dari string, return hexdigest.
    Wrapper convenience untuk string input.
    """
    return sha3_256_hex(message.encode(encoding))


# ─────────────────────────────────────────────────────────────────────────────
# HMAC-SHA3-256 (PURE — tanpa hmac library)
# ─────────────────────────────────────────────────────────────────────────────

_HMAC_BLOCKSIZE = _SHA3_256_RATE  # 136 byte untuk SHA3-256

def hmac_sha3_256_raw(key: bytes, message: bytes) -> bytes:
    """
    HMAC-SHA3-256 implementasi murni (RFC 2104).

    HMAC(K, m) = H( (K' XOR opad) || H( (K' XOR ipad) || m ) )
    Dimana:
      K' = key yang dipad/ditruncate ke blocksize
      ipad = 0x36 * blocksize
      opad = 0x5C * blocksize

    Parameter:
        key: bytes — kunci HMAC (arbitrary length)
        message: bytes — pesan

    Return:
        bytes (32 byte) — HMAC-SHA3-256
    """
    # Derive K' (key normalization)
    if len(key) > _HMAC_BLOCKSIZE:
        k_prime = sha3_256_raw(key)       # truncate oversized key
    else:
        k_prime = key
    # Pad K' ke blocksize
    k_prime = k_prime + b'\x00' * (_HMAC_BLOCKSIZE - len(k_prime))

    # Inner hash: H( (K' XOR ipad) || message )
    ipad = bytes(b ^ 0x36 for b in k_prime)
    inner = sha3_256_raw(ipad + message)

    # Outer hash: H( (K' XOR opad) || inner )
    opad = bytes(b ^ 0x5C for b in k_prime)
    return sha3_256_raw(opad + inner)


def hmac_sha3_256_hex(key: bytes, message: bytes) -> str:
    """Return HMAC-SHA3-256 sebagai hexadecimal string."""
    return ''.join(f'{b:02x}' for b in hmac_sha3_256_raw(key, message))


# ─────────────────────────────────────────────────────────────────────────────
# CONSTANT-TIME COMPARISON (pengganti hmac.compare_digest)
# ─────────────────────────────────────────────────────────────────────────────

def constant_time_compare(a: str, b: str) -> bool:
    """
    Perbandingan string constant-time untuk mencegah timing attack.
    Implementasi manual tanpa hmac.compare_digest.

    Waktu eksekusi sama terlepas dari posisi perbedaan pertama.
    Ini penting agar attacker tidak bisa mengukur waktu untuk menebak hash.

    Menggunakan XOR reduction: result = 0 jika semua karakter sama.
    """
    if len(a) != len(b):
        # Panjang berbeda — tetap proses full length untuk konstan-waktu
        # Bandingkan dengan padding dummy
        dummy = b[:len(a)] if len(b) >= len(a) else b + b[0:1] * (len(a) - len(b))
        result = len(a) ^ len(b)  # nonzero = berbeda
        for ca, cb in zip(a, dummy):
            result |= ord(ca) ^ ord(cb)
        return False  # panjang berbeda pasti False

    # Panjang sama — XOR semua karakter, accumulate diff bits
    diff = 0
    for ca, cb in zip(a, b):
        diff |= ord(ca) ^ ord(cb)
    return diff == 0


# ─────────────────────────────────────────────────────────────────────────────
# SELF-TEST — NIST KNOWN ANSWER TESTS (KAT)
# ─────────────────────────────────────────────────────────────────────────────

_SHA3_256_KAT = [
    # (input_hex, expected_sha3_256_hex)
    # Source: NIST FIPS 202 Appendix A / CAVP test vectors
    (
        b"",
        "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a"
    ),
    (
        b"abc",
        "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532"
    ),
    (
        b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
        "41c0dba2a9d6240849100376a8235e2c82e1b9998a999e21db32dd97496d3376"
    ),
    (
        b"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu",
        "916f6061fe879741ca6469b43971dfdb28b1a32dc36cb3254e812be27aad1d18"
    ),
]


def run_kat() -> bool:
    """
    Jalankan Known Answer Tests untuk validasi implementasi SHA-3-256.
    Return True jika semua test lulus.
    """
    print("=" * 60)
    print("  SHA-3-256 Raw Implementation — Known Answer Tests")
    print("=" * 60)
    all_pass = True
    for i, (msg, expected) in enumerate(_SHA3_256_KAT):
        got = sha3_256_hex(msg)
        ok  = (got == expected)
        all_pass = all_pass and ok
        status = "[PASS]" if ok else "[FAIL]"
        print(f"  {status} KAT-{i+1}: input={repr(msg)[:30]}")
        if not ok:
            print(f"         Expected: {expected}")
            print(f"         Got:      {got}")
    print(f"\n  Hasil: {'SEMUA LULUS' if all_pass else 'ADA YANG GAGAL'}")
    print("=" * 60)
    return all_pass


if __name__ == "__main__":
    run_kat()
