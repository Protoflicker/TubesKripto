"""
app.py — E-Health Crypto Simulator — Kelompok 7
Progress 3: Sistem lengkap dengan endpoint pengujian keamanan dan performa.
"""
import time
import os
import random
import secrets as secrets_mod

from flask import Flask, request, jsonify, render_template
from crypto.raw_aes import encrypt_aes_gcm_raw as _aes_enc, decrypt_aes_gcm_raw as _aes_dec

from crypto.sha3_utils    import compute_sha3_256, verify_sha3_256, compute_avalanche_effect
from crypto.aes_gcm_utils import generate_key, encrypt_aes_gcm, decrypt_aes_gcm, build_packet, parse_packet

app = Flask(__name__)
SERVER_KEY = generate_key()


# ─────────────────────────────────────────────────────────────
#  HALAMAN UTAMA
# ─────────────────────────────────────────────────────────────
@app.route('/')
def index():
    return render_template('index.html')


# ─────────────────────────────────────────────────────────────
#  RESET KUNCI SERVER
# ─────────────────────────────────────────────────────────────
@app.route('/api/reset_key', methods=['POST'])
def reset_key():
    global SERVER_KEY
    SERVER_KEY = generate_key()
    return jsonify({
        'last5': SERVER_KEY.hex()[-5:],
        'key_preview': SERVER_KEY.hex()[:16] + '...' + SERVER_KEY.hex()[-8:],
    })


# ─────────────────────────────────────────────────────────────
#  PREVIEW KUNCI (5 KARAKTER TERAKHIR)
# ─────────────────────────────────────────────────────────────
@app.route('/api/key_preview', methods=['GET'])
def key_preview():
    return jsonify({'last5': SERVER_KEY.hex()[-5:]})


# ─────────────────────────────────────────────────────────────
#  PROSES ENKRIPSI + DEKRIPSI (Messaging Demo)
# ─────────────────────────────────────────────────────────────
@app.route('/process', methods=['POST'])
def process():
    data                  = request.json
    message               = data.get('message', '')
    mitm_enabled          = data.get('mitm_enabled', False)
    mitm_byte_pos         = int(data.get('mitm_byte_pos', 30))
    tamper_hash_triggered = data.get('tamper_hash', False)

    steps = []
    result = {
        'is_valid': False, 'message': None, 'error': None,
        'plaintext_length': 0, 'packet_size': 0, 'processing_time_ms': 0,
        'digest': None, 'iv': None, 'auth_tag': None,
        'mitm_triggered': mitm_enabled, 'tamper_hash_triggered': tamper_hash_triggered
    }

    start_time = time.perf_counter()

    # Step 1 — SHA-3-256
    msg_bytes = message.encode('utf-8')
    N_msg = len(msg_bytes)
    steps.append({'type': 'SHA3', 'title': 'Menghitung SHA-3-256 dari plaintext...',
                  'detail': {'Input': f'"{message[:50]}..." ({N_msg} byte)' if N_msg > 50 else f'"{message}" ({N_msg} byte)'}, 'delay_ms': 300})

    digest = compute_sha3_256(message)
    steps.append({'type': 'SHA3', 'title': 'SHA-3-256 digest berhasil dihitung',
                  'detail': {'Digest': digest, 'Bit': '256', 'Byte': '32', 'Deterministik': 'Ya'}, 'delay_ms': 300})

    # Step 2 — Build payload
    payload = message + '||HASH||' + digest
    N_payload = len(payload.encode('utf-8'))
    steps.append({'type': 'PACKET', 'title': 'Menyusun payload gabungan...',
                  'detail': {'Format': 'plaintext + ||HASH|| + digest', 'Panjang total': f'{N_payload} byte'}, 'delay_ms': 250})

    # Step 3 — AES-256-GCM Encrypt
    iv, ciphertext, auth_tag = encrypt_aes_gcm(SERVER_KEY, payload)
    N_ct = len(ciphertext)

    steps.append({'type': 'AES-ENC', 'title': 'Membangkitkan IV 96-bit secara acak (CSPRNG)...',
                  'detail': {'IV': iv.hex()}, 'delay_ms': 300})
    steps.append({'type': 'AES-ENC', 'title': 'Menjalankan AES-256-GCM encrypt_and_digest()...',
                  'detail': {'Key': f'{SERVER_KEY.hex()[:16]}... (32 byte / 256 bit)',
                              'Mode': 'GCM — Counter Mode + GHASH over GF(2¹²⁸)'}, 'delay_ms': 400})
    steps.append({'type': 'AES-ENC', 'title': 'Enkripsi AEAD selesai',
                  'detail': {'Ciphertext': f'{ciphertext.hex()[:32]}... ({N_ct} byte)',
                              'Auth Tag': f'{auth_tag.hex()} (16 byte / 128 bit)'}, 'delay_ms': 300})

    # Step 4 — Build packet
    packet = build_packet(iv, auth_tag, ciphertext)
    packet_size = len(packet)
    steps.append({'type': 'PACKET', 'title': 'Menyusun paket biner untuk transmisi...',
                  'detail': {'Struktur': f'IV[12] + AuthTag[16] + CT[{N_ct}]',
                              'Total': f'{packet_size} byte'}, 'delay_ms': 250})

    # Step 5 — Optional MITM attack
    ct_bytes = bytearray(ciphertext)
    if mitm_enabled:
        pos = max(0, min(mitm_byte_pos, N_ct - 1))
        before, ct_bytes[pos] = ct_bytes[pos], ct_bytes[pos] ^ 0xFF
        steps.append({'type': 'ATTACK',
                      'title': f'MITM: Memodifikasi byte ke-[{pos}] ciphertext (XOR 0xFF)',
                      'detail': {'Byte sebelum': f'0x{before:02X}', 'Byte sesudah': f'0x{ct_bytes[pos]:02X}',
                                 'Dampak': 'Auth Tag akan mismatch, dekripsi GAGAL'}, 'delay_ms': 500})

    # Step 6 — Parse + Decrypt
    tampered_packet = build_packet(iv, auth_tag, bytes(ct_bytes))
    parsed_iv, parsed_tag, parsed_ct = parse_packet(tampered_packet)

    steps.append({'type': 'AES-DEC', 'title': 'Memisahkan IV / Auth Tag / Ciphertext dari paket...',
                  'detail': {'IV': parsed_iv.hex(), 'Tag': parsed_tag.hex(),
                              'CT': f'[{len(parsed_ct)} byte]'}, 'delay_ms': 300})
    steps.append({'type': 'AES-DEC', 'title': 'Menjalankan decrypt_and_verify() — Gerbang Keamanan 1...',
                  'detail': {'Verifikasi': 'GHASH Authentication Tag (128-bit)'}, 'delay_ms': 400})

    try:
        decrypted_payload = decrypt_aes_gcm(SERVER_KEY, parsed_iv, parsed_ct, parsed_tag)
        steps.append({'type': 'AES-DEC', 'title': 'Auth Tag valid, integritas transmisi terjamin',
                      'detail': {'Payload': f'{len(decrypted_payload.encode())} byte ter-dekripsi'}, 'delay_ms': 300})

        parts = decrypted_payload.split('||HASH||', 1)
        if len(parts) == 2:
            dec_message, received_hash = parts

            steps.append({'type': 'VERIFY', 'title': 'Memisahkan plaintext dan hash dari payload...',
                          'detail': {'Plaintext': f'"{dec_message[:50]}..."' if len(dec_message) > 50 else f'"{dec_message}"',
                                     'Hash diterima': received_hash}, 'delay_ms': 300})

            if tamper_hash_triggered:
                tampered = received_hash[:-1] + ('0' if received_hash[-1] != '0' else '1')
                steps.append({'type': 'ATTACK', 'title': 'TAMPER: Mengubah hash setelah dekripsi (simulasi storage attack)',
                              'detail': {'Hash asli': received_hash[:24] + '...', 'Hash diubah': tampered[:24] + '...'}, 'delay_ms': 400})
                received_hash = tampered

            computed_hash = compute_sha3_256(dec_message)
            steps.append({'type': 'VERIFY', 'title': 'Menghitung ulang SHA-3-256 — Gerbang Keamanan 2...',
                          'detail': {'Hash computed': computed_hash}, 'delay_ms': 300})

            if computed_hash == received_hash:
                steps.append({'type': 'OK', 'title': 'Hash COCOK, Integritas konten terjamin',
                              'detail': {'Status': 'PESAN VALID, diteruskan ke penerima'}, 'delay_ms': 300})
                result.update({'is_valid': True, 'message': dec_message})
            else:
                steps.append({'type': 'ERROR', 'title': 'Hash TIDAK COCOK, Integritas konten gagal',
                              'detail': {'Penyebab': 'SHA-3 digest mismatch setelah dekripsi',
                                         'Status': 'PESAN DITOLAK, tidak dikirim ke penerima'}, 'delay_ms': 300})
                result['error'] = 'hash_mismatch'

    except ValueError:
        steps.append({'type': 'ERROR', 'title': 'MAC check FAILED, Auth Tag tidak cocok',
                      'detail': {'Penyebab': 'Ciphertext telah dimodifikasi dalam transit',
                                 'Status': 'PESAN DITOLAK, tidak dikirim ke penerima (kemungkinan MITM)'}, 'delay_ms': 300})
        result['error'] = 'mac_failed'

    end_time = time.perf_counter()
    result.update({
        'plaintext_length': N_msg, 'packet_size': packet_size,
        'processing_time_ms': round((end_time - start_time) * 1000, 2),
        'digest': digest, 'iv': iv.hex(), 'auth_tag': auth_tag.hex()
    })
    return jsonify({'steps': steps, 'result': result})


# ─────────────────────────────────────────────────────────────
#  E4 — AVALANCHE EFFECT SHA-3-256
# ─────────────────────────────────────────────────────────────
@app.route('/api/test/avalanche_sha3', methods=['POST'])
def api_avalanche_sha3():
    data = request.json or {}
    iterations = max(10, min(int(data.get('iterations', 100)), 300))
    base = data.get('message',
                    'Pasien: Budi Santoso. Diagnosis: ISPA. Resep: Amoxicillin 500mg, 3x1, 5 hari.')
    results = []
    for i in range(iterations):
        chars = list(base)
        pos = i % len(base)
        chars[pos] = chr(ord(chars[pos]) ^ 1)
        ae = compute_avalanche_effect(base, ''.join(chars))
        results.append(ae['percentage'])

    mean = sum(results) / len(results)
    variance = sum((x - mean) ** 2 for x in results) / len(results)
    std = variance ** 0.5

    bins = list(range(40, 62, 2))
    hist = [0] * (len(bins) - 1)
    for v in results:
        for j in range(len(bins) - 1):
            if bins[j] <= v < bins[j + 1]:
                hist[j] += 1
                break
    labels = [f'{bins[i]}-{bins[i+1]}%' for i in range(len(bins) - 1)]

    return jsonify({
        'iterations': iterations, 'mean': round(mean, 2), 'std': round(std, 2),
        'min': round(min(results), 2), 'max': round(max(results), 2),
        'distribution': [round(x, 2) for x in results],
        'histogram': {'labels': labels, 'counts': hist},
        'pass': 40 <= mean <= 60, 'pass_strict': 45 <= mean <= 55
    })


# ─────────────────────────────────────────────────────────────
#  E1 — AVALANCHE EFFECT AES-256-GCM (Key Sensitivity)
# ─────────────────────────────────────────────────────────────
@app.route('/api/test/avalanche_aes', methods=['POST'])
def api_avalanche_aes():
    data = request.json or {}
    iterations = max(10, min(int(data.get('iterations', 100)), 150))
    plaintext = data.get('message',
                         'Pasien: Budi Santoso. Diagnosis: ISPA. Resep: Amoxicillin 500mg, 3x1, 5 hari.')
    results = []
    for _ in range(iterations):
        key1 = generate_key()
        key2 = bytearray(key1)
        key2[random.randint(0, 31)] ^= (1 << random.randint(0, 7))

        iv = os.urandom(12)
        _, tag1_raw = _aes_enc.__wrapped__(key1, plaintext, iv=iv) if hasattr(_aes_enc, '__wrapped__') else (None, None)
        # Gunakan raw_aes langsung untuk enkripsi dengan IV tetap
        import struct
        from crypto.raw_aes import _key_expansion_256, _aes_encrypt_block, _xor_bytes, _ghash, _bytes_to_int128, _int128_to_bytes, _aes_ctr_keystream
        def _enc_fixed_iv(k, pt_bytes, iv_fixed):
            rk = _key_expansion_256(k)
            H = _bytes_to_int128(_aes_encrypt_block(b'\x00'*16, rk))
            ks = _aes_ctr_keystream(k, iv_fixed, 2, len(pt_bytes)) if pt_bytes else b''
            ct = _xor_bytes(pt_bytes, ks) if pt_bytes else b''
            S  = _ghash(H, b'', ct)
            j0 = _aes_ctr_keystream(k, iv_fixed, 1, 16)
            return _xor_bytes(j0, S)
        pt_b = plaintext.encode('utf-8')
        tag1 = _enc_fixed_iv(key1, pt_b, iv)
        tag2 = _enc_fixed_iv(bytes(key2), pt_b, iv)

        b1 = bin(int(tag1.hex(), 16))[2:].zfill(128)
        b2 = bin(int(tag2.hex(), 16))[2:].zfill(128)
        changed = sum(a != b for a, b in zip(b1, b2))
        results.append(round(changed / 128 * 100, 2))

    mean = sum(results) / len(results)
    variance = sum((x - mean) ** 2 for x in results) / len(results)
    std = variance ** 0.5

    bins = list(range(30, 72, 4))
    hist = [0] * (len(bins) - 1)
    for v in results:
        for j in range(len(bins) - 1):
            if bins[j] <= v < bins[j + 1]:
                hist[j] += 1
                break
    labels = [f'{bins[i]}-{bins[i+1]}%' for i in range(len(bins) - 1)]

    return jsonify({
        'iterations': iterations, 'mean': round(mean, 2), 'std': round(std, 2),
        'min': round(min(results), 2), 'max': round(max(results), 2),
        'distribution': [round(x, 2) for x in results],
        'histogram': {'labels': labels, 'counts': hist},
        'pass': 40 <= mean <= 60, 'pass_strict': 45 <= mean <= 55
    })


# ─────────────────────────────────────────────────────────────
#  H2 — COLLISION RESISTANCE SHA-3-256
# ─────────────────────────────────────────────────────────────
@app.route('/api/test/collision', methods=['POST'])
def api_collision():
    data = request.json or {}
    pairs = max(100, min(int(data.get('pairs', 10000)), 50000))
    seen = {}
    collisions = 0
    for i in range(pairs):
        msg = secrets_mod.token_hex(16 + (i % 48))
        h = compute_sha3_256(msg)
        if h in seen:
            collisions += 1
        else:
            seen[h] = msg
    return jsonify({
        'pairs_tested': pairs, 'unique_hashes': len(seen),
        'collisions': collisions, 'pass': collisions == 0,
        'collision_probability': f'≈ 2⁻¹²⁸ per pasang (birthday bound)',
        'security_level': '128-bit collision resistance'
    })


# ─────────────────────────────────────────────────────────────
#  E2/E3 — WAKTU KOMPUTASI & THROUGHPUT AES-256-GCM
# ─────────────────────────────────────────────────────────────
@app.route('/api/test/performance', methods=['POST'])
def api_performance():
    data = request.json or {}
    repeats = max(10, min(int(data.get('repeats', 50)), 100))
    sizes = [50, 100, 500, 1000, 5000]
    key = generate_key()
    rows = []

    for size in sizes:
        msg = 'P' * size
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
        size_mb = size / (1024 * 1024)
        throughput = size_mb / (enc_mean / 1000) if enc_mean > 0 else 9999

        rows.append({
            'size': size, 'size_kb': round(size / 1024, 3),
            'enc_ms': round(enc_mean, 4), 'dec_ms': round(dec_mean, 4),
            'total_ms': round(enc_mean + dec_mean, 4),
            'throughput_mbs': round(throughput, 2),
            'pass_enc': enc_mean < 5.0, 'pass_dec': dec_mean < 5.0,
            'overhead_bytes': 12 + 16
        })

    return jsonify({'results': rows, 'repeats': repeats,
                    'key_size_bits': 256, 'mode': 'GCM-AEAD'})


# ─────────────────────────────────────────────────────────────
#  E5 — THROUGHPUT SHA-3-256 HASHING
# ─────────────────────────────────────────────────────────────
@app.route('/api/test/hash_throughput', methods=['POST'])
def api_hash_throughput():
    data = request.json or {}
    repeats = max(10, min(int(data.get('repeats', 30)), 100))
    sizes_kb = [1, 10, 100, 1024]
    rows = []
    for size_kb in sizes_kb:
        msg = 'H' * (size_kb * 1024)
        times = []
        for _ in range(repeats):
            t0 = time.perf_counter()
            compute_sha3_256(msg)
            times.append(time.perf_counter() - t0)
        mean_s = sum(times) / len(times)
        throughput = (size_kb / 1024) / mean_s if mean_s > 0 else 9999
        rows.append({
            'size_kb': size_kb,
            'time_ms': round(mean_s * 1000, 4),
            'throughput_mbs': round(throughput, 1),
            'pass': throughput > 50
        })
    return jsonify({'results': rows, 'repeats': repeats})


if __name__ == '__main__':
    app.run(debug=True, port=5000)
