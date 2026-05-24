import time
import os
from flask import Flask, request, jsonify, render_template
from crypto.sha3_utils import compute_sha3_256, verify_sha3_256
from crypto.aes_gcm_utils import generate_key, encrypt_aes_gcm, decrypt_aes_gcm, build_packet, parse_packet

app = Flask(__name__)

# Menggunakan kunci di memori untuk simulasi session / server memory
SERVER_KEY = generate_key()

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/process', methods=['POST'])
def process():
    data = request.json
    message = data.get('message', '')
    mitm_enabled = data.get('mitm_enabled', False)
    mitm_byte_pos = int(data.get('mitm_byte_pos', 30))
    tamper_hash_triggered = data.get('tamper_hash', False)

    steps = []
    result = {
        "is_valid": False,
        "message": None,
        "error": None,
        "plaintext_length": 0,
        "packet_size": 0,
        "processing_time_ms": 0,
        "digest": None,
        "iv": None,
        "auth_tag": None,
        "mitm_triggered": mitm_enabled,
        "tamper_hash_triggered": tamper_hash_triggered
    }

    start_time = time.perf_counter()

    # Step 1: Menghitung SHA-3
    msg_bytes = message.encode('utf-8')
    N_msg = len(msg_bytes)
    
    steps.append({
        "type": "SHA3", 
        "title": "Menghitung SHA-3-256 dari plaintext...", 
        "detail": {
            "Input": f'"{message}" ({N_msg} byte)'
        }, 
        "delay_ms": 300
    })

    digest = compute_sha3_256(message)
    steps.append({
        "type": "SHA3",
        "title": "SHA-3-256 digest berhasil dihitung",
        "detail": {
            "Digest": digest,
            "Bit": "256",
            "Byte": "32",
            "Deterministik": "Ya"
        },
        "delay_ms": 300
    })

    # Step 3: Payload
    payload = message + "||HASH||" + digest
    payload_bytes = payload.encode('utf-8')
    N_payload = len(payload_bytes)
    steps.append({
        "type": "PACKET",
        "title": "Menyusun payload...",
        "detail": {
            "Format": "plaintext + ||HASH|| + digest",
            "Panjang total": f"{N_payload} byte"
        },
        "delay_ms": 300
    })

    # Step 4: AES-ENC IV
    iv, ciphertext, auth_tag = encrypt_aes_gcm(SERVER_KEY, payload)
    
    steps.append({
        "type": "AES-ENC",
        "title": "Membangkitkan IV 96-bit secara acak (CSPRNG)...",
        "detail": {
            "IV": iv.hex()
        },
        "delay_ms": 300
    })

    steps.append({
        "type": "AES-ENC",
        "title": "Menjalankan AES-256-GCM encrypt_and_digest()...",
        "detail": {
            "Key": f"{SERVER_KEY.hex()[:16]}... (32 byte / 256 bit)",
            "Mode": "GCM (Counter + GHASH)"
        },
        "delay_ms": 400
    })

    N_ct = len(ciphertext)
    steps.append({
        "type": "AES-ENC",
        "title": "Enkripsi selesai",
        "detail": {
            "Ciphertext": f"{ciphertext.hex()[:32]}... ({N_ct} byte)" if N_ct > 16 else f"{ciphertext.hex()} ({N_ct} byte)",
            "Auth Tag": f"{auth_tag.hex()} (16 byte / 128 bit)"
        },
        "delay_ms": 300
    })

    packet = build_packet(iv, auth_tag, ciphertext)
    packet_size = len(packet)
    steps.append({
        "type": "PACKET",
        "title": "Menyusun paket transmisi...",
        "detail": {
            "Format": f"IV[12] + AuthTag[16] + CT[{N_ct}] = {packet_size} byte"
        },
        "delay_ms": 300
    })

    # Simulasi MITM
    ciphertext_mut = bytearray(ciphertext)
    if mitm_enabled:
        pos = min(mitm_byte_pos, max(0, N_ct - 1))
        before = ciphertext_mut[pos]
        ciphertext_mut[pos] ^= 0xFF
        after = ciphertext_mut[pos]
        steps.append({
            "type": "ATTACK",
            "title": f"⚠️ MITM: Memodifikasi byte ke-[{pos}] ciphertext (XOR 0xFF)",
            "detail": {
                "Sebelum": f"0x{before:02x}",
                "Sesudah": f"0x{after:02x}"
            },
            "delay_ms": 500
        })

    # Step 9: AES-DEC Parse
    parsed_iv, parsed_tag, parsed_ct = parse_packet(build_packet(iv, auth_tag, bytes(ciphertext_mut)))
    steps.append({
        "type": "AES-DEC",
        "title": "Menerima paket, memisahkan IV / Auth Tag / Ciphertext...",
        "detail": {
            "IV": parsed_iv.hex(),
            "Tag": parsed_tag.hex(),
            "CT": f"[{len(parsed_ct)} byte]"
        },
        "delay_ms": 300
    })

    steps.append({
        "type": "AES-DEC",
        "title": "Menjalankan decrypt_and_verify()...",
        "detail": {
            "Verifikasi": "GHASH Auth Tag..."
        },
        "delay_ms": 400
    })

    try:
        decrypted_payload = decrypt_aes_gcm(SERVER_KEY, parsed_iv, parsed_ct, parsed_tag)
        steps.append({
            "type": "AES-DEC",
            "title": "✓ Auth Tag valid — integritas jaringan terjamin",
            "detail": {
                "Payload ter-dekripsi": f"{len(decrypted_payload.encode('utf-8'))} byte"
            },
            "delay_ms": 300
        })

        parts = decrypted_payload.split('||HASH||')
        if len(parts) == 2:
            dec_message, received_hash = parts
            
            steps.append({
                "type": "VERIFY",
                "title": "Memisahkan plaintext dan hash dari payload...",
                "detail": {
                    "Plaintext": f'"{dec_message}"',
                    "Hash diterima": received_hash
                },
                "delay_ms": 300
            })

            # Simulasi Tamper Hash
            if tamper_hash_triggered:
                # Mengubah karakter terakhir dari hash
                tampered_hash = received_hash[:-1] + ('0' if received_hash[-1] != '0' else '1')
                steps.append({
                    "type": "ATTACK",
                    "title": "⚠️ TAMPER: Mengubah hash setelah dekripsi (simulasi serangan storage)",
                    "detail": {
                        "Hash asli": received_hash,
                        "Hash diubah": tampered_hash
                    },
                    "delay_ms": 400
                })
                received_hash = tampered_hash

            computed_hash = compute_sha3_256(dec_message)
            steps.append({
                "type": "VERIFY",
                "title": "Menghitung ulang SHA-3-256 dari plaintext yang didekripsi...",
                "detail": {
                    "Hash computed": computed_hash
                },
                "delay_ms": 300
            })

            if computed_hash == received_hash:
                steps.append({
                    "type": "OK",
                    "title": "✅ Hash COCOK — Integritas konten terjamin",
                    "detail": {
                        "Status": "Pesan VALID dan diteruskan ke pasien"
                    },
                    "delay_ms": 300
                })
                result["is_valid"] = True
                result["message"] = dec_message
            else:
                steps.append({
                    "type": "ERROR",
                    "title": "❌ Hash TIDAK COCOK — Integritas konten gagal",
                    "detail": {
                        "Penyebab": "Digest SHA-3 tidak sesuai dengan data"
                    },
                    "delay_ms": 300
                })
                result["error"] = "Hash tidak cocok"

    except ValueError as e:
        steps.append({
            "type": "ERROR",
            "title": "❌ MAC check FAILED — Auth Tag tidak cocok!",
            "detail": {
                "Penyebab": f"byte ciphertext telah dimodifikasi",
                "Status": "Pesan DITOLAK. Kemungkinan serangan MITM."
            },
            "delay_ms": 300
        })
        result["error"] = "MAC check failed"

    end_time = time.perf_counter()
    
    result["plaintext_length"] = N_msg
    result["packet_size"] = packet_size
    result["processing_time_ms"] = round((end_time - start_time) * 1000, 2)
    result["digest"] = digest
    result["iv"] = iv.hex()
    result["auth_tag"] = auth_tag.hex()

    return jsonify({"steps": steps, "result": result})

if __name__ == '__main__':
    app.run(debug=True, port=5000)
