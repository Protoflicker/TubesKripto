"""
crypto/replay_guard.py
Replay Attack Resistance — IV/Nonce tracking sederhana di sisi server.

Mekanisme: simpan IV yang pernah digunakan dalam in-memory dict beserta
timestamp-nya. IV yang dipakai ulang dalam window TTL akan ditolak.

Thread-safe via threading.Lock. Tidak butuh database eksternal.
"""
import time
from threading import Lock


DEFAULT_TTL_SECONDS = 600   # 10 menit window


class ReplayGuard:
    """In-memory replay protection berbasis IV cache dengan TTL.

    Contoh pemakaian:
        guard = ReplayGuard(ttl_seconds=600)
        if guard.is_replay(iv_bytes):
            raise ValueError('Replay attack detected')
        # ... lanjutkan dekripsi
    """

    def __init__(self, ttl_seconds: int = DEFAULT_TTL_SECONDS):
        if ttl_seconds <= 0:
            raise ValueError('ttl_seconds harus > 0')
        self._seen = {}                # iv_hex -> first_seen_timestamp
        self._lock = Lock()
        self._ttl = ttl_seconds

    def is_replay(self, iv: bytes) -> bool:
        """True jika IV sudah pernah dipakai dalam window TTL.
        Side-effect: kalau IV baru, otomatis tercatat."""
        if not isinstance(iv, (bytes, bytearray)):
            raise TypeError('iv harus bytes')
        iv_hex = bytes(iv).hex()
        now = time.time()
        with self._lock:
            self._purge_expired(now)
            if iv_hex in self._seen:
                return True
            self._seen[iv_hex] = now
            return False

    def _purge_expired(self, now: float):
        """Hapus entri yang sudah melewati TTL. Caller harus pegang lock."""
        cutoff = now - self._ttl
        expired = [k for k, ts in self._seen.items() if ts < cutoff]
        for k in expired:
            del self._seen[k]

    def reset(self):
        """Kosongkan cache (untuk testing)."""
        with self._lock:
            self._seen.clear()

    def size(self) -> int:
        with self._lock:
            return len(self._seen)
