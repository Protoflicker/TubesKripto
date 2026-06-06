"""
api/index.py — Entry point untuk Vercel Serverless Function (runtime @vercel/python).

Vercel mendeteksi objek WSGI bernama `app` di file ini dan menjalankannya. Kita cukup
mengimpor instance Flask dari app.py di root proyek. Seluruh route, template, dan static
files tetap berada di app.py / templates/ / static/ — file ini hanya jembatan.
"""
import os
import sys

# Pastikan root proyek ada di sys.path agar `import app` berhasil saat dibundel Vercel.
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from app import app  # noqa: E402  (objek WSGI yang dijalankan Vercel)

# Alias yang juga dikenali oleh sebagian runtime.
application = app
