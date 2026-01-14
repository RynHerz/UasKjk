import os
import sys

# Hapus database lama
files_to_delete = [
    'database.db',
    'instance/database.db'
]

for file in files_to_delete:
    if os.path.exists(file):
        try:
            os.remove(file)
            print(f"✓ Berhasil hapus: {file}")
        except Exception as e:
            print(f"✗ Gagal hapus {file}: {e}")
    else:
        print(f"⊗ File tidak ditemukan: {file}")

# Hapus folder instance jika ada
if os.path.exists('instance'):
    try:
        import shutil
        shutil.rmtree('instance')
        print("✓ Folder instance berhasil dihapus")
    except Exception as e:
        print(f"✗ Gagal hapus folder instance: {e}")

print("\n" + "="*50)
print("DATABASE LAMA SUDAH DIHAPUS!")
print("Sekarang jalankan: python app.py")
print("="*50)