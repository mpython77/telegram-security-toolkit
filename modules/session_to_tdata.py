"""
Session to TData Converter
Converts a Telethon SQLite .session file into clean, unencrypted Telegram Desktop tdata.
"""

import sys
import asyncio
import argparse
from pathlib import Path

if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

CURRENT_DIR = Path(__file__).resolve().parent
PARENT_DIR = CURRENT_DIR.parent
if str(PARENT_DIR) not in sys.path:
    sys.path.insert(0, str(PARENT_DIR))

# Ensure opentele patch is active for Python 3.13+
from patches.patch_opentele import apply_patch
from core.session_manager import SessionManager


def convert_session(session_path: str, output_tdata: str):
    sess_file = Path(session_path)
    if not sess_file.exists():
        raise FileNotFoundError(f"Sessiya fayli topilmadi: {sess_file}")

    out_dir = Path(output_tdata)

    print("=" * 60)
    print("Telegram Session -> Toza TData Konverter")
    print(f"Kirish sessiyasi : {sess_file.name}")
    print(f"Chiqish papkasi  : {out_dir}")
    print("=" * 60)

    # Ensure OpenTele patch is applied
    apply_patch()

    print("⏳ Telegram serveriga ulanmoqda va tdata generatsiya qilinmoqda...")
    asyncio.run(SessionManager.session_to_tdata(sess_file, out_dir))

    print("\n🎉 MUVAFFAQIYATLI YAKUNLANDI!")
    print(f"Toza, parolsiz tdata quyidagi manzilga saqlandi:")
    print(f"👉 {out_dir.resolve()}")
    print("\n💡 Ko'rsatma:")
    print("Ushbu tdata papkasini istalgan Telegram Desktop (yoki Portable) papkasiga joylashtiring.")
    print("Telegram ochilganda hech qanday parol yoki SMS so'ramasdan to'g'ridan-to'g'ri ishga tushadi.")


def main():
    parser = argparse.ArgumentParser(description="Convert Telethon .session to Telegram Desktop tdata")
    parser.add_argument("--session", "-s", required=True, help="Kirish .session fayli yo'li")
    parser.add_argument("--output", "-o", required=True, help="Chiqish tdata papkasi yo'li")

    args = parser.parse_args()
    try:
        convert_session(args.session, args.output)
    except Exception as e:
        print(f"❌ Xatolik yuz berdi: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
