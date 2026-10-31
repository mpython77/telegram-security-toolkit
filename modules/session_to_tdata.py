"""
Session to TData Converter
Converts one or multiple Telethon SQLite .session files into clean, unencrypted
Telegram Desktop tdata using a 100% Pure-Python native serializer (zero PyQt5/opentele requirement).
"""

import sys
import asyncio
import argparse
from pathlib import Path
from typing import Union, Sequence

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

from core.session_manager import SessionManager


def convert_session(
    session_path: Union[str, Path, Sequence[Union[str, Path]]],
    output_tdata: Union[str, Path],
    use_opentele: bool = False,
) -> Path:
    if isinstance(session_path, (str, Path)):
        sess_list = [Path(session_path)]
    else:
        sess_list = [Path(p) for p in session_path]

    for s_file in sess_list:
        if not s_file.exists():
            raise FileNotFoundError(f"Sessiya fayli topilmadi: {s_file}")

    out_dir = Path(output_tdata)

    print("=" * 60)
    print("Telegram Session -> Toza TData Konverter (Pure-Python Engine)")
    print(f"Kirish sessiyalari : {', '.join(s.name for s in sess_list)} ({len(sess_list)} ta)")
    print(f"Chiqish papkasi    : {out_dir}")
    print("=" * 60)

    print("⏳ TData strukturalari generatsiya qilinmoqda...")
    asyncio.run(SessionManager.session_to_tdata(sess_list, out_dir, use_opentele=use_opentele))

    print("\n🎉 MUVAFFAQIYATLI YAKUNLANDI!")
    print("Toza, parolsiz tdata quyidagi manzilga saqlandi:")
    print(f"👉 {out_dir.resolve()}")
    print("\n💡 Ko'rsatma:")
    print("Ushbu tdata papkasini istalgan Telegram Desktop (yoki Portable) papkasiga joylashtiring.")
    print("Telegram ochilganda hech qanday parol yoki SMS so'ramasdan to'g'ridan-to'g'ri ishga tushadi.")
    return out_dir


def main():
    parser = argparse.ArgumentParser(description="Convert Telethon .session(s) to Telegram Desktop tdata")
    parser.add_argument(
        "--session", "-s", nargs="+", required=True, help="Bitta yoki bir nechta kirish .session fayli yo'li"
    )
    parser.add_argument("--output", "-o", required=True, help="Chiqish tdata papkasi yo'li")
    parser.add_argument("--opentele", action="store_true", help="Pure-Python o'rniga eski opentele dvigatelini ishlatish")

    args = parser.parse_args()
    try:
        convert_session(args.session, args.output, use_opentele=args.opentele)
    except Exception as e:
        print(f"❌ Xatolik yuz berdi: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
