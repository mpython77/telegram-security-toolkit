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
            raise FileNotFoundError(f"Session file not found: {s_file}")

    out_dir = Path(output_tdata)

    print("=" * 60)
    print("Telegram Session -> Clean TData Converter (Pure-Python Engine)")
    print(f"Input sessions     : {', '.join(s.name for s in sess_list)} ({len(sess_list)})")
    print(f"Output directory   : {out_dir}")
    print("=" * 60)

    print("⏳ Generating tdata structures...")
    asyncio.run(SessionManager.session_to_tdata(sess_list, out_dir, use_opentele=use_opentele))

    print("\n🎉 SUCCESSFULLY COMPLETED!")
    print("Clean, passcode-free tdata directory created at:")
    print(f"👉 {out_dir.resolve()}")
    print("\n💡 Usage instructions:")
    print("Place this tdata folder into any Telegram Desktop (or Portable) directory.")
    print("Telegram will open directly without asking for any passcode or SMS code.")
    return out_dir


def main():
    parser = argparse.ArgumentParser(description="Convert Telethon .session(s) to Telegram Desktop tdata")
    parser.add_argument(
        "--session", "-s", nargs="+", required=True, help="One or more input .session file path(s)"
    )
    parser.add_argument("--output", "-o", required=True, help="Output tdata directory path")
    parser.add_argument("--opentele", action="store_true", help="Use legacy opentele engine instead of native Pure-Python engine")

    args = parser.parse_args()
    try:
        convert_session(args.session, args.output, use_opentele=args.opentele)
    except Exception as e:
        print(f"❌ Error occurred: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
