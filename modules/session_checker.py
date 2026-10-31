"""
Telegram Session Health & Verification Tool
Checks authorization status, retrieves profile details, and lists active login sessions.
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

from core.session_manager import SessionManager


def check_session_cli(session_path: str):
    sess_file = Path(session_path)
    if not sess_file.exists():
        raise FileNotFoundError(f"Sessiya fayli topilmadi: {sess_file}")

    print("=" * 60)
    print("Telegram Sessiya Holatini Tekshirish")
    print(f"Fayl: {sess_file.name}")
    print("=" * 60)

    res = asyncio.run(SessionManager.verify_session(sess_file))

    if not res.get("authorized"):
        print("\n❌ SEANSI FAOL EMAS (O'chgan yoki bekor qilingan):")
        if res.get("error"):
            print(f"   ⚠️ Sabab: {res['error']}")
        else:
            print("   ℹ️ Ushbu sessiya Telegram serverida faol emas yoki avtorizatsiyadan chiqarilgan.")
        print("=" * 60 + "\n")
        return False

    print("\n✅ SEANSI TO'LIQ FAOL VA TIRIK!")
    print(f"   👤 Ism-familiya : {res.get('first_name')} {res.get('last_name')}")
    print(f"   🏷️ Username      : @{res.get('username') or 'yo\'q'}")
    print(f"   🆔 Telegram ID   : {res.get('user_id')}")
    print(f"   📞 Telefon       : +{res.get('phone')}")

    devices = res.get("devices", [])
    if devices:
        print(f"\n📱 Faol qurilmalar va sessiyalar soni: {len(devices)} ta")
        for idx, dev in enumerate(devices, 1):
            print(f"   {idx}. {dev}")

    dialogs = res.get("recent_dialogs", [])
    if dialogs:
        print(f"\n💬 Oxirgi chatlar:")
        for idx, d_name in enumerate(dialogs, 1):
            print(f"   {idx}. {d_name}")
    print("=" * 60 + "\n")


def main():
    parser = argparse.ArgumentParser(description="Check Telegram .session status and health")
    parser.add_argument("--session", "-s", required=True, help="Tekshiriladigan .session fayli yo'li")

    args = parser.parse_args()
    try:
        check_session_cli(args.session)
    except Exception as e:
        print(f"❌ Xatolik yuz berdi: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
