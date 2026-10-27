"""
Telegram Security & Forensics Toolkit
Main Orchestrator & CLI Interface
"""

import os
import sys
from pathlib import Path

if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

CURRENT_DIR = Path(__file__).resolve().parent
if str(CURRENT_DIR) not in sys.path:
    sys.path.insert(0, str(CURRENT_DIR))

from patches.patch_opentele import apply_patch
from modules.harvester import main as run_harvester
from modules.cracker import main as run_cracker, KD2Cracker
from modules.session_extractor import main as run_extractor, extract_session_from_backup
from modules.session_to_tdata import main as run_converter, convert_session
from modules.session_checker import main as run_checker, check_session_cli


BANNER = r"""
======================================================================
  _____ _     ____ ____    _____            _ _    _ _   
 |_   _| |   / ___|  _ \  |_   _|__   ___  | | | _(_) |_ 
   | | | |  | |  _| |_) |   | |/ _ \ / _ \ | | |/ / | __|
   | | | |__| |_| |  _ <    | | (_) | (_) || |   <| | |_ 
   |_| |_____\____|_| \_\   |_|\___/ \___/ |_|_|\_\_|\__|
   Telegram Desktop Security, Forensics & Recovery Toolkit
======================================================================
"""


def interactive_menu():
    while True:
        print(BANNER)
        print("  [1] 📦 Telegram TData Harvester (Keraksiz keshni tashlab, ixcham ZIP yaratish)")
        print("  [2] 🔓 KD2 Passcode Cracker (Argon2id + AES-IGE PIN kodni multi-core sindirish)")
        print("  [3] 🔑 Session Extractor (Arxivdan toza Telethon .session ajratib olish)")
        print("  [4] 🚀 Session -> TData Converter (.session faylini parolsiz tdata ga aylantirish)")
        print("  [5] 🔍 Session Health Checker (Sessiya holati, profil va qurilmalarni tekshirish)")
        print("  [6] 🩹 Python 3.13 / 3.14 OpenTele Patchini tekshirish va o'rnatish")
        print("  [0] ❌ Chiqish")
        print("=" * 70)

        choice = input("Tanlovingizni kiriting [0-6]: ").strip()

        if choice == "0":
            print("\nDastur yakunlandi. Xayr!")
            break

        elif choice == "1":
            print("\n--- 1. TData Harvester ---")
            run_harvester()

        elif choice == "2":
            print("\n--- 2. KD2 Passcode Cracker ---")
            src = input("ZIP arxiv yoki tdata papkasi yo'lini kiriting: ").strip().strip('"')
            if not src:
                print("❌ Manba kiritilmadi!")
                continue
            mode = input("Rejimni tanlang (1: 4-xonali PIN [0000-9999], 2: Maxsus oraliq, 3: Wordlist) [1]: ").strip()
            
            candidates = []
            if mode == "2":
                start_n = int(input("Boshlanish soni (masalan: 1000): ").strip())
                end_n = int(input("Tugash soni (masalan: 2000): ").strip())
                candidates = [f"{i:04d}" for i in range(start_n, end_n + 1)]
            elif mode == "3":
                w_path = input("Wordlist .txt fayl yo'li: ").strip().strip('"')
                candidates = Path(w_path).read_text(encoding="utf-8", errors="ignore").splitlines()
            else:
                candidates = [f"{i:04d}" for i in range(10000)]

            cracker = KD2Cracker.from_source(src)
            cracker.crack(candidates)

        elif choice == "3":
            print("\n--- 3. Session Extractor ---")
            src = input("ZIP arxiv yoki tdata papkasi yo'li: ").strip().strip('"')
            pwd = input("Lokal PIN/Parol (agar bo'lsa): ").strip()
            key_f = input("Yoki found_local_key.bin fayl yo'li (bo'sh qoldirish mumkin): ").strip().strip('"')
            dc = input("Maqsadli DC ID [standart: 2]: ").strip()
            dc_id = int(dc) if dc else 2
            out_sess = input("Chiqish .session fayli nomi [standart: telegram_recovered.session]: ").strip()
            if not out_sess:
                out_sess = "telegram_recovered.session"

            extract_session_from_backup(
                source=src,
                passcode=pwd if pwd else None,
                local_key_path=key_f if key_f else None,
                target_dc=dc_id,
                output_session_path=out_sess,
            )

        elif choice == "4":
            print("\n--- 4. Session -> Toza TData Converter ---")
            sess = input("Kirish .session fayli yo'li: ").strip().strip('"')
            out_td = input("Chiqish tdata papkasi yo'li: ").strip().strip('"')
            convert_session(sess, out_td)

        elif choice == "5":
            print("\n--- 5. Session Health Checker ---")
            sess = input("Tekshiriladigan .session fayli yo'li: ").strip().strip('"')
            check_session_cli(sess)

        elif choice == "6":
            print("\n--- 6. OpenTele Patch ---")
            apply_patch()

        else:
            print("⚠️ Noto'g'ri tanlov! Qaytadan urinib ko'ring.")

        input("\nDavom etish uchun [Enter] tugmasini bosing...")


if __name__ == "__main__":
    if len(sys.argv) > 1:
        # If CLI flags were passed, let modules handle their arguments
        subcmd = sys.argv[1].lower()
        if subcmd in ["--harvest", "-h"]:
            sys.argv.pop(1)
            run_harvester()
        elif subcmd in ["--crack", "-c"]:
            sys.argv.pop(1)
            run_cracker()
        elif subcmd in ["--extract", "-e"]:
            sys.argv.pop(1)
            run_extractor()
        elif subcmd in ["--convert"]:
            sys.argv.pop(1)
            run_converter()
        elif subcmd in ["--check"]:
            sys.argv.pop(1)
            run_checker()
        elif subcmd in ["--patch"]:
            apply_patch()
        else:
            interactive_menu()
    else:
        interactive_menu()
