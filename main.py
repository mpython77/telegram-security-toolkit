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
from modules.harvester import main as run_harvester_cli, run_harvest, find_all_tdata
from modules.cracker import main as run_cracker_cli, KD2Cracker
from modules.session_extractor import main as run_extractor_cli, extract_session_from_backup
from modules.session_to_tdata import main as run_converter_cli, convert_session
from modules.session_checker import main as run_checker_cli, check_session_cli
from modules.restorer import main as run_restorer_cli, unlock_and_restore_tdata


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

HELP_TEXT = """
Telegram Desktop Security, Forensics & Recovery Toolkit - CLI Yordam

Foydalanish:
  python main.py                         Interaktiv menyuni ishga tushirish
  python main.py --harvest [opsiyalar]   TData qidirish va ixcham ZIP arxiv yaratish
  python main.py --crack   [opsiyalar]   KD2 / PBKDF2 parolni multi-core sindirish
  python main.py --extract [opsiyalar]   Arxiv/tdata dan Telethon .session ajratish
  python main.py --convert [opsiyalar]   .session faylini parolsiz toza tdata qilish
  python main.py --check   [opsiyalar]   .session faolligini va profilni tekshirish
  python main.py --restore [opsiyalar]   Arxiv/tdata ni parolini yechib Telegram'ga tiklash
  python main.py --patch                 Python 3.13/3.14+ va Telegram v7.x+ OpenTele patchi
  python main.py --test                  Barcha avtomatlashtirilgan testlarni bajarish
"""


def interactive_menu():
    while True:
        print(BANNER)
        print("  [1] 📦 Telegram TData Harvester (Keraksiz keshni tashlab, ixcham ZIP yaratish)")
        print("  [2] 🔓 KD2 Passcode Cracker (Argon2id + AES-IGE PIN kodni multi-core sindirish)")
        print("  [3] 🔑 Session Extractor (Arxivdan toza Telethon .session ajratib olish)")
        print("  [4] 🚀 Session -> TData Converter (.session faylini parolsiz tdata ga aylantirish)")
        print("  [5] 🔍 Session Health Checker (Sessiya holati, profil va qurilmalarni tekshirish)")
        print("  [6] 🔄 TData Restorer & Passcode Unlocker (Arxivni parolsiz holatda to'liq tiklash)")
        print("  [7] 🩹 Python 3.13/3.14+ & Telegram v7.x+ OpenTele Patchini o'rnatish")
        print("  [0] ❌ Chiqish")
        print("=" * 70)

        try:
            choice = input("Tanlovingizni kiriting [0-7]: ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\nDastur yakunlandi. Xayr!")
            break

        if choice == "0":
            print("\nDastur yakunlandi. Xayr!")
            break

        try:
            if choice == "1":
                print("\n--- 1. TData Harvester ---")
                out_dir = input("ZIP saqlanadigan papka [standart: joriy papka]: ").strip().strip('"') or "."
                custom_p = input("Maxsus tdata yo'li (avtomatik qidirish uchun bo'sh qoldiring): ").strip().strip('"') or None
                run_harvest(output_dir=out_dir, custom_path=custom_p)

            elif choice == "2":
                print("\n--- 2. KD2 Passcode Cracker ---")
                src = input("ZIP arxiv yoki tdata papkasi yo'lini kiriting: ").strip().strip('"')
                if not src:
                    print("❌ Manba kiritilmadi!")
                    continue
                mode = input(
                    "Rejimni tanlang (1: 4-xonali PIN [0000-9999], 2: 6-xonali PIN [000000-999999], "
                    "3: Maxsus oraliq, 4: Wordlist) [1]: "
                ).strip()

                candidates = []
                if mode == "2":
                    candidates = [f"{i:06d}" for i in range(1000000)]
                elif mode == "3":
                    start_n = int(input("Boshlanish soni (masalan: 1000): ").strip())
                    end_n = int(input("Tugash soni (masalan: 2000): ").strip())
                    width = max(4, len(str(end_n)))
                    candidates = [f"{i:0{width}d}" for i in range(start_n, end_n + 1)]
                elif mode == "4":
                    w_path = input("Wordlist .txt fayl yo'li: ").strip().strip('"')
                    candidates = Path(w_path).read_text(encoding="utf-8", errors="ignore").splitlines()
                else:
                    candidates = [f"{i:04d}" for i in range(10000)]

                cracker = KD2Cracker.from_source(src)
                cracker.crack(candidates)

            elif choice == "3":
                print("\n--- 3. Session Extractor ---")
                src = input("ZIP arxiv yoki tdata papkasi yo'li: ").strip().strip('"')
                pwd = input("Lokal PIN/Parol (agar parolsiz bo'lsa, bo'sh qoldiring): ").strip()
                key_f = input("Yoki found_local_key.bin fayl yo'li (bo'sh qoldirish mumkin): ").strip().strip('"')
                dc = input("Maqsadli DC ID [standart: avtomatik MainDC]: ").strip()
                dc_id = int(dc) if dc else None
                out_sess = input("Chiqish .session fayli nomi [avtomatik nomlash uchun bo'sh qoldiring]: ").strip().strip('"')

                extract_session_from_backup(
                    source=src,
                    passcode=pwd if pwd else None,
                    local_key_path=key_f if key_f else None,
                    target_dc=dc_id,
                    output_session_path=out_sess if out_sess else None,
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
                print("\n--- 6. TData Restorer & In-Place Passcode Unlocker ---")
                src = input("ZIP/XZ arxiv yoki tdata papkasi yo'li: ").strip().strip('"')
                tgt = input("Tiklanadigan tdata yo'li (tizimdan avtomatik topish uchun bo'sh qoldiring): ").strip().strip('"')
                if not tgt:
                    cands = find_all_tdata()
                    if not cands:
                        print("❌ Tizimda tdata topilmadi! Yo'lni qo'lda kiriting.")
                        continue
                    for idx, c_path in enumerate(cands, 1):
                        print(f"   {idx}. {c_path}")
                    sel = input(f"Tanlang [1-{len(cands)}, standart=1]: ").strip() or "1"
                    tgt = str(cands[int(sel) - 1])
                pwd = input("Lokal PIN/Parol (avtomatik topish yoki parolsiz bo'lsa bo'sh qoldiring): ").strip()
                auto_c = input("Agar parol bo'lsa, 4-xonali PIN-kodni avtomatik ochsinmi? (y/n) [y]: ").strip().lower()
                unlock_and_restore_tdata(
                    source=src,
                    target_tdata=tgt,
                    passcode=pwd if pwd else None,
                    auto_crack_pin4=(auto_c != "n"),
                )

            elif choice == "7":
                print("\n--- 7. OpenTele Patch ---")
                apply_patch()

            else:
                print("⚠️ Noto'g'ri tanlov! Qaytadan urinib ko'ring.")

        except Exception as e:
            print(f"\n❌ Xatolik yuz berdi: {e}")

        try:
            input("\nDavom etish uchun [Enter] tugmasini bosing...")
        except (EOFError, KeyboardInterrupt):
            break


if __name__ == "__main__":
    if len(sys.argv) > 1:
        subcmd = sys.argv[1].lower()
        if subcmd in ["-h", "--help", "help"]:
            print(BANNER)
            print(HELP_TEXT)
        elif subcmd == "--harvest":
            sys.argv.pop(1)
            run_harvester_cli()
        elif subcmd in ["--crack", "-c"]:
            sys.argv.pop(1)
            run_cracker_cli()
        elif subcmd in ["--extract", "-e"]:
            sys.argv.pop(1)
            run_extractor_cli()
        elif subcmd == "--convert":
            sys.argv.pop(1)
            run_converter_cli()
        elif subcmd == "--check":
            sys.argv.pop(1)
            run_checker_cli()
        elif subcmd in ["--restore", "-r", "--unlock"]:
            sys.argv.pop(1)
            run_restorer_cli()
        elif subcmd == "--patch":
            apply_patch()
        elif subcmd == "--test":
            from tests.run_all_tests import run_suite
            sys.exit(0 if run_suite() else 1)
        else:
            print(f"⚠️ Noma'lum buyruq: {subcmd}")
            print(HELP_TEXT)
            sys.exit(1)
    else:
        interactive_menu()
