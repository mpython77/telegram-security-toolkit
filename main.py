"""
Telegram Security & Forensics Toolkit
Main Orchestrator & CLI Interface
"""

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
from modules.forensic_analyzer import main as run_analyzer_cli, analyze_source


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
Telegram Desktop Security, Forensics & Recovery Toolkit - CLI Help

Usage:
  python main.py                         Launch interactive menu
  python main.py --harvest [options]     Find TData installations and create compact ZIP
  python main.py --crack   [options]     Multi-core KD2 / PBKDF2 passcode cracker
  python main.py --extract [options]     Extract Telethon .session from backup/tdata
  python main.py --convert [options]     Convert .session file(s) to clean, unencrypted tdata
  python main.py --check   [options]     Verify session connectivity and account details
  python main.py --restore [options]     Restore and unlock passcode in-place to target tdata
  python main.py --analyze [options]     100% offline forensic audit and JSON report
  python main.py --patch                 Install Python 3.13/3.14+ & Telegram v7.x+ OpenTele patch
  python main.py --test                  Run the full automated test suite
"""


def interactive_menu():
    while True:
        print(BANNER)
        print("  [1] 📦 Telegram TData Harvester (Skip media cache, create lightweight ZIP)")
        print("  [2] 🔓 KD2 Passcode Cracker (Argon2id + AES-IGE multi-core brute-force)")
        print("  [3] 🔑 Session Extractor (Extract clean Telethon .session from backup)")
        print("  [4] 🚀 Session -> TData Converter (Convert .session file(s) to clean tdata)")
        print("  [5] 🔍 Session Health Checker (Verify session status, profile, and devices)")
        print("  [6] 🔄 TData Restorer & Passcode Unlocker (Restore archive with passcode removed)")
        print("  [7] 🔬 Offline Forensic Analyzer (100% offline audit & JSON export)")
        print("  [8] 🩹 Apply Python 3.13/3.14+ & Telegram v7.x+ OpenTele Patch")
        print("  [0] ❌ Exit")
        print("=" * 70)

        try:
            choice = input("Enter your choice [0-8]: ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\nExiting. Goodbye!")
            break

        if choice == "0":
            print("\nExiting. Goodbye!")
            break

        try:
            if choice == "1":
                print("\n--- 1. TData Harvester ---")
                out_dir = input("Output directory for ZIP archive [default: current dir]: ").strip().strip('"') or "."
                custom_p = input("Custom tdata path (leave empty for auto-discovery): ").strip().strip('"') or None
                run_harvest(output_dir=out_dir, custom_path=custom_p)

            elif choice == "2":
                print("\n--- 2. KD2 Passcode Cracker ---")
                src = input("Enter path to ZIP/XZ archive or tdata directory: ").strip().strip('"')
                if not src:
                    print("❌ No source path provided!")
                    continue
                mode = input(
                    "Select mode (1: 4-digit PIN [0000-9999], 2: 6-digit PIN [000000-999999], "
                    "3: Custom range, 4: Wordlist) [1]: "
                ).strip()

                candidates = []
                if mode == "2":
                    candidates = [f"{i:06d}" for i in range(1000000)]
                elif mode == "3":
                    start_n = int(input("Start number (e.g. 1000): ").strip())
                    end_n = int(input("End number (e.g. 2000): ").strip())
                    width = max(4, len(str(end_n)))
                    candidates = [f"{i:0{width}d}" for i in range(start_n, end_n + 1)]
                elif mode == "4":
                    w_path = input("Wordlist .txt file path: ").strip().strip('"')
                    candidates = Path(w_path).read_text(encoding="utf-8", errors="ignore").splitlines()
                else:
                    candidates = [f"{i:04d}" for i in range(10000)]

                cracker = KD2Cracker.from_source(src)
                cracker.crack(candidates)

            elif choice == "3":
                print("\n--- 3. Session Extractor ---")
                src = input("Path to ZIP/XZ archive or tdata directory: ").strip().strip('"')
                pwd = input("Local PIN/passcode (leave empty if unencrypted): ").strip()
                key_f = input("Or path to found_local_key.bin (optional): ").strip().strip('"')
                dc = input("Target DC ID [default: automatic MainDC]: ").strip()
                dc_id = int(dc) if dc else None
                out_sess = input("Output .session file path [leave empty for auto-naming]: ").strip().strip('"')

                extract_session_from_backup(
                    source=src,
                    passcode=pwd if pwd else None,
                    local_key_path=key_f if key_f else None,
                    target_dc=dc_id,
                    output_session_path=out_sess if out_sess else None,
                )

            elif choice == "4":
                print("\n--- 4. Session -> Clean TData Converter ---")
                sess = input("Input .session file path(s) (space-separated for multi-account): ").strip().strip('"')
                sess_paths = [p.strip().strip('"') for p in sess.split() if p.strip()]
                out_td = input("Output tdata directory path: ").strip().strip('"')
                convert_session(sess_paths, out_td)

            elif choice == "5":
                print("\n--- 5. Session Health Checker ---")
                sess = input("Path to .session file to verify: ").strip().strip('"')
                check_session_cli(sess)

            elif choice == "6":
                print("\n--- 6. TData Restorer & In-Place Passcode Unlocker ---")
                src = input("Path to ZIP/XZ archive or tdata directory: ").strip().strip('"')
                tgt = input("Target tdata destination path (leave empty for auto-detection): ").strip().strip('"')
                if not tgt:
                    cands = find_all_tdata()
                    if not cands:
                        print("❌ No Telegram Desktop tdata found on this system! Please enter path manually.")
                        continue
                    for idx, c_path in enumerate(cands, 1):
                        print(f"   {idx}. {c_path}")
                    sel = input(f"Select [1-{len(cands)}, default=1]: ").strip() or "1"
                    tgt = str(cands[int(sel) - 1])
                pwd = input("Local PIN/passcode (leave empty for auto-crack or if unencrypted): ").strip()
                auto_c = input("If locked, automatically crack 4-digit PIN? (y/n) [y]: ").strip().lower()
                unlock_and_restore_tdata(
                    source=src,
                    target_tdata=tgt,
                    passcode=pwd if pwd else None,
                    auto_crack_pin4=(auto_c != "n"),
                )

            elif choice == "7":
                print("\n--- 7. Offline Forensic Analyzer ---")
                src = input("Path to ZIP/XZ archive, tdata directory, or .session file: ").strip().strip('"')
                pwd = input("Local PIN/passcode (if known, or leave empty): ").strip()
                json_out = input("JSON report export path (optional, e.g. audit.json): ").strip().strip('"')
                analyze_source(
                    source=src,
                    passcode=pwd if pwd else None,
                    output_json=json_out if json_out else None,
                )

            elif choice == "8":
                print("\n--- 8. OpenTele Patch ---")
                apply_patch()

            else:
                print("⚠️ Invalid selection! Please try again.")

        except Exception as e:
            print(f"\n❌ An error occurred: {e}")

        try:
            input("\nPress [Enter] to continue...")
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
        elif subcmd in ["--analyze", "-a", "--audit"]:
            sys.argv.pop(1)
            run_analyzer_cli()
        elif subcmd == "--patch":
            apply_patch()
        elif subcmd == "--test":
            from tests.run_all_tests import run_suite
            sys.exit(0 if run_suite() else 1)
        else:
            print(f"⚠️ Unknown command: {subcmd}")
            print(HELP_TEXT)
            sys.exit(1)
    else:
        interactive_menu()
