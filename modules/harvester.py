"""
Telegram TData Harvester & Lightweight Archiver
Scans the system for Telegram Desktop installations (Desktop, Store UWP, Portable, Snap, Flatpak)
and extracts only session-critical authentication files into a lightweight, high-compression ZIP archive.
"""

import os
import sys
import zipfile
import platform
import argparse
from pathlib import Path
from datetime import datetime
from typing import Set, List, Tuple, Optional

if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass


def get_os_info() -> Tuple[str, str]:
    os_name = platform.system()
    os_map = {"Windows": "🪟 Windows", "Linux": "🐧 Linux", "Darwin": "🍎 macOS"}
    return os_name, os_map.get(os_name, f"❓ {os_name}")


def find_tdata_windows() -> Set[Path]:
    user_home = Path.home()
    candidates: Set[Path] = set()

    # 1. Standard AppData locations
    possible_paths = [
        user_home / "AppData" / "Roaming" / "Telegram Desktop" / "tdata",
        user_home / "AppData" / "Local" / "Telegram Desktop" / "tdata",
        user_home / "Downloads" / "Telegram Desktop" / "tdata",
        user_home / "Desktop" / "Telegram Desktop" / "tdata",
    ]
    for p in possible_paths:
        try:
            if p.exists() and p.is_dir():
                candidates.add(p.resolve())
        except Exception:
            pass

    # 2. Portable folders on Desktop & Downloads (e.g. Desktop/Telegram_2/tdata)
    for parent_dir in [user_home / "Desktop", user_home / "Downloads"]:
        if parent_dir.exists() and parent_dir.is_dir():
            try:
                for item in parent_dir.glob("*elegram*"):
                    if item.is_dir():
                        td = item / "tdata"
                        if td.exists() and td.is_dir():
                            candidates.add(td.resolve())
            except Exception:
                pass

    # 3. Microsoft Store UWP
    packages_root = user_home / "AppData" / "Local" / "Packages"
    if packages_root.exists():
        try:
            for folder in packages_root.glob("TelegramMessengerLLP.TelegramDesktop_*"):
                ms_path = folder / "LocalCache" / "Roaming" / "Telegram Desktop UWP" / "tdata"
                if ms_path.exists() and ms_path.is_dir():
                    candidates.add(ms_path.resolve())
        except Exception:
            pass

    # 4. Portable installations on root drives
    import string
    portable_names = ["Telegram", "TelegramDesktop", "Telegram Portable", "Telegram_2"]
    for letter in string.ascii_uppercase:
        drive = Path(f"{letter}:\\")
        try:
            if drive.exists() and drive.is_dir():
                for item in drive.glob("*"):
                    if item.is_dir() and any(pn.lower() in item.name.lower() for pn in portable_names):
                        tdata_p = item / "tdata"
                        if tdata_p.exists() and tdata_p.is_dir():
                            candidates.add(tdata_p.resolve())
        except Exception:
            continue

    return candidates


def find_tdata_linux() -> Set[Path]:
    user_home = Path.home()
    candidates: Set[Path] = set()
    std = user_home / ".local" / "share" / "TelegramDesktop" / "tdata"
    if std.exists() and std.is_dir():
        candidates.add(std.resolve())

    snap = user_home / "snap" / "telegram-desktop" / "current" / ".local" / "share" / "TelegramDesktop" / "tdata"
    if snap.exists() and snap.is_dir():
        candidates.add(snap.resolve())

    flatpak = user_home / ".var" / "app" / "org.telegram.desktop" / "data" / "TelegramDesktop" / "tdata"
    if flatpak.exists() and flatpak.is_dir():
        candidates.add(flatpak.resolve())

    return candidates


def find_tdata_macos() -> Set[Path]:
    user_home = Path.home()
    candidates: Set[Path] = set()
    std = user_home / "Library" / "Application Support" / "Telegram Desktop" / "tdata"
    if std.exists() and std.is_dir():
        candidates.add(std.resolve())
    return candidates


def find_all_tdata() -> List[Path]:
    os_name, _ = get_os_info()
    if os_name == "Windows":
        return sorted(list(find_tdata_windows()))
    elif os_name == "Linux":
        return sorted(list(find_tdata_linux()))
    elif os_name == "Darwin":
        return sorted(list(find_tdata_macos()))
    return []


def is_session_critical(file_path: Path, tdata_root: Path) -> bool:
    name = file_path.name
    rel_parts = file_path.relative_to(tdata_root).parts
    skip_dirs = {"user_data", "dumps", "temp", "emoji", "dictionaries", "webview", "logs"}

    if any(p.lower() in skip_dirs for p in rel_parts):
        return False

    if name.startswith("key_data"):
        return True
    if name.startswith("settings"):
        return True
    if len(rel_parts) >= 2 and len(rel_parts[0]) == 16:
        return True
    if len(name) == 17 and name.endswith("s") and len(name[:-1]) == 16:
        return True

    return False


def harvest_tdata(tdata_path: Path, output_zip: Path) -> bool:
    print(f"📦 Archiving: {tdata_path}")
    output_zip.parent.mkdir(parents=True, exist_ok=True)

    files_to_pack: List[Path] = []
    for item in tdata_path.rglob("*"):
        try:
            if item.is_file() and is_session_critical(item, tdata_path):
                files_to_pack.append(item)
        except (PermissionError, OSError):
            continue

    if not files_to_pack:
        print("⚠️ No session-critical files found!")
        return False

    packed_count = 0
    with zipfile.ZipFile(output_zip, "w", zipfile.ZIP_DEFLATED, compresslevel=9) as zf:
        for f in files_to_pack:
            try:
                arcname = f.relative_to(tdata_path.parent)
                zf.write(f, arcname)
                packed_count += 1
            except (PermissionError, OSError) as e:
                print(f"   ⚠️ File locked (skipped): {f.name} ({e})")

    if packed_count == 0:
        output_zip.unlink(missing_ok=True)
        return False

    size_mb = output_zip.stat().st_size / (1024 * 1024)
    print(f"✅ Successfully archived: {output_zip.name} ({size_mb:.2f} MB)")
    print(f"   Total packed files: {packed_count}")
    return True


def run_harvest(output_dir: str = ".", custom_path: Optional[str] = None) -> List[Path]:
    os_name, os_icon = get_os_info()

    print("=" * 60)
    print(f"Telegram TData Harvester ({os_icon})")
    print("=" * 60)

    tdata_dirs = [Path(custom_path)] if custom_path else find_all_tdata()

    if not tdata_dirs:
        print("❌ No Telegram tdata directories found on this system!")
        return []

    print(f"Discovered tdata locations ({len(tdata_dirs)}):")
    for idx, td in enumerate(tdata_dirs, 1):
        print(f"   {idx}. {td}")

    created_zips: List[Path] = []
    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    for idx, td in enumerate(tdata_dirs, 1):
        out_name = f"TG_Backup_{os_name}_{timestamp}_{idx}.zip" if len(tdata_dirs) > 1 else f"TG_Backup_{os_name}_{timestamp}.zip"
        out_zip = Path(output_dir) / out_name
        if harvest_tdata(td, out_zip):
            created_zips.append(out_zip)

    return created_zips


def main():
    parser = argparse.ArgumentParser(description="Telegram TData Harvester")
    parser.add_argument("--output", "-o", type=str, default=".", help="Directory to save generated ZIP archive")
    parser.add_argument("--path", "-p", type=str, help="Custom tdata directory path (if not detected automatically)")

    args = parser.parse_args()
    zips = run_harvest(output_dir=args.output, custom_path=args.path)
    if not zips:
        sys.exit(1)


if __name__ == "__main__":
    main()
