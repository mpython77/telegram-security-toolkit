"""
Telegram TData Restorer & In-Place Passcode Unlocker
Restores Telegram Desktop backups (.zip, .tar.xz, or tdata folders) to a target directory
or installed Telegram Desktop/UWP/Portable location.
Automatically removes/unlocks local KD2/PBKDF2 passcodes in-place while preserving 100%
of original multi-DC keys ([1, 2, 4, 5]), maps, drafts, stickers, and local cache files!
"""

import os
import sys
import shutil
import struct
import zipfile
import tarfile
import lzma
import tempfile
import argparse
from pathlib import Path
from datetime import datetime
from typing import Optional, Union, Dict, Any, List

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

from core.tdata_parser import TDataParser
from core.crypto import verify_kd2_candidate
from core.dc_extractor import DCExtractor, MtpSessionInfo
from modules.harvester import find_all_tdata
from modules.cracker import KD2Cracker


def _extract_source_to_temp(source_path: Path, temp_dir: Path) -> Path:
    """
    Safely extracts a .zip / .tar.xz / .tar.gz archive (with Zip-Slip protection)
    or copies a tdata folder into temp_dir, returning the path to the folder containing key_datas.
    """
    if source_path.is_file():
        name_low = source_path.name.lower()
        if name_low.endswith(".zip"):
            TDataParser.safe_extract_zip(source_path, temp_dir)
        elif name_low.endswith((".tar.xz", ".xz", ".tar.gz", ".tgz", ".tar")):
            TDataParser.safe_extract_tar(source_path, temp_dir)
        else:
            raise ValueError(f"Unsupported archive format: {source_path.suffix}")
    elif source_path.is_dir():
        shutil.copytree(source_path, temp_dir / "source_tdata", dirs_exist_ok=True)
    else:
        raise FileNotFoundError(f"Source not found: {source_path}")

    kd_files = sorted(list(temp_dir.rglob("key_datas")))
    if not kd_files:
        raise ValueError(f"'key_datas' file not found in source: {source_path}")
    return kd_files[0].parent


def unlock_and_restore_tdata(
    source: Union[str, Path],
    target_tdata: Union[str, Path],
    passcode: Optional[str] = None,
    local_key_path: Optional[Union[str, Path]] = None,
    auto_crack_pin4: bool = False,
    create_backup: bool = True,
) -> Dict[str, Any]:
    """
    Restores a Telegram backup (.zip, .tar.xz, or tdata folder) into target_tdata.
    If the backup is protected by a local passcode (KD2 Argon2id or PBKDF2):
    - Uses provided passcode, local_key_path, or auto-cracks 4-digit PIN (if auto_crack_pin4=True)
    - Re-wraps the original 256-byte LocalKey under an empty passcode ('') in key_datas
    - Filters out orphaned multi-account .s files that don't match LocalKey
    - Preserves 100% of valid account files (all multi-DC keys [1, 2, 4, 5], maps, configs, inner .s cache)
    """
    source_path = Path(source)
    target_path = Path(target_tdata)
    if not source_path.exists():
        raise FileNotFoundError(f"Source not found: {source_path}")

    print("=" * 65)
    print("🔄 Telegram TData Restorer & In-Place Passcode Unlocker")
    print(f"📂 Source : {source_path}")
    print(f"🎯 Target : {target_path}")
    print("=" * 65)

    temp_root = Path(tempfile.mkdtemp(prefix="tlgr_restore_"))
    try:
        acc_dir = _extract_source_to_temp(source_path, temp_root)
        kd_file = acc_dir / "key_datas"
        kd_raw = kd_file.read_bytes()
        tdf_version = struct.unpack_from("<I", kd_raw, 4)[0]
        kd2_info = TDataParser.parse_kd2(kd_raw)

        # 1. Obtain LocalKey
        local_key: Optional[bytes] = None
        was_locked = True

        if local_key_path and Path(local_key_path).exists():
            local_key = Path(local_key_path).read_bytes()[:256]
            print(f"🔑 LocalKey loaded from file ({len(local_key)} bytes)")
        else:
            # First test if already unlocked (empty passcode '') when passcode not explicitly given
            if passcode is None:
                ok_empty, lk_empty = verify_kd2_candidate(
                    "",
                    kd2_info.salt,
                    kd2_info.key128,
                    kd2_info.ciphertext,
                    time_cost=kd2_info.time_cost,
                    memory_cost=kd2_info.memory_cost,
                    kdf_id=kd2_info.kdf_id,
                )
                if ok_empty and lk_empty is not None:
                    local_key = lk_empty[:256]
                    was_locked = False
                    print("✅ Backup has no local PIN/passcode (unencrypted state).")

            if local_key is None and passcode is not None:
                ok_pwd, lk_pwd = verify_kd2_candidate(
                    passcode,
                    kd2_info.salt,
                    kd2_info.key128,
                    kd2_info.ciphertext,
                    time_cost=kd2_info.time_cost,
                    memory_cost=kd2_info.memory_cost,
                    kdf_id=kd2_info.kdf_id,
                )
                if not ok_pwd or lk_pwd is None:
                    raise ValueError(f"Invalid local passcode: '{passcode}'")
                local_key = lk_pwd[:256]
                print(f"🔓 Local passcode ('{passcode}') verified! LocalKey unlocked.")

            if local_key is None and auto_crack_pin4:
                print("⚡ Backup is passcode-protected! Starting automatic 4-digit PIN brute-force...")
                cracker = KD2Cracker(kd2_info)
                pins = [f"{i:04d}" for i in range(10000)]
                found_pwd, lk_cracked = cracker.crack(pins, save_artifacts=False)
                if found_pwd is not None and lk_cracked is not None:
                    local_key = lk_cracked[:256]
                    passcode = found_pwd
                else:
                    raise ValueError("No matching passcode found in 4-digit PIN range!")

            if local_key is None:
                raise ValueError(
                    "This backup is protected with a local PIN/passcode! "
                    "Please specify --passcode or enable --auto-crack mode."
                )

        # 2. Verify all account session files in acc_dir and map them to account indexes (0..15)
        index_by_folder: Dict[str, int] = TDataParser.get_account_index_map()

        valid_accounts: Dict[str, MtpSessionInfo] = {}
        valid_indexes: List[int] = []
        removed_orphans: List[str] = []

        for item in list(acc_dir.iterdir()):
            if item.is_file() and len(item.name) == 17 and item.name.endswith("s"):
                folder_part = item.name[:-1]
                comp_dir = acc_dir / folder_part
                if not comp_dir.exists():
                    continue
                maps_file = comp_dir / "maps"
                maps_raw = maps_file.read_bytes() if maps_file.exists() else None
                try:
                    s_info = DCExtractor.extract_session_info(item.read_bytes(), local_key, maps_raw=maps_raw)
                    if s_info.dc_keys:
                        valid_accounts[folder_part] = s_info
                        acc_idx = index_by_folder.get(folder_part, len(valid_indexes))
                        if acc_idx not in valid_indexes:
                            valid_indexes.append(acc_idx)
                except Exception:
                    # Orphaned account from an older LocalKey -> remove so it doesn't break restore
                    item.unlink(missing_ok=True)
                    shutil.rmtree(comp_dir, ignore_errors=True)
                    removed_orphans.append(folder_part)

        if not valid_accounts:
            raise ValueError("No valid session matching this LocalKey found in archive!")

        valid_indexes.sort()

        # 3. Rewrite key_datas in-place without passcode (preserving the exact same LocalKey!)
        unlocked_kd_bytes = TDataParser.create_unlocked_key_datas(
            local_key=local_key,
            account_indexes=valid_indexes,
            active_index=valid_indexes[0],
            version=tdf_version,
        )
        kd_file.write_bytes(unlocked_kd_bytes)
        if was_locked:
            print("🛡️  key_datas file rewritten to passcode-free (unlocked) format (all cache and DC keys preserved)!")

        if removed_orphans:
            print(f"🧹 Cleaned up orphaned/mismatched session files: {removed_orphans}")

        # 4. Print restored account details
        print(f"\n📋 Restoring accounts ({len(valid_accounts)}):")
        for folder_part, s_info in valid_accounts.items():
            prof_str = ""
            if s_info.profile:
                p = s_info.profile
                uname = f"@{p.username}" if p.username else "none"
                ph = f"+{p.phone}" if p.phone else "none"
                prof_str = f" | {p.full_name} ({uname}, {ph})"
            print(
                f"   ✅ [{folder_part}] User ID: {s_info.user_id}{prof_str} | "
                f"Main DC: {s_info.main_dc_id} | DCs: {list(s_info.dc_keys.keys())}"
            )
            if s_info.profile and s_info.profile.bio:
                print(f"      📝 Bio: {s_info.profile.bio}")

        # 5. Backup existing target_path if requested
        backup_created: Optional[Path] = None
        if create_backup and target_path.exists() and any(target_path.iterdir()):
            ts = datetime.now().strftime("%Y%m%d_%H%M%S")
            backup_dir = target_path.parent / f"tdata_pre_restore_backup_{ts}"
            shutil.copytree(target_path, backup_dir, dirs_exist_ok=True)
            backup_created = backup_dir
            print(f"\n💾 Backed up existing target tdata to: {backup_dir}")

        # 6. Copy unlocked tdata files to target_path
        target_path.mkdir(parents=True, exist_ok=True)
        copied_files = 0

        # Copy key_datas
        shutil.copy2(kd_file, target_path / "key_datas")
        copied_files += 1

        # Copy valid account folders and .s files
        for folder_part in valid_accounts.keys():
            s_src = acc_dir / f"{folder_part}s"
            d_src = acc_dir / folder_part
            s_dst = target_path / f"{folder_part}s"
            d_dst = target_path / folder_part

            if d_dst.exists():
                shutil.rmtree(d_dst, ignore_errors=True)
            shutil.copytree(d_src, d_dst, dirs_exist_ok=True)
            shutil.copy2(s_src, s_dst)
            copied_files += 1 + sum(1 for f in d_dst.rglob("*") if f.is_file())

        # Copy settings* if present and not passcode-locked
        for item in acc_dir.iterdir():
            if item.is_file() and item.name.startswith("settings"):
                shutil.copy2(item, target_path / item.name)
                copied_files += 1

        print(f"\n🎉 SUCCESSFULLY RESTORED! Total {copied_files} file(s) -> {target_path}")
        print("=" * 65 + "\n")

        return {
            "target_tdata": str(target_path),
            "was_locked": was_locked,
            "passcode_used": passcode,
            "accounts": {
                k: {
                    "user_id": v.user_id,
                    "main_dc_id": v.main_dc_id,
                    "dcs": list(v.dc_keys.keys()),
                    "profile": {
                        "full_name": v.profile.full_name,
                        "username": v.profile.username,
                        "phone": v.profile.phone,
                        "bio": v.profile.bio,
                    } if v.profile else None,
                }
                for k, v in valid_accounts.items()
            },
            "copied_files": copied_files,
            "backup_dir": str(backup_created) if backup_created else None,
        }
    finally:
        shutil.rmtree(temp_root, ignore_errors=True)


def main():
    parser = argparse.ArgumentParser(description="Telegram TData Restorer & In-Place Passcode Unlocker")
    parser.add_argument("--source", "-s", required=True, help="Path to backup ZIP/XZ archive or tdata directory")
    parser.add_argument("--target", "-t", required=False, help="Path to destination tdata directory (searched automatically if omitted)")
    parser.add_argument("--passcode", "-p", type=str, default=None, help="Local PIN/passcode (if known)")
    parser.add_argument("--key", "-k", type=str, default=None, help="Pre-recovered found_local_key.bin file path")
    parser.add_argument("--auto-crack", action="store_true", help="Automatically brute-force 4-digit PIN if backup is passcode-protected")
    parser.add_argument("--no-backup", action="store_true", help="Do not backup existing destination tdata before overwriting")

    args = parser.parse_args()

    target = args.target
    if not target:
        candidates = find_all_tdata()
        if not candidates:
            print("❌ No Telegram Desktop tdata directory found on system! Specify path with --target.")
            sys.exit(1)
        target = str(candidates[0])
        print(f"ℹ️ Automatically selected tdata: {target}")

    try:
        unlock_and_restore_tdata(
            source=args.source,
            target_tdata=target,
            passcode=args.passcode,
            local_key_path=args.key,
            auto_crack_pin4=args.auto_crack,
            create_backup=not args.no_backup,
        )
    except Exception as e:
        print(f"❌ Error occurred: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
