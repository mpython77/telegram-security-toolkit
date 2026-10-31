"""
Telegram Session Extractor
Extracts MTProto AuthKeys, User ID, and Main DC ID from decrypted tdata backups
(.zip, .tar.xz, .tar.gz, or tdata folders) and exports them as Telethon SQLite .session files.
Supports both single-account and multi-account (--all / --account-index) extraction.
"""

import sys
import argparse
from pathlib import Path
from typing import Optional, Union, Dict, List

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
from core.session_manager import SessionManager


def extract_session_from_backup(
    source: Union[str, Path],
    passcode: Optional[str] = None,
    local_key_path: Optional[Union[str, Path]] = None,
    target_dc: Optional[int] = None,
    output_session_path: Optional[Union[str, Path]] = None,
    account_index: Optional[int] = None,
    extract_all: bool = False,
) -> Union[Path, List[Path]]:
    source_path = Path(source)
    if not source_path.exists():
        raise FileNotFoundError(f"Source not found: {source_path}")

    # 1. Parse KD2/PBKDF2, session files, and maps from any supported archive or directory
    bundle = TDataParser.load_full_source(source_path)
    kd2_info = bundle.kd2_info
    session_files = bundle.session_files
    maps_files = bundle.maps_files

    if not session_files:
        raise ValueError("No session files (*s) found in archive/directory!")

    # 2. Obtain master LocalKey
    local_key: Optional[bytes] = None
    if local_key_path and Path(local_key_path).exists():
        local_key = Path(local_key_path).read_bytes()[:256]
        print(f"🔑 LocalKey loaded from file: {len(local_key)} bytes")
    else:
        cand_pwd = passcode if passcode is not None else ""
        if passcode is not None:
            print(f"🔍 Testing passcode: '{passcode}'...")
        else:
            print("🔍 Checking empty passcode (passcode-free account)...")

        ok, cand_key = verify_kd2_candidate(
            cand_pwd,
            kd2_info.salt,
            kd2_info.key128,
            kd2_info.ciphertext,
            time_cost=kd2_info.time_cost,
            memory_cost=kd2_info.memory_cost,
            kdf_id=kd2_info.kdf_id,
        )
        if not ok or cand_key is None:
            if passcode is None:
                raise ValueError("Account is protected by a local passcode! Please provide --passcode or --key.")
            raise ValueError(f"Invalid passcode: '{passcode}'")

        local_key = cand_key[:256]
        print(f"✅ Key unlocked! LocalKey decrypted successfully ({len(local_key)} bytes)")

    # 2.5 Inspect accounts metadata from key_datas
    if bundle.kd_raw:
        acc_meta = TDataParser.parse_accounts_metadata(bundle.kd_raw, local_key)
        if acc_meta:
            print(
                f"📋 Telegram configuration: {acc_meta['count']} account(s) "
                f"(Active profile index: {acc_meta['active_index']})"
            )

    # 3. Decrypt and scan all session files for active DC keys and offline profile
    print(f"📦 Analyzing session files in backup ({len(session_files)})...")
    valid_sessions: Dict[str, MtpSessionInfo] = {}

    for s_name, s_raw in session_files.items():
        try:
            folder_part = Path(s_name).name[:-1]
            maps_raw = maps_files.get(folder_part)
            s_info = DCExtractor.extract_session_info(s_raw, local_key, maps_raw=maps_raw)
            if s_info.dc_keys:
                valid_sessions[s_name] = s_info
        except Exception:
            continue

    if not valid_sessions:
        raise ValueError(
            "No active MTProto AuthKey found in session files! "
            "Passcode may be incorrect or session data was purged."
        )

    # Prioritize authenticated sessions (user_id > 0) over unauthenticated login-screen sessions (user_id == 0)
    auth_sessions = {k: v for k, v in valid_sessions.items() if v.user_id > 0}
    if auth_sessions:
        valid_sessions = auth_sessions
    else:
        print("⚠️ WARNING: This tdata is not logged in yet (Login screen, User ID = 0)!")

    print(f"✅ Active authorized accounts found: {len(valid_sessions)}")
    session_items = list(valid_sessions.items())
    for idx, (s_name, s_info) in enumerate(session_items):
        prof_str = ""
        if s_info.profile:
            p = s_info.profile
            uname = f"@{p.username}" if p.username else "none"
            ph = f"+{p.phone}" if p.phone else "none"
            prof_str = f" | Name: {p.full_name} ({uname}, {ph})"
        print(
            f"   👉 [{idx}] Account: {Path(s_name).name} | User ID: {s_info.user_id}{prof_str} | "
            f"Main DC: {s_info.main_dc_id} | DC Keys: {list(s_info.dc_keys.keys())}"
        )
        if s_info.profile and s_info.profile.bio:
            print(f"      📝 Bio: {s_info.profile.bio}")

    def _export_single(s_name: str, s_info: MtpSessionInfo, out_path_opt: Optional[Path]) -> Path:
        all_dc_keys = s_info.dc_keys
        dc_to_use = target_dc if target_dc is not None else s_info.main_dc_id
        if dc_to_use not in all_dc_keys:
            fallback_dc = s_info.main_dc_id if s_info.main_dc_id in all_dc_keys else list(all_dc_keys.keys())[0]
            print(f"⚠️ Requested DC {dc_to_use} not found, defaulted to main DC {fallback_dc}.")
            dc_to_use = fallback_dc

        auth_key = all_dc_keys[dc_to_use]
        print(f"\nSelected account: {Path(s_name).name} (User ID: {s_info.user_id}, DC: {dc_to_use})")

        if not out_path_opt:
            out_path_opt = Path.cwd() / f"account_{s_info.user_id}_dc{dc_to_use}.session"

        sess_file = SessionManager.create_telethon_session(
            auth_key=auth_key,
            dc_id=dc_to_use,
            output_path=out_path_opt,
            user_id=s_info.user_id,
            all_dc_keys=all_dc_keys,
            profile=s_info.profile,
        )
        print("🎉 Telethon session created successfully:")
        print(f"👉 {sess_file.resolve()}\n")
        return sess_file

    if extract_all:
        exported: List[Path] = []
        base_dir = Path(output_session_path) if output_session_path else Path.cwd()
        if base_dir.suffix == ".session":
            base_dir = base_dir.parent
        base_dir.mkdir(parents=True, exist_ok=True)
        for s_name, s_info in session_items:
            dc_id_eff = target_dc if (target_dc and target_dc in s_info.dc_keys) else s_info.main_dc_id
            out_f = base_dir / f"account_{s_info.user_id}_dc{dc_id_eff}.session"
            exported.append(_export_single(s_name, s_info, out_f))
        return exported

    sel_idx = account_index if account_index is not None else 0
    if sel_idx < 0 or sel_idx >= len(session_items):
        raise ValueError(f"Invalid account index: {sel_idx} (available: 0..{len(session_items) - 1})")

    chosen_s_name, chosen_info = session_items[sel_idx]
    out_p = Path(output_session_path) if output_session_path else None
    return _export_single(chosen_s_name, chosen_info, out_p)


def main():
    parser = argparse.ArgumentParser(description="Telegram Session Extractor")
    parser.add_argument("--source", "-s", required=True, help="Telegram backup (.zip/.tar.xz) or tdata directory")
    parser.add_argument("--passcode", "-p", type=str, default=None, help="Local PIN/Passcode (not required if passcode-free)")
    parser.add_argument("--key", "-k", type=str, default=None, help="Path to pre-recovered found_local_key.bin file")
    parser.add_argument("--dc", type=int, default=None, help="Target Data Center ID (default: automatic Main DC)")
    parser.add_argument("--account-index", "-i", type=int, default=None, help="Account index to extract (default: 0)")
    parser.add_argument("--all", action="store_true", help="Export all active accounts into separate .session files")
    parser.add_argument("--output", "-o", type=str, default=None, help="Output .session file or directory path")

    args = parser.parse_args()

    try:
        extract_session_from_backup(
            source=args.source,
            passcode=args.passcode,
            local_key_path=args.key,
            target_dc=args.dc,
            output_session_path=args.output,
            account_index=args.account_index,
            extract_all=args.all,
        )
    except Exception as e:
        print(f"❌ Error occurred: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
