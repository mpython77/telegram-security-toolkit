"""
Offline Digital Forensics & Integrity Analyzer for Telegram Desktop Backups
Performs 100% offline, zero-network forensic inspection of .zip, .tar.xz, tdata folders,
and Telethon .session files:
- Chain-of-custody SHA-256 file hashes & TDF$ MD5 checksum verification
- KDF parameter auditing (KD2 Argon2id vs PBKDF2-HMAC-SHA512)
- Multi-account & orphaned session detection
- MTProto 64-bit auth_key_id & SHA-256 key fingerprinting across all DCs
- Full TLV inspection of <account>/maps (lskType inventory, local drafts, offline profile)
- Structured JSON forensic report export
"""

import sys
import json
import hashlib
import argparse
from pathlib import Path
from datetime import datetime, timezone
from typing import Dict, Any, Optional, Union

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
from core.dc_extractor import DCExtractor
from core.session_manager import SessionManager


def _compute_file_sha256(file_path: Path) -> str:
    h = hashlib.sha256()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.digest().hex()


def analyze_source(
    source: Union[str, Path],
    passcode: Optional[str] = None,
    local_key_path: Optional[Union[str, Path]] = None,
    output_json: Optional[Union[str, Path]] = None,
    quiet: bool = False,
) -> Dict[str, Any]:
    """
    Runs a 100% offline forensic audit on a Telegram backup archive, tdata directory, or .session file.
    Returns a structured forensic report dictionary.
    """
    source_path = Path(source)
    if not source_path.exists():
        raise FileNotFoundError(f"Source not found: {source_path}")

    report: Dict[str, Any] = {
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "source_path": str(source_path.resolve()),
        "source_name": source_path.name,
        "source_type": None,
        "container_sha256": _compute_file_sha256(source_path) if source_path.is_file() else None,
        "container_size_bytes": source_path.stat().st_size if source_path.is_file() else None,
    }

    # Case 1: Telethon SQLite .session file
    if source_path.is_file() and source_path.suffix.lower() == ".session":
        report["source_type"] = "telethon_session"
        meta = SessionManager.read_offline_session_meta(source_path)
        dc_keys = meta.get("dc_keys") or {}
        dc_fingerprints = {
            int(dc): DCExtractor.compute_auth_key_fingerprint(k_bytes)
            for dc, k_bytes in sorted(dc_keys.items())
        }
        report["session_info"] = {
            "dc_id": meta.get("dc_id"),
            "server": meta.get("server"),
            "user_id": meta.get("user_id"),
            "username": meta.get("username"),
            "phone": meta.get("phone"),
            "first_name": meta.get("first_name"),
            "auth_key_id": meta.get("auth_key_id"),
            "auth_key_id_hex": meta.get("auth_key_id_hex"),
            "auth_key_sha256": meta.get("auth_key_sha256"),
            "dc_list": meta.get("dc_list", []),
            "dc_fingerprints": dc_fingerprints,
        }
        if not quiet:
            _print_report(report)
        if output_json:
            Path(output_json).write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
        return report

    # Case 2: Telegram Desktop tdata archive (.zip, .tar.xz, .tar.gz) or directory
    report["source_type"] = "tdata_archive" if source_path.is_file() else "tdata_directory"
    bundle = TDataParser.load_full_source(source_path)
    kd2 = bundle.kd2_info

    total_tdf = len(bundle.all_tdf_status)
    valid_tdf = sum(1 for v in bundle.all_tdf_status.values() if v.get("md5_valid"))
    corrupted_tdf = [k for k, v in bundle.all_tdf_status.items() if not v.get("md5_valid")]

    report["tdf_integrity"] = {
        "total_tdf_files": total_tdf,
        "valid_md5_count": valid_tdf,
        "corrupted_files": corrupted_tdf,
        "files": bundle.all_tdf_status,
    }

    kdf_name = "KD2 Argon2id" if kd2.kdf_id != 0 else "PBKDF2-HMAC-SHA512"
    report["encryption"] = {
        "tdf_version": bundle.tdf_version,
        "tdf_version_str": TDataParser.format_tdf_version(bundle.tdf_version),
        "kdf_id": kd2.kdf_id,
        "kdf_name": kdf_name,
        "memory_cost_kb": kd2.memory_cost,
        "time_cost": kd2.time_cost,
        "threads": kd2.threads,
        "salt_hex": kd2.salt.hex(),
        "key128_hex": kd2.key128.hex(),
        "has_passcode": None,
        "unlocked": False,
        "local_key_sha256": None,
    }

    # Attempt to unlock LocalKey (via local_key_path, empty passcode, or provided passcode)
    local_key: Optional[bytes] = None
    if local_key_path and Path(local_key_path).exists():
        local_key = Path(local_key_path).read_bytes()[:256]
        report["encryption"]["unlocked"] = True
    else:
        ok_empty, lk_empty = verify_kd2_candidate(
            "",
            kd2.salt,
            kd2.key128,
            kd2.ciphertext,
            time_cost=kd2.time_cost,
            memory_cost=kd2.memory_cost,
            kdf_id=kd2.kdf_id,
        )
        if ok_empty and lk_empty is not None:
            local_key = lk_empty[:256]
            report["encryption"]["has_passcode"] = False
            report["encryption"]["unlocked"] = True
        else:
            report["encryption"]["has_passcode"] = True
            if passcode is not None:
                ok_pwd, lk_pwd = verify_kd2_candidate(
                    passcode,
                    kd2.salt,
                    kd2.key128,
                    kd2.ciphertext,
                    time_cost=kd2.time_cost,
                    memory_cost=kd2.memory_cost,
                    kdf_id=kd2.kdf_id,
                )
                if ok_pwd and lk_pwd is not None:
                    local_key = lk_pwd[:256]
                    report["encryption"]["unlocked"] = True

    report["accounts_metadata"] = None
    report["accounts"] = []
    report["orphaned_sessions"] = []

    if local_key is not None:
        report["encryption"]["local_key_sha256"] = hashlib.sha256(local_key[:256]).hexdigest()
        report["accounts_metadata"] = TDataParser.parse_accounts_metadata(bundle.kd_raw, local_key)

        idx_map = TDataParser.get_account_index_map()
        for s_name, s_raw in bundle.session_files.items():
            folder_part = Path(s_name).name[:-1]
            acc_idx = idx_map.get(folder_part)
            maps_raw = bundle.maps_files.get(folder_part)

            try:
                s_info = DCExtractor.extract_session_info(s_raw, local_key, maps_raw=maps_raw)
                maps_audit = DCExtractor.inspect_maps_blocks(maps_raw, local_key) if maps_raw else None
                dc_fingerprints = {
                    int(dc): DCExtractor.compute_auth_key_fingerprint(k_bytes)
                    for dc, k_bytes in sorted(s_info.dc_keys.items())
                }
                report["accounts"].append({
                    "folder_hash": folder_part,
                    "session_file": Path(s_name).name,
                    "account_index": acc_idx,
                    "user_id": s_info.user_id,
                    "main_dc_id": s_info.main_dc_id,
                    "dcs": sorted(list(s_info.dc_keys.keys())),
                    "dc_fingerprints": dc_fingerprints,
                    "profile": {
                        "first_name": s_info.profile.first_name,
                        "last_name": s_info.profile.last_name,
                        "full_name": s_info.profile.full_name,
                        "username": s_info.profile.username,
                        "phone": s_info.profile.phone,
                        "bio": s_info.profile.bio,
                    } if s_info.profile else None,
                    "maps_summary": {
                        "decrypted": maps_audit["decrypted"] if maps_audit else False,
                        "block_count": len(maps_audit["blocks"]) if maps_audit else 0,
                        "block_types": [b["name"] for b in maps_audit["blocks"]] if maps_audit else [],
                        "draft_count": maps_audit["draft_count"] if maps_audit else 0,
                        "draft_peer_ids": maps_audit["draft_peer_ids"] if maps_audit else [],
                    } if maps_audit else None,
                })
            except Exception as e:
                report["orphaned_sessions"].append({
                    "folder_hash": folder_part,
                    "session_file": Path(s_name).name,
                    "account_index": acc_idx,
                    "reason": str(e),
                })

    if not quiet:
        _print_report(report)

    if output_json:
        out_p = Path(output_json)
        out_p.parent.mkdir(parents=True, exist_ok=True)
        out_p.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
        if not quiet:
            print(f"📄 Forensic JSON report saved to: {out_p.resolve()}")

    return report


def _print_report(report: Dict[str, Any]) -> None:
    print("=" * 70)
    print("🔬 TELEGRAM DESKTOP OFFLINE DIGITAL FORENSIC REPORT")
    print("=" * 70)
    print(f"📂 Source          : {report['source_path']}")
    print(f"🏷️  Source Type     : {report['source_type']}")
    if report.get("container_sha256"):
        print(f"🛡️  SHA-256 (File)  : {report['container_sha256']}")

    if report["source_type"] == "telethon_session":
        si = report["session_info"]
        print("-" * 70)
        print(f"🆔 User ID         : {si.get('user_id') or 'Unknown'}")
        print(f"👤 Name / Username : {si.get('first_name') or '-'} (@{si.get('username') or 'none'})")
        print(f"📞 Phone           : +{si.get('phone') or 'none'}")
        print(f"🌐 Main DC         : DC {si.get('dc_id')} ({si.get('server')})")
        print(f"🔑 AuthKey ID      : {si.get('auth_key_id_hex')} ({si.get('auth_key_id')})")
        print(f"🔑 Available DCs   : {si.get('dc_list')}")
        print("=" * 70)
        return

    tdf = report["tdf_integrity"]
    enc = report["encryption"]
    print("-" * 70)
    print(f"📦 TDF$ Integrity  : {tdf['valid_md5_count']}/{tdf['total_tdf_files']} files passed MD5 verification")
    if tdf["corrupted_files"]:
        print(f"⚠️  Corrupted       : {tdf['corrupted_files']}")
    print(f"🔖 TDF$ Version    : {enc['tdf_version_str']}")
    print(f"🔐 KDF Algorithm   : {enc['kdf_name']} (kdf_id={enc['kdf_id']})")
    if enc["kdf_id"] != 0:
        print(f"⚙️  Argon2id        : {enc['memory_cost_kb'] // 1024} MB RAM, {enc['time_cost']} iterations, {enc['threads']} threads")
    print(f"🧂 Salt (32 bytes) : {enc['salt_hex'][:32]}...")
    print(f"🔒 Local Passcode  : {'YES (Protected)' if enc['has_passcode'] else 'NO (Unencrypted)'}")
    print(f"🔓 Key Status      : {'UNLOCKED (LocalKey ready)' if enc['unlocked'] else 'LOCKED (specify --passcode)'}")

    if enc["unlocked"]:
        print(f"🧬 LocalKey SHA256 : {enc['local_key_sha256'][:32]}...")
        meta = report.get("accounts_metadata")
        if meta:
            print(f"📋 Configuration   : {meta['count']} account(s), indexes={meta['indexes']}, active={meta['active_index']}")

        print("-" * 70)
        print(f"✅ Active Accounts ({len(report['accounts'])}):")
        for acc in report["accounts"]:
            prof = acc.get("profile") or {}
            p_str = f"{prof.get('full_name', '')} (@{prof.get('username') or 'none'}, +{prof.get('phone') or 'none'})"
            print(f"   • [{acc['folder_hash']}] (Index: {acc['account_index']}) | User ID: {acc['user_id']} | {p_str}")
            print(f"     🌐 Main DC: {acc['main_dc_id']} | All DCs: {acc['dcs']}")
            for dc_id, fp in acc["dc_fingerprints"].items():
                print(f"        - DC {dc_id}: key_id={fp['auth_key_id_hex']} | sha256={fp['sha256'][:16]}...")
            ms = acc.get("maps_summary")
            if ms and ms.get("decrypted"):
                print(f"     🗺️  maps blocks ({ms['block_count']}): {', '.join(ms['block_types'])}")
                print(f"     📝 Saved drafts (lskDraft): {ms['draft_count']}")

        if report["orphaned_sessions"]:
            print(f"\n🧹 Orphaned sessions belonging to previous/different LocalKeys ({len(report['orphaned_sessions'])}):")
            for orph in report["orphaned_sessions"]:
                print(f"   • [{orph['folder_hash']}] (Index: {orph['account_index']}) -> {orph['reason']}")

    print("=" * 70 + "\n")


def main():
    parser = argparse.ArgumentParser(description="Telegram Offline Forensic Analyzer")
    parser.add_argument("--source", "-s", required=True, help="Backup (.zip/.tar.xz), tdata folder, or .session file")
    parser.add_argument("--passcode", "-p", type=str, default=None, help="Local PIN/passcode (if present)")
    parser.add_argument("--key", "-k", type=str, default=None, help="Pre-recovered found_local_key.bin file path")
    parser.add_argument("--json", "-j", type=str, default=None, help="Path to export JSON forensic report (e.g. audit.json)")

    args = parser.parse_args()
    try:
        analyze_source(
            source=args.source,
            passcode=args.passcode,
            local_key_path=args.key,
            output_json=args.json,
        )
    except Exception as e:
        print(f"❌ Error occurred: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
