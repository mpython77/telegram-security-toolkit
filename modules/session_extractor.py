"""
Telegram Session Extractor
Extracts MTProto AuthKeys, User ID, and Main DC ID from decrypted tdata
and exports them as Telethon SQLite .session files.
"""

import sys
import argparse
from pathlib import Path
from typing import Optional, Union, Dict

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
) -> Path:
    source_path = Path(source)
    if not source_path.exists():
        raise FileNotFoundError(f"Manba topilmadi: {source_path}")

    # 1. Parse KD2/PBKDF2 and session files
    if source_path.is_file() and source_path.suffix.lower() == ".zip":
        kd2_info, session_files = TDataParser.load_from_zip(source_path)
    elif source_path.is_dir():
        kd2_info, session_files = TDataParser.load_from_dir(source_path)
    else:
        raise ValueError("Manba ZIP fayl yoki tdata papkasi bo'lishi kerak")

    if not session_files:
        raise ValueError("Arxiv/papkada sessiya fayli (*s) topilmadi!")

    # 2. Obtain master LocalKey
    local_key: Optional[bytes] = None
    if local_key_path and Path(local_key_path).exists():
        local_key = Path(local_key_path).read_bytes()[:256]
        print(f"🔑 LocalKey fayldan yuklandi: {len(local_key)} bayt")
    else:
        cand_pwd = passcode if passcode is not None else ""
        if passcode is not None:
            print(f"🔍 Parol tekshirilmoqda: '{passcode}'...")
        else:
            print("🔍 Lokal parolsiz (bo'sh parol '') holati tekshirilmoqda...")

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
                raise ValueError("Akkauntda lokal parol o'rnatilgan! Iltimos, --passcode yoki --key parametrini kiriting.")
            raise ValueError(f"Noto'g'ri passcode: '{passcode}'")

        local_key = cand_key[:256]
        print(f"✅ Kalit ochildi! LocalKey shifrdan yechildi ({len(local_key)} bayt)")

    # 2.5 Inspect accounts metadata from key_datas
    try:
        import zipfile

        kd_raw = None
        if source_path.is_file() and source_path.suffix.lower() == ".zip":
            with zipfile.ZipFile(source_path, "r") as zf:
                kd_entry = [n for n in zf.namelist() if n.endswith("key_datas")]
                if kd_entry:
                    kd_raw = zf.read(kd_entry[0])
        elif source_path.is_dir():
            kd_f = source_path / "key_datas"
            if kd_f.exists():
                kd_raw = kd_f.read_bytes()
            else:
                nested = list(source_path.rglob("key_datas"))
                if nested:
                    kd_raw = nested[0].read_bytes()

        if kd_raw:
            acc_meta = TDataParser.parse_accounts_metadata(kd_raw, local_key)
            if acc_meta:
                print(f"📋 Telegram konfiguratsiyasi: {acc_meta['count']} ta akkaunt (Faol profil indeksi: {acc_meta['active_index']})")
    except Exception:
        pass

    # 3. Decrypt and scan all session files for active DC keys
    print(f"📦 Arxivdagi sessiya fayllari tahlil qilinmoqda ({len(session_files)} ta)...")
    valid_sessions: Dict[str, MtpSessionInfo] = {}

    for s_name, s_raw in session_files.items():
        try:
            s_info = DCExtractor.extract_session_info(s_raw, local_key)
            if s_info.dc_keys:
                valid_sessions[s_name] = s_info
        except Exception:
            continue

    if not valid_sessions:
        raise ValueError(
            "Sessiya fayllari ichidan birorta ham faol MTProto AuthKey topilmadi! "
            "Parol noto'g'ri bo'lishi yoki sessiya tozalangan bo'lishi mumkin."
        )

    print(f"✅ Faol avtorizatsiyaga ega akkauntlar soni: {len(valid_sessions)} ta")
    for s_name, s_info in valid_sessions.items():
        print(
            f"   👉 Akkaunt: {Path(s_name).name} | User ID: {s_info.user_id} | "
            f"Main DC: {s_info.main_dc_id} | DC kalitlari: {list(s_info.dc_keys.keys())}"
        )

    # Pick the target account (first active one by default)
    chosen_s_name = list(valid_sessions.keys())[0]
    chosen_info = valid_sessions[chosen_s_name]
    all_dc_keys = chosen_info.dc_keys

    # Determine target DC: prefer explicit target_dc if valid, else chosen_info.main_dc_id
    dc_to_use = target_dc if target_dc is not None else chosen_info.main_dc_id
    if dc_to_use not in all_dc_keys:
        fallback_dc = chosen_info.main_dc_id if chosen_info.main_dc_id in all_dc_keys else list(all_dc_keys.keys())[0]
        print(f"⚠️ So'ralgan DC {dc_to_use} topilmadi, asosiy DC {fallback_dc} tanlandi.")
        dc_to_use = fallback_dc

    auth_key = all_dc_keys[dc_to_use]
    print(f"\nTanlangan akkaunt: {Path(chosen_s_name).name} (User ID: {chosen_info.user_id}, DC: {dc_to_use})")

    # 4. Create Telethon SQLite .session (with User ID stored in entities id=0)
    if not output_session_path:
        output_session_path = Path.cwd() / f"account_{chosen_info.user_id}_dc{dc_to_use}.session"
    else:
        output_session_path = Path(output_session_path)

    sess_file = SessionManager.create_telethon_session(
        auth_key=auth_key,
        dc_id=dc_to_use,
        output_path=output_session_path,
        user_id=chosen_info.user_id,
    )
    print("🎉 Telethon sessiyasi muvaffaqiyatli yaratildi:")
    print(f"👉 {sess_file.resolve()}\n")
    return sess_file


def main():
    parser = argparse.ArgumentParser(description="Telegram Session Extractor")
    parser.add_argument("--source", "-s", required=True, help="Telegram backup ZIP fayli yoki tdata papkasi")
    parser.add_argument("--passcode", "-p", type=str, default=None, help="Lokal PIN/Parol (agar parolsiz bo'lsa, kiritish shart emas)")
    parser.add_argument("--key", "-k", type=str, default=None, help="Oldindan topilgan found_local_key.bin fayli")
    parser.add_argument("--dc", type=int, default=None, help="Maqsadli Data Center ID (standart: avtomatik MainDC)")
    parser.add_argument("--output", "-o", type=str, default=None, help="Chiqish .session fayli yo'li")

    args = parser.parse_args()

    try:
        extract_session_from_backup(
            source=args.source,
            passcode=args.passcode,
            local_key_path=args.key,
            target_dc=args.dc,
            output_session_path=args.output,
        )
    except Exception as e:
        print(f"❌ Xatolik yuz berdi: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
