"""
Telegram Session Extractor
Extracts MTProto AuthKeys from decrypted tdata and exports them as Telethon SQLite .session files.
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
from core.dc_extractor import DCExtractor
from core.session_manager import SessionManager


def extract_session_from_backup(
    source: Union[str, Path],
    passcode: Optional[str] = None,
    local_key_path: Optional[Union[str, Path]] = None,
    target_dc: int = 2,
    output_session_path: Optional[Union[str, Path]] = None,
) -> Path:
    source_path = Path(source)
    if not source_path.exists():
        raise FileNotFoundError(f"Manba topilmadi: {source_path}")

    # 1. Parse KD2 and session files
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
    elif passcode is not None:
        print(f"🔍 Parol tekshirilmoqda: '{passcode}'...")
        ok, cand_key = verify_kd2_candidate(
            passcode,
            kd2_info.salt,
            kd2_info.key128,
            kd2_info.ciphertext,
            time_cost=kd2_info.time_cost,
            memory_cost=kd2_info.memory_cost,
        )
        if not ok or cand_key is None:
            raise ValueError(f"Noto'g'ri passcode: '{passcode}'")
        local_key = cand_key[:256]
        print(f"✅ Parol to'g'ri! LocalKey shifrdan yechildi ({len(local_key)} bayt)")
    else:
        raise ValueError("Yo --passcode yoki --key parametri ko'rsatilishi shart!")

    # 3. Decrypt primary session file
    first_s_name = list(session_files.keys())[0]
    session_s_raw = session_files[first_s_name]
    print(f"📦 Sessiya fayli shifrdan yechilmoqda: {first_s_name}...")

    all_dc_keys = DCExtractor.extract_all_dc_keys(session_s_raw, local_key)
    print(f"🌐 Topilgan DC kalitlari soni: {len(all_dc_keys)} ta")
    for dc_id, k_data in all_dc_keys.items():
        print(f"   - DC {dc_id}: {k_data[:16].hex()}... ({len(k_data)} bayt)")

    if target_dc not in all_dc_keys:
        fallback_dc = list(all_dc_keys.keys())[0]
        print(f"⚠️ DC {target_dc} topilmadi, DC {fallback_dc} tanlanmoqda.")
        target_dc = fallback_dc

    auth_key = all_dc_keys[target_dc]

    # 4. Create Telethon SQLite .session
    if not output_session_path:
        output_session_path = Path.cwd() / f"telegram_dc{target_dc}.session"
    else:
        output_session_path = Path(output_session_path)

    sess_file = SessionManager.create_telethon_session(auth_key, target_dc, output_session_path)
    print(f"🎉 Telethon sessiyasi muvaffaqiyatli yaratildi:")
    print(f"👉 {sess_file.resolve()}\n")
    return sess_file


def main():
    parser = argparse.ArgumentParser(description="Telegram Session Extractor")
    parser.add_argument("--source", "-s", required=True, help="Telegram backup ZIP fayli yoki tdata papkasi")
    parser.add_argument("--passcode", "-p", type=str, help="Lokal PIN/Parol (masalan: 9562)")
    parser.add_argument("--key", "-k", type=str, help="Oldindan topilgan found_local_key.bin fayli")
    parser.add_argument("--dc", type=int, default=2, help="Maqsadli Data Center ID (standart: 2)")
    parser.add_argument("--output", "-o", type=str, help="Chiqish .session fayli yo'li")

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
