"""
Synthetic Test Fixtures for Telegram Security Toolkit.
Generates 100% synthetic, realistic Telegram Desktop tdata directories,
ZIP backups, and Telethon .session files with ZERO external dependencies
and ZERO real personal information.
"""

import os
import struct
import zipfile
import sqlite3
import tempfile
import shutil
from pathlib import Path
from typing import Optional, Dict, Tuple, Sequence

from core.tdata_parser import TDataParser
from core.crypto import (
    derive_kd2_wrap_key,
    derive_pbkdf2_wrap_key,
    encrypt_local_block,
)
from core.dc_extractor import DCExtractor


def create_synthetic_session(
    session_path: Path,
    user_id: int = 100000001,
    dc_id: int = 2,
    auth_key: Optional[bytes] = None,
    dc_keys: Optional[Dict[int, bytes]] = None,
) -> Path:
    """
    Creates a valid Telethon SQLite .session file with synthetic keys.
    """
    session_path = Path(session_path)
    session_path.parent.mkdir(parents=True, exist_ok=True)
    if session_path.exists():
        session_path.unlink()

    if auth_key is None:
        auth_key = os.urandom(256)
    if dc_keys is None:
        dc_keys = {1: os.urandom(256), 2: auth_key, 4: os.urandom(256), 5: os.urandom(256)}
    if dc_id not in dc_keys:
        dc_keys[dc_id] = auth_key

    conn = sqlite3.connect(session_path)
    cur = conn.cursor()

    cur.execute("CREATE TABLE version (version INTEGER PRIMARY KEY)")
    cur.execute("INSERT INTO version VALUES (7)")

    cur.execute(
        "CREATE TABLE sessions (dc_id INTEGER PRIMARY KEY, server_address TEXT, port INTEGER, auth_key BLOB, takeout_id INTEGER)"
    )
    cur.execute(
        "INSERT INTO sessions VALUES (?, ?, ?, ?, ?)",
        (dc_id, "149.154.167.51", 443, auth_key, None),
    )

    cur.execute("CREATE TABLE entities (id INTEGER PRIMARY KEY, hash INTEGER NOT NULL, username TEXT, phone INTEGER, name TEXT, date INTEGER)")
    cur.execute(
        "INSERT INTO entities VALUES (?, ?, ?, ?, ?, ?)",
        (0, user_id, f"synth_user_{user_id}", 15550001111, "Synthetic User", 1700000000),
    )

    cur.execute("CREATE TABLE tdata_dc_keys (dc_id INTEGER PRIMARY KEY, auth_key BLOB NOT NULL)")
    for d, k in dc_keys.items():
        cur.execute("INSERT INTO tdata_dc_keys VALUES (?, ?)", (d, k))

    conn.commit()
    conn.close()
    return session_path


def create_synthetic_tdata(
    target_dir: Path,
    passcode: Optional[str] = None,
    user_id: int = 100000001,
    username: str = "synthetic_user",
    first_name: str = "Synthetic",
    last_name: str = "Tester",
    phone: str = "15551234567",
    bio: str = "Synthetic automated test account",
    main_dc_id: int = 2,
    dc_ids: Sequence[int] = (1, 2, 4, 5),
    account_index: int = 0,
    version: int = 7003003,
) -> Tuple[bytes, bytes, Dict[int, bytes]]:
    """
    Creates a realistic Telegram Desktop tdata folder with synthetic keys and profile.
    Returns: (local_key, main_auth_key, dc_keys)
    """
    target_dir = Path(target_dir)
    target_dir.mkdir(parents=True, exist_ok=True)

    local_key = os.urandom(256)
    main_auth_key = os.urandom(256)
    dc_keys = {d: (main_auth_key if d == main_dc_id else os.urandom(256)) for d in dc_ids}

    # 1. key_datas
    salt = os.urandom(32)
    account_indexes = [account_index]
    active_index = account_index

    info_inner = struct.pack(">i", len(account_indexes))
    for idx in account_indexes:
        info_inner += struct.pack(">i", idx)
    info_inner += struct.pack(">i", active_index)
    info_enc = encrypt_local_block(info_inner, local_key)

    def qba(b: bytes) -> bytes:
        return struct.pack(">I", len(b)) + b

    if passcode is not None and passcode != "":
        # KD2 Argon2id encrypted
        pass_key = derive_kd2_wrap_key(passcode, salt, time_cost=8, memory_cost=65536, threads=1)
        key_enc = encrypt_local_block(local_key, pass_key)
        key128 = key_enc[:16]
        ciphertext = key_enc[16:]

        kd2_block = (
            b"KD2\x00"
            + struct.pack(">IIIIII", 2, 1, 1, 1, 1, 65536)
            + struct.pack(">III", 8, 1, len(salt))
            + salt
            + struct.pack(">I", len(key_enc))
            + key_enc
        )
        kd_payload = qba(salt) + qba(key_enc) + qba(info_enc) + qba(kd2_block)
    else:
        # Unencrypted PBKDF2
        pass_key = derive_pbkdf2_wrap_key("", salt)
        key_enc = encrypt_local_block(local_key, pass_key)
        kd2_stub = b"KD2\x00" + struct.pack(">III", 2, 0, 0)
        kd_payload = qba(salt) + qba(key_enc) + qba(info_enc) + qba(kd2_stub)

    kd_tdf = TDataParser.write_tdf(kd_payload, version=version)
    (target_dir / "key_datas").write_bytes(kd_tdf)

    # 2. Account .s file
    folder_part, s_filename = TDataParser.compute_account_filename(account_index)
    s_bytes = DCExtractor.serialize_mtp_authorization(
        user_id=user_id,
        main_dc_id=main_dc_id,
        dc_keys=dc_keys,
        local_key=local_key,
        version=version,
    )
    (target_dir / s_filename).write_bytes(s_bytes)

    # 3. Account maps file with offline profile
    def qstr(s: str) -> bytes:
        b = s.encode("utf-16-be")
        return struct.pack(">I", len(b)) + b

    marker = bytes.fromhex("ffffffff000000a0000000a000000000")
    self_buf = (
        b"\x01" * 28
        + marker
        + qstr(first_name)
        + qstr(last_name)
        + qstr(phone)
        + qstr(username)
        + (b"\x00" * 32)
        + qstr(bio)
    )
    map_stream = (
        struct.pack(">IQ", 9, 123456789)  # lskUserSettings
        + struct.pack(">IIQQQQ", 1, 2, 111, 222, 333, 444)  # lskDraft
        + struct.pack(">II", 21, len(self_buf)) + self_buf  # lskSelfSerialized
    )
    enc_map = encrypt_local_block(map_stream, local_key)
    maps_payload = struct.pack(">III", 0xFFFFFFFF, 0xFFFFFFFF, len(enc_map)) + enc_map
    maps_tdf = TDataParser.write_tdf(maps_payload, version=version)

    acc_dir = target_dir / folder_part
    acc_dir.mkdir(parents=True, exist_ok=True)
    (acc_dir / "maps").write_bytes(maps_tdf)

    return local_key, main_auth_key, dc_keys


def create_synthetic_zip_backup(
    zip_path: Path,
    passcode: Optional[str] = "1234",
    user_id: int = 100000001,
    username: str = "synthetic_user",
    first_name: str = "Synthetic",
    last_name: str = "Tester",
    phone: str = "15551234567",
    bio: str = "Synthetic automated test account",
    main_dc_id: int = 2,
    dc_ids: Sequence[int] = (1, 2, 4, 5),
    account_index: int = 0,
    version: int = 7003003,
) -> Tuple[bytes, bytes, Dict[int, bytes]]:
    """
    Creates a valid synthetic ZIP backup containing tdata/...
    """
    zip_path = Path(zip_path)
    zip_path.parent.mkdir(parents=True, exist_ok=True)
    if zip_path.exists():
        zip_path.unlink()

    temp_td = Path(tempfile.mkdtemp(prefix="synth_td_"))
    try:
        lk, ak, dcs = create_synthetic_tdata(
            target_dir=temp_td,
            passcode=passcode,
            user_id=user_id,
            username=username,
            first_name=first_name,
            last_name=last_name,
            phone=phone,
            bio=bio,
            main_dc_id=main_dc_id,
            dc_ids=dc_ids,
            account_index=account_index,
            version=version,
        )

        with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
            for root, _, files in os.walk(temp_td):
                for f in files:
                    fp = Path(root) / f
                    rel = fp.relative_to(temp_td)
                    zf.write(fp, arcname=f"tdata/{rel.as_posix()}")

        return lk, ak, dcs
    finally:
        shutil.rmtree(temp_td, ignore_errors=True)
