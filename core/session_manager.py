"""
Telegram Session Manager
- Creates Telethon SQLite .session files from raw AuthKeys (including self user_id entity)
- Verifies authorization status and retrieves account information
- Converts .session to clean, unencrypted Telegram Desktop tdata (offline or online)
"""

import time
import asyncio
import sqlite3
from pathlib import Path
from typing import Dict, Any, Optional, Union
from .dc_extractor import DCExtractor, OfflineUserProfile


class SessionManager:
    """
    Manages Telethon .session files and Telegram Desktop tdata conversion.
    """

    DEFAULT_API_ID = 5685951
    DEFAULT_API_HASH = "5251d17e23f6a5092ec61076c594cb39"

    @staticmethod
    def create_telethon_session(
        auth_key: bytes,
        dc_id: int,
        output_path: Union[str, Path],
        user_id: Optional[int] = None,
        all_dc_keys: Optional[Dict[int, bytes]] = None,
        profile: Optional[OfflineUserProfile] = None,
    ) -> Path:
        """
        Creates an authentic Telethon v8 SQLite database (.session) containing the auth_key,
        optional self user_id entity (id=0) with offline profile metadata, and multi-DC keys.
        """
        out_path = Path(output_path)
        if out_path.suffix != ".session":
            out_path = out_path.with_suffix(".session")

        out_path.parent.mkdir(parents=True, exist_ok=True)
        if out_path.exists():
            out_path.unlink()

        ip, port = DCExtractor.get_dc_server_info(dc_id)

        conn = sqlite3.connect(out_path)
        try:
            cur = conn.cursor()

            # Telethon Schema version 8
            cur.execute("CREATE TABLE IF NOT EXISTS version (version INTEGER PRIMARY KEY)")
            cur.execute("INSERT OR REPLACE INTO version VALUES (8)")

            cur.execute("""
                CREATE TABLE IF NOT EXISTS sessions (
                    dc_id INTEGER PRIMARY KEY,
                    server_address TEXT,
                    port INTEGER,
                    auth_key BLOB,
                    takeout_id INTEGER,
                    tmp_auth_key BLOB
                )
            """)
            cur.execute(
                "INSERT OR REPLACE INTO sessions VALUES (?, ?, ?, ?, ?, ?)",
                (dc_id, ip, port, auth_key, None, None),
            )

            cur.execute("""
                CREATE TABLE IF NOT EXISTS entities (
                    id INTEGER PRIMARY KEY,
                    hash INTEGER NOT NULL,
                    username TEXT,
                    phone INTEGER,
                    name TEXT,
                    date INTEGER
                )
            """)
            if user_id is not None and user_id > 0:
                u_name = profile.username if (profile and profile.username) else None
                f_name = profile.full_name if (profile and profile.full_name) else None
                ph_int = None
                if profile and profile.phone and profile.phone.isdigit():
                    ph_int = int(profile.phone)
                cur.execute(
                    "INSERT OR REPLACE INTO entities VALUES (?, ?, ?, ?, ?, ?)",
                    (0, int(user_id), u_name, ph_int, f_name, int(time.time())),
                )

            # Store all multi-DC keys in an auxiliary table so session_to_tdata preserves all DCs
            cur.execute("""
                CREATE TABLE IF NOT EXISTS tdata_dc_keys (
                    dc_id INTEGER PRIMARY KEY,
                    auth_key BLOB NOT NULL
                )
            """)
            dc_map = dict(all_dc_keys) if all_dc_keys else {dc_id: auth_key}
            if dc_id not in dc_map:
                dc_map[dc_id] = auth_key
            for k_dc, k_blob in dc_map.items():
                if len(k_blob) == 256:
                    cur.execute(
                        "INSERT OR REPLACE INTO tdata_dc_keys VALUES (?, ?)",
                        (int(k_dc), k_blob),
                    )

            cur.execute("""
                CREATE TABLE IF NOT EXISTS sent_files (
                    md5_digest BLOB,
                    file_size INTEGER,
                    type INTEGER,
                    id INTEGER,
                    hash INTEGER,
                    PRIMARY KEY(md5_digest, file_size, type)
                )
            """)

            cur.execute("""
                CREATE TABLE IF NOT EXISTS update_state (
                    id INTEGER PRIMARY KEY,
                    pts INTEGER,
                    qts INTEGER,
                    date INTEGER,
                    seq INTEGER
                )
            """)

            conn.commit()
        finally:
            conn.close()
        return out_path

    @staticmethod
    def read_offline_session_meta(session_path: Union[str, Path]) -> Dict[str, Any]:
        """
        Reads offline metadata (dc_id, user_id, username, phone, name, all_dc_keys)
        stored inside the Telethon .session SQLite file.
        """
        meta: Dict[str, Any] = {}
        sess_file = Path(session_path)
        if not sess_file.exists():
            return meta
        try:
            conn = sqlite3.connect(sess_file)
            cur = conn.cursor()
            row_s = cur.execute("SELECT dc_id, server_address, port FROM sessions LIMIT 1").fetchone()
            if row_s:
                meta["dc_id"] = row_s[0]
                meta["server"] = f"{row_s[1]}:{row_s[2]}"
            row_e = cur.execute("SELECT hash, username, phone, name FROM entities WHERE id = 0").fetchone()
            if row_e:
                meta["user_id"] = int(row_e[0]) if row_e[0] else None
                meta["username"] = row_e[1] or ""
                meta["phone"] = str(row_e[2]) if row_e[2] else ""
                meta["first_name"] = row_e[3] or ""
            try:
                rows_dc = cur.execute("SELECT dc_id FROM tdata_dc_keys ORDER BY dc_id").fetchall()
                if rows_dc:
                    meta["dc_list"] = [int(r[0]) for r in rows_dc]
            except Exception:
                pass
            conn.close()
        except Exception:
            pass
        return meta

    @classmethod
    async def verify_session(
        cls,
        session_path: Union[str, Path],
        api_id: int = DEFAULT_API_ID,
        api_hash: str = DEFAULT_API_HASH,
    ) -> Dict[str, Any]:
        """
        Verifies if the session is alive on Telegram servers.
        Retrieves user profile, active sessions, and recent dialogs.
        Gracefully handles revoked, expired, duplicated or network errors,
        while still returning any offline profile metadata stored in the session.
        """
        from telethon import TelegramClient

        sess_file = Path(session_path)
        sess_base = str(sess_file.with_suffix(""))
        offline_meta = cls.read_offline_session_meta(sess_file)

        client = TelegramClient(sess_base, api_id, api_hash)
        try:
            try:
                await client.connect()
            except Exception as e:
                err_str = str(e)
                err_type = type(e).__name__
                if "AuthKeyDuplicated" in err_type or "different IP" in err_str:
                    return {
                        **offline_meta,
                        "authorized": False,
                        "status": "DUPLICATED",
                        "error": "Sessiya kaliti bir vaqtning o'zida boshqa IP-manzildan ishlatilgani sababli Telegram serveri tomonidan bekor qilingan (AuthKeyDuplicatedError).",
                        "session_path": str(sess_file),
                    }
                elif "AuthKeyUnregistered" in err_type or "unregistered" in err_str.lower():
                    return {
                        **offline_meta,
                        "authorized": False,
                        "status": "UNREGISTERED",
                        "error": "Sessiya Telegram serveridan chiqarib yuborilgan yoki seans tugatilgan (AuthKeyUnregisteredError).",
                        "session_path": str(sess_file),
                    }
                else:
                    return {
                        **offline_meta,
                        "authorized": False,
                        "status": "CONNECTION_ERROR",
                        "error": f"Serverga ulanishda xatolik yuz berdi: {e}",
                        "session_path": str(sess_file),
                    }

            try:
                is_auth = await client.is_user_authorized()
            except Exception as e:
                return {
                    **offline_meta,
                    "authorized": False,
                    "status": "REVOKED",
                    "error": f"Avtorizatsiyani tekshirishda xatolik: {e}",
                    "session_path": str(sess_file),
                }

            result: Dict[str, Any] = {
                **offline_meta,
                "authorized": is_auth,
                "status": "ACTIVE" if is_auth else "EXPIRED",
                "session_path": str(sess_file),
            }

            if is_auth:
                try:
                    me = await client.get_me()
                    result["user_id"] = me.id
                    result["first_name"] = me.first_name or ""
                    result["last_name"] = me.last_name or ""
                    result["username"] = me.username or ""
                    result["phone"] = me.phone or ""
                except Exception as e:
                    result["profile_error"] = str(e)

                try:
                    from telethon.tl.functions.account import GetAuthorizationsRequest
                    auths = await client(GetAuthorizationsRequest())
                    result["active_authorizations"] = len(auths.authorizations)
                    result["devices"] = [
                        f"{a.device_model} ({a.app_name}) - {a.country}"
                        for a in auths.authorizations
                    ]
                except Exception:
                    result["active_authorizations"] = "N/A"
                    result["devices"] = []

                # Sample 5 recent dialogs
                dialogs_list = []
                try:
                    async for dialog in client.iter_dialogs(limit=5):
                        dialogs_list.append(dialog.name)
                except Exception:
                    pass
                result["recent_dialogs"] = dialogs_list

            return result
        finally:
            try:
                if client.is_connected():
                    await client.disconnect()
            except Exception:
                pass

    @classmethod
    async def session_to_tdata(
        cls,
        session_path: Union[str, Path],
        output_tdata_dir: Union[str, Path],
        api_id: int = DEFAULT_API_ID,
        api_hash: str = DEFAULT_API_HASH,
    ) -> Path:
        """
        Converts a Telethon .session file into clean, unencrypted Telegram Desktop tdata.
        Works offline if self user_id (entity id=0) is stored in the session, or connects online if needed.
        Preserves all multi-DC keys if stored in tdata_dc_keys.
        """
        from opentele.api import UseCurrentSession
        from opentele.tl import TelegramClient as OpenTeleClient
        from opentele.td import AuthKey, AuthKeyType
        from opentele.td.configs import DcId

        sess_path = Path(session_path)
        if sess_path.suffix != ".session":
            sess_path = sess_path.with_suffix(".session")

        out_dir = Path(output_tdata_dir)
        out_dir.mkdir(parents=True, exist_ok=True)

        # Check if user_id and multi-DC keys are stored in SQLite
        stored_user_id: Optional[int] = None
        extra_dc_keys: Dict[int, bytes] = {}
        try:
            conn = sqlite3.connect(sess_path)
            cur = conn.cursor()
            row = cur.execute("SELECT hash FROM entities WHERE id = 0").fetchone()
            if row and row[0]:
                stored_user_id = int(row[0])
            try:
                for dc_r, k_blob in cur.execute("SELECT dc_id, auth_key FROM tdata_dc_keys").fetchall():
                    if k_blob and len(bytes(k_blob)) == 256:
                        extra_dc_keys[int(dc_r)] = bytes(k_blob)
            except Exception:
                pass
            conn.close()
        except Exception:
            pass

        client = OpenTeleClient(str(sess_path.with_suffix("")), api_id=api_id, api_hash=api_hash)
        try:
            if stored_user_id:
                client.UserId = stored_user_id
            else:
                await client.connect()

            tdesk = await client.ToTDesktop(flag=UseCurrentSession)

            # Inject any additional multi-DC keys (e.g. DC 1, 4, 5) into mainAccount
            if extra_dc_keys and hasattr(tdesk, "mainAccount") and tdesk.mainAccount:
                existing_dcs = {int(k.dcId) for k in tdesk.mainAccount._Account__mtpKeys}
                for dc_id, k_bytes in sorted(extra_dc_keys.items()):
                    if dc_id not in existing_dcs:
                        tdesk.mainAccount._Account__mtpKeys.append(
                            AuthKey(k_bytes, AuthKeyType.ReadFromFile, DcId(dc_id))
                        )

            tdesk.SaveTData(str(out_dir))
        finally:
            if client.is_connected():
                await client.disconnect()
            elif hasattr(client, "session") and client.session:
                try:
                    client.session.close()
                except Exception:
                    pass

        return out_dir
