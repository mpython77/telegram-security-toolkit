"""
Telegram Session Manager
- Creates Telethon SQLite .session files from raw AuthKeys
- Verifies authorization status and retrieves account information
- Converts .session to clean, unencrypted Telegram Desktop tdata
"""

import asyncio
import sqlite3
from pathlib import Path
from typing import Dict, Any, Optional, Union
from .dc_extractor import DCExtractor


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
    ) -> Path:
        """
        Creates an authentic Telethon v8 SQLite database (.session) containing the auth_key.
        """
        out_path = Path(output_path)
        if out_path.suffix != ".session":
            out_path = out_path.with_suffix(".session")

        out_path.parent.mkdir(parents=True, exist_ok=True)
        if out_path.exists():
            out_path.unlink()

        ip, port = DCExtractor.get_dc_server_info(dc_id)

        conn = sqlite3.connect(out_path)
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
        conn.close()
        return out_path

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
        """
        from telethon import TelegramClient

        sess_file = Path(session_path)
        sess_base = str(sess_file.with_suffix(""))

        client = TelegramClient(sess_base, api_id, api_hash)
        await client.connect()

        is_auth = await client.is_user_authorized()
        result: Dict[str, Any] = {
            "authorized": is_auth,
            "session_path": str(sess_file),
        }

        if is_auth:
            me = await client.get_me()
            result["user_id"] = me.id
            result["first_name"] = me.first_name or ""
            result["last_name"] = me.last_name or ""
            result["username"] = me.username or ""
            result["phone"] = me.phone or ""

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

        await client.disconnect()
        return result

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
        """
        from opentele.api import UseCurrentSession
        from opentele.td import TDesktop
        from opentele.tl import TelegramClient as OpenTeleClient

        sess_path = Path(session_path)
        out_dir = Path(output_tdata_dir)
        out_dir.mkdir(parents=True, exist_ok=True)

        client = OpenTeleClient(str(sess_path.with_suffix("")), api_id=api_id, api_hash=api_hash)
        await client.connect()

        tdesk = await client.ToTDesktop(flag=UseCurrentSession)
        tdesk.SaveTData(str(out_dir))
        await client.disconnect()

        return out_dir
