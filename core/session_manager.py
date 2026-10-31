"""
Telegram Session Manager
- Creates Telethon SQLite .session files from raw AuthKeys (including self user_id entity & multi-DC keys)
- Verifies authorization status with official Telegram Desktop client headers and optional proxy
- Converts single or multiple .session files into clean, passcode-free Telegram Desktop tdata
  using a 100% Pure-Python native engine (zero PyQt5 / opentele requirement!)
"""

import os
import time
import sqlite3
from pathlib import Path
from typing import Dict, Any, List, Optional, Sequence, Union
from .dc_extractor import DCExtractor, OfflineUserProfile
from .tdata_parser import TDataParser


class SessionManager:
    """
    Manages Telethon .session files and native Telegram Desktop tdata conversion.
    """

    # Official Telegram Desktop API credentials (overridable via environment variables)
    DEFAULT_API_ID = int(os.environ.get("TG_API_ID", "2040"))
    DEFAULT_API_HASH = os.environ.get("TG_API_HASH", "b18441a1ff607e10a989891a5462e627")

    TDESKTOP_DEVICE_PARAMS: Dict[str, str] = {
        "device_model": os.environ.get("TG_DEVICE_MODEL", "Desktop"),
        "system_version": os.environ.get("TG_SYSTEM_VERSION", "Windows 10"),
        "app_version": os.environ.get("TG_APP_VERSION", "5.10.3 x64"),
        "lang_code": "en",
        "system_lang_code": "en-US",
    }

    @staticmethod
    def _secure_file_permissions(file_path: Path) -> None:
        """Restricts file permissions to owner-only (0600) where supported."""
        try:
            os.chmod(file_path, 0o600)
        except Exception:
            pass

    @classmethod
    def create_telethon_session(
        cls,
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
                (dc_id, ip, port, auth_key[:256], None, None),
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
                if profile and profile.phone:
                    clean_ph = profile.phone.lstrip("+").replace(" ", "")
                    if clean_ph.isdigit():
                        ph_int = int(clean_ph)
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
            dc_map = dict(all_dc_keys) if all_dc_keys else {dc_id: auth_key[:256]}
            if dc_id not in dc_map:
                dc_map[dc_id] = auth_key[:256]
            for k_dc, k_blob in dc_map.items():
                if len(k_blob) >= 256:
                    cur.execute(
                        "INSERT OR REPLACE INTO tdata_dc_keys VALUES (?, ?)",
                        (int(k_dc), bytes(k_blob[:256])),
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

        cls._secure_file_permissions(out_path)
        return out_path

    @staticmethod
    def read_offline_session_meta(session_path: Union[str, Path]) -> Dict[str, Any]:
        """
        Reads offline metadata (dc_id, auth_key, auth_key_id, user_id, username, phone, name, all_dc_keys)
        stored inside the Telethon .session SQLite file without connecting to the network.
        """
        meta: Dict[str, Any] = {}
        sess_file = Path(session_path)
        if not sess_file.exists():
            return meta
        try:
            conn = sqlite3.connect(sess_file)
            cur = conn.cursor()
            row_s = cur.execute("SELECT dc_id, server_address, port, auth_key FROM sessions LIMIT 1").fetchone()
            if row_s:
                meta["dc_id"] = int(row_s[0])
                meta["server"] = f"{row_s[1]}:{row_s[2]}"
                if row_s[3] and len(bytes(row_s[3])) >= 256:
                    ak = bytes(row_s[3])[:256]
                    meta["auth_key"] = ak
                    fp = DCExtractor.compute_auth_key_fingerprint(ak)
                    meta["auth_key_id"] = fp["auth_key_id"]
                    meta["auth_key_id_hex"] = fp["auth_key_id_hex"]
                    meta["auth_key_sha256"] = fp["sha256"]

            row_e = cur.execute("SELECT hash, username, phone, name FROM entities WHERE id = 0").fetchone()
            if row_e:
                meta["user_id"] = int(row_e[0]) if row_e[0] else None
                meta["username"] = row_e[1] or ""
                meta["phone"] = str(row_e[2]) if row_e[2] else ""
                meta["first_name"] = row_e[3] or ""

            dc_keys_map: Dict[int, bytes] = {}
            if "dc_id" in meta and "auth_key" in meta:
                dc_keys_map[meta["dc_id"]] = meta["auth_key"]

            try:
                rows_dc = cur.execute("SELECT dc_id, auth_key FROM tdata_dc_keys ORDER BY dc_id").fetchall()
                for r_dc, r_key in rows_dc:
                    if r_key and len(bytes(r_key)) >= 256:
                        dc_keys_map[int(r_dc)] = bytes(r_key)[:256]
            except Exception:
                pass

            if dc_keys_map:
                meta["dc_list"] = sorted(list(dc_keys_map.keys()))
                meta["dc_keys"] = dc_keys_map

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
        proxy: Optional[Any] = None,
    ) -> Dict[str, Any]:
        """
        Verifies if the session is alive on Telegram servers using official Telegram Desktop
        client headers to avoid anti-fraud flags.
        Retrieves user profile, active sessions, and recent dialogs.
        Gracefully handles revoked, expired, duplicated or network errors,
        while still returning any offline profile metadata stored in the session.
        """
        from telethon import TelegramClient

        sess_file = Path(session_path)
        sess_base = str(sess_file.with_suffix(""))
        offline_meta = cls.read_offline_session_meta(sess_file)
        # Remove raw binary keys from public verification dict
        offline_public = {k: v for k, v in offline_meta.items() if k not in ("auth_key", "dc_keys")}

        client = TelegramClient(
            sess_base,
            api_id,
            api_hash,
            proxy=proxy,
            **cls.TDESKTOP_DEVICE_PARAMS,
        )
        try:
            try:
                await client.connect()
            except Exception as e:
                err_str = str(e)
                err_type = type(e).__name__
                if "AuthKeyDuplicated" in err_type or "different IP" in err_str:
                    return {
                        **offline_public,
                        "authorized": False,
                        "status": "DUPLICATED",
                        "error": "Session authorization key was revoked by Telegram server because it was simultaneously used from another IP address (AuthKeyDuplicatedError).",
                        "session_path": str(sess_file),
                    }
                elif "AuthKeyUnregistered" in err_type or "unregistered" in err_str.lower():
                    return {
                        **offline_public,
                        "authorized": False,
                        "status": "UNREGISTERED",
                        "error": "Session has been logged out or terminated on Telegram servers (AuthKeyUnregisteredError).",
                        "session_path": str(sess_file),
                    }
                else:
                    return {
                        **offline_public,
                        "authorized": False,
                        "status": "CONNECTION_ERROR",
                        "error": f"Connection error occurred while connecting to server: {e}",
                        "session_path": str(sess_file),
                    }

            try:
                is_auth = await client.is_user_authorized()
            except Exception as e:
                return {
                    **offline_public,
                    "authorized": False,
                    "status": "REVOKED",
                    "error": f"Error verifying authorization status: {e}",
                    "session_path": str(sess_file),
                }

            result: Dict[str, Any] = {
                **offline_public,
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
    async def session_to_tdata_native(
        cls,
        session_paths: Union[str, Path, Sequence[Union[str, Path]]],
        output_tdata_dir: Union[str, Path],
        api_id: int = DEFAULT_API_ID,
        api_hash: str = DEFAULT_API_HASH,
        version: int = 7003003,
    ) -> Path:
        """
        100% Pure-Python native converter from one or multiple Telethon .session files
        into a clean, passcode-free Telegram Desktop tdata directory.
        - Requires ZERO PyQt5 / opentele dependencies!
        - Supports multi-account tdata creation (up to 16 accounts: index 0..15)
        - Preserves all multi-DC keys ([1, 2, 4, 5]) stored in tdata_dc_keys
        - Works completely offline if user_id (entities id=0) is present in the session
        """
        if isinstance(session_paths, (str, Path)):
            sess_list = [Path(session_paths)]
        else:
            sess_list = [Path(p) for p in session_paths]

        if not sess_list:
            raise ValueError("At least one .session file must be specified")

        out_dir = Path(output_tdata_dir)
        out_dir.mkdir(parents=True, exist_ok=True)

        accounts_payload: List[Dict[str, Any]] = []

        for s_path in sess_list:
            if s_path.suffix != ".session":
                s_path = s_path.with_suffix(".session")
            if not s_path.exists():
                raise FileNotFoundError(f"Session file not found: {s_path}")

            meta = cls.read_offline_session_meta(s_path)
            dc_id = meta.get("dc_id")
            auth_key = meta.get("auth_key")
            user_id = meta.get("user_id")
            dc_keys = meta.get("dc_keys") or {}

            if not dc_id or not auth_key or len(auth_key) < 256:
                raise ValueError(f"Valid AuthKey not found in session file: {s_path}")

            if not user_id or user_id <= 0:
                # Fallback: connect online once to fetch self user_id if not cached offline
                from telethon import TelegramClient
                client = TelegramClient(
                    str(s_path.with_suffix("")),
                    api_id,
                    api_hash,
                    **cls.TDESKTOP_DEVICE_PARAMS,
                )
                try:
                    await client.connect()
                    me = await client.get_me()
                    if me and me.id:
                        user_id = int(me.id)
                finally:
                    if client.is_connected():
                        await client.disconnect()

            if not user_id or user_id <= 0:
                raise ValueError(
                    f"User ID not found in session file and could not be fetched from server: {s_path.name}"
                )

            if dc_id not in dc_keys:
                dc_keys[dc_id] = auth_key[:256]

            accounts_payload.append({
                "user_id": int(user_id),
                "main_dc_id": int(dc_id),
                "dc_keys": dc_keys,
            })

        # Generate a fresh 256-byte master LocalKey and unlocked key_datas
        local_key = os.urandom(256)
        account_indexes = list(range(len(accounts_payload)))

        kd_bytes = TDataParser.create_unlocked_key_datas(
            local_key=local_key,
            account_indexes=account_indexes,
            active_index=0,
            version=version,
        )
        (out_dir / "key_datas").write_bytes(kd_bytes)

        # Write each account's <folder_part>s and <folder_part>/maps
        for idx, acc in enumerate(accounts_payload):
            folder_part, s_filename = TDataParser.compute_account_filename(idx)
            s_bytes = DCExtractor.serialize_mtp_authorization(
                user_id=acc["user_id"],
                main_dc_id=acc["main_dc_id"],
                dc_keys=acc["dc_keys"],
                local_key=local_key,
                version=version,
            )
            (out_dir / s_filename).write_bytes(s_bytes)

            comp_dir = out_dir / folder_part
            comp_dir.mkdir(parents=True, exist_ok=True)
            maps_bytes = DCExtractor.create_minimal_maps_tdf(
                local_key=local_key,
                version=version,
            )
            (comp_dir / "maps").write_bytes(maps_bytes)

        return out_dir

    @classmethod
    async def session_to_tdata(
        cls,
        session_path: Union[str, Path, Sequence[Union[str, Path]]],
        output_tdata_dir: Union[str, Path],
        api_id: int = DEFAULT_API_ID,
        api_hash: str = DEFAULT_API_HASH,
        use_opentele: bool = False,
    ) -> Path:
        """
        Converts one or more Telethon .session files into clean, unencrypted Telegram Desktop tdata.
        By default uses the 100% Pure-Python native serializer (zero PyQt5/opentele dependency).
        Can optionally fall back to opentele if use_opentele=True.
        """
        if not use_opentele:
            return await cls.session_to_tdata_native(
                session_paths=session_path,
                output_tdata_dir=output_tdata_dir,
                api_id=api_id,
                api_hash=api_hash,
            )

        from opentele.api import UseCurrentSession
        from opentele.tl import TelegramClient as OpenTeleClient
        from opentele.td import AuthKey, AuthKeyType
        from opentele.td.configs import DcId

        if isinstance(session_path, (list, tuple)):
            sess_path = Path(session_path[0])
        else:
            sess_path = Path(session_path)
        if sess_path.suffix != ".session":
            sess_path = sess_path.with_suffix(".session")

        out_dir = Path(output_tdata_dir)
        out_dir.mkdir(parents=True, exist_ok=True)

        meta = cls.read_offline_session_meta(sess_path)
        stored_user_id = meta.get("user_id")
        extra_dc_keys = meta.get("dc_keys") or {}

        client = OpenTeleClient(str(sess_path.with_suffix("")), api_id=api_id, api_hash=api_hash)
        try:
            if stored_user_id:
                client.UserId = stored_user_id
            else:
                await client.connect()

            tdesk = await client.ToTDesktop(flag=UseCurrentSession)

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
