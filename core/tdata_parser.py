"""
Telegram Desktop tdata Binary Parser
Parses Telegram's proprietary TDF$ format, validates checksums, safely handles
archive formats (.zip, .tar.xz, .tar.gz, directories) with Zip-Slip protection,
and extracts KD2 / PBKDF2 encryption structures.
"""

import hashlib
import lzma
import shutil
import struct
import tarfile
import tempfile
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Union, Any


@dataclass
class KD2Info:
    """Holds parsed KD2 (Argon2id + AES-IGE) or PBKDF2 parameters"""
    version: int
    kdf_id: int
    memory_cost: int
    time_cost: int
    threads: int
    salt_len: int
    salt: bytes
    enc_len: int
    enc_blob: bytes
    key128: bytes
    ciphertext: bytes


@dataclass
class TDataSourceBundle:
    """Holds all parsed artifacts from a tdata backup archive or directory."""
    kd2_info: KD2Info
    kd_raw: bytes
    tdf_version: int
    session_files: Dict[str, bytes]
    maps_files: Dict[str, bytes]
    all_tdf_status: Dict[str, Dict[str, Any]]


class TDataParser:
    """
    Parser for Telegram Desktop tdata storage files and backup archives (.zip, .tar.xz, .tar.gz, folders).
    """

    MAGIC_TDF = b"TDF$"
    MAX_ACCOUNTS = 16

    @staticmethod
    def format_tdf_version(version: int) -> str:
        """Converts integer TDF version (e.g. 7003003 or 4010002) to human-readable string."""
        if version <= 0:
            return str(version)
        major = version // 1000000
        minor = (version % 1000000) // 1000
        patch = version % 1000
        return f"{major}.{minor}.{patch} ({version})"

    @staticmethod
    def verify_tdf_integrity(raw_data: bytes) -> Dict[str, Any]:
        """
        Inspects a raw binary buffer and returns TDF$ metadata and MD5 integrity status
        without raising an exception.
        """
        info: Dict[str, Any] = {
            "size_bytes": len(raw_data),
            "sha256": hashlib.sha256(raw_data).hexdigest(),
            "is_tdf": False,
            "version": None,
            "version_str": None,
            "md5_valid": False,
            "error": None,
        }
        if len(raw_data) < 24:
            info["error"] = f"Fayl hajmi juda kichik ({len(raw_data)} bayt)"
            return info

        magic = raw_data[:4]
        if magic != TDataParser.MAGIC_TDF:
            info["error"] = f"Magic header TDF$ emas ({magic!r})"
            return info

        info["is_tdf"] = True
        version = struct.unpack_from("<I", raw_data, 4)[0]
        info["version"] = version
        info["version_str"] = TDataParser.format_tdf_version(version)

        payload = raw_data[8:-16]
        data_size = len(payload)
        stored_md5 = raw_data[-16:]
        check_buf = payload + data_size.to_bytes(4, "little") + version.to_bytes(4, "little") + magic
        calc_md5 = hashlib.md5(check_buf).digest()
        info["md5_valid"] = (stored_md5 == calc_md5)
        info["stored_md5"] = stored_md5.hex()
        info["calculated_md5"] = calc_md5.hex()
        if not info["md5_valid"]:
            info["error"] = "MD5 nazorat summasi mos kelmadi"
        return info

    @staticmethod
    def read_tdf(raw_data: bytes) -> bytes:
        """
        Validates TDF$ header and trailing MD5 checksum, returning the unwrapped payload.
        TDF format:
        - 0..4: Magic b'TDF$'
        - 4..8: Version (Little-Endian uint32)
        - 8..-16: Payload
        - -16..: MD5 checksum of (payload + len(payload) + version + magic)
        """
        if len(raw_data) < 24:
            raise ValueError(f"Fayl hajmi juda kichik: {len(raw_data)} bayt")

        magic = raw_data[:4]
        if magic != TDataParser.MAGIC_TDF:
            raise ValueError(f"Noto'g'ri magic header: {magic!r}, kutilgan: {TDataParser.MAGIC_TDF!r}")

        version = struct.unpack_from("<I", raw_data, 4)[0]
        payload = raw_data[8:-16]
        data_size = len(payload)
        stored_md5 = raw_data[-16:]

        check_buf = payload + data_size.to_bytes(4, "little") + version.to_bytes(4, "little") + magic
        calc_md5 = hashlib.md5(check_buf).digest()

        if stored_md5 != calc_md5:
            raise ValueError("TDF$ fayl MD5 tekshiruvidan o'tmadi (fayl shikastlangan bo'lishi mumkin)")

        return payload

    @staticmethod
    def write_tdf(payload: bytes, version: int = 7003003) -> bytes:
        """
        Serializes payload into a valid Telegram Desktop TDF$ binary buffer with MD5 footer.
        """
        magic = TDataParser.MAGIC_TDF
        ver_bytes = version.to_bytes(4, "little")
        size_bytes = len(payload).to_bytes(4, "little")
        md5_digest = hashlib.md5(payload + size_bytes + ver_bytes + magic).digest()
        return magic + ver_bytes + payload + md5_digest

    @staticmethod
    def create_unlocked_key_datas(
        local_key: bytes,
        account_indexes: Optional[List[int]] = None,
        active_index: int = 0,
        version: int = 7003003,
    ) -> bytes:
        """
        Creates a passcode-free key_datas TDF$ file that wraps the existing 256-byte local_key
        under an empty passcode ('', PBKDF2 1 iteration).
        Preserves 100% compatibility with existing encrypted session/maps/cache files!
        """
        import os
        from .crypto import derive_pbkdf2_wrap_key, encrypt_local_block

        if account_indexes is None or len(account_indexes) == 0:
            account_indexes = [0]

        salt = os.urandom(32)
        passcode_key = derive_pbkdf2_wrap_key("", salt)
        key_encrypted = encrypt_local_block(local_key[:256], passcode_key)

        info_inner = struct.pack(">i", len(account_indexes))
        for idx in account_indexes:
            info_inner += struct.pack(">i", idx)
        info_inner += struct.pack(">i", active_index)
        info_encrypted = encrypt_local_block(info_inner, local_key[:256])

        def qba(b: bytes) -> bytes:
            return struct.pack(">I", len(b)) + b

        payload = qba(salt) + qba(key_encrypted) + qba(info_encrypted)
        return TDataParser.write_tdf(payload, version=version)

    @staticmethod
    def parse_kd2(key_datas_raw: bytes) -> KD2Info:
        """
        Parses key_datas (both KD2 Argon2id and Standard/Legacy PBKDF2 formats).
        Correctly handles Telegram Desktop v5.x-v7.x+ where an unencrypted key_datas
        still appends a 16-byte 'KD2\\x00' stub with kdf_id=0.
        Validates TDF$ header and MD5 checksum first.
        """
        payload = TDataParser.read_tdf(key_datas_raw)

        idx = payload.find(b"KD2\x00")
        if idx != -1:
            blob = payload[idx:]
            if len(blob) >= 12:
                ver = struct.unpack_from(">I", blob, 4)[0]
                kdf_id = struct.unpack_from(">I", blob, 8)[0]
                if kdf_id != 0:
                    if len(blob) < 76 + 288:
                        raise ValueError(f"KD2 tuzilmasi hajmi yetarli emas: {len(blob)} bayt")

                    mem = struct.unpack_from(">I", blob, 24)[0]
                    time_c = struct.unpack_from(">I", blob, 28)[0]
                    th = struct.unpack_from(">I", blob, 32)[0]
                    salt_len = struct.unpack_from(">I", blob, 36)[0]

                    if 40 + salt_len + 4 > len(blob):
                        raise ValueError("KD2 salt uzunligi noto'g'ri")

                    salt = blob[40 : 40 + salt_len]
                    enc_len_offset = 40 + salt_len
                    enc_len = struct.unpack_from(">I", blob, enc_len_offset)[0]

                    enc_blob_offset = enc_len_offset + 4
                    if enc_blob_offset + enc_len > len(blob) or enc_len < 32:
                        raise ValueError("KD2 shifrlangan blok uzunligi noto'g'ri")
                    enc_blob = blob[enc_blob_offset : enc_blob_offset + enc_len]

                    key128 = enc_blob[:16]
                    ciphertext = enc_blob[16:]

                    return KD2Info(
                        version=ver,
                        kdf_id=kdf_id,
                        memory_cost=mem,
                        time_cost=time_c,
                        threads=th,
                        salt_len=salt_len,
                        salt=salt,
                        enc_len=enc_len,
                        enc_blob=enc_blob,
                        key128=key128,
                        ciphertext=ciphertext,
                    )

        # Standard / Legacy PBKDF2 format (used when no passcode is set, kdf_id=0 in KD2 stub, or pre-KD2 passcodes):
        # Field 0: salt (QByteArray), Field 1: keyEncrypted (QByteArray)
        if len(payload) < 40:
            raise ValueError(f"key_datas payload juda kichik: {len(payload)} bayt")

        salt_len = struct.unpack_from(">I", payload, 0)[0]
        if salt_len == 0xFFFFFFFF or 4 + salt_len + 4 > len(payload):
            raise ValueError("key_datas ichida na KD2 va na yaroqli PBKDF2 tuzilmasi topildi.")

        salt = payload[4 : 4 + salt_len]
        enc_len = struct.unpack_from(">I", payload, 4 + salt_len)[0]
        if enc_len == 0xFFFFFFFF or 8 + salt_len + enc_len > len(payload) or enc_len < 32:
            raise ValueError("key_datas ichida shifrlangan kalit bloki (keyEncrypted) topilmadi.")

        enc_blob = payload[8 + salt_len : 8 + salt_len + enc_len]
        key128 = enc_blob[:16]
        ciphertext = enc_blob[16:]

        return KD2Info(
            version=1,
            kdf_id=0,  # 0 indicates PBKDF2-HMAC-SHA512
            memory_cost=0,
            time_cost=100000,
            threads=1,
            salt_len=salt_len,
            salt=salt,
            enc_len=enc_len,
            enc_blob=enc_blob,
            key128=key128,
            ciphertext=ciphertext,
        )

    @staticmethod
    def compute_account_filename(index: int, key_file: str = "data") -> Tuple[str, str]:
        """
        Computes the folder name and session filename (.s) for a Telegram Desktop account index.
        Index 0 -> ('D877F783D5D3EF8C', 'D877F783D5D3EF8Cs')
        Index 1 -> ('A7FDF864FBC10B77', 'A7FDF864FBC10B77s')
        Index 2 -> ('F8806DD0C461824F', 'F8806DD0C461824Fs')
        Supports any account index (0..15+).
        """
        data_name = key_file if index == 0 else f"{key_file}#{index + 1}"
        md5_bytes = hashlib.md5(data_name.encode("utf-8")).digest()
        val = int.from_bytes(md5_bytes, "little")

        folder_part = ""
        for _ in range(16):
            v = val & 0xF
            if v < 10:
                folder_part += chr(ord("0") + v)
            else:
                folder_part += chr(ord("A") + (v - 10))
            val >>= 4
        return folder_part, folder_part + "s"

    @classmethod
    def get_account_index_map(cls, max_accounts: int = MAX_ACCOUNTS) -> Dict[str, int]:
        """Returns mapping of 16-char folder hash -> account index (0..max_accounts-1)."""
        mapping: Dict[str, int] = {}
        for idx in range(max_accounts):
            f_part, _ = cls.compute_account_filename(idx)
            mapping[f_part] = idx
        return mapping

    @staticmethod
    def parse_accounts_metadata(key_datas_raw: bytes, local_key: bytes) -> Optional[Dict[str, Any]]:
        """
        Decrypts infoEncrypted in key_datas to retrieve active accounts list and active_index.
        """
        try:
            from .crypto import decrypt_local_block

            payload = TDataParser.read_tdf(key_datas_raw)
            salt_len = struct.unpack_from(">I", payload, 0)[0]
            pos = 4 + salt_len
            f1_len = struct.unpack_from(">I", payload, pos)[0]
            pos += 4
            if f1_len != 0xFFFFFFFF:
                pos += f1_len
            if pos + 4 > len(payload):
                return None

            info_len = struct.unpack_from(">I", payload, pos)[0]
            pos += 4
            if info_len == 0xFFFFFFFF or pos + info_len > len(payload) or info_len < 32:
                return None

            info_enc = payload[pos : pos + info_len]
            stream = decrypt_local_block(info_enc, local_key[:256])
            if not stream or len(stream) < 4:
                return None

            count = struct.unpack_from(">i", stream, 0)[0]
            if count < 0 or count > 64:
                return None
            p = 4
            indexes = []
            for _ in range(count):
                if p + 4 <= len(stream):
                    idx = struct.unpack_from(">i", stream, p)[0]
                    indexes.append(idx)
                    p += 4
            active_idx = struct.unpack_from(">i", stream, p)[0] if p + 4 <= len(stream) else 0
            if active_idx < 0 or (indexes and active_idx not in indexes and active_idx >= count):
                active_idx = indexes[0] if indexes else 0
            return {"count": count, "indexes": indexes, "active_index": active_idx}
        except Exception:
            return None

    @staticmethod
    def safe_extract_zip(zip_path: Union[str, Path], target_dir: Union[str, Path]) -> Path:
        """
        Safely extracts a ZIP archive into target_dir with strict Zip-Slip (Path Traversal) protection.
        Raises ValueError if any archive entry attempts to escape target_dir.
        """
        target_root = Path(target_dir).resolve()
        target_root.mkdir(parents=True, exist_ok=True)

        with zipfile.ZipFile(zip_path, "r") as zf:
            for member in zf.infolist():
                member_name = member.filename.replace("\\", "/")
                if member_name.startswith("/") or ".." in Path(member_name).parts:
                    raise ValueError(f"Xavfli arxiv yo'li (Zip-Slip aniqlandi): {member.filename}")
                dest_path = (target_root / member_name).resolve()
                if not dest_path.is_relative_to(target_root):
                    raise ValueError(f"Xavfli arxiv yo'li (Zip-Slip aniqlandi): {member.filename}")
                if member.is_dir():
                    dest_path.mkdir(parents=True, exist_ok=True)
                else:
                    dest_path.parent.mkdir(parents=True, exist_ok=True)
                    with zf.open(member, "r") as src, open(dest_path, "wb") as dst:
                        shutil.copyfileobj(src, dst)
        return target_root

    @staticmethod
    def safe_extract_tar(tar_path: Union[str, Path], target_dir: Union[str, Path]) -> Path:
        """
        Safely extracts a TAR / TAR.XZ / TAR.GZ archive into target_dir with strict
        Path Traversal and symlink/device-file protection.
        """
        target_root = Path(target_dir).resolve()
        target_root.mkdir(parents=True, exist_ok=True)
        src_path = Path(tar_path)

        def _extract_tar_obj(tar_obj: tarfile.TarFile) -> None:
            for member in tar_obj.getmembers():
                member_name = member.name.replace("\\", "/")
                if member_name.startswith("/") or ".." in Path(member_name).parts:
                    raise ValueError(f"Xavfli TAR yo'li (Path Traversal aniqlandi): {member.name}")
                if member.issym() or member.islnk() or member.isdev():
                    raise ValueError(f"Xavfli TAR element turi (symlink/device rad etildi): {member.name}")
                dest_path = (target_root / member_name).resolve()
                if not dest_path.is_relative_to(target_root):
                    raise ValueError(f"Xavfli TAR yo'li (Path Traversal aniqlandi): {member.name}")
                if member.isdir():
                    dest_path.mkdir(parents=True, exist_ok=True)
                elif member.isfile():
                    dest_path.parent.mkdir(parents=True, exist_ok=True)
                    f_src = tar_obj.extractfile(member)
                    if f_src is not None:
                        with f_src, open(dest_path, "wb") as f_dst:
                            shutil.copyfileobj(f_src, f_dst)

        if src_path.suffix.lower() == ".xz":
            with lzma.open(src_path, "rb") as f_in:
                with tarfile.open(fileobj=f_in) as tar:
                    _extract_tar_obj(tar)
        else:
            with tarfile.open(src_path, "r:*") as tar:
                _extract_tar_obj(tar)

        return target_root

    @classmethod
    def load_full_source(cls, source: Union[str, Path]) -> TDataSourceBundle:
        """
        Universal loader that inspects any .zip, .tar.xz, .tar.gz, .tar archive or tdata directory
        and returns a complete TDataSourceBundle (kd2_info, kd_raw, tdf_version, session_files,
        maps_files, and integrity status of all TDF$ files).
        """
        source_path = Path(source)
        if not source_path.exists():
            raise FileNotFoundError(f"Manba topilmadi: {source_path}")

        if source_path.is_file() and source_path.name.startswith("key_data"):
            kd_raw = source_path.read_bytes()
            tdf_ver = struct.unpack_from("<I", kd_raw, 4)[0] if len(kd_raw) >= 8 else 7003003
            kd2_info = cls.parse_kd2(kd_raw)
            return TDataSourceBundle(
                kd2_info=kd2_info,
                kd_raw=kd_raw,
                tdf_version=tdf_ver,
                session_files={},
                maps_files={},
                all_tdf_status={"key_datas": cls.verify_tdf_integrity(kd_raw)},
            )

        temp_dir: Optional[Path] = None
        try:
            if source_path.is_file():
                name_low = source_path.name.lower()
                temp_dir = Path(tempfile.mkdtemp(prefix="tlgr_parse_"))
                if name_low.endswith(".zip"):
                    cls.safe_extract_zip(source_path, temp_dir)
                elif name_low.endswith((".tar.xz", ".xz", ".tar.gz", ".tgz", ".tar")):
                    cls.safe_extract_tar(source_path, temp_dir)
                else:
                    raise ValueError(f"Qo'llab-quvvatlanmaydigan manba fayl formati: {source_path.name}")
                scan_root = temp_dir
            elif source_path.is_dir():
                scan_root = source_path
            else:
                raise ValueError(f"Noma'lum manba: {source_path}")

            kd_path = scan_root / "key_datas"
            if not kd_path.exists():
                nested_kd = sorted(list(scan_root.rglob("key_datas")))
                if nested_kd:
                    kd_path = nested_kd[0]
                else:
                    raise ValueError(f"key_datas topilmadi: {source_path}")

            tdata_root = kd_path.parent
            kd_raw = kd_path.read_bytes()
            tdf_version = struct.unpack_from("<I", kd_raw, 4)[0] if len(kd_raw) >= 8 else 7003003
            kd2_info = cls.parse_kd2(kd_raw)

            session_files: Dict[str, bytes] = {}
            maps_files: Dict[str, bytes] = {}
            all_tdf_status: Dict[str, Dict[str, Any]] = {}

            for item in sorted(tdata_root.rglob("*")):
                if not item.is_file():
                    continue
                rel_key = item.relative_to(tdata_root).as_posix()
                raw_bytes = item.read_bytes()
                if len(raw_bytes) >= 4 and raw_bytes[:4] == cls.MAGIC_TDF:
                    all_tdf_status[rel_key] = cls.verify_tdf_integrity(raw_bytes)

            # Detect authentic top-level account session files (<16_hex>s)
            for item in sorted(tdata_root.iterdir()):
                if item.is_file() and len(item.name) == 17 and item.name.endswith("s"):
                    folder_part = item.name[:-1]
                    comp_dir = tdata_root / folder_part
                    if comp_dir.exists() and comp_dir.is_dir():
                        session_files[item.name] = item.read_bytes()
                        mp_path = comp_dir / "maps"
                        if mp_path.exists() and mp_path.is_file():
                            maps_files[folder_part] = mp_path.read_bytes()

            if not session_files:
                for item in sorted(tdata_root.iterdir()):
                    if item.is_file() and len(item.name) == 17 and item.name.endswith("s"):
                        session_files[item.name] = item.read_bytes()

            return TDataSourceBundle(
                kd2_info=kd2_info,
                kd_raw=kd_raw,
                tdf_version=tdf_version,
                session_files=session_files,
                maps_files=maps_files,
                all_tdf_status=all_tdf_status,
            )
        finally:
            if temp_dir and temp_dir.exists():
                shutil.rmtree(temp_dir, ignore_errors=True)

    @classmethod
    def load_from_source(cls, source: Union[str, Path]) -> Tuple[KD2Info, Dict[str, bytes]]:
        """
        Universal loader returning (KD2Info, session_files) from .zip, .tar.xz, .tar.gz, or directory.
        """
        bundle = cls.load_full_source(source)
        return bundle.kd2_info, bundle.session_files

    @classmethod
    def load_from_zip(cls, zip_path: Union[str, Path]) -> Tuple[KD2Info, Dict[str, bytes]]:
        """
        Loads KD2Info and all session files directly from a Telegram backup ZIP archive.
        """
        zip_path = Path(zip_path)
        if not zip_path.exists():
            raise FileNotFoundError(f"Arxiv fayli topilmadi: {zip_path}")

        session_files = {}
        kd2_info = None

        with zipfile.ZipFile(zip_path, "r") as zf:
            namelist = zf.namelist()
            kd_files = [n for n in namelist if n.endswith("key_datas")]
            if not kd_files:
                raise ValueError("Arxiv ichida key_datas fayli topilmadi!")

            kd_raw = zf.read(kd_files[0])
            kd2_info = cls.parse_kd2(kd_raw)

            for name in namelist:
                basename = Path(name).name
                if len(basename) == 17 and basename.endswith("s"):
                    companion_prefix = name[:-1] + "/"
                    has_companion = any(n.startswith(companion_prefix) for n in namelist)
                    if has_companion:
                        session_files[name] = zf.read(name)

            if not session_files:
                for name in namelist:
                    basename = Path(name).name
                    if len(basename) == 17 and basename.endswith("s"):
                        session_files[name] = zf.read(name)

        return kd2_info, session_files

    @classmethod
    def load_from_dir(cls, dir_path: Union[str, Path]) -> Tuple[KD2Info, Dict[str, bytes]]:
        """
        Loads KD2Info and session files from a tdata directory.
        """
        bundle = cls.load_full_source(dir_path)
        return bundle.kd2_info, bundle.session_files
