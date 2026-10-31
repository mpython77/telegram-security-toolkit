"""
Telegram Desktop tdata Binary Parser
Parses Telegram's proprietary TDF$ format and extracts KD2 encryption structures.
"""

import hashlib
import struct
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Union, Any


@dataclass
class KD2Info:
    """Holds parsed KD2 (Argon2id + AES-IGE) parameters"""
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


class TDataParser:
    """
    Parser for Telegram Desktop tdata storage files and ZIP backups.
    """

    MAGIC_TDF = b"TDF$"

    @staticmethod
    def read_tdf(raw_data: bytes) -> bytes:
        """
        Validates TDF$ header and trailing MD5 checksum, returning the decrypted/unwrapped payload.
        TDF format:
        - 0..4: Magic b'TDF$'
        - 4..8: Version (Little-Endian uint32)
        - 8..-16: Payload
        - -16..: MD5 checksum of (payload + version + magic)
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

        # Exact Telegram TDF$ checksum formula:
        # md5(payload + len(payload) + version + magic)
        check_buf = payload + data_size.to_bytes(4, "little") + version.to_bytes(4, "little") + magic
        calc_md5 = hashlib.md5(check_buf).digest()

        if stored_md5 != calc_md5:
            raise ValueError("TDF$ fayl MD5 tekshiruvidan o'tmadi (fayl shikastlangan bo'lishi mumkin)")

        return payload

    @staticmethod
    def parse_kd2(key_datas_raw: bytes) -> KD2Info:
        """
        Parses key_datas (both KD2 Argon2id and Standard/Legacy PBKDF2 formats).
        Validates TDF$ header and MD5 checksum first.
        """
        payload = TDataParser.read_tdf(key_datas_raw)

        idx = key_datas_raw.find(b"KD2\x00")
        if idx != -1:
            blob = key_datas_raw[idx:]
            if len(blob) < 76 + 288:
                raise ValueError(f"KD2 tuzilmasi hajmi yetarli emas: {len(blob)} bayt")

            ver = struct.unpack_from(">I", blob, 4)[0]
            kdf_id = struct.unpack_from(">I", blob, 8)[0]
            mem = struct.unpack_from(">I", blob, 24)[0]
            time_c = struct.unpack_from(">I", blob, 28)[0]
            th = struct.unpack_from(">I", blob, 32)[0]
            salt_len = struct.unpack_from(">I", blob, 36)[0]

            salt = blob[40 : 40 + salt_len]
            enc_len_offset = 40 + salt_len
            enc_len = struct.unpack_from(">I", blob, enc_len_offset)[0]

            enc_blob_offset = enc_len_offset + 4
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

        # Standard / Legacy PBKDF2 format (used when no passcode is set or pre-KD2 passcodes):
        # Field 0: salt (QByteArray), Field 1: keyEncrypted (QByteArray)
        if len(payload) < 40:
            raise ValueError(f"key_datas payload juda kichik: {len(payload)} bayt")

        salt_len = struct.unpack_from(">I", payload, 0)[0]
        if salt_len == 0xFFFFFFFF or 4 + salt_len + 4 > len(payload):
            raise ValueError("key_datas ichida na KD2 va na yaroqli PBKDF2 tuzilmasi topildi.")

        salt = payload[4 : 4 + salt_len]
        enc_len = struct.unpack_from(">I", payload, 4 + salt_len)[0]
        if enc_len == 0xFFFFFFFF or 8 + salt_len + enc_len > len(payload):
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

    @staticmethod
    def parse_accounts_metadata(key_datas_raw: bytes, local_key: bytes) -> Optional[Dict[str, Any]]:
        """
        Decrypts infoEncrypted in key_datas to retrieve active accounts list and active_index.
        """
        try:
            from .crypto import prepare_aes_oldmtp, decrypt_aes_ige

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
            k128, cipher = info_enc[:16], info_enc[16:]
            ak, aiv = prepare_aes_oldmtp(local_key[:256], k128)
            dec = decrypt_aes_ige(cipher, ak, aiv)
            if hashlib.sha1(dec).digest()[:16] != k128:
                return None

            sz = struct.unpack_from("<I", dec, 0)[0]
            stream = dec[4 : 4 + sz]
            if len(stream) < 4:
                return None

            count = struct.unpack_from(">i", stream, 0)[0]
            p = 4
            indexes = []
            for _ in range(count):
                if p + 4 <= len(stream):
                    idx = struct.unpack_from(">i", stream, p)[0]
                    indexes.append(idx)
                    p += 4
            active_idx = struct.unpack_from(">i", stream, p)[0] if p + 4 <= len(stream) else 0
            return {"count": count, "indexes": indexes, "active_index": active_idx}
        except Exception:
            return None

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

            # Detect genuine account session files:
            # In Telegram Desktop, an authentic session file <16_hex>s ALWAYS has
            # an accompanying companion folder <16_hex> in the same directory.
            # Files inside <16_hex>/ are internal cache/maps and must be filtered out.
            for name in namelist:
                basename = Path(name).name
                if len(basename) == 17 and basename.endswith("s"):
                    companion_prefix = name[:-1] + "/"
                    has_companion = any(n.startswith(companion_prefix) for n in namelist)
                    if has_companion:
                        session_files[name] = zf.read(name)

            # Fallback: if no companion directory found (e.g. flat single archive)
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
        dir_path = Path(dir_path)
        if not dir_path.exists() or not dir_path.is_dir():
            raise FileNotFoundError(f"tdata papkasi topilmadi: {dir_path}")

        kd_path = dir_path / "key_datas"
        if not kd_path.exists():
            # Try searching in subfolders (e.g. if root was passed)
            nested_kd = list(dir_path.rglob("key_datas"))
            if nested_kd:
                kd_path = nested_kd[0]
            else:
                raise ValueError(f"key_datas topilmadi: {dir_path}")

        kd_raw = kd_path.read_bytes()
        kd2_info = cls.parse_kd2(kd_raw)

        session_files = {}
        for item in dir_path.rglob("*"):
            if item.is_file() and len(item.name) == 17 and item.name.endswith("s"):
                companion_dir = item.parent / item.name[:-1]
                if companion_dir.exists() and companion_dir.is_dir():
                    session_files[str(item.relative_to(dir_path))] = item.read_bytes()

        if not session_files:
            for item in dir_path.iterdir():
                if item.is_file() and len(item.name) == 17 and item.name.endswith("s"):
                    session_files[item.name] = item.read_bytes()

        return kd2_info, session_files
