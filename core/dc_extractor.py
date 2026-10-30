"""
Telegram Multi-DC AuthKey Extractor
Decrypts Telegram Desktop session (.s) files and extracts MTProto AuthKeys, User ID, and Main DC ID.
"""

import hashlib
import struct
from dataclasses import dataclass
from typing import Dict, Tuple
from .crypto import prepare_aes_oldmtp, decrypt_aes_ige
from .tdata_parser import TDataParser


@dataclass
class MtpSessionInfo:
    """Holds parsed MTProto authorization metadata from a Telegram Desktop .s file."""
    user_id: int
    main_dc_id: int
    dc_keys: Dict[int, bytes]


class DCExtractor:
    """
    Decrypts session (.s) files using the recovered LocalKey and extracts Multi-DC AuthKeys.
    """

    # Telegram Data Center Production Server IP addresses
    DC_SERVERS: Dict[int, Tuple[str, int]] = {
        1: ("149.154.175.53", 443),   # Miami / Americas
        2: ("149.154.167.51", 443),   # Amsterdam / Europe, CIS, Central Asia
        3: ("149.154.175.100", 443),  # Miami / WebRTC
        4: ("149.154.167.92", 443),   # Amsterdam / Large files
        5: ("91.108.56.130", 443),    # Singapore / Asia
    }

    DBI_MTP_AUTHORIZATION = 75  # 0x4b

    @staticmethod
    def decrypt_session_data(session_s_raw: bytes, local_key: bytes) -> bytes:
        """
        Decrypts the raw .s session file using the 256-byte master LocalKey.
        Verifies both TDF$ MD5 checksum and MTProto AES-IGE SHA-1 checksum.
        Returns the decrypted inner serialized stream.
        """
        payload = TDataParser.read_tdf(session_s_raw)

        enc_len = struct.unpack_from(">I", payload, 0)[0]
        if enc_len == 0xFFFFFFFF or 4 + enc_len > len(payload) or enc_len < 32:
            raise ValueError(f"Noto'g'ri shifrlangan blok uzunligi: {enc_len}")

        enc_data = payload[4 : 4 + enc_len]
        key128 = enc_data[:16]
        cipher = enc_data[16:]

        cand_key = local_key[:256]
        aes_k, aes_iv = prepare_aes_oldmtp(cand_key, key128)
        decrypted = decrypt_aes_ige(cipher, aes_k, aes_iv)

        # Verify MTProto Local Storage SHA-1 checksum
        if hashlib.sha1(decrypted).digest()[:16] != key128:
            raise ValueError("Sessiya fayli SHA-1 tekshiruvidan o'tmadi (boshqa LocalKey bilan shifrlangan)")

        size = struct.unpack_from("<I", decrypted, 0)[0]
        if size > len(decrypted) - 4:
            raise ValueError(f"Ichki blok hajmi noto'g'ri: {size} > {len(decrypted) - 4}")

        return decrypted[4 : 4 + size]

    @classmethod
    def extract_session_info(cls, session_s_raw: bytes, local_key: bytes) -> MtpSessionInfo:
        """
        Extracts User ID, Main DC ID, and all MTProto AuthKeys from a session (.s) file.
        Supports both modern 64-bit UserID (kWideIdsTag) and legacy 32-bit UserID headers.
        """
        inner = cls.decrypt_session_data(session_s_raw, local_key)
        if len(inner) < 16:
            raise ValueError("Shifrdan yechilgan sessiya ma'lumotlari juda qisqa")

        block_id = struct.unpack_from(">i", inner, 0)[0]
        if block_id != cls.DBI_MTP_AUTHORIZATION:
            raise ValueError(f"Noto'g'ri blok identifikatori: {block_id} (kutilgan: {cls.DBI_MTP_AUTHORIZATION})")

        qba_len = struct.unpack_from(">I", inner, 4)[0]
        if qba_len == 0xFFFFFFFF or 8 + qba_len > len(inner):
            raise ValueError(f"Noto'g'ri mtp_authorization uzunligi: {qba_len}")

        mtp_auth = inner[8 : 8 + qba_len]

        u32, dc32 = struct.unpack_from(">ii", mtp_auth, 0)
        if u32 == -1 and dc32 == -1:
            # kWideIdsTag (64-bit user_id + 32-bit main_dc_id)
            user_id = struct.unpack_from(">Q", mtp_auth, 8)[0]
            main_dc_id = struct.unpack_from(">i", mtp_auth, 16)[0]
            pos = 20
        else:
            user_id = u32
            main_dc_id = dc32
            pos = 8

        key_count = struct.unpack_from(">i", mtp_auth, pos)[0]
        pos += 4

        if key_count < 0 or key_count > 32 or pos + key_count * 260 > len(mtp_auth):
            raise ValueError(f"Noto'g'ri DC kalitlari soni: {key_count}")

        dc_keys: Dict[int, bytes] = {}
        for _ in range(key_count):
            dc_id = struct.unpack_from(">i", mtp_auth, pos)[0]
            pos += 4
            k_data = mtp_auth[pos : pos + 256]
            pos += 256
            dc_keys[dc_id] = k_data

        return MtpSessionInfo(user_id=user_id, main_dc_id=main_dc_id, dc_keys=dc_keys)

    @classmethod
    def extract_all_dc_keys(cls, session_s_raw: bytes, local_key: bytes) -> Dict[int, bytes]:
        """
        Extracts all MTProto AuthKeys indexed by DC ID.
        Telegram typically stores keys for DC 1, 2, 4, 5.
        """
        info = cls.extract_session_info(session_s_raw, local_key)
        return info.dc_keys

    @classmethod
    def get_dc_server_info(cls, dc_id: int) -> Tuple[str, int]:
        """
        Returns (ip, port) for a given DC ID. Defaults to DC 2 if unknown.
        """
        return cls.DC_SERVERS.get(dc_id, ("149.154.167.51", 443))
