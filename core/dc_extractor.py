"""
Telegram Multi-DC AuthKey Extractor
Decrypts Telegram Desktop session (.s) files and extracts MTProto AuthKeys, User ID, and Main DC ID.
"""

import hashlib
import struct
from dataclasses import dataclass
from typing import Dict, Tuple, Optional
from .crypto import prepare_aes_oldmtp, decrypt_aes_ige, decrypt_local_block
from .tdata_parser import TDataParser


@dataclass
class OfflineUserProfile:
    """Holds user profile metadata extracted offline from Telegram Desktop's <account>/maps (lskSelfSerialized)."""
    first_name: str = ""
    last_name: str = ""
    phone: str = ""
    username: str = ""
    bio: str = ""

    @property
    def full_name(self) -> str:
        return f"{self.first_name} {self.last_name}".strip()


@dataclass
class MtpSessionInfo:
    """Holds parsed MTProto authorization metadata from a Telegram Desktop .s file."""
    user_id: int
    main_dc_id: int
    dc_keys: Dict[int, bytes]
    profile: Optional[OfflineUserProfile] = None


class DCExtractor:
    """
    Decrypts session (.s) files and companion maps files using the recovered LocalKey,
    extracting Multi-DC AuthKeys, User ID, Main DC ID, and offline user profile metadata.
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
    LSK_SELF_SERIALIZED = 21    # 0x15

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
        full_len = len(decrypted)
        if 4 <= size <= full_len and size > full_len - 16:
            return decrypted[4:size]
        elif 0 <= size <= full_len - 4:
            return decrypted[4 : 4 + size]
        raise ValueError(f"Ichki blok hajmi noto'g'ri: {size} > {full_len - 4}")

    @classmethod
    def extract_offline_profile(cls, maps_raw: bytes, local_key: bytes) -> Optional[OfflineUserProfile]:
        """
        Extracts the user's First Name, Last Name, Phone, Username, and Bio offline
        from <account_folder>/maps (lskSelfSerialized = 21).
        """
        try:
            mp = TDataParser.read_tdf(maps_raw)
            pos = 0
            # maps has 3 QByteArrays: legacySalt, legacyKeyEncrypted, mapEncrypted
            for _ in range(2):
                ln = struct.unpack_from(">I", mp, pos)[0]
                pos += 4
                if ln != 0xFFFFFFFF:
                    pos += ln
            map_enc_len = struct.unpack_from(">I", mp, pos)[0]
            pos += 4
            if map_enc_len == 0xFFFFFFFF or pos + map_enc_len > len(mp):
                return None

            map_enc = mp[pos : pos + map_enc_len]
            stream = decrypt_local_block(map_enc, local_key[:256])
            if not stream or len(stream) < 12:
                return None

            kt = struct.unpack_from(">I", stream, 0)[0]
            if kt != cls.LSK_SELF_SERIALIZED:
                return None

            slen = struct.unpack_from(">I", stream, 4)[0]
            if slen == 0xFFFFFFFF or slen < 96 or 8 + slen > len(stream):
                return None

            self_ser = stream[8 : 8 + slen]

            def read_qstr(buf: bytes, offset: int) -> Tuple[str, int]:
                if offset + 4 > len(buf):
                    return "", offset
                qlen = struct.unpack_from(">I", buf, offset)[0]
                offset += 4
                if qlen == 0xFFFFFFFF or offset + qlen > len(buf):
                    return "", offset
                text = buf[offset : offset + qlen].decode("utf-16-be", errors="replace")
                return text, offset + qlen

            marker = bytes.fromhex("ffffffff000000a0000000a000000000")
            m_idx = self_ser.find(marker)
            p_off = (m_idx + len(marker)) if m_idx != -1 else 92

            first_name, p_off = read_qstr(self_ser, p_off)
            last_name, p_off = read_qstr(self_ser, p_off)
            phone, p_off = read_qstr(self_ser, p_off)
            username, p_off = read_qstr(self_ser, p_off)
            bio = ""
            if p_off + 32 <= len(self_ser):
                bio, _ = read_qstr(self_ser, p_off + 32)

            if not (first_name or last_name or phone or username):
                return None

            return OfflineUserProfile(
                first_name=first_name,
                last_name=last_name,
                phone=phone,
                username=username,
                bio=bio,
            )
        except Exception:
            return None

    @classmethod
    def extract_session_info(
        cls,
        session_s_raw: bytes,
        local_key: bytes,
        maps_raw: Optional[bytes] = None,
    ) -> MtpSessionInfo:
        """
        Extracts User ID, Main DC ID, all MTProto AuthKeys, and optional offline user profile.
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

        profile = cls.extract_offline_profile(maps_raw, local_key) if maps_raw else None
        return MtpSessionInfo(
            user_id=user_id,
            main_dc_id=main_dc_id,
            dc_keys=dc_keys,
            profile=profile,
        )

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
