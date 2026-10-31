"""
Telegram Multi-DC AuthKey Extractor & Native TData Serializer
Decrypts Telegram Desktop session (.s) and companion maps files, extracts MTProto AuthKeys,
User ID, Main DC ID, offline user profiles, and serializes native TDesktop structures in pure Python.
"""

import hashlib
import struct
from dataclasses import dataclass
from typing import Dict, List, Tuple, Optional, Any
from .crypto import prepare_aes_oldmtp, decrypt_aes_ige, encrypt_local_block, decrypt_local_block
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
    Also provides pure-Python serialization for .s and maps files.
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

    LSK_NAMES: Dict[int, str] = {
        0: "lskUserMap",
        1: "lskDraft",
        2: "lskDraftPosition",
        3: "lskLegacyImages",
        4: "lskLocations",
        5: "lskLegacyStickerImages",
        6: "lskLegacyAudios",
        7: "lskRecentStickersOld",
        8: "lskBackgroundOldOld",
        9: "lskUserSettings",
        10: "lskRecentHashtagsAndBots",
        11: "lskStickersOld",
        12: "lskSavedPeersOld",
        13: "lskReportSpamStatusesOld",
        14: "lskSavedGifsOld",
        15: "lskSavedGifs",
        16: "lskStickersKeys",
        17: "lskTrustedBots",
        18: "lskFavedStickers",
        19: "lskExportSettings",
        20: "lskBackgroundOld",
        21: "lskSelfSerialized",
        22: "lskMasksKeys",
        23: "lskCustomEmojiKeys",
        24: "lskSearchSuggestions",
        25: "lskWebviewTokens",
        26: "lskRoundPlaceholder",
        27: "lskStaticMap",
    }

    @staticmethod
    def compute_auth_key_id(auth_key: bytes) -> int:
        """
        Computes the official 64-bit MTProto auth_key_id:
        Lower 64 bits (last 8 bytes) of SHA-1(auth_key) as unsigned 64-bit little-endian integer.
        """
        if len(auth_key) < 256:
            raise ValueError(f"AuthKey 256 bayt bo'lishi shart (berildi: {len(auth_key)} bayt)")
        sha1_digest = hashlib.sha1(auth_key[:256]).digest()
        return int.from_bytes(sha1_digest[-8:], "little", signed=False)

    @classmethod
    def compute_auth_key_fingerprint(cls, auth_key: bytes) -> Dict[str, Any]:
        """Returns auth_key_id (int and hex) and SHA-256 fingerprint for forensic reporting."""
        key_id = cls.compute_auth_key_id(auth_key)
        return {
            "auth_key_id": key_id,
            "auth_key_id_hex": f"0x{key_id:016x}",
            "sha256": hashlib.sha256(auth_key[:256]).hexdigest(),
        }

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
    def inspect_maps_blocks(cls, maps_raw: bytes, local_key: bytes) -> Dict[str, Any]:
        """
        Decrypts <account>/maps and walks the entire TLV stream across all lskType blocks (0..27).
        Returns block inventory, draft counts, draft peer IDs, and the raw lskSelfSerialized buffer
        regardless of where lskSelfSerialized is located in the stream.
        """
        result: Dict[str, Any] = {
            "decrypted": False,
            "blocks": [],
            "draft_count": 0,
            "draft_peer_ids": [],
            "self_serialized": None,
        }
        try:
            mp = TDataParser.read_tdf(maps_raw)
            pos = 0
            for _ in range(2):
                if pos + 4 > len(mp):
                    return result
                ln = struct.unpack_from(">I", mp, pos)[0]
                pos += 4
                if ln != 0xFFFFFFFF:
                    pos += ln
            if pos + 4 > len(mp):
                return result
            map_enc_len = struct.unpack_from(">I", mp, pos)[0]
            pos += 4
            if map_enc_len == 0xFFFFFFFF or pos + map_enc_len > len(mp):
                return result

            map_enc = mp[pos : pos + map_enc_len]
            stream = decrypt_local_block(map_enc, local_key[:256])
            if not stream or len(stream) < 4:
                return result

            result["decrypted"] = True
            s_pos = 0
            single_u64_types = {4, 7, 8, 9, 10, 11, 12, 13, 14, 15, 17, 18, 19, 24, 26}

            while s_pos + 4 <= len(stream):
                kt = struct.unpack_from(">I", stream, s_pos)[0]
                s_pos += 4
                kt_name = cls.LSK_NAMES.get(kt, f"lskUnknown_{kt}")

                if kt == cls.LSK_SELF_SERIALIZED:
                    if s_pos + 4 > len(stream):
                        break
                    slen = struct.unpack_from(">I", stream, s_pos)[0]
                    s_pos += 4
                    if slen == 0xFFFFFFFF:
                        result["blocks"].append({"id": kt, "name": kt_name, "size": 0})
                        continue
                    if s_pos + slen > len(stream):
                        break
                    result["self_serialized"] = stream[s_pos : s_pos + slen]
                    result["blocks"].append({"id": kt, "name": kt_name, "size": slen})
                    s_pos += slen

                elif kt == 25:  # lskWebviewTokens (2 QByteArrays: bots, other)
                    start_w = s_pos
                    ok_w = True
                    for _ in range(2):
                        if s_pos + 4 > len(stream):
                            ok_w = False
                            break
                        qlen = struct.unpack_from(">I", stream, s_pos)[0]
                        s_pos += 4
                        if qlen != 0xFFFFFFFF:
                            if s_pos + qlen > len(stream):
                                ok_w = False
                                break
                            s_pos += qlen
                    if not ok_w:
                        break
                    result["blocks"].append({"id": kt, "name": kt_name, "size": s_pos - start_w})

                elif kt in (1, 2):  # lskDraft, lskDraftPosition
                    if s_pos + 4 > len(stream):
                        break
                    count = struct.unpack_from(">I", stream, s_pos)[0]
                    s_pos += 4
                    if count > 10000 or s_pos + count * 16 > len(stream):
                        break
                    peers = []
                    for _ in range(count):
                        _fkey, peer_ser = struct.unpack_from(">QQ", stream, s_pos)
                        s_pos += 16
                        peers.append(peer_ser)
                    if kt == 1:
                        result["draft_count"] += count
                        result["draft_peer_ids"].extend(peers)
                    result["blocks"].append({"id": kt, "name": kt_name, "count": count})

                elif kt in (3, 5, 6):  # lskLegacyImages, lskLegacyStickerImages, lskLegacyAudios
                    if s_pos + 4 > len(stream):
                        break
                    count = struct.unpack_from(">I", stream, s_pos)[0]
                    s_pos += 4
                    if count > 10000 or s_pos + count * 28 > len(stream):
                        break
                    s_pos += count * 28
                    result["blocks"].append({"id": kt, "name": kt_name, "count": count})

                elif kt in single_u64_types:
                    if s_pos + 8 > len(stream):
                        break
                    s_pos += 8
                    result["blocks"].append({"id": kt, "name": kt_name, "size": 8})

                elif kt == 20:  # lskBackgroundOld (2 * uint64)
                    if s_pos + 16 > len(stream):
                        break
                    s_pos += 16
                    result["blocks"].append({"id": kt, "name": kt_name, "size": 16})

                elif kt == 16:  # lskStickersKeys (4 * uint64)
                    if s_pos + 32 > len(stream):
                        break
                    s_pos += 32
                    result["blocks"].append({"id": kt, "name": kt_name, "size": 32})

                elif kt in (22, 23):  # lskMasksKeys, lskCustomEmojiKeys (3 * uint64)
                    if s_pos + 24 > len(stream):
                        break
                    s_pos += 24
                    result["blocks"].append({"id": kt, "name": kt_name, "size": 24})

                else:
                    # Unknown future lskType: record it and stop walking
                    result["blocks"].append({"id": kt, "name": kt_name, "size": "unknown"})
                    break

            return result
        except Exception:
            return result

    @staticmethod
    def _parse_self_serialized_buffer(self_ser: bytes) -> Optional[OfflineUserProfile]:
        """
        Parses Data::Serialize::writeSelf buffer into OfflineUserProfile.
        Supports both profiles with UserPhoto (via UserPhoto marker) and profiles without
        a photo (via structured UTF-16BE QString quartet scanning).
        """
        if not self_ser or len(self_ser) < 28:
            return None

        def read_qstr_strict(buf: bytes, offset: int) -> Optional[Tuple[str, int]]:
            if offset + 4 > len(buf):
                return None
            qlen = struct.unpack_from(">I", buf, offset)[0]
            offset += 4
            if qlen == 0xFFFFFFFF:
                return "", offset
            # Valid QString in UTF-16BE must have even byte length and reasonable size
            if qlen % 2 != 0 or qlen > 1024 or offset + qlen > len(buf):
                return None
            try:
                text = buf[offset : offset + qlen].decode("utf-16-be")
            except UnicodeDecodeError:
                return None
            if any(ord(c) < 32 and c not in ("\n", "\r", "\t") for c in text):
                return None
            return text, offset + qlen

        def parse_at_offset(start_off: int) -> Optional[OfflineUserProfile]:
            r1 = read_qstr_strict(self_ser, start_off)
            if r1 is None:
                return None
            first_name, off1 = r1

            r2 = read_qstr_strict(self_ser, off1)
            if r2 is None:
                return None
            last_name, off2 = r2

            r3 = read_qstr_strict(self_ser, off2)
            if r3 is None:
                return None
            phone, off3 = r3

            r4 = read_qstr_strict(self_ser, off3)
            if r4 is None:
                return None
            username, off4 = r4

            # Validate phone & username characteristics to avoid false offsets
            clean_phone = phone.lstrip("+").replace(" ", "")
            if clean_phone and (not clean_phone.isdigit() or len(clean_phone) < 5 or len(clean_phone) > 16):
                return None
            if username and not all(c.isalnum() or c == "_" for c in username):
                return None
            if not (first_name or last_name or clean_phone or username):
                return None

            bio = ""
            if off4 + 32 <= len(self_ser):
                r_bio = read_qstr_strict(self_ser, off4 + 32)
                if r_bio is not None:
                    bio = r_bio[0]

            return OfflineUserProfile(
                first_name=first_name,
                last_name=last_name,
                phone=clean_phone or phone,
                username=username,
                bio=bio,
            )

        # 1. Check standard UserPhoto marker first
        marker = bytes.fromhex("ffffffff000000a0000000a000000000")
        m_idx = self_ser.find(marker)
        if m_idx != -1:
            prof = parse_at_offset(m_idx + len(marker))
            if prof is not None:
                return prof

        # 2. Check standard offsets (e.g. 92 with photo, 28/32/36 without photo) and 4-byte aligned scan
        candidate_offsets = [92, 28, 32, 36, 40, 44, 88, 96]
        for off in range(16, min(len(self_ser) - 16, 160), 4):
            if off not in candidate_offsets:
                candidate_offsets.append(off)

        for off in candidate_offsets:
            prof = parse_at_offset(off)
            if prof is not None and (prof.phone or prof.username or prof.first_name):
                return prof

        return None

    @classmethod
    def extract_offline_profile(cls, maps_raw: bytes, local_key: bytes) -> Optional[OfflineUserProfile]:
        """
        Extracts the user's First Name, Last Name, Phone, Username, and Bio offline
        from <account_folder>/maps (lskSelfSerialized = 21) at any position in the maps stream.
        """
        info = cls.inspect_maps_blocks(maps_raw, local_key)
        self_ser = info.get("self_serialized")
        if not self_ser:
            return None
        return cls._parse_self_serialized_buffer(self_ser)

    @classmethod
    def serialize_mtp_authorization(
        cls,
        user_id: int,
        main_dc_id: int,
        dc_keys: Dict[int, bytes],
        local_key: bytes,
        version: int = 7003003,
    ) -> bytes:
        """
        Serializes an account's MTProto authorization (dbiMtpAuthorization = 75) into a valid
        encrypted Telegram Desktop .s TDF$ binary buffer in 100% pure Python (no PyQt5/opentele).
        """
        if not dc_keys:
            raise ValueError("Kamida bitta DC kaliti bo'lishi shart")

        # kWideIdsTag (-1, -1) + 64-bit UserId + 32-bit MainDcId
        mtp_auth = struct.pack(">iiQi", -1, -1, int(user_id), int(main_dc_id))

        # Write active mtpKeys
        sorted_keys = sorted((int(dc), k[:256]) for dc, k in dc_keys.items() if len(k) >= 256)
        mtp_auth += struct.pack(">i", len(sorted_keys))
        for dc_id, k_bytes in sorted_keys:
            mtp_auth += struct.pack(">i", dc_id) + k_bytes

        # Write mtpKeysToDestroy (0 keys)
        mtp_auth += struct.pack(">i", 0)

        # Wrap in dbiMtpAuthorization (75) + QByteArray(mtp_auth)
        inner = struct.pack(">iI", cls.DBI_MTP_AUTHORIZATION, len(mtp_auth)) + mtp_auth
        enc_mtp = encrypt_local_block(inner, local_key[:256])
        payload = struct.pack(">I", len(enc_mtp)) + enc_mtp
        return TDataParser.write_tdf(payload, version=version)

    @classmethod
    def create_minimal_maps_tdf(
        cls,
        local_key: bytes,
        version: int = 7003003,
    ) -> bytes:
        """
        Creates a clean, valid <account_folder>/maps TDF$ file in 100% pure Python.
        Compatible with both Telegram Desktop and OpenTele TDesktop.
        """
        # Write lskUserSettings (9) with a valid default settings FileKey
        map_inner = struct.pack(">IQ", 9, 1851671142505648812)
        enc_map = encrypt_local_block(map_inner, local_key[:256])

        # 2 empty QByteArrays (legacySalt, legacyKeyEncrypted) + QByteArray(enc_map)
        payload = struct.pack(">III", 0xFFFFFFFF, 0xFFFFFFFF, len(enc_map)) + enc_map
        return TDataParser.write_tdf(payload, version=version)

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
