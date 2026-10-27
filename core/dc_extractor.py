"""
Telegram Multi-DC AuthKey Extractor
Decrypts Telegram Desktop session (.s) files and extracts MTProto AuthKeys for each Data Center (DC).
"""

import struct
from typing import Dict, Tuple, Optional
from .crypto import prepare_aes_oldmtp, decrypt_aes_ige
from .tdata_parser import TDataParser


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

    @staticmethod
    def decrypt_session_data(session_s_raw: bytes, local_key: bytes) -> bytes:
        """
        Decrypts the raw .s session file using the 256-byte master LocalKey.
        Returns the decrypted inner serialized stream.
        """
        payload = TDataParser.read_tdf(session_s_raw)

        enc_len = struct.unpack_from(">I", payload, 0)[0]
        enc_data = payload[4 : 4 + enc_len]
        key128 = enc_data[:16]
        cipher = enc_data[16:]

        cand_key = local_key[:256]
        aes_k, aes_iv = prepare_aes_oldmtp(cand_key, key128)
        decrypted = decrypt_aes_ige(cipher, aes_k, aes_iv)

        size = struct.unpack_from("<I", decrypted, 0)[0]
        return decrypted[4 : 4 + size]

    @classmethod
    def extract_all_dc_keys(cls, session_s_raw: bytes, local_key: bytes) -> Dict[int, bytes]:
        """
        Extracts all MTProto AuthKeys indexed by DC ID.
        Telegram typically stores keys for DC 1, 2, 4, 5.
        """
        inner = cls.decrypt_session_data(session_s_raw, local_key)

        qba_len = struct.unpack_from(">I", inner, 4)[0]
        mtp_auth = inner[8 : 8 + qba_len]

        pos = 20
        key_count = struct.unpack_from(">i", mtp_auth, pos)[0]
        pos += 4

        dc_keys: Dict[int, bytes] = {}
        for _ in range(key_count):
            dc_id = struct.unpack_from(">i", mtp_auth, pos)[0]
            pos += 4
            k_data = mtp_auth[pos : pos + 256]
            pos += 256
            dc_keys[dc_id] = k_data

        return dc_keys

    @classmethod
    def get_dc_server_info(cls, dc_id: int) -> Tuple[str, int]:
        """
        Returns (ip, port) for a given DC ID. Defaults to DC 2 if unknown.
        """
        return cls.DC_SERVERS.get(dc_id, ("149.154.167.51", 443))
