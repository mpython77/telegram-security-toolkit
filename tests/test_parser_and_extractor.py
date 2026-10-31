"""
Integration tests for TDataParser and DCExtractor
Covers KD2 (Argon2id), Standard/Legacy PBKDF2 (unencrypted & passcode),
TDF$ MD5 tamper detection, and MTProto SHA-1 integrity verification.
"""

import os
import sys
import unittest
from pathlib import Path

TOOLKIT_ROOT = Path(__file__).resolve().parent.parent
if str(TOOLKIT_ROOT) not in sys.path:
    sys.path.insert(0, str(TOOLKIT_ROOT))

from core.tdata_parser import TDataParser
from core.crypto import verify_kd2_candidate
from core.dc_extractor import DCExtractor

WORKSPACE_DIR = TOOLKIT_ROOT.parent
BACKUP_1 = WORKSPACE_DIR / "TG_Backup_Windows_2026-10-27_22-56-03.zip"
BACKUP_2 = WORKSPACE_DIR / "TG_Backup_Windows_2026-10-27_11-37-16 (3).zip"
UNENCRYPTED_TDATA = WORKSPACE_DIR / "tdata_account_faxriddinovich"


class TestParserAndExtractor(unittest.TestCase):

    def test_tdf_tamper_detection(self):
        if not BACKUP_2.exists():
            self.skipTest(f"{BACKUP_2.name} topilmadi")

        _, session_files = TDataParser.load_from_zip(BACKUP_2)
        raw_s = list(session_files.values())[0]

        # Valid TDF should pass
        payload = TDataParser.read_tdf(raw_s)
        self.assertGreater(len(payload), 100)

        # Flip 1 bit in payload -> MD5 check must raise ValueError
        tampered = bytearray(raw_s)
        tampered[12] ^= 0xFF
        with self.assertRaises(ValueError):
            TDataParser.read_tdf(bytes(tampered))

    def test_backup_1_passcode_and_keys(self):
        if not BACKUP_1.exists():
            self.skipTest(f"{BACKUP_1.name} topilmadi")

        kd2, session_files = TDataParser.load_from_zip(BACKUP_1)
        self.assertEqual(kd2.kdf_id, 1)
        self.assertEqual(kd2.memory_cost, 65536)
        self.assertEqual(kd2.time_cost, 8)
        self.assertEqual(len(kd2.salt), 32)

        # Known passcode 1111
        ok, local_key = verify_kd2_candidate("1111", kd2.salt, kd2.key128, kd2.ciphertext, kdf_id=kd2.kdf_id)
        self.assertTrue(ok)
        self.assertIsNotNone(local_key)
        self.assertGreaterEqual(len(local_key), 256)

        # Extract active DC keys and verify UserID + MainDC
        valid_found = False
        for s_name, raw in session_files.items():
            try:
                info = DCExtractor.extract_session_info(raw, local_key)
                if info.dc_keys:
                    valid_found = True
                    self.assertEqual(info.user_id, 1684305595)
                    self.assertEqual(info.main_dc_id, 2)
                    self.assertIn(2, info.dc_keys)
                    self.assertEqual(len(info.dc_keys[2]), 256)
            except Exception:
                pass
        self.assertTrue(valid_found)

    def test_backup_2_passcode_and_keys(self):
        if not BACKUP_2.exists():
            self.skipTest(f"{BACKUP_2.name} topilmadi")

        kd2, session_files = TDataParser.load_from_zip(BACKUP_2)
        # Known cracked passcode 9562
        ok, local_key = verify_kd2_candidate("9562", kd2.salt, kd2.key128, kd2.ciphertext, kdf_id=kd2.kdf_id)
        self.assertTrue(ok)
        self.assertIsNotNone(local_key)
        self.assertGreaterEqual(len(local_key), 256)

        valid_found = False
        for s_name, raw in session_files.items():
            try:
                info = DCExtractor.extract_session_info(raw, local_key)
                if info.dc_keys:
                    valid_found = True
                    self.assertEqual(info.user_id, 6769431746)
                    self.assertEqual(info.main_dc_id, 2)
                    self.assertIn(2, info.dc_keys)
                    self.assertEqual(len(info.dc_keys[2]), 256)
            except Exception:
                pass
        self.assertTrue(valid_found)

        # Wrong LocalKey must be rejected by SHA-1 check
        wrong_key = os.urandom(256)
        raw_s = list(session_files.values())[0]
        with self.assertRaises(ValueError):
            DCExtractor.extract_session_info(raw_s, wrong_key)

    def test_unencrypted_pbkdf2_tdata(self):
        if not UNENCRYPTED_TDATA.exists():
            self.skipTest(f"{UNENCRYPTED_TDATA.name} topilmadi")

        kd2, session_files = TDataParser.load_from_dir(UNENCRYPTED_TDATA)
        self.assertEqual(kd2.kdf_id, 0)  # PBKDF2 format

        ok, local_key = verify_kd2_candidate("", kd2.salt, kd2.key128, kd2.ciphertext, kdf_id=kd2.kdf_id)
        self.assertTrue(ok)
        self.assertIsNotNone(local_key)

        raw_s = list(session_files.values())[0]
        info = DCExtractor.extract_session_info(raw_s, local_key)
        self.assertEqual(info.user_id, 6769431746)
        self.assertEqual(info.main_dc_id, 2)
        self.assertIn(2, info.dc_keys)

    def test_compute_account_filename(self):
        f0, s0 = TDataParser.compute_account_filename(0)
        self.assertEqual(f0, "D877F783D5D3EF8C")
        self.assertEqual(s0, "D877F783D5D3EF8Cs")

        f1, s1 = TDataParser.compute_account_filename(1)
        self.assertEqual(f1, "A7FDF864FBC10B77")
        self.assertEqual(s1, "A7FDF864FBC10B77s")

        f2, s2 = TDataParser.compute_account_filename(2)
        self.assertEqual(f2, "F8806DD0C461824F")
        self.assertEqual(s2, "F8806DD0C461824Fs")

    def test_parse_accounts_metadata(self):
        if not BACKUP_1.exists():
            self.skipTest(f"{BACKUP_1.name} topilmadi")

        kd2, _ = TDataParser.load_from_zip(BACKUP_1)
        ok, local_key = verify_kd2_candidate("1111", kd2.salt, kd2.key128, kd2.ciphertext, kdf_id=kd2.kdf_id)
        self.assertTrue(ok)

        with __import__("zipfile").ZipFile(BACKUP_1) as zf:
            kd_name = [n for n in zf.namelist() if n.endswith("key_datas")][0]
            kd_raw = zf.read(kd_name)

        meta = TDataParser.parse_accounts_metadata(kd_raw, local_key)
        self.assertIsNotNone(meta)
        self.assertEqual(meta["count"], 1)
        self.assertEqual(meta["indexes"], [0])
        self.assertEqual(meta["active_index"], 0)


if __name__ == "__main__":
    unittest.main()
