"""
Integration tests for TDataParser and DCExtractor
"""

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


class TestParserAndExtractor(unittest.TestCase):

    def test_backup_1_passcode_and_keys(self):
        if not BACKUP_1.exists():
            self.skipTest(f"{BACKUP_1.name} topilmadi")

        kd2, session_files = TDataParser.load_from_zip(BACKUP_1)
        self.assertEqual(kd2.memory_cost, 65536)
        self.assertEqual(kd2.time_cost, 8)
        self.assertEqual(len(kd2.salt), 32)

        # Known passcode 1111
        ok, local_key = verify_kd2_candidate("1111", kd2.salt, kd2.key128, kd2.ciphertext)
        self.assertTrue(ok)
        self.assertIsNotNone(local_key)
        self.assertGreaterEqual(len(local_key), 256)
        self.assertEqual(len(local_key[:256]), 256)

        # Extract active DC keys
        valid_found = False
        for s_name, raw in session_files.items():
            try:
                dc_keys = DCExtractor.extract_all_dc_keys(raw, local_key)
                if dc_keys:
                    valid_found = True
                    self.assertIn(2, dc_keys)
                    self.assertEqual(len(dc_keys[2]), 256)
            except Exception:
                pass
        self.assertTrue(valid_found)

    def test_backup_2_passcode_and_keys(self):
        if not BACKUP_2.exists():
            self.skipTest(f"{BACKUP_2.name} topilmadi")

        kd2, session_files = TDataParser.load_from_zip(BACKUP_2)
        # Known cracked passcode 9562
        ok, local_key = verify_kd2_candidate("9562", kd2.salt, kd2.key128, kd2.ciphertext)
        self.assertTrue(ok)
        self.assertIsNotNone(local_key)
        self.assertGreaterEqual(len(local_key), 256)
        self.assertEqual(len(local_key[:256]), 256)

        valid_found = False
        for s_name, raw in session_files.items():
            try:
                dc_keys = DCExtractor.extract_all_dc_keys(raw, local_key)
                if dc_keys:
                    valid_found = True
                    self.assertIn(2, dc_keys)
                    self.assertEqual(len(dc_keys[2]), 256)
            except Exception:
                pass
        self.assertTrue(valid_found)


if __name__ == "__main__":
    unittest.main()
