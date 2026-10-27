"""
End-to-End Pipeline Test
Tests complete workflow: Parsing -> Multi-core Cracking -> Session Extraction -> Schema Verification
"""

import os
import sys
import shutil
import sqlite3
import unittest
from pathlib import Path

TOOLKIT_ROOT = Path(__file__).resolve().parent.parent
if str(TOOLKIT_ROOT) not in sys.path:
    sys.path.insert(0, str(TOOLKIT_ROOT))

from core.tdata_parser import TDataParser
from modules.cracker import KD2Cracker
from modules.session_extractor import extract_session_from_backup

WORKSPACE_DIR = TOOLKIT_ROOT.parent
BACKUP_1 = WORKSPACE_DIR / "TG_Backup_Windows_2026-10-27_22-56-03.zip"


class TestE2EPipeline(unittest.TestCase):

    def setUp(self):
        self.test_dir = TOOLKIT_ROOT / "tests" / "temp_e2e_test"
        self.test_dir.mkdir(parents=True, exist_ok=True)

    def tearDown(self):
        if self.test_dir.exists():
            shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_full_e2e_recovery_pipeline(self):
        if not BACKUP_1.exists():
            self.skipTest(f"{BACKUP_1.name} topilmadi")

        # 1. Crack known passcode in targeted range (1108 - 1114)
        cracker = KD2Cracker.from_source(BACKUP_1)
        test_candidates = [f"{i:04d}" for i in range(1108, 1115)]

        result = cracker.crack(test_candidates, output_dir=self.test_dir)
        self.assertIsNotNone(result)

        pwd, local_key = result
        self.assertEqual(pwd, "1111")
        self.assertGreaterEqual(len(local_key), 256)

        # Check saved files
        saved_pwd = (self.test_dir / "found_passcode.txt").read_text(encoding="utf-8").strip()
        self.assertEqual(saved_pwd, "1111")

        saved_key = (self.test_dir / "found_local_key.bin").read_bytes()
        self.assertGreaterEqual(len(saved_key), 256)

        # 2. Extract Telethon .session using cracked passcode
        out_session = self.test_dir / "e2e_output.session"
        extracted_path = extract_session_from_backup(
            source=BACKUP_1,
            passcode=saved_pwd,
            target_dc=2,
            output_session_path=out_session,
        )

        self.assertTrue(extracted_path.exists())
        self.assertGreater(extracted_path.stat().st_size, 1024)

        # 3. Verify SQLite Telethon database structure
        conn = sqlite3.connect(extracted_path)
        cur = conn.cursor()

        # Check tables
        tables = [r[0] for r in cur.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()]
        self.assertIn("version", tables)
        self.assertIn("sessions", tables)
        self.assertIn("entities", tables)

        # Check session entry
        cur.execute("SELECT dc_id, server_address, port, auth_key FROM sessions")
        row = cur.fetchone()
        self.assertIsNotNone(row)
        dc_id, server_ip, port, auth_key = row

        self.assertEqual(dc_id, 2)
        self.assertEqual(server_ip, "149.154.167.51")
        self.assertEqual(port, 443)
        self.assertEqual(len(auth_key), 256)

        conn.close()


if __name__ == "__main__":
    unittest.main()
