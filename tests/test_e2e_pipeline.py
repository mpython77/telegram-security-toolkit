"""
End-to-End Pipeline Test
Tests complete workflow:
1. Parsing & Multi-core Cracking (KD2 Argon2id)
2. Session Extraction (with UserID stored in SQLite entities id=0)
3. Offline Session -> Clean Passcode-Free TData conversion
4. Re-extracting session from the newly generated Passcode-Free TData and verifying byte-for-byte AuthKey match!
"""

import os
import sys
import shutil
import asyncio
import sqlite3
import unittest
from pathlib import Path

TOOLKIT_ROOT = Path(__file__).resolve().parent.parent
if str(TOOLKIT_ROOT) not in sys.path:
    sys.path.insert(0, str(TOOLKIT_ROOT))

from core.tdata_parser import TDataParser
from core.session_manager import SessionManager
from modules.cracker import KD2Cracker
from modules.session_extractor import extract_session_from_backup
from modules.restorer import unlock_and_restore_tdata

WORKSPACE_DIR = TOOLKIT_ROOT.parent
BACKUP_1 = WORKSPACE_DIR / "TG_Backup_Windows_2026-10-27_22-56-03.zip"
BACKUP_2 = WORKSPACE_DIR / "TG_Backup_Windows_2026-10-27_11-37-16 (3).zip"


class TestE2EPipeline(unittest.TestCase):

    def setUp(self):
        self.test_dir = TOOLKIT_ROOT / "tests" / "temp_e2e_test"
        self.test_dir.mkdir(parents=True, exist_ok=True)

    def tearDown(self):
        if self.test_dir.exists():
            shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_full_e2e_recovery_and_tdata_roundtrip(self):
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

        # 2. Extract Telethon .session using cracked passcode
        out_session = self.test_dir / "e2e_output.session"
        extracted_path = extract_session_from_backup(
            source=BACKUP_1,
            passcode=saved_pwd,
            output_session_path=out_session,
        )

        self.assertTrue(extracted_path.exists())
        self.assertGreater(extracted_path.stat().st_size, 1024)

        # 3. Verify SQLite Telethon database structure & stored User ID
        conn = sqlite3.connect(extracted_path)
        cur = conn.cursor()

        tables = [r[0] for r in cur.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()]
        self.assertIn("version", tables)
        self.assertIn("sessions", tables)
        self.assertIn("entities", tables)

        cur.execute("SELECT dc_id, server_address, port, auth_key FROM sessions")
        row = cur.fetchone()
        self.assertIsNotNone(row)
        dc_id, server_ip, port, auth_key = row

        self.assertEqual(dc_id, 2)
        self.assertEqual(server_ip, "149.154.167.51")
        self.assertEqual(port, 443)
        self.assertEqual(len(auth_key), 256)

        cur.execute("SELECT hash FROM entities WHERE id = 0")
        self_row = cur.fetchone()
        self.assertIsNotNone(self_row)
        self.assertEqual(self_row[0], 1684305595)
        conn.close()

        # 4. Convert .session to clean, passcode-free tdata
        clean_tdata_dir = self.test_dir / "clean_tdata"
        asyncio.run(SessionManager.session_to_tdata(extracted_path, clean_tdata_dir))
        self.assertTrue((clean_tdata_dir / "key_datas").exists())
        self.assertTrue((clean_tdata_dir / "D877F783D5D3EF8Cs").exists())

        # 5. Re-extract session from the newly generated passcode-free tdata (with NO passcode!)
        roundtrip_session = self.test_dir / "roundtrip.session"
        re_extracted = extract_session_from_backup(
            source=clean_tdata_dir,
            passcode=None,
            output_session_path=roundtrip_session,
        )
        self.assertTrue(re_extracted.exists())

        conn2 = sqlite3.connect(re_extracted)
        cur2 = conn2.cursor()
        cur2.execute("SELECT dc_id, auth_key FROM sessions")
        dc2, ak2 = cur2.fetchone()
        conn2.close()

        self.assertEqual(dc2, 2)
        self.assertEqual(ak2, auth_key)

    def test_inplace_unlock_and_restore_both_backups(self):
        """
        Tests unlock_and_restore_tdata on both real encrypted backups (1111 and 9562),
        verifying that in-place passcode removal preserves all 4 DC keys [1, 2, 4, 5],
        offline profile, inner cache files, and loads natively in OpenTele TDesktop!
        """
        from opentele.td import TDesktop

        for idx, (backup_zip, pin, expected_uid, expected_uname) in enumerate(
            [
                (BACKUP_1, "1111", 1684305595, "Foreveri7"),
                (BACKUP_2, "9562", 6769431746, "faxriddinovich2005"),
            ],
            1,
        ):
            if not backup_zip.exists():
                continue

            target_dir = self.test_dir / f"restored_tdata_{idx}"
            res = unlock_and_restore_tdata(
                source=backup_zip,
                target_tdata=target_dir,
                passcode=pin,
                create_backup=False,
            )
            self.assertTrue(res["was_locked"])
            self.assertIn("D877F783D5D3EF8C", res["accounts"])
            acc_meta = res["accounts"]["D877F783D5D3EF8C"]
            self.assertEqual(acc_meta["user_id"], expected_uid)
            self.assertEqual(acc_meta["dcs"], [1, 2, 4, 5])
            self.assertEqual(acc_meta["profile"]["username"], expected_uname)

            # Verify OpenTele TDesktop loads the restored tdata natively with NO passcode!
            td = TDesktop(str(target_dir))
            self.assertTrue(td.isLoaded())
            self.assertEqual(td.mainAccount.UserId, expected_uid)
            self.assertEqual(int(td.mainAccount.MainDcId), 2)
            loaded_dcs = sorted([int(k.dcId) for k in td.mainAccount._Account__mtpKeys])
            self.assertEqual(loaded_dcs, [1, 2, 4, 5])


if __name__ == "__main__":
    unittest.main()
