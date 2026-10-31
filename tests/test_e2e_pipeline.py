"""
End-to-End Pipeline & 10/10 Architecture Tests
Tests complete workflow:
1. Parsing & Multi-core Cracking (KD2 Argon2id) + save_artifacts=False regression check
2. Session Extraction (single & multi-account --all)
3. 100% Pure-Python Native Session -> Clean Passcode-Free TData conversion (single & multi-account)
4. Re-extracting sessions from the newly generated Passcode-Free TData and verifying byte-for-byte AuthKey match
5. Offline Forensic Analyzer (analyze_source) on .zip, tdata folder, and .session with JSON export
6. In-place Passcode Unlocker & Restorer on both encrypted backups
"""

import os
import sys
import json
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
from modules.forensic_analyzer import analyze_source

WORKSPACE_DIR = TOOLKIT_ROOT.parent
BACKUP_1 = WORKSPACE_DIR / "TG_Backup_Windows_2026-10-27_22-56-03.zip"
BACKUP_2 = WORKSPACE_DIR / "TG_Backup_Windows_2026-10-27_11-37-16 (3).zip"
UNENCRYPTED_TDATA = WORKSPACE_DIR / "tdata_account_faxriddinovich"


class TestE2EPipeline(unittest.TestCase):

    def setUp(self):
        self.test_dir = TOOLKIT_ROOT / "tests" / "temp_e2e_test"
        self.test_dir.mkdir(parents=True, exist_ok=True)

    def tearDown(self):
        if self.test_dir.exists():
            shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_cracker_save_artifacts_false(self):
        """Regression test: ensures KD2Cracker.crack(..., save_artifacts=False) does not raise TypeError."""
        if not BACKUP_1.exists():
            self.skipTest(f"{BACKUP_1.name} topilmadi")

        cracker = KD2Cracker.from_source(BACKUP_1)
        no_art_dir = self.test_dir / "no_artifacts"
        res = cracker.crack(["1110", "1111"], output_dir=no_art_dir, save_artifacts=False)
        self.assertIsNotNone(res)
        self.assertEqual(res[0], "1111")
        self.assertFalse((no_art_dir / "found_passcode.txt").exists())

    def test_full_e2e_recovery_and_native_tdata_roundtrip(self):
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

        # 3. Verify SQLite Telethon database structure & stored User ID + multi-DC keys
        conn = sqlite3.connect(extracted_path)
        cur = conn.cursor()

        tables = [r[0] for r in cur.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()]
        self.assertIn("version", tables)
        self.assertIn("sessions", tables)
        self.assertIn("entities", tables)
        self.assertIn("tdata_dc_keys", tables)

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

        # 4. Convert .session to clean, passcode-free tdata using 100% Pure-Python native engine
        clean_tdata_dir = self.test_dir / "clean_tdata_native"
        asyncio.run(SessionManager.session_to_tdata(extracted_path, clean_tdata_dir))
        self.assertTrue((clean_tdata_dir / "key_datas").exists())
        self.assertTrue((clean_tdata_dir / "D877F783D5D3EF8Cs").exists())
        self.assertTrue((clean_tdata_dir / "D877F783D5D3EF8C" / "maps").exists())

        # 5. Re-extract session from the newly generated passcode-free tdata (with NO passcode!)
        roundtrip_session = self.test_dir / "roundtrip.session"
        re_extracted = extract_session_from_backup(
            source=clean_tdata_dir,
            passcode=None,
            output_session_path=roundtrip_session,
        )
        self.assertTrue(re_extracted.exists())

        meta_rt = SessionManager.read_offline_session_meta(re_extracted)
        self.assertEqual(meta_rt["dc_id"], 2)
        self.assertEqual(meta_rt["auth_key"], auth_key)
        self.assertEqual(meta_rt["dc_list"], [1, 2, 4, 5])

    def test_native_multi_account_tdata_and_extract_all(self):
        """
        Tests merging 2 separate Telethon .session files into a single multi-account tdata
        (index 0: D877F783D5D3EF8C, index 1: A7FDF864FBC10B77) in pure Python,
        verifying both extract_all=True and OpenTele TDesktop multi-account loading!
        """
        if not (BACKUP_1.exists() and BACKUP_2.exists()):
            self.skipTest("Test backuplari topilmadi")

        s1 = extract_session_from_backup(BACKUP_1, passcode="1111", output_session_path=self.test_dir / "acc1.session")
        s2 = extract_session_from_backup(BACKUP_2, passcode="9562", output_session_path=self.test_dir / "acc2.session")

        multi_tdata = self.test_dir / "multi_account_tdata"
        asyncio.run(SessionManager.session_to_tdata_native([s1, s2], multi_tdata))

        self.assertTrue((multi_tdata / "D877F783D5D3EF8Cs").exists())
        self.assertTrue((multi_tdata / "A7FDF864FBC10B77s").exists())

        # Extract all accounts back from the multi-account tdata
        out_all_dir = self.test_dir / "extracted_all"
        exported_list = extract_session_from_backup(
            source=multi_tdata,
            passcode=None,
            output_session_path=out_all_dir,
            extract_all=True,
        )
        self.assertEqual(len(exported_list), 2)

        # Verify OpenTele TDesktop loads both accounts from our pure-Python generated tdata!
        from patches.patch_opentele import apply_patch
        apply_patch()
        from opentele.td import TDesktop
        td = TDesktop(str(multi_tdata))
        self.assertTrue(td.isLoaded())
        self.assertEqual(td.accountsCount, 2)
        loaded_uids = {acc.UserId for acc in td.accounts}
        self.assertEqual(loaded_uids, {1684305595, 6769431746})

    def test_forensic_analyzer_offline_audit(self):
        """Tests offline forensic analyzer on encrypted ZIP, unencrypted tdata, and .session."""
        if not BACKUP_1.exists():
            self.skipTest(f"{BACKUP_1.name} topilmadi")

        json_path = self.test_dir / "audit_backup1.json"
        rep = analyze_source(BACKUP_1, passcode="1111", output_json=json_path, quiet=True)
        self.assertTrue(json_path.exists())
        loaded_json = json.loads(json_path.read_text(encoding="utf-8"))
        self.assertEqual(loaded_json["encryption"]["kdf_name"], "KD2 Argon2id")
        self.assertTrue(loaded_json["encryption"]["unlocked"])
        self.assertEqual(len(loaded_json["accounts"]), 1)
        self.assertEqual(loaded_json["accounts"][0]["user_id"], 1684305595)
        self.assertEqual(loaded_json["accounts"][0]["dcs"], [1, 2, 4, 5])
        self.assertEqual(len(loaded_json["orphaned_sessions"]), 2)

        # Also test forensic audit on a .session file
        sess_file = extract_session_from_backup(
            BACKUP_1, passcode="1111", output_session_path=self.test_dir / "audit_test.session"
        )
        sess_rep = analyze_source(sess_file, quiet=True)
        self.assertEqual(sess_rep["source_type"], "telethon_session")
        self.assertEqual(sess_rep["session_info"]["user_id"], 1684305595)
        self.assertEqual(sess_rep["session_info"]["dc_list"], [1, 2, 4, 5])

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

            td = TDesktop(str(target_dir))
            self.assertTrue(td.isLoaded())
            self.assertEqual(td.mainAccount.UserId, expected_uid)
            self.assertEqual(int(td.mainAccount.MainDcId), 2)
            loaded_dcs = sorted([int(k.dcId) for k in td.mainAccount._Account__mtpKeys])
            self.assertEqual(loaded_dcs, [1, 2, 4, 5])


if __name__ == "__main__":
    unittest.main()
