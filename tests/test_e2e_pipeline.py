"""
End-to-End Pipeline & Integration Tests for Telegram Security Toolkit.
Tests the full lifecycle:
1. Passcode cracking (KD2 Argon2id) & artifact saving
2. Telethon .session extraction & SQLite schema verification
3. Pure-Python Session -> TData conversion (zero Qt / opentele dependency)
4. Multi-account session merging (up to 16 accounts)
5. 100% Offline Digital Forensic Audit & JSON reporting
6. In-place passcode unlocker & restorer
All tests use 100% synthetic, realistic mock fixtures (zero personal data).
"""

import os
import sys
import json
import shutil
import asyncio
import sqlite3
import tempfile
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
from tests.synthetic_fixtures import (
    create_synthetic_session,
    create_synthetic_tdata,
    create_synthetic_zip_backup,
)


class TestE2EPipeline(unittest.TestCase):

    def setUp(self):
        self.test_dir = Path(tempfile.mkdtemp(prefix="tlgr_test_e2e_"))

    def tearDown(self):
        if self.test_dir.exists():
            shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_cracker_save_artifacts_false(self):
        """Regression test: ensures KD2Cracker.crack(..., save_artifacts=False) does not raise TypeError."""
        synth_zip = self.test_dir / "cracker_test.zip"
        create_synthetic_zip_backup(synth_zip, passcode="1234")

        cracker = KD2Cracker.from_source(synth_zip)
        no_art_dir = self.test_dir / "no_artifacts"
        res = cracker.crack(["1233", "1234"], output_dir=no_art_dir, save_artifacts=False)
        self.assertIsNotNone(res)
        self.assertEqual(res[0], "1234")
        self.assertFalse((no_art_dir / "found_passcode.txt").exists())

    def test_full_e2e_recovery_and_native_tdata_roundtrip(self):
        """
        Tests the complete pipeline:
        Crack KD2 passcode -> Extract Telethon session -> Verify SQLite database ->
        Convert to clean native TData -> Re-extract session without passcode!
        """
        synth_zip = self.test_dir / "roundtrip_source.zip"
        expected_lk, expected_ak, _ = create_synthetic_zip_backup(
            synth_zip,
            passcode="1234",
            user_id=100000001,
            main_dc_id=2,
            dc_ids=[1, 2, 4, 5],
        )

        # 1. Crack known passcode in targeted range (1230 - 1236)
        cracker = KD2Cracker.from_source(synth_zip)
        test_candidates = [f"{i:04d}" for i in range(1230, 1237)]

        result = cracker.crack(test_candidates, output_dir=self.test_dir)
        self.assertIsNotNone(result)

        pwd, local_key = result
        self.assertEqual(pwd, "1234")
        self.assertEqual(local_key, expected_lk)

        saved_pwd = (self.test_dir / "found_passcode.txt").read_text(encoding="utf-8").strip()
        self.assertEqual(saved_pwd, "1234")

        # 2. Extract Telethon .session using cracked passcode
        out_session = self.test_dir / "e2e_output.session"
        extracted_path = extract_session_from_backup(
            source=synth_zip,
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
        self.assertEqual(self_row[0], 100000001)
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
        s1 = create_synthetic_session(self.test_dir / "acc1.session", user_id=100000001)
        s2 = create_synthetic_session(self.test_dir / "acc2.session", user_id=200000002)

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
        self.assertEqual(loaded_uids, {100000001, 200000002})

    def test_forensic_analyzer_offline_audit(self):
        """Tests offline forensic analyzer on encrypted ZIP, unencrypted tdata, and .session."""
        synth_zip = self.test_dir / "audit_source.zip"
        create_synthetic_zip_backup(
            synth_zip,
            passcode="1234",
            user_id=100000001,
            dc_ids=[1, 2, 4, 5],
        )

        json_path = self.test_dir / "audit_report.json"
        rep = analyze_source(synth_zip, passcode="1234", output_json=json_path, quiet=True)
        self.assertTrue(json_path.exists())
        loaded_json = json.loads(json_path.read_text(encoding="utf-8"))
        self.assertEqual(loaded_json["encryption"]["kdf_name"], "KD2 Argon2id")
        self.assertTrue(loaded_json["encryption"]["unlocked"])
        self.assertEqual(len(loaded_json["accounts"]), 1)
        self.assertEqual(loaded_json["accounts"][0]["user_id"], 100000001)
        self.assertEqual(loaded_json["accounts"][0]["dcs"], [1, 2, 4, 5])

        # Also test forensic audit on a .session file
        sess_file = extract_session_from_backup(
            synth_zip, passcode="1234", output_session_path=self.test_dir / "audit_test.session"
        )
        sess_rep = analyze_source(sess_file, quiet=True)
        self.assertEqual(sess_rep["source_type"], "telethon_session")
        self.assertEqual(sess_rep["session_info"]["user_id"], 100000001)
        self.assertEqual(sess_rep["session_info"]["dc_list"], [1, 2, 4, 5])

    def test_inplace_unlock_and_restore(self):
        """
        Tests unlock_and_restore_tdata on a locked synthetic backup,
        verifying that in-place passcode removal preserves all 4 DC keys [1, 2, 4, 5],
        offline profile, inner cache files, and loads natively in OpenTele TDesktop!
        """
        from opentele.td import TDesktop

        synth_zip = self.test_dir / "restore_source.zip"
        create_synthetic_zip_backup(
            synth_zip,
            passcode="1234",
            user_id=100000001,
            username="synth_restore_user",
            dc_ids=[1, 2, 4, 5],
        )

        target_dir = self.test_dir / "restored_tdata"
        res = unlock_and_restore_tdata(
            source=synth_zip,
            target_tdata=target_dir,
            passcode="1234",
            create_backup=False,
        )
        self.assertTrue(res["was_locked"])
        self.assertIn("D877F783D5D3EF8C", res["accounts"])
        acc_meta = res["accounts"]["D877F783D5D3EF8C"]
        self.assertEqual(acc_meta["user_id"], 100000001)
        self.assertEqual(acc_meta["dcs"], [1, 2, 4, 5])
        self.assertEqual(acc_meta["profile"]["username"], "synth_restore_user")

        td = TDesktop(str(target_dir))
        self.assertTrue(td.isLoaded())
        self.assertEqual(td.mainAccount.UserId, 100000001)
        self.assertEqual(int(td.mainAccount.MainDcId), 2)
        loaded_dcs = sorted([int(k.dcId) for k in td.mainAccount._Account__mtpKeys])
        self.assertEqual(loaded_dcs, [1, 2, 4, 5])


if __name__ == "__main__":
    unittest.main()
