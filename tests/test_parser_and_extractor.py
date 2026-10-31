"""
Integration tests for TDataParser and DCExtractor
Covers KD2 (Argon2id), Standard/Legacy PBKDF2 (unencrypted & passcode),
TDF$ MD5 tamper detection, Zip-Slip defense, .tar.xz loading,
multi-block TLV maps parsing, and MTProto SHA-1 / auth_key_id verification.
"""

import io
import os
import sys
import shutil
import struct
import tarfile
import tempfile
import zipfile
import unittest
from pathlib import Path

TOOLKIT_ROOT = Path(__file__).resolve().parent.parent
if str(TOOLKIT_ROOT) not in sys.path:
    sys.path.insert(0, str(TOOLKIT_ROOT))

from core.tdata_parser import TDataParser
from core.crypto import verify_kd2_candidate, encrypt_local_block
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

        # verify_tdf_integrity should report md5_valid=False without raising
        status = TDataParser.verify_tdf_integrity(bytes(tampered))
        self.assertTrue(status["is_tdf"])
        self.assertFalse(status["md5_valid"])

    def test_zip_slip_path_traversal_defense(self):
        """Ensures safe_extract_zip blocks archives containing '../' path traversal."""
        tmp = Path(tempfile.mkdtemp(prefix="tlgr_zipslip_"))
        try:
            malicious_zip = tmp / "malicious.zip"
            with zipfile.ZipFile(malicious_zip, "w") as zf:
                zf.writestr("../../escaped_evil.txt", b"evil")

            extract_target = tmp / "out"
            with self.assertRaises(ValueError):
                TDataParser.safe_extract_zip(malicious_zip, extract_target)
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    def test_tar_xz_universal_loader(self):
        """Tests loading tdata from a .tar.xz archive via TDataParser.load_from_source."""
        if not UNENCRYPTED_TDATA.exists():
            self.skipTest(f"{UNENCRYPTED_TDATA.name} topilmadi")

        tmp = Path(tempfile.mkdtemp(prefix="tlgr_tarxz_"))
        try:
            tar_xz_path = tmp / "backup_test.tar.xz"
            with tarfile.open(tar_xz_path, "w:xz") as tar:
                tar.add(UNENCRYPTED_TDATA, arcname="tdata")

            kd2, session_files = TDataParser.load_from_source(tar_xz_path)
            self.assertEqual(kd2.kdf_id, 0)
            self.assertGreaterEqual(len(session_files), 1)
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    def test_backup_1_passcode_and_keys(self):
        if not BACKUP_1.exists():
            self.skipTest(f"{BACKUP_1.name} topilmadi")

        kd2, session_files = TDataParser.load_from_zip(BACKUP_1)
        self.assertEqual(kd2.kdf_id, 1)
        self.assertEqual(kd2.memory_cost, 65536)
        self.assertEqual(kd2.time_cost, 8)
        self.assertEqual(len(kd2.salt), 32)

        ok, local_key = verify_kd2_candidate("1111", kd2.salt, kd2.key128, kd2.ciphertext, kdf_id=kd2.kdf_id)
        self.assertTrue(ok)
        self.assertIsNotNone(local_key)
        self.assertGreaterEqual(len(local_key), 256)

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
                    # Verify MTProto auth_key_id calculation
                    fp = DCExtractor.compute_auth_key_fingerprint(info.dc_keys[2])
                    self.assertGreater(fp["auth_key_id"], 0)
                    self.assertTrue(fp["auth_key_id_hex"].startswith("0x"))
            except Exception:
                pass
        self.assertTrue(valid_found)

    def test_backup_2_passcode_and_keys(self):
        if not BACKUP_2.exists():
            self.skipTest(f"{BACKUP_2.name} topilmadi")

        kd2, session_files = TDataParser.load_from_zip(BACKUP_2)
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

        wrong_key = os.urandom(256)
        raw_s = list(session_files.values())[0]
        with self.assertRaises(ValueError):
            DCExtractor.extract_session_info(raw_s, wrong_key)

    def test_unencrypted_pbkdf2_tdata(self):
        if not UNENCRYPTED_TDATA.exists():
            self.skipTest(f"{UNENCRYPTED_TDATA.name} topilmadi")

        kd2, session_files = TDataParser.load_from_dir(UNENCRYPTED_TDATA)
        self.assertEqual(kd2.kdf_id, 0)

        ok, local_key = verify_kd2_candidate("", kd2.salt, kd2.key128, kd2.ciphertext, kdf_id=kd2.kdf_id)
        self.assertTrue(ok)
        self.assertIsNotNone(local_key)

        raw_s = list(session_files.values())[0]
        info = DCExtractor.extract_session_info(raw_s, local_key)
        self.assertEqual(info.user_id, 6769431746)
        self.assertEqual(info.main_dc_id, 2)
        self.assertIn(2, info.dc_keys)

    def test_compute_account_filename_and_16_accounts(self):
        f0, s0 = TDataParser.compute_account_filename(0)
        self.assertEqual(f0, "D877F783D5D3EF8C")
        self.assertEqual(s0, "D877F783D5D3EF8Cs")

        f1, s1 = TDataParser.compute_account_filename(1)
        self.assertEqual(f1, "A7FDF864FBC10B77")
        self.assertEqual(s1, "A7FDF864FBC10B77s")

        f2, s2 = TDataParser.compute_account_filename(2)
        self.assertEqual(f2, "F8806DD0C461824F")
        self.assertEqual(s2, "F8806DD0C461824Fs")

        idx_map = TDataParser.get_account_index_map(16)
        self.assertEqual(len(idx_map), 16)
        self.assertEqual(idx_map["D877F783D5D3EF8C"], 0)
        self.assertEqual(idx_map["A7FDF864FBC10B77"], 1)
        self.assertEqual(idx_map["F8806DD0C461824F"], 2)

    def test_parse_accounts_metadata(self):
        if not BACKUP_1.exists():
            self.skipTest(f"{BACKUP_1.name} topilmadi")

        kd2, _ = TDataParser.load_from_zip(BACKUP_1)
        ok, local_key = verify_kd2_candidate("1111", kd2.salt, kd2.key128, kd2.ciphertext, kdf_id=kd2.kdf_id)
        self.assertTrue(ok)

        with zipfile.ZipFile(BACKUP_1) as zf:
            kd_name = [n for n in zf.namelist() if n.endswith("key_datas")][0]
            kd_raw = zf.read(kd_name)

        meta = TDataParser.parse_accounts_metadata(kd_raw, local_key)
        self.assertIsNotNone(meta)
        self.assertEqual(meta["count"], 1)
        self.assertEqual(meta["indexes"], [0])
        self.assertEqual(meta["active_index"], 0)

    def test_kd2_stub_kdf_id_0(self):
        """
        Tests Telegram Desktop v5.x-v7.x+ key_datas when NO passcode is set,
        which appends a 16-byte 'KD2\\x00' stub with kdf_id=0 at the end of key_datas.
        """
        from core.crypto import derive_pbkdf2_wrap_key

        local_key = os.urandom(256)
        salt = os.urandom(32)
        pass_key = derive_pbkdf2_wrap_key("", salt)
        key_enc = encrypt_local_block(local_key, pass_key)
        info_enc = encrypt_local_block(struct.pack(">iii", 1, 0, 0), local_key)
        kd2_stub = b"KD2\x00" + struct.pack(">III", 2, 0, 0)

        def qba(b: bytes) -> bytes:
            return struct.pack(">I", len(b)) + b

        payload = qba(salt) + qba(key_enc) + qba(info_enc) + qba(kd2_stub)
        raw_tdf = TDataParser.write_tdf(payload, version=7003003)

        kd2 = TDataParser.parse_kd2(raw_tdf)
        self.assertEqual(kd2.kdf_id, 0)
        ok, recovered_lk = verify_kd2_candidate("", kd2.salt, kd2.key128, kd2.ciphertext, kdf_id=kd2.kdf_id)
        self.assertTrue(ok)
        self.assertEqual(recovered_lk, local_key)

    def test_offline_profile_extraction_and_multiblock_maps(self):
        """
        Tests offline user profile extraction (lskSelfSerialized) from <account>/maps
        in both Backup 1 and Backup 2, AND tests a synthetic maps stream where
        lskSelfSerialized is NOT the first block and has NO UserPhoto marker.
        """
        if BACKUP_1.exists():
            kd2_1, _ = TDataParser.load_from_zip(BACKUP_1)
            ok1, lk1 = verify_kd2_candidate("1111", kd2_1.salt, kd2_1.key128, kd2_1.ciphertext)
            self.assertTrue(ok1)
            with zipfile.ZipFile(BACKUP_1) as zf:
                maps_1 = zf.read([n for n in zf.namelist() if n.endswith("D877F783D5D3EF8C/maps")][0])
            prof1 = DCExtractor.extract_offline_profile(maps_1, lk1)
            self.assertIsNotNone(prof1)
            self.assertEqual(prof1.first_name, "Möydinov")
            self.assertEqual(prof1.last_name, "Doston")
            self.assertEqual(prof1.phone, "998913434402")
            self.assertEqual(prof1.username, "Foreveri7")
            self.assertIn("Solo leveling", prof1.bio)

        if BACKUP_2.exists():
            kd2_2, _ = TDataParser.load_from_zip(BACKUP_2)
            ok2, lk2 = verify_kd2_candidate("9562", kd2_2.salt, kd2_2.key128, kd2_2.ciphertext)
            self.assertTrue(ok2)
            with zipfile.ZipFile(BACKUP_2) as zf:
                maps_2 = zf.read([n for n in zf.namelist() if n.endswith("D877F783D5D3EF8C/maps")][0])
            prof2 = DCExtractor.extract_offline_profile(maps_2, lk2)
            self.assertIsNotNone(prof2)
            self.assertEqual(prof2.first_name, "FAXRIDDINOVICH_._")
            self.assertEqual(prof2.phone, "998503027275")
            self.assertEqual(prof2.username, "faxriddinovich2005")
            self.assertTrue(len(prof2.bio) > 5)

        # Synthetic multi-block maps test:
        # Block 1: lskUserSettings (9)
        # Block 2: lskDraft (1) with 2 drafts
        # Block 3: lskSelfSerialized (21) WITHOUT UserPhoto marker (28-byte header)
        synth_key = os.urandom(256)

        def qstr(s: str) -> bytes:
            b = s.encode("utf-16-be")
            return struct.pack(">I", len(b)) + b

        # 28-byte header (peer_id + flags + no photo) + 4 QStrings + 32-byte gap + bio QString
        self_buf = (
            b"\x00" * 28
            + qstr("Alisher")
            + qstr("Navoiy")
            + qstr("998901234567")
            + qstr("navoiy_uz")
            + (b"\x00" * 32)
            + qstr("Buyuk mutafakkir")
        )
        map_stream = (
            struct.pack(">IQ", 9, 123456789)  # lskUserSettings
            + struct.pack(">IIQQQQ", 1, 2, 111, 222, 333, 444)  # lskDraft (2 drafts)
            + struct.pack(">II", 21, len(self_buf)) + self_buf  # lskSelfSerialized at 3rd position!
        )
        enc_map = encrypt_local_block(map_stream, synth_key)
        maps_tdf = TDataParser.write_tdf(struct.pack(">III", 0xFFFFFFFF, 0xFFFFFFFF, len(enc_map)) + enc_map)

        inspected = DCExtractor.inspect_maps_blocks(maps_tdf, synth_key)
        self.assertTrue(inspected["decrypted"])
        self.assertEqual(inspected["draft_count"], 2)
        self.assertEqual(len(inspected["blocks"]), 3)

        synth_prof = DCExtractor.extract_offline_profile(maps_tdf, synth_key)
        self.assertIsNotNone(synth_prof)
        self.assertEqual(synth_prof.first_name, "Alisher")
        self.assertEqual(synth_prof.last_name, "Navoiy")
        self.assertEqual(synth_prof.phone, "998901234567")
        self.assertEqual(synth_prof.username, "navoiy_uz")
        self.assertEqual(synth_prof.bio, "Buyuk mutafakkir")


if __name__ == "__main__":
    unittest.main()
