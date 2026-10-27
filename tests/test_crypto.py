"""
Unit tests for core.crypto
"""

import os
import sys
import unittest
from pathlib import Path

# Add toolkit root to sys.path
TOOLKIT_ROOT = Path(__file__).resolve().parent.parent
if str(TOOLKIT_ROOT) not in sys.path:
    sys.path.insert(0, str(TOOLKIT_ROOT))

from core.crypto import (
    prepare_aes_oldmtp,
    derive_kd2_wrap_key,
    decrypt_aes_ige,
    encrypt_aes_ige,
    verify_kd2_candidate,
)


class TestCrypto(unittest.TestCase):

    def test_aes_ige_roundtrip(self):
        key = os.urandom(32)
        iv = os.urandom(32)
        # Plaintext MUST be a multiple of 16 bytes for AES-IGE
        plaintext = b"Telegram_Security_Toolkit_Test!!" * 4  # 32 * 4 = 128 bytes (multiple of 16)

        ciphertext = encrypt_aes_ige(plaintext, key, iv)
        self.assertNotEqual(ciphertext, plaintext)

        decrypted = decrypt_aes_ige(ciphertext, key, iv)
        self.assertEqual(decrypted, plaintext)

    def test_prepare_aes_oldmtp(self):
        auth_key = os.urandom(256)
        msg_key = os.urandom(16)

        aes_key, aes_iv = prepare_aes_oldmtp(auth_key, msg_key)
        self.assertEqual(len(aes_key), 32)
        self.assertEqual(len(aes_iv), 32)

    def test_derive_kd2_wrap_key(self):
        salt = os.urandom(32)
        # Using light parameters for rapid unit testing
        wrap_key = derive_kd2_wrap_key(
            passcode="1234",
            salt=salt,
            time_cost=1,
            memory_cost=1024,
            threads=1,
            hash_len=256,
        )
        self.assertEqual(len(wrap_key), 256)


if __name__ == "__main__":
    unittest.main()
