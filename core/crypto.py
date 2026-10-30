"""
Telegram Cryptography Primitives
- KD2 (Argon2id) Key Derivation Function
- MTProto AES-IGE KDF (prepareAES_oldmtp)
- AES-256-IGE Encryption/Decryption
"""

import hashlib
import struct
from typing import Tuple, Optional
import argon2.low_level
import tgcrypto


def prepare_aes_oldmtp(auth_key: bytes, msg_key: bytes, is_client: bool = False) -> Tuple[bytes, bytes]:
    """
    Derives AES-256 key and IV from 256-byte AuthKey and 16-byte msg_key (key128)
    according to Telegram Desktop's internal MTProto Local Storage specification.
    
    Telegram Desktop uses x = 8 for local storage decryption.
    """
    x = 8 if not is_client else 0
    sha1_a = hashlib.sha1(msg_key[:16] + auth_key[x : x + 32]).digest()
    sha1_b = hashlib.sha1(auth_key[x + 32 : x + 48] + msg_key[:16] + auth_key[x + 48 : x + 64]).digest()
    sha1_c = hashlib.sha1(auth_key[x + 64 : x + 96] + msg_key[:16]).digest()
    sha1_d = hashlib.sha1(msg_key[:16] + auth_key[x + 96 : x + 128]).digest()

    aes_key = sha1_a[:8] + sha1_b[8:20] + sha1_c[4:16]
    aes_iv = sha1_a[8:20] + sha1_b[:8] + sha1_c[16:20] + sha1_d[:8]
    return aes_key, aes_iv


def derive_kd2_wrap_key(
    passcode: str,
    salt: bytes,
    time_cost: int = 8,
    memory_cost: int = 65536,
    threads: int = 1,
    hash_len: int = 256,
) -> bytes:
    """
    Derives the 256-byte wrap_key using Argon2id with Telegram's KD2 parameters.
    Default parameters in Telegram Desktop:
    - time_cost: 8 iterations
    - memory_cost: 65536 KiB (64 MiB)
    - parallelism: 1 thread
    - hash_len: 256 bytes
    """
    return argon2.low_level.hash_secret_raw(
        secret=passcode.encode("utf-8"),
        salt=salt,
        time_cost=time_cost,
        memory_cost=memory_cost,
        parallelism=threads,
        hash_len=hash_len,
        type=argon2.low_level.Type.ID,
    )


def derive_pbkdf2_wrap_key(
    passcode: str,
    salt: bytes,
    legacy: bool = False,
) -> bytes:
    """
    Derives the 256-byte wrap_key using Telegram Desktop's standard/legacy PBKDF2-HMAC-SHA512.
    Used when no local passcode is set (iterations=1) or in PBKDF2 passcode format (iterations=100000).
    """
    pwd_bytes = passcode.encode("utf-8")
    iterations = 1 if len(pwd_bytes) == 0 else 100000
    if legacy:
        return hashlib.pbkdf2_hmac("sha512", pwd_bytes, salt, iterations, 256)
    hash_key = hashlib.sha512(salt + pwd_bytes + salt).digest()
    return hashlib.pbkdf2_hmac("sha512", hash_key, salt, iterations, 256)


def decrypt_aes_ige(ciphertext: bytes, key: bytes, iv: bytes) -> bytes:
    """
    Decrypts ciphertext using AES-256-IGE via optimized C implementation (tgcrypto).
    """
    return tgcrypto.ige256_decrypt(ciphertext, key, iv)


def encrypt_aes_ige(plaintext: bytes, key: bytes, iv: bytes) -> bytes:
    """
    Encrypts plaintext using AES-256-IGE via optimized C implementation (tgcrypto).
    """
    return tgcrypto.ige256_encrypt(plaintext, key, iv)


def verify_kd2_candidate(
    passcode: str,
    salt: bytes,
    key128: bytes,
    ciphertext: bytes,
    time_cost: int = 8,
    memory_cost: int = 65536,
    kdf_id: int = 1,
) -> Tuple[bool, Optional[bytes]]:
    """
    Verifies a passcode candidate against KD2 (Argon2id) or PBKDF2 encrypted payload.
    Returns (True, local_key) if successful, otherwise (False, None).
    """
    try:
        if kdf_id == 0 or memory_cost == 0:
            # Try standard PBKDF2 (sha512(salt + pass + salt)) then legacy PBKDF2
            for is_legacy in (False, True):
                wrap_key = derive_pbkdf2_wrap_key(passcode, salt, legacy=is_legacy)
                aes_key, aes_iv = prepare_aes_oldmtp(wrap_key, key128)
                decrypted = decrypt_aes_ige(ciphertext, aes_key, aes_iv)
                if hashlib.sha1(decrypted).digest()[:16] == key128:
                    size = struct.unpack_from("<I", decrypted, 0)[0]
                    local_key = decrypted[4 : 4 + size]
                    return True, local_key
            return False, None

        wrap_key = derive_kd2_wrap_key(passcode, salt, time_cost=time_cost, memory_cost=memory_cost)
        aes_key, aes_iv = prepare_aes_oldmtp(wrap_key, key128)
        decrypted = decrypt_aes_ige(ciphertext, aes_key, aes_iv)
        
        # Verify SHA-1 integrity check: first 16 bytes of sha1(decrypted) must equal key128
        if hashlib.sha1(decrypted).digest()[:16] == key128:
            size = struct.unpack_from("<I", decrypted, 0)[0]
            local_key = decrypted[4 : 4 + size]
            return True, local_key
    except Exception:
        pass
    return False, None
