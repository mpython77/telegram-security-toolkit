"""
Telegram Security & Forensics Toolkit - Core Engine
"""

import sys

if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

__version__ = "1.0.0"

from .crypto import (
    prepare_aes_oldmtp,
    derive_kd2_wrap_key,
    derive_pbkdf2_wrap_key,
    decrypt_aes_ige,
    encrypt_aes_ige,
    encrypt_local_block,
    decrypt_local_block,
    verify_kd2_candidate,
)
from .tdata_parser import TDataParser, KD2Info
from .dc_extractor import DCExtractor, MtpSessionInfo, OfflineUserProfile
from .session_manager import SessionManager
from .hardware import (
    get_cpu_topology,
    get_system_specs,
    get_optimal_worker_count,
    set_process_low_priority,
)

__all__ = [
    "__version__",
    "prepare_aes_oldmtp",
    "derive_kd2_wrap_key",
    "derive_pbkdf2_wrap_key",
    "decrypt_aes_ige",
    "encrypt_aes_ige",
    "encrypt_local_block",
    "decrypt_local_block",
    "verify_kd2_candidate",
    "TDataParser",
    "KD2Info",
    "DCExtractor",
    "MtpSessionInfo",
    "OfflineUserProfile",
    "SessionManager",
    "get_cpu_topology",
    "get_system_specs",
    "get_optimal_worker_count",
    "set_process_low_priority",
]
