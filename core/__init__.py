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

from .crypto import prepare_aes_oldmtp, derive_kd2_wrap_key, decrypt_aes_ige, verify_kd2_candidate
from .tdata_parser import TDataParser
from .dc_extractor import DCExtractor
from .session_manager import SessionManager
from .hardware import get_system_specs, get_optimal_worker_count, set_process_low_priority

__all__ = [
    "prepare_aes_oldmtp",
    "derive_kd2_wrap_key",
    "decrypt_aes_ige",
    "verify_kd2_candidate",
    "TDataParser",
    "DCExtractor",
    "SessionManager",
    "get_system_specs",
    "get_optimal_worker_count",
    "set_process_low_priority",
]
