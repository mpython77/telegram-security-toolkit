"""
Universal Test Runner for Telegram Security Toolkit
Runs all unit and integration test suites.
"""

import sys
import unittest
from pathlib import Path

if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

CURRENT_DIR = Path(__file__).resolve().parent
TOOLKIT_ROOT = CURRENT_DIR.parent
if str(TOOLKIT_ROOT) not in sys.path:
    sys.path.insert(0, str(TOOLKIT_ROOT))


def run_suite():
    loader = unittest.TestLoader()
    suite = loader.discover(start_dir=str(CURRENT_DIR), pattern="test_*.py")

    print("=" * 65)
    print("TELEGRAM SECURITY TOOLKIT - FULL AUTOMATED TEST SUITE")
    print(f"Python Version: {sys.version.split()[0]} ({sys.platform})")
    print("=" * 65)

    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)

    print("\n" + "=" * 65)
    if result.wasSuccessful():
        print(f"🎉 ALL TESTS PASSED SUCCESSFULLY! ({result.testsRun} tests)")
    else:
        print(f"❌ FAILURES OCCURRED: {len(result.errors)} errors, {len(result.failures)} failures.")
    print("=" * 65)
    return result.wasSuccessful()


if __name__ == "__main__":
    success = run_suite()
    sys.exit(0 if success else 1)
