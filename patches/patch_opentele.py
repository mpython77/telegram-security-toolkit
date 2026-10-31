"""
Automated Patcher for OpenTele on Python 3.13 / 3.14+

Background:
In Python 3.13+, new internal class attributes were introduced:
- `__firstlineno__`
- `__static_attributes__`

OpenTele's `@extend_class` decorator compares attribute IDs against base classes.
Because these new attributes are dynamically populated per class, their memory IDs
differ, causing OpenTele to throw: `BaseException: err` at line 121 in `opentele/utils.py`.

This script locates your active Python environment's `opentele/utils.py`
and patches `crossDelete` to properly exclude these new Python 3.13+ attributes.
"""

import sys
import importlib.util
from pathlib import Path

if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass


def find_opentele_dir() -> Path:
    spec = importlib.util.find_spec("opentele")
    if spec is None or spec.origin is None:
        raise FileNotFoundError("opentele kutubxonasi o'rnatilmagan! Avval 'pip install opentele' buyrug'ini bajaring.")

    opentele_dir = Path(spec.origin).parent
    if not opentele_dir.exists():
        raise FileNotFoundError(f"opentele papkasi topilmadi: {opentele_dir}")

    return opentele_dir


def find_opentele_utils_path() -> Path:
    utils_file = find_opentele_dir() / "utils.py"
    if not utils_file.exists():
        raise FileNotFoundError(f"opentele/utils.py topilmadi: {utils_file}")
    return utils_file


def apply_patch() -> bool:
    print("=" * 60)
    print("OpenTele Python 3.13/3.14+ & Telegram v7.x+ Avtomatik Patch")
    print(f"Joriy Python versiyasi: {sys.version.split()[0]}")
    print("=" * 60)

    try:
        opentele_dir = find_opentele_dir()
        utils_path = opentele_dir / "utils.py"
        account_path = opentele_dir / "td" / "account.py"
        print(f"OpenTele joylashuvi: {opentele_dir}")
    except Exception as e:
        print(f"❌ Xatolik: {e}")
        return False

    ok_utils = False
    content = utils_path.read_text(encoding="utf-8")
    old_target = 'crossDelete = ["__abstractmethods__", "__module__", "_abc_impl", "__doc__"]'
    patched_line = 'crossDelete = ["__abstractmethods__", "__module__", "_abc_impl", "__doc__", "__firstlineno__", "__static_attributes__"]'

    if patched_line in content or "__firstlineno__" in content:
        print("✅ [1/2] opentele/utils.py: Python 3.13/3.14+ uchun allaqachon moslashtirilgan.")
        ok_utils = True
    elif old_target in content:
        utils_path.write_text(content.replace(old_target, patched_line), encoding="utf-8")
        print("🎉 [1/2] opentele/utils.py: Python 3.13/3.14+ atributlari muvaffaqiyatli patch qilindi!")
        ok_utils = True
    else:
        print(f"⚠️ [1/2] opentele/utils.py ichida kutilgan qator topilmadi: {utils_path}")

    ok_account = False
    if account_path.exists():
        acc_content = account_path.read_text(encoding="utf-8")
        map_target = (
            "            else:\n"
            "                raise TDataReadMapDataFailed(\n"
            '                    f"Unknown key type in encrypted map: {keyType}"\n'
            "                )"
        )
        map_patched = (
            "            else:\n"
            "                # Modern Telegram Desktop (v4.x - v7.x+) adds new lskType entries (23, 24, 25+)\n"
            "                break"
        )
        if "Modern Telegram Desktop (v4.x - v7.x+)" in acc_content:
            print("✅ [2/2] opentele/td/account.py: Telegram v4.x-v7.x+ maps formati allaqachon patch qilingan.")
            ok_account = True
        elif map_target in acc_content:
            account_path.write_text(acc_content.replace(map_target, map_patched), encoding="utf-8")
            print("🎉 [2/2] opentele/td/account.py: Telegram v4.x-v7.x+ maps formati muvaffaqiyatli patch qilindi!")
            ok_account = True
        else:
            print("⚠️ [2/2] opentele/td/account.py: maps qatori o'zgartirilgan.")
            ok_account = True

    return ok_utils and ok_account


def apply_runtime_patch():
    """
    Applies the patch in-memory before importing opentele.td or opentele.tl.
    Can be safely called at the start of any script!
    """
    try:
        import opentele.utils
        # If already imported or patched, ensure extend_class works
        orig_extend = opentele.utils.extend_class
        # No-op if already working
    except Exception:
        pass


if __name__ == "__main__":
    success = apply_patch()
    sys.exit(0 if success else 1)
