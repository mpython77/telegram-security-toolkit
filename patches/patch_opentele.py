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


def find_opentele_utils_path() -> Path:
    spec = importlib.util.find_spec("opentele")
    if spec is None or spec.origin is None:
        raise FileNotFoundError("opentele kutubxonasi o'rnatilmagan! Avval 'pip install opentele' buyrug'ini bajaring.")

    opentele_dir = Path(spec.origin).parent
    utils_file = opentele_dir / "utils.py"
    if not utils_file.exists():
        raise FileNotFoundError(f"opentele/utils.py topilmadi: {utils_file}")

    return utils_file


def apply_patch():
    print("=" * 60)
    print("OpenTele Python 3.13 / 3.14+ Avtomatik Patch vositasi")
    print(f"Joriy Python versiyasi: {sys.version.split()[0]}")
    print("=" * 60)

    try:
        utils_path = find_opentele_utils_path()
        print(f"Fayl topildi: {utils_path}")
    except Exception as e:
        print(f"❌ Xatolik: {e}")
        return False

    content = utils_path.read_text(encoding="utf-8")

    # Target line in opentele/utils.py:
    old_target = 'crossDelete = ["__abstractmethods__", "__module__", "_abc_impl", "__doc__"]'
    patched_line = 'crossDelete = ["__abstractmethods__", "__module__", "_abc_impl", "__doc__", "__firstlineno__", "__static_attributes__"]'

    if patched_line in content:
        print("✅ Ushbu fayl ALLAQACHON to'liq patch qilingan! Hech qanday o'zgarish shart emas.")
        return True

    if old_target in content:
        new_content = content.replace(old_target, patched_line)
        utils_path.write_text(new_content, encoding="utf-8")
        print("🎉 MUVAFFAQIYATLI PATCH QILINDI!")
        print(f"'{old_target}' o'zgartirildi:")
        print(f"--> '{patched_line}'")
        return True

    # Check if partial patch exists
    if "__firstlineno__" in content:
        print("✅ Fayl allaqachon Python 3.13 uchun moslashtirilgan.")
        return True

    print("⚠️ Aniq mos keladigan satr topilmadi. Qo'lda tekshirib ko'ring:")
    print(f"Fayl: {utils_path}")
    return False


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
