"""
Unit tests for core.hardware
"""

import sys
import unittest
from pathlib import Path

TOOLKIT_ROOT = Path(__file__).resolve().parent.parent
if str(TOOLKIT_ROOT) not in sys.path:
    sys.path.insert(0, str(TOOLKIT_ROOT))

from core.hardware import (
    get_available_ram_mb,
    get_total_ram_mb,
    get_system_specs,
    get_optimal_worker_count,
    set_process_low_priority,
)


class TestHardware(unittest.TestCase):

    def test_ram_detection(self):
        total_ram = get_total_ram_mb()
        avail_ram = get_available_ram_mb()

        self.assertGreater(total_ram, 512.0)
        self.assertGreater(avail_ram, 100.0)
        self.assertLessEqual(avail_ram, total_ram * 1.05)

    def test_system_specs(self):
        specs = get_system_specs()
        self.assertIn("os", specs)
        self.assertIn("cpu_threads", specs)
        self.assertIn("total_ram_mb", specs)
        self.assertIn("avail_ram_mb", specs)
        self.assertGreaterEqual(specs["cpu_threads"], 1)

    def test_optimal_worker_count(self):
        workers, reason = get_optimal_worker_count()
        self.assertGreaterEqual(workers, 1)
        self.assertIsInstance(reason, str)

        # Test user override
        override_workers, override_reason = get_optimal_worker_count(user_override=7)
        self.assertEqual(override_workers, 7)

    def test_set_priority(self):
        # Should execute cleanly without throwing exceptions
        set_process_low_priority()


if __name__ == "__main__":
    unittest.main()
