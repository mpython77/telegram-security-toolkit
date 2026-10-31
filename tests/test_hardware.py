"""
Unit tests for core.hardware
Verifies physical core + logical thread topology detection, RAM detection,
and adaptive multi-core scaling across 4C/8T, 8C/8T, 8C/16T, 20C/40T, and low-RAM systems.
"""

import sys
import unittest
from pathlib import Path

TOOLKIT_ROOT = Path(__file__).resolve().parent.parent
if str(TOOLKIT_ROOT) not in sys.path:
    sys.path.insert(0, str(TOOLKIT_ROOT))

from core.hardware import (
    get_cpu_topology,
    get_available_ram_mb,
    get_total_ram_mb,
    get_system_specs,
    get_optimal_worker_count,
    set_process_low_priority,
    MAX_WINDOWS_POOL_WORKERS,
)


class TestHardware(unittest.TestCase):

    def test_cpu_topology_detection(self):
        cores, threads = get_cpu_topology()
        self.assertGreaterEqual(cores, 1)
        self.assertGreaterEqual(threads, cores)

    def test_ram_detection(self):
        total_ram = get_total_ram_mb()
        avail_ram = get_available_ram_mb()

        self.assertGreater(total_ram, 512.0)
        self.assertGreater(avail_ram, 100.0)
        self.assertLessEqual(avail_ram, total_ram * 1.05)

    def test_system_specs(self):
        specs = get_system_specs()
        self.assertIn("os", specs)
        self.assertIn("cpu_cores", specs)
        self.assertIn("cpu_threads", specs)
        self.assertIn("total_ram_mb", specs)
        self.assertIn("avail_ram_mb", specs)
        self.assertGreaterEqual(specs["cpu_cores"], 1)
        self.assertGreaterEqual(specs["cpu_threads"], specs["cpu_cores"])

    def test_optimal_worker_count(self):
        workers, reason = get_optimal_worker_count()
        self.assertGreaterEqual(workers, 1)
        self.assertIsInstance(reason, str)

        # Test user override
        override_workers, override_reason = get_optimal_worker_count(user_override=7)
        self.assertEqual(override_workers, 7)

    def test_adaptive_scaling_across_cpu_topologies(self):
        """
        Verifies 100% maximum CPU thread utilization across:
        - 4 cores / 8 threads (4C/8T)
        - 8 cores / 8 threads (8C/8T)
        - 8 cores / 16 threads (8C/16T)
        - 20 cores / 40 threads (20C/40T)
        - RAM-constrained system (20C/40T with only 1.5 GB free RAM)
        - Extreme workstation (64C/128T)
        """
        # 1. 4 cores / 8 threads with 8 GB available RAM -> uses all 8 threads
        w_4c8t, r_4c8t = get_optimal_worker_count(
            memory_per_worker_mb=96,
            detected_cores=4,
            detected_threads=8,
            detected_avail_ram_mb=8192.0,
        )
        self.assertEqual(w_4c8t, 8)
        self.assertIn("4 cores / 8 threads", r_4c8t)
        self.assertIn("8/8", r_4c8t)

        # 2. 8 cores / 8 threads with 16 GB available RAM -> uses all 8 threads
        w_8c8t, r_8c8t = get_optimal_worker_count(
            memory_per_worker_mb=96,
            detected_cores=8,
            detected_threads=8,
            detected_avail_ram_mb=16384.0,
        )
        self.assertEqual(w_8c8t, 8)
        self.assertIn("8 cores / 8 threads", r_8c8t)
        self.assertIn("8/8", r_8c8t)

        # 3. 8 cores / 16 threads with 16 GB available RAM -> uses all 16 threads
        w_8c16t, r_8c16t = get_optimal_worker_count(
            memory_per_worker_mb=96,
            detected_cores=8,
            detected_threads=16,
            detected_avail_ram_mb=16384.0,
        )
        self.assertEqual(w_8c16t, 16)
        self.assertIn("8 cores / 16 threads", r_8c16t)
        self.assertIn("16/16", r_8c16t)

        # 4. 20 cores / 40 threads with 32 GB available RAM -> uses all 40 threads
        w_20c40t, r_20c40t = get_optimal_worker_count(
            memory_per_worker_mb=96,
            detected_cores=20,
            detected_threads=40,
            detected_avail_ram_mb=32768.0,
        )
        self.assertEqual(w_20c40t, 40)
        self.assertIn("20 cores / 40 threads", r_20c40t)
        self.assertIn("40/40", r_20c40t)

        # 5. RAM-constrained 20C/40T system (only 1472 MB free RAM -> 960 MB usable -> 10 workers)
        w_lowram, r_lowram = get_optimal_worker_count(
            memory_per_worker_mb=96,
            detected_cores=20,
            detected_threads=40,
            detected_avail_ram_mb=1472.0,
        )
        self.assertEqual(w_lowram, 10)
        self.assertIn("RAM-bounded safe limit", r_lowram)

        # 6. Extreme 64C/128T system -> respects OS ProcessPoolExecutor handle cap on Windows (61)
        w_128t, _ = get_optimal_worker_count(
            memory_per_worker_mb=96,
            detected_cores=64,
            detected_threads=128,
            detected_avail_ram_mb=131072.0,
        )
        if sys.platform == "win32":
            self.assertEqual(w_128t, MAX_WINDOWS_POOL_WORKERS)
        else:
            self.assertEqual(w_128t, 128)

    def test_set_priority(self):
        # Should execute cleanly without throwing exceptions
        set_process_low_priority()


if __name__ == "__main__":
    unittest.main()
