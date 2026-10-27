"""
Hardware Detection & Resource Scaling Engine
Dynamically tunes multithreading and memory allocation across various CPU architectures
(Intel P/E-cores, AMD Ryzen/Threadripper, low-RAM and high-RAM systems).
"""

import os
import sys
import platform
from typing import Dict, Any, Tuple, Optional


def get_available_ram_mb() -> float:
    """
    Returns available physical memory in Megabytes without external dependencies.
    Works natively on Windows, Linux, and macOS.
    """
    try:
        if sys.platform == "win32":
            import ctypes
            from ctypes import wintypes

            class MEMORYSTATUSEX(ctypes.Structure):
                _fields_ = [
                    ("dwLength", wintypes.DWORD),
                    ("dwMemoryLoad", wintypes.DWORD),
                    ("ullTotalPhys", ctypes.c_uint64),
                    ("ullAvailPhys", ctypes.c_uint64),
                    ("ullTotalPageFile", ctypes.c_uint64),
                    ("ullAvailPageFile", ctypes.c_uint64),
                    ("ullTotalVirtual", ctypes.c_uint64),
                    ("ullAvailVirtual", ctypes.c_uint64),
                    ("sullAvailExtendedVirtual", ctypes.c_uint64),
                ]

            stat = MEMORYSTATUSEX()
            stat.dwLength = ctypes.sizeof(MEMORYSTATUSEX)
            kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
            kernel32.GlobalMemoryStatusEx.argtypes = [ctypes.POINTER(MEMORYSTATUSEX)]
            kernel32.GlobalMemoryStatusEx.restype = wintypes.BOOL

            if kernel32.GlobalMemoryStatusEx(ctypes.byref(stat)):
                return stat.ullAvailPhys / (1024 * 1024)

        elif sys.platform.startswith("linux"):
            with open("/proc/meminfo", "r", encoding="utf-8") as f:
                for line in f:
                    if line.startswith("MemAvailable:"):
                        kb = int(line.split()[1])
                        return kb / 1024.0

        elif sys.platform == "darwin":
            # macOS fallback
            import subprocess
            out = subprocess.check_output(["sysctl", "-n", "hw.memsize"]).strip()
            total_mb = int(out) / (1024 * 1024)
            return total_mb * 0.5  # estimate 50% available
    except Exception:
        pass

    # Universal fallback: assume 2048 MB available
    return 2048.0


def get_total_ram_mb() -> float:
    """
    Returns total physical memory in Megabytes.
    """
    try:
        if sys.platform == "win32":
            import ctypes
            from ctypes import wintypes

            class MEMORYSTATUSEX(ctypes.Structure):
                _fields_ = [
                    ("dwLength", wintypes.DWORD),
                    ("dwMemoryLoad", wintypes.DWORD),
                    ("ullTotalPhys", ctypes.c_uint64),
                    ("ullAvailPhys", ctypes.c_uint64),
                    ("ullTotalPageFile", ctypes.c_uint64),
                    ("ullAvailPageFile", ctypes.c_uint64),
                    ("ullTotalVirtual", ctypes.c_uint64),
                    ("ullAvailVirtual", ctypes.c_uint64),
                    ("sullAvailExtendedVirtual", ctypes.c_uint64),
                ]

            stat = MEMORYSTATUSEX()
            stat.dwLength = ctypes.sizeof(MEMORYSTATUSEX)
            kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
            kernel32.GlobalMemoryStatusEx.argtypes = [ctypes.POINTER(MEMORYSTATUSEX)]
            kernel32.GlobalMemoryStatusEx.restype = wintypes.BOOL

            if kernel32.GlobalMemoryStatusEx(ctypes.byref(stat)):
                return stat.ullTotalPhys / (1024 * 1024)

        elif sys.platform.startswith("linux"):
            with open("/proc/meminfo", "r", encoding="utf-8") as f:
                for line in f:
                    if line.startswith("MemTotal:"):
                        kb = int(line.split()[1])
                        return kb / 1024.0
    except Exception:
        pass

    return 4096.0


def get_system_specs() -> Dict[str, Any]:
    """
    Gathers detailed hardware specifications.
    """
    cpu_threads = os.cpu_count() or 4
    total_ram = get_total_ram_mb()
    avail_ram = get_available_ram_mb()

    return {
        "os": platform.system(),
        "release": platform.release(),
        "arch": platform.machine(),
        "cpu_threads": cpu_threads,
        "total_ram_mb": round(total_ram, 1),
        "avail_ram_mb": round(avail_ram, 1),
    }


def get_optimal_worker_count(
    memory_per_worker_mb: int = 96,
    user_override: Optional[int] = None,
) -> Tuple[int, str]:
    """
    Calculates the safest and fastest worker count.
    Argon2id (64MB) + Python worker memory (~32MB) = ~96MB per worker.
    Ensures the system never freezes or hits out-of-memory swapping.
    """
    cpu_threads = os.cpu_count() or 4
    avail_ram = get_available_ram_mb()

    if user_override is not None and user_override > 0:
        return user_override, f"Foydalanuvchi tomonidan qo'lda belgilangan: {user_override}"

    # Reserve 512 MB for OS and other background apps
    usable_ram = max(256.0, avail_ram - 512.0)
    ram_limit_workers = max(1, int(usable_ram // memory_per_worker_mb))

    # CPU thread cap: on systems with > 4 cores, leave 1 thread free for OS UI responsiveness
    if cpu_threads > 4:
        cpu_optimal = cpu_threads - 1
    else:
        cpu_optimal = cpu_threads

    optimal = min(cpu_optimal, ram_limit_workers)
    optimal = max(1, optimal)

    reason = (
        f"CPU: {cpu_threads} oqim, Mavjud RAM: {avail_ram:.0f} MB -> "
        f"Xavfsiz va optimal oqimlar: {optimal} ta"
    )
    return optimal, reason


def set_process_low_priority():
    """
    Lowers the priority of the current worker process so the computer's UI,
    mouse and apps remain completely smooth and lag-free during heavy brute-forcing.
    """
    try:
        if sys.platform == "win32":
            import ctypes
            from ctypes import wintypes

            kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
            handle = kernel32.GetCurrentProcess()
            kernel32.SetPriorityClass.argtypes = [wintypes.HANDLE, wintypes.DWORD]
            kernel32.SetPriorityClass.restype = wintypes.BOOL
            # 0x00004000 = BELOW_NORMAL_PRIORITY_CLASS
            kernel32.SetPriorityClass(handle, 0x00004000)
        else:
            os.nice(10)
    except Exception:
        pass
