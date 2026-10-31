"""
Hardware Detection & Adaptive Resource Scaling Engine
Dynamically detects physical CPU cores, logical threads (SMT/Hyper-Threading),
and available physical RAM across Windows, Linux, and macOS to maximize
multi-core cracking throughput without causing OOM or UI lag.
"""

import os
import sys
import platform
from typing import Dict, Any, Tuple, Optional

# Python's ProcessPoolExecutor on Windows is bounded by WaitForMultipleObjects (61 handles max)
MAX_WINDOWS_POOL_WORKERS = 61


def get_cpu_topology() -> Tuple[int, int]:
    """
    Detects (physical_cores, logical_threads) natively without external dependencies.
    Works across Windows (Win32 GetLogicalProcessorInformationEx), Linux (/proc/cpuinfo),
    and macOS (sysctl).
    """
    logical_threads = os.cpu_count() or 4
    physical_cores = 0

    try:
        if sys.platform == "win32":
            import ctypes
            from ctypes import wintypes

            kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
            length = wintypes.DWORD(0)
            # 0 = RelationProcessorCore
            kernel32.GetLogicalProcessorInformationEx(0, None, ctypes.byref(length))
            if length.value > 0:
                buf = (ctypes.c_byte * length.value)()
                if kernel32.GetLogicalProcessorInformationEx(0, buf, ctypes.byref(length)):
                    raw = bytes(buf)
                    offset = 0
                    count = 0
                    while offset + 8 <= len(raw):
                        rel = int.from_bytes(raw[offset : offset + 4], "little")
                        size = int.from_bytes(raw[offset + 4 : offset + 8], "little")
                        if size <= 0:
                            break
                        if rel == 0:
                            count += 1
                        offset += size
                    if count > 0:
                        physical_cores = count

        elif sys.platform.startswith("linux"):
            core_ids = set()
            phys_id = "0"
            with open("/proc/cpuinfo", "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    if line.startswith("physical id"):
                        phys_id = line.split(":", 1)[1].strip()
                    elif line.startswith("core id"):
                        cid = line.split(":", 1)[1].strip()
                        core_ids.add((phys_id, cid))
            if core_ids:
                physical_cores = len(core_ids)

        elif sys.platform == "darwin":
            import subprocess
            out = subprocess.check_output(["sysctl", "-n", "hw.physicalcpu"]).strip()
            physical_cores = int(out)
    except Exception:
        pass

    if physical_cores <= 0 or physical_cores > logical_threads:
        physical_cores = max(1, logical_threads // 2) if logical_threads > 1 else 1

    return physical_cores, logical_threads


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
            import subprocess
            out = subprocess.check_output(["sysctl", "-n", "hw.memsize"]).strip()
            total_mb = int(out) / (1024 * 1024)
            return total_mb * 0.5
    except Exception:
        pass

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
    Gathers detailed hardware specifications (OS, physical cores, logical threads, RAM).
    """
    cpu_cores, cpu_threads = get_cpu_topology()
    total_ram = get_total_ram_mb()
    avail_ram = get_available_ram_mb()

    return {
        "os": platform.system(),
        "release": platform.release(),
        "arch": platform.machine(),
        "cpu_cores": cpu_cores,
        "cpu_threads": cpu_threads,
        "total_ram_mb": round(total_ram, 1),
        "avail_ram_mb": round(avail_ram, 1),
    }


def get_optimal_worker_count(
    memory_per_worker_mb: int = 96,
    user_override: Optional[int] = None,
    detected_cores: Optional[int] = None,
    detected_threads: Optional[int] = None,
    detected_avail_ram_mb: Optional[float] = None,
) -> Tuple[int, str]:
    """
    Calculates the fastest and safest worker count for any CPU topology
    (e.g., 4C/8T, 8C/8T, 8C/16T, 20C/40T, 32C/64T).
    - Uses 100% of logical threads when RAM permits (since workers run at BELOW_NORMAL priority,
      the OS scheduler keeps UI responsiveness smooth even at 100% thread utilization).
    - Caps workers by available physical RAM (Argon2id 64MB + ~32MB worker overhead = ~96MB/worker)
      to prevent OOM or disk swap thrashing.
    - Respects Windows ProcessPoolExecutor 61-worker handle limit on win32.
    """
    if detected_cores is not None and detected_threads is not None:
        cpu_cores, cpu_threads = detected_cores, detected_threads
    else:
        cpu_cores, cpu_threads = get_cpu_topology()

    avail_ram = detected_avail_ram_mb if detected_avail_ram_mb is not None else get_available_ram_mb()
    platform_cap = MAX_WINDOWS_POOL_WORKERS if sys.platform == "win32" else 512

    if user_override is not None and user_override > 0:
        capped = min(user_override, platform_cap)
        return capped, f"User manually specified: {capped} (CPU: {cpu_cores}C/{cpu_threads}T)"

    # Reserve 512 MB for OS and foreground applications
    usable_ram = max(256.0, avail_ram - 512.0)
    ram_limit_workers = max(1, int(usable_ram // max(1, memory_per_worker_mb)))

    # Utilize 100% of logical CPU threads up to RAM and OS handle limits
    optimal = min(cpu_threads, ram_limit_workers, platform_cap)
    optimal = max(1, optimal)

    if optimal == cpu_threads:
        mode_note = "100% max CPU power"
    elif optimal == ram_limit_workers:
        mode_note = "RAM-bounded safe limit"
    else:
        mode_note = "OS pool handle limit"

    reason = (
        f"CPU: {cpu_cores} cores / {cpu_threads} threads, Available RAM: {avail_ram:.0f} MB -> "
        f"Optimal workers: {optimal}/{cpu_threads} ({mode_note})"
    )
    return optimal, reason


def set_process_low_priority():
    """
    Lowers the priority of the current worker process (BELOW_NORMAL_PRIORITY_CLASS on Windows,
    nice(10) on Linux/macOS) so 100% of CPU threads can be utilized for cracking while
    the OS automatically prioritizes mouse, UI, and foreground tasks with zero lag.
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
