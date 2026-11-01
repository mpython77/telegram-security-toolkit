# Telegram Desktop Security, Forensics & Recovery Toolkit

A comprehensive, production-grade toolkit for **Telegram Desktop (`tdata`)** security auditing, offline digital forensics, passcode analysis, and multi-session authentication recovery.

---

## 📌 Table of Contents
1. [Overview & Key Features](#-overview--key-features)
2. [Telegram Local Encryption Architecture (KD2 & TDF$)](#-telegram-local-encryption-architecture-kd2--tdf)
3. [Why CPU and Multiprocessing Instead of Hashcat & GPU?](#-why-cpu-and-multiprocessing-instead-of-hashcat--gpu)
4. [System Requirements & Installation](#-system-requirements--installation)
5. [Step-by-Step Usage Guide](#-step-by-step-usage-guide)
   - [Step 1: Lightweight TData Harvester (`--harvest`)](#step-1-lightweight-tdata-harvester---harvest)
   - [Step 2: Offline Forensic Analyzer & Integrity Audit (`--analyze`)](#step-2-offline-forensic-analyzer--integrity-audit---analyze)
   - [Step 3: KD2 / PBKDF2 Multi-Core Passcode Cracker (`--crack`)](#step-3-kd2--pbkdf2-multi-core-passcode-cracker---crack)
   - [Step 4: Multi-DC & Multi-Account Session Extractor (`--extract`)](#step-4-multi-dc--multi-account-session-extractor---extract)
   - [Step 5: Pure-Python Session to TData Converter (`--convert`)](#step-5-pure-python-session-to-tdata-converter---convert)
   - [Step 6: In-Place Passcode Unlocker & Restorer (`--restore`)](#step-6-in-place-passcode-unlocker--restorer---restore)
   - [Step 7: Session Verification & Health Checker (`--check`)](#step-7-session-verification--health-checker---check)
   - [Step 8: Automated Test Suite (`--test`)](#step-8-automated-test-suite---test)
6. [Python 3.13 / 3.14+ and Telegram v7.x+ OpenTele Compatibility Patch (`--patch`)](#-python-313--314-and-telegram-v7x-opentele-compatibility-patch---patch)
7. [Multi-Account Workflow & Telegram Portable Execution](#-multi-account-workflow--telegram-portable-execution)
8. [Git & Operational Security Guidelines](#-git--operational-security-guidelines)
9. [Architecture & Project Structure](#-architecture--project-structure)

---

## 🚀 Overview & Key Features

This toolkit unifies the complete Telegram Desktop security lifecycle through a central command-line interface (`main.py`):

* **📦 Lightweight TData Harvester (`--harvest`):** Scans the local system across standard installations (Roaming AppData, Microsoft Store UWP, Portable folders, Linux Snap/Flatpak, macOS Application Support), ignores gigabytes of disposable media and cache directories, and archives critical authentication files into a compact ZIP container.
* **🔬 100% Offline Forensic Analyzer (`--analyze`):** Performs zero-network forensic verification on `.zip`, `.tar.xz`, raw `tdata` directories, or `.session` files. Audits container SHA-256 hashes, `TDF$` MD5 checksums, KDF parameters, offline profiles (`Full Name`, `@username`, `+Phone`, `User ID`, `Bio`), 64-bit MTProto `auth_key_id` fingerprints across all Data Centers, and complete TLV block inventory from `maps`. Exports structured JSON reports.
* **🔓 Dual-KDF Multi-Core Cracker (`--crack`):** High-throughput brute-force engine for modern **KD2 (`Argon2id` + `AES-256-IGE`)** and legacy/standard **`PBKDF2-HMAC-SHA512`** local passcode containers. Dynamically scales worker processes based on hardware core topology and available physical RAM while keeping system UI responsiveness smooth.
* **🔑 Multi-DC & Multi-Account Session Extractor (`--extract`):** Decrypts `.s` and `maps` files to recover master `LocalKey` and all Data Center keys (`DC 1, 2, 4, 5`). Generates authentic Telethon SQLite `.session` files for single or all (`--all`) active accounts simultaneously.
* **🚀 Pure-Python `Session -> TData` Converter (`--convert`):** Eliminates fragile dependencies on external C++/Qt libraries (`PyQt5` or unmaintained `opentele`). Generates valid, passcode-free `tdata` folders directly in pure Python (`struct.pack` and AES-256-IGE), supporting up to 16 accounts merged into a single multi-account `tdata`.
* **🔄 In-Place Passcode Unlocker & Restorer (`--restore`):** Restores any backup archive (`.zip`, `.tar.xz`, `.tar.gz`) or `tdata` folder directly into a target Telegram Desktop directory, rewriting `key_datas` in-place to remove the local passcode while retaining 100% of authentic DC keys (`[1, 2, 4, 5]`), drafts (`lskDraft`), stickers, and local database cache.
* **🛡️ Hardened Archive Security (Zip-Slip Defense):** Implements path traversal validation and strict symlink filtering when decompressing untrusted backup archives, rejecting relative parent directory traversals (`../../`).

---

## 🔐 Telegram Local Encryption Architecture (KD2 & TDF$)

Telegram Desktop isolates and encrypts its local state within the `tdata` directory using proprietary binary formats.

### 1. The Container Format (`TDF$`):
Every critical file (`key_datas`, `D877F783D5D3EF8Cs`, companion `maps`, `configs`, `settings`) follows the `TDF$` binary structure:
* **0..4 bytes:** Magic header `TDF$` (`0x54 0x44 0x46 0x24`)
* **4..8 bytes:** Telegram client version (Little-Endian `uint32`, e.g., `7003003` for `v7.3.3`)
* **8..N-16 bytes:** Encrypted binary payload
* **Last 16 bytes:** Integrity check: `MD5(payload + len(payload) + version + "TDF$")`

### 2. KD2 Key Derivation (`key_datas`):
When a local passcode is configured, Telegram Desktop enforces the `KD2\0` (Key Derivation v2) specification:
* **KDF Algorithm:** `Argon2id` (v13, `kdf_id = 1`)
* **Memory Cost (`memory_cost`):** `65536 KiB` (64 MB of physical RAM allocated per attempt)
* **Time Cost (`time_cost`):** `8` iterations
* **Parallelism (`threads`):** `1` thread
* **Salt Length:** `32` bytes
* **Encrypted Key Blob:** `288` bytes (`16` bytes `key128` + `272` bytes encrypted payload)

From the passcode candidate and salt, a 256-byte `wrap_key` is derived via Argon2id. Using Telegram's internal `prepareAES_oldmtp` derivation, a 32-byte AES key and 32-byte IV are computed. The ciphertext is decrypted via AES-256-IGE; if the first 16 bytes of `SHA-1(decrypted)` match `key128`, the candidate is confirmed and the 256-byte master **LocalKey** is extracted.

When no passcode is set (`passcode = ""`), Telegram uses `kdf_id = 0` (`PBKDF2-HMAC-SHA512` with 1 iteration) to wrap the master `LocalKey`.

---

## ⚡ Why CPU and Multiprocessing Instead of Hashcat & GPU?

1. **Absence of KD2 in Existing Hashcat Modules:** Hashcat supports legacy Telegram PBKDF2 formats (`-m 22600` and `-m 24500`), but has no support for modern `Argon2id + AES-256-IGE` (KD2).
2. **Argon2id Memory-Hardness:**
   * Argon2id is intentionally designed to be memory-hard. Each hashing attempt requires 64 MB of high-speed memory access, rendering GPU SIMD clusters memory-bound.
   * Modern multi-core CPUs paired with high-bandwidth memory (DDR4/DDR5) compute ~25–35 full 64 MB Argon2id operations per second across multi-threading cores.
   * A 4-digit numeric PIN space (`10,000` combinations) completes in **5–8 minutes** on standard multi-core hardware.

---

## 📦 System Requirements & Installation

### 1. Requirements:
* **Python:** `3.10`, `3.11`, `3.12`, `3.13`, or `3.14+`
* **Operating System:** Windows 10/11, Linux, or macOS

### 2. Installation:
Clone the repository and install dependencies:
```bash
pip install -r requirements.txt
```
Or install as a local package via `pyproject.toml`:
```bash
pip install -e .
```

Core libraries:
* `telethon` — Telegram MTProto API client
* `tgcrypto` — High-performance C-accelerated AES-256-IGE encryption/decryption
* `argon2-cffi` — C implementation of Argon2id
* `pycryptodome` — Cryptographic calculation primitives
* `opentele` *(optional fallback)* — Legacy Qt-based conversion module (not required by the native Pure-Python engine)

---

## 🛠️ Step-by-Step Usage Guide

Launch the unified interactive menu:
```bash
python main.py
```
Or invoke specific command-line operations directly:

---

### Step 1: Lightweight TData Harvester (`--harvest`)
Locates active Telegram Desktop storage locations, skips media/cache files, and outputs a clean ZIP archive:
```bash
python main.py --harvest -o .
```
Specify a custom directory:
```bash
python main.py --harvest -p "C:\Custom\Telegram\tdata" -o .
```

---

### Step 2: Offline Forensic Analyzer & Integrity Audit (`--analyze`)
Inspects any `.zip`, `.tar.xz`, `tdata` folder, or `.session` file without connecting to Telegram servers:
```bash
# Analyze unencrypted or locked archive:
python main.py --analyze -s backup.zip

# Analyze with known passcode and export JSON report:
python main.py --analyze -s backup.zip -p 1234 -j audit_report.json
```

---

### Step 3: KD2 / PBKDF2 Multi-Core Passcode Cracker (`--crack`)
Brute-forces the master `LocalKey` across all available CPU threads:
```bash
# 4-digit numeric PINs (0000-9999):
python main.py --crack -s backup.zip --mode pin4

# 6-digit numeric PINs (000000-999999):
python main.py --crack -s backup.zip --mode pin6

# Custom numerical range:
python main.py --crack -s backup.zip --mode range --start 1000 --end 2000

# Dictionary wordlist:
python main.py --crack -s backup.zip --mode wordlist -w passwords.txt
```
Recovered passcodes and keys are saved to `found_passcode.txt` and `found_local_key.bin`.

---

### Step 4: Multi-DC & Multi-Account Session Extractor (`--extract`)
Extracts MTProto authentication keys and profile details into Telethon `.session` SQLite files:
```bash
# Extract the primary account:
python main.py --extract -s backup.zip -p 1234 -o account.session

# Extract ALL active accounts into individual .session files:
python main.py --extract -s backup.zip -p 1234 --all -o ./sessions/

# Extract a specific account index (e.g., account index 1):
python main.py --extract -s backup.zip -p 1234 --account-index 1
```

---

### Step 5: Pure-Python Session to TData Converter (`--convert`)
Converts `.session` file(s) into clean, passcode-free `tdata` using the native Pure-Python serialization engine:
```bash
# Convert a single session:
python main.py --convert -s account.session -o "C:\Telegram_Clean\tdata"

# Merge multiple sessions into a single Multi-Account tdata:
python main.py --convert -s acc1.session acc2.session -o "C:\Telegram_Multi\tdata"
```

---

### Step 6: In-Place Passcode Unlocker & Restorer (`--restore`)
Restores an encrypted archive or directory to a target `tdata` folder, unlocking the local passcode in-place while preserving all 4 DC keys (`[1, 2, 4, 5]`), maps, drafts, and local cache:
```bash
# Restore with known passcode:
python main.py --restore -s backup.zip -t "C:\Telegram_Portable\tdata" -p 1234

# Restore with automated 4-digit PIN discovery:
python main.py --restore -s backup.zip -t "C:\Telegram_Portable\tdata" --auto-crack
```

---

### Step 7: Session Verification & Health Checker (`--check`)
Verifies session connectivity against Telegram servers using official Telegram Desktop client identification headers:
```bash
python main.py --check -s account.session
```

---

### Step 8: Automated Test Suite (`--test`)
Executes the full suite of **22 automated unit and end-to-end regression tests**:
```bash
python main.py --test
```

---

## 🩹 Python 3.13 / 3.14+ and Telegram v7.x+ OpenTele Compatibility Patch (`--patch`)

The core `SessionManager.session_to_tdata` engine is written in pure Python and requires neither `opentele` nor `PyQt5`. However, for workflows that interact with existing `opentele` installations, the included patch resolves three upstream issues:
1. **Python 3.13+ Class Attributes:** Excludes `__firstlineno__` and `__static_attributes__` during dynamic class extension in `opentele/utils.py`.
2. **Telegram v4.x–v7.x+ Map Block Types:** Handles unknown `lskType` identifiers (`23, 24, 25+`) in `opentele/td/account.py`.
3. **Multi-Account Recursion Loop:** Prevents an infinite `RecursionError` in `Account.api` when loading multiple accounts in `opentele/td/account.py`.

Apply the patch with:
```bash
python main.py --patch
```

---

## 👥 Multi-Account Workflow & Telegram Portable Execution

1. **Consolidated Multi-Account TData:**
   Run `python main.py --convert -s acc1.session acc2.session -o "C:\Telegram_Portable\tdata"` to combine up to 16 accounts into one client directory.
2. **Side-by-Side Portable Instances:**
   Deploy the official **Telegram Desktop Portable** build into a distinct directory (e.g., `C:\Telegram_Instance2`) alongside your primary client. Extracted `tdata` configurations run concurrently without session conflicts.

---

## 🛡️ Git & Operational Security Guidelines

1. **Keep Repositories Private:** Never publish sensitive session artifacts or encryption keys to public repositories.
2. **Enforce `.gitignore` Protections:** The included `.gitignore` rules prevent SQLite sessions (`*.session`), binary keys (`*.bin`), passcode dumps (`found_*.txt`), JSON forensic exports, and compressed archives (`*.zip`, `*.xz`) from being tracked by version control.

---

## 🏛️ Architecture & Project Structure

```text
Telegram_Security_Toolkit/
│
├── README.md                        # Technical documentation and reference manual
├── pyproject.toml                   # Standard Python packaging configuration (v1.0.0)
├── requirements.txt                 # Project dependencies
├── .gitignore                       # Artifact and session exclusions
├── main.py                          # Unified CLI entry point and interactive menu
│
├── core/                            # Cryptographic and binary parsing foundation
│   ├── __init__.py
│   ├── crypto.py                    # KD2 Argon2id, PBKDF2-HMAC-SHA512, MTProto AES-256-IGE
│   ├── hardware.py                  # Dynamic CPU/RAM resource scaling and process priority
│   ├── tdata_parser.py              # TDF$ format parser, MD5 integrity, Zip-Slip defense
│   ├── dc_extractor.py              # Multi-DC keys, TLV maps parser, Pure-Python TData serializer
│   └── session_manager.py           # SQLite .session creation & Pure-Python multi-account conversion
│
├── modules/                         # Functional CLI and operational modules
│   ├── __init__.py
│   ├── harvester.py                 # TData discovery and lightweight archiver
│   ├── forensic_analyzer.py         # 100% offline forensic analysis and JSON report generator
│   ├── cracker.py                   # Multi-core adaptive KD2/PBKDF2 brute-force engine
│   ├── session_extractor.py         # Single and multi-account (--all) session exporter
│   ├── session_to_tdata.py          # Session-to-TData generator (Pure-Python engine)
│   ├── session_checker.py           # Remote session status and account metadata verification
│   └── restorer.py                  # In-place passcode unlocker and backup restorer
│
├── patches/                         # Compatibility layer for legacy external libraries
│   ├── README.md                    # Root-cause analysis and patch documentation
│   └── patch_opentele.py            # Automated 3-in-1 patcher
│
└── tests/                           # 22 automated unit and integration tests
    ├── test_crypto.py               # Cryptographic primitive tests
    ├── test_hardware.py             # Hardware detection and resource allocation tests
    ├── test_parser_and_extractor.py # Zip-Slip, .tar.xz, TLV maps, 16-account & TDF$ tests
    ├── test_e2e_pipeline.py         # Pure-Python multi-account tdata, forensic audit & E2E tests
    └── run_all_tests.py             # Test runner orchestrator
```
