# Telegram Desktop Security, Forensics & Recovery Toolkit

**Telegram Desktop (`tdata`)** xavfsizligi, oflayn raqamli kriministika (*Digital Forensics*) va avtorizatsiya sessiyalarini tiklash uchun mo'ljallangan professional vositalar to'plami.

---

## 📌 Mundarija
1. [Loyiha haqida va Asosiy Imkoniyatlar](#-loyiha-haqida-va-asosiy-imkoniyatlar)
2. [Telegramning Lokal Shifrlash Arxitekturasi (KD2 va TDF$)](#-telegramning-lokal-shifrlash-arxitekturasi-kd2-va-tdf)
3. [Nega Hashcat va GPU emas, balki CPU tanlandi?](#-nega-hashcat-va-gpu-emas-balki-cpu-tanlandi)
4. [Tizim Talablari va O'rnatish](#-tizim-talablari-va-ornatish)
5. [Bosqichma-bosqich Foydalanish Yo'riqnomasi](#-bosqichma-bosqich-foydalanish-yoriqnomasi)
   - [1-qadam: TData Harvester (`--harvest`)](#1-qadam-tdata-harvester---harvest)
   - [2-qadam: Oflayn Kriministik Tahlil va JSON Audit (`--analyze`)](#2-qadam-oflayn-kriministik-tahlil-va-json-audit---analyze)
   - [3-qadam: KD2 / PBKDF2 Passcode Cracker (`--crack`)](#3-qadam-kd2--pbkdf2-passcode-cracker---crack)
   - [4-qadam: Multi-DC va Multi-Account Session Extractor (`--extract`)](#4-qadam-multi-dc-va-multi-account-session-extractor---extract)
   - [5-qadam: Pure-Python Session -> TData Converter (`--convert`)](#5-qadam-pure-python-session---tdata-converter---convert)
   - [6-qadam: TData Restorer & In-Place Passcode Unlocker (`--restore`)](#6-qadam-tdata-restorer--in-place-passcode-unlocker---restore)
   - [7-qadam: Sessiya Holatini Tekshirish (`--check`)](#7-qadam-sessiya-holatini-tekshirish---check)
   - [8-qadam: Avtomatlashtirilgan Testlar To'plami (`--test`)](#8-qadam-avtomatlashtirilgan-testlar-toplami---test)
6. [Python 3.13 / 3.14+ va Telegram v7.x+ OpenTele Patchi (`--patch`)](#-python-313--314-va-telegram-v7x-opentele-patchi---patch)
7. [Bir nechta Akkauntni Ishlatish (Multi-Account va Telegram Portable)](#-bir-nechta-akkauntni-ishlatish-multi-account-va-telegram-portable)
8. [Git va Xavfsizlik Qoidalari](#-git-va-xavfsizlik-qoidalari)
9. [Loyiha Arxitekturasi](#-loyiha-arxitekturasi)

---

## 🚀 Loyiha haqida va Asosiy Imkoniyatlar

Ushbu to'plam barcha jarayonlarni yagona markazlashgan interfeys (`main.py`) orqali bajaradi:

* **📦 Yengil Harvester (`--harvest`):** Kompyuterdagi (AppData, Microsoft Store UWP, Portable, Linux Snap/Flatpak, macOS) Telegram o'rnatmalaridan gigabaytlab keraksiz media va keshni tashlab, faqat shifrlangan eng zaruriy sessiya fayllarini ixcham `.zip` arxivga yig'adi.
* **🔬 100% Oflayn Kriministik Tahlil (`--analyze`):** Tarmoqqa umuman ulanmasdan har qanday `.zip`, `.tar.xz`, `tdata` papkasi yoki `.session` faylning SHA-256 xeshini, `TDF$` MD5 butunligini, KDF parametrlarini, oflayn foydalanuvchi profilini (`Ism`, `@username`, `+telefon`, `User ID`, `Bio`), har bir DC kalitining 64-bitli MTProto `auth_key_id` barmoq izini va `maps` ichidagi barcha `lskType` bloklarini tahlil qilib, JSON hisobot chiqaradi.
* **🔓 Dual-KDF Multi-Core Cracker (`--crack`):** Telegramning yangi **KD2 (`Argon2id` + `AES-256-IGE`)** hamda standart/eski **`PBKDF2-HMAC-SHA512`** lokal parolini mavjud CPU oqimlari va bo'sh RAM hajmiga moslashgan holda parallel ravishda ochadi.
* **🔑 Multi-DC va Multi-Account Session Extractor (`--extract`):** Shifrlangan `.s` va `maps` fayllaridan barcha Data Center (`DC 1, 2, 4, 5`) kalitlarini hamda oflayn profilni ajratib olib, bitta yoki barcha (`--all`) akkauntlar uchun tayyor Telethon SQLite `.session` yaratadi.
* **🚀 100% Pure-Python `Session -> TData` Konverter (`--convert`):** Tashqi `PyQt5` yoki `opentele` kutubxonalarisiz, sof Python kriptografik seriyalash dvigateli yordamida bitta yoki bir nechta `.session` fayllarini parolsiz, toza `tdata` papkasiga (16 tagacha akkauntni bitta `tdata` ga birlashtirgan holda) aylantiradi.
* **🔄 In-Place Passcode Unlocker & Restorer (`--restore`):** Backup arxivini (`.zip`, `.tar.xz`, `.tar.gz`) yoki `tdata` papkasini barcha 4 ta DC kalitlari (`[1, 2, 4, 5]`), `maps`, qoralamalar (`lskDraft`), stikerlar va kesh fayllarini **100% saqlagan holda** lokal PIN/parolni joyida olib tashlab, to'g'ridan-to'g'ri Telegram Desktop ichiga tiklaydi.
* **🛡️ Xavfsiz Arxivlash (Zip-Slip Defense):** Noma'lum manbadan olingan `.zip` va `.tar.xz` arxivlarni ochishda `../../` ko'rinishidagi Path Traversal va zararli symlink hujumlarini avtomatik bloklaydi.

---

## 🔐 Telegramning Lokal Shifrlash Arxitekturasi (KD2 va TDF$)

Telegram Desktop o'zining barcha lokal ma'lumotlarini `tdata` papkasida maxsus shifrlangan konteynerlarda saqlaydi.

### 1. Fayl formati (`TDF$`):
Barcha shifrlangan fayllar (`key_datas`, `D877F783D5D3EF8Cs`, `maps`, `configs`, `settings`) quyidagi binar tuzilishga ega:
* **0..4 bayt:** Magic header `TDF$`
* **4..8 bayt:** Telegram versiyasi (Little-Endian `uint32`, masalan `7003003` -> `v7.3.3`)
* **8..N-16 bayt:** Shifrlangan asosiy yuklama (Payload)
* **Oxirgi 16 bayt:** `MD5(payload + len(payload) + version + "TDF$")` nazorat summasi

### 2. KD2 Tuzilmasi (`key_datas`):
Lokal parol (Passcode) o'rnatilganda Telegram `KD2\0` (Key Derivation v2) algoritmini ishga tushiradi:
* **Algoritm:** `Argon2id` (v13, `kdf_id = 1`)
* **Xotira sarfi (`memory_cost`):** `65536 KiB` (har bir urinish uchun 64 MB operativ xotira)
* **Iteratsiyalar soni (`time_cost`):** `8` qadam
* **Oqimlar soni (`parallelism`):** `1` oqim
* **Salt:** `32` bayt
* **Shifrlangan blok (`enc_blob`):** `288` bayt (`16` bayt `key128` + `272` bayt shifrlangan ma'lumot)

Paroldan 256 baytli `wrap_key` hosil qilinadi. Ushbu `wrap_key` va `key128` orqali Telegramning `prepareAES_oldmtp` funksiyasi yordamida 32 baytli AES-256 kaliti va 32 baytli IV yasaladi. AES-256-IGE orqali shifrdan yechilgan blokning SHA-1 heshining dastlabki 16 bayti `key128` ga teng kelsa, parol to'g'ri deb topiladi va ichidan 256 baytli master **LocalKey** olinadi. Parol o'rnatilmagan (`passcode = ""`) holatda esa `kdf_id = 0` (`PBKDF2-HMAC-SHA512`, 1 iteratsiya) ishlatiladi.

---

## ⚡ Nega Hashcat va GPU emas, balki CPU tanlandi?

1. **Hashcatda KD2 moduli yo'q:** Hashcat faqat Telegramning eski PBKDF2 shifrlashini qo'llab-quvvatlaydi (`-m 22600` va `-m 24500`). Zamonaviy `Argon2id + MTProto AES-IGE` bo'lgan KD2 algoritmi Hashcatda mavjud emas.
2. **Argon2id xotiraga bog'liq (Memory-Hard):**
   * Argon2id har bitta urinish uchun GPU yadrolarini emas, balki yuqori tezlikdagi operativ xotira (RAM va L3 Kesh) o'tkazuvchanligini talab qiladi.
   * Zamonaviy ko'p yadroli protsessorlar (masalan: 16 oqimli CPU + DDR5 RAM) har soniyada ~25–35 ta to'liq 64 MB lik Argon2id hisoblashini amalga oshiradi.
   * Shu sababli, 4-xonali barcha 10 000 ta PIN kombinatsiyasini qidirish CPUda o'rtacha **5–8 daqiqa** vaqt oladi.

---

## 📦 Tizim Talablari va O'rnatish

### 1. Talablar:
* **Python:** `3.10`, `3.11`, `3.12`, `3.13` yoki `3.14+`
* **OS:** Windows 10/11, Linux yoki macOS

### 2. O'rnatish:
Loyiha papkasiga o'ting va zarur kutubxonalarni o'rnating:
```bash
pip install -r requirements.txt
```
Yoki standart Python paketi sifatida (`pyproject.toml` orqali) o'rnating:
```bash
pip install -e .
```

Asosiy kutubxonalar:
* `telethon` — Telegram MTProto API mijozi
* `tgcrypto` — C tilida yozilgan tezkor AES-256-IGE shifrlash kutubxonasi
* `argon2-cffi` — C darajasidagi rasmiy Argon2id implementatsiyasi
* `pycryptodome` — Kriptografik primitivlar
* `opentele` *(ixtiyoriy)* — Qo'shimcha moslashuvchanlik uchun (asosiy `session -> tdata` dvigateli Pure-Python'da yozilgan bo'lib, `opentele` va `PyQt5` siz ham to'liq ishlaydi)

---

## 🛠️ Bosqichma-bosqich Foydalanish Yo'riqnomasi

Barcha amallarni yagona interaktiv menyudan boshqarishingiz mumkin:
```bash
python main.py
```
Yoki buyruqlar satri (CLI) orqali to'g'ridan-to'g'ri chaqirishingiz mumkin:

---

### 1-qadam: TData Harvester (`--harvest`)
Kompyuterdagi barcha Telegram Desktop o'rnatmalarini topadi va keraksiz keshni tashlab, faqat sessiya uchun muhim fayllardan ixcham ZIP arxiv yaratadi:
```bash
python main.py --harvest -o .
```
Maxsus papkani ko'rsatish uchun:
```bash
python main.py --harvest -p "C:\Custom\Telegram\tdata" -o .
```

---

### 2-qadam: Oflayn Kriministik Tahlil va JSON Audit (`--analyze`)
Tarmoqqa umuman ulanmasdan (100% oflayn) har qanday `.zip`, `.tar.xz`, `tdata` papkasi yoki `.session` faylning butunligini, KDF parametrlarini, oflayn foydalanuvchi profilini, DC kalitlarining 64-bitli `auth_key_id` barmoq izlarini va `maps` ichidagi `lskType` bloklarini tahlil qiladi:
```bash
# Parolsiz yoki qulflangan arxivni tekshirish:
python main.py --analyze -s "TG_Backup_Windows_....zip"

# Parol ma'lum bo'lsa, ichki profil va kalitlarni ham ochib JSON hisobotga saqlash:
python main.py --analyze -s "TG_Backup_Windows_....zip" -p 1111 -j audit_report.json
```

---

### 3-qadam: KD2 / PBKDF2 Passcode Cracker (`--crack`)
Arxivdagi (`.zip`, `.tar.xz`) yoki `tdata` papkasidagi `key_datas` faylini tekshirib, lokal parolni ko'p yadroli CPUda parallel qidiradi:
```bash
# 4-xonali PIN-kodlar (0000-9999):
python main.py --crack -s "TG_Backup_Windows_....zip" --mode pin4

# 6-xonali PIN-kodlar (000000-999999):
python main.py --crack -s "TG_Backup_Windows_....zip" --mode pin6

# Muayyan sonlar oralig'i:
python main.py --crack -s "TG_Backup_Windows_....zip" --mode range --start 1000 --end 2000

# Wordlist (parollar lug'ati):
python main.py --crack -s "TG_Backup_Windows_....zip" --mode wordlist -w passwords.txt
```
Topilgan parol va 256-baytlik kalit `found_passcode.txt` hamda `found_local_key.bin` fayllariga saqlanadi.

---

### 4-qadam: Multi-DC va Multi-Account Session Extractor (`--extract`)
Arxiv yoki `tdata` papkasidan barcha Data Center (`DC 1, 2, 4, 5`) kalitlarini va oflayn profilni ajratib olib, Telethon SQLite `.session` fayliga eksport qiladi:
```bash
# Asosiy akkauntni ajratib olish:
python main.py --extract -s "TG_Backup_Windows_....zip" -p 1111 -o account.session

# Backup ichidagi BARCHA faol akkauntlarni alohida .session fayllariga ajratish:
python main.py --extract -s "TG_Backup_Windows_....zip" -p 1111 --all -o ./sessions/

# Muayyan indeksdagi akkauntni tanlash (masalan, 1-indeks):
python main.py --extract -s "TG_Backup_Windows_....zip" -p 1111 --account-index 1
```

---

### 5-qadam: Pure-Python Session -> TData Converter (`--convert`)
Bitta yoki bir nechta `.session` faylini **100% Pure-Python dvigateli** yordamida parolsiz, toza `tdata` papkasiga aylantiradi:
```bash
# Bitta .session faylidan toza tdata yaratish:
python main.py --convert -s account.session -o "C:\Telegram_Clean\tdata"

# Bir nechta .session fayllarini bitta Multi-Account tdata papkasiga birlashtirish:
python main.py --convert -s acc1.session acc2.session -o "C:\Telegram_Multi\tdata"
```

---

### 6-qadam: TData Restorer & In-Place Passcode Unlocker (`--restore`)
Har qanday backup arxivini (`.zip`, `.tar.xz`, `.tar.gz`) yoki `tdata` papkasini **barcha 4 ta DC kalitlari (`[1, 2, 4, 5]`), `maps` (oflayn profil), qoralamalar (`lskDraft`), stikerlar va lokal kesh fayllarini 100% saqlagan holda** lokal PIN/parolni joyida olib tashlab, Telegram Desktop papkasiga tiklaydi:
```bash
# Parol ma'lum bo'lsa:
python main.py --restore -s "TG_Backup_Windows_....zip" -t "C:\Telegram_Portable\tdata" -p 1111

# Parol noma'lum bo'lsa (4-xonali PIN-kodni avtomatik topib, parolsiz tiklash):
python main.py --restore -s "TG_Backup_Windows_....zip" -t "C:\Telegram_Portable\tdata" --auto-crack
```

---

### 7-qadam: Sessiya Holatini Tekshirish (`--check`)
Sessiyaning serverda faolligini rasmiy Telegram Desktop qurilma sarlavhalari orqali tekshiradi, profil ma'lumotlari, ulangan qurilmalar va oxirgi dialoglarni ko'rsatadi (sessiya serverdan o'chirilgan bo'lsa ham, fayl ichidagi oflayn profilni ekranga chiqaradi):
```bash
python main.py --check -s account.session
```

---

### 8-qadam: Avtomatlashtirilgan Testlar To'plami (`--test`)
Kriptografik primitivlar, xotira hisoblashlari, Zip-Slip himoyasi, `.tar.xz` universal o'qish, ko'p blokli `maps` TLV parslovi, Pure-Python multi-account `tdata` konvertatsiyasi va E2E tiklash zanjiridan iborat **22 ta avtomatlashtirilgan testni** ishga tushiradi:
```bash
python main.py --test
```

---

## 🩹 Python 3.13 / 3.14+ va Telegram v7.x+ OpenTele Patchi (`--patch`)

Asosiy `SessionManager.session_to_tdata` dvigateli Pure-Python'da ishlaydi va `opentele` ga muhtoj emas. Biroq, agar tizimingizda `opentele` kutubxonasidan qo'shimcha foydalanmoqchi bo'lsangiz, undagi 3 ta arxitekturaviy xatoni avtomatik tuzatuvchi patch mavjud:
1. **Python 3.13 / 3.14+ `__firstlineno__` va `__static_attributes__` xatosi** (`opentele/utils.py`);
2. **Telegram Desktop v4.x–v7.x+ yangi `maps` `lskType` (`23, 24, 25+`) xatosi** (`opentele/td/account.py`);
3. **Ko'p akkauntli (`Multi-Account`) `tdata` yuklashda `Account.api` cheksiz `RecursionError` xatosi** (`opentele/td/account.py`).

Patchni o'rnatish:
```bash
python main.py --patch
```

---

## 👥 Bir nechta Akkauntni Ishlatish (Multi-Account va Telegram Portable)

1. **Bitta Telegram ichida bir nechta akkaunt:**
   `python main.py --convert -s acc1.session acc2.session -o "C:\Telegram_Portable\tdata"` buyrug'i orqali 16 tagacha akkauntni bitta `tdata` papkasiga joylashtirishingiz mumkin.
2. **Alohida Telegram Portable nusxasi:**
   Rasmiy **Telegram Desktop Portable** versiyasini alohida papkaga (masalan: `C:\Telegram_2`) joylab, ichiga tiklangan `tdata` papkasini qo'ysangiz, asosiy Telegram va Portable Telegram bir-biriga xalaqit bermasdan parallel ishlaydi.

---

## 🛡️ Git va Xavfsizlik Qoidalari

1. **Repository'ni PRIVATE (Yopiq) saqlang:** Maxfiy kalitlar va xavfsizlik vositalarini ochiq (Public) repozitoriyga yuklamang.
2. **`.gitignore` himoyasi:** Loyiha ichidagi `.gitignore` fayli shaxsiy sessiyalar (`*.session`), binar kalitlar (`*.bin`), parollar (`found_*.txt`), JSON audit hisobotlari va arxivlar (`*.zip`, `*.xz`) gitga tushib ketishini avtomatik bloklaydi.

---

## 🏛️ Loyiha Arxitekturasi

```text
Telegram_Security_Toolkit/
│
├── README.md                        # Texnik va amaliy qo'llanma
├── pyproject.toml                   # Standart Python paket konfiguratsiyasi (v2.0.0)
├── requirements.txt                 # Zarur kutubxonalar ro'yxati
├── .gitignore                       # Maxfiy ma'lumotlar va sessiyalar himoyasi
├── main.py                          # Yagona interaktiv menyu va CLI orkestratori
│
├── core/                            # Kriptografik va binar tahlil yadrosi
│   ├── __init__.py
│   ├── crypto.py                    # KD2 Argon2id, PBKDF2-HMAC-SHA512, MTProto AES-256-IGE
│   ├── hardware.py                  # Dinamik CPU oqimlari va RAM xotirani xavfsiz boshqarish
│   ├── tdata_parser.py              # TDF$ formati, MD5 nazorati, Zip-Slip himoyasi, universal loader
│   ├── dc_extractor.py              # Multi-DC AuthKey, TLV maps parseri, Pure-Python TData seriyalash
│   └── session_manager.py           # SQLite .session yaratish va Pure-Python multi-account session->tdata
│
├── modules/                         # Amaliy CLI va SDK modullari
│   ├── __init__.py
│   ├── harvester.py                 # TData qidiruvchi va ixcham ZIP arxivlovchi
│   ├── forensic_analyzer.py         # 100% oflayn kriministik tahlil va JSON audit hisoboti
│   ├── cracker.py                   # Ko'p oqimli adaptiv KD2 / PBKDF2 parol tiklovchi
│   ├── session_extractor.py         # Bitta yoki barcha (--all) akkauntlardan .session ajratuvchi
│   ├── session_to_tdata.py          # Bitta yoki bir nechta .session ni toza tdata ga aylantiruvchi
│   ├── session_checker.py           # Sessiya faolligi va profil ma'lumotlarini tekshiruvchi
│   └── restorer.py                  # Backupni parolsiz holatda to'liq tiklovchi (In-Place Unlocker)
│
├── patches/                         # Qo'shimcha OpenTele moslashuvchanlik paketi
│   ├── README.md                    # OpenTele 3 ta xatosining texnik tahlili
│   └── patch_opentele.py            # Avtomatik 3-in-1 patch skripti
│
└── tests/                           # 22 ta avtomatlashtirilgan Unit va E2E testlar to'plami
    ├── test_crypto.py               # Kriptografik primitivlar testi
    ├── test_hardware.py             # Uskuna va xotira boshqaruvi testi
    ├── test_parser_and_extractor.py # Zip-Slip, .tar.xz, TLV maps, 16-account va TDF$ testlari
    ├── test_e2e_pipeline.py         # Pure-Python multi-account tdata, forensic audit va E2E zanjir
    └── run_all_tests.py             # Barcha testlarni yagona buyruqda ishga tushiruvchi
```
