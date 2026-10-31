# Python 3.13 / 3.14+ va Telegram v7.x+ OpenTele Moslashuvchanlik Qo'llanmasi

## 1. Muammolarning tub mohiyati (Root Cause)

### Muammo #1: Python 3.13 / 3.14+ klass atributlari (`opentele/utils.py`)
Python 3.13 versiyasidan boshlab (va Python 3.14 da) interpretator klasslarni dinamik yaratish tizimini yangiladi. Natijada har bir Python klassining `__dict__` lug'atiga yangi ichki atributlar qo'shildi:
- `__firstlineno__` (klass qaysi satrda boshlanganini bildiruvchi `int`)
- `__static_attributes__` (statik atributlar nomi `tuple`)

`opentele` kutubxonasida klasslarni kengaytirish uchun `@extend_class` dekoratori ishlatiladi (`opentele/utils.py`):
```python
newAttributes = dict(decorated_cls.__dict__)
crossDelete = ["__abstractmethods__", "__module__", "_abc_impl", "__doc__"]
```
OpenTele faqatgina shu 4 ta atributni tozalaydi. Yangi `__firstlineno__` va `__static_attributes__` esa lug'atda qolib ketadi va `raise BaseException("err")` xatosi bilan to'xtab qoladi.

### Muammo #2: Zamonaviy Telegram Desktop v4.x–v7.x+ `maps` formati (`opentele/td/account.py`)
Telegram Desktop 4.0 dan 7.x gacha bo'lgan versiyalarida `<account_folder>/maps` fayliga yangi `lskType` bloklari (`lskCustomEmojiKeys = 23`, `lskSearchSuggestions = 24`, `lskWebviewTokens = 25` va boshqalar) qo'shildi.
`opentele/td/account.py` ichidagi `MapData.read()` funksiyasi yangilanmagani sababli, `keyType == 23` ni ko'rganda `TDataReadMapDataFailed("Unknown key type in encrypted map: 23")` xatosini tashlaydi va zamonaviy `tdata` papkalarini o'qiy olmaydi.

### Muammo #3: Ko'p Akkauntli (`Multi-Account`) `tdata` da `RecursionError` (`opentele/td/account.py`)
`TDesktop` obyekti ichida 2 va undan ortiq akkaunt (`D877F783D5D3EF8Cs`, `A7FDF864FBC10B77s`, ...) yuklanganda, `Account.__init__` ichidagi `self.api = api.copy()` chaqiruvi `Account.api` va `TDesktop.api` setterlari o'rtasida cheksiz sikl (`RecursionError: maximum recursion depth exceeded`) keltirib chiqaradi.

---

## 2. Yechim

`patch_opentele.py` vositasi uchala muammoni ham avtomatik ravishda 1 soniyada hal qiladi:
1. `opentele/utils.py` ichidagi `crossDelete` ro'yxatiga `"__firstlineno__"` va `"__static_attributes__"` ni qo'shadi.
2. `opentele/td/account.py` ichidagi `MapData.read` siklida yangi `lskType` identifikatorlari kelganda xato otish o'rniga `break` qilib, barcha asosiy ma'lumotlarni va 4 ta DC kalitlarini (`[1, 2, 4, 5]`) to'liq yuklashni ta'minlaydi.
3. `opentele/td/account.py` ichidagi `Account.api` setterida obyektlarning xotira manzillarini emas, balki `api_id` qiymatini solishtirib, ko'p akkauntli `RecursionError` xatosini bartaraf etadi.

### Avtomatik o'rnatish (1 ta buyruq):
```bash
python patches/patch_opentele.py
```
yoki:
```bash
python main.py --patch
```
