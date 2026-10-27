# Python 3.13 / 3.14+ OpenTele Moslashuvchanlik Qo'llanmasi

## 1. Muammoning tub mohiyati (Root Cause)

Python 3.13 versiyasidan boshlab (va kelgusi Python 3.14 da) Python interpretatori klasslarni dinamik yaratish va tekshirish tizimini yangiladi.
Natijada har bir Python klassi uchun standart `__dict__` ichiga yangi ichki atributlar qo'shildi:
- `__firstlineno__` (klass qaysi satrda boshlanganini bildiruvchi int)
- `__static_attributes__` (statik atributlar nomi tuple)

### Nega OpenTele yiqiladi?
`opentele` kutubxonasida klasslarni kengaytirish uchun `@extend_class` dekoratori ishlatiladi (`opentele/utils.py`, 100-125 satrlar atrofida):
```python
newAttributes = dict(decorated_cls.__dict__)
crossDelete = ["__abstractmethods__", "__module__", "_abc_impl", "__doc__"]
```
OpenTele faqatgina shu 4 ta atributni tozalab tashlaydi. Yangi paydo bo'lgan `__firstlineno__` va `__static_attributes__` esa lug'atda qolib ketadi!

Keyin esa quyidagi taqqoslash kodiga keladi:
```python
if result != None:
    if id(result["value"]) == id(attributeValue):
        crossDelete[attributeName] = attributeValue
    else:
        if not override.isOverride(attributeValue):
            print(f"[{attributeName}] {id(result['value'])} - {id(attributeValue)}")
            raise BaseException("err")
```
Chunki har bir sinfda `__firstlineno__` har xil qiymat va alohida xotira manziliga (`id`) ega bo'ladi. Ular mos kelmagani uchun va `override` deb belgilanmagani uchun dastur `raise BaseException("err")` tashlab, butunlay to'xtaydi!

---

## 2. Yechim

Yechim juda oddiy va aniq: `crossDelete` ro'yxatiga ushbu yangi dunder atributlarni ham qo'shib qo'yish kerak.

### Avtomatik yechim (1 ta buyruq):
```bash
python patches/patch_opentele.py
```

### Qo'lda yechim (Manual):
O'zingizning Python `site-packages` papkangizdagi `opentele/utils.py` faylini oching (masalan: `AppData\Roaming\Python\Python313\site-packages\opentele\utils.py`).

93-satrdagi:
```python
crossDelete = ["__abstractmethods__", "__module__", "_abc_impl", "__doc__"]
```
satrini quyidagiga o'zgartiring:
```python
crossDelete = ["__abstractmethods__", "__module__", "_abc_impl", "__doc__", "__firstlineno__", "__static_attributes__"]
```

Faylni saqlang. Shundan so'ng `opentele.td` va `opentele.tl` hech qanday xatosiz ishlaydi.
