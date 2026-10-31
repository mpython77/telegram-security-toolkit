# Python 3.13 / 3.14+ and Telegram v7.x+ OpenTele Compatibility Guide

## 1. Root Cause Analysis

### Issue #1: Python 3.13 / 3.14+ Internal Class Attributes (`opentele/utils.py`)
Starting with Python 3.13 (and continuing in Python 3.14+), the interpreter introduced internal class attributes into `__dict__` during dynamic class evaluation:
- `__firstlineno__` (integer indicating the starting line number of the class definition)
- `__static_attributes__` (tuple of static attribute names)

The `opentele` package uses a custom `@extend_class` decorator to mutate base classes (`opentele/utils.py`):
```python
newAttributes = dict(decorated_cls.__dict__)
crossDelete = ["__abstractmethods__", "__module__", "_abc_impl", "__doc__"]
```
Because `opentele` only stripped those four legacy attributes, the presence of `__firstlineno__` and `__static_attributes__` caused attribute ID collisions, throwing `raise BaseException("err")` at runtime and preventing imports.

### Issue #2: Modern Telegram Desktop v4.x–v7.x+ `maps` Format (`opentele/td/account.py`)
In Telegram Desktop versions 4.0 through 7.x+, several new `lskType` block structures were added to `<account_folder>/maps` (`lskCustomEmojiKeys = 23`, `lskSearchSuggestions = 24`, `lskWebviewTokens = 25`, etc.).
Because `opentele/td/account.py` had not been maintained, encountering `keyType == 23` raised `TDataReadMapDataFailed("Unknown key type in encrypted map: 23")`, aborting initialization and failing to load modern `tdata` accounts.

### Issue #3: Multi-Account Infinite Recursion in `Account.api` (`opentele/td/account.py`)
When loading two or more accounts (`D877F783D5D3EF8Cs`, `A7FDF864FBC10B77s`, ...) within a single `TDesktop` instance, `Account.__init__` executes `self.api = api.copy()`. The bidirectional setter synchronization between `Account.api` and `TDesktop.api` triggered an infinite recursive loop:
`RecursionError: maximum recursion depth exceeded`.

---

## 2. The Solution

The `patch_opentele.py` script automatically addresses all three issues:
1. Appends `"__firstlineno__"` and `"__static_attributes__"` to `crossDelete` in `opentele/utils.py`.
2. Patches `opentele/td/account.py` so encountering unrecognized future `lskType` entries exits the TLV loop cleanly without crashing, preserving all primary DC keys (`[1, 2, 4, 5]`) and profile data.
3. Compares `api_id` values instead of object memory identity in the `Account.api` setter, eliminating the multi-account `RecursionError`.

### Applying the Patch (Single Command):
```bash
python patches/patch_opentele.py
```
or via the main orchestrator:
```bash
python main.py --patch
```
