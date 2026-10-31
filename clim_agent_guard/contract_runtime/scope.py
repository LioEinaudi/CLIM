"""Conservative literal and directory/** resource policy, no arbitrary glob."""
from __future__ import annotations
import re
import unicodedata

class ContractError(ValueError):
    def __init__(self, code: str):
        self.code=code
        super().__init__(code)

def require(ok: bool, code: str) -> None:
    if not ok:
        raise ContractError(code)

def safe_identifier(value: object, code: str='INVALID_IDENTIFIER') -> str:
    require(isinstance(value,str) and bool(re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.:-]{0,79}', value)),code)
    return value

def resource(value: object, pattern: bool=False) -> str:
    require(isinstance(value,str) and 0 < len(value) <= 1024,'UNSAFE_RESOURCE')
    prefix=value[:-3] if pattern and value.endswith('/**') else value
    parts=prefix.split('/')
    require(not prefix.startswith('/') and not prefix.endswith('/') and
            all(part not in ('','.','..') for part in parts) and
            not any(ch in prefix for ch in '*?[]\\') and
            all(p not in {'.git','.codex','.clim'} for p in parts) and
            unicodedata.normalize('NFC',value)==value and
            not any(unicodedata.category(ch).startswith('C') for ch in value), 'UNSAFE_RESOURCE')
    return value

def scope_patterns(items: object, allow_empty: bool=False) -> list[str]:
    require(isinstance(items,list) and (allow_empty or bool(items)) and len(items)<=100,'INVALID_SCOPE')
    return list(dict.fromkeys(resource(x,True) for x in items))

def contains(parent: str, child: str) -> bool:
    return parent==child or (parent.endswith('/**') and child.startswith(parent[:-2]))

def intersects(a: str, b: str) -> bool:
    return contains(a,b) or contains(b,a)

def authorized(paths: list[str], allowed: list[str], denied: list[str]) -> bool:
    return all(any(contains(a,p) for a in allowed) and not any(contains(d,p) for d in denied) for p in paths)
