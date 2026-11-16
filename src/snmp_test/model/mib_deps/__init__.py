"""Offline standard-MIB dependency data shipped with the package.

The tolerant parser resolves ``::= { parent N }`` parents by name.  Standard
MIBs reference parents/TCs defined in imported modules (SNMPv2-SMI, SNMPv2-TC,
IF-MIB, ...), which the original single-vendor parser did not know.  This small
symbol table is the offline dependency set: no ASN.1 text files and no network
access are needed at runtime.
"""

from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path
from typing import Any

_PATH = Path(__file__).parent / "standard-symbols.json"


@lru_cache(maxsize=1)
def _load() -> dict[str, Any]:
    try:
        data = json.loads(_PATH.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {"oids": {}, "types": {}}
    return data if isinstance(data, dict) else {"oids": {}, "types": {}}


def standard_oids() -> dict[str, str]:
    """Parent symbol name -> numeric OID (merged into the model's OID table)."""
    return {str(k): str(v) for k, v in (_load().get("oids") or {}).items()}


def resolve_tc(name: str) -> str | None:
    """Map a textual convention / imported type name to a known base type."""
    if not name:
        return None
    types = _load().get("types") or {}
    if name in types:
        return str(types[name])
    lowered = name.lower()
    for key, value in types.items():
        if str(key).lower() == lowered:
            return str(value)
    return None


__all__ = ["standard_oids", "resolve_tc"]
