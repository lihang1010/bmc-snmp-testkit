"""Optional pysmi-backed helpers for generic MIB imports.

pysmi's SMIv2 parser is used for two things that the tolerant line parser
cannot do reliably:

* extract ``IMPORTS ... FROM`` dependencies (for diagnostics / the warnings API);
* perform a strict SMIv2 syntax check (an informational signal, not a gate).

Full pysmi *compilation* into a MIB tree is intentionally not attempted: it
requires the ASN.1 text of every imported module, which is not available
offline.  The actual node tree is always produced by our tolerant parser plus
the built-in standard symbol table (``model.mib_deps``), so a missing or
failing pysmi installation never changes the resulting model.
"""

from __future__ import annotations

from typing import Any


def smi_info(text: str) -> dict[str, Any]:
    """Return ``{parser, imports, strict_ok, error}`` for an uploaded MIB."""
    info: dict[str, Any] = {
        "parser": "tolerant+pysmi-check",
        "imports": {},
        "strict_ok": None,
        "error": None,
    }
    try:
        from pysmi.parser import SmiV2Parser
    except ImportError:
        info["parser"] = "tolerant"
        info["error"] = "pysmi 未安装，跳过严格 SMI 语法检查"
        return info
    try:
        ast = SmiV2Parser().parse(text)
    except Exception as exc:  # non-strict vendor MIBs are expected to fail
        info["strict_ok"] = False
        info["error"] = f"SMIv2 严格语法检查失败: {type(exc).__name__}: {exc}"
        return info
    info["strict_ok"] = True
    if ast:
        entry = ast[0]
        imports = entry[2] if isinstance(entry, (tuple, list)) and len(entry) > 2 else {}
        if isinstance(imports, dict):
            info["imports"] = {
                str(module): [str(sym) for sym in (symbols or [])]
                for module, symbols in imports.items()
            }
    return info


__all__ = ["smi_info"]
