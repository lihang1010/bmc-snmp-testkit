"""Resolve parsed definitions into a numeric OID tree and a :class:`MibModel`."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from .mib_parser import MibParser, ParsedMib
from .types import MibModel, MibNode, SyntaxSpec

BUILTIN_OIDS: dict[str, str] = {
    "iso": "1",
    "org": "1.3",
    "dod": "1.3.6",
    "internet": "1.3.6.1",
    "directory": "1.3.6.1.1",
    "mgmt": "1.3.6.1.2",
    "mib-2": "1.3.6.1.2.1",
    "experimental": "1.3.6.1.3",
    "private": "1.3.6.1.4",
    "enterprises": "1.3.6.1.4.1",
    "security": "1.3.6.1.5",
    "snmpV2": "1.3.6.1.6",
    "snmpDomains": "1.3.6.1.6.1",
    "snmpProxys": "1.3.6.1.6.2",
    "snmpModules": "1.3.6.1.6.3",
    "zeroDotZero": "0.0",
}


def _syntax_from_parsed(parsed: dict[str, Any] | None) -> SyntaxSpec | None:
    if not parsed:
        return None
    return SyntaxSpec(
        base_type=str(parsed.get("base_type", "OCTET STRING")),
        enum={str(k): int(v) for k, v in (parsed.get("enum") or {}).items()},
        ranges=tuple((int(a), int(b)) for a, b in (parsed.get("ranges") or ())),
        size=tuple(parsed["size"]) if parsed.get("size") else None,
        raw=str(parsed.get("raw", "")),
        entry_type=parsed.get("entry_type"),
    )


def build_model(path: str | Path, root_oid: str | None = None) -> MibModel:
    """Parse ``path`` and return a fully resolved, serialisable model."""
    source = Path(path)
    parsed: ParsedMib = MibParser(source).parse()
    syntax_parsed: dict[str, dict[str, Any] | None] = getattr(parsed, "syntax_parsed", {})
    sequence_types: dict[str, list[str]] = getattr(parsed, "sequence_types", {})

    warnings = list(parsed.warnings)

    # ---- pass 1: numeric OID resolution (iterative, supports forward references)
    assignments = [d for d in parsed.definitions if d.parent_name and d.kind != "sequence_type"]
    pending = list(assignments)
    oid_of: dict[str, str] = dict(BUILTIN_OIDS)
    resolved: dict[str, Any] = {}
    progress = True
    while pending and progress:
        progress = False
        remaining = []
        for d in pending:
            parent = oid_of.get(d.parent_name)
            if parent is None:
                remaining.append(d)
                continue
            oid_of[d.name] = f"{parent}.{d.sub_id}"
            resolved[d.name] = d
            progress = True
        pending = remaining

    for d in pending:
        warnings.append(
            {
                "line": str(d.source_line),
                "code": "UNRESOLVED_PARENT",
                "message": f"'{d.name}' references unknown parent '{d.parent_name}'; node excluded",
            }
        )

    # detect duplicate numeric OIDs among resolved nodes
    oid_owner: dict[str, str] = {}
    for name, d in resolved.items():
        oid = oid_of[name]
        if oid in oid_owner:
            warnings.append(
                {
                    "line": str(d.source_line),
                    "code": "DUPLICATE_OID",
                    "message": f"'{name}' shares numeric OID {oid} with '{oid_owner[oid]}'",
                }
            )
        else:
            oid_owner[oid] = name

    # ---- pass 2: nodes + kinds
    nodes: list[MibNode] = []
    for name, d in resolved.items():
        nodes.append(
            MibNode(
                name=name,
                oid=oid_of[name],
                kind="scalar",
                access=d.access if d.kind == "object_type" else "not-accessible",
                syntax=_syntax_from_parsed(syntax_parsed.get(name)) if d.kind == "object_type" else None,
                index_names=tuple(d.index_names),
                parent_name=d.parent_name,
                sub_id=d.sub_id,
                status=d.status,
                description=d.description,
                source_line=d.source_line,
            )
        )
    by_name: dict[str, MibNode] = {n.name: n for n in nodes}

    entry_names: set[str] = set()
    table_names: set[str] = set()
    for node in nodes:
        if node.kind == "scalar" and node.parent_name in BUILTIN_OIDS and node.syntax is None:
            node.kind = "group"
            continue
        syntax = node.syntax
        if syntax and syntax.is_table:
            node.kind = "table"
            table_names.add(node.name)
        elif node.index_names or (syntax and syntax.base_type in sequence_types):
            node.kind = "entry"
            entry_names.add(node.name)

    for node in nodes:
        if node.kind == "scalar" and node.parent_name in entry_names:
            node.kind = "column"
            entry = by_name.get(node.parent_name)
            if entry and entry.parent_name in table_names:
                node.table_name = entry.parent_name

    # OBJECT IDENTIFIER definitions must be groups even if they carry a syntax
    for node in nodes:
        d = resolved[node.name]
        if d.kind == "object_identifier":
            node.kind = "group"
            node.access = "not-accessible"

    # ---- tables summary
    tables: list[dict[str, Any]] = []
    for table in nodes:
        if table.kind != "table":
            continue
        entry = next(
            (n for n in nodes if n.kind == "entry" and n.parent_name == table.name), None
        )
        columns = [n for n in nodes if n.kind == "column" and n.table_name == table.name]
        tables.append(
            {
                "name": table.name,
                "oid": table.oid,
                "entry_name": entry.name if entry else "",
                "entry_oid": entry.oid if entry else "",
                "index_names": list(entry.index_names) if entry else [],
                "column_count": len(columns),
                "columns": [c.name for c in columns],
            }
        )

    stats = dict(parsed.stats)
    stats["resolved_nodes"] = len(nodes)
    stats["unresolved_nodes"] = len(pending)
    stats["by_kind"] = {
        kind: sum(1 for n in nodes if n.kind == kind)
        for kind in ("group", "table", "entry", "column", "scalar")
    }
    stats["root_oid"] = root_oid or oid_of.get("ttyRoot", "1.3.6.1.4.1.52305")

    model = MibModel(
        module_name=parsed.module_name,
        mib_path=str(source),
        mib_sha256=MibModel.hash_file(source),
        root_oid=stats["root_oid"],
        nodes=nodes,
        stats=stats,
        warnings=warnings,
        tables=tables,
        sequence_types={k: list(v) for k, v in sequence_types.items()},
    )
    return model.reindex()


def load_model(path: str | Path) -> MibModel:
    import json

    return MibModel.from_dict(json.loads(Path(path).read_text(encoding="utf-8")))
