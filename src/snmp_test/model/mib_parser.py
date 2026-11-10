"""Tolerant, line-oriented SMI parser for the vendor MIB shipped with this repo.

The input file is *not* strict SMIv2 (module name contains hyphens, ``Integer32{...}``
inline enumerations, 71 commented-out definitions, multi-line quoted DESCRIPTIONs,
mixed tabs/CRLF).  Strict compilers such as pysmi reject it, so this module implements
a two-pass tolerant parser:

1. strip ``--`` comments (quote-aware, keeping line numbers and commented stats);
2. assemble definition blocks with a small state machine, then resolve numeric OIDs
   from ``::= { parent N }`` in :mod:`snmp_test.model.mib_model`.

Nothing here ever writes to the MIB file.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

NAME = r"[A-Za-z][A-Za-z0-9_-]*"

DECL_RE = re.compile(rf"^({NAME})\s+(OBJECT-TYPE|OBJECT\s+IDENTIFIER)\b(.*)$", re.I)
TYPEDEF_RE = re.compile(rf"^({NAME})\s*::=\s*(.*)$")
OID_ASSIGN_RE = re.compile(rf"::=\s*\{{\s*({NAME}|\d+)\s+(\d+)\s*\}}")
SYNTAX_RE = re.compile(
    r"\bSYNTAX\b(.*?)(?=\b(?:MAX-ACCESS|ACCESS|STATUS|DESCRIPTION|INDEX)\b|::=\s*\{|\Z)",
    re.S | re.I,
)
ACCESS_RE = re.compile(r"\b(?:MAX-ACCESS|ACCESS)\s+([A-Za-z][A-Za-z0-9-]*)", re.I)
STATUS_RE = re.compile(r"\bSTATUS\s+([A-Za-z][A-Za-z0-9-]*)", re.I)
DESCRIPTION_RE = re.compile(r'\bDESCRIPTION\s*"([\s\S]*?)"', re.I)
INDEX_RE = re.compile(r"\bINDEX\s*\{([\s\S]*?)\}", re.I)
ENUM_ITEM_RE = re.compile(rf"({NAME})\s*\(\s*(-?\d+)\s*\)")
RANGE_RE = re.compile(r"\(\s*(-?\d+)\s*\.\.\s*(-?\d+)\s*\)")
SIZE_RE = re.compile(r"SIZE\s*\(\s*(\d+)\s*\.\.\s*(\d+)\s*\)", re.I)
MEMBER_RE = re.compile(rf"^\s*({NAME})\s+({NAME})\s*,?\s*$")

COMMENTED_OT_RE = re.compile(rf"^\s*--\s*{NAME}\s+OBJECT-TYPE\b", re.I)
COMMENTED_OID_RE = re.compile(rf"^\s*--\s*{NAME}\s+OBJECT\s+IDENTIFIER\b", re.I)
COMMENTED_SYNTAX_RE = re.compile(r"^\s*--\s*SYNTAX\b", re.I)
SECTION_RE = re.compile(r"^\s*--\s*\S+\s+start\b", re.I)


@dataclass
class RawDefinition:
    name: str
    kind: str  # object_type | object_identifier | sequence_type
    source_line: int
    parent_name: str = ""
    sub_id: int = 0
    syntax_raw: str = ""
    access: str = "read-only"
    status: str = "current"
    description: str = ""
    index_names: list[str] = field(default_factory=list)
    members: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "kind": self.kind,
            "source_line": self.source_line,
            "parent_name": self.parent_name,
            "sub_id": self.sub_id,
            "syntax_raw": self.syntax_raw,
            "access": self.access,
            "status": self.status,
            "description": self.description,
            "index_names": self.index_names,
            "members": self.members,
        }


@dataclass
class ParsedMib:
    module_name: str
    path: str
    text: str
    definitions: list[RawDefinition]
    stats: dict[str, Any]
    warnings: list[dict[str, str]]
    cleaned_lines: list[tuple[int, str, bool]]


def _strip_comments(lines: list[str]) -> list[tuple[int, str, bool]]:
    """Return ``(line_no, code, was_full_line_comment)``.

    A quote state is carried across lines because DESCRIPTION values in this MIB
    legitimately span several lines.  Full-line comments are dropped *before*
    updating the quote state so commented-out definitions cannot corrupt it.
    """
    out: list[tuple[int, str, bool]] = []
    in_quote = False
    for lineno, line in enumerate(lines, 1):
        if line.lstrip().startswith("--"):
            out.append((lineno, "", True))
            continue
        cut = len(line)
        quote = in_quote
        i = 0
        while i < len(line):
            ch = line[i]
            if ch == '"':
                quote = not quote
            elif not quote and line.startswith("--", i):
                cut = i
                break
            i += 1
        in_quote = quote
        out.append((lineno, line[:cut].rstrip(), False))
    return out


def _parse_syntax(raw: str) -> dict[str, Any]:
    raw = (raw or "").strip()
    upper = raw.upper()
    base: str
    entry_type: str | None = None
    if re.search(r"SEQUENCE\s+OF", upper):
        base = "SEQUENCE OF"
        m = re.search(rf"SEQUENCE\s+OF\s+({NAME})", raw, re.I)
        entry_type = m.group(1) if m else None
    elif "OCTET STRING" in upper:
        base = "OCTET STRING"
    elif "DISPLAYSTRING" in upper:
        base = "DisplayString"
    elif "IPADDRESS" in upper:
        base = "IpAddress"
    elif "PHYSADDRESS" in upper:
        base = "PhysAddress"
    elif "OBJECT IDENTIFIER" in upper:
        base = "OBJECT IDENTIFIER"
    elif re.search(r"\bINTEGER32\b|\bINTEGER\b", upper):
        base = "Integer32"
    else:
        first = raw.split()[0] if raw.split() else "OCTET STRING"
        base = first.strip(",;")

    enum = {m.group(1): int(m.group(2)) for m in ENUM_ITEM_RE.finditer(raw)}
    ranges = tuple((int(m.group(1)), int(m.group(2))) for m in RANGE_RE.finditer(raw))
    size_match = SIZE_RE.search(raw)
    size: tuple[int, int] | None = None
    if size_match:
        size = (int(size_match.group(1)), int(size_match.group(2)))
    elif base == "DisplayString":
        size = (0, 255)  # RFC1213-MIB DisplayString
    elif base == "IpAddress":
        size = (4, 4)

    return {
        "base_type": base,
        "enum": enum,
        "ranges": ranges,
        "size": size,
        "raw": " ".join(raw.split()),
        "entry_type": entry_type,
    }


def _parse_object_block(name: str, kind: str, lines: list[tuple[int, str]]) -> RawDefinition | None:
    text = "\n".join(code for _, code in lines)
    first_line = lines[0][0] if lines else 0
    oid_match = OID_ASSIGN_RE.search(text)
    if not oid_match:
        return None
    syntax_match = SYNTAX_RE.search(text)
    access_match = ACCESS_RE.search(text)
    status_match = STATUS_RE.search(text)
    desc_match = DESCRIPTION_RE.search(text)
    index_match = INDEX_RE.search(text)

    index_names: list[str] = []
    if index_match:
        body = index_match.group(1)
        index_names = [t for t in re.split(r"[,\s]+", body) if re.fullmatch(NAME, t)]

    syntax_raw = syntax_match.group(1).strip() if syntax_match else ""
    syntax = _parse_syntax(syntax_raw) if syntax_raw else None

    return RawDefinition(
        name=name,
        kind=kind,
        source_line=first_line,
        parent_name=oid_match.group(1),
        sub_id=int(oid_match.group(2)),
        syntax_raw=syntax["raw"] if syntax else "",
        access=(access_match.group(1).lower() if access_match else "read-only"),
        status=(status_match.group(1).lower() if status_match else "current"),
        description=" ".join((desc_match.group(1) if desc_match else "").split()),
        index_names=index_names,
    )


class MibParser:
    """Parse a single MIB file into :class:`ParsedMib`."""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)

    def parse(self) -> ParsedMib:
        text = self.path.read_text(encoding="utf-8", errors="replace").replace("\r\n", "\n").replace("\r", "\n")
        raw_lines = text.split("\n")
        cleaned = _strip_comments(raw_lines)
        warnings: list[dict[str, str]] = []

        module_name = ""
        for lineno, code, _ in cleaned:
            s = code.strip()
            if "DEFINITIONS" in s and "BEGIN" in s:
                module_name = s.split()[0]
                break
        if not module_name:
            warnings.append({"line": "1", "code": "MODULE_NAME_MISSING", "message": "DEFINITIONS ::= BEGIN not found"})
            module_name = self.path.stem
        if self.path.stem not in module_name:
            warnings.append(
                {
                    "line": "1",
                    "code": "MODULE_FILENAME_MISMATCH",
                    "message": f"module name '{module_name}' differs from file name '{self.path.name}'",
                }
            )

        definitions: list[RawDefinition] = []
        syntax_parsed: dict[str, dict[str, Any] | None] = {}
        sequence_types: dict[str, list[str]] = {}
        i = 0
        n = len(cleaned)
        while i < n:
            lineno, code, was_comment = cleaned[i]
            s = code.strip()
            if not s or was_comment:
                i += 1
                continue

            decl = DECL_RE.match(s)
            if decl:
                name = decl.group(1)
                kind = "object_type" if decl.group(2).upper().replace(" ", "") == "OBJECT-TYPE" else "object_identifier"
                block: list[tuple[int, str]] = [(lineno, s)]
                oid_match = OID_ASSIGN_RE.search(s)
                j = i + 1
                while oid_match is None and j < n:
                    ln2, code2, _ = cleaned[j]
                    s2 = code2.strip()
                    if s2:
                        block.append((ln2, s2))
                        oid_match = OID_ASSIGN_RE.search(s2)
                    j += 1
                    if oid_match is None and j < n:
                        nxt = cleaned[j][1].strip()
                        if DECL_RE.match(nxt) or TYPEDEF_RE.match(nxt):
                            warnings.append(
                                {
                                    "line": str(lineno),
                                    "code": "BLOCK_NOT_TERMINATED",
                                    "message": f"definition '{name}' has no '::= {{ parent N }}'; skipped",
                                }
                            )
                            break
                if oid_match is not None:
                    parsed = _parse_object_block(name, kind, block)
                    if parsed:
                        # recover the syntax dict via a second, cheap parse
                        syntax_parsed[name] = _parse_syntax(parsed.syntax_raw) if parsed.syntax_raw else None
                        definitions.append(parsed)
                i = j
                continue

            typedef = TYPEDEF_RE.match(s)
            if typedef:
                name, rhs = typedef.group(1), typedef.group(2).strip()
                block = [(lineno, s)]
                brace = s.count("{") - s.count("}")
                j = i + 1
                if "SEQUENCE" not in rhs.upper() and brace == 0:
                    # 'XxxEntry ::=' followed by 'SEQUENCE {' on the next code line
                    while j < n and not cleaned[j][1].strip():
                        j += 1
                    if j < n and "SEQUENCE" in cleaned[j][1].upper():
                        block.append((cleaned[j][0], cleaned[j][1].strip()))
                        brace += cleaned[j][1].count("{") - cleaned[j][1].count("}")
                        j += 1
                    else:
                        i = j
                        continue
                elif "SEQUENCE" not in rhs.upper():
                    i = j
                    continue
                while brace > 0 and j < n:
                    ln2, code2, _ = cleaned[j]
                    if code2.strip():
                        block.append((ln2, code2.strip()))
                    brace += code2.count("{") - code2.count("}")
                    j += 1
                members = []
                for _, line in block[1:]:
                    mm = MEMBER_RE.match(line)
                    if mm:
                        members.append(mm.group(1))
                sequence_types[name] = members
                definitions.append(
                    RawDefinition(name=name, kind="sequence_type", source_line=lineno, members=members)
                )
                i = j
                continue

            i += 1

        # ---- statistics (deliberately based on the raw source, not just parsed nodes)
        def count(pattern: re.Pattern[str]) -> int:
            return sum(1 for line in raw_lines if pattern.match(line))

        empty_desc = sum(1 for _, code, c in cleaned if not c and re.fullmatch(r'\s*""\s*', code))
        quote_only = sum(1 for _, code, c in cleaned if not c and re.fullmatch(r'\s*"\s*', code))
        # DESCRIPTION is always on its own line; the quoted value may be a complete
        # single-line string (37), an empty ``""`` (661) or a 3-line quoted block (432).
        single_desc = sum(
            1
            for _, code, c in cleaned
            if not c and re.fullmatch(r'\s*".+"\s*', code) and not re.search(r"\s*::=", code)
        )

        ot = [d for d in definitions if d.kind == "object_type"]
        oid_defs = [d for d in definitions if d.kind == "object_identifier"]
        seq_defs = [d for d in definitions if d.kind == "sequence_type"]
        table_defs = [d for d in ot if (syntax_parsed.get(d.name) or {}).get("base_type") == "SEQUENCE OF"]
        entry_defs = [d for d in ot if d.index_names]
        entry_names = {d.name for d in entry_defs}
        # entry syntax references a SEQUENCE type even if INDEX is missing
        for d in ot:
            sp = syntax_parsed.get(d.name) or {}
            if d.name not in entry_names and sp.get("base_type") in sequence_types:
                entry_defs.append(d)
                entry_names.add(d.name)
        column_defs = [d for d in ot if d.parent_name in entry_names]
        scalar_defs = [
            d for d in ot if d not in table_defs and d not in entry_defs and d not in column_defs
        ]

        access_counts: dict[str, int] = {}
        for d in ot:
            access_counts[d.access] = access_counts.get(d.access, 0) + 1

        enum_blocks = sum(
            1 for d in ot if (syntax_parsed.get(d.name) or {}).get("enum")
        )
        notifications = len(re.findall(r"\b(?:NOTIFICATION-TYPE|TRAP-TYPE)\b", text, re.I))

        stats: dict[str, Any] = {
            "source_lines": len(raw_lines),
            "object_types": len(ot),
            "object_identifiers": len(oid_defs),
            "sequence_types": len(seq_defs),
            "tables": len(table_defs),
            "entries": len(entry_defs),
            "columns": len(column_defs),
            "scalars": len(scalar_defs),
            "oid_assignments": len([d for d in definitions if d.parent_name]),
            "access": access_counts,
            "inline_enums": enum_blocks,
            "notifications": notifications,
            "commented_object_types": count(COMMENTED_OT_RE),
            "commented_object_identifiers": count(COMMENTED_OID_RE),
            "commented_syntax_lines": count(COMMENTED_SYNTAX_RE),
            "section_markers": count(SECTION_RE),
            "description_forms": {
                "empty": empty_desc,
                "single_line": single_desc,
                "multi_line": quote_only // 2,
            },
        }

        # ---- warnings about suspicious but tolerated constructs
        seen_subids: dict[tuple[str, int], str] = {}
        for d in definitions:
            if not d.parent_name:
                continue
            key = (d.parent_name, d.sub_id)
            if key in seen_subids:
                warnings.append(
                    {
                        "line": str(d.source_line),
                        "code": "DUPLICATE_SUBID",
                        "message": f"'{d.name}' reuses {d.parent_name}.{d.sub_id} (also '{seen_subids[key]}')",
                    }
                )
            else:
                seen_subids[key] = d.name
            sp = syntax_parsed.get(d.name)
            if sp and sp.get("base_type") not in {
                "Integer32", "OCTET STRING", "DisplayString", "IpAddress", "PhysAddress",
                "OBJECT IDENTIFIER", "SEQUENCE OF",
            } and sp.get("base_type") not in sequence_types:
                warnings.append(
                    {
                        "line": str(d.source_line),
                        "code": "UNKNOWN_SYNTAX",
                        "message": f"'{d.name}' uses unrecognised SYNTAX '{sp.get('base_type')}'",
                    }
                )

        parsed = ParsedMib(
            module_name=module_name,
            path=str(self.path),
            text=text,
            definitions=definitions,
            stats=stats,
            warnings=warnings,
            cleaned_lines=cleaned,
        )
        # attach auxiliary data without changing the public dataclass shape
        setattr(parsed, "syntax_parsed", syntax_parsed)
        setattr(parsed, "sequence_types", sequence_types)
        return parsed
