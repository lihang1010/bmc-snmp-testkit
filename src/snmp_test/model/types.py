"""Shared data structures for the MIB parser, case generator, runner and reporter.

All structures are plain dataclasses with explicit JSON (de)serialisation so that the
generated model and case repository are human readable and stable across runs.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, ClassVar, Iterable

SNMP_VERSIONS = ("v1", "v2c", "v3")
OPERATIONS = ("GET", "GETNEXT", "GETBULK", "SET", "TRAP", "INFORM")
ACCESS_LEVELS = ("read-only", "read-write", "write-only", "not-accessible")

# ASN.1 / SMI base types understood by the value factory and the mock agent.
INTEGER_TYPES = ("Integer32", "INTEGER")
STRING_TYPES = ("OCTET STRING", "DisplayString")
ADDRESS_TYPES = ("IpAddress", "PhysAddress")


def _tuples(value: Any) -> tuple[tuple[int, int], ...]:
    if not value:
        return ()
    return tuple((int(a), int(b)) for a, b in value)


def _str_tuple(value: Any) -> tuple[str, ...]:
    return tuple(str(x) for x in (value or ()))


@dataclass(frozen=True)
class SyntaxSpec:
    """Normalised SYNTAX clause of an OBJECT-TYPE."""

    base_type: str = "OCTET STRING"
    enum: dict[str, int] = field(default_factory=dict)
    ranges: tuple[tuple[int, int], ...] = ()
    size: tuple[int, int] | None = None
    raw: str = ""
    entry_type: str | None = None

    @property
    def is_table(self) -> bool:
        return self.base_type == "SEQUENCE OF"

    @property
    def is_integer(self) -> bool:
        return self.base_type in INTEGER_TYPES

    @property
    def is_string(self) -> bool:
        return self.base_type in STRING_TYPES

    @property
    def is_address(self) -> bool:
        return self.base_type in ADDRESS_TYPES

    @property
    def enum_values(self) -> tuple[int, ...]:
        return tuple(sorted(set(self.enum.values())))

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any] | None) -> "SyntaxSpec | None":
        if not data:
            return None
        return cls(
            base_type=str(data.get("base_type", "OCTET STRING")),
            enum={str(k): int(v) for k, v in (data.get("enum") or {}).items()},
            ranges=_tuples(data.get("ranges")),
            size=tuple(data["size"]) if data.get("size") else None,
            raw=str(data.get("raw", "")),
            entry_type=data.get("entry_type"),
        )


@dataclass
class MibNode:
    """A single named node of the parsed OID tree.

    Mutable on purpose: the model builder classifies nodes in a second pass.
    """

    name: str
    oid: str = ""
    kind: str = "scalar"  # group | table | entry | column | scalar
    access: str = "read-only"
    syntax: SyntaxSpec | None = None
    index_names: tuple[str, ...] = ()
    table_name: str | None = None
    parent_name: str = ""
    sub_id: int = 0
    status: str = "current"
    description: str = ""
    source_line: int = 0
    warnings: tuple[str, ...] = ()

    @property
    def readable(self) -> bool:
        return self.access in ("read-only", "read-write") and self.kind in ("scalar", "column")

    @property
    def writable(self) -> bool:
        return self.access in ("read-write", "write-only") and self.kind in ("scalar", "column")

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["syntax"] = self.syntax.to_dict() if self.syntax else None
        return d

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "MibNode":
        return cls(
            name=str(data["name"]),
            oid=str(data.get("oid", "")),
            kind=str(data.get("kind", "scalar")),
            access=str(data.get("access", "read-only")),
            syntax=SyntaxSpec.from_dict(data.get("syntax")),
            index_names=_str_tuple(data.get("index_names")),
            table_name=data.get("table_name"),
            parent_name=str(data.get("parent_name", "")),
            sub_id=int(data.get("sub_id", 0)),
            status=str(data.get("status", "current")),
            description=str(data.get("description", "")),
            source_line=int(data.get("source_line", 0)),
            warnings=_str_tuple(data.get("warnings")),
        )


@dataclass(frozen=True)
class MibInstance:
    """An addressable instance OID (scalar ``.0`` or column ``.<row>``)."""

    oid: str
    node_name: str
    kind: str  # scalar | column
    access: str
    syntax: SyntaxSpec | None
    table_name: str | None
    row_index: str
    module: str


@dataclass
class MibModel:
    """Complete normalised view of a MIB file."""

    module_name: str = ""
    mib_path: str = ""
    mib_sha256: str = ""
    root_oid: str = "1.3.6.1.4.1.52305"
    nodes: list[MibNode] = field(default_factory=list)
    stats: dict[str, Any] = field(default_factory=dict)
    warnings: list[dict[str, str]] = field(default_factory=list)
    tables: list[dict[str, Any]] = field(default_factory=list)
    sequence_types: dict[str, list[str]] = field(default_factory=dict)

    _by_name: dict[str, MibNode] = field(default_factory=dict, repr=False, compare=False)
    _by_oid: dict[str, MibNode] = field(default_factory=dict, repr=False, compare=False)

    def reindex(self) -> "MibModel":
        self._by_name = {n.name: n for n in self.nodes}
        self._by_oid = {n.oid: n for n in self.nodes}
        return self

    def node_by_name(self, name: str) -> MibNode | None:
        if not self._by_name:
            self.reindex()
        return self._by_name.get(name)

    def node_by_oid(self, oid: str) -> MibNode | None:
        if not self._by_oid:
            self.reindex()
        return self._by_oid.get(oid)

    def ancestors(self, node: MibNode) -> list[MibNode]:
        out: list[MibNode] = []
        cur = node
        seen: set[str] = set()
        while cur.parent_name and cur.parent_name not in seen:
            seen.add(cur.parent_name)
            parent = self.node_by_name(cur.parent_name)
            if parent is None:
                break
            out.append(parent)
            cur = parent
        return out

    def module_of(self, node: MibNode) -> str:
        """Top-level subtree name under the enterprise root (for grouping/tags)."""
        chain = self.ancestors(node)
        root_len = len(self.root_oid.split("."))
        candidates = [n for n in chain if len(n.oid.split(".")) == root_len + 1]
        return candidates[-1].name if candidates else (chain[-1].name if chain else node.name)

    def instances(self, rows_per_table: int = 2, max_columns_per_table: int = 0) -> list[MibInstance]:
        """Expand scalars and table columns into concrete instance OIDs.

        ``max_columns_per_table=0`` means no limit (full OID coverage).
        """
        result: list[MibInstance] = []
        per_table: dict[str, int] = {}
        for node in self.nodes:
            if node.kind == "scalar":
                result.append(
                    MibInstance(
                        oid=f"{node.oid}.0",
                        node_name=node.name,
                        kind="scalar",
                        access=node.access,
                        syntax=node.syntax,
                        table_name=None,
                        row_index="0",
                        module=self.module_of(node),
                    )
                )
            elif node.kind == "column":
                key = node.table_name or node.parent_name
                count = per_table.get(key, 0)
                if max_columns_per_table and count >= max_columns_per_table:
                    continue
                per_table[key] = count + 1
                for row in range(1, max(1, rows_per_table) + 1):
                    result.append(
                        MibInstance(
                            oid=f"{node.oid}.{row}",
                            node_name=node.name,
                            kind="column",
                            access=node.access,
                            syntax=node.syntax,
                            table_name=node.table_name,
                            row_index=str(row),
                            module=self.module_of(node),
                        )
                    )
        return result

    def to_dict(self) -> dict[str, Any]:
        return {
            "module_name": self.module_name,
            "mib_path": self.mib_path,
            "mib_sha256": self.mib_sha256,
            "root_oid": self.root_oid,
            "nodes": [n.to_dict() for n in self.nodes],
            "stats": self.stats,
            "warnings": self.warnings,
            "tables": self.tables,
            "sequence_types": self.sequence_types,
        }

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent, ensure_ascii=False, sort_keys=True)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "MibModel":
        model = cls(
            module_name=str(data.get("module_name", "")),
            mib_path=str(data.get("mib_path", "")),
            mib_sha256=str(data.get("mib_sha256", "")),
            root_oid=str(data.get("root_oid", "1.3.6.1.4.1.52305")),
            nodes=[MibNode.from_dict(n) for n in data.get("nodes", [])],
            stats=dict(data.get("stats", {})),
            warnings=[dict(w) for w in data.get("warnings", [])],
            tables=[dict(t) for t in data.get("tables", [])],
            sequence_types={k: list(v) for k, v in (data.get("sequence_types") or {}).items()},
        )
        return model.reindex()

    @staticmethod
    def hash_file(path: str | Path) -> str:
        h = hashlib.sha256()
        with Path(path).open("rb") as fh:
            for chunk in iter(lambda: fh.read(1 << 20), b""):
                h.update(chunk)
        return h.hexdigest()


@dataclass(frozen=True)
class TestCase:
    """A single, stably identified, data-only test case."""

    __test__: ClassVar[bool] = False  # pytest: this is data, not a test class
    case_id: str
    name: str
    oid: str
    operation: str
    version: str
    category: str  # normal | boundary | type | access | invalid | compat | trap
    tags: tuple[str, ...]
    payload: dict[str, Any]
    expectation: dict[str, Any]
    safety: str = "safe"  # safe | guarded | blocked
    priority: int = 3
    module: str = ""
    description: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "TestCase":
        return cls(
            case_id=str(data["case_id"]),
            name=str(data.get("name", "")),
            oid=str(data.get("oid", "")),
            operation=str(data["operation"]),
            version=str(data["version"]),
            category=str(data.get("category", "normal")),
            tags=_str_tuple(data.get("tags")),
            payload=dict(data.get("payload") or {}),
            expectation=dict(data.get("expectation") or {}),
            safety=str(data.get("safety", "safe")),
            priority=int(data.get("priority", 3)),
            module=str(data.get("module", "")),
            description=str(data.get("description", "")),
        )


@dataclass
class Varbind:
    oid: str
    type: str
    value: Any
    exception: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class SnmpResponse:
    error_indication: str | None
    error_status: str
    error_index: int
    varbinds: list[Varbind]
    version: str
    operation: str
    target: str
    elapsed_ms: float = 0.0
    raw: str = ""

    @property
    def ok(self) -> bool:
        return self.error_indication is None and self.error_status in ("noError", "0")

    def to_dict(self) -> dict[str, Any]:
        return {
            "error_indication": self.error_indication,
            "error_status": self.error_status,
            "error_index": self.error_index,
            "varbinds": [v.to_dict() for v in self.varbinds],
            "version": self.version,
            "operation": self.operation,
            "target": self.target,
            "elapsed_ms": self.elapsed_ms,
            "raw": self.raw,
        }


@dataclass
class CaseResult:
    case_id: str
    name: str
    status: str = "error"  # passed | failed | error | skipped | blocked
    operation: str = ""
    version: str = ""
    module: str = ""
    target: str = ""
    tags: tuple[str, ...] = ()
    duration_ms: float = 0.0
    expectation: dict[str, Any] = field(default_factory=dict)
    actual: dict[str, Any] = field(default_factory=dict)
    message: str = ""
    logs: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class TrapRecord:
    """A received trap/inform, normalised to a version independent shape."""

    pdu_type: str  # trap | inform
    version: str
    source: str
    community: str = ""
    security_name: str = ""
    security_level: str = ""
    uptime: int | None = None
    trap_oid: str = ""
    enterprise_oid: str = ""
    agent_address: str = ""
    varbinds: list[Varbind] = field(default_factory=list)
    received_at: float = 0.0
    correlation_id: str = ""
    ack_sent: bool = False

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["varbinds"] = [v.to_dict() for v in self.varbinds]
        return d


@dataclass(frozen=True)
class TrapExpectation:
    """Declarative expectation loaded from ``config/trap-expectations.yaml``."""

    name: str
    trigger: dict[str, Any]
    pdu_type: str = "trap"
    version: str = "v2c"
    expected_trap_oids: tuple[str, ...] = ()
    enterprise_oid: str = ""
    community: str = ""
    security_name: str = ""
    varbinds: tuple[dict[str, Any], ...] = ()
    severity: int | None = None
    max_latency_s: float = 5.0
    expect_ack: bool = False
    tags: tuple[str, ...] = ()

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "TrapExpectation":
        return cls(
            name=str(data["name"]),
            trigger=dict(data.get("trigger") or {}),
            pdu_type=str(data.get("pdu_type", "trap")),
            version=str(data.get("version", "v2c")),
            expected_trap_oids=_str_tuple(data.get("expected_trap_oids")),
            enterprise_oid=str(data.get("enterprise_oid", "")),
            community=str(data.get("community", "")),
            security_name=str(data.get("security_name", "")),
            varbinds=tuple(dict(v) for v in (data.get("varbinds") or [])),
            severity=int(data["severity"]) if data.get("severity") is not None else None,
            max_latency_s=float(data.get("max_latency_s", 5.0)),
            expect_ack=bool(data.get("expect_ack", False)),
            tags=_str_tuple(data.get("tags")),
        )


def stable_case_id(mib_hash: str, *parts: Iterable[str] | str) -> str:
    """Deterministic short id, stable for the same MIB + case definition."""
    flat: list[str] = []
    for part in parts:
        if isinstance(part, str):
            flat.append(part)
        else:
            flat.extend(str(x) for x in part)
    digest = hashlib.sha256("|".join([mib_hash, *flat]).encode("utf-8")).hexdigest()
    return f"TC-{digest[:16]}"
