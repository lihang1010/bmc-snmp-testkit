"""Expand a :class:`MibModel` into a stable, declarative case repository."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from snmp_test.model.types import MibInstance, MibModel, TestCase, stable_case_id
from snmp_test.runner.safety import DEFAULT_POLICY, classify_node

from .value_factory import (
    alternate_value,
    asn1_type,
    boundary_values,
    invalid_values,
    seed_value,
    value_assertions,
)

ALL_VERSIONS = ("v1", "v2c", "v3")


@dataclass
class GeneratorOptions:
    versions: tuple[str, ...] = ALL_VERSIONS
    rows_per_table: int = 2
    # 0 = unlimited.  Applies to GETNEXT/GETBULK/SET cases; GET always covers every OID.
    max_cases_per_table: int = 8
    enable_set: bool = True
    policy: dict[str, Any] = field(default_factory=lambda: dict(DEFAULT_POLICY))
    wrong_community: str = "invalid-community"
    wrong_v3_user: str = "invalid-user"
    max_varbinds: int = 20
    bulk_max_repetitions: int = 6
    seed: int = 20261109


def _varbind(oid: str, spec: Any | None = None) -> dict[str, Any]:
    if spec is None:
        return {"oid": oid, "asn1": "Null", "value": None}
    return {"oid": oid, "asn1": spec.asn1, "value": spec.value}


class CaseBuilder:
    def __init__(self, model: MibModel, options: GeneratorOptions | None = None) -> None:
        self.model = model
        self.opts = options or GeneratorOptions()
        self.hash = model.mib_sha256
        self.cases: list[TestCase] = []
        self._seen: set[str] = set()

    def _add(self, **kwargs: Any) -> None:
        case = TestCase(**kwargs)
        # identical definitions must collapse: case_id is the identity
        if case.case_id in self._seen:
            return
        self._seen.add(case.case_id)
        self.cases.append(case)

    def _mk(
        self,
        *,
        name: str,
        oid: str,
        operation: str,
        version: str,
        category: str,
        tags: tuple[str, ...],
        payload: dict[str, Any],
        expectation: dict[str, Any],
        safety: str = "safe",
        priority: int = 3,
        module: str = "",
        description: str = "",
        discriminator: str = "",
    ) -> None:
        case_id = stable_case_id(
            self.hash,
            name,
            oid,
            operation,
            version,
            category,
            discriminator,
        )
        self._add(
            case_id=case_id,
            name=name,
            oid=oid,
            operation=operation,
            version=version,
            category=category,
            tags=tuple(tags),
            payload=payload,
            expectation=expectation,
            safety=safety,
            priority=priority,
            module=module,
            description=description,
        )

    def _tags(self, inst: MibInstance | None, operation: str, version: str, category: str) -> tuple[str, ...]:
        tags = [operation.lower(), version, category]
        if inst:
            tags.extend([inst.kind, inst.module])
            if inst.table_name:
                tags.append(inst.table_name)
        else:
            tags.append("global")
        if category in ("invalid", "access", "type"):
            tags.append("negative")
        if operation == "SET":
            tags.append("set")
        return tuple(dict.fromkeys(tags))

    def _safety_for(self, inst: MibInstance) -> str:
        node = self.model.node_by_name(inst.node_name)
        if node is None:
            return "guarded"
        return classify_node(node, self.opts.policy)[0]

    # ------------------------------------------------------------------ GET
    def _get_cases(self, instances: list[MibInstance]) -> None:
        for inst in instances:
            readable = inst.access in ("read-only", "read-write")
            assertions = (
                value_assertions(inst.syntax)
                + [{"kind": "oid_equals", "oid": inst.oid}]
                if readable
                else [{"kind": "rejected"}]
            )
            for version in self.opts.versions:
                self._mk(
                    name=f"GET {inst.node_name}[{inst.row_index}]",
                    oid=inst.oid,
                    operation="GET",
                    version=version,
                    category="normal" if readable else "access",
                    tags=self._tags(inst, "GET", version, "normal" if readable else "access"),
                    payload={
                        "varbinds": [_varbind(inst.oid)],
                        "node_name": inst.node_name,
                        "expected_types": value_assertions(inst.syntax),
                    },
                    expectation={"assertions": assertions},
                    module=inst.module,
                    description=f"Read {inst.node_name} and validate type/value domain",
                )

    # -------------------------------------------------------------- GETNEXT
    def _getnext_cases(self, instances: list[MibInstance]) -> None:
        starts: list[tuple[str, str, str]] = []  # (label, oid, prefix)
        for table in self.model.tables:
            col = next((n for n in self.model.nodes if n.table_name == table["name"]), None)
            if col:
                starts.append((f"table:{table['name']}", col.oid, col.oid))
        seen_modules: set[str] = set()
        for inst in instances:
            if inst.kind == "scalar" and inst.module not in seen_modules:
                seen_modules.add(inst.module)
                node = self.model.node_by_name(inst.node_name)
                if node:
                    starts.append((f"module:{inst.module}", node.oid, self.model.root_oid))

        for label, start, prefix in starts:
            for version in self.opts.versions:
                self._mk(
                    name=f"GETNEXT {label}",
                    oid=start,
                    operation="GETNEXT",
                    version=version,
                    category="normal",
                    tags=self._tags(None, "GETNEXT", version, "normal") + (label,),
                    payload={"varbinds": [_varbind(start)], "start_oid": start},
                    expectation={
                        "assertions": [
                            {"kind": "no_error"},
                            {"kind": "varbind_count", "min": 1},
                            {"kind": "oid_gt", "oid": start},
                            {"kind": "oid_prefix", "prefix": prefix},
                            {"kind": "oid_order"},
                        ]
                    },
                    module=label,
                    description="Lexicographic successor and OID ordering",
                )

        end_oid = f"{self.model.root_oid}.9999"
        for version in self.opts.versions:
            self._mk(
                name="GETNEXT end-of-MIB boundary",
                oid=end_oid,
                operation="GETNEXT",
                version=version,
                category="boundary",
                tags=self._tags(None, "GETNEXT", version, "boundary"),
                payload={"varbinds": [_varbind(end_oid)], "start_oid": end_oid},
                expectation={"assertions": [{"kind": "end_of_mib"}]},
                description="v1 noSuchName / v2c,v3 endOfMibView at the tree end",
            )

    # -------------------------------------------------------------- GETBULK
    def _getbulk_cases(self) -> None:
        starts: list[tuple[str, str]] = []
        for table in self.model.tables[: max(1, self.opts.max_cases_per_table or len(self.model.tables))]:
            col = next((n for n in self.model.nodes if n.table_name == table["name"]), None)
            if col:
                starts.append((f"table:{table['name']}", col.oid))
        scalars = [n for n in self.model.nodes if n.kind == "scalar"]
        for node in scalars[: min(7, len(scalars))]:
            starts.append((f"scalar:{node.name}", node.oid))

        for label, start in starts:
            for version in self.opts.versions:
                if version == "v1":
                    continue
                self._mk(
                    name=f"GETBULK {label}",
                    oid=start,
                    operation="GETBULK",
                    version=version,
                    category="normal",
                    tags=self._tags(None, "GETBULK", version, "normal") + (label,),
                    payload={
                        "varbinds": [_varbind(start)],
                        "start_oid": start,
                        "non_repeaters": 0,
                        "max_repetitions": self.opts.bulk_max_repetitions,
                    },
                    expectation={
                        "assertions": [
                            {"kind": "no_error"},
                            {"kind": "varbind_count", "min": 1},
                            {"kind": "oid_ge", "oid": start},
                            {"kind": "oid_prefix", "prefix": self.model.root_oid},
                            {"kind": "no_crash"},
                        ]
                    },
                    module=label,
                    description="Bulk walk with bounded max-repetitions",
                )

        # v1 has no GetBulk PDU: record an explicit, auditable compatibility skip.
        self._mk(
            name="GETBULK unsupported on v1",
            oid=self.model.root_oid,
            operation="GETBULK",
            version="v1",
            category="compat",
            tags=("getbulk", "v1", "compat"),
            payload={"varbinds": [_varbind(self.model.root_oid)], "non_repeaters": 0, "max_repetitions": 1},
            expectation={"skip": True, "reason": "SNMP v1 does not define GetBulkRequest-PDU"},
            priority=5,
            description="Version capability matrix entry",
        )

    # ------------------------------------------------------------------ SET
    def _set_cases(self, instances: list[MibInstance]) -> None:
        if not self.opts.enable_set:
            return
        writable = [i for i in instances if i.access in ("read-write", "write-only")]
        per_table: dict[str, int] = {}
        readonly_sample: list[MibInstance] = []
        seen_tables: set[str] = set()

        for inst in instances:
            if inst.access != "read-only":
                continue
            if inst.kind == "column":
                if inst.table_name in seen_tables:
                    continue
                seen_tables.add(inst.table_name)
            readonly_sample.append(inst)

        for inst in writable:
            if inst.kind == "column" and self.opts.max_cases_per_table:
                key = inst.table_name or inst.module
                if per_table.get(key, 0) >= self.opts.max_cases_per_table:
                    continue
                per_table[key] = per_table.get(key, 0) + 1

            node = self.model.node_by_name(inst.node_name)
            seed = seed_value(inst.syntax, inst.node_name, inst.row_index)
            alt = alternate_value(inst.syntax, seed, inst.node_name, inst.row_index)
            safety = self._safety_for(inst)

            boundary = boundary_values(inst.syntax)
            invalid = invalid_values(inst.syntax)
            candidates: list[tuple[str, Any, list[dict[str, Any]], str, str]] = [
                (
                    "normal",
                    alt,
                    [{"kind": "no_error"}, {"kind": "value_equals", "value": alt.value}],
                    "valid SET with read-back",
                    "alt",
                ),
            ]
            if boundary:
                candidates.append(("boundary", boundary[0], [{"kind": "no_error"}], "boundary value SET", f"b:{boundary[0].label}"))
            for spec in invalid[:2]:
                candidates.append(("invalid", spec, [{"kind": "rejected"}], "invalid value must be refused", f"i:{spec.label}"))

            for category, spec, assertions, desc, discriminator in candidates:
                for version in self.opts.versions:
                    self._mk(
                        name=f"SET {inst.node_name}[{inst.row_index}] {spec.label}",
                        oid=inst.oid,
                        operation="SET",
                        version=version,
                        category=category,
                        tags=self._tags(inst, "SET", version, category)
                        + (("guarded",) if safety == "guarded" else ())
                        + (("blocked",) if safety == "blocked" else ()),
                        payload={
                            "varbinds": [_varbind(inst.oid, spec)],
                            "node_name": inst.node_name,
                            "expected_value": spec.value,
                            "asn1": asn1_type(inst.syntax),
                            "source_line": node.source_line if node else 0,
                        },
                        expectation={"assertions": assertions},
                        safety=safety,
                        priority=1 if category == "invalid" else 2,
                        module=inst.module,
                        description=desc,
                        discriminator=discriminator,
                    )

        # read-only nodes must reject SET (access-control matrix)
        for inst in readonly_sample[: max(1, self.opts.max_cases_per_table or 40)]:
            spec = seed_value(inst.syntax, inst.node_name, inst.row_index)
            for version in self.opts.versions:
                self._mk(
                    name=f"SET read-only {inst.node_name} rejected",
                    oid=inst.oid,
                    operation="SET",
                    version=version,
                    category="access",
                    tags=self._tags(inst, "SET", version, "access") + ("negative",),
                    payload={"varbinds": [_varbind(inst.oid, spec)], "node_name": inst.node_name},
                    expectation={"assertions": [{"kind": "rejected"}]},
                    safety="safe",
                    priority=1,
                    module=inst.module,
                    description="read-only OID must refuse SET",
                )

    # ------------------------------------------------- auth & invalid input
    def _auth_and_invalid_cases(self, instances: list[MibInstance]) -> None:
        probe = next((i for i in instances if i.access in ("read-only", "read-write")), None)
        if not probe:
            return
        oid = probe.oid

        overrides: list[tuple[str, str, dict[str, Any]]] = [
            ("wrong community (v1)", "v1", {"community": self.opts.wrong_community}),
            ("wrong community (v2c)", "v2c", {"community": self.opts.wrong_community}),
            ("unknown v3 user", "v3", {"v3_user": self.opts.wrong_v3_user}),
            ("wrong v3 auth key", "v3", {"auth_key": "definitely-wrong-auth-key"}),
            ("wrong v3 priv key", "v3", {"priv_key": "definitely-wrong-priv-key"}),
        ]
        for label, version, override in overrides:
            if version not in self.opts.versions:
                continue
            self._mk(
                name=f"GET with {label}",
                oid=oid,
                operation="GET",
                version=version,
                category="access",
                tags=("get", version, "access", "negative", "auth"),
                payload={"varbinds": [_varbind(oid)], "credential_override": override},
                expectation={"assertions": [{"kind": "auth_rejected"}]},
                priority=1,
                description="Invalid credentials must not return data",
                discriminator=label,
            )

        # read-only community must be refused for SET (VACM access control)
        writable = next((i for i in instances if i.access == "read-write"), None)
        if writable:
            spec = alternate_value(
                writable.syntax,
                seed_value(writable.syntax, writable.node_name, writable.row_index),
                writable.node_name,
                writable.row_index,
            )
            for version in ("v1", "v2c"):
                if version not in self.opts.versions:
                    continue
                self._mk(
                    name=f"SET with read-only community ({version})",
                    oid=writable.oid,
                    operation="SET",
                    version=version,
                    category="access",
                    tags=("set", version, "access", "negative", "vacm"),
                    payload={
                        "varbinds": [_varbind(writable.oid, spec)],
                        "node_name": writable.node_name,
                        "credential_override": {"community": "__READ_ONLY__"},
                    },
                    expectation={"assertions": [{"kind": "rejected"}]},
                    priority=1,
                    module=writable.module,
                    description="Read-only community must not be able to SET",
                )

        missing = f"{self.model.root_oid}.9999.1"
        for version in self.opts.versions:
            self._mk(
                name="GET non-existent OID",
                oid=missing,
                operation="GET",
                version=version,
                category="invalid",
                tags=("get", version, "invalid", "negative"),
                payload={"varbinds": [_varbind(missing)]},
                expectation={"assertions": [{"kind": "no_such"}]},
                priority=1,
                description="v1 noSuchName / v2c,v3 noSuchObject|noSuchInstance",
            )
            self._mk(
                name="GET malformed OID",
                oid="1.3.6.1.4.1..52305",
                operation="GET",
                version=version,
                category="invalid",
                tags=("get", version, "invalid", "negative"),
                payload={"varbinds": [_varbind("1.3.6.1.4.1..52305")], "expect_client_error": True},
                # Depending on the stack the malformed OID is either refused
                # locally (clientError) or answered with noSuchName / an
                # exception varbind.  All three are valid rejections.
                expectation={"assertions": [{"kind": "rejected"}]},
                priority=2,
                description="Malformed OID must be rejected locally without a device write",
            )
            bulk = [_varbind(oid) for _ in range(self.opts.max_varbinds + 1)]
            self._mk(
                name="GET with excessive varbinds",
                oid=oid,
                operation="GET",
                version=version,
                category="invalid",
                tags=("get", version, "invalid", "negative", "flood"),
                payload={"varbinds": bulk},
                expectation={"assertions": [{"kind": "no_crash"}]},
                priority=3,
                description="Agent must either answer or return tooBig, never crash the client",
            )

    def build(self) -> list[TestCase]:
        instances = self.model.instances(rows_per_table=self.opts.rows_per_table)
        self._get_cases(instances)
        self._getnext_cases(instances)
        self._getbulk_cases()
        self._set_cases(instances)
        self._auth_and_invalid_cases(instances)
        self.cases.sort(key=lambda c: (c.priority, c.case_id))
        return self.cases


def generate_cases(model: MibModel, options: GeneratorOptions | None = None) -> list[TestCase]:
    return CaseBuilder(model, options).build()


def cases_to_json(cases: list[TestCase], model: MibModel, options: GeneratorOptions) -> str:
    import json

    counts: dict[str, int] = {}
    for case in cases:
        counts[case.operation] = counts.get(case.operation, 0) + 1
    payload = {
        "schema": 1,
        "mib_sha256": model.mib_sha256,
        "mib_path": model.mib_path,
        "module_name": model.module_name,
        "root_oid": model.root_oid,
        "options": {
            "versions": list(options.versions),
            "rows_per_table": options.rows_per_table,
            "max_cases_per_table": options.max_cases_per_table,
            "enable_set": options.enable_set,
            "bulk_max_repetitions": options.bulk_max_repetitions,
            "seed": options.seed,
        },
        "total": len(cases),
        "by_operation": counts,
        "cases": [c.to_dict() for c in cases],
    }
    return json.dumps(payload, indent=1, ensure_ascii=False, sort_keys=True)
