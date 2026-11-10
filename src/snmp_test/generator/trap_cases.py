"""Generate trap / inform verification cases from declarative expectations.

The vendor MIB contains no NOTIFICATION-TYPE definitions, so the expected trap
content cannot be derived from the MIB itself.  It lives in
``config/trap-expectations.yaml`` (see docs for the IPMI/PEF mapping rationale).
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from snmp_test.model.types import TestCase, TrapExpectation, stable_case_id


def load_expectations(path: str | Path) -> list[TrapExpectation]:
    p = Path(path)
    if not p.is_file():
        return []
    data = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
    return [TrapExpectation.from_dict(item) for item in (data.get("expectations") or [])]


def _trap_assertions(exp: TrapExpectation) -> list[dict[str, Any]]:
    assertions: list[dict[str, Any]] = [
        {"kind": "trap_received"},
        {"kind": "trap_pdu_type", "expected": exp.pdu_type},
        {"kind": "trap_version", "expected": exp.version},
        {"kind": "trap_latency", "max_s": exp.max_latency_s},
    ]
    if exp.expected_trap_oids:
        assertions.append({"kind": "trap_oid_in", "allowed": list(exp.expected_trap_oids)})
    if exp.enterprise_oid:
        assertions.append({"kind": "trap_enterprise", "expected": exp.enterprise_oid})
    if exp.community:
        assertions.append({"kind": "trap_community", "expected": exp.community})
    if exp.security_name:
        assertions.append({"kind": "trap_security_name", "expected": exp.security_name})
    if exp.severity is not None:
        assertions.append({"kind": "trap_severity", "expected": exp.severity})
    if exp.varbinds:
        assertions.append({"kind": "trap_varbinds", "expected": [dict(v) for v in exp.varbinds]})
    if exp.expect_ack:
        assertions.append({"kind": "trap_ack"})
    return assertions


def generate_trap_cases(
    expectations: list[TrapExpectation],
    mib_hash: str,
    allowed_versions: tuple[str, ...] = ("v1", "v2c", "v3"),
) -> list[TestCase]:
    cases: list[TestCase] = []
    for exp in expectations:
        if exp.version not in allowed_versions:
            continue
        trigger = dict(exp.trigger)
        trigger_type = str(trigger.get("type", "mock_event"))
        if trigger.get("enabled") is False:
            continue
        # External triggers (Redfish/IPMI state changes) are never enabled implicitly.
        if trigger_type in ("external", "snmp_set") and not trigger.get("explicitly_enabled"):
            continue
        operation = "INFORM" if exp.pdu_type == "inform" else "TRAP"
        tags = tuple(
            dict.fromkeys(
                ("trap", operation.lower(), exp.version, "notification", *exp.tags)
            )
        )
        case_id = stable_case_id(mib_hash, "trap", exp.name, operation, exp.version)
        cases.append(
            TestCase(
                case_id=case_id,
                name=exp.name,
                oid=exp.enterprise_oid or "",
                operation=operation,
                version=exp.version,
                category="trap",
                tags=tags,
                payload={
                    "trigger": trigger,
                    "expectation_ref": exp.name,
                    "trap_expectation": {
                        "name": exp.name,
                        "pdu_type": exp.pdu_type,
                        "version": exp.version,
                        "expected_trap_oids": list(exp.expected_trap_oids),
                        "enterprise_oid": exp.enterprise_oid,
                        "community": exp.community,
                        "security_name": exp.security_name,
                        "varbinds": [dict(v) for v in exp.varbinds],
                        "severity": exp.severity,
                        "max_latency_s": exp.max_latency_s,
                        "expect_ack": exp.expect_ack,
                    },
                },
                expectation={"assertions": _trap_assertions(exp)},
                safety="safe",
                priority=1,
                module="notification",
                description=f"{operation} {exp.version}: {exp.name}",
            )
        )
    return cases
