"""Declarative assertion library.

Everything a generated case expects is data (``TestCase.expectation``).  This
module is the only place that interprets it, so the same assertions are used by
the batch executor and by the pytest bridge.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from snmp_test.model.types import SnmpResponse, TestCase, TrapRecord, Varbind
from snmp_test.snmp.errors import EXCEPTION_TYPES, is_auth_error, is_rejection_status, is_timeout

TYPE_ALIASES: dict[str, set[str]] = {
    "Integer32": {"Integer32", "Integer", "Unsigned32", "Gauge32", "Counter32", "Counter64", "TimeTicks"},
    "OctetString": {"OctetString", "DisplayString", "Opaque", "Bits", "PhysAddress"},
    "IpAddress": {"IpAddress", "OctetString"},
    "ObjectIdentifier": {"ObjectIdentifier", "ObjectName"},
    "TimeTicks": {"TimeTicks", "Integer32", "Integer", "Gauge32", "Unsigned32"},
    "Null": {"Null"},
    "NoSuchObject": {"NoSuchObject"},
    "NoSuchInstance": {"NoSuchInstance"},
    "EndOfMibView": {"EndOfMibView"},
}

SEVERITY_WORDS = {"critical": 3, "non-recoverable": 3, "warning": 2, "non-critical": 2, "waring": 2}


@dataclass
class AssertionOutcome:
    passed: bool = True
    failures: list[str] = field(default_factory=list)
    details: dict[str, Any] = field(default_factory=dict)

    def fail(self, message: str) -> None:
        self.passed = False
        self.failures.append(message)


def _oid_key(oid: str) -> tuple[int, ...]:
    try:
        return tuple(int(x) for x in oid.strip(".").split("."))
    except Exception:
        return ()


def _numeric(value: Any) -> float | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        return float(value)
    try:
        return float(str(value))
    except Exception:
        return None


def _type_matches(actual: str, allowed: list[str]) -> bool:
    expanded: set[str] = set()
    for name in allowed:
        expanded |= TYPE_ALIASES.get(name, {name})
    return actual in expanded


def _exceptions(response: SnmpResponse) -> set[str]:
    return {v.exception for v in response.varbinds if v.exception}


def _usable_varbinds(response: SnmpResponse) -> list[Varbind]:
    return [v for v in response.varbinds if v.exception is None]


def _rejected(response: SnmpResponse) -> bool:
    # A malformed value may be refused by the client adapter before any PDU is
    # sent; that is also a valid refusal and must not be reported as a failure.
    if (response.error_indication or "").startswith("clientError"):
        return True
    if response.error_indication and is_auth_error(response.error_indication):
        return True
    if is_rejection_status(response.error_status, response.version):
        return True
    return bool(_exceptions(response) & {"NoSuchObject", "NoSuchInstance", "EndOfMibView"})


def _trap_severity(record: TrapRecord) -> int | None:
    for vb in record.varbinds:
        text = str(vb.value).lower()
        for word, level in SEVERITY_WORDS.items():
            if word in text:
                return level
    return None


def _find_varbind(record: TrapRecord, oid: str) -> Varbind | None:
    for vb in record.varbinds:
        if vb.oid == oid:
            return vb
    return None


def evaluate(
    case: TestCase,
    response: SnmpResponse | None = None,
    *,
    trap: TrapRecord | None = None,
    trigger: dict[str, Any] | None = None,
) -> AssertionOutcome:
    out = AssertionOutcome()
    assertions = case.expectation.get("assertions") or []
    if not assertions:
        return out

    for spec in assertions:
        kind = str(spec.get("kind", ""))
        r = response
        if kind.startswith("trap_"):
            out.details.setdefault("trap_checks", []).append(kind)
            if trap is None:
                out.fail(f"{kind}: no matching trap/inform received")
                continue
            if kind == "trap_received":
                pass
            elif kind == "trap_pdu_type":
                if trap.pdu_type != spec.get("expected"):
                    out.fail(f"trap pdu_type {trap.pdu_type!r} != {spec.get('expected')!r}")
            elif kind == "trap_version":
                if trap.version != spec.get("expected"):
                    out.fail(f"trap version {trap.version!r} != {spec.get('expected')!r}")
            elif kind == "trap_oid_in":
                if trap.trap_oid not in (spec.get("allowed") or []):
                    out.fail(f"trap OID {trap.trap_oid!r} not in {spec.get('allowed')}")
            elif kind == "trap_enterprise":
                if trap.enterprise_oid != spec.get("expected"):
                    out.fail(f"enterprise {trap.enterprise_oid!r} != {spec.get('expected')!r}")
            elif kind == "trap_community":
                if trap.community and trap.community != spec.get("expected"):
                    out.fail(f"community {trap.community!r} != {spec.get('expected')!r}")
            elif kind == "trap_security_name":
                if trap.security_name != spec.get("expected"):
                    out.fail(f"security_name {trap.security_name!r} != {spec.get('expected')!r}")
            elif kind == "trap_severity":
                actual = _trap_severity(trap)
                if actual != spec.get("expected"):
                    out.fail(f"severity {actual!r} != {spec.get('expected')!r}")
            elif kind == "trap_ack":
                if not trap.ack_sent:
                    out.fail("inform was not acknowledged by the receiver")
            elif kind == "trap_latency":
                sent = float((trigger or {}).get("triggered_at") or trap.received_at)
                latency = max(0.0, trap.received_at - sent)
                out.details["latency_s"] = round(latency, 3)
                if latency > float(spec.get("max_s", 5.0)):
                    out.fail(f"trap latency {latency:.3f}s > {spec.get('max_s')}s")
            elif kind == "trap_varbinds":
                for expected in spec.get("expected") or []:
                    vb = _find_varbind(trap, str(expected.get("oid")))
                    if vb is None:
                        out.fail(f"expected varbind {expected.get('oid')} missing from trap")
                        continue
                    exp_type = expected.get("type")
                    if exp_type and not _type_matches(vb.type, [str(exp_type)]):
                        out.fail(f"varbind {vb.oid} type {vb.type!r} != {exp_type!r}")
                    if expected.get("value") is not None and str(vb.value) != str(expected["value"]):
                        out.fail(f"varbind {vb.oid} value {vb.value!r} != {expected['value']!r}")
                    if expected.get("contains") and str(expected["contains"]) not in str(vb.value):
                        out.fail(f"varbind {vb.oid} value {vb.value!r} lacks {expected['contains']!r}")
            elif kind == "trap_source":
                if trap.source and str(spec.get("expected")) not in trap.source:
                    out.fail(f"trap source {trap.source!r} != {spec.get('expected')!r}")
            else:
                out.fail(f"unknown trap assertion kind: {kind}")
            continue

        if r is None:
            out.fail(f"{kind}: no SNMP response available")
            continue

        usable = _usable_varbinds(r)
        if kind == "no_error":
            if r.error_indication is not None or r.error_status not in ("noError", "0"):
                out.fail(f"expected no error, got indication={r.error_indication!r} status={r.error_status!r}")
        elif kind == "rejected":
            if not _rejected(r):
                out.fail(f"expected rejection, got status={r.error_status!r} indication={r.error_indication!r}")
        elif kind == "no_such":
            ok = r.error_status == "noSuchName" or bool(_exceptions(r) & {"NoSuchObject", "NoSuchInstance"})
            if not ok:
                out.fail(f"expected noSuchName/noSuchObject/noSuchInstance, got {r.error_status!r}")
        elif kind == "end_of_mib":
            ok = r.error_status == "noSuchName" or "EndOfMibView" in _exceptions(r)
            if not ok:
                out.fail(f"expected endOfMibView (or v1 noSuchName), got {r.error_status!r}")
        elif kind == "auth_rejected":
            ok = bool(r.error_indication and (is_timeout(r.error_indication) or is_auth_error(r.error_indication)))
            ok = ok or is_rejection_status(r.error_status, r.version) or bool(_exceptions(r) & set(EXCEPTION_TYPES))
            # USM failures can surface as an empty, but perfectly formed, v3
            # response.  The contract is "no data was disclosed".
            ok = ok or not usable
            if not ok:
                out.fail(f"invalid credentials should not return data, got {r.error_status!r} / {r.varbinds[:1]}")
        elif kind == "client_error":
            if not (r.error_indication or "").startswith("clientError"):
                out.fail(f"expected client-side rejection, got {r.error_indication!r} / {r.error_status!r}")
        elif kind == "no_crash":
            # A structured response (success, protocol error or client error) is
            # acceptable; an unhandled exception would never reach this point.
            out.details.setdefault("no_crash", True)
        elif kind == "varbind_count":
            count = len(r.varbinds)
            if "equal" in spec and count != int(spec["equal"]):
                out.fail(f"varbind count {count} != {spec['equal']}")
            if "min" in spec and count < int(spec["min"]):
                out.fail(f"varbind count {count} < {spec['min']}")
            if "max" in spec and count > int(spec["max"]):
                out.fail(f"varbind count {count} > {spec['max']}")
        elif kind == "value_type":
            allowed = list(spec.get("allowed") or [])
            for vb in usable:
                if not _type_matches(vb.type, allowed):
                    out.fail(f"{vb.oid} type {vb.type!r} not in {allowed}")
        elif kind == "value_in":
            allowed = {str(x) for x in (spec.get("allowed") or [])}
            for vb in usable:
                if str(vb.value) not in allowed:
                    out.fail(f"{vb.oid} value {vb.value!r} not in {sorted(allowed)}")
        elif kind == "value_in_range":
            for vb in usable:
                number = _numeric(vb.value)
                if number is None or not (float(spec["min"]) <= number <= float(spec["max"])):
                    out.fail(f"{vb.oid} value {vb.value!r} outside [{spec['min']}, {spec['max']}]")
        elif kind == "value_length":
            for vb in usable:
                length = len(str(vb.value))
                if not (int(spec["min"]) <= length <= int(spec["max"])):
                    out.fail(f"{vb.oid} length {length} outside [{spec['min']}, {spec['max']}]")
        elif kind == "value_equals":
            if not usable or str(usable[0].value) != str(spec.get("value")):
                out.fail(f"value {usable[0].value if usable else None!r} != {spec.get('value')!r}")
        elif kind == "oid_equals":
            if not r.varbinds or r.varbinds[0].oid != spec.get("oid"):
                out.fail(f"OID {r.varbinds[0].oid if r.varbinds else None!r} != {spec.get('oid')!r}")
        elif kind == "oid_gt":
            base = _oid_key(str(spec.get("oid")))
            for vb in usable:
                if _oid_key(vb.oid) <= base:
                    out.fail(f"OID {vb.oid} is not a successor of {spec.get('oid')}")
        elif kind == "oid_ge":
            base = _oid_key(str(spec.get("oid")))
            if not usable or _oid_key(usable[0].oid) < base:
                out.fail(f"first OID is below {spec.get('oid')}")
        elif kind == "oid_prefix":
            prefix = str(spec.get("prefix", ""))
            if not usable or not usable[0].oid.startswith(prefix):
                out.fail(f"first OID {usable[0].oid if usable else None!r} does not start with {prefix!r}")
        elif kind == "oid_order":
            keys = [_oid_key(v.oid) for v in usable]
            if any(a >= b for a, b in zip(keys, keys[1:])):
                out.fail("returned OIDs are not strictly increasing")
        else:
            out.fail(f"unknown assertion kind: {kind}")

    out.details["assertion_count"] = len(assertions)
    return out
