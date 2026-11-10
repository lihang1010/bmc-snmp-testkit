"""Derive legal, boundary and illegal SNMP values from a :class:`SyntaxSpec`."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from snmp_test.model.types import SyntaxSpec

INT32_MIN, INT32_MAX = -(2**31), 2**31 - 1

ASN1_FOR_BASE_TYPE: dict[str, str] = {
    "Integer32": "Integer32",
    "INTEGER": "Integer32",
    "OCTET STRING": "OctetString",
    "DisplayString": "OctetString",
    "IpAddress": "IpAddress",
    "PhysAddress": "OctetString",
    "OBJECT IDENTIFIER": "ObjectIdentifier",
    "SEQUENCE OF": "Null",
}


@dataclass(frozen=True)
class ValueSpec:
    """A single value to put into a varbind, independent of PySNMP objects."""

    asn1: str  # Integer32 | OctetString | IpAddress | ObjectIdentifier | Null
    value: Any  # int | str | None
    label: str = "valid"
    valid: bool = True

    def to_dict(self) -> dict[str, Any]:
        return {"asn1": self.asn1, "value": self.value, "label": self.label, "valid": self.valid}


def asn1_type(syntax: SyntaxSpec | None) -> str:
    if syntax is None:
        return "Null"
    return ASN1_FOR_BASE_TYPE.get(syntax.base_type, "OctetString")


def expected_types(syntax: SyntaxSpec | None) -> list[str]:
    """ASN.1 type names accepted as a valid response for this syntax."""
    t = asn1_type(syntax)
    if t == "Integer32":
        # Agents may legitimately answer INTEGER / Integer32 / Gauge32 for SMIv2 integers.
        return ["Integer32", "Integer", "Gauge32", "Unsigned32", "Counter32", "Counter64"]
    if t == "OctetString":
        return ["OctetString", "DisplayString", "Opaque", "Bits"]
    if t == "IpAddress":
        return ["IpAddress", "OctetString"]
    return [t]


def _clip_string(text: str, syntax: SyntaxSpec | None) -> str:
    upper = syntax.size[1] if syntax and syntax.size else 255
    return text[: max(1, min(upper, 255))]


def seed_value(syntax: SyntaxSpec | None, node_name: str, row_index: str = "0") -> ValueSpec:
    """Deterministic plausible value used to seed the mock agent."""
    if syntax is None:
        return ValueSpec("Null", None, "seed")
    if syntax.is_integer:
        if syntax.enum:
            value = min(syntax.enum.values())
        elif syntax.ranges:
            value = max(syntax.ranges[0][0], 0)
        else:
            value = 0
        return ValueSpec("Integer32", int(value), "seed")
    if syntax.base_type == "IpAddress":
        return ValueSpec("IpAddress", "192.0.2.10", "seed")
    if syntax.base_type == "OBJECT IDENTIFIER":
        return ValueSpec("ObjectIdentifier", "1.3.6.1.4.1.52305", "seed")
    text = _clip_string(f"{node_name[:18]}-{row_index}", syntax)
    return ValueSpec("OctetString", text, "seed")


def alternate_value(syntax: SyntaxSpec | None, seed: ValueSpec, node_name: str, row_index: str) -> ValueSpec:
    """A *different* legal value, used by SET read-back verification."""
    if syntax is None:
        return seed
    if syntax.is_integer:
        if syntax.enum:
            values = sorted(set(syntax.enum.values()))
            candidates = [v for v in values if v != seed.value]
            value = candidates[0] if candidates else values[0]
        elif syntax.ranges:
            lo, hi = syntax.ranges[0]
            value = hi if hi != seed.value else lo
        else:
            value = (int(seed.value) + 1) & 0x7FFFFFFF
        return ValueSpec("Integer32", int(value), "alternate")
    if syntax.base_type == "IpAddress":
        return ValueSpec("IpAddress", "192.0.2.11" if seed.value != "192.0.2.11" else "192.0.2.12", "alternate")
    text = _clip_string(f"{node_name[:14]}-set-{row_index}", syntax)
    if text == seed.value:
        text = _clip_string(text + "x", syntax)
    return ValueSpec("OctetString", text, "alternate")


def boundary_values(syntax: SyntaxSpec | None) -> list[ValueSpec]:
    out: list[ValueSpec] = []
    if syntax is None:
        return out
    if syntax.is_integer:
        if syntax.enum:
            out.extend(ValueSpec("Integer32", v, f"enum:{v}") for v in syntax.enum_values)
        for lo, hi in syntax.ranges:
            out.append(ValueSpec("Integer32", lo, f"range_min:{lo}"))
            out.append(ValueSpec("Integer32", hi, f"range_max:{hi}"))
        if not syntax.enum and not syntax.ranges:
            out.append(ValueSpec("Integer32", INT32_MIN, "int32_min"))
            out.append(ValueSpec("Integer32", INT32_MAX, "int32_max"))
    elif syntax.is_string or syntax.is_address:
        if syntax.size:
            out.append(ValueSpec("OctetString", "A" * syntax.size[1], f"size_max:{syntax.size[1]}"))
    return out


def invalid_values(syntax: SyntaxSpec | None) -> list[ValueSpec]:
    """Values that a conforming agent must reject (wrong type / out of range)."""
    t = asn1_type(syntax)
    out: list[ValueSpec] = []
    if t == "Integer32":
        out.append(ValueSpec("OctetString", "not-an-integer", "wrong_type", valid=False))
        if syntax:
            if syntax.enum:
                used = set(syntax.enum.values())
                candidate = max(used) + 1 if used else 1
                out.append(ValueSpec("Integer32", candidate, "enum_out_of_set", valid=False))
            if syntax.ranges:
                lo, hi = syntax.ranges[0]
                out.append(ValueSpec("Integer32", hi + 1, "above_range", valid=False))
                out.append(ValueSpec("Integer32", lo - 1, "below_range", valid=False))
    elif t in ("OctetString", "IpAddress"):
        out.append(ValueSpec("Integer32", 12345, "wrong_type", valid=False))
        # Only assert over-length when the MIB actually declares a SIZE (or we
        # inferred one from DisplayString's RFC definition).  An unconstrained
        # OCTET STRING legitimately accepts 256 bytes.
        if syntax and syntax.size and syntax.base_type != "IpAddress":
            out.append(ValueSpec("OctetString", "X" * (syntax.size[1] + 1), "over_length", valid=False))
        if t == "IpAddress":
            out.append(ValueSpec("IpAddress", "999.999.999.999", "invalid_address", valid=False))
    return out


def value_assertions(syntax: SyntaxSpec | None) -> list[dict[str, Any]]:
    """Declarative assertions used for a normal GET response."""
    assertions: list[dict[str, Any]] = [
        {"kind": "no_error"},
        {"kind": "varbind_count", "min": 1},
        {"kind": "value_type", "allowed": expected_types(syntax)},
    ]
    if syntax is None:
        return assertions
    if syntax.is_integer:
        if syntax.enum:
            assertions.append({"kind": "value_in", "allowed": list(syntax.enum_values)})
        for lo, hi in syntax.ranges:
            assertions.append({"kind": "value_in_range", "min": lo, "max": hi})
        if not syntax.enum and not syntax.ranges:
            assertions.append({"kind": "value_in_range", "min": INT32_MIN, "max": INT32_MAX})
    # For IpAddress the SIZE constraint is expressed in raw octets, while the
    # normalised value is the dotted-quad text; the type assertion already
    # covers it, so a text-length check would be a false positive.
    if syntax.size and not syntax.is_address:
        assertions.append({"kind": "value_length", "min": syntax.size[0], "max": syntax.size[1]})
    return assertions
