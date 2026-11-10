"""Safety policy for SET operations: classification, backup/restore and audit.

Design goal: the framework must never change BMC state by default.  Every SET is
1. classified at generation time (safe / guarded / blocked),
2. re-checked at execution time,
3. preceded by a GET backup and followed by a guaranteed restore in ``finally``.

A failed restore aborts all remaining SET cases for that target, because continuing
would leave the device in an unknown state.
"""

from __future__ import annotations

import json
import re
import time
from pathlib import Path
from typing import Any, Protocol

from snmp_test.model.types import MibNode, SnmpResponse, TestCase

DEFAULT_POLICY: dict[str, Any] = {
    "version": 1,
    "set_enabled": True,
    "restore_on_failure_abort_target": True,
    "hard_block": {
        "names": ["serverPowerStatusControl", "addBmcUser", "delBmcUser"],
        "name_patterns": [r"(?i)power.*(control|cycle|reset|off|on)$"],
    },
    "blacklist": {
        "access": ["write-only"],
        "names": ["delBmcUserSession", "deleteSession", "sessionDelete", "clearEventLog"],
        "name_patterns": [
            r"(?i)ipv4(address|gateway|subnetmask)$",
            r"(?i)ipv6(address|gateway)$",
            r"(?i)(add|del|delete|remove).*(user|session)$",
            r"(?i)(passwd|password|secret|community)$",
        ],
        "oid_prefixes": [],
    },
    "whitelist": {"names": []},
}


class SafetyAbort(RuntimeError):
    """Raised when a restore failed; the executor must stop SET cases for the target."""

    def __init__(self, target: str, message: str) -> None:
        super().__init__(message)
        self.target = target


class SessionLike(Protocol):
    async def get(self, oids: list[str]) -> SnmpResponse: ...

    async def set(self, varbinds: list[dict[str, Any]]) -> SnmpResponse: ...


def load_policy(path: str | Path | None) -> dict[str, Any]:
    if not path:
        return dict(DEFAULT_POLICY)
    p = Path(path)
    if not p.is_file():
        return dict(DEFAULT_POLICY)
    import yaml

    loaded = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
    merged = dict(DEFAULT_POLICY)
    for key, value in loaded.items():
        if isinstance(value, dict) and isinstance(merged.get(key), dict):
            merged[key] = {**merged[key], **value}
        else:
            merged[key] = value
    return merged


def _matches(node: MibNode, section: dict[str, Any]) -> str | None:
    for name in section.get("names", []) or []:
        if node.name == name:
            return f"name:{name}"
    for pattern in section.get("name_patterns", []) or []:
        if re.search(pattern, node.name):
            return f"pattern:{pattern}"
    for prefix in section.get("oid_prefixes", []) or []:
        if node.oid.startswith(prefix):
            return f"oid_prefix:{prefix}"
    if node.access in (section.get("access") or []):
        return f"access:{node.access}"
    return None


def classify_node(node: MibNode, policy: dict[str, Any] | None = None) -> tuple[str, str]:
    """Return ``(safety_level, reason)`` for a node."""
    policy = policy or DEFAULT_POLICY
    whitelist = policy.get("whitelist", {}).get("names", []) or []
    if node.name in whitelist:
        return "safe", f"explicitly whitelisted:{node.name}"
    hit = _matches(node, policy.get("hard_block", {}) or {})
    if hit:
        return "blocked", f"hard_block:{hit}"
    hit = _matches(node, policy.get("blacklist", {}) or {})
    if hit:
        return "guarded", f"blacklist:{hit}"
    return "safe", "default"


def blocked_nodes(model, policy: dict[str, Any] | None = None) -> list[str]:
    return [n.name for n in model.nodes if classify_node(n, policy)[0] == "blocked"]


class SafetyGateway:
    """Runtime gatekeeper shared by the executor and the pytest plugin."""

    def __init__(
        self,
        policy: dict[str, Any] | None = None,
        *,
        allow_guarded: bool = False,
        set_enabled: bool = True,
        audit_path: str | Path | None = None,
    ) -> None:
        self.policy = policy or DEFAULT_POLICY
        self.allow_guarded = bool(allow_guarded)
        self.set_enabled = bool(set_enabled) and bool(self.policy.get("set_enabled", True))
        self.audit_path = Path(audit_path) if audit_path else None
        if self.audit_path:
            self.audit_path.parent.mkdir(parents=True, exist_ok=True)

    def check(self, case: TestCase) -> tuple[bool, str]:
        if case.operation != "SET":
            return True, ""
        if not self.set_enabled:
            return False, "SET disabled by configuration / safety policy"
        if case.safety == "blocked":
            return False, "hard-blocked OID: state-changing operation is never allowed"
        if case.safety == "guarded" and not self.allow_guarded:
            return False, "guarded OID requires explicit whitelist and --allow-guarded"
        if case.safety == "guarded" and self.allow_guarded:
            names = self.policy.get("whitelist", {}).get("names", []) or []
            node_name = case.payload.get("node_name", "")
            if node_name not in names:
                return False, "guarded OID is not in the explicit whitelist"
        return True, ""

    async def guarded_set(
        self,
        session: SessionLike,
        case: TestCase,
        varbinds: list[dict[str, Any]],
    ) -> tuple[SnmpResponse, list[str]]:
        """SET with backup/read-back/restore.  Returns ``(set_response, trace)``."""
        trace: list[str] = []
        oids = [v["oid"] for v in varbinds]
        backup = await session.get(oids)
        trace.append(f"backup: {backup.to_dict()}")
        if not backup.ok or not backup.varbinds:
            raise RuntimeError(f"backup GET failed for {oids}; SET refused without a restore point")
        if any(vb.exception for vb in backup.varbinds):
            raise RuntimeError(f"backup GET returned an exception for {oids}; SET refused")

        integer_types = {"Integer32", "Integer", "Unsigned32", "Gauge32", "Counter32", "Counter64", "TimeTicks"}
        originals: list[dict[str, Any]] = []
        for vb in backup.varbinds:
            if vb.type in integer_types:
                asn1 = "Integer32"
            elif vb.type in ("OctetString", "DisplayString", "Opaque", "Bits"):
                asn1 = "OctetString"
            elif vb.type == "IpAddress":
                asn1 = "IpAddress"
            else:
                raise RuntimeError(f"unsupported backup type {vb.type!r} for {vb.oid}")
            originals.append({"oid": vb.oid, "asn1": asn1, "value": vb.value})

        response: SnmpResponse | None = None
        try:
            response = await session.set(varbinds)
            trace.append(f"set: {response.to_dict()}")
            if response.ok:
                readback = await session.get(oids)
                trace.append(f"readback: {readback.to_dict()}")
                if not readback.ok:
                    response.raw += " | readback failed after SET"
                elif readback.varbinds and str(readback.varbinds[0].value) != str(varbinds[0].get("value")):
                    response.raw += " | readback value differs from requested value"
        finally:
            if response is not None and response.ok:
                restore = await session.set(originals)
                trace.append(f"restore: {restore.to_dict()}")
                verify = await session.get(oids)
                trace.append(f"restore_verify: {verify.to_dict()}")
                if not restore.ok or not verify.ok:
                    raise SafetyAbort(
                        case.payload.get("target", ""),
                        f"restore failed for {oids}; aborting remaining SET cases",
                    )
            else:
                # A rejected SET cannot have changed state; the restore SET would
                # itself be refused (e.g. read-only community) and must not abort.
                trace.append("restore: skipped (SET rejected, no state changed)")
            self._audit(case, originals, varbinds, response, trace)
        assert response is not None
        return response, trace

    def _audit(
        self,
        case: TestCase,
        originals: list[dict[str, Any]],
        varbinds: list[dict[str, Any]],
        response: SnmpResponse | None,
        trace: list[str],
    ) -> None:
        if not self.audit_path:
            return
        entry = {
            "ts": time.time(),
            "case_id": case.case_id,
            "target": case.payload.get("target", ""),
            "oid": [v["oid"] for v in varbinds],
            "backup": originals,
            "requested": varbinds,
            "set_ok": bool(response and response.ok),
            "restore_verified": "restore_verify" in " ".join(trace),
        }
        with self.audit_path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(entry, ensure_ascii=False, default=str) + "\n")
