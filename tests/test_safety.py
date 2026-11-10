"""Safety gateway: classification, backup/restore, abort and credential masking."""

from __future__ import annotations

import asyncio
import logging

import pytest

from snmp_test.config import CredentialMaskingFilter, collect_secrets, load_config, mask_secrets
from snmp_test.model.types import SnmpResponse, TestCase, Varbind
from snmp_test.runner.safety import SafetyAbort, SafetyGateway, blocked_nodes, classify_node, load_policy

OID = "1.3.6.1.4.1.52305.1.1.0"


class FakeSession:
    def __init__(self, value="original", *, set_ok=True, restore_ok=True):
        self.store = {OID: value}
        self.calls: list[tuple[str, list]] = []
        self.set_count = 0
        self.set_ok = set_ok
        self.restore_ok = restore_ok

    async def get(self, oids, **kwargs):
        varbinds = kwargs.get("varbinds")
        keys = [v["oid"] for v in varbinds] if varbinds is not None else list(oids)
        self.calls.append(("GET", keys))
        return SnmpResponse(
            None, "noError", 0,
            [Varbind(k, "OctetString", self.store.get(k, "")) for k in keys],
            "v2c", "GET", "t",
        )

    async def set(self, varbinds):
        self.set_count += 1
        self.calls.append(("SET", [v["oid"] for v in varbinds]))
        is_restore = self.set_count > 1
        ok = self.set_ok if not is_restore else self.restore_ok
        if not ok:
            return SnmpResponse(None, "notWritable", 1, [], "v2c", "SET", "t")
        for v in varbinds:
            self.store[v["oid"]] = v["value"]
        return SnmpResponse(
            None, "noError", 0,
            [Varbind(v["oid"], "OctetString", v["value"]) for v in varbinds],
            "v2c", "SET", "t",
        )


def set_case(safety="safe", node_name="hostname"):
    return TestCase(
        case_id="TC-set", name="SET test", oid=OID, operation="SET", version="v2c",
        category="normal", tags=("set",), payload={"node_name": node_name, "target": "t"},
        expectation={"assertions": [{"kind": "no_error"}]}, safety=safety,
    )


def run(coro):
    return asyncio.run(coro)


def test_classification_of_high_risk_nodes(offline_model):
    power = offline_model.node_by_name("serverPowerStatusControl")
    assert classify_node(power)[0] == "blocked"
    assert power.name in blocked_nodes(offline_model)
    assert classify_node(offline_model.node_by_name("hostname"))[0] == "safe"
    ip = next(n for n in offline_model.nodes if n.syntax and n.syntax.base_type == "IpAddress")
    assert classify_node(ip)[0] == "guarded"


def test_gateway_blocks_guarded_by_default():
    gw = SafetyGateway()
    assert gw.check(set_case("blocked"))[0] is False
    assert "never" in gw.check(set_case("blocked"))[1]
    assert gw.check(set_case("guarded"))[0] is False
    assert gw.check(set_case("safe"))[0] is True


def test_guarded_requires_explicit_whitelist():
    policy = load_policy(None)
    policy = {**policy, "whitelist": {"names": ["hostname"]}}
    gw = SafetyGateway(policy, allow_guarded=True)
    assert gw.check(set_case("guarded", "hostname"))[0] is True
    assert gw.check(set_case("guarded", "other"))[0] is False


def test_set_disabled_globally():
    gw = SafetyGateway(set_enabled=False)
    assert gw.check(set_case("safe"))[0] is False


def test_backup_set_readback_restore(tmp_path):
    gw = SafetyGateway(audit_path=tmp_path / "audit.jsonl")
    session = FakeSession()
    response, trace = run(gw.guarded_set(session, set_case(), [{"oid": OID, "asn1": "OctetString", "value": "new"}]))
    assert response.ok
    assert session.store[OID] == "original", "value must be restored"
    assert [op for op, _ in session.calls] == ["GET", "SET", "GET", "SET", "GET"]
    assert any("restore_verify" in t for t in trace)
    assert (tmp_path / "audit.jsonl").is_file()


def test_restore_failure_aborts(tmp_path):
    gw = SafetyGateway(audit_path=tmp_path / "audit.jsonl")
    session = FakeSession(restore_ok=False)
    with pytest.raises(SafetyAbort) as exc:
        run(gw.guarded_set(session, set_case(), [{"oid": OID, "asn1": "OctetString", "value": "new"}]))
    assert exc.value.target == "t"
    assert "aborting" in str(exc.value)


def test_rejected_set_skips_restore(tmp_path):
    gw = SafetyGateway(audit_path=tmp_path / "audit.jsonl")
    session = FakeSession(set_ok=False)
    response, trace = run(gw.guarded_set(session, set_case(), [{"oid": OID, "asn1": "OctetString", "value": "new"}]))
    assert not response.ok
    assert session.set_count == 1
    assert any("skipped" in t for t in trace)
    assert session.store[OID] == "original"


def test_config_masking_and_env_interpolation(example_config_path, monkeypatch, tmp_path):
    monkeypatch.setenv("SNMP_V3_AUTH_KEY", "super-secret-auth")
    cfg = load_config(example_config_path)
    assert cfg.validate() == []
    assert "super-secret-auth" in cfg.secrets
    masked = cfg.masked()
    assert "super-secret-auth" not in str(masked)
    assert "***" in str(masked)
    assert mask_secrets({"community": "public", "note": "ok"})["community"] == "***"
    assert collect_secrets({"nested": [{"auth_key": "abcd1234"}]}) == ["abcd1234"]

    record = logging.LogRecord("n", 20, "x", 1, "auth=%s", ("super-secret-auth",), None)
    assert CredentialMaskingFilter(cfg.secrets).filter(record)
    assert "super-secret-auth" not in record.getMessage()


def test_live_mode_requires_explicit_opt_in(example_config_path):
    from snmp_test.cli import build_parser, cmd_run

    parser = build_parser()
    args = parser.parse_args(["--config", str(example_config_path), "run", "--mode", "live"])
    assert args.allow_live is False
    # The CLI must refuse to contact a real device without --allow-live.
    assert cmd_run(args) == 2
