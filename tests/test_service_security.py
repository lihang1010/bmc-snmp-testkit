"""Service security guard: no API path may bypass the live confirmation."""

from __future__ import annotations

import asyncio
from pathlib import Path

import pytest

from snmp_test.config import load_config
from snmp_test.model.mib_model import build_model
from snmp_test.runner.executor import Runtime
from snmp_test.security import AccessDenied, AuthStore, SecurityPolicy, User

ROOT = Path(__file__).resolve().parents[1]
MIB = ROOT / "TTY-T1ZDG-v1.0_20261026.mib"


def _cfg(mode="mock", host="127.0.0.1"):
    cfg = load_config(ROOT / "config" / "config.example.yaml")
    cfg.raw["mode"] = mode
    cfg.raw["targets"] = [{
        "name": "t", "enabled": True, "host": host, "port": 161,
        "versions": ["v1"], "v1": {"community": "c", "read_only_community": "c"},
    }]
    return cfg


def test_runtime_blocks_live_without_confirmation(tmp_path):
    cfg = _cfg("live", "192.0.2.10")
    model = build_model(MIB)
    with pytest.raises(AccessDenied) as exc:
        Runtime(cfg, model, run_dir=tmp_path / "r", security=SecurityPolicy(allow_live=False))
    assert "confirmation" in str(exc.value)


def test_runtime_blocks_host_outside_allowlist(tmp_path):
    cfg = _cfg("live", "192.0.2.10")
    model = build_model(MIB)
    policy = SecurityPolicy(allow_live=True, allowed_targets=("192.0.2.99",), readonly_only=True)
    with pytest.raises(AccessDenied) as exc:
        Runtime(cfg, model, run_dir=tmp_path / "r", security=policy)
    assert "not in" in str(exc.value)


def test_cli_style_confirmation_populates_allowlist():
    cfg = _cfg("live", "192.0.2.10")
    policy = SecurityPolicy.from_config(cfg, allow_live=True)
    assert policy.allow_live
    assert cfg.targets[0].host in policy.allowed_targets
    policy.enforce(cfg)  # must not raise


def test_readonly_policy_disables_set_and_non_get():
    cfg = _cfg("mock")
    policy = SecurityPolicy(readonly_only=True)
    assert policy.effective_set_enabled(cfg) is False
    assert policy.allows_operation("GET") is True
    assert policy.allows_operation("GETNEXT") is True
    assert policy.allows_operation("SET") is False


def test_mock_mode_never_requires_live_confirmation(tmp_path):
    cfg = _cfg("mock")
    model = build_model(MIB)
    runtime = Runtime(cfg, model, run_dir=tmp_path / "mock", security=SecurityPolicy(readonly_only=True))

    async def start_stop():
        await runtime.start()
        await runtime.stop()

    asyncio.run(start_stop())
    runtime.close()


def test_auth_store_roles_and_dev_fallback():
    store = AuthStore([
        User("alice", "tok-a", "operator"),
        User("bob", "tok-b", "viewer"),
        User("root", "tok-c", "admin"),
    ])
    assert store.authenticate("tok-a").name == "alice"
    assert store.authenticate("tok-a").can("write") is True
    assert store.authenticate("tok-a").can("live") is False
    assert store.authenticate("tok-b").can("write") is False
    assert store.authenticate("tok-c").can("live") is True
    assert store.authenticate("wrong") is None
    assert store.authenticate(None) is None
    dev = AuthStore.load(ROOT / "config" / "__missing__.yaml")
    assert dev.dev_token and dev.authenticate(dev.dev_token).role == "admin"
