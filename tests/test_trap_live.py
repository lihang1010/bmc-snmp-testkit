"""Live-style trap/inform matching: content correlation and target credentials."""

from __future__ import annotations

import asyncio
import copy
import time
from pathlib import Path

from pysnmp.hlapi.v3arch.asyncio import (
    CommunityData,
    ContextData,
    ObjectIdentity,
    ObjectType,
    SnmpEngine,
    UdpTransportTarget,
    UsmUserData,
    send_notification,
)
from pysnmp.proto.rfc1902 import ObjectIdentifier, TimeTicks

from snmp_test.config import Config, load_config
from snmp_test.model.types import TestCase
from snmp_test.runner.executor import Runtime
from snmp_test.snmp.mock_agent import NOTIFY_ENGINE_ID
from snmp_test.snmp.trap_listener import (
    NOTIFY_ENGINE_ID_HEX,
    TrapListener,
    engine_id_hex,
)
from snmp_test.snmp.transport import AUTH_PROTOCOLS, PRIV_PROTOCOLS

ROOT = Path(__file__).resolve().parents[1]
CONFIG = ROOT / "config" / "config.example.yaml"
TRAP_PORT = 11912
TRAP_OID = "1.3.6.1.4.1.52305.0.1"
COMMUNITY = "live-trap-community"
V3_USER = "trapsink"


def _live_config(mode: str = "live") -> Config:
    cfg = load_config(CONFIG)
    raw = copy.deepcopy(cfg.raw)
    raw["mode"] = mode
    raw["targets"] = [{
        "name": "lab-bmc",
        "enabled": True,
        "host": "127.0.0.1",
        "port": 11911,
        "versions": ["v1", "v2c", "v3"],
        "v1": {"community": COMMUNITY, "read_only_community": COMMUNITY},
        "v2c": {"community": COMMUNITY, "read_only_community": COMMUNITY},
        "v3": {
            "user": V3_USER,
            "auth_protocol": "SHA",
            "auth_key": "authpass123",
            "priv_protocol": "AES128",
            "priv_key": "privpass123",
            "security_level": "authPriv",
        },
    }]
    # Prove the listener accepts credentials from targets[], not the mock block.
    raw["mock"]["communities"] = {}
    raw["mock"]["v3"] = {}
    raw["trap"]["listen_port"] = TRAP_PORT
    return Config(raw, CONFIG)


def _run(body):
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        return loop.run_until_complete(body())
    finally:
        loop.close()
        asyncio.set_event_loop(None)


def _trap_varbinds(trap_oid: str = TRAP_OID):
    return (
        ObjectType(ObjectIdentity("1.3.6.1.2.1.1.3.0"), TimeTicks(0)),
        ObjectType(ObjectIdentity("1.3.6.1.6.3.1.1.4.1.0"), ObjectIdentifier(trap_oid)),
    )


async def _send_v2c(community: str = COMMUNITY, trap_oid: str = TRAP_OID) -> None:
    engine = SnmpEngine()
    try:
        target = await UdpTransportTarget.create(("127.0.0.1", TRAP_PORT), timeout=2.0, retries=0)
        await send_notification(
            engine, CommunityData(community, mpModel=1), target, ContextData(), "trap",
            *_trap_varbinds(trap_oid),
        )
    finally:
        engine.transport_dispatcher.close_dispatcher()
        await asyncio.sleep(0)


def test_listener_matches_live_trap_without_correlation_id():
    cfg = _live_config()

    async def body():
        listener = TrapListener(cfg)
        await listener.start()
        try:
            started = time.time()
            await _send_v2c()
            record = await listener.wait_for_match(
                pdu_type="trap", version="v2c", trap_oids=[TRAP_OID],
                source="127.0.0.1", after=started,
                claimant="TC-live-1", claim=True, timeout=3.0,
            )
            assert record is not None, listener.snapshot()
            assert record.correlation_id == ""  # real devices do not inject one
            assert record.trap_oid == TRAP_OID
            assert "127.0.0.1" in record.source
            assert record.claimed_by == "TC-live-1"
            # A claimed record must not satisfy a second case.
            assert await listener.wait_for_match(
                pdu_type="trap", version="v2c", trap_oids=[TRAP_OID],
                claimant="TC-live-2", claim=True, timeout=0.3,
            ) is None
        finally:
            await listener.stop()

    _run(body)


def test_listener_rejects_wrong_oid_and_source():
    cfg = _live_config()

    async def body():
        listener = TrapListener(cfg)
        await listener.start()
        try:
            started = time.time()
            await _send_v2c(trap_oid=TRAP_OID)
            assert await listener.wait_for_match(
                pdu_type="trap", version="v2c", trap_oids=["1.3.6.1.4.1.52305.0.9"],
                after=started, timeout=0.3,
            ) is None
            assert await listener.wait_for_match(
                pdu_type="trap", version="v2c", trap_oids=[TRAP_OID],
                source="192.0.2.99", after=started, timeout=0.3,
            ) is None
            record = await listener.wait_for_match(
                pdu_type="trap", version="v2c", trap_oids=[TRAP_OID],
                source="127.0.0.1", after=started, timeout=0.3,
            )
            assert record is not None
        finally:
            await listener.stop()

    _run(body)


def test_listener_accepts_v3_trap_after_engine_registration():
    cfg = _live_config()
    target = cfg.targets[0]

    async def body():
        listener = TrapListener(cfg)
        await listener.start()
        try:
            # Simulates the executor discovering snmpEngineID.0 before waiting.
            listener.register_target(target, NOTIFY_ENGINE_ID_HEX)
            started = time.time()
            engine = SnmpEngine(snmpEngineID=NOTIFY_ENGINE_ID)
            try:
                udp_target = await UdpTransportTarget.create(("127.0.0.1", TRAP_PORT), timeout=2.0, retries=0)
                auth = UsmUserData(
                    V3_USER,
                    authKey="authpass123",
                    privKey="privpass123",
                    authProtocol=AUTH_PROTOCOLS["SHA"],
                    privProtocol=PRIV_PROTOCOLS["AES128"],
                    securityEngineId=NOTIFY_ENGINE_ID,
                )
                await send_notification(engine, auth, udp_target, ContextData(), "trap", *_trap_varbinds())
            finally:
                engine.transport_dispatcher.close_dispatcher()
                await asyncio.sleep(0)
            record = await listener.wait_for_match(
                pdu_type="trap", version="v3", trap_oids=[TRAP_OID],
                source="127.0.0.1", after=started, timeout=3.0,
            )
            assert record is not None, listener.snapshot()
            assert record.security_name == V3_USER
        finally:
            await listener.stop()

    _run(body)


def test_engine_id_hex_normalisation():
    assert engine_id_hex("0x800000000102030405") == NOTIFY_ENGINE_ID_HEX
    assert engine_id_hex("800000000102030405") == NOTIFY_ENGINE_ID_HEX
    assert engine_id_hex(NOTIFY_ENGINE_ID) == NOTIFY_ENGINE_ID_HEX
    assert engine_id_hex("abc") == ""


def test_runtime_live_case_falls_back_to_passive_matching(tmp_path: Path):
    cfg = _live_config()
    model_cfg = load_config(CONFIG)
    from snmp_test.model.mib_model import build_model

    model = build_model(model_cfg.mib_path)
    case = TestCase(
        case_id="TC-live-passive",
        name="live-passive-trap",
        oid="",
        operation="TRAP",
        version="v2c",
        category="trap",
        tags=("trap", "v2c"),
        payload={
            # mock_event cannot be synthesised on a real BMC; live mode must
            # downgrade it to passive content matching.
            "trigger": {"type": "mock_event", "enabled": True},
            "trap_expectation": {
                "name": "live-passive-trap",
                "pdu_type": "trap",
                "version": "v2c",
                "expected_trap_oids": [TRAP_OID],
                "max_latency_s": 5.0,
            },
        },
        expectation={"assertions": [
            {"kind": "trap_received"},
            {"kind": "trap_pdu_type", "expected": "trap"},
            {"kind": "trap_version", "expected": "v2c"},
            {"kind": "trap_oid_in", "allowed": [TRAP_OID]},
        ]},
        safety="safe",
        module="notification",
    )

    async def body():
        runtime = Runtime(
            cfg, model, run_id="live-trap", run_dir=tmp_path / "runs" / "live-trap",
            allow_live=True, readonly_only=True,
        )
        await runtime.start()
        try:
            async def sender():
                await asyncio.sleep(0.3)
                await _send_v2c()

            task = asyncio.create_task(sender())
            results = await runtime.run([case])
            await task
            return results
        finally:
            await runtime.stop()
            runtime.close()

    results = _run(body)
    assert len(results) == 1
    result = results[0]
    assert result.status == "passed", result.message
    assert result.actual["trigger"]["passive"] is True
    assert result.actual["trap"]["correlation_id"] == ""
    assert result.actual["trap"]["trap_oid"] == TRAP_OID
