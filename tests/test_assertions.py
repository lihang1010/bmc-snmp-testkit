"""Assertion library unit tests, including v1 / v2c error semantics."""

from __future__ import annotations

import pytest

from snmp_test.model.types import SnmpResponse, TestCase, TrapRecord, Varbind
from snmp_test.runner.assertions import evaluate
from snmp_test.snmp.errors import is_rejection_status, normalize_error_status


def case(assertions, **kwargs):
    return TestCase(
        case_id="TC-test",
        name="unit",
        oid="1.3.6.1.4.1.52305.1.1.0",
        operation=kwargs.get("operation", "GET"),
        version=kwargs.get("version", "v2c"),
        category="normal",
        tags=(),
        payload={},
        expectation={"assertions": assertions},
    )


def response(status="noError", indication=None, varbinds=None, version="v2c"):
    return SnmpResponse(
        error_indication=indication,
        error_status=status,
        error_index=0,
        varbinds=varbinds if varbinds is not None else [Varbind("1.3.6.1.4.1.52305.1.1.0", "OctetString", "bmc")],
        version=version,
        operation="GET",
        target="t",
    )


@pytest.mark.parametrize(
    "raw,expected",
    [(0, "noError"), (2, "noSuchName"), (17, "notWritable"), (6, "noAccess"), ("noError", "noError")],
)
def test_error_status_normalization(raw, expected):
    assert normalize_error_status(raw) == expected


@pytest.mark.parametrize(
    "version,status",
    [("v1", "noSuchName"), ("v1", "badValue"), ("v2c", "notWritable"), ("v3", "noAccess")],
)
def test_rejection_status(version, status):
    assert is_rejection_status(status, version)


def test_positive_get_assertions():
    c = case([
        {"kind": "no_error"},
        {"kind": "varbind_count", "min": 1},
        {"kind": "value_type", "allowed": ["OctetString"]},
        {"kind": "oid_equals", "oid": "1.3.6.1.4.1.52305.1.1.0"},
    ])
    assert evaluate(c, response()).passed


def test_value_domain_assertions():
    c = case([
        {"kind": "value_type", "allowed": ["Integer32"]},
        {"kind": "value_in", "allowed": [0, 1, 2]},
        {"kind": "value_in_range", "min": 0, "max": 2},
    ])
    vb = [Varbind("1.3.6.1.4.1.52305.7.1.1.0", "Integer32", 1)]
    assert evaluate(c, response(varbinds=vb)).passed
    bad = [Varbind("1.3.6.1.4.1.52305.7.1.1.0", "Integer32", 9)]
    out = evaluate(c, response(varbinds=bad))
    assert not out.passed and len(out.failures) >= 2


def test_rejected_accepts_v1_and_v2c_forms():
    c = case([{"kind": "rejected"}])
    assert evaluate(c, response("noSuchName", version="v1")).passed
    assert evaluate(c, response("notWritable", version="v2c")).passed
    assert evaluate(c, response("badValue", version="v1")).passed
    assert evaluate(c, response(indication="clientError: bad OID")).passed
    assert not evaluate(c, response()).passed


def test_no_such_and_end_of_mib():
    c = case([{"kind": "no_such"}])
    assert evaluate(c, response("noSuchName", version="v1")).passed
    assert evaluate(c, response(varbinds=[Varbind("1.3.6.1", "NoSuchInstance", "NoSuchInstance", "NoSuchInstance")])).passed
    eom = case([{"kind": "end_of_mib"}])
    assert evaluate(eom, response("noSuchName", version="v1")).passed
    assert evaluate(eom, response(varbinds=[Varbind("1.3.6.1", "EndOfMibView", "EndOfMibView", "EndOfMibView")])).passed


def test_auth_rejected():
    c = case([{"kind": "auth_rejected"}])
    assert evaluate(c, response(indication="requestTimeout")).passed
    assert evaluate(c, response(indication="authenticationFailure")).passed
    assert evaluate(c, response(varbinds=[])).passed
    assert not evaluate(c, response()).passed


def test_oid_ordering_and_prefix():
    c = case([
        {"kind": "oid_gt", "oid": "1.3.6.1.4.1.52305.1.1"},
        {"kind": "oid_prefix", "prefix": "1.3.6.1.4.1.52305"},
        {"kind": "oid_order"},
    ])
    vbs = [
        Varbind("1.3.6.1.4.1.52305.1.1.0", "OctetString", "a"),
        Varbind("1.3.6.1.4.1.52305.1.3.0", "OctetString", "b"),
    ]
    assert evaluate(c, response(varbinds=vbs)).passed
    unordered = [vbs[1], vbs[0]]
    assert not evaluate(c, response(varbinds=unordered)).passed


def test_trap_assertions():
    c = case([
        {"kind": "trap_received"},
        {"kind": "trap_pdu_type", "expected": "inform"},
        {"kind": "trap_version", "expected": "v3"},
        {"kind": "trap_oid_in", "allowed": ["1.3.6.1.4.1.52305.0.1"]},
        {"kind": "trap_enterprise", "expected": "1.3.6.1.4.1.52305"},
        {"kind": "trap_security_name", "expected": "bmcuser"},
        {"kind": "trap_severity", "expected": 3},
        {"kind": "trap_ack"},
        {"kind": "trap_varbinds", "expected": [
            {"oid": "1.3.6.1.6.3.1.1.4.1.0", "type": "ObjectIdentifier"},
            {"oid": "1.3.6.1.4.1.52305.2.11.1.7.1", "type": "OctetString", "contains": "Critical"},
        ]},
    ])
    trap = TrapRecord(
        pdu_type="inform", version="v3", source="127.0.0.1", security_name="bmcuser",
        trap_oid="1.3.6.1.4.1.52305.0.1", enterprise_oid="1.3.6.1.4.1.52305",
        ack_sent=True, received_at=100.0,
        varbinds=[
            Varbind("1.3.6.1.6.3.1.1.4.1.0", "ObjectIdentifier", "1.3.6.1.4.1.52305.0.1"),
            Varbind("1.3.6.1.4.1.52305.2.11.1.7.1", "OctetString", "Critical"),
        ],
    )
    assert evaluate(c, trap=trap, trigger={"triggered_at": 99.5}).passed
    trap.ack_sent = False
    assert not evaluate(c, trap=trap, trigger={"triggered_at": 99.5}).passed
    assert not evaluate(c, trap=None).passed


def test_trap_latency():
    c = case([{"kind": "trap_latency", "max_s": 1.0}])
    trap = TrapRecord(pdu_type="trap", version="v2c", source="", received_at=100.0)
    assert evaluate(c, trap=trap, trigger={"triggered_at": 99.5}).passed
    assert not evaluate(c, trap=trap, trigger={"triggered_at": 90.0}).passed
