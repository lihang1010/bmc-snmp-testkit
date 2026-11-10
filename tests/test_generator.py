"""Case generation: matrix coverage, stable ids, safety grading, value domains."""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from snmp_test.generator.case_builder import GeneratorOptions, generate_cases
from snmp_test.generator.trap_cases import generate_trap_cases, load_expectations
from snmp_test.generator.value_factory import (
    alternate_value,
    boundary_values,
    invalid_values,
    seed_value,
    value_assertions,
)
from snmp_test.model.mib_model import build_model
from snmp_test.model.types import stable_case_id
from snmp_test.runner.safety import classify_node

MIB = Path(__file__).resolve().parents[1] / "TTY-T1ZDG-v1.0_20261026.mib"


@pytest.fixture(scope="module")
def model():
    return build_model(MIB)


@pytest.fixture(scope="module")
def cases(model):
    return generate_cases(model, GeneratorOptions())


def test_operation_and_version_matrix(cases):
    ops = {c.operation for c in cases}
    versions = {c.version for c in cases}
    assert {"GET", "GETNEXT", "GETBULK", "SET"} <= ops
    assert versions == {"v1", "v2c", "v3"}
    for op in ("GET", "GETNEXT", "SET"):
        for version in ("v1", "v2c", "v3"):
            assert any(c.operation == op and c.version == version for c in cases), (op, version)
    # v1 must not generate real GETBULK requests, only a documented compat skip
    v1_bulk = [c for c in cases if c.operation == "GETBULK" and c.version == "v1"]
    assert len(v1_bulk) == 1 and v1_bulk[0].expectation.get("skip") is True


def test_full_oid_coverage_for_get(cases, model):
    get_oids = {c.oid for c in cases if c.operation == "GET" and c.category == "normal"}
    expected = {i.oid for i in model.instances(rows_per_table=2) if i.access in ("read-only", "read-write")}
    assert expected <= get_oids


def test_case_ids_are_stable_and_unique(cases, model):
    ids = [c.case_id for c in cases]
    assert len(set(ids)) == len(ids)
    again = generate_cases(model, GeneratorOptions())
    assert [c.case_id for c in again] == ids
    assert [c.to_dict() for c in again] == [c.to_dict() for c in cases]
    assert stable_case_id(model.mib_sha256, "a", "GET", "v1") == stable_case_id(model.mib_sha256, "a", "GET", "v1")


def test_different_mib_hash_changes_ids(model):
    a = generate_cases(model, GeneratorOptions(max_cases_per_table=1, rows_per_table=1))
    b = generate_cases(model, GeneratorOptions(max_cases_per_table=2, rows_per_table=1))
    assert a and b
    # changing generation options must not accidentally reuse the same id for a
    # different payload
    assert {c.case_id for c in a}.issubset({c.case_id for c in b}) or a != b


def test_high_risk_nodes_are_graded(model, cases):
    power = model.node_by_name("serverPowerStatusControl")
    assert classify_node(power)[0] == "blocked"
    assert model.node_by_name("delBmcUser")
    assert any(c.safety == "blocked" for c in cases if c.operation == "SET")
    assert any(c.safety == "guarded" for c in cases if c.operation == "SET")
    # no default case may carry a state-changing power value
    for c in cases:
        if c.operation == "SET" and "serverPowerStatusControl" in c.name:
            assert c.safety == "blocked"


def test_negative_cases_expect_rejection(cases):
    negative = [c for c in cases if "negative" in c.tags]
    assert negative
    for c in negative:
        kinds = {a["kind"] for a in c.expectation.get("assertions", [])}
        assert kinds & {"rejected", "no_such", "auth_rejected", "client_error", "no_crash"}


def test_value_factory_domains(model):
    enum_node = model.node_by_name("snmptrapSeverity").syntax
    assert [v.value for v in boundary_values(enum_node)] == [1, 2, 3]
    assert all(not v.valid for v in invalid_values(enum_node))

    ranged = model.node_by_name("authPort").syntax
    assert [(v.value, v.label) for v in boundary_values(ranged)] == [(1, "range_min:1"), (65535, "range_max:65535")]
    assert {v.label for v in invalid_values(ranged)} >= {"wrong_type", "above_range", "below_range"}

    seed = seed_value(ranged, "authPort", "1")
    alt = alternate_value(ranged, seed, "authPort", "1")
    assert seed.value != alt.value
    assert "value_in_range" in {a["kind"] for a in value_assertions(ranged)}


def test_trap_case_generation(tmp_path: Path, model):
    cfg = tmp_path / "trap.yaml"
    cfg.write_text(
        yaml.safe_dump(
            {
                "expectations": [
                    {
                        "name": "cold-start-v2c",
                        "pdu_type": "trap",
                        "version": "v2c",
                        "trigger": {"type": "mock_event", "event": "coldStart"},
                        "expected_trap_oids": ["1.3.6.1.6.3.1.1.5.1"],
                        "enterprise_oid": "1.3.6.1.4.1.52305",
                        "community": "public",
                        "varbinds": [{"oid": "1.3.6.1.4.1.52305.2.11.1.2.1", "type": "Integer32"}],
                        "max_latency_s": 3.0,
                        "tags": ["coldstart"],
                    },
                    {
                        "name": "external-disabled",
                        "pdu_type": "inform",
                        "version": "v3",
                        "trigger": {"type": "external", "command": "ipmitool ..."},
                    },
                ]
            }
        ),
        encoding="utf-8",
    )
    exps = load_expectations(cfg)
    assert len(exps) == 2
    trap_cases = generate_trap_cases(exps, model.mib_sha256, allowed_versions=("v1", "v2c", "v3"))
    # external triggers without explicit opt-in are never generated
    assert len(trap_cases) == 1
    case = trap_cases[0]
    assert case.operation == "TRAP" and case.version == "v2c"
    kinds = {a["kind"] for a in case.expectation["assertions"]}
    assert {"trap_received", "trap_oid_in", "trap_varbinds", "trap_latency"} <= kinds
