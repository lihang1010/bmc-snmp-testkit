"""Integrity assertions for the tolerant MIB parser against the real input MIB."""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from snmp_test.model.mib_model import build_model
from snmp_test.model.mib_parser import MibParser

MIB = Path(__file__).resolve().parents[1] / "TTY-T1ZDG-v1.0_20261026.mib"


@pytest.fixture(scope="module")
def model():
    return build_model(MIB)


def test_mib_file_is_present_and_read_only_input():
    assert MIB.is_file()
    assert MIB.stat().st_size > 200_000


def test_parsing_baseline_matches_manual_audit(model):
    s = model.stats
    assert s["source_lines"] == 11414
    assert s["object_types"] == 1130
    assert s["object_identifiers"] == 29  # 38 lines 12-49 minus 9 commented ones
    assert s["sequence_types"] == 39
    assert s["tables"] == 39
    assert s["entries"] == 39
    assert s["columns"] == 941
    assert s["scalars"] == 111
    assert s["resolved_nodes"] == 1159
    assert s["unresolved_nodes"] == 0
    assert s["notifications"] == 0
    assert s["commented_object_types"] == 71
    assert s["commented_object_identifiers"] == 9
    assert s["section_markers"] == 59
    assert s["inline_enums"] == 91
    assert s["description_forms"] == {"empty": 661, "single_line": 37, "multi_line": 432}
    assert s["access"] == {
        "read-only": 940,
        "read-write": 137,
        "write-only": 7,
        "not-accessible": 46,
    }
    assert s["by_kind"] == {"group": 29, "table": 39, "entry": 39, "column": 941, "scalar": 111}


def test_root_and_module(model):
    assert model.root_oid == "1.3.6.1.4.1.52305"
    assert model.module_name == "TTY-T4XDG-v1-4-MIB"
    assert model.node_by_name("ttyRoot").oid == "1.3.6.1.4.1.52305"
    assert len(model.mib_sha256) == 64


def test_module_filename_mismatch_is_reported(model):
    assert any(w["code"] == "MODULE_FILENAME_MISMATCH" for w in model.warnings)


def test_commented_definitions_are_excluded(model):
    for name in ("platformInfo", "meVersion", "kvmMouseSetting", "powerConf", "eepromControl"):
        assert model.node_by_name(name) is None
    assert model.node_by_name("hostname") is not None


def test_oid_numbers_are_not_assumed_continuous(model):
    # serverSysInfo children 2 and 10 are commented out; the remaining ones keep
    # their explicit sub-identifiers.
    children = {n.sub_id: n.name for n in model.nodes if n.parent_name == "serverSysInfo"}
    assert 1 in children and 3 in children
    assert 2 not in children and 10 not in children


def test_inline_enum_and_range(model):
    snmptrap_enable = model.node_by_name("snmptrapEnable")
    assert snmptrap_enable.syntax.is_integer
    assert snmptrap_enable.syntax.enum == {"diabled": 0, "enable": 1}
    assert snmptrap_enable.syntax.enum_values == (0, 1)

    auth_port = model.node_by_name("authPort")
    assert auth_port.syntax.ranges == ((1, 65535),)
    assert auth_port.syntax.enum == {}

    health = model.node_by_name("memoryHealth")
    assert health.syntax.enum == {"normal": 0, "abnormal": 1, "absent": 2}


def test_string_and_address_syntax(model):
    assert model.node_by_name("hostname").syntax.base_type == "OCTET STRING"
    assert model.node_by_name("pcieInfoNo").syntax.base_type == "DisplayString"
    assert model.node_by_name("pcieInfoNo").syntax.size == (0, 255)
    ip_nodes = [n for n in model.nodes if n.syntax and n.syntax.base_type == "IpAddress"]
    assert len(ip_nodes) == 3


def test_tables_columns_and_index(model):
    trap_table = next(t for t in model.tables if t["name"] == "snmptrapPoliciesTable")
    assert trap_table["oid"] == "1.3.6.1.4.1.52305.3.13.1"
    assert trap_table["entry_name"] == "snmptrapPoliciesEntry"
    assert trap_table["index_names"] == ["snmptrapIndex"]
    assert trap_table["column_count"] == 16

    col = model.node_by_name("snmptrapEnable")
    assert col.kind == "column"
    assert col.table_name == "snmptrapPoliciesTable"
    assert col.oid == "1.3.6.1.4.1.52305.3.13.1.1.2"
    assert col.access == "read-write"

    # a name ending in "Table" that is really a column
    assert model.node_by_name("raidLogicalInfoBadBlocksTable").kind == "column"


def test_high_risk_nodes_detected(model):
    power = model.node_by_name("serverPowerStatusControl")
    assert power is not None
    assert power.access == "write-only"
    assert power.syntax.enum == {
        "powerOff": 0, "powerOn": 1, "powerCycle": 2, "hardReset": 3, "ACPIClose": 4
    }
    assert model.node_by_name("addBmcUser").access == "write-only"
    assert model.node_by_name("delBmcUser").access == "write-only"


def test_instances_are_expanded_with_explicit_indices(model):
    instances = model.instances(rows_per_table=2)
    scalars = [i for i in instances if i.kind == "scalar"]
    columns = [i for i in instances if i.kind == "column"]
    assert len(scalars) == 111
    assert len(columns) == 941 * 2
    assert all(i.oid.endswith(".0") for i in scalars)
    assert all(i.row_index in ("1", "2") for i in columns)
    assert all(i.module for i in instances)


def test_limiting_columns_per_table(model):
    full = model.instances(rows_per_table=1)
    limited = model.instances(rows_per_table=1, max_columns_per_table=2)
    assert len(limited) < len(full)
    assert len(limited) == 111 + 39 * 2


def test_model_json_round_trip(model):
    from snmp_test.model.types import MibModel

    restored = MibModel.from_dict(__import__("json").loads(model.to_json()))
    assert restored.mib_sha256 == model.mib_sha256
    assert len(restored.nodes) == len(model.nodes)
    assert restored.node_by_name("authPort").syntax.ranges == ((1, 65535),)


def test_parser_is_deterministic():
    p = MibParser(MIB)
    a, b = p.parse(), p.parse()
    assert a.stats == b.stats
    assert [d.to_dict() for d in a.definitions] == [d.to_dict() for d in b.definitions]


def test_no_inline_comments_or_same_line_double_assign(model):
    text = MIB.read_text(encoding="utf-8", errors="replace")
    # Regression guards: this MIB has no trailing comments and no '::=' inside
    # descriptions.  If a future revision adds them, the parser must be revisited.
    assert not re.search(r"\S[^\S\n]+--[^\S\n]*\S", text)
    assert not re.search(r'::=[^\n]*"[^"]*::=', text)
