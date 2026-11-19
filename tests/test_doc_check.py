from __future__ import annotations

from pathlib import Path

from docx import Document

from snmp_test.model.mib_model import build_model
from snmp_test.model.types import MibModel, MibNode, SyntaxSpec
from snmp_test.service.doc_check import (
    DocRow,
    append_missing_docx,
    apply_fixes,
    apply_mib_fixes,
    build_changes,
    compare_rows,
    extract_notes,
    parse_docx,
)
import shutil

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "tests" / "fixtures" / "TEST-IF-MIB.mib"
HEADERS = ["节点", "数据类型", "含义", "实现规格", "状态"]


def _document(path: Path, rows: list[list[str]]) -> Path:
    doc = Document()
    table = doc.add_table(rows=1, cols=5)
    for index, header in enumerate(HEADERS):
        table.rows[0].cells[index].text = header
    for values in rows:
        cells = table.add_row().cells
        for index, value in enumerate(values):
            cells[index].text = value
    doc.save(path)
    return path


def _rows() -> list[list[str]]:
    return [
        ["testIfIndex OID:1.3.6.1.2.1.999.1.1.1.1", "Integer32", "索引", "read-only", "current"],
        ["testIfDescr OID:1.3.6.1.2.1.999.1.1.1.2", "Integer32", "描述", "read-only", "current"],
        ["testIfOpStatus OID:1.3.6.1.2.1.999.1.1.1.4", "Integer32", "状态", "read-only", "current"],
        ["notInMib OID:1.3.6.1.2.1.999.1.1.99.1", "Integer32", "不存在", "read-only", "current"],
        ["testIfIndex OID:1.3.6.1.2.1.999.1.1.1.1#dup", "Integer32", "重复", "read-only", "current"],
        ["serviceInterface OID:1.3.6.1.2.1.999.1.1.1.3", "DisplayString", "界面", "详见{备注1}", "current"],
    ]


def test_parse_compare_and_fix_docx(tmp_path: Path):
    source = _document(tmp_path / "source.docx", _rows())
    document = Document(source)
    document.add_paragraph("备注1：只有 web 服务该项具有 read-write 属性。")
    document.save(source)
    parsed = parse_docx(source)
    assert len(parsed) == 6
    assert parsed[0].name == "testIfIndex"
    assert parsed[0].oid == "1.3.6.1.2.1.999.1.1.1.1"

    model = build_model(FIXTURE)
    findings, details = compare_rows(parsed, model, extract_notes(source))
    summary = details["summary"]
    assert summary["doc_rows"] == 6
    assert summary["matched"] == 4
    assert summary["doc_only"] == 1
    assert summary["type_mismatch"] == 2
    assert summary["name_mismatch"] == 2
    assert summary["access_mismatch"] == 1
    assert summary["auto_fixable"] == 2
    assert summary["manual_review"] == 5
    access_note = next(
        f for f in findings if f["field"] == "access" and f["oid"].endswith(".1.3")
    )
    assert access_note["note"] == "备注1：只有 web 服务该项具有 read-write 属性。"
    changes = build_changes(findings)
    assert any(c["target"] == "docx" for c in changes)
    assert any(c["target"] == "mib" for c in changes)
    assert any(c["target"] == "manual" for c in changes)

    mib_copy = tmp_path / "source.mib"
    shutil.copy(FIXTURE, mib_copy)
    fixed_mib = tmp_path / "fixed.mib"
    diff, changed = apply_mib_fixes(mib_copy, fixed_mib, findings)
    assert changed == 2 and "SYNTAX" in diff
    fixed_model = build_model(fixed_mib)
    assert fixed_model.node_by_name("testIfDescr").syntax.base_type == "Integer32"

    fixed = tmp_path / "fixed.docx"
    assert apply_fixes(source, fixed, parsed, findings) == 2
    approved = {row.oid: row for row in parse_docx(fixed)}
    assert approved["1.3.6.1.2.1.999.1.1.1.2"].dtype == "DisplayString"
    assert approved["1.3.6.1.2.1.999.1.1.1.3"].dtype == "Integer32"
    assert approved["1.3.6.1.2.1.999.1.1.1.3"].access == "详见{备注1}"
    assert approved["1.3.6.1.2.1.999.1.1.1.4"].name == "testIfOpStatus"

    fixed_doc = Document(fixed)
    assert any("本次自动修正记录" in p.text for p in fixed_doc.paragraphs)
    assert len(fixed_doc.tables) == len(Document(source).tables) + 1
    assert "updateFields" in fixed_doc.settings.element.xml

    missing = details["mib_only_oids"]
    supplement = tmp_path / "supplement.docx"
    assert append_missing_docx(source, supplement, model, missing) == len(missing)
    supplement_doc = Document(supplement)
    assert any("附录" in p.text for p in supplement_doc.paragraphs)
    assert any("本次文档补充记录" in p.text for p in supplement_doc.paragraphs)
    assert "updateFields" in supplement_doc.settings.element.xml


def test_parse_rejects_document_without_interface_tables(tmp_path: Path):
    path = tmp_path / "empty.docx"
    doc = Document()
    doc.add_paragraph("no tables here")
    doc.save(path)
    try:
        parse_docx(path)
    except ValueError as exc:
        assert "没有找到" in str(exc)
    else:
        raise AssertionError("document without interface tables must be rejected")


def _column(name: str, oid: str, table: str, base: str, sub_id: int) -> MibNode:
    return MibNode(
        name=name, oid=oid, kind="column", access="read-only",
        syntax=SyntaxSpec(base_type=base), table_name=table,
        parent_name="entry", sub_id=sub_id,
    )


def test_mib_only_groups_split_templates_from_real_gaps():
    nodes = [
        _column("idxA", "1.3.6.1.4.1.1.1.1.1", "tblA", "Integer32", 1),
        _column("valA", "1.3.6.1.4.1.1.1.1.2", "tblA", "DisplayString", 2),
        _column("idxB", "1.3.6.1.4.1.1.2.1.1", "tblB", "Integer32", 1),
        _column("valB", "1.3.6.1.4.1.1.2.1.2", "tblB", "DisplayString", 2),
        _column("x", "1.3.6.1.4.1.1.3.1.1", "tblC", "Integer32", 1),
        _column("y", "1.3.6.1.4.1.1.3.1.2", "tblC", "Integer32", 2),
        _column("z", "1.3.6.1.4.1.1.3.1.3", "tblC", "Integer32", 3),
    ]
    model = MibModel(nodes=nodes).reindex()
    documented = [
        DocRow("idxA", "1.3.6.1.4.1.1.1.1.1", "Integer32", "", "read-only", "current", 0, 1),
        DocRow("valA", "1.3.6.1.4.1.1.1.1.2", "DisplayString", "", "read-only", "current", 0, 2),
    ]
    _, details = compare_rows(documented, model)
    summary = details["summary"]
    assert summary["mib_only"] == 5
    assert summary["mib_only_template"] == 2  # tblB has the same shape as tblA
    assert summary["mib_only_uncovered"] == 3  # tblC has a different shape
    groups = {g["table"]: g for g in details["mib_only_groups"]}
    assert groups["tblB"]["template_covered"] is True
    assert groups["tblC"]["template_covered"] is False
