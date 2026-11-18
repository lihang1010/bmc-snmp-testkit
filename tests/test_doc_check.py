from __future__ import annotations

from pathlib import Path

from docx import Document

from snmp_test.model.mib_model import build_model
from snmp_test.service.doc_check import (
    apply_fixes,
    compare_rows,
    extract_notes,
    parse_docx,
)

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

    fixed = tmp_path / "fixed.docx"
    assert apply_fixes(source, fixed, parsed, findings) == 2
    approved = {row.oid: row for row in parse_docx(fixed)}
    assert approved["1.3.6.1.2.1.999.1.1.1.2"].dtype == "DisplayString"
    assert approved["1.3.6.1.2.1.999.1.1.1.3"].dtype == "Integer32"
    assert approved["1.3.6.1.2.1.999.1.1.1.3"].access == "详见{备注1}"
    assert approved["1.3.6.1.2.1.999.1.1.1.3"].access == "详见{备注1}"
    assert approved["1.3.6.1.2.1.999.1.1.1.4"].name == "testIfOpStatus"


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
