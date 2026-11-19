"""DOCX interface-document consistency check against a parsed MIB model.

The document tables use five columns: 节点 / 数据类型 / 含义 / 实现规格 / 状态.
Rows are matched by OID; the service reports differences and can emit a fixed
copy that only rewrites machine-checkable fields (type/access/status).
"""

from __future__ import annotations

import difflib
import json
import re
import shutil
import time
import uuid
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from docx import Document

from snmp_test.model.mib_model import build_model
from snmp_test.model.types import MibModel
from snmp_test.service.mibs import MibError, MibLibrary

CHECK_ID_RE = re.compile(r"^[0-9a-f]{12}$")
OID_RE = re.compile(r"([0-9]+(?:\.[0-9]+)+)")
NOTE_RE = re.compile(r"^\s*备注\s*([0-9]+)\s*[:：]\s*(.+)$")
NOTE_REF_RE = re.compile(r"备注\s*([0-9]+)")
MAX_DOCX_BYTES = 20 * 1024 * 1024
HEADERS = ("节点", "数据类型", "含义", "实现规格", "状态")
FIELD_INDEX = {"type": 1, "access": 3, "status": 4}

_TYPE_ALIASES = {
    "INTEGER": "INTEGER32",
    "INTEGER32": "INTEGER32",
    "GAUGE32": "INTEGER32",
    "UNSIGNED32": "INTEGER32",
    "COUNTER32": "INTEGER32",
    "COUNTER64": "INTEGER32",
    "DISPLAYSTRING": "OCTETSTRING",
    "OCTETSTRING": "OCTETSTRING",
    "PHYSADDRESS": "OCTETSTRING",
    "OPAQUE": "OCTETSTRING",
    "BITS": "OCTETSTRING",
}
ACCESS_VALUES = {"read-only", "read-write", "write-only", "not-accessible", "accessible-for-notify"}
MIB_TYPE_NAMES = {
    "INTEGER32": "Integer32", "INTEGER": "INTEGER", "DISPLAYSTRING": "DisplayString",
    "OCTETSTRING": "OCTET STRING", "IPADDRESS": "IpAddress", "TIMETICKS": "TimeTicks",
    "GAUGE32": "Gauge32", "UNSIGNED32": "Unsigned32", "COUNTER32": "Counter32",
    "COUNTER64": "Counter64", "OBJECTIDENTIFIER": "OBJECT IDENTIFIER",
}


class DocCheckError(ValueError):
    """Validation/parse failure whose message is safe to show to users."""


@dataclass
class DocRow:
    name: str
    oid: str
    dtype: str
    meaning: str
    access: str
    status: str
    table_index: int
    row_index: int


def _cell_text(cell: Any) -> str:
    return " ".join((cell.text or "").split())


def _norm_type(value: str) -> str:
    key = re.sub(r"\s+", "", (value or "").upper())
    return _TYPE_ALIASES.get(key, key)


def _split_node_cell(text: str) -> tuple[str, str] | None:
    match = OID_RE.search(text)
    if not match:
        return None
    name = text[: match.start()]
    name = re.sub(r"\bOID\b", "", name, flags=re.I).strip().strip(":：").strip()
    return (name, match.group(1)) if name else None


def parse_docx(path: str | Path) -> list[DocRow]:
    try:
        document = Document(str(path))
    except Exception as exc:
        raise DocCheckError(f"无法打开 DOCX：{exc}") from exc
    rows: list[DocRow] = []
    for table_index, table in enumerate(document.tables):
        table_rows = list(table.rows)
        if not table_rows:
            continue
        header_at = None
        for index, row in enumerate(table_rows[:3]):
            texts = [_cell_text(cell) for cell in row.cells]
            if texts[:5] == list(HEADERS):
                header_at = index
                break
        if header_at is None:
            continue
        for row_index, row in enumerate(table_rows[header_at + 1:], start=header_at + 1):
            cells = row.cells
            if len(cells) < 5:
                continue
            node = _split_node_cell(_cell_text(cells[0]))
            if node is None:
                continue
            rows.append(DocRow(
                name=node[0],
                oid=node[1],
                dtype=_cell_text(cells[1]),
                meaning=_cell_text(cells[2]),
                access=_cell_text(cells[3]),
                status=_cell_text(cells[4]),
                table_index=table_index,
                row_index=row_index,
            ))
    if not rows:
        raise DocCheckError("DOCX 中没有找到「节点 / 数据类型 / 含义 / 实现规格 / 状态」表格")
    return rows


def extract_notes(path: str | Path) -> dict[str, str]:
    """Collect ``备注N：...`` paragraphs so referenced notes can be shown."""
    try:
        document = Document(str(path))
    except Exception:
        return {}
    notes: dict[str, str] = {}
    for paragraph in document.paragraphs:
        text = " ".join((paragraph.text or "").split())
        match = NOTE_RE.match(text)
        if match:
            notes[match.group(1)] = match.group(2)
    return notes


def _finding(row: DocRow, field: str, doc_value: Any, mib_value: Any, *,
             action: str, severity: str, note: str = "",
             mib_line: int = 0) -> dict[str, Any]:
    result = {
        "oid": row.oid,
        "name": row.name,
        "field": field,
        "doc_value": doc_value,
        "mib_value": mib_value,
        "action": action,
        "severity": severity,
        "table_index": row.table_index,
        "row_index": row.row_index,
        "mib_line": mib_line,
    }
    if note:
        result["note"] = note
    return result


def compare_rows(
    rows: list[DocRow], model: MibModel, notes: dict[str, str] | None = None,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    notes = notes or {}
    nodes = {n.oid: n for n in model.nodes if n.kind in ("scalar", "column")}
    findings: list[dict[str, Any]] = []
    seen: set[str] = set()
    for row in rows:
        if row.oid in seen:
            findings.append(_finding(row, "oid", row.oid, "duplicate", action="manual", severity="warning"))
            continue
        seen.add(row.oid)
        node = nodes.get(row.oid)
        if node is None:
            findings.append(_finding(
                row, "oid", row.oid, "MIB 中不存在", action="manual", severity="error",
            ))
            continue
        if row.name != node.name:
            findings.append(_finding(
                row, "name", row.name, node.name,
                action="manual", severity="warning", mib_line=node.source_line,
            ))
        mib_type = node.syntax.base_type if node.syntax else ""
        if _norm_type(row.dtype) != _norm_type(mib_type):
            findings.append(_finding(
                row, "type", row.dtype, mib_type,
                action="update_doc", severity="error", mib_line=node.source_line,
            ))
        if row.access.lower() not in ACCESS_VALUES:
            refs = NOTE_REF_RE.findall(row.access)
            note = "；".join(
                f"备注{ref}：{notes[ref]}" for ref in refs if ref in notes
            )
            findings.append(_finding(
                row, "access", row.access, node.access,
                action="manual", severity="warning", note=note, mib_line=node.source_line,
            ))
        elif row.access.lower() != node.access:
            findings.append(_finding(
                row, "access", row.access, node.access,
                action="update_doc", severity="warning", mib_line=node.source_line,
            ))
        if row.status.lower() != node.status:
            findings.append(_finding(
                row, "status", row.status, node.status,
                action="update_doc", severity="warning", mib_line=node.source_line,
            ))
    mib_only = sorted(set(nodes) - seen)
    documented_tables = {
        nodes[oid].table_name for oid in (seen & set(nodes))
        if nodes[oid].kind == "column" and nodes[oid].table_name
    }
    column_sets: dict[str | None, list] = {}
    for node in nodes.values():
        column_sets.setdefault(node.table_name, []).append(node)

    def shape(table: str | None) -> tuple:
        return tuple(
            (n.syntax.base_type if n.syntax else "", n.access)
            for n in sorted(column_sets.get(table) or [], key=lambda n: n.oid)
        )

    documented_shapes = {shape(table) for table in documented_tables}
    missing_by_table = Counter(nodes[oid].table_name for oid in mib_only)
    groups = []
    for table, count in missing_by_table.most_common():
        covered = table is not None and shape(table) in documented_shapes
        groups.append({
            "table": table or "(scalar)",
            "count": count,
            "template_covered": covered,
        })
    template_covered = sum(g["count"] for g in groups if g["template_covered"])
    uncovered = len(mib_only) - template_covered
    summary = {
        "doc_rows": len(rows),
        "matched": len(seen & set(nodes)),
        "doc_only": sum(1 for f in findings if f["field"] == "oid" and f["mib_value"] == "MIB 中不存在"),
        "mib_only": len(mib_only),
        "mib_only_template": template_covered,
        "mib_only_uncovered": uncovered,
        "name_mismatch": sum(1 for f in findings if f["field"] == "name"),
        "type_mismatch": sum(1 for f in findings if f["field"] == "type"),
        "access_mismatch": sum(1 for f in findings if f["field"] == "access"),
        "status_mismatch": sum(1 for f in findings if f["field"] == "status"),
        "auto_fixable": sum(1 for f in findings if f["action"] == "update_doc"),
        "manual_review": sum(1 for f in findings if f["action"] == "manual"),
    }
    return findings, {
        "summary": summary,
        "mib_only_sample": mib_only[:20],
        "mib_only_oids": mib_only,
        "mib_only_groups": groups[:30],
    }


def _rewrite_cell(cell: Any, value: str) -> None:
    """Replace text while keeping the first run's character formatting."""
    paragraph = cell.paragraphs[0]
    runs = paragraph.runs
    if not runs:
        paragraph.add_run(value)
        return
    runs[0].text = value
    for run in runs[1:]:
        run.text = ""


def apply_fixes(source: str | Path, destination: str | Path, rows: list[DocRow],
                findings: list[dict[str, Any]]) -> int:
    document = Document(str(source))
    lookup = {(row.table_index, row.row_index): row for row in rows}
    changed = 0
    for finding in findings:
        if finding.get("action") != "update_doc":
            continue
        row = lookup.get((finding.get("table_index"), finding.get("row_index")))
        column = FIELD_INDEX.get(str(finding.get("field")))
        if row is None or column is None:
            continue
        table = document.tables[row.table_index]
        _rewrite_cell(table.rows[row.row_index].cells[column], str(finding["mib_value"]))
        changed += 1
    document.save(str(destination))
    return changed


def _mib_type_name(value: Any) -> str:
    key = re.sub(r"\s+", "", str(value or "").upper())
    return MIB_TYPE_NAMES.get(key, "")


def build_changes(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    changes: list[dict[str, Any]] = []
    for finding in findings:
        base = {
            "oid": finding["oid"],
            "name": finding["name"],
            "field": finding["field"],
            "mib_line": finding.get("mib_line", 0),
        }
        if finding.get("action") != "update_doc":
            changes.append({**base, "target": "manual", "old": finding["doc_value"],
                            "new": finding["mib_value"], "confidence": "manual"})
            continue
        changes.append({**base, "target": "docx", "old": finding["mib_value"],
                        "new": finding["doc_value"], "confidence": "high"})
        field = finding["field"]
        doc_value = finding["doc_value"]
        valid = (
            (field == "type" and bool(_mib_type_name(doc_value)))
            or (field == "access" and str(doc_value).lower() in ACCESS_VALUES)
            or (field == "status" and str(doc_value).lower() in ("current", "deprecated", "obsolete"))
        )
        if valid:
            changes.append({**base, "target": "mib", "old": finding["mib_value"],
                            "new": doc_value, "confidence": "medium"})
    return changes


def _block_end(lines: list[str], start: int) -> int:
    for index in range(start, min(len(lines), start + 200)):
        if "::=" in lines[index] and "{" in lines[index]:
            return index
    return min(len(lines) - 1, start + 60)


def apply_mib_fixes(source: str | Path, destination: str | Path,
                    findings: list[dict[str, Any]]) -> tuple[str, int]:
    source_path = Path(source)
    original = source_path.read_text(encoding="utf-8", errors="replace")
    lines = original.split("\n")
    grouped: dict[int, list[dict[str, Any]]] = {}
    for finding in findings:
        if finding.get("action") != "update_doc" or not finding.get("mib_line"):
            continue
        if finding["field"] not in ("type", "access", "status"):
            continue
        grouped.setdefault(int(finding["mib_line"]), []).append(finding)

    changed = 0
    for line_no in sorted(grouped, reverse=True):
        start = line_no - 1
        if not 0 <= start < len(lines):
            continue
        end = _block_end(lines, start)
        block = "\n".join(lines[start:end + 1])
        updated = block
        for finding in grouped[line_no]:
            field, doc_value = finding["field"], str(finding["doc_value"])
            if field == "type":
                new_type = _mib_type_name(doc_value)
                if not new_type:
                    continue
                pattern = re.compile(
                    r"(?is)(\bSYNTAX\s+)(.*?)(?=\s+(?:MAX-ACCESS|ACCESS|STATUS|DESCRIPTION|INDEX)\b|::=)"
                )
                updated, count = pattern.subn(lambda m: m.group(1) + new_type, updated, count=1)
            elif field == "access":
                if doc_value.lower() not in ACCESS_VALUES:
                    continue
                pattern = re.compile(r"(?i)(\b(?:MAX-ACCESS|ACCESS)\s+)([A-Za-z-]+)")
                updated, count = pattern.subn(r"\g<1>" + doc_value, updated, count=1)
            else:
                if doc_value.lower() not in ("current", "deprecated", "obsolete"):
                    continue
                pattern = re.compile(r"(?i)(\bSTATUS\s+)([A-Za-z-]+)")
                updated, count = pattern.subn(r"\g<1>" + doc_value, updated, count=1)
            if count:
                changed += 1
        if updated != block:
            lines[start:end + 1] = updated.split("\n")

    fixed = "\n".join(lines)
    destination = Path(destination)
    destination.write_text(fixed, encoding="utf-8")
    try:
        build_model(destination)
    except Exception as exc:
        destination.unlink(missing_ok=True)
        raise DocCheckError(f"生成修正版 MIB 后无法重新解析：{exc}") from exc
    diff = "".join(difflib.unified_diff(
        original.splitlines(keepends=True), fixed.splitlines(keepends=True),
        fromfile=source_path.name, tofile=destination.name,
    ))
    return diff, changed


def append_missing_docx(source: str | Path, destination: str | Path,
                        model: MibModel, missing_oids: list[str]) -> int:
    document = Document(str(source))
    document.add_page_break()
    document.add_heading("附录：MIB 中未在本文档列出的节点", level=1)
    document.add_paragraph(
        "以下内容由测试框架根据 MIB 自动生成，用于补齐文档未逐行列出的节点；"
        "“含义”取自 MIB DESCRIPTION，可能为空。"
    )
    by_oid = {n.oid: n for n in model.nodes if n.kind in ("scalar", "column")}
    groups: dict[str, list[Any]] = {}
    for oid in missing_oids:
        node = by_oid.get(oid)
        if node is not None:
            groups.setdefault(node.table_name or "标量（scalar）", []).append(node)
    added = 0
    for table_name, nodes in sorted(groups.items()):
        document.add_heading(f"{table_name}（{len(nodes)} 个节点）", level=2)
        table = document.add_table(rows=1, cols=5)
        try:
            table.style = "Table Grid"
        except Exception:
            pass
        for index, header in enumerate(HEADERS):
            table.rows[0].cells[index].text = header
        for node in sorted(nodes, key=lambda n: n.oid):
            cells = table.add_row().cells
            values = [
                f"{node.name} OID:{node.oid}",
                node.syntax.base_type if node.syntax else "",
                node.description,
                node.access,
                node.status,
            ]
            for index, value in enumerate(values):
                cells[index].text = str(value or "")
            added += 1
    document.save(str(destination))
    return added


class DocCheckService:
    def __init__(self, root: str | Path, library: MibLibrary) -> None:
        self.root = Path(root)
        self.library = library
        self.base = self.root / "work" / "docchecks"
        self.base.mkdir(parents=True, exist_ok=True)

    def _dir(self, check_id: str) -> Path:
        if not CHECK_ID_RE.match(check_id):
            raise DocCheckError("无效的检查 ID")
        return self.base / check_id

    def create(self, filename: str, content: bytes, mib_id: str, user: str) -> dict[str, Any]:
        if not content or len(content) > MAX_DOCX_BYTES:
            raise DocCheckError("DOCX 文件为空或超过 20 MB")
        if not content.startswith(b"PK"):
            raise DocCheckError("文件不是有效的 DOCX")
        try:
            model_path = self.library.model_path(mib_id)
            model = MibModel.from_dict(json.loads(model_path.read_text(encoding="utf-8")))
        except (MibError, OSError, ValueError) as exc:
            raise DocCheckError(f"MIB 不存在或模型损坏：{exc}") from exc

        check_id = uuid.uuid4().hex[:12]
        folder = self._dir(check_id)
        folder.mkdir(parents=True, exist_ok=True)
        safe_name = re.sub(r"[^A-Za-z0-9._-]", "_", Path(filename or "document.docx").name)[:120]
        source = folder / (safe_name if safe_name.lower().endswith(".docx") else "document.docx")
        source.write_bytes(content)
        try:
            rows = parse_docx(source)
        except Exception:
            shutil.rmtree(folder, ignore_errors=True)
            raise
        findings, details = compare_rows(rows, model, extract_notes(source))
        changes = build_changes(findings)
        fixed_name = ""
        if any(f["action"] == "update_doc" for f in findings):
            fixed = folder / "fixed.docx"
            try:
                apply_fixes(source, fixed, rows, findings)
                fixed_name = "fixed.docx"
            except Exception as exc:
                raise DocCheckError(f"生成修正版 DOCX 失败：{exc}") from exc

        fixed_mib_name = ""
        mib_diff = ""
        if any(c["target"] == "mib" for c in changes):
            try:
                mib_diff, _ = apply_mib_fixes(
                    self.library.mib_path(mib_id), folder / "fixed.mib", findings,
                )
                if mib_diff:
                    fixed_mib_name = "fixed.mib"
            except DocCheckError:
                raise
            except Exception as exc:
                raise DocCheckError(f"生成修正版 MIB 失败：{exc}") from exc

        supplement_name = ""
        missing = details.get("mib_only_oids") or []
        if missing:
            try:
                append_missing_docx(source, folder / "supplement.docx", model, missing)
                supplement_name = "supplement.docx"
            except Exception as exc:
                raise DocCheckError(f"生成补充文档失败：{exc}") from exc

        report = {
            "check_id": check_id,
            "user": user,
            "filename": safe_name,
            "mib_id": mib_id,
            "mib_module": model.module_name,
            "created_at": time.time(),
            **details,
            "findings": findings,
            "changes": changes,
            "mib_diff": mib_diff,
            "fixed_available": bool(fixed_name),
            "fixed_mib_available": bool(fixed_mib_name),
            "supplement_available": bool(supplement_name),
            "supplement_count": len(missing),
        }
        (folder / "report.json").write_text(
            json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8"
        )
        (folder / "meta.json").write_text(
            json.dumps({"user": user, "filename": safe_name, "mib_id": mib_id},
                       ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
        return report

    def get(self, check_id: str, user: str) -> dict[str, Any]:
        folder = self._dir(check_id)
        try:
            meta = json.loads((folder / "meta.json").read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            raise DocCheckError("检查记录不存在") from exc
        if meta.get("user") != user:
            raise DocCheckError("检查记录不存在")
        return json.loads((folder / "report.json").read_text(encoding="utf-8"))

    def _artifact(self, check_id: str, user: str, name: str, flag: str, label: str) -> Path:
        report = self.get(check_id, user)
        path = self._dir(check_id) / name
        if not report.get(flag) or not path.is_file():
            raise DocCheckError(f"没有可下载的{label}")
        return path

    def fixed_path(self, check_id: str, user: str) -> Path:
        return self._artifact(check_id, user, "fixed.docx", "fixed_available", "修正版 DOCX")

    def fixed_mib_path(self, check_id: str, user: str) -> Path:
        return self._artifact(check_id, user, "fixed.mib", "fixed_mib_available", "修正版 MIB")

    def supplement_path(self, check_id: str, user: str) -> Path:
        return self._artifact(check_id, user, "supplement.docx", "supplement_available", "补充文档")
