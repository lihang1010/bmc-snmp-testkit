"""Unified, read-only audit timeline for the Web console.

Two append-only journals already exist and are left untouched:

* ``work/jobs/audit.jsonl``  -- MIB uploads/deletions and job lifecycle events
* ``work/probe-audit.jsonl`` -- one-shot SNMP probes (GET/GETNEXT/WALK/SET)

This module normalises both into one timeline so a single page can trace who
did what, without migrating or rewriting any historical data.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

JOB_EVENTS: dict[str, tuple[str, str, str]] = {
    "mib_upload": ("mib", "MIB 上传", "ok"),
    "mib_deleted": ("mib", "MIB 删除", "ok"),
    "job_submitted": ("job", "任务提交", "ok"),
    "job_started": ("job", "任务开始", "info"),
    "job_waiting": ("job", "等待目标", "warn"),
    "job_finished": ("job", "任务完成", "ok"),
    "job_failed": ("job", "任务失败", "fail"),
    "job_deleted": ("job", "任务删除", "ok"),
}

CATEGORY_LABELS = {"mib": "MIB", "job": "任务", "probe": "探测"}


def _read_rows(path: Path) -> list[dict[str, Any]]:
    if not path.is_file():
        return []
    rows: list[dict[str, Any]] = []
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError:
        return rows
    for line in lines:
        try:
            row = json.loads(line)
        except Exception:
            continue
        if isinstance(row, dict):
            rows.append(row)
    return rows


def _detail(row: dict[str, Any], category: str, event: str) -> str:
    if category == "mib":
        return str(row.get("filename") or row.get("mib_id") or "")
    if category == "job":
        parts = [str(row.get("job_id") or "")]
        for key in ("mode", "target", "version"):
            if row.get(key):
                parts.append(str(row[key]))
        if row.get("limit"):
            parts.append(f"上限 {row['limit']}")
        if event == "job_finished":
            summary = row.get("summary") or {}
            parts.append(f"{summary.get('passed', 0)}/{summary.get('total', 0)} 通过")
        if row.get("error"):
            parts.append(str(row["error"])[:120])
        return " · ".join(p for p in parts if p)
    parts = [str(row.get("oid") or "")]
    if row.get("value") is not None:
        parts.append(f"值={row['value']}")
    if row.get("count") is not None:
        parts.append(f"返回 {row['count']} 条")
    if row.get("elapsed_ms") is not None:
        parts.append(f"{row['elapsed_ms']} ms")
    if row.get("error"):
        parts.append(str(row["error"]))
    return " · ".join(p for p in parts if p)


def _normalise(row: dict[str, Any], source: str) -> dict[str, Any] | None:
    ts = float(row.get("ts") or 0)
    user = str(row.get("user") or "-")
    if source == "probe":
        operation = str(row.get("operation") or "PROBE")
        ok = bool(row.get("ok"))
        return {
            "ts": ts,
            "user": user,
            "category": "probe",
            "category_label": CATEGORY_LABELS["probe"],
            "event": operation,
            "action": f"探测 {operation}",
            "target": str(row.get("target") or ""),
            "detail": _detail(row, "probe", operation),
            "result": "ok" if ok else "fail",
            "mode": str(row.get("mode") or ""),
        }
    event = str(row.get("event") or "")
    category, action, result = JOB_EVENTS.get(event, ("job", event or "事件", "info"))
    if event == "job_finished":
        summary = row.get("summary") or {}
        if int(summary.get("failed") or 0) > 0:
            result = "warn"
    return {
        "ts": ts,
        "user": user,
        "category": category,
        "category_label": CATEGORY_LABELS.get(category, category),
        "event": event,
        "action": action,
        "target": str(row.get("target") or row.get("mib_id") or row.get("job_id") or ""),
        "detail": _detail(row, category, event),
        "result": result,
        "mode": str(row.get("mode") or ""),
    }


class AuditFeed:
    def __init__(self, root: str | Path) -> None:
        self.root = Path(root)
        self.sources = (
            (self.root / "work" / "jobs" / "audit.jsonl", "job"),
            (self.root / "work" / "probe-audit.jsonl", "probe"),
        )

    def entries(
        self,
        limit: int = 100,
        user: str = "",
        category: str = "",
        event: str = "",
    ) -> list[dict[str, Any]]:
        rows: list[dict[str, Any]] = []
        for path, source in self.sources:
            for raw in _read_rows(path):
                normalised = _normalise(raw, source)
                if normalised is not None:
                    rows.append(normalised)
        rows.sort(key=lambda r: r["ts"], reverse=True)
        if user:
            rows = [r for r in rows if r["user"] == user]
        if category:
            rows = [r for r in rows if r["category"] == category]
        if event:
            rows = [r for r in rows if r["event"] == event]
        return rows[: max(1, min(int(limit), 1000))]
