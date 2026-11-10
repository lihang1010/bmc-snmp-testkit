"""Pytest bridge: parameterised generated cases, marker mapping and result hooks.

The batch CLI (``snmp-test run``) is the primary runner.  This plugin makes the
same generated cases runnable through pytest for CI integration, ``-m`` marker
filtering and ``--lf`` failed-first reruns.
"""

from __future__ import annotations

import asyncio
import json
import os
import time
from datetime import datetime
from pathlib import Path
from typing import Any

import pytest

from snmp_test.config import load_config
from snmp_test.model.mib_model import build_model
from snmp_test.model.types import CaseResult, TestCase
from snmp_test.runner.case_store import CaseStore
from snmp_test.runner.executor import Runtime

CASES_ENV = "SNMP_TEST_CASES"
CONFIG_ENV = "SNMP_TEST_CONFIG"
LIMIT_ENV = "SNMP_TEST_PYTEST_LIMIT"
CASE_ID_PARAM = "snmp_case_id"

MARKERS = {
    "v1", "v2c", "v3", "get", "getnext", "getbulk", "set", "trap", "negative", "guarded",
}

_cases: list[TestCase] = []
_by_id: dict[str, TestCase] = {}
_reports: list[dict[str, Any]] = []


def _default_cases_path() -> Path:
    return Path(__file__).resolve().parents[3] / "cases" / "generated" / "cases.json"


def _default_config_path() -> Path:
    # The pytest bridge is an offline self-test: never pick up a live config.
    return Path(__file__).resolve().parents[3] / "config" / "config.example.yaml"


def _stratified_subset(store: CaseStore, limit: int) -> list[TestCase]:
    """Deterministic, small but representative subset for a pytest run."""
    buckets: dict[tuple[str, str, str], list[TestCase]] = {}
    for case in store.cases:
        buckets.setdefault((case.operation, case.version, case.category), []).append(case)
    selected: list[TestCase] = []
    # priority cases first (negative / auth / trap), then round-robin one per bucket
    ordered = sorted(store.cases, key=lambda c: (c.priority, c.case_id))
    for case in ordered:
        if case.category in ("invalid", "access", "trap", "compat") and case not in selected:
            selected.append(case)
        if len(selected) >= limit:
            break
    idx = 0
    keys = sorted(buckets)
    while len(selected) < limit and keys:
        bucket = buckets[keys[idx % len(keys)]]
        pos = idx // len(keys)
        if pos < len(bucket) and bucket[pos] not in selected:
            selected.append(bucket[pos])
        idx += 1
        if idx > limit * len(keys) + len(keys):
            break
    return selected[:limit]


def _load_cases() -> list[TestCase]:
    global _cases, _by_id
    if _cases:
        return _cases
    path = Path(os.environ.get(CASES_ENV) or _default_cases_path())
    if not path.is_file():
        _cases = []
        _by_id = {}
        return _cases
    store = CaseStore.read(path)
    limit = int(os.environ.get(LIMIT_ENV, "80"))
    _cases = _stratified_subset(store, limit) if limit > 0 else store.cases
    _by_id = {c.case_id: c for c in _cases}
    return _cases


def pytest_generate_tests(metafunc: Any) -> None:
    if CASE_ID_PARAM not in metafunc.fixturenames:
        return
    cases = _load_cases()
    if not cases:
        metafunc.parametrize(CASE_ID_PARAM, ["__NO_CASES__"], ids=["generate-cases-first"])
        return
    metafunc.parametrize(
        CASE_ID_PARAM,
        [c.case_id for c in cases],
        ids=[f"{c.operation}-{c.version}-{c.case_id[-8:]}" for c in cases],
    )


def pytest_collection_modifyitems(config: Any, items: list[Any]) -> None:
    for item in items:
        if CASE_ID_PARAM not in getattr(item, "fixturenames", []):
            continue
        case_id = item.callspec.params.get(CASE_ID_PARAM)
        case = _by_id.get(case_id)
        if not case:
            continue
        for tag in case.tags:
            if tag in MARKERS:
                item.add_marker(getattr(pytest.mark, tag))
        if case.safety in ("guarded", "blocked"):
            item.add_marker(pytest.mark.guarded)


def pytest_runtest_logreport(report: Any) -> None:
    if report.when != "call" and not (report.when == "setup" and report.skipped):
        return
    case_id = None
    for marker in getattr(report, "keywords", {}):
        if isinstance(marker, str) and marker.startswith("TC-"):
            case_id = marker
            break
    _reports.append(
        {
            "nodeid": report.nodeid,
            "case_id": case_id,
            "outcome": report.outcome,
            "duration_s": round(getattr(report, "duration", 0.0), 4),
            "longrepr": str(getattr(report, "longrepr", ""))[:4000],
            "ts": time.time(),
        }
    )


def pytest_sessionfinish(session: Any, exitstatus: int) -> None:
    if not _reports:
        return
    out = Path(os.environ.get("SNMP_TEST_PYTEST_OUT", "runs/pytest-results"))
    out.mkdir(parents=True, exist_ok=True)
    path = out / f"pytest-{datetime.now().strftime('%Y%m%d-%H%M%S')}.json"
    path.write_text(
        json.dumps({"exitstatus": exitstatus, "reports": _reports}, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )


@pytest.fixture(scope="session")
def snmp_runtime():
    """One event loop, one SNMP session pool and one mock agent for the session."""
    cfg = load_config(os.environ.get(CONFIG_ENV) or _default_config_path())
    errors = cfg.validate()
    assert not errors, f"invalid configuration: {errors}"
    model = build_model(cfg.mib_path)
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    runtime = Runtime(cfg, model, run_id=f"pytest-{datetime.now().strftime('%Y%m%d-%H%M%S')}")
    loop.run_until_complete(runtime.start())
    try:
        yield loop, runtime, _by_id
    finally:
        loop.run_until_complete(runtime.stop())
        runtime.close()
        loop.close()
        asyncio.set_event_loop(None)


def run_generated_case(snmp_runtime, case_id: str) -> CaseResult:
    """Shared assertion entry point for ``tests/test_generated_cases.py``."""
    loop, runtime, by_id = snmp_runtime
    if case_id == "__NO_CASES__":
        pytest.skip("no generated cases; run `snmp-test generate` first")
    case = by_id.get(case_id)
    if case is None:
        pytest.skip(f"case {case_id} not loaded")
    targets = runtime.targets_for(case)
    if not targets:
        pytest.skip(f"no target supports {case.version}")
    result = loop.run_until_complete(runtime.run_one(targets[0], case))
    assert result.status not in ("failed", "error"), (
        f"{result.case_id} {result.status}: {result.message}\nactual={result.actual}"
    )
    return result
