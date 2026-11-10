"""End-to-end self test: mock agent, 3 versions, 4 operations, trap/inform, reports."""

from __future__ import annotations

import asyncio
import copy
import json
from pathlib import Path

import pytest

from snmp_test.config import Config, load_config
from snmp_test.generator.case_builder import GeneratorOptions, generate_cases
from snmp_test.generator.trap_cases import generate_trap_cases, load_expectations
from snmp_test.model.mib_model import build_model
from snmp_test.report.writers import write_all
from snmp_test.runner.executor import Runtime
from snmp_test.runner.safety import load_policy

ROOT = Path(__file__).resolve().parents[1]
CONFIG = ROOT / "config" / "config.example.yaml"


def _isolated_config(tmp_path: Path) -> Config:
    """Use dedicated loopback ports so pytest's session fixture cannot collide."""
    cfg = load_config(CONFIG)
    raw = copy.deepcopy(cfg.raw)
    raw["mock"]["port"] = 11711
    raw["mock"]["trap_port"] = 11712
    raw["trap"]["listen_port"] = 11712
    raw["targets"][0]["port"] = 11711
    raw["report"]["output_dir"] = str(tmp_path / "runs")
    return Config(raw, CONFIG)


def _selected_cases(model, cfg):
    options = GeneratorOptions(rows_per_table=1, max_cases_per_table=2, policy=load_policy(cfg.resolve("config/safety-policy.yaml")))
    base = generate_cases(model, options)
    traps = generate_trap_cases(
        load_expectations(cfg.resolve("config/trap-expectations.yaml")),
        model.mib_sha256,
        options.versions,
    )
    picked: list = []
    for op, version in (("GET", "v1"), ("GET", "v2c"), ("GET", "v3"),
                        ("GETNEXT", "v1"), ("GETNEXT", "v2c"), ("GETNEXT", "v3"),
                        ("GETBULK", "v2c"), ("GETBULK", "v3"),
                        ("SET", "v1"), ("SET", "v2c"), ("SET", "v3")):
        safe = [c for c in base if c.operation == op and c.version == version and c.safety == "safe" and c.category == "normal"]
        if safe:
            picked.append(safe[0])
    invalid = [c for c in base if c.operation == "SET" and c.category == "invalid" and c.safety == "safe"]
    picked.extend(invalid[:3])
    picked.extend(traps)
    return picked


def _run_once(cfg, model, cases, run_id: str, tmp_path: Path):
    async def body():
        runtime = Runtime(cfg, model, run_id=run_id, run_dir=tmp_path / "runs" / run_id)
        await runtime.start()
        try:
            results = await runtime.run(cases)
            paths = write_all(
                runtime.collector, cfg=cfg, model=model, cases=cases,
                policy=load_policy(cfg.resolve("config/safety-policy.yaml")),
                extra={"mode": cfg.mode},
            )
            return results, paths, runtime.collector.summary()
        finally:
            await runtime.stop()
            runtime.close()

    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        return loop.run_until_complete(body())
    finally:
        loop.close()
        asyncio.set_event_loop(None)


def test_end_to_end_with_mock_agent(tmp_path: Path):
    cfg = _isolated_config(tmp_path)
    assert cfg.validate() == []
    model = build_model(cfg.mib_path)
    cases = _selected_cases(model, cfg)
    assert {c.operation for c in cases} == {"GET", "GETNEXT", "GETBULK", "SET", "TRAP", "INFORM"}

    results, paths, summary = _run_once(cfg, model, cases, "e2e-a", tmp_path)

    failed = [r for r in results if r.status in ("failed", "error")]
    assert not failed, [(r.case_id, r.message) for r in failed]
    assert summary["overall"]["effective_pass_rate"] == 100.0
    trap_results = [r for r in results if r.operation in ("TRAP", "INFORM")]
    assert len(trap_results) == 6
    assert all(r.status == "passed" for r in trap_results)
    assert any(r.operation == "INFORM" and "trap_ack" in str(r.expectation) for r in results)

    for name in ("results.json", "report.html", "junit.xml", "run.log", "pdus.jsonl",
                 "config-snapshot.yaml", "mib.sha256", "case-manifest.json", "safety-policy.json"):
        assert (tmp_path / "runs" / "e2e-a" / name).is_file(), name

    html = (tmp_path / "runs" / "e2e-a" / "report.html").read_text(encoding="utf-8")
    assert "BMC SNMP" in html and "e2e-a" in html
    data = json.loads((tmp_path / "runs" / "e2e-a" / "results.json").read_text(encoding="utf-8"))
    assert data["summary"]["overall"]["total"] == len(results)
    assert data["summary"]["by_version"]
    snapshot = (tmp_path / "runs" / "e2e-a" / "config-snapshot.yaml").read_text(encoding="utf-8")
    assert "authpass123" not in snapshot  # credentials masked

    # repeatability: same case set, same stable ids, same outcomes
    results2, _, summary2 = _run_once(cfg, model, cases, "e2e-b", tmp_path)
    assert [r.case_id for r in results2] == [r.case_id for r in results]
    assert [r.status for r in results2] == [r.status for r in results]
    assert summary2["overall"]["effective_pass_rate"] == summary["overall"]["effective_pass_rate"]


def test_dry_run_sends_no_pdus(tmp_path: Path):
    cfg = _isolated_config(tmp_path)
    model = build_model(cfg.mib_path)
    cases = _selected_cases(model, cfg)[:3]

    async def body():
        runtime = Runtime(cfg, model, run_id="e2e-dry", run_dir=tmp_path / "runs" / "e2e-dry")
        await runtime.start()
        try:
            return await runtime.run(cases, dry_run=True)
        finally:
            await runtime.stop()
            runtime.close()

    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        results = loop.run_until_complete(body())
    finally:
        loop.close()
        asyncio.set_event_loop(None)
    assert results and all(r.status == "skipped" and "dry-run" in r.message for r in results)
