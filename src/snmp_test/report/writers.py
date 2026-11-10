"""Write results.json, report.html, junit.xml and reproducibility snapshots."""

from __future__ import annotations

import json
import xml.etree.ElementTree as ET
from datetime import datetime
from pathlib import Path
from typing import Any

import yaml
from jinja2 import Environment, FileSystemLoader, select_autoescape

from snmp_test.config import Config
from snmp_test.model.types import MibModel, TestCase
from snmp_test.report.collector import ResultCollector
from snmp_test.runner.safety import blocked_nodes


def _templates() -> Environment:
    path = Path(__file__).parent / "templates"
    return Environment(
        loader=FileSystemLoader(str(path)),
        autoescape=select_autoescape(["html", "xml"]),
        trim_blocks=True,
        lstrip_blocks=True,
    )


def write_results_json(collector: ResultCollector, extra: dict[str, Any] | None = None) -> Path:
    path = collector.run_dir / "results.json"
    payload = {
        "schema": 1,
        "run_id": collector.run_id,
        "summary": collector.summary(),
        "results": collector.results_dict(),
        "failures": collector.failures(),
        **(extra or {}),
    }
    path.write_text(json.dumps(payload, indent=2, ensure_ascii=False, default=str), encoding="utf-8")
    return path


def write_junit_xml(collector: ResultCollector) -> Path:
    path = collector.run_dir / "junit.xml"
    suites = ET.Element("testsuites", {"name": "bmc-snmp-test", "time": "0"})
    groups: dict[str, list[dict[str, Any]]] = {}
    for result in collector.results_dict():
        groups.setdefault(result["operation"], []).append(result)
    for operation, items in sorted(groups.items()):
        failures = sum(1 for r in items if r["status"] in ("failed", "error"))
        skipped = sum(1 for r in items if r["status"] in ("skipped", "blocked"))
        suite = ET.SubElement(
            suites,
            "testsuite",
            {
                "name": operation,
                "tests": str(len(items)),
                "failures": str(failures),
                "skipped": str(skipped),
                "errors": "0",
                "time": str(round(sum(r["duration_ms"] for r in items) / 1000.0, 3)),
            },
        )
        for r in items:
            case = ET.SubElement(
                suite,
                "testcase",
                {
                    "name": r["name"],
                    "classname": f"{r['module']}.{r['version']}",
                    "time": str(round(r["duration_ms"] / 1000.0, 4)),
                },
            )
            if r["status"] in ("failed", "error"):
                failure = ET.SubElement(case, "failure", {"message": r["message"][:500]})
                failure.text = json.dumps(r.get("actual", {}), ensure_ascii=False, default=str)[:4000]
            elif r["status"] in ("skipped", "blocked"):
                ET.SubElement(case, "skipped", {"message": r["message"][:500]})
    ET.ElementTree(suites).write(path, encoding="utf-8", xml_declaration=True)
    return path


def write_html_report(collector: ResultCollector, context: dict[str, Any]) -> Path:
    path = collector.run_dir / "report.html"
    env = _templates()
    template = env.get_template("report.html.j2")
    summary = collector.summary()
    log_path = collector.run_dir / "run.log"
    log_tail = ""
    if log_path.is_file():
        lines = log_path.read_text(encoding="utf-8", errors="replace").splitlines()
        log_tail = "\n".join(lines[-80:])
    payload = {
        "run_id": collector.run_id,
        "generated_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "summary": summary,
        "results": collector.results_dict(),
        "failures": collector.failures(),
        "log_tail": log_tail,
        **context,
    }
    path.write_text(template.render(**payload), encoding="utf-8")
    return path


def write_snapshots(
    collector: ResultCollector,
    *,
    cfg: Config,
    model: MibModel,
    cases: list[TestCase],
    policy: dict[str, Any],
) -> dict[str, str]:
    run_dir = collector.run_dir
    config_path = run_dir / "config-snapshot.yaml"
    config_path.write_text(
        yaml.safe_dump(cfg.masked(), allow_unicode=True, sort_keys=False),
        encoding="utf-8",
    )
    (run_dir / "mib.sha256").write_text(
        f"{model.mib_sha256}  {Path(model.mib_path).name}\n{json.dumps(model.stats, indent=2, ensure_ascii=False)}\n",
        encoding="utf-8",
    )
    (run_dir / "safety-policy.json").write_text(
        json.dumps(policy, indent=2, ensure_ascii=False), encoding="utf-8"
    )
    (run_dir / "case-manifest.json").write_text(
        json.dumps(
            {
                "total": len(cases),
                "case_ids": [c.case_id for c in cases],
                "by_operation": _count(cases, "operation"),
                "by_version": _count(cases, "version"),
            },
            indent=2,
            ensure_ascii=False,
        ),
        encoding="utf-8",
    )
    return {
        "config_snapshot": str(config_path),
        "mib_hash": model.mib_sha256,
        "case_count": str(len(cases)),
    }


def _count(cases: list[TestCase], attr: str) -> dict[str, int]:
    out: dict[str, int] = {}
    for case in cases:
        key = getattr(case, attr)
        out[key] = out.get(key, 0) + 1
    return out


def write_all(
    collector: ResultCollector,
    *,
    cfg: Config,
    model: MibModel,
    cases: list[TestCase],
    policy: dict[str, Any],
    extra: dict[str, Any] | None = None,
) -> dict[str, str]:
    snapshots = write_snapshots(collector, cfg=cfg, model=model, cases=cases, policy=policy)
    result_json = write_results_json(collector, {**(extra or {}), "snapshots": snapshots})
    junit = write_junit_xml(collector)
    html_report = write_html_report(
        collector,
        {
            "mode": cfg.mode,
            "targets": [{"name": t.name, "host": t.host, "port": t.port, "versions": list(t.versions)} for t in cfg.targets],
            "mib": {"name": Path(model.mib_path).name, "sha256": model.mib_sha256, "module": model.module_name, "root": model.root_oid},
            "policy": {
                "allow_guarded": bool(cfg.execution.get("allow_guarded", False)),
                "set_enabled": bool(cfg.execution.get("enable_set", True)),
                "hard_blocked": blocked_nodes(model, policy),
            },
            "snapshots": snapshots,
            "extra": extra or {},
        },
    )
    return {
        "run_dir": str(collector.run_dir),
        "results_json": str(result_json),
        "junit_xml": str(junit),
        "report_html": str(html_report),
        "run_log": str(collector.run_dir / "run.log"),
        "pdu_log": str(collector.run_dir / "pdus.jsonl"),
        **{k: str(v) for k, v in snapshots.items()},
    }
