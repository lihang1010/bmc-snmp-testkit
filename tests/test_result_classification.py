"""Device-side shortfalls (unsupported / timeout) must not look like defects."""

from __future__ import annotations

import asyncio
import copy
from pathlib import Path
from types import SimpleNamespace

from snmp_test.config import Config, load_config
from snmp_test.model.types import CaseResult, SnmpResponse, TestCase, Varbind
from snmp_test.report.collector import ResultCollector
from snmp_test.report.writers import write_html_report, write_junit_xml
from snmp_test.runner.executor import Runtime

ROOT = Path(__file__).resolve().parents[1]


def _response(**overrides) -> SnmpResponse:
    base = dict(
        error_indication=None,
        error_status="noError",
        error_index=0,
        varbinds=[],
        version="v2c",
        operation="GET",
        target="bmc",
    )
    base.update(overrides)
    return SnmpResponse(**base)


def _result(assertions: list[dict]) -> CaseResult:
    return CaseResult(
        case_id="TC-test",
        name="read a MIB-declared object",
        operation="GET",
        version="v2c",
        target="bmc",
        expectation={"assertions": assertions},
    )


def _finish(result: CaseResult, response: SnmpResponse) -> CaseResult:
    runtime = object.__new__(Runtime)
    runtime.collector = SimpleNamespace(add_pdu=lambda **_: None)
    runtime._finish(result, response)
    return result


def test_timeout_is_classified_not_failed():
    result = _finish(_result([{"kind": "no_error"}]), _response(error_indication="requestTimeout"))
    assert result.status == "timeout"
    assert "requestTimeout" in result.message


def test_v1_nosuchname_is_unsupported():
    result = _finish(_result([{"kind": "no_error"}]), _response(version="v1", error_status="noSuchName"))
    assert result.status == "unsupported"


def test_v2c_exception_varbind_is_unsupported():
    response = _response(
        varbinds=[Varbind(oid="1.3.6.1.4.1.52305.1.0", type="NoSuchInstance", value="NoSuchInstance", exception="NoSuchInstance")]
    )
    assertions = [
        {"kind": "no_error"},
        {"kind": "varbind_count", "min": 1},
        {"kind": "value_type", "allowed": ["OctetString"]},
    ]
    assert _finish(_result(assertions), response).status == "unsupported"


def test_expected_rejection_still_passes():
    # A negative case that *expects* noSuchName must not be reclassified.
    result = _finish(_result([{"kind": "no_such"}]), _response(version="v1", error_status="noSuchName"))
    assert result.status == "passed"


def test_other_assertion_failures_stay_failed():
    response = _response(varbinds=[Varbind(oid="1.3.6.1.4.1.52305.1.0", type="Integer32", value=7)])
    result = _finish(_result([{"kind": "value_equals", "value": 9}]), response)
    assert result.status == "failed"


def test_summary_and_junit_treat_shortfalls_as_not_run(tmp_path):
    cfg = load_config(ROOT / "config" / "config.example.yaml")
    collector = ResultCollector(cfg, "classify-a", tmp_path / "run")
    statuses = ["passed"] * 6 + ["failed"] + ["timeout"] * 2 + ["unsupported"] + ["skipped"] + ["blocked"]
    for index, status in enumerate(statuses):
        collector.add(CaseResult(case_id=f"TC-{index}", name="case", status=status, operation="GET", version="v2c"))
    collector.finish()

    overall = collector.summary()["overall"]
    assert overall["passed"] == 6
    assert overall["failed"] == 1
    assert overall["timeout"] == 2
    assert overall["unsupported"] == 1
    assert overall["effective_pass_rate"] == round(100.0 * 6 / 7, 2)
    assert len(collector.failures()) == 2  # failed + blocked
    assert len(collector.shortfalls()) == 3

    junit = write_junit_xml(collector).read_text(encoding="utf-8")
    assert junit.count("<skipped") == 5  # 2 timeout + 1 unsupported + skipped + blocked

    html = write_html_report(
        collector,
        {
            "mode": "live",
            "targets": [{"name": "bmc", "host": "10.0.0.1", "port": 161, "versions": ["v2c"]}],
            "mib": {"name": "TEST.mib", "sha256": "0" * 64, "module": "TEST", "root": "1.3.6.1.4.1.1"},
            "policy": {"allow_guarded": False, "set_enabled": False, "hard_blocked": []},
            "snapshots": {"case_count": str(len(statuses))},
            "extra": {},
        },
    ).read_text(encoding="utf-8")
    assert "设备未实现 / 超时用例（3）" in html
    assert '<option value="timeout">timeout</option>' in html

    collector.close()


def _get_case(oid: str, *, assertion: str = "no_error") -> TestCase:
    return TestCase(
        case_id="TC-baseline",
        name="GET baseline probe",
        oid=oid,
        operation="GET",
        version="v2c",
        category="normal",
        tags=(),
        payload={"varbinds": [{"oid": oid, "asn1": "Null", "value": None}]},
        expectation={"assertions": [{"kind": assertion}, {"kind": "varbind_count", "min": 1}]},
        module="test",
    )


def test_oid_baseline_preclassifies_absent_get(offline_config, offline_model, tmp_path):
    cfg = Config(copy.deepcopy(offline_config.raw), ROOT / "config" / "config.example.yaml")
    cfg.raw["execution"]["oid_baseline"] = True
    runtime = Runtime(cfg, offline_model, run_id="baseline-unit", run_dir=tmp_path / "run")
    target = cfg.targets[0]
    case = _get_case("1.3.6.1.4.1.52305.999.1.0")
    try:
        runtime._baseline_cache[(target.name, case.version)] = {"1.3.6.1.4.1.52305.1.1.0"}
        to_run, preclassified = asyncio.run(runtime._apply_baseline([(target, case)]))
        assert to_run == []
        assert [r.status for r in preclassified] == ["unsupported"]
        assert runtime.collector.results[-1].case_id == case.case_id
        assert not runtime._baseline_applicable(_get_case(case.oid, assertion="no_such"))
    finally:
        runtime.collector.close()


def test_oid_baseline_skips_supported_get(offline_config, offline_model, tmp_path):
    cfg = Config(copy.deepcopy(offline_config.raw), ROOT / "config" / "config.example.yaml")
    runtime = Runtime(cfg, offline_model, run_id="baseline-unit-2", run_dir=tmp_path / "run2")
    target = cfg.targets[0]
    case = _get_case("1.3.6.1.4.1.52305.1.1.0")
    try:
        runtime._baseline_cache[(target.name, case.version)] = {case.oid}
        to_run, preclassified = asyncio.run(runtime._apply_baseline([(target, case)]))
        assert to_run == [(target, case)]
        assert preclassified == []
    finally:
        runtime.collector.close()
