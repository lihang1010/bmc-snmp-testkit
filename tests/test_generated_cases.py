"""Run generated cases through pytest (CI / marker filtering / --lf)."""

from __future__ import annotations

from snmp_test.runner.pytest_plugin import run_generated_case


def test_generated_case(snmp_runtime, snmp_case_id):
    run_generated_case(snmp_runtime, snmp_case_id)
