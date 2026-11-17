"""Session reuse, bulk walks and live concurrency/rate limiting."""

from __future__ import annotations

import asyncio
import copy
import time
from pathlib import Path

from snmp_test.config import Config, load_config
from snmp_test.model.types import CaseResult, SnmpResponse, TestCase, Varbind
from snmp_test.runner.executor import Runtime
from snmp_test.service.probe import ProbeService, _oid_key

ROOT = Path(__file__).resolve().parents[1]
CONFIG = ROOT / "config" / "config.example.yaml"
ROOT_OID = "1.3.6.1.4.1.52305.3.13.1.1.2"
ROWS = [f"{ROOT_OID}.{i}" for i in range(1, 41)]


class _FakeSession:
    def __init__(self, rows: list[str], *, v1_nosuch_end: bool = False) -> None:
        self.rows = rows
        self.v1_nosuch_end = v1_nosuch_end
        self.bulk_calls = 0
        self.next_calls = 0

    def _next(self, cursor: str) -> list[str]:
        key = _oid_key(cursor)
        return [row for row in self.rows if _oid_key(row) > key]

    async def get_next(self, oids):
        self.next_calls += 1
        remaining = self._next(oids[0])
        if not remaining:
            if self.v1_nosuch_end:
                return SnmpResponse(error_indication=None, error_status="noSuchName", error_index=0,
                                    varbinds=[], version="v1", operation="GETNEXT", target="fake")
            return SnmpResponse(error_indication=None, error_status="noError", error_index=0,
                                varbinds=[Varbind(oid=oids[0], type="EndOfMibView",
                                                  value="EndOfMibView", exception="EndOfMibView")],
                                version="v1", operation="GETNEXT", target="fake")
        return SnmpResponse(error_indication=None, error_status="noError", error_index=0,
                            varbinds=[Varbind(oid=remaining[0], type="Integer32", value=1)],
                            version="v1", operation="GETNEXT", target="fake")

    async def get_bulk(self, oids, *, non_repeaters=0, max_repetitions=6):
        self.bulk_calls += 1
        remaining = self._next(oids[0])[:max_repetitions]
        varbinds = [
            Varbind(oid=row, type="Integer32", value=1) for row in remaining
        ]
        if not remaining:
            varbinds.append(Varbind(oid=oids[0], type="EndOfMibView",
                                    value="EndOfMibView", exception="EndOfMibView"))
        return SnmpResponse(error_indication=None, error_status="noError", error_index=0,
                            varbinds=varbinds, version="v2c", operation="GETBULK", target="fake")


def test_walk_paces_v1_steps(tmp_path: Path):
    """Space out GETNEXT steps so long v1 walks do not overwhelm the agent."""
    service = ProbeService(tmp_path, tmp_path / "web.yaml")
    service.rate_limit_ms = 40

    async def body():
        # execute() throttles before the first request; _walk paces the rest.
        await service._throttle("192.0.2.1")
        started = time.monotonic()
        varbinds, error, truncated = await service._walk(
            _FakeSession(ROWS), "v1", ROOT_OID, "", 4, host="192.0.2.1",
        )
        elapsed = time.monotonic() - started
        assert len(varbinds) == 4 and truncated is True and error == ""
        assert elapsed >= 0.11  # three gaps between four steps

    _run(body)


def _run(body):
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        return loop.run_until_complete(body())
    finally:
        loop.close()
        asyncio.set_event_loop(None)


def test_walk_uses_getbulk_for_v2c_and_getnext_for_v1(tmp_path: Path):
    service = ProbeService(tmp_path, tmp_path / "web.yaml")

    async def body():
        bulk_session = _FakeSession(ROWS)
        varbinds, error, truncated = await service._walk(
            bulk_session, "v2c", ROOT_OID, "", 30,
        )
        assert error == "" and truncated is True
        assert len(varbinds) == 30
        assert bulk_session.bulk_calls == 2  # 25 + 5
        assert bulk_session.next_calls == 0

        v1_session = _FakeSession(ROWS)
        varbinds, error, truncated = await service._walk(
            v1_session, "v1", ROOT_OID, "", 5,
        )
        assert error == "" and truncated is True
        assert len(varbinds) == 5
        assert v1_session.next_calls == 5
        assert v1_session.bulk_calls == 0

        # The last page stops at the end of the subtree instead of reporting a
        # short-but-truncated page.
        end_session = _FakeSession(ROWS[:3])
        varbinds, error, truncated = await service._walk(
            end_session, "v2c", ROOT_OID, "", 30,
        )
        assert len(varbinds) == 3 and truncated is False and error == ""

        # v1 reports end-of-MIB as noSuchName; after rows were collected that is
        # a normal stop, not a walk failure.
        v1_end = _FakeSession(ROWS[:3], v1_nosuch_end=True)
        varbinds, error, truncated = await service._walk(
            v1_end, "v1", ROOT_OID, "", 30,
        )
        assert len(varbinds) == 3 and truncated is False and error == ""

    _run(body)


def _live_runtime(tmp_path: Path, *, live_concurrency: int, interval_ms: float = 0) -> Runtime:
    cfg = load_config(CONFIG)
    raw = copy.deepcopy(cfg.raw)
    raw["mode"] = "live"
    raw["targets"] = [{
        "name": "lab-bmc", "enabled": True, "host": "127.0.0.1", "port": 161,
        "versions": ["v2c"],
        "v2c": {"community": "public", "read_only_community": "public"},
    }]
    raw["execution"]["live_concurrency"] = live_concurrency
    raw["execution"]["request_interval_ms"] = interval_ms
    raw["trap"]["listen_port"] = 0  # never started in these tests
    live_cfg: Config = Config(raw, CONFIG)
    from snmp_test.model.mib_model import build_model

    model = build_model(cfg.mib_path)
    return Runtime(
        live_cfg, model, run_id="perf", run_dir=tmp_path / "runs" / "perf",
        allow_live=True, readonly_only=True,
    )


def _case(name: str) -> TestCase:
    return TestCase(
        case_id=name, name=name, oid="1.3.6.1.2.1.1.1.0", operation="GET",
        version="v2c", category="normal", tags=(), payload={}, expectation={},
        safety="safe",
    )


def test_live_concurrency_caps_parallel_requests_per_target(tmp_path: Path):
    runtime = _live_runtime(tmp_path, live_concurrency=2)
    active = 0
    peak = 0

    async def fake_dispatch(target, case, result: CaseResult):
        nonlocal active, peak
        active += 1
        peak = max(peak, active)
        await asyncio.sleep(0.05)
        active -= 1
        result.status = "passed"

    runtime._dispatch = fake_dispatch  # type: ignore[method-assign]
    target = runtime.cfg.targets[0]

    async def body():
        results: list[CaseResult] = [
            CaseResult(case_id=f"c{i}", name=f"c{i}", operation="GET", version="v2c")
            for i in range(6)
        ]
        await asyncio.gather(*(
            runtime._execute_guarded(target, _case(f"c{i}"), results[i]) for i in range(6)
        ))
        return results

    results = _run(body)
    assert peak == 2
    assert all(r.status == "passed" for r in results)


def test_request_interval_spaces_requests(tmp_path: Path):
    runtime = _live_runtime(tmp_path, live_concurrency=1, interval_ms=80)
    target = runtime.cfg.targets[0]

    async def body():
        started = time.monotonic()
        await runtime._throttle(target)
        await runtime._throttle(target)
        return time.monotonic() - started

    elapsed = _run(body)
    assert elapsed >= 0.07, elapsed
