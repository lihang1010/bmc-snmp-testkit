"""Sockets and log files must be released on failure paths, not only on success."""

from __future__ import annotations

import asyncio
import copy
import gc
import logging
from pathlib import Path

import pytest

from snmp_test.config import Config
from snmp_test.runner import executor
from snmp_test.runner.executor import run_batch
from snmp_test.snmp.mock_agent import MockAgent
from snmp_test.snmp.trap_listener import TrapListener
from snmp_test.snmp.transport import SnmpSession, TransportPool

ROOT = Path(__file__).resolve().parents[1]
FD_DIR = Path("/proc/self/fd")
linux_only = pytest.mark.skipif(not FD_DIR.is_dir(), reason="Linux FD accounting required")


def _fds() -> int:
    return len(list(FD_DIR.iterdir()))


def _run(coro):
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()


def _cfg(offline_config, tmp_path: Path, **trap) -> Config:
    raw = copy.deepcopy(offline_config.raw)
    raw["report"]["output_dir"] = str(tmp_path / "runs")
    raw["trap"].update({"listen_host": "127.0.0.1", "listen_port": 0, **trap})
    return Config(raw, ROOT / "config" / "config.example.yaml")


@linux_only
@pytest.mark.parametrize("failure", [RuntimeError("start failed"), asyncio.CancelledError()])
def test_failed_batch_releases_run_files(offline_config, offline_model, tmp_path, monkeypatch, failure):
    cfg = _cfg(offline_config, tmp_path)

    async def fail(self):
        raise failure

    monkeypatch.setattr(executor.Runtime, "start", fail)
    gc.collect()
    baseline = _fds()
    gc.disable()
    try:
        with pytest.raises(type(failure)):
            _run(run_batch(cfg, offline_model, [], run_id="cleanup-run"))
        assert _fds() <= baseline
        assert not logging.getLogger("snmp_test.run.cleanup-run").handlers
    finally:
        gc.enable()
        gc.collect()


class _Dispatcher:
    def __init__(self) -> None:
        self.closed = False

    def job_finished(self, job_id: int) -> None:
        raise KeyError(job_id)

    def close_dispatcher(self) -> None:
        self.closed = True


class _Engine:
    def __init__(self) -> None:
        self.transport_dispatcher = _Dispatcher()


def test_listener_stop_closes_dispatcher_after_failed_start(offline_config):
    listener = TrapListener(offline_config)
    listener.engine = _Engine()  # start() failed before job_started(1)
    _run(listener.stop())
    assert listener.engine.transport_dispatcher.closed


def test_mock_agent_closes_notification_engines():
    agent = object.__new__(MockAgent)
    agent.engine = None
    engines = [_Engine(), _Engine()]
    agent.notify_engines = list(engines)
    _run(agent.stop())
    assert all(e.transport_dispatcher.closed for e in engines)
    assert agent.notify_engines == []


def test_pool_close_waits_for_session_being_opened(offline_config, monkeypatch):
    opening = asyncio.Event()
    release = asyncio.Event()
    closed: list[SnmpSession] = []

    async def slow_open(self):
        opening.set()
        await release.wait()
        return self

    async def record_close(self):
        closed.append(self)

    monkeypatch.setattr(SnmpSession, "open", slow_open)
    monkeypatch.setattr(SnmpSession, "close", record_close)

    async def body():
        pool = TransportPool(offline_config)
        target = offline_config.targets[0]
        acquiring = asyncio.create_task(pool.session(target, "v2c"))
        await opening.wait()
        closing = asyncio.create_task(pool.close())
        await asyncio.sleep(0)
        release.set()
        session = await acquiring
        await closing
        assert closed == [session]

    _run(body())
