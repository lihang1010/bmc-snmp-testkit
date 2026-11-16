"""Batch execution engine: concurrency, session reuse, safety and traps."""

from __future__ import annotations

import asyncio
import time
import traceback
import uuid
from dataclasses import replace
from datetime import datetime
from pathlib import Path
from typing import Any, Callable

from snmp_test.config import Config, TargetConfig
from snmp_test.model.types import CaseResult, MibModel, SnmpResponse, TestCase, TrapRecord
from snmp_test.report.collector import ResultCollector
from snmp_test.runner.assertions import evaluate
from snmp_test.runner.safety import SafetyAbort, SafetyGateway, load_policy
from snmp_test.security import SecurityPolicy
from snmp_test.snmp.errors import is_timeout
from snmp_test.snmp.mock_agent import MockAgent
from snmp_test.snmp.trap_listener import TrapListener, engine_id_hex
from snmp_test.snmp.transport import TransportPool
from snmp_test.snmp.triggers import TriggerAdapter


def make_run_id() -> str:
    return datetime.now().strftime("%Y%m%d-%H%M%S") + "-" + uuid.uuid4().hex[:6]


class Runtime:
    """Owns every long-lived resource for one run."""

    def __init__(
        self,
        cfg: Config,
        model: MibModel,
        *,
        run_id: str | None = None,
        run_dir: str | Path | None = None,
        allow_guarded: bool | None = None,
        enable_set: bool | None = None,
        allow_live: bool | None = None,
        readonly_only: bool | None = None,
        security: SecurityPolicy | None = None,
    ) -> None:
        self.cfg = cfg
        self.model = model
        self.security = security or SecurityPolicy.from_config(
            cfg, allow_live=allow_live, readonly_only=readonly_only
        )
        # Enforce before creating any files or sockets: Python API callers must
        # not be able to reach a real device without the same confirmation the
        # CLI requires.
        self.security.enforce(cfg)
        self.run_id = run_id or make_run_id()
        output = Path(cfg.resolve(str(cfg.report.get("output_dir", "runs"))))
        self.run_dir = Path(run_dir) if run_dir else output / self.run_id
        ex = cfg.execution
        self.concurrency = max(1, int(ex.get("concurrency", 12)))
        self.sem = asyncio.Semaphore(self.concurrency)
        self.set_locks: dict[str, asyncio.Lock] = {}
        self.trap_lock = asyncio.Lock()
        self.aborted_targets: set[str] = set()
        self._trap_targets_ready: set[str] = set()
        self._trap_engines_ready: set[str] = set()
        self.oid_baseline = bool(ex.get("oid_baseline", False))
        self.oid_baseline_max = max(1, int(ex.get("oid_baseline_max", 20000)))
        self._baseline_cache: dict[tuple[str, str], set[str] | None] = {}
        self.policy = load_policy(cfg.resolve(str(cfg.safety.get("policy_file", "config/safety-policy.yaml"))))
        self.collector = ResultCollector(cfg, self.run_id, self.run_dir)
        effective_guarded = (
            False if self.security.readonly_only
            else bool(ex.get("allow_guarded", False) if allow_guarded is None else allow_guarded)
        )
        effective_set = self.security.effective_set_enabled(cfg)
        if enable_set is not None:
            effective_set = effective_set and bool(enable_set)
        self.safety = SafetyGateway(
            self.policy,
            allow_guarded=effective_guarded,
            set_enabled=effective_set,
            audit_path=self.run_dir / "safety-audit.jsonl",
        )
        self.pool = TransportPool(cfg)
        self.listener = TrapListener(cfg)
        self.agent: MockAgent | None = MockAgent(model, cfg) if cfg.mode == "mock" else None
        self.triggers = TriggerAdapter(cfg, self.agent, self.listener)
        self.dry_run = False

    async def start(self) -> "Runtime":
        if self.agent is not None:
            await self.agent.start()
        await self.listener.start()
        self.collector.logger.info(
            "run %s started: mode=%s targets=%s cases_dir=%s",
            self.run_id, self.cfg.mode, [t.name for t in self.cfg.targets], self.run_dir,
        )
        return self

    async def stop(self) -> None:
        await self.pool.close()
        await self.listener.stop()
        if self.agent is not None:
            await self.agent.stop()
        self.collector.finish()

    def close(self) -> None:
        self.collector.close()

    def targets_for(self, case: TestCase) -> list[TargetConfig]:
        return [t for t in self.cfg.targets if case.version in t.versions]

    async def run(
        self,
        cases: list[TestCase],
        *,
        dry_run: bool = False,
        on_progress: Callable[[int, int, int, int], None] | None = None,
        cancel_event: asyncio.Event | None = None,
    ) -> list[CaseResult]:
        self.dry_run = dry_run
        pairs: list[tuple[TargetConfig, TestCase]] = []
        for case in cases:
            for target in self.targets_for(case):
                pairs.append((target, case))
        self.collector.logger.info("scheduled %d case x target executions", len(pairs))
        planned = len(pairs)
        # Progress is reported from inside _run_one (per completed case) instead
        # of from the wait loop: awaiting completions one by one (as_completed)
        # perturbs event-loop scheduling enough to make SNMP timeouts flaky.
        self._progress_cb = on_progress
        self._progress_total = planned
        self._progress_done = 0
        self._progress_passed = 0
        self._progress_failed = 0
        baseline_results: list[CaseResult] = []
        if self.oid_baseline and not dry_run:
            pairs, baseline_results = await self._apply_baseline(pairs, cancel_event=cancel_event)
        results: list[CaseResult] = list(baseline_results)
        chunk = 50
        for start in range(0, len(pairs), chunk):
            if cancel_event is not None and cancel_event.is_set():
                break
            batch = pairs[start : start + chunk]
            gathered = await asyncio.gather(
                *(self._run_one(target, case) for target, case in batch),
                return_exceptions=False,
            )
            results.extend(gathered)
        return results

    def _bump_progress(self, result: CaseResult) -> None:
        cb = getattr(self, "_progress_cb", None)
        if cb is None:
            return
        self._progress_done += 1
        if result.status == "passed":
            self._progress_passed += 1
        elif result.status in ("failed", "error", "timeout", "unsupported"):
            self._progress_failed += 1
        cb(self._progress_done, self._progress_total, self._progress_passed, self._progress_failed)

    async def _apply_baseline(
        self,
        pairs: list[tuple[TargetConfig, TestCase]],
        *,
        cancel_event: asyncio.Event | None = None,
    ) -> tuple[list[tuple[TargetConfig, TestCase]], list[CaseResult]]:
        """Mark GETs whose instance OID is absent from a live walk as unsupported."""
        wanted_versions = {
            (target.name, case.version)
            for target, case in pairs
            if self._baseline_applicable(case)
        }
        for target_name, version in sorted(wanted_versions):
            if cancel_event is not None and cancel_event.is_set():
                break
            target = next((t for t in self.cfg.targets if t.name == target_name), None)
            if target is None:
                continue
            await self._baseline_oids(target, version)

        to_run: list[tuple[TargetConfig, TestCase]] = []
        preclassified: list[CaseResult] = []
        for target, case in pairs:
            implemented = self._baseline_cache.get((target.name, case.version))
            if implemented is not None and self._baseline_applicable(case):
                wanted = [str(v.get("oid")) for v in case.payload.get("varbinds") or [] if v.get("oid")]
                if wanted and not any(oid in implemented for oid in wanted):
                    result = CaseResult(
                        case_id=case.case_id,
                        name=case.name,
                        status="unsupported",
                        operation=case.operation,
                        version=case.version,
                        module=case.module,
                        target=target.name,
                        tags=case.tags,
                        expectation=case.expectation,
                        message=f"OID absent from {target.name}/{case.version} baseline walk",
                    )
                    self.collector.add(result)
                    self._bump_progress(result)
                    preclassified.append(result)
                    continue
            to_run.append((target, case))
        self.collector.logger.info(
            "oid baseline: %d preclassified unsupported, %d will be executed",
            len(preclassified), len(to_run),
        )
        return to_run, preclassified

    def _baseline_applicable(self, case: TestCase) -> bool:
        if case.operation != "GET" or not case.payload.get("varbinds"):
            return False
        kinds = {str(spec.get("kind", "")) for spec in case.expectation.get("assertions") or []}
        return not (kinds & {"rejected", "no_such", "end_of_mib", "auth_rejected", "client_error"})

    async def _baseline_oids(self, target: TargetConfig, version: str) -> set[str] | None:
        key = (target.name, version)
        if key in self._baseline_cache:
            return self._baseline_cache[key]
        session = await self.pool.session(target, version)
        root = self.model.root_oid.strip(".")
        root_prefix = root + "."
        current = root
        found: set[str] = set()
        error = ""
        while len(found) < self.oid_baseline_max:
            if version == "v1":
                response = await session.get_next([current])
                varbinds = list(response.varbinds[:1])
            else:
                response = await session.get_bulk(
                    [current], non_repeaters=0, max_repetitions=25,
                )
                varbinds = list(response.varbinds)
            if response.error_indication or response.error_status not in ("noError", "0"):
                error = response.error_indication or response.error_status
                break
            progressed = False
            stop = False
            for varbind in varbinds:
                if varbind.exception is not None:
                    stop = True
                    break
                if varbind.oid != root and not varbind.oid.startswith(root_prefix):
                    stop = True
                    break
                if _oid_key(varbind.oid) <= _oid_key(current):
                    stop = True
                    break
                current = varbind.oid
                found.add(varbind.oid)
                progressed = True
                if len(found) >= self.oid_baseline_max:
                    break
            if stop or not progressed:
                break
        if error or not found:
            self.collector.logger.warning(
                "oid baseline unavailable for %s/%s (%s); GET cases will run normally",
                target.name, version, error or "empty walk",
            )
            self._baseline_cache[key] = None
        else:
            self.collector.logger.info(
                "oid baseline for %s/%s: %d OIDs discovered", target.name, version, len(found),
            )
            self._baseline_cache[key] = found
        return self._baseline_cache[key]

    async def run_one(self, target: TargetConfig, case: TestCase) -> CaseResult:
        """Public single-case entry point used by the pytest bridge."""
        return await self._run_one(target, case)

    async def _run_one(self, target: TargetConfig, case: TestCase) -> CaseResult:
        started = time.perf_counter()
        result = CaseResult(
            case_id=case.case_id,
            name=case.name,
            operation=case.operation,
            version=case.version,
            module=case.module,
            target=target.name,
            tags=case.tags,
            expectation=case.expectation,
        )
        try:
            async with self.sem:
                if case.expectation.get("skip"):
                    result.status = "skipped"
                    result.message = str(case.expectation.get("reason", "skipped by design"))
                elif self.dry_run:
                    result.status = "skipped"
                    result.message = "dry-run: no PDU sent"
                else:
                    allowed, reason = self.safety.check(case)
                    if not self.security.allows_operation(case.operation):
                        allowed, reason = False, f"read-only service forbids operation {case.operation}"
                    if not allowed:
                        result.status = "blocked"
                        result.message = reason
                    elif case.operation == "SET" and target.name in self.aborted_targets:
                        result.status = "error"
                        result.message = "target SET cases aborted after a failed restore"
                    elif case.operation == "SET":
                        async with self.set_locks.setdefault(target.name, asyncio.Lock()):
                            await self._execute_set(target, case, result)
                    elif case.operation in ("TRAP", "INFORM"):
                        async with self.trap_lock:
                            await self._execute_trap(target, case, result)
                    else:
                        await self._execute_read(target, case, result)
        except SafetyAbort as exc:
            self.aborted_targets.add(target.name)
            result.status = "error"
            result.message = f"SAFETY ABORT: {exc}"
            self.collector.logger.error("safety abort on %s: %s", target.name, exc)
        except Exception as exc:
            result.status = "error"
            result.message = f"{type(exc).__name__}: {exc}"
            result.logs.append(traceback.format_exc(limit=6))
        result.duration_ms = round((time.perf_counter() - started) * 1000, 2)
        self.collector.add(result)
        self._bump_progress(result)
        return result

    def _override(self, target: TargetConfig, case: TestCase) -> dict[str, Any]:
        override = dict(case.payload.get("credential_override") or {})
        if override.get("community") == "__READ_ONLY__":
            override["community"] = target.read_only_community(case.version)
        return override

    async def _session(self, target: TargetConfig, case: TestCase):
        return await self.pool.session(target, case.version, self._override(target, case))

    async def _execute_read(self, target: TargetConfig, case: TestCase, result: CaseResult) -> None:
        session = await self._session(target, case)
        varbinds = list(case.payload.get("varbinds") or [])
        operation = case.operation
        if operation == "GET":
            response = await session.get(varbinds=varbinds)
        elif operation == "GETNEXT":
            response = await session.get_next(varbinds=varbinds)
        elif operation == "GETBULK":
            response = await session.get_bulk(
                varbinds=varbinds,
                non_repeaters=int(case.payload.get("non_repeaters", 0)),
                max_repetitions=int(case.payload.get("max_repetitions", 6)),
            )
        else:
            raise RuntimeError(f"unsupported read operation {operation}")
        self._finish(result, response)

    async def _execute_set(self, target: TargetConfig, case: TestCase, result: CaseResult) -> None:
        session = await self._session(target, case)
        varbinds = list(case.payload.get("varbinds") or [])
        guarded_case = replace(case, payload={**case.payload, "target": target.name})
        response, trace = await self.safety.guarded_set(session, guarded_case, varbinds)
        result.logs.extend(trace)
        self._finish(result, response)
        self.collector.add_pdu(
            case_id=case.case_id, target=target.name, version=case.version,
            operation="SET", response=response, note="guarded backup/set/restore",
        )

    async def _prepare_trap_target(self, target: TargetConfig, *, need_engine_id: bool) -> None:
        """Register target credentials, discovering its v3 engine id if needed."""
        v3 = dict(target.v3 or {})
        if target.name not in self._trap_targets_ready:
            self._trap_targets_ready.add(target.name)
            self.listener.register_target(target)
        if not need_engine_id or target.name in self._trap_engines_ready:
            return
        self._trap_engines_ready.add(target.name)
        if not v3.get("user"):
            return
        engine_hex = engine_id_hex(v3.get("trap_engine_id") or "")
        if not engine_hex and self.cfg.mode == "live" and "v3" in target.versions:
            try:
                session = await self.pool.session(target, "v3")
                response = await session.get(["1.3.6.1.6.3.10.2.1.1.0"])
                varbind = response.varbinds[0] if response.varbinds else None
                if not response.error_indication and varbind is not None and varbind.exception is None:
                    engine_hex = engine_id_hex(varbind.value)
            except Exception as exc:
                self.collector.logger.warning(
                    "trap: could not discover v3 engine id for %s: %s", target.name, exc,
                )
        if engine_hex:
            try:
                self.listener.register_target(target, engine_hex)
            except Exception as exc:
                self.collector.logger.warning("trap: could not register %s: %s", target.name, exc)
                return
            self.collector.logger.info(
                "trap: registered v3 engine %s for %s", engine_hex, target.name,
            )

    async def _execute_trap(self, target: TargetConfig, case: TestCase, result: CaseResult) -> None:
        exp = case.payload.get("trap_expectation") or {}
        version = str(exp.get("version") or case.version)
        # Only unconfirmed v3 notifications are originator-authoritative.
        await self._prepare_trap_target(
            target, need_engine_id=case.operation == "TRAP" and version == "v3",
        )
        fired = await self.triggers.fire(case)
        timeout = float(exp.get("max_latency_s") or self.cfg.trap.get("receive_timeout_s", 5.0))
        if fired.get("passive"):
            # Live matching cannot rely on the mock-only correlation varbind.
            trap: TrapRecord | None = await self.listener.wait_for_match(
                pdu_type=str(exp.get("pdu_type") or ("inform" if case.operation == "INFORM" else "trap")),
                version=version,
                trap_oids=exp.get("expected_trap_oids") or (),
                source=str(exp.get("source") or target.host),
                after=float(fired.get("triggered_at") or time.time()),
                claimant=case.case_id,
                claim=True,
                timeout=timeout,
            )
        else:
            trap = await self.listener.wait_for(
                case.case_id,
                pdu_type=exp.get("pdu_type"),
                version=exp.get("version"),
                after=float(fired.get("triggered_at") or 0.0),
                timeout=timeout,
                claim=True,
            )
        outcome = evaluate(case, trap=trap, trigger=fired)
        result.actual = {
            "trigger": fired,
            "trap": trap.to_dict() if trap else None,
            "listener_records": len(self.listener.records),
        }
        result.status = "passed" if outcome.passed else "failed"
        result.message = "; ".join(outcome.failures) if outcome.failures else "trap/inform matched expectation"
        result.expectation = {**case.expectation, "_details": outcome.details}
        self.collector.add_pdu(
            case_id=case.case_id, target="trap-listener", version=case.version,
            operation=case.operation, response=None, note=json_safe({"trigger": fired, "trap": trap.to_dict() if trap else None}),
        )

    def _finish(self, result: CaseResult, response: SnmpResponse) -> None:
        outcome = evaluate(result_case_from_result(result), response)
        result.actual = {**response.to_dict(), "_assertions": outcome.details}
        if outcome.passed:
            result.status = "passed"
            result.message = "all assertions passed"
        else:
            # A failing read is not always a product defect: the device may not
            # implement the MIB-declared OID, or may not answer at all.  Keeping
            # those outcomes separate keeps the effective pass rate meaningful.
            result.status = shortfall_status(response) or "failed"
            result.message = "; ".join(outcome.failures)
        self.collector.add_pdu(
            case_id=result.case_id, target=result.target, version=result.version,
            operation=result.operation, response=response,
        )


def shortfall_status(response: SnmpResponse) -> str | None:
    """Classify a failed response that reflects device support, not assertions."""
    if is_timeout(response.error_indication):
        return "timeout"
    if response.error_status == "noSuchName":
        return "unsupported"
    if any(v.exception in ("NoSuchObject", "NoSuchInstance") for v in response.varbinds):
        return "unsupported"
    return None


def _TestCaseStub(result: CaseResult) -> TestCase:  # pragma: no cover - helper
    from snmp_test.model.types import TestCase

    return TestCase(
        case_id=result.case_id,
        name=result.name,
        oid="",
        operation=result.operation,
        version=result.version,
        category="",
        tags=result.tags,
        payload={},
        expectation=result.expectation,
    )


def result_case_from_result(result: CaseResult) -> TestCase:
    return _TestCaseStub(result)


def json_safe(value: Any) -> str:
    import json

    return json.dumps(value, ensure_ascii=False, default=str)[:1500]


def _oid_key(oid: str) -> tuple[int, ...]:
    try:
        return tuple(int(part) for part in oid.strip(".").split("."))
    except ValueError:
        return ()


async def run_batch(
    cfg: Config,
    model: MibModel,
    cases: list[TestCase],
    *,
    run_id: str | None = None,
    allow_guarded: bool | None = None,
    enable_set: bool | None = None,
    allow_live: bool | None = None,
    readonly_only: bool | None = None,
    security: SecurityPolicy | None = None,
    dry_run: bool = False,
    on_progress: Callable[[int, int, int, int], None] | None = None,
    cancel_event: asyncio.Event | None = None,
) -> tuple[Runtime, list[CaseResult]]:
    """Convenience entry point: start resources, run, stop, return results."""
    runtime = Runtime(
        cfg, model, run_id=run_id,
        allow_guarded=allow_guarded, enable_set=enable_set,
        allow_live=allow_live, readonly_only=readonly_only, security=security,
    )
    await runtime.start()
    try:
        results = await runtime.run(
            cases, dry_run=dry_run, on_progress=on_progress, cancel_event=cancel_event,
        )
    finally:
        await runtime.stop()
    return runtime, results
