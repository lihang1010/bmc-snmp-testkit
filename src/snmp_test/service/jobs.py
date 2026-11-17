"""Serial job runner and persistent job store.

A single worker processes jobs one at a time.  This is required because the
trap receiver and (in mock mode) the simulated agent bind fixed UDP ports, and
because hammering a BMC from many concurrent users is undesirable anyway.
"""

from __future__ import annotations

import asyncio
import json
import shutil
import time
import traceback
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from snmp_test.config import load_config
from snmp_test.model.types import MibModel
from snmp_test.report.writers import write_all
from snmp_test.runner.case_store import CaseFilter
from snmp_test.runner.executor import make_run_id, run_batch
from snmp_test.runner.safety import load_policy
from snmp_test.security import SecurityPolicy
from snmp_test.service.mibs import MibLibrary
from snmp_test.service.probe import ProbeService
from snmp_test.service.web_policy import WebPolicy

WEB_MOCK_PORT = 11811
WEB_TRAP_PORT = 11812
PORT_STRIDE = 10
MAX_WORKERS = 4


def slot_ports(slot: int) -> tuple[int, int]:
    """Each worker slot gets its own mock/trap port pair, so runs can overlap."""
    return WEB_MOCK_PORT + slot * PORT_STRIDE, WEB_TRAP_PORT + slot * PORT_STRIDE


@dataclass
class Job:
    job_id: str
    user: str
    mib_id: str
    target_host: str
    target_port: int
    version: str
    mode: str = "mock"
    modules: tuple[str, ...] = ()
    limit: int = 20
    credential: dict[str, Any] = field(default_factory=dict, repr=False)
    status: str = "queued"
    created_at: float = field(default_factory=time.time)
    started_at: float | None = None
    finished_at: float | None = None
    run_id: str | None = None
    case_count: int = 0
    summary: dict[str, Any] = field(default_factory=dict)
    progress: dict[str, Any] = field(default_factory=dict)
    message: str = ""

    def public_dict(self) -> dict[str, Any]:
        """Never serialise credentials."""
        return {
            "job_id": self.job_id,
            "user": self.user,
            "mib_id": self.mib_id,
            "target_host": self.target_host,
            "target_port": self.target_port,
            "version": self.version,
            "mode": self.mode,
            "modules": list(self.modules),
            "limit": self.limit,
            "status": self.status,
            "created_at": self.created_at,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "run_id": self.run_id,
            "case_count": self.case_count,
            "summary": self.summary,
            "message": self.message,
            "progress": self.progress,
        }


class JobStore:
    def __init__(self, root: str | Path) -> None:
        self.root = Path(root)
        self.base = self.root / "work" / "jobs"
        self.base.mkdir(parents=True, exist_ok=True)
        self.journal = self.base / "jobs.jsonl"
        self.audit = self.base / "audit.jsonl"
        self._jobs: dict[str, Job] = {}
        self._load()

    def _load(self) -> None:
        if not self.journal.is_file():
            return
        for line in self.journal.read_text(encoding="utf-8").splitlines():
            try:
                data = json.loads(line)
                job = Job(
                    job_id=data["job_id"], user=data["user"], mib_id=data["mib_id"],
                    target_host=data["target_host"], target_port=int(data["target_port"]),
                    version=data["version"], mode=data.get("mode", "mock"),
                    modules=tuple(data.get("modules") or ()), limit=int(data.get("limit", 20)),
                    status=data.get("status", "queued"),
                    created_at=float(data.get("created_at", 0)),
                    started_at=data.get("started_at"), finished_at=data.get("finished_at"),
                    run_id=data.get("run_id"), case_count=int(data.get("case_count", 0)),
                    summary=data.get("summary") or {}, message=data.get("message", ""),
                    progress=data.get("progress") or {},
                )
                self._jobs[job.job_id] = job
            except Exception:
                continue
        # Anything that was mid-flight when the process died is reported as failed.
        for job in self._jobs.values():
            if job.status in ("queued", "waiting", "running"):
                job.status = "failed"
                job.message = "interrupted by service restart"
                job.finished_at = time.time()
                # Persist the correction: otherwise the journal keeps claiming
                # "running" and the UI resurrects a job that no longer exists.
                self._append(job)
                self.audit_log({
                    "event": "job_failed", "job_id": job.job_id, "user": job.user,
                    "mib_id": job.mib_id, "target": job.target_host, "mode": job.mode,
                    "reason": "service_restart", "error": job.message,
                })

    def create(self, **kwargs: Any) -> Job:
        job = Job(job_id=uuid.uuid4().hex[:12], **kwargs)
        self._jobs[job.job_id] = job
        self._append(job)
        return job

    def get(self, job_id: str) -> Job | None:
        return self._jobs.get(job_id)

    def list(self, limit: int = 50) -> list[Job]:
        return sorted(self._jobs.values(), key=lambda j: j.created_at, reverse=True)[:limit]

    def list_for(self, user: str, limit: int = 50) -> list[Job]:
        """Only the jobs owned by ``user`` -- the queue is private per account."""
        items = [j for j in self._jobs.values() if j.user == user]
        return sorted(items, key=lambda j: j.created_at, reverse=True)[:limit]

    def _append(self, job: Job) -> None:
        with self.journal.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(job.public_dict(), ensure_ascii=False, default=str) + "\n")

    def update(self, job: Job) -> None:
        self._append(job)

    def delete(self, job_id: str) -> Job:
        """Drop one job, rewrite the journal and remove its run directory."""
        job = self._jobs.pop(job_id, None)
        if job is None:
            raise KeyError(job_id)
        self._rewrite()
        for run_id in {job.run_id, f"web-{job_id}"}:
            if not run_id:
                continue
            folder = self.root / "runs" / run_id
            if folder.is_dir():
                shutil.rmtree(folder, ignore_errors=True)
        return job

    def _rewrite(self) -> None:
        """Persist only the current jobs (the journal is append-only otherwise)."""
        tmp = self.journal.with_suffix(".jsonl.tmp")
        with tmp.open("w", encoding="utf-8") as fh:
            for job in sorted(self._jobs.values(), key=lambda j: j.created_at):
                fh.write(json.dumps(job.public_dict(), ensure_ascii=False, default=str) + "\n")
        tmp.replace(self.journal)

    def audit_log(self, entry: dict[str, Any]) -> None:
        with self.audit.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps({"ts": time.time(), **entry}, ensure_ascii=False, default=str) + "\n")


class JobRunner:
    def __init__(
        self,
        root: str | Path,
        library: MibLibrary,
        store: JobStore,
        *,
        config_path: str | Path | None = None,
        web_security: dict[str, Any] | None = None,
        workers: int = 2,
        probe: ProbeService | None = None,
    ) -> None:
        self.root = Path(root)
        self.library = library
        self.store = store
        self.config_path = Path(config_path) if config_path else self.root / "config" / "web.yaml"
        self.web_security = dict(web_security or {})
        self.policy = WebPolicy.from_security(self.web_security)
        settings = self._job_settings()
        self.timeout_s = max(0.1, float(settings.get("timeout_s", 5.0)))
        self.retries = max(0, int(settings.get("retries", 1)))
        self.probe = probe
        self.queue: asyncio.Queue[Job | None] = asyncio.Queue()
        self.workers = max(1, min(int(workers), MAX_WORKERS))
        self._tasks: list[asyncio.Task] = []
        self._current: dict[int, str] = {}
        self._target_locks: dict[str, asyncio.Lock] = {}
        self._cancel: dict[str, asyncio.Event] = {}

    @property
    def current_jobs(self) -> list[str]:
        return [job_id for job_id in self._current.values() if job_id]

    def _job_settings(self) -> dict[str, Any]:
        if not self.config_path.is_file():
            return {}
        try:
            raw = yaml.safe_load(self.config_path.read_text(encoding="utf-8")) or {}
        except Exception:
            return {}
        return dict(raw.get("jobs") or {})

    async def start(self) -> "JobRunner":
        for slot in range(self.workers):
            self._tasks.append(
                asyncio.create_task(self._worker(slot), name=f"snmp-job-worker-{slot}")
            )
        return self

    async def stop(self) -> None:
        for _ in self._tasks:
            await self.queue.put(None)
        for task in self._tasks:
            try:
                await asyncio.wait_for(task, timeout=10)
            except asyncio.TimeoutError:
                task.cancel()
        self._tasks.clear()
        # A shutdown can cancel a job mid-run; persist the interrupted state so
        # the UI does not show a phantom "running" job after the next start.
        for job in self.store.list(500):
            if job.status in ("queued", "waiting", "running"):
                job.status = "failed"
                job.finished_at = time.time()
                job.message = "interrupted by service shutdown"
                self.store.update(job)
                self.store.audit_log({
                    "event": "job_failed", "job_id": job.job_id, "user": job.user,
                    "mib_id": job.mib_id, "target": job.target_host, "mode": job.mode,
                    "reason": "service_shutdown", "error": job.message,
                })

    async def submit(self, job: Job) -> None:
        await self.queue.put(job)

    def request_cancel(self, job_id: str) -> None:
        """Flag a running/queued job to stop at the next batch boundary.

        Safe to call from a request handler: it only flips an asyncio.Event and
        updates the in-memory job record.  The worker task observes the event and
        stops submitting further batches; already-in-flight batches finish so we
        keep their partial results.
        """
        evt = self._cancel.setdefault(job_id, asyncio.Event())
        evt.set()
        job = self.store.get(job_id)
        if job is not None and job.status in ("queued", "waiting", "running"):
            job.status = "cancelled"
            job.finished_at = time.time()
            job.message = "任务已被用户中断"
            self.store.update(job)
            self.store.audit_log({
                "event": "job_cancelled", "job_id": job_id, "user": job.user,
                "mib_id": job.mib_id, "target": job.target_host,
            })

    def pending(self) -> int:
        return self.queue.qsize()

    async def _worker(self, slot: int) -> None:
        while True:
            job = await self.queue.get()
            if job is None:
                self.queue.task_done()
                return
            try:
                await self._run_job(job, slot)
            finally:
                self.queue.task_done()

    async def _run_job(self, job: Job, slot: int) -> None:
        # Different targets may run in parallel; the same live target is serialised
        # so a real BMC never receives two batches at once.
        lock: asyncio.Lock | None = None
        if job.mode == "live":
            lock = self._target_locks.setdefault(job.target_host, asyncio.Lock())
            if lock.locked():
                job.status = "waiting"
                job.message = f"目标 {job.target_host} 正在执行其他任务，等待中"
                self.store.update(job)
                self.store.audit_log({
                    "event": "job_waiting", "job_id": job.job_id,
                    "user": job.user, "target": job.target_host,
                })
        if lock is None:
            await self._run_slot(job, slot)
            return
        async with lock:
            await self._run_slot(job, slot)

    async def _run_slot(self, job: Job, slot: int) -> None:
        self._current[slot] = job.job_id
        try:
            await self._execute(job, slot)
        except Exception as exc:
            job.status = "failed"
            job.message = f"{type(exc).__name__}: {exc}"
            job.finished_at = time.time()
            self.store.update(job)
            self.store.audit_log({
                "event": "job_failed", "job_id": job.job_id, "user": job.user,
                "mib_id": job.mib_id, "target": job.target_host,
                "mode": job.mode, "error": job.message,
            })
        finally:
            self._current.pop(slot, None)
            self._cancel.pop(job.job_id, None)

    def _build_config(self, job: Job, slot: int = 0):
        model_path = self.library.model_path(job.mib_id)
        mib_path = self.library.mib_path(job.mib_id)
        mock_port, trap_port = slot_ports(slot)
        if job.mode == "mock":
            host, port = "127.0.0.1", mock_port
            cred = {"community": "private", "read_only_community": "public"}
        else:
            host, port = job.target_host, job.target_port
            cred = {"community": job.credential.get("community") or "public"}
            cred["read_only_community"] = job.credential.get("community") or "public"
        v3 = {
            "user": job.credential.get("v3_user") or "bmcuser",
            "auth_protocol": job.credential.get("auth_protocol") or "SHA",
            "auth_key": job.credential.get("auth_key") or "authpass123",
            "priv_protocol": job.credential.get("priv_protocol") or "AES128",
            "priv_key": job.credential.get("priv_key") or "privpass123",
            "security_level": job.credential.get("security_level") or "authPriv",
        }
        overrides = {
            "mode": job.mode,
            "mib": str(mib_path),
            "targets": [{
                "name": f"web-{job.job_id}",
                "enabled": True,
                "host": host,
                "port": port,
                "versions": [job.version],
                "v1": dict(cred),
                "v2c": dict(cred),
                "v3": v3,
            }],
            "mock": {
                "bind_host": "127.0.0.1",
                "port": mock_port,
                "trap_port": trap_port,
                "rows_per_table": 2,
                "communities": {"read_only": "public", "read_write": "private"},
                "v3": v3,
            },
            "trap": {"listen_host": "127.0.0.1", "listen_port": trap_port, "receive_timeout_s": 5.0},
            "execution": {
                "concurrency": 4, "timeout_s": self.timeout_s, "retries": self.retries,
                "rows_per_table": 2, "max_cases_per_table": 8,
                "max_varbinds": 20, "bulk_max_repetitions": 6,
                "allow_guarded": False, "enable_set": False, "limit": 0, "seed": 20261109,
            },
            "security": {
                "allow_live": self.policy.allow_live,
                "allowed_targets": (list(self.policy.allowed_targets) or [host]) if job.mode == "live" else [],
                "readonly_only": True,
            },
            "report": {"output_dir": "runs", "pdu_log_sample_rate": 1.0, "log_level": "INFO"},
            "safety": {"policy_file": str(self.root / "config" / "safety-policy.yaml")},
        }
        cfg = load_config(self.config_path, overrides=overrides)
        model = MibModel.from_dict(json.loads(Path(model_path).read_text(encoding="utf-8")))
        return cfg, model

    async def _execute(self, job: Job, slot: int = 0) -> None:
        job.status = "running"
        job.started_at = time.time()
        self.store.update(job)
        self.store.audit_log({
            "event": "job_started", "job_id": job.job_id, "user": job.user,
            "mib_id": job.mib_id, "target": job.target_host, "mode": job.mode,
            "version": job.version, "limit": job.limit,
        })

        if job.mode not in ("mock", "live"):
            raise ValueError(f"unsupported mode {job.mode!r}")

        # Pre-flight reachability check for live targets: a live device that does
        # not answer SNMP would otherwise produce an all-failing job.  Probe it
        # with a single GET and abort early with a clear message instead of
        # wasting a full run on an unreachable target.
        if job.mode == "live" and self.probe is not None:
            try:
                presult = await self.probe.execute(
                    {
                        "mode": "live",
                        "target_host": job.target_host,
                        "target_port": job.target_port,
                        "version": job.version,
                        "operation": "GET",
                        "oid": "1.3.6.1.2.1.1.3.0",
                        "credential": job.credential,
                    },
                    job.user,
                )
                perr = presult.get("error")
            except Exception as exc:
                perr = f"{type(exc).__name__}: {exc}"
            if perr:
                job.status = "failed"
                job.finished_at = time.time()
                job.message = (
                    f"目标 {job.target_host}:{job.target_port} 不可达或 SNMP 无响应"
                    f"（{perr}），任务已终止"
                )
                self.store.update(job)
                self.store.audit_log({
                    "event": "job_failed", "job_id": job.job_id, "user": job.user,
                    "mib_id": job.mib_id, "target": job.target_host,
                    "mode": job.mode, "reason": "unreachable", "error": job.message,
                })
                return

        cfg, model = self._build_config(job, slot)
        # Read-only operation set: GET / GETNEXT / GETBULK (the two SNMP walk
        # primitives).  All three are zero-risk read operations.  Round-robin
        # across operations that actually have matching cases keeps walks from
        # being crowded out by GET, while still honouring the requested limit
        # exactly (v1 has no normal GETBULK cases, so it must not consume a share).
        read_ops = ("GET", "GETNEXT", "GETBULK")
        case_store = self.library.load_cases(job.mib_id)
        pools = {
            op: case_store.select(CaseFilter(
                operations={op},
                categories={"normal"},
                versions={job.version},
                modules=set(job.modules),
                exclude_tags={"auth", "flood", "negative", "guarded", "blocked"},
            ))
            for op in read_ops
        }
        ops = [op for op in read_ops if pools[op]]
        cases: list = []
        taken = {op: 0 for op in ops}
        while True:
            if job.limit and len(cases) >= job.limit:
                break
            progressed = False
            for op in ops:
                if job.limit and len(cases) >= job.limit:
                    break
                if taken[op] < len(pools[op]):
                    cases.append(pools[op][taken[op]])
                    taken[op] += 1
                    progressed = True
            if not progressed:
                break
        if not cases:
            raise ValueError("no read-only GET/GETNEXT/GETBULK cases matched the requested filters")
        job.case_count = len(cases)

        security = SecurityPolicy(
            allow_live=self.policy.allow_live,
            allowed_targets=self.policy.allowed_targets or ((job.target_host,) if job.mode == "live" else ()),
            readonly_only=True,
        )
        run_id = f"web-{job.job_id}"

        _last_flush = [0.0]

        def _on_progress(done: int, total: int, passed: int, failed: int, unsupported: int) -> None:
            job.progress = {
                "done": done, "total": total, "passed": passed,
                "failed": failed, "unsupported": unsupported,
            }
            # Flush progress to the journal periodically: if the process dies
            # mid-run, the last persisted line still shows how far it got.
            now = time.time()
            if done >= total or now - _last_flush[0] >= 10.0:
                _last_flush[0] = now
                self.store.update(job)

        evt = self._cancel.setdefault(job.job_id, asyncio.Event())
        runtime, _ = await run_batch(
            cfg, model, cases,
            run_id=run_id,
            enable_set=False,
            allow_guarded=False,
            security=security,
            on_progress=_on_progress,
            cancel_event=evt,
        )
        cancelled = evt.is_set()
        try:
            write_all(
                runtime.collector,
                cfg=cfg,
                model=model,
                cases=cases,
                policy=load_policy(self.root / "config" / "safety-policy.yaml"),
                extra={"mode": job.mode, "job_id": job.job_id, "user": job.user, "mib_id": job.mib_id},
            )
            summary = runtime.collector.summary()["overall"]
            job.summary = summary
            job.run_id = run_id
            if cancelled:
                job.status = "cancelled"
                job.message = job.message or "任务已被用户中断"
            else:
                job.status = "done"
                job.message = (
                    f"{summary['passed']}/{summary['total']} passed, "
                    f"unsupported {summary['unsupported']}, "
                    f"effective {summary['effective_pass_rate']}%"
                )
        finally:
            runtime.close()

        job.finished_at = time.time()
        self.store.update(job)
        self.store.audit_log({
            "event": "job_finished", "job_id": job.job_id, "user": job.user,
            "mib_id": job.mib_id, "target": job.target_host, "mode": job.mode,
            "run_id": job.run_id, "summary": job.summary,
        })
