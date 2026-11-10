"""Serial job runner and persistent job store.

A single worker processes jobs one at a time.  This is required because the
trap receiver and (in mock mode) the simulated agent bind fixed UDP ports, and
because hammering a BMC from many concurrent users is undesirable anyway.
"""

from __future__ import annotations

import asyncio
import json
import time
import traceback
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from snmp_test.config import load_config
from snmp_test.model.types import MibModel
from snmp_test.report.writers import write_all
from snmp_test.runner.case_store import CaseFilter
from snmp_test.runner.executor import make_run_id, run_batch
from snmp_test.runner.safety import load_policy
from snmp_test.security import AccessDenied, SecurityPolicy
from snmp_test.service.mibs import MibLibrary

WEB_MOCK_PORT = 11811
WEB_TRAP_PORT = 11812


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
        }


class JobStore:
    def __init__(self, root: str | Path) -> None:
        self.base = Path(root) / "work" / "jobs"
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
                )
                self._jobs[job.job_id] = job
            except Exception:
                continue
        # Anything that was mid-flight when the process died is reported as failed.
        for job in self._jobs.values():
            if job.status in ("queued", "running"):
                job.status = "failed"
                job.message = "interrupted by service restart"
                job.finished_at = time.time()

    def create(self, **kwargs: Any) -> Job:
        job = Job(job_id=uuid.uuid4().hex[:12], **kwargs)
        self._jobs[job.job_id] = job
        self._append(job)
        return job

    def get(self, job_id: str) -> Job | None:
        return self._jobs.get(job_id)

    def list(self, limit: int = 50) -> list[Job]:
        return sorted(self._jobs.values(), key=lambda j: j.created_at, reverse=True)[:limit]

    def _append(self, job: Job) -> None:
        with self.journal.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(job.public_dict(), ensure_ascii=False, default=str) + "\n")

    def update(self, job: Job) -> None:
        self._append(job)

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
    ) -> None:
        self.root = Path(root)
        self.library = library
        self.store = store
        self.config_path = Path(config_path) if config_path else self.root / "config" / "web.yaml"
        self.web_security = dict(web_security or {})
        self.queue: asyncio.Queue[Job | None] = asyncio.Queue()
        self._task: asyncio.Task | None = None
        self.current: str | None = None

    async def start(self) -> "JobRunner":
        self._task = asyncio.create_task(self._worker(), name="snmp-job-worker")
        return self

    async def stop(self) -> None:
        if self._task is not None:
            await self.queue.put(None)
            try:
                await asyncio.wait_for(self._task, timeout=5)
            except asyncio.TimeoutError:
                self._task.cancel()
            self._task = None

    async def submit(self, job: Job) -> None:
        await self.queue.put(job)

    def pending(self) -> int:
        return self.queue.qsize()

    async def _worker(self) -> None:
        while True:
            job = await self.queue.get()
            if job is None:
                self.queue.task_done()
                break
            self.current = job.job_id
            try:
                await self._execute(job)
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
                self.current = None
                self.queue.task_done()

    def _build_config(self, job: Job):
        model_path = self.library.model_path(job.mib_id)
        mib_path = self.library.mib_path(job.mib_id)
        if job.mode == "mock":
            host, port = "127.0.0.1", WEB_MOCK_PORT
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
                "port": WEB_MOCK_PORT,
                "trap_port": WEB_TRAP_PORT,
                "rows_per_table": 2,
                "communities": {"read_only": "public", "read_write": "private"},
                "v3": v3,
            },
            "trap": {"listen_host": "127.0.0.1", "listen_port": WEB_TRAP_PORT, "receive_timeout_s": 5.0},
            "execution": {
                "concurrency": 4, "timeout_s": 3.0, "retries": 0,
                "rows_per_table": 2, "max_cases_per_table": 8,
                "max_varbinds": 20, "bulk_max_repetitions": 6,
                "allow_guarded": False, "enable_set": False, "limit": 0, "seed": 20261109,
            },
            "security": {
                "allow_live": bool(self.web_security.get("allow_live", False)),
                "allowed_targets": list(self.web_security.get("allowed_targets") or []),
                "readonly_only": True,
            },
            "report": {"output_dir": "runs", "pdu_log_sample_rate": 1.0, "log_level": "INFO"},
            "safety": {"policy_file": str(self.root / "config" / "safety-policy.yaml")},
        }
        cfg = load_config(self.config_path, overrides=overrides)
        model = MibModel.from_dict(json.loads(Path(model_path).read_text(encoding="utf-8")))
        return cfg, model

    async def _execute(self, job: Job) -> None:
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
        if job.mode == "live" and job.target_host not in set(self.web_security.get("allowed_targets") or []):
            raise AccessDenied(f"target {job.target_host!r} is not in security.allowed_targets")

        cfg, model = self._build_config(job)
        cases = self.library.load_cases(job.mib_id).select(
            CaseFilter(
                operations={"GET"},
                categories={"normal"},
                versions={job.version},
                modules=set(job.modules),
                exclude_tags={"auth", "flood", "negative", "guarded", "blocked"},
                limit=job.limit,
            )
        )
        if not cases:
            raise ValueError("no read-only GET cases matched the requested filters")
        job.case_count = len(cases)

        security = SecurityPolicy(
            allow_live=bool(self.web_security.get("allow_live", False)),
            allowed_targets=tuple(self.web_security.get("allowed_targets") or []),
            readonly_only=True,
        )
        run_id = f"web-{job.job_id}"
        runtime, _ = await run_batch(
            cfg, model, cases,
            run_id=run_id,
            enable_set=False,
            allow_guarded=False,
            security=security,
        )
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
            job.status = "done"
            job.message = f"{summary['passed']}/{summary['total']} passed, effective {summary['effective_pass_rate']}%"
        finally:
            runtime.close()

        job.finished_at = time.time()
        self.store.update(job)
        self.store.audit_log({
            "event": "job_finished", "job_id": job.job_id, "user": job.user,
            "mib_id": job.mib_id, "target": job.target_host, "mode": job.mode,
            "run_id": job.run_id, "summary": job.summary,
        })
