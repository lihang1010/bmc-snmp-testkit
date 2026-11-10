"""Read-only FastAPI service for multi-user BMC SNMP testing.

Design constraints implemented here:
  * read-only by default: SET / guarded operations are never reachable via API;
  * live access is gated by admin role AND server-side target allowlist;
  * credentials are accepted per request and never written to disk;
  * jobs are executed by a single serial worker (fixed UDP ports, BMC safety);
  * each uploaded MIB gets its own content-addressed model and case repository.
"""

from __future__ import annotations

import argparse
import os
import re
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

import yaml
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, Response
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel, Field
from starlette.concurrency import run_in_threadpool

from snmp_test.security import AuthStore, User
from snmp_test.service.jobs import JobRunner, JobStore
from snmp_test.service.mibs import MibError, MibLibrary

COOKIE = "snmp_test_session"
RUN_ID_RE = re.compile(r"^[A-Za-z0-9._-]{1,80}$")
MODULE_RE = re.compile(r"^[A-Za-z0-9_-]{1,64}$")
VERSIONS = ("v1", "v2c", "v3")
MAX_LIMIT = 500

ROOT = Path(__file__).resolve().parents[3]


class JobRequest(BaseModel):
    mib_id: str = Field(min_length=16, max_length=16)
    mode: str = "mock"
    target_host: str = "127.0.0.1"
    target_port: int = 161
    version: str = "v1"
    modules: list[str] = Field(default_factory=list)
    limit: int = 20
    credential: dict[str, Any] = Field(default_factory=dict)


def _web_security(config_path: Path) -> dict[str, Any]:
    if not config_path.is_file():
        return {}
    raw = yaml.safe_load(config_path.read_text(encoding="utf-8")) or {}
    return dict(raw.get("security") or {})


def _token(request: Request) -> str | None:
    header = request.headers.get("authorization", "")
    if header.lower().startswith("bearer "):
        return header[7:].strip()
    return request.cookies.get(COOKIE)


def create_app(
    *,
    root: str | Path | None = None,
    config_path: str | Path | None = None,
) -> FastAPI:
    workspace = Path(root) if root else ROOT
    cfg_path = Path(config_path) if config_path else workspace / "config" / "web.yaml"
    security_cfg = _web_security(cfg_path)
    auth = AuthStore.load(cfg_path)
    library = MibLibrary(workspace, workspace / "config" / "safety-policy.yaml")
    store = JobStore(workspace)
    runner = JobRunner(workspace, library, store, config_path=cfg_path, web_security=security_cfg)
    templates = Jinja2Templates(directory=str(Path(__file__).parent / "templates"))

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        await runner.start()
        app.state.dev_token = auth.dev_token
        yield
        await runner.stop()

    app = FastAPI(
        title="bmc-snmp-testkit · 只读测试服务",
        version="1.0",
        description="多用户 · 多 MIB · 只读 GET · 串行任务 · 可追溯报告",
        lifespan=lifespan,
    )
    app.state.auth = auth
    app.state.library = library
    app.state.store = store
    app.state.runner = runner
    app.state.security = security_cfg
    app.state.workspace = workspace
    app.state.templates = templates

    def require(request: Request, action: str = "read") -> User:
        user = auth.authenticate(_token(request))
        if user is None:
            raise HTTPException(401, "未认证：请提供 Bearer token 或先建立会话")
        if not user.can(action):
            raise HTTPException(403, f"角色 {user.role!r} 无权执行此操作（需要 {action}）")
        return user

    def find_run(run_id: str):
        if not RUN_ID_RE.match(run_id):
            raise HTTPException(400, "invalid run_id")
        for job in store.list(500):
            if job.run_id == run_id:
                return job
        raise HTTPException(404, "run not found")

    # ------------------------------------------------------------- session
    @app.get("/health")
    async def health():
        return {"status": "ok", "readonly": True, "workers": 1}

    @app.post("/api/session")
    async def create_session(request: Request):
        body = await request.json()
        user = auth.authenticate(str(body.get("token") or ""))
        if user is None:
            raise HTTPException(401, "invalid token")
        response = JSONResponse({"user": user.name, "role": user.role})
        response.set_cookie(COOKIE, user.token, httponly=True, samesite="lax")
        return response

    @app.get("/api/session")
    async def get_session(request: Request):
        user = require(request)
        return {"user": user.name, "role": user.role}

    @app.delete("/api/session")
    async def delete_session():
        response = JSONResponse({"logged_out": True})
        response.delete_cookie(COOKIE)
        return response

    # ------------------------------------------------------------- config
    @app.get("/api/config")
    async def get_config(request: Request):
        require(request)
        return {
            "readonly_only": True,
            "allowed_operations": ["GET"],
            "live_enabled": bool(security_cfg.get("allow_live", False)),
            "allowed_targets": list(security_cfg.get("allowed_targets") or []),
            "versions": list(VERSIONS),
            "default_limit": 20,
            "max_limit": MAX_LIMIT,
            "queue_length": runner.pending(),
            "current_job": runner.current,
            "mib_count": len(library.list()),
            "job_count": len(store.list(500)),
        }

    # ------------------------------------------------------------- mibs
    @app.post("/api/mibs")
    async def upload_mib(request: Request):
        user = require(request, "write")
        filename = request.headers.get("x-mib-filename", "upload.mib")
        content = await request.body()
        try:
            record = await run_in_threadpool(
                library.add, filename, content, uploaded_by=user.name
            )
        except MibError as exc:
            raise HTTPException(400, str(exc)) from exc
        except Exception as exc:
            raise HTTPException(422, f"MIB 解析失败: {exc}") from exc
        store.audit_log({"event": "mib_upload", "user": user.name, "mib_id": record.mib_id,
                         "filename": record.filename, "sha256": record.sha256})
        return {"mib": record.to_dict(), "cases_path": f"/api/mibs/{record.mib_id}/cases"}

    @app.get("/api/mibs")
    async def list_mibs(request: Request):
        require(request)
        return {"mibs": [r.to_dict() for r in library.list()]}

    @app.get("/api/mibs/{mib_id}")
    async def get_mib(mib_id: str, request: Request):
        require(request)
        try:
            return library.get(mib_id).to_dict()
        except MibError as exc:
            raise HTTPException(404, str(exc)) from exc

    @app.get("/api/mibs/{mib_id}/cases")
    async def get_cases(mib_id: str, request: Request, limit: int = 20):
        require(request)
        try:
            cases = library.load_cases(mib_id).cases
        except MibError as exc:
            raise HTTPException(404, str(exc)) from exc
        return {
            "total": len(cases),
            "sample": [c.to_dict() for c in cases[: max(1, min(limit, 100))]],
        }

    # ------------------------------------------------------------- jobs
    @app.post("/api/jobs")
    async def create_job(payload: JobRequest, request: Request):
        user = require(request, "write")
        if payload.version not in VERSIONS:
            raise HTTPException(400, f"version must be one of {VERSIONS}")
        if payload.mode not in ("mock", "live"):
            raise HTTPException(400, "mode must be 'mock' or 'live'")
        if not (1 <= payload.limit <= MAX_LIMIT):
            raise HTTPException(400, f"limit must be between 1 and {MAX_LIMIT}")
        if not (1 <= payload.target_port <= 65535):
            raise HTTPException(400, "invalid target_port")
        for module in payload.modules:
            if not MODULE_RE.match(module):
                raise HTTPException(400, f"invalid module name {module!r}")
        try:
            library.get(payload.mib_id)
        except MibError as exc:
            raise HTTPException(404, str(exc)) from exc
        if payload.mode == "live":
            if not user.can("live"):
                raise HTTPException(403, "live 模式需要 admin 角色")
            if not security_cfg.get("allow_live"):
                raise HTTPException(403, "服务端未开启 security.allow_live")
            allowed = set(security_cfg.get("allowed_targets") or [])
            if payload.target_host not in allowed:
                raise HTTPException(403, "目标不在 security.allowed_targets 白名单内")

        job = store.create(
            user=user.name,
            mib_id=payload.mib_id,
            target_host=payload.target_host,
            target_port=payload.target_port,
            version=payload.version,
            mode=payload.mode,
            modules=tuple(payload.modules),
            limit=payload.limit,
            credential=dict(payload.credential),  # memory only, never persisted
        )
        await runner.submit(job)
        store.audit_log({"event": "job_submitted", "job_id": job.job_id, "user": user.name,
                         "mib_id": job.mib_id, "target": job.target_host, "mode": job.mode,
                         "version": job.version, "limit": job.limit})
        return {"job": job.public_dict()}

    @app.get("/api/jobs")
    async def list_jobs(request: Request, limit: int = 50):
        require(request)
        return {"jobs": [j.public_dict() for j in store.list(min(limit, 200))]}

    @app.get("/api/jobs/{job_id}")
    async def get_job(job_id: str, request: Request):
        require(request)
        job = store.get(job_id)
        if job is None:
            raise HTTPException(404, "job not found")
        return job.public_dict()

    # ------------------------------------------------------------- reports
    @app.get("/runs/{run_id}/report.html")
    async def report_html(run_id: str, request: Request):
        require(request)
        find_run(run_id)
        path = workspace / "runs" / run_id / "report.html"
        if not path.is_file():
            raise HTTPException(404, "report not generated yet")
        return FileResponse(path, media_type="text/html")

    @app.get("/runs/{run_id}/results.json")
    async def report_json(run_id: str, request: Request):
        require(request)
        find_run(run_id)
        path = workspace / "runs" / run_id / "results.json"
        if not path.is_file():
            raise HTTPException(404, "results not generated yet")
        return FileResponse(path, media_type="application/json")

    @app.get("/api/runs/{run_id}/files")
    async def run_files(run_id: str, request: Request):
        require(request)
        find_run(run_id)
        folder = workspace / "runs" / run_id
        return {"files": sorted(p.name for p in folder.iterdir() if p.is_file())}

    # ------------------------------------------------------------- ui
    @app.get("/", response_class=HTMLResponse)
    async def index(request: Request):
        return templates.TemplateResponse(
            request, "index.html", {"title": "bmc-snmp-testkit · 只读测试服务"}
        )

    @app.get("/favicon.ico")
    async def favicon():
        return Response(status_code=204)

    return app


app = create_app()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="snmp-test-web", description="bmc-snmp-testkit 只读 Web 服务")
    parser.add_argument("--host", default=os.environ.get("SNMP_TEST_WEB_HOST", "127.0.0.1"))
    parser.add_argument("--port", type=int, default=int(os.environ.get("SNMP_TEST_WEB_PORT", "8080")))
    parser.add_argument("--root", default=None, help="工作区根目录（默认当前项目）")
    parser.add_argument("--config", default=None, help="config/web.yaml 路径")
    args = parser.parse_args(argv)

    if args.root or args.config:
        global app
        app = create_app(root=args.root, config_path=args.config)
    token = AuthStore.load(Path(args.config) if args.config else ROOT / "config" / "web.yaml").dev_token
    if token:
        print(f"[snmp-test-web] 开发模式临时 admin token: {token}", flush=True)
    print(f"[snmp-test-web] 监听 http://{args.host}:{args.port}（只读服务，SET 已禁用）", flush=True)
    import uvicorn

    uvicorn.run(app, host=args.host, port=args.port, log_level="info")
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
