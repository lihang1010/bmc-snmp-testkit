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
import json
import os
import re
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

import yaml
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, RedirectResponse, Response
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel, Field
from starlette.concurrency import run_in_threadpool

from snmp_test.service.auth import AuthError, AuthService, SESSION_TTL_SECONDS, User
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


class CodeRequest(BaseModel):
    email: str
    purpose: str = "login"


class RegisterRequest(BaseModel):
    email: str
    code: str
    password: str


class LoginRequest(BaseModel):
    email: str
    password: str | None = None
    code: str | None = None
    method: str = "password"


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
    auth = AuthService(workspace / "work" / "auth.db")
    library = MibLibrary(workspace, workspace / "config" / "safety-policy.yaml")
    store = JobStore(workspace)
    runner = JobRunner(workspace, library, store, config_path=cfg_path, web_security=security_cfg)
    templates = Jinja2Templates(directory=str(Path(__file__).parent / "templates"))

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        await runner.start()
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
            raise HTTPException(401, "未登录：请先登录")
        if not user.can(action):
            raise HTTPException(403, f"当前账号无权执行该操作（需要 {action}）")
        return user

    def find_run(run_id: str, user: User):
        if not RUN_ID_RE.match(run_id):
            raise HTTPException(400, "invalid run_id")
        for job in store.list_for(user.email, 500):
            if job.run_id == run_id:
                return job
        raise HTTPException(404, "run not found")

    def set_session(response: Response, token: str) -> None:
        response.set_cookie(COOKIE, token, httponly=True, samesite="lax", max_age=SESSION_TTL_SECONDS)

    # ------------------------------------------------------------- auth
    @app.get("/health")
    async def health():
        return {"status": "ok", "readonly": True, "workers": 1}

    @app.post("/api/auth/code")
    async def auth_send_code(payload: CodeRequest):
        try:
            return auth.send_code(payload.email, payload.purpose)
        except AuthError as exc:
            raise HTTPException(400, str(exc)) from exc

    @app.post("/api/auth/register")
    async def auth_register(payload: RegisterRequest):
        try:
            token, user = auth.register(payload.email, payload.code, payload.password)
        except AuthError as exc:
            raise HTTPException(400, str(exc)) from exc
        response = JSONResponse({"user": user.email})
        set_session(response, token)
        return response

    @app.post("/api/auth/login")
    async def auth_login(payload: LoginRequest):
        try:
            if payload.method == "code":
                token, user = auth.login_code(payload.email, payload.code or "")
            else:
                token, user = auth.login_password(payload.email, payload.password or "")
        except AuthError as exc:
            raise HTTPException(401, str(exc)) from exc
        response = JSONResponse({"user": user.email})
        set_session(response, token)
        return response

    @app.post("/api/auth/logout")
    async def auth_logout(request: Request):
        auth.logout(_token(request))
        response = JSONResponse({"logged_out": True})
        response.delete_cookie(COOKIE)
        return response

    @app.get("/api/auth/me")
    async def auth_me(request: Request):
        user = require(request)
        return {"user": user.email, "email": user.email, "role": user.role}

    # Kept for the console page's polling code.
    @app.get("/api/session")
    async def get_session(request: Request):
        user = require(request)
        return {"user": user.email, "role": user.role}

    # ------------------------------------------------------------- config
    @app.get("/api/config")
    async def get_config(request: Request):
        user = require(request)
        return {
            "user": user.email,
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
            "job_count": len(store.list_for(user.email, 500)),
        }

    # ------------------------------------------------------------- mibs
    @app.post("/api/mibs")
    async def upload_mib(request: Request):
        user = require(request, "write")
        filename = request.headers.get("x-mib-filename", "upload.mib")
        content = await request.body()
        try:
            record = await run_in_threadpool(
                library.add, filename, content, uploaded_by=user.email
            )
        except MibError as exc:
            raise HTTPException(400, str(exc)) from exc
        except Exception as exc:
            raise HTTPException(422, f"MIB 解析失败: {exc}") from exc
        store.audit_log({"event": "mib_upload", "user": user.email, "mib_id": record.mib_id,
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

    @app.get("/api/mibs/{mib_id}/nodes")
    async def get_nodes(
        mib_id: str,
        request: Request,
        q: str = "",
        kind: str = "",
        access: str = "",
        limit: int = 50,
        offset: int = 0,
    ):
        require(request)
        try:
            model = json.loads(library.model_path(mib_id).read_text(encoding="utf-8"))
        except MibError as exc:
            raise HTTPException(404, str(exc)) from exc
        except (OSError, ValueError) as exc:
            raise HTTPException(500, f"model.json 读取失败: {exc}") from exc
        needle = q.strip().lower()
        matched = [
            node
            for node in (model.get("nodes") or [])
            if (not kind or node.get("kind") == kind)
            and (not access or node.get("access") == access)
            and (
                not needle
                or needle in str(node.get("name", "")).lower()
                or needle in str(node.get("oid", ""))
            )
        ]
        limit = max(1, min(limit, 200))
        offset = max(0, offset)
        return {
            "total": len(matched),
            "offset": offset,
            "limit": limit,
            "nodes": matched[offset: offset + limit],
        }

    @app.get("/api/mibs/{mib_id}/cases")
    async def get_cases(
        mib_id: str,
        request: Request,
        q: str = "",
        operation: str = "",
        category: str = "",
        module: str = "",
        limit: int = 50,
        offset: int = 0,
    ):
        require(request)
        try:
            cases = library.load_cases(mib_id).cases
        except MibError as exc:
            raise HTTPException(404, str(exc)) from exc
        needle = q.strip().lower()
        matched = [
            case
            for case in cases
            if (not operation or case.operation == operation)
            and (not category or case.category == category)
            and (not module or case.module == module)
            and (
                not needle
                or needle in str(case.name).lower()
                or needle in str(case.oid)
                or needle in str(case.case_id).lower()
            )
        ]
        limit = max(1, min(limit, 200))
        offset = max(0, offset)
        return {
            "total": len(matched),
            "offset": offset,
            "limit": limit,
            "cases": [case.to_dict() for case in matched[offset: offset + limit]],
        }

    @app.delete("/api/mibs/{mib_id}")
    async def delete_mib(mib_id: str, request: Request):
        user = require(request, "write")
        try:
            record = library.get(mib_id)
        except MibError as exc:
            raise HTTPException(404, str(exc)) from exc
        await run_in_threadpool(library.delete, mib_id)
        store.audit_log({
            "event": "mib_deleted",
            "user": user.email,
            "mib_id": mib_id,
            "filename": record.filename,
        })
        return {"deleted": mib_id}

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
        user = require(request)
        return {"jobs": [j.public_dict() for j in store.list_for(user.email, min(limit, 200))]}

    @app.get("/api/jobs/{job_id}")
    async def get_job(job_id: str, request: Request):
        user = require(request)
        job = store.get(job_id)
        if job is None or job.user != user.email:
            raise HTTPException(404, "job not found")
        return job.public_dict()

    @app.delete("/api/jobs/{job_id}")
    async def delete_job(job_id: str, request: Request):
        user = require(request, "write")
        job = store.get(job_id)
        if job is None or job.user != user.email:
            raise HTTPException(404, "job not found")
        if job.status in ("queued", "running"):
            raise HTTPException(409, "任务正在执行，无法删除")
        await run_in_threadpool(store.delete, job_id)
        store.audit_log({"event": "job_deleted", "user": user.email, "job_id": job_id})
        return {"deleted": job_id}

    # ------------------------------------------------------------- reports
    @app.get("/runs/{run_id}/report.html")
    async def report_html(run_id: str, request: Request):
        user = require(request)
        find_run(run_id, user)
        path = workspace / "runs" / run_id / "report.html"
        if not path.is_file():
            raise HTTPException(404, "report not generated yet")
        return FileResponse(path, media_type="text/html")

    @app.get("/runs/{run_id}/results.json")
    async def report_json(run_id: str, request: Request):
        user = require(request)
        find_run(run_id, user)
        path = workspace / "runs" / run_id / "results.json"
        if not path.is_file():
            raise HTTPException(404, "results not generated yet")
        return FileResponse(path, media_type="application/json")

    @app.get("/api/runs/{run_id}/files")
    async def run_files(run_id: str, request: Request):
        user = require(request)
        find_run(run_id, user)
        folder = workspace / "runs" / run_id
        return {"files": sorted(p.name for p in folder.iterdir() if p.is_file())}

    # ------------------------------------------------------------- ui
    @app.get("/login", response_class=HTMLResponse)
    async def login_page(request: Request):
        if auth.authenticate(_token(request)) is not None:
            return RedirectResponse("/", status_code=302)
        return templates.TemplateResponse(
            request, "login.html", {"title": "登录 · bmc-snmp-testkit"}
        )

    @app.get("/", response_class=HTMLResponse)
    async def index(request: Request):
        if auth.authenticate(_token(request)) is None:
            return RedirectResponse("/login", status_code=302)
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
    if os.environ.get("SNMP_TEST_DEV_BYPASS", "").strip().lower() in ("1", "true", "yes", "on"):
        print("[snmp-test-web] 开发旁路已启用：跳过登录（仅本地调试）", flush=True)
    if not os.environ.get("SNMP_TEST_SMTP_HOST", "").strip():
        print("[snmp-test-web] 未配置 SMTP：验证码写入 work/mail-dev.log 并显示在登录页", flush=True)
    print(f"[snmp-test-web] 监听 http://{args.host}:{args.port}（只读服务，SET 已禁用）", flush=True)
    import uvicorn

    uvicorn.run(app, host=args.host, port=args.port, log_level="info")
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
