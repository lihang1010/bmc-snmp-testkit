"""FastAPI service for multi-user BMC SNMP testing.

Design constraints implemented here:
  * batch jobs stay read-only: only GET/GETNEXT/GETBULK cases are selected;
  * interactive probes (MIB browser) support GET/GETNEXT/WALK/SET, guarded by
    ``security.web`` policy, the safety policy's hard blocks and the audit log;
  * live access is open by default on the intranet and can be tightened through
    ``security.web.allow_live`` / ``allowed_targets`` / ``readonly_only``;
  * credentials are accepted per request and never written to disk;
  * jobs run on a small worker pool (default 2, max 4) with per-target serialisation;
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
from urllib.parse import unquote

import yaml
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, RedirectResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel, Field
from starlette.concurrency import run_in_threadpool

from snmp_test.service.audit import AuditFeed
from snmp_test.service.auth import AuthError, AuthService, Mailer, SESSION_TTL_SECONDS, User
from snmp_test.service.doc_check import DocCheckError, DocCheckService
from snmp_test.service.jobs import JobRunner, JobStore
from snmp_test.service.mibs import MibError, MibLibrary
from snmp_test.service.probe import ProbeError, ProbeService

COOKIE = "snmp_test_session"
RUN_ID_RE = re.compile(r"^[A-Za-z0-9._-]{1,80}$")
MODULE_RE = re.compile(r"^[A-Za-z0-9_-]{1,64}$")
VERSIONS = ("v1", "v2c", "v3")
MAX_LIMIT = 500

ROOT = Path(__file__).resolve().parents[3]
DEFAULT_MAIL_ADMINS = ("lihang@ttyinfo.com",)


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


class ResetRequest(BaseModel):
    email: str
    code: str
    password: str


class MailSettingsRequest(BaseModel):
    host: str = ""
    port: int = 587
    user: str = ""
    password: str = ""
    sender: str = ""
    tls: bool = True
    ssl: bool = False


class LoginRequest(BaseModel):
    email: str
    password: str | None = None
    code: str | None = None
    method: str = "password"


class ProbeRequest(BaseModel):
    mib_id: str | None = None
    mode: str = "mock"
    target_host: str = "127.0.0.1"
    target_port: int = 161
    version: str = "v1"
    credential: dict[str, Any] = Field(default_factory=dict)
    operation: str = "GET"
    oid: str
    value: str | None = None
    asn1: str = "OctetString"
    max_results: int = 50
    cursor: str | None = None


def _web_security(config_path: Path) -> dict[str, Any]:
    if not config_path.is_file():
        return {}
    raw = yaml.safe_load(config_path.read_text(encoding="utf-8")) or {}
    return dict(raw.get("security") or {})


def _mail_settings(config_path: Path) -> dict[str, Any]:
    if not config_path.is_file():
        return {}
    raw = yaml.safe_load(config_path.read_text(encoding="utf-8")) or {}
    return dict(raw.get("mail") or {})


def _mail_admins(config_path: Path) -> tuple[str, ...]:
    """Accounts allowed to view/change mail settings (defaults to one admin)."""
    if not config_path.is_file():
        return DEFAULT_MAIL_ADMINS
    try:
        raw = yaml.safe_load(config_path.read_text(encoding="utf-8")) or {}
    except Exception:
        return DEFAULT_MAIL_ADMINS
    values = raw.get("admin_emails")
    if values is None:
        return DEFAULT_MAIL_ADMINS
    return tuple(str(v).strip().lower() for v in values if str(v).strip())


def _read_yaml(path: Path) -> dict[str, Any]:
    if not path.is_file():
        return {}
    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except (OSError, ValueError):
        return {}
    return dict(raw) if isinstance(raw, dict) else {}


def _mail_override_path(workspace: Path) -> Path:
    return workspace / "work" / "mail.yaml"


def _load_mail_config(workspace: Path, config_path: Path) -> dict[str, Any]:
    merged = _mail_settings(config_path)
    merged.update(_read_yaml(_mail_override_path(workspace)))
    return merged


def _save_mail_config(workspace: Path, updates: dict[str, Any]) -> None:
    path = _mail_override_path(workspace)
    current = _read_yaml(path)
    current.update({key: value for key, value in updates.items() if value is not None})
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        yaml.safe_dump(current, allow_unicode=True, sort_keys=False), encoding="utf-8"
    )
    path.chmod(0o600)


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
    mail_admins = _mail_admins(cfg_path)
    auth = AuthService(
        workspace / "work" / "auth.db",
        mail_settings=_load_mail_config(workspace, cfg_path),
    )
    library = MibLibrary(workspace, workspace / "config" / "safety-policy.yaml")
    store = JobStore(workspace)
    workers = int(os.environ.get("SNMP_TEST_WEB_WORKERS", "2") or 2)
    probe = ProbeService(workspace, cfg_path, library=library, web_security=security_cfg)
    runner = JobRunner(
        workspace, library, store,
        config_path=cfg_path, web_security=security_cfg, workers=workers,
        probe=probe,
    )
    audit_feed = AuditFeed(workspace)
    doc_checks = DocCheckService(workspace, library)
    templates = Jinja2Templates(directory=str(Path(__file__).parent / "templates"))

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        await runner.start()
        yield
        await runner.stop()
        await probe.stop()

    app = FastAPI(
        title="bmc-snmp-testkit · BMC SNMP 测试服务",
        version="1.0",
        description="多用户 · 多 MIB · 批量只读任务 · 交互式探测 · 可追溯报告",
        lifespan=lifespan,
    )
    app.state.auth = auth
    app.state.library = library
    app.state.store = store
    app.state.runner = runner
    app.state.probe = probe
    app.state.doc_checks = doc_checks
    app.state.security = security_cfg
    app.state.workspace = workspace
    app.state.templates = templates

    static_dir = Path(__file__).parent / "static"
    if static_dir.is_dir():
        app.mount("/static", StaticFiles(directory=str(static_dir)), name="static")

    def require(request: Request, action: str = "read") -> User:
        user = auth.authenticate(_token(request))
        if user is None:
            raise HTTPException(401, "未登录：请先登录")
        if not user.can(action):
            raise HTTPException(403, f"当前账号无权执行该操作（需要 {action}）")
        return user

    def require_mail_admin(request: Request) -> User:
        user = require(request)
        if user.email.strip().lower() not in mail_admins:
            raise HTTPException(403, "仅指定账号可访问邮件设置")
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
        return {"status": "ok", "readonly": True, "workers": runner.workers}

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

    @app.post("/api/auth/reset")
    async def auth_reset(payload: ResetRequest):
        try:
            token, user = auth.reset_password(payload.email, payload.code, payload.password)
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

    @app.post("/api/doc-check")
    async def create_doc_check(request: Request):
        user = require(request)
        mib_id = request.headers.get("x-mib-id", "").strip()
        filename = unquote(request.headers.get("x-docx-filename", "document.docx"))
        content = await request.body()
        try:
            report = doc_checks.create(filename, content, mib_id, user.email)
        except DocCheckError as exc:
            raise HTTPException(400, str(exc)) from exc
        store.audit_log({
            "event": "doc_check", "user": user.email, "mib_id": mib_id,
            "filename": report["filename"], "check_id": report["check_id"],
            "summary": report["summary"],
        })
        return {"report": report}

    @app.get("/api/doc-check/{check_id}")
    async def get_doc_check(check_id: str, request: Request):
        user = require(request)
        try:
            return doc_checks.get(check_id, user.email)
        except DocCheckError as exc:
            raise HTTPException(404, str(exc)) from exc

    @app.get("/api/doc-check/{check_id}/fixed.docx")
    async def download_doc_check(check_id: str, request: Request):
        user = require(request)
        try:
            path = doc_checks.fixed_path(check_id, user.email)
        except DocCheckError as exc:
            raise HTTPException(404, str(exc)) from exc
        return FileResponse(
            path,
            filename=f"{path.parent.name}-fixed.docx",
            media_type="application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        )

    @app.post("/api/mail/test")
    async def mail_test(request: Request):
        user = require_mail_admin(request)
        try:
            auth.mailer.send_test(user.email)
        except AuthError as exc:
            raise HTTPException(400, str(exc)) from exc
        return {"sent": True, "to": user.email}

    def mail_status() -> dict[str, Any]:
        mailer = auth.mailer
        return {
            "host": mailer.host,
            "port": mailer.port,
            "user": mailer.username,
            "sender": mailer.sender,
            "tls": mailer.starttls,
            "ssl": mailer.use_ssl,
            "configured": mailer.configured,
            "has_password": bool(mailer.password),
            "env_override": bool(os.environ.get("SNMP_TEST_SMTP_HOST", "").strip()),
        }

    @app.get("/api/mail/settings")
    async def get_mail_settings(request: Request):
        require_mail_admin(request)
        return mail_status()

    @app.put("/api/mail/settings")
    async def put_mail_settings(payload: MailSettingsRequest, request: Request):
        require_mail_admin(request)
        if not (1 <= payload.port <= 65535):
            raise HTTPException(400, "端口必须在 1–65535 之间")
        updates = {
            "host": payload.host.strip(),
            "port": payload.port,
            "user": payload.user.strip(),
            "sender": payload.sender.strip(),
            "tls": payload.tls,
            "ssl": payload.ssl,
        }
        if payload.password:
            updates["password"] = payload.password
        _save_mail_config(workspace, updates)
        auth.mailer = Mailer(_load_mail_config(workspace, cfg_path))
        return mail_status()

    # Kept for the console page's polling code.
    @app.get("/api/session")
    async def get_session(request: Request):
        user = require(request)
        return {"user": user.email, "role": user.role}

    # ------------------------------------------------------------- config
    @app.get("/api/config")
    async def get_config(request: Request):
        user = require(request)
        desc = probe.policy.describe()
        return {
            "user": user.email,
            "readonly_only": True,
            "allowed_operations": ["GET"],
            "live_enabled": bool(desc["allow_live"]),
            "allowed_targets": list(desc["allowed_targets"]),
            "probe_live_set_enabled": bool(desc["live_set_enabled"]),
            "probe_readonly_only": bool(desc["readonly_only"]),
            "probe_hard_block_enabled": bool(desc["hard_block_enabled"]),
            "audit_enabled": True,
            "versions": list(VERSIONS),
            "default_limit": 20,
            "max_limit": MAX_LIMIT,
            "job_timeout_s": runner.timeout_s,
            "job_retries": runner.retries,
            "probe_timeout_s": probe.timeout_s,
            "probe_retries": probe.retries,
            "queue_length": runner.pending(),
            "current_job": runner.current_jobs[0] if runner.current_jobs else None,
            "current_jobs": runner.current_jobs,
            "workers": runner.workers,
            "mib_count": len(library.list()),
            "job_count": len(store.list_for(user.email, 500)),
            "mail_admin": user.email.strip().lower() in mail_admins,
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

    @app.get("/api/mibs/{mib_id}/modules")
    async def get_mib_modules(mib_id: str, request: Request):
        """Top-level modules parsed from the MIB, for the job filter dropdown."""
        require(request)
        try:
            path = library.model_path(mib_id)
        except MibError as exc:
            raise HTTPException(404, str(exc)) from exc
        if not path.is_file():
            raise HTTPException(404, "MIB 不存在")
        try:
            model = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            raise HTTPException(500, f"model.json 读取失败: {exc}") from exc
        nodes = model.get("nodes") or []
        root_oid = str(model.get("root_oid") or "")
        root_name = next((n.get("name") for n in nodes if n.get("oid") == root_oid), "")
        modules = []
        for node in nodes:
            if node.get("parent_name") != root_name or node.get("kind") != "group":
                continue
            oid = str(node.get("oid") or "")
            if not oid:
                continue
            modules.append({
                "name": node.get("name"),
                "oid": oid,
                "node_count": sum(
                    1 for n in nodes
                    if n.get("oid") == oid or str(n.get("oid") or "").startswith(oid + ".")
                ),
            })
        modules.sort(key=lambda m: m["oid"])
        return {"mib_id": mib_id, "root_oid": root_oid, "modules": modules}

    @app.get("/api/mibs/{mib_id}/warnings")
    async def get_mib_warnings(mib_id: str, request: Request):
        """Parse warnings + IMPORTS/strict-syntax info, so skipped nodes are visible."""
        require(request)
        try:
            library.get(mib_id)
            path = library.model_path(mib_id).parent / "parse-warnings.json"
        except MibError as exc:
            raise HTTPException(404, str(exc)) from exc
        if not path.is_file():
            return {"total": 0, "warnings": [], "stats": {}, "parser": {}}
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            raise HTTPException(500, f"parse-warnings.json 读取失败: {exc}") from exc

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

    @app.get("/api/mibs/{mib_id}/tree")
    async def get_tree(mib_id: str, request: Request):
        """Return every node of a MIB in one request for the browser's tree view.

        /nodes is paged (<=200) and aimed at search UIs; a 1000+ node tree would
        otherwise need several round-trips to assemble.  Node fields are trimmed
        to what the tree/table renderer actually consumes.
        """
        require(request)
        try:
            path = library.model_path(mib_id)
        except MibError as exc:
            raise HTTPException(404, str(exc)) from exc
        if not path.is_file():
            raise HTTPException(404, "MIB 不存在")
        try:
            model = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            raise HTTPException(500, f"model.json 读取失败: {exc}") from exc
        keys = ("name", "oid", "kind", "access", "sub_id", "parent_name",
                "table_name", "index_names")
        nodes = []
        for n in model.get("nodes") or []:
            node = {k: n.get(k) for k in keys}
            syn = n.get("syntax") or None
            node["syntax"] = (
                {k: syn.get(k) for k in ("base_type", "enum", "ranges", "size", "raw")}
                if syn else None
            )
            nodes.append(node)
        return {
            "mib_id": mib_id,
            "module_name": model.get("module_name", ""),
            "root_oid": model.get("root_oid", ""),
            "total": len(nodes),
            "nodes": nodes,
            "tables": model.get("tables") or [],
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

    # ------------------------------------------------------------- snmp probe
    @app.get("/api/snmp/capabilities")
    async def probe_caps(request: Request):
        require(request)
        return probe.capabilities()

    @app.get("/api/snmp/audit")
    async def probe_audit(request: Request, limit: int = 50, user: str = "", operation: str = ""):
        require(request)
        return {"entries": probe.audit.recent(limit=limit, user=user, operation=operation)}

    @app.get("/api/audit")
    async def audit_entries(
        request: Request,
        limit: int = 100,
        user: str = "",
        category: str = "",
        event: str = "",
    ):
        require(request)
        entries = audit_feed.entries(limit=limit, user=user, category=category, event=event)
        return {"entries": entries, "total": len(entries)}

    @app.post("/api/snmp/probe")
    async def snmp_probe(payload: ProbeRequest, request: Request):
        user = require(request)
        try:
            return await probe.execute(payload.model_dump(), user.email)
        except ProbeError as exc:
            raise HTTPException(400, str(exc)) from exc
        except Exception as exc:
            raise HTTPException(502, f"SNMP 请求失败: {exc}") from exc

    # ------------------------------------------------------------- jobs
    @app.post("/api/jobs")
    async def create_job(payload: JobRequest, request: Request):
        user = require(request, "write")
        if payload.version not in VERSIONS:
            raise HTTPException(400, f"version must be one of {VERSIONS}")
        if payload.mode not in ("mock", "live"):
            raise HTTPException(400, "mode must be 'mock' or 'live'")
        if not (0 <= payload.limit <= MAX_LIMIT):
            raise HTTPException(400, f"limit must be 0 (full run) or between 1 and {MAX_LIMIT}")
        if not (1 <= payload.target_port <= 65535):
            raise HTTPException(400, "invalid target_port")
        if payload.mode == "live":
            # Reject before the job enters the queue (same policy as interactive probes).
            denied = probe.policy.check("live", "GET", payload.target_host)
            if denied:
                store.audit_log({"event": "job_rejected", "user": user.name,
                                 "target": payload.target_host, "mode": payload.mode,
                                 "reason": "policy_denied", "error": denied})
                raise HTTPException(400, denied)
            # Live targets require complete credentials; mock mode uses built-ins.
            cred = payload.credential or {}
            if payload.version in ("v1", "v2c"):
                if not str(cred.get("community") or "").strip():
                    raise HTTPException(400, "live 模式 v1/v2c 必须填写团体名")
            else:
                if not str(cred.get("v3_user") or "").strip():
                    raise HTTPException(400, "live 模式 v3 必须填写用户名")
                level = str(cred.get("security_level") or "authPriv")
                if level in ("authNoPriv", "authPriv") and not str(cred.get("auth_key") or "").strip():
                    raise HTTPException(400, "当前 v3 安全级别必须填写认证密钥")
                if level == "authPriv" and not str(cred.get("priv_key") or "").strip():
                    raise HTTPException(400, "当前 v3 安全级别必须填写加密密钥")
        for module in payload.modules:
            if not MODULE_RE.match(module):
                raise HTTPException(400, f"invalid module name {module!r}")
        try:
            library.get(payload.mib_id)
        except MibError as exc:
            raise HTTPException(404, str(exc)) from exc
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
        if job.status in ("queued", "waiting", "running"):
            raise HTTPException(409, "任务正在执行或排队，无法删除")
        await run_in_threadpool(store.delete, job_id)
        store.audit_log({"event": "job_deleted", "user": user.email, "job_id": job_id})
        return {"deleted": job_id}

    @app.post("/api/jobs/{job_id}/cancel")
    async def cancel_job(job_id: str, request: Request):
        user = require(request, "write")
        job = store.get(job_id)
        if job is None or job.user != user.email:
            raise HTTPException(404, "job not found")
        if job.status not in ("queued", "waiting", "running"):
            raise HTTPException(409, "任务已结束，无法中断")
        runner.request_cancel(job_id)
        return {"job": job.public_dict()}

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

    @app.get("/audit", response_class=HTMLResponse)
    async def audit_page(request: Request):
        if auth.authenticate(_token(request)) is None:
            return RedirectResponse("/login", status_code=302)
        return templates.TemplateResponse(
            request, "audit.html", {"title": "操作记录 · bmc-snmp-testkit"}
        )

    @app.get("/mib-browser", response_class=HTMLResponse)
    async def mib_browser_page(request: Request):
        if auth.authenticate(_token(request)) is None:
            return RedirectResponse("/login", status_code=302)
        return templates.TemplateResponse(
            request, "mib_browser.html", {"title": "MIB 浏览器 · bmc-snmp-testkit"}
        )

    @app.get("/mail-settings", response_class=HTMLResponse)
    async def mail_settings_page(request: Request):
        user = auth.authenticate(_token(request))
        if user is None:
            return RedirectResponse("/login", status_code=302)
        if user.email.strip().lower() not in mail_admins:
            return HTMLResponse(
                "<h1>403</h1><p>仅指定账号可访问邮件设置。</p>", status_code=403
            )
        return templates.TemplateResponse(
            request, "mail_settings.html", {"title": "邮件设置 · bmc-snmp-testkit"}
        )

    @app.get("/doc-check", response_class=HTMLResponse)
    async def doc_check_page(request: Request):
        if auth.authenticate(_token(request)) is None:
            return RedirectResponse("/login", status_code=302)
        return templates.TemplateResponse(
            request, "doc_check.html", {"title": "文档一致性检查 · bmc-snmp-testkit"}
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
    print(
        f"[snmp-test-web] 监听 http://{args.host}:{args.port}"
        f"（批量任务只读；交互探测可 GET/GETNEXT/WALK/SET，受 security.web 与安全策略约束）",
        flush=True,
    )
    import uvicorn

    uvicorn.run(app, host=args.host, port=args.port, log_level="info")
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
