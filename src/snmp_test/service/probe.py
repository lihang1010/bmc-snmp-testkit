"""One-shot SNMP probe for the Web console (GET / GETNEXT / WALK / SET).

Deliberately outside the job queue: no run directory, no report, no case
assertions.  One long-lived mock agent on a dedicated port pair serves every
mock probe, so it never races with the job workers' ports (11811 + slot*10).

This is an intranet service: live targets are reachable without an allowlist.
Instead of preventive gates, every probe (including SET values) is recorded in
``work/probe-audit.jsonl`` so any action can be traced back to an account.
Credentials are never written to the audit trail; the UI still asks for a
confirmation before SET to avoid mis-clicks.
"""

from __future__ import annotations

import asyncio
import json
import os
import re
import threading
import time
from pathlib import Path
from typing import Any

from snmp_test.config import load_config
from snmp_test.model.types import MibModel
from snmp_test.snmp.mock_agent import MockAgent
from snmp_test.snmp.transport import SnmpSession
from snmp_test.service.mibs import MibLibrary

PROBE_MOCK_PORT = 11911
PROBE_TRAP_PORT = 11912
MAX_WALK = 200

OID_RE = re.compile(r"^\.?[0-9]+(\.[0-9]+)+$")
ASN1_TYPES = ("Integer32", "OctetString", "IpAddress", "ObjectIdentifier", "TimeTicks", "Null")
OPERATIONS = ("GET", "GETNEXT", "WALK", "SET")


class ProbeError(ValueError):
    """Validation failure whose message is safe to show to users."""


class ProbeAudit:
    """Append-only JSONL audit trail for interactive SNMP operations."""

    def __init__(self, root: str | Path) -> None:
        self.path = Path(root) / "work" / "probe-audit.jsonl"
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()

    def record(self, entry: dict[str, Any]) -> None:
        line = json.dumps({"ts": time.time(), **entry}, ensure_ascii=False, default=str)
        with self._lock, self.path.open("a", encoding="utf-8") as fh:
            fh.write(line + "\n")

    def recent(self, limit: int = 50, user: str = "", operation: str = "") -> list[dict[str, Any]]:
        if not self.path.is_file():
            return []
        with self._lock:
            lines = self.path.read_text(encoding="utf-8").splitlines()
        wanted = max(1, min(int(limit), 500))
        rows: list[dict[str, Any]] = []
        for line in reversed(lines):
            try:
                row = json.loads(line)
            except Exception:
                continue
            if user and row.get("user") != user:
                continue
            if operation and row.get("operation") != operation:
                continue
            rows.append(row)
            if len(rows) >= wanted:
                break
        return rows


class ProbeService:
    def __init__(
        self,
        root: str | Path,
        config_path: str | Path,
        *,
        library: MibLibrary | None = None,
        web_security: dict[str, Any] | None = None,
    ) -> None:
        self.root = Path(root)
        self.config_path = Path(config_path)
        self.library = library
        # Overridable so several local instances (or pytest) can run side by side.
        self.mock_port = int(os.environ.get("SNMP_TEST_PROBE_MOCK_PORT", PROBE_MOCK_PORT))
        self.trap_port = int(os.environ.get("SNMP_TEST_PROBE_TRAP_PORT", PROBE_TRAP_PORT))
        self.audit = ProbeAudit(self.root)
        self._agent: MockAgent | None = None
        self._agent_lock = asyncio.Lock()

    # ------------------------------------------------------------- policy
    def capabilities(self) -> dict[str, Any]:
        return {
            "operations": list(OPERATIONS),
            "mock_set": True,
            "live_set": True,
            "allow_live": True,
            "allowed_targets": [],
            "set_enabled": True,
            "audit_enabled": True,
            "audit_path": "work/probe-audit.jsonl",
            "max_walk": MAX_WALK,
            "mock_port": self.mock_port,
            "asn1_types": list(ASN1_TYPES),
        }

    async def stop(self) -> None:
        async with self._agent_lock:
            if self._agent is not None:
                await self._agent.stop()
                self._agent = None

    # ------------------------------------------------------------- config
    def _model_and_mib(self) -> tuple[MibModel, Path]:
        records = self.library.list() if self.library else []
        if records:
            model_path = self.library.model_path(records[0].mib_id)
            mib_path = self.library.mib_path(records[0].mib_id)
        else:
            model_path = self.root / "cases" / "generated" / "model.json"
            mib_path = self.root / "TTY-T1ZDG-v1.0_20261026.mib"
        if model_path.is_file():
            return MibModel.from_dict(json.loads(model_path.read_text(encoding="utf-8"))), mib_path
        return MibModel.from_dict({
            "module_name": "probe", "mib_path": str(mib_path), "mib_sha256": "",
            "root_oid": "1.3.6.1", "nodes": [], "tables": [],
            "sequence_types": [], "stats": {}, "warnings": [],
        }), mib_path

    def _overrides(self, req: dict[str, Any], mib_path: Path) -> tuple[dict[str, Any], dict[str, Any], str]:
        mode = str(req.get("mode") or "mock").lower()
        version = str(req.get("version") or "v1").lower()
        cred = dict(req.get("credential") or {})
        default_community = "private" if mode == "mock" else "public"
        community = str(cred.get("community") or default_community)
        v3 = {
            "user": str(cred.get("v3_user") or "bmcuser"),
            "auth_protocol": str(cred.get("auth_protocol") or "SHA"),
            "auth_key": str(cred.get("auth_key") or "authpass123"),
            "priv_protocol": str(cred.get("priv_protocol") or "AES128"),
            "priv_key": str(cred.get("priv_key") or "privpass123"),
            "security_level": str(cred.get("security_level") or "authPriv"),
        }
        host = "127.0.0.1" if mode == "mock" else str(req.get("target_host") or "127.0.0.1")
        port = self.mock_port if mode == "mock" else int(req.get("target_port") or 161)
        overrides: dict[str, Any] = {
            "mode": mode,
            "mib": str(mib_path),
            "targets": [{
                "name": "probe", "enabled": True, "host": host, "port": port,
                "versions": [version],
                "v1": {"community": community, "read_only_community": community},
                "v2c": {"community": community, "read_only_community": community},
                "v3": v3,
            }],
            "mock": {
                "bind_host": "127.0.0.1", "port": self.mock_port,
                "trap_port": self.trap_port, "rows_per_table": 2,
                "communities": {"read_only": "public", "read_write": "private"},
                "v3": v3,
            },
            "trap": {"listen_host": "127.0.0.1", "listen_port": self.trap_port,
                     "receive_timeout_s": 5.0},
            "execution": {"concurrency": 1, "timeout_s": 2.0, "retries": 0,
                          "enable_set": True, "limit": 0},
            "security": {
                "allow_live": True,
                "allowed_targets": [host] if mode == "live" else [],
                "readonly_only": False,
            },
            "report": {"output_dir": "runs"},
            "safety": {"policy_file": str(self.root / "config" / "safety-policy.yaml")},
        }
        return overrides, cred, version

    async def _ensure_agent(self, overrides: dict[str, Any]) -> None:
        async with self._agent_lock:
            if self._agent is not None:
                return
            model, _ = self._model_and_mib()
            agent_overrides = dict(overrides)
            agent_overrides["mode"] = "mock"
            cfg = load_config(self.config_path, overrides=agent_overrides)
            agent = MockAgent(model, cfg)
            await agent.start()
            self._agent = agent

    # ------------------------------------------------------------- execute
    async def execute(self, req: dict[str, Any], user: str) -> dict[str, Any]:
        mode = str(req.get("mode") or "mock").lower()
        operation = str(req.get("operation") or "GET").upper()
        oid = str(req.get("oid") or "").strip()
        cursor = str(req.get("cursor") or "").strip()
        version = str(req.get("version") or "v1").lower()

        if mode not in ("mock", "live"):
            raise ProbeError(f"不支持的模式 {mode!r}")
        if operation not in OPERATIONS:
            raise ProbeError(f"不支持的操作 {operation!r}")
        if not OID_RE.match(oid):
            raise ProbeError("OID 格式不正确，应形如 1.3.6.1.4.1.52305.6.1")
        if version not in ("v1", "v2c", "v3"):
            raise ProbeError(f"不支持的 SNMP 版本 {version!r}")
        if cursor:
            if operation != "WALK":
                raise ProbeError("cursor 仅用于 WALK 续页")
            if not OID_RE.match(cursor):
                raise ProbeError("cursor OID 格式不正确")
            if not cursor.lstrip(".").startswith(oid.lstrip(".") + "."):
                raise ProbeError("cursor 不在所请求的 OID 子树内")

        host = str(req.get("target_host") or "127.0.0.1")

        asn1 = str(req.get("asn1") or "OctetString")
        value = req.get("value")
        if operation == "SET":
            if value is None or str(value) == "":
                raise ProbeError("SET 需要填写值")
            if asn1 not in ASN1_TYPES:
                raise ProbeError(f"不支持的值类型 {asn1!r}")
            if asn1 == "Integer32":
                try:
                    int(value)
                except (TypeError, ValueError) as exc:
                    raise ProbeError("Integer32 需要整数值") from exc

        _model, mib_path = self._model_and_mib()
        overrides, cred, version = self._overrides(req, mib_path)
        if mode == "mock":
            await self._ensure_agent(overrides)
        cfg = load_config(self.config_path, overrides=overrides)
        target = cfg.targets[0]
        session = SnmpSession(cfg, target, version, override=cred)

        started = time.perf_counter()
        varbinds: list[Any] = []
        error = ""
        truncated = False
        try:
            await session.open()
            if operation == "WALK":
                limit = max(1, min(int(req.get("max_results") or 50), MAX_WALK))
                prefix = oid.lstrip(".")
                # ``oid`` stays the subtree root; ``cursor`` (when present) is
                # the last OID of the previous page, so GETNEXT resumes exactly
                # where it stopped instead of treating the last OID as a new root.
                walk_cursor = cursor or oid
                for _ in range(limit):
                    step = await session.get_next([walk_cursor])
                    if step.error_indication or step.error_status not in ("noError", "0"):
                        error = str(step.error_indication or step.error_status)
                        break
                    usable = [vb for vb in step.varbinds if vb.exception is None]
                    if not usable:
                        break
                    vb = usable[0]
                    if not str(vb.oid).startswith(prefix + "."):
                        break
                    varbinds.append(vb)
                    walk_cursor = str(vb.oid)
                truncated = len(varbinds) >= limit
            else:
                if operation == "GET":
                    response = await session.get([oid])
                elif operation == "GETNEXT":
                    response = await session.get_next([oid])
                else:
                    response = await session.set([{"oid": oid, "asn1": asn1, "value": value}])
                varbinds = list(response.varbinds)
                if response.error_indication or response.error_status not in ("noError", "0"):
                    error = str(response.error_indication or response.error_status)
        finally:
            await session.close()

        result = {
            "ok": not error,
            "operation": operation,
            "oid": oid,
            "mode": mode,
            "version": version,
            "target": f"127.0.0.1:{self.mock_port}" if mode == "mock" else f"{host}:{req.get('target_port') or 161}",
            "user": user,
            "error": error or None,
            "varbinds": [vb.to_dict() for vb in varbinds],
            "count": len(varbinds),
            "truncated": truncated,
            "next_cursor": str(varbinds[-1].oid) if truncated and varbinds else None,
            "elapsed_ms": round((time.perf_counter() - started) * 1000, 2),
        }
        self.audit.record({
            "user": user,
            "mode": mode,
            "target": result["target"],
            "version": version,
            "operation": operation,
            "oid": oid,
            "cursor": cursor or None,
            "value": str(value) if operation == "SET" else None,
            "asn1": asn1 if operation == "SET" else None,
            "ok": result["ok"],
            "error": result["error"],
            "count": result["count"],
            "elapsed_ms": result["elapsed_ms"],
        })
        return result
