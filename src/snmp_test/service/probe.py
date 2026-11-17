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
from collections import OrderedDict
from pathlib import Path
from typing import Any

import yaml

from snmp_test.config import load_config
from snmp_test.model.types import MibModel
from snmp_test.runner.safety import classify_node, load_policy
from snmp_test.snmp.mock_agent import MockAgent
from snmp_test.snmp.transport import SnmpSession
from snmp_test.service.mibs import MibError, MibLibrary
from snmp_test.service.web_policy import WebPolicy

PROBE_MOCK_PORT = 11911
PROBE_TRAP_PORT = 11912
MAX_WALK = 200

OID_RE = re.compile(r"^\.?[0-9]+(\.[0-9]+)+$")
ASN1_TYPES = ("Integer32", "OctetString", "IpAddress", "ObjectIdentifier", "TimeTicks", "Null")
OPERATIONS = ("GET", "GETNEXT", "WALK", "SET")


def _oid_key(oid: str) -> tuple[int, ...]:
    try:
        return tuple(int(part) for part in oid.strip(".").split("."))
    except ValueError:
        return ()


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
        self.policy = WebPolicy.from_security(web_security)
        self._agent: MockAgent | None = None
        self._agent_mib_id: str | None = None
        self._agent_lock = asyncio.Lock()
        # Mock probes share one UDP port, so switching MIBs must not restart the
        # agent while another mock request is still using it.
        self._mock_lock = asyncio.Lock()
        probe_cfg = self._probe_settings()
        self.concurrency = max(1, int(probe_cfg.get("concurrency", 4)))
        # A small gap keeps long v1 GETNEXT walks from overwhelming BMC agents,
        # which otherwise drop the occasional request mid-walk.
        self.rate_limit_ms = max(0.0, float(probe_cfg.get("rate_limit_ms", 20)))
        self.timeout_s = max(0.1, float(probe_cfg.get("timeout_s", 5.0)))
        # BMC SNMP stacks occasionally drop a single packet during long walks;
        # one retransmission is cheap compared with losing the whole walk.
        self.retries = max(0, int(probe_cfg.get("retries", 1)))
        self.session_ttl = max(1.0, float(probe_cfg.get("session_ttl_s", 300)))
        self.session_cache_size = max(1, int(probe_cfg.get("session_cache_size", 16)))
        self._live_sem = asyncio.Semaphore(self.concurrency)
        self._sessions: OrderedDict[tuple[Any, ...], tuple[SnmpSession, float]] = OrderedDict()
        self._session_lock = asyncio.Lock()
        self._next_request_at: dict[str, float] = {}
        self._throttle_lock = asyncio.Lock()

    def _probe_settings(self) -> dict[str, Any]:
        if not self.config_path.is_file():
            return {}
        try:
            raw = yaml.safe_load(self.config_path.read_text(encoding="utf-8")) or {}
        except Exception:
            return {}
        return dict(raw.get("probe") or {})

    # ------------------------------------------------------------- policy
    def capabilities(self) -> dict[str, Any]:
        desc = self.policy.describe()
        live_set = bool(desc["live_set_enabled"])
        return {
            "operations": list(OPERATIONS),
            "mock_set": True,
            "live_set": live_set,
            "allow_live": bool(desc["allow_live"]),
            "allowed_targets": list(desc["allowed_targets"]),
            "set_enabled": live_set,
            "readonly_only": bool(desc["readonly_only"]),
            "hard_block_enabled": bool(desc["hard_block_enabled"]),
            "audit_enabled": True,
            "audit_path": "work/probe-audit.jsonl",
            "max_walk": MAX_WALK,
            "mock_port": self.mock_port,
            "asn1_types": list(ASN1_TYPES),
            "probe_concurrency": self.concurrency,
            "probe_rate_limit_ms": self.rate_limit_ms,
            "probe_timeout_s": self.timeout_s,
            "probe_retries": self.retries,
            "session_cache_size": self.session_cache_size,
        }

    def _deny(self, req: dict[str, Any], user: str, reason: str) -> None:
        """Record a policy rejection (otherwise invisible in the audit trail)."""
        self.audit.record({
            "user": user,
            "mode": str(req.get("mode") or "mock"),
            "target": str(req.get("target_host") or ""),
            "version": str(req.get("version") or ""),
            "mib_id": str(req.get("mib_id") or "") or None,
            "operation": str(req.get("operation") or ""),
            "oid": str(req.get("oid") or ""),
            "ok": False,
            "error": reason,
            "count": 0,
            "elapsed_ms": 0,
            "policy_denied": True,
        })

    @staticmethod
    def _node_for_oid(model: Any, oid: str) -> Any | None:
        """Longest-prefix lookup of an instance OID back to its scalar/column node."""
        best = None
        best_len = -1
        for node in model.nodes:
            if node.kind not in ("scalar", "column") or not node.oid:
                continue
            target = oid.lstrip(".")
            base = node.oid.lstrip(".")
            if (target == base or target.startswith(base + ".")) and len(base) > best_len:
                best_len = len(base)
                best = node
        return best

    async def stop(self) -> None:
        async with self._agent_lock:
            if self._agent is not None:
                await self._agent.stop()
                self._agent = None
        async with self._session_lock:
            sessions = [entry[0] for entry in self._sessions.values()]
            self._sessions.clear()
        for session in sessions:
            await session.close()

    # ------------------------------------------------------------- config
    def _model_and_mib(self, mib_id: str | None = None) -> tuple[MibModel, Path, str]:
        records = self.library.list() if self.library else []
        record = None
        if mib_id:
            if self.library is None:
                raise ProbeError("当前服务未启用 MIB 库")
            try:
                record = self.library.get(mib_id)
            except MibError as exc:
                raise ProbeError("所选 MIB 不存在或已被删除，请刷新后重试") from exc
        elif records:
            record = records[0]
        if record is not None:
            model_path = self.library.model_path(record.mib_id)
            mib_path = self.library.mib_path(record.mib_id)
            resolved_id = record.mib_id
        else:
            model_path = self.root / "cases" / "generated" / "model.json"
            mib_path = self.root / "TTY-T1ZDG-v1.0_20261026.mib"
            resolved_id = ""
        if model_path.is_file():
            model = MibModel.from_dict(json.loads(model_path.read_text(encoding="utf-8")))
            return model, mib_path, resolved_id
        return MibModel.from_dict({
            "module_name": "probe", "mib_path": str(mib_path), "mib_sha256": "",
            "root_oid": "1.3.6.1", "nodes": [], "tables": [],
            "sequence_types": [], "stats": {}, "warnings": [],
        }), mib_path, resolved_id

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
            "execution": {"concurrency": 1, "timeout_s": self.timeout_s, "retries": self.retries,
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

    async def _ensure_agent(self, overrides: dict[str, Any], mib_id: str, model: MibModel) -> None:
        async with self._agent_lock:
            if self._agent is not None and self._agent_mib_id == mib_id:
                return
            if self._agent is not None:
                await self._agent.stop()
                self._agent = None
                self._agent_mib_id = None
            agent_overrides = dict(overrides)
            agent_overrides["mode"] = "mock"
            cfg = load_config(self.config_path, overrides=agent_overrides)
            agent = MockAgent(model, cfg)
            try:
                await agent.start()
            except BaseException:
                await agent.stop()
                raise
            self._agent = agent
            self._agent_mib_id = mib_id

    # ------------------------------------------------------------- execute
    @staticmethod
    def _session_key(cfg: Any, target: Any, version: str, cred: dict[str, Any]) -> tuple[Any, ...]:
        cred_part = tuple(sorted((str(k), str(v)) for k, v in cred.items()))
        return (cfg.mode, target.host, target.port, version, cred_part)

    async def _acquire_session(self, cfg: Any, target: Any, version: str, cred: dict[str, Any]) -> SnmpSession:
        """Reuse an idle session; v3 discovery and UDP sockets are expensive."""
        key = self._session_key(cfg, target, version, cred)
        now = time.monotonic()
        async with self._session_lock:
            entry = self._sessions.get(key)
            if entry is not None and now - entry[1] <= self.session_ttl:
                self._sessions.move_to_end(key)
                self._sessions[key] = (entry[0], now)
                return entry[0]
            if entry is not None:
                self._sessions.pop(key, None)
                await entry[0].close()
            session = SnmpSession(cfg, target, version, override=cred)
            await session.open()
            self._sessions[key] = (session, now)
            while len(self._sessions) > self.session_cache_size:
                _, (stale, _) = self._sessions.popitem(last=False)
                await stale.close()
            return session

    async def _throttle(self, host: str) -> None:
        if self.rate_limit_ms <= 0:
            return
        interval = self.rate_limit_ms / 1000.0
        async with self._throttle_lock:
            now = time.monotonic()
            wait = self._next_request_at.get(host, 0.0) - now
            if wait > 0:
                await asyncio.sleep(wait)
                now += wait
            self._next_request_at[host] = now + interval

    async def _walk(
        self, session: SnmpSession, version: str, oid: str, cursor: str, limit: int,
        host: str = "",
    ) -> tuple[list[Any], str, bool]:
        """Walk a subtree, using GETBULK on v2c/v3 to cut round trips by ~25x."""
        prefix = oid.lstrip(".")
        walk_cursor = cursor or oid
        varbinds: list[Any] = []
        error = ""
        while len(varbinds) < limit:
            # Pace the long v1 GETNEXT chain: a 200-row table is 200 packets,
            # and BMC agents drop requests when they arrive back to back.
            if host and varbinds:
                await self._throttle(host)
            remaining = limit - len(varbinds)
            if version == "v1":
                step = await session.get_next([walk_cursor])
                candidates = list(step.varbinds[:1])
            else:
                step = await session.get_bulk(
                    [walk_cursor], non_repeaters=0, max_repetitions=min(25, remaining),
                )
                candidates = list(step.varbinds)
            if step.error_indication or step.error_status not in ("noError", "0"):
                # v1 signals "no more variables" as noSuchName; after at least
                # one row that is a normal end-of-subtree, not a failure.
                if version == "v1" and step.error_status == "noSuchName" and varbinds:
                    break
                error = str(step.error_indication or step.error_status)
                break
            progressed = False
            stop = False
            for vb in candidates:
                if vb.exception is not None:
                    stop = True
                    break
                if not str(vb.oid).startswith(prefix + "."):
                    stop = True
                    break
                if varbinds and _oid_key(str(vb.oid)) <= _oid_key(str(varbinds[-1].oid)):
                    stop = True
                    break
                varbinds.append(vb)
                walk_cursor = str(vb.oid)
                progressed = True
                if len(varbinds) >= limit:
                    break
            if stop or not progressed:
                break
        return varbinds, error, len(varbinds) >= limit

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

        denied = self.policy.check(mode, operation, host)
        if denied:
            self._deny(req, user, denied)
            raise ProbeError(denied)

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

        model, mib_path, resolved_mib_id = self._model_and_mib(str(req.get("mib_id") or "").strip() or None)
        if operation == "SET" and mode == "live" and self.policy.hard_block_enabled:
            node = self._node_for_oid(model, oid)
            if node is not None:
                level, reason = classify_node(
                    node, load_policy(self.root / "config" / "safety-policy.yaml")
                )
                if level != "safe":
                    msg = f"SET 被安全策略阻断：{node.name}（{reason}）"
                    self._deny(req, user, msg)
                    raise ProbeError(msg)
        overrides, cred, version = self._overrides(req, mib_path)
        mock_lock = self._mock_lock if mode == "mock" else None
        if mock_lock is not None:
            await mock_lock.acquire()
        if mode == "live":
            await self._live_sem.acquire()
            await self._throttle(host)
        started = time.perf_counter()
        varbinds: list[Any] = []
        error = ""
        truncated = False
        try:
            if mode == "mock":
                await self._ensure_agent(overrides, resolved_mib_id, model)
            cfg = load_config(self.config_path, overrides=overrides)
            target = cfg.targets[0]
            session = await self._acquire_session(cfg, target, version, cred)
            if operation == "WALK":
                limit = max(1, min(int(req.get("max_results") or 50), MAX_WALK))
                # ``oid`` stays the subtree root; ``cursor`` (when present) is
                # the last OID of the previous page, so the walk resumes exactly
                # where it stopped instead of treating the last OID as a new root.
                varbinds, error, truncated = await self._walk(
                    session, version, oid, cursor, limit, host if mode == "live" else "",
                )
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
            if mock_lock is not None:
                mock_lock.release()
            if mode == "live":
                self._live_sem.release()

        result = {
            "ok": not error,
            "operation": operation,
            "oid": oid,
            "mode": mode,
            "version": version,
            "mib_id": resolved_mib_id or None,
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
            "mib_id": resolved_mib_id or None,
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
