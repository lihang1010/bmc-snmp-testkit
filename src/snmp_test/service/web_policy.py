"""Central policy for the interactive web surface (probe console + MIB browser).

Defaults preserve the intranet behaviour: any live target is reachable and SET
is available, guarded by the UI confirmation, the safety policy's hard blocks
and the audit log.  Operators can tighten everything through the ``security.web``
section of ``config/web.yaml``::

    security:
      web:
        allow_live: true
        allowed_targets: ["10.0.0.10"]
        readonly_only: false
        live_set_enabled: false
        hard_block_enabled: true

The legacy top-level ``security.allow_live`` / ``allowed_targets`` keys are
deliberately NOT consumed here: they belong to the old role/token template and
were never enforced, so honouring them would silently break existing setups.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class WebPolicy:
    allow_live: bool = True
    allowed_targets: tuple[str, ...] = ()
    readonly_only: bool = False
    live_set_enabled: bool = True
    hard_block_enabled: bool = True

    @classmethod
    def from_security(cls, sec: dict[str, Any] | None) -> "WebPolicy":
        raw = dict(sec or {})
        web = dict(raw.get("web") or {})
        targets = tuple(
            str(x).strip() for x in (web.get("allowed_targets") or []) if str(x).strip()
        )
        return cls(
            allow_live=bool(web.get("allow_live", True)),
            allowed_targets=targets,
            readonly_only=bool(web.get("readonly_only", False)),
            live_set_enabled=bool(web.get("live_set_enabled", True)),
            hard_block_enabled=bool(web.get("hard_block_enabled", True)),
        )

    def allows_target(self, host: str) -> bool:
        # An empty allowlist means "no restriction" (the intranet default).
        return not self.allowed_targets or host in self.allowed_targets

    def check(self, mode: str, operation: str, host: str) -> str | None:
        """Return a rejection reason, or ``None`` when the request is allowed."""
        if mode != "live":
            return None
        if not self.allow_live:
            return "live 模式已被服务策略禁用（security.web.allow_live=false）"
        if not self.allows_target(host):
            return f"目标 {host} 不在 security.web.allowed_targets 允许列表内"
        if operation == "SET":
            if self.readonly_only:
                return "服务为只读模式，禁止 SET（security.web.readonly_only=true）"
            if not self.live_set_enabled:
                return "live SET 已被服务策略禁用（security.web.live_set_enabled=false）"
        return None

    def describe(self) -> dict[str, Any]:
        return {
            "allow_live": self.allow_live,
            "allowed_targets": list(self.allowed_targets),
            "readonly_only": self.readonly_only,
            "live_set_enabled": self.live_set_enabled and not self.readonly_only,
            "hard_block_enabled": self.hard_block_enabled,
        }
