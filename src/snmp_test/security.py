"""Service-level security guard and lightweight per-user auth.

The CLI used to be the only place that checked ``--allow-live``.  When the
framework is exposed as a service, Python API callers must not be able to
bypass that check, so the guard lives here and is enforced inside ``Runtime``.
"""

from __future__ import annotations

import os
import secrets
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from snmp_test.config import Config

READONLY_OPERATIONS = frozenset({"GET", "GETNEXT", "GETBULK", "TRAP", "INFORM"})
ROLES = ("viewer", "operator", "admin")


class AccessDenied(RuntimeError):
    """Raised when a request violates the service security policy."""


def _env_flag(name: str) -> bool:
    return os.environ.get(name, "").strip().lower() in ("1", "true", "yes", "on")


@dataclass(frozen=True)
class SecurityPolicy:
    allow_live: bool = False
    allowed_targets: tuple[str, ...] = ()
    readonly_only: bool = False

    @classmethod
    def from_config(
        cls,
        cfg: Config,
        *,
        allow_live: bool | None = None,
        readonly_only: bool | None = None,
    ) -> "SecurityPolicy":
        sec = dict(cfg.raw.get("security") or {})
        if allow_live is None:
            allow_live = bool(sec.get("allow_live", False)) or _env_flag("SNMP_TEST_ALLOW_LIVE")
        if readonly_only is None:
            readonly_only = bool(sec.get("readonly_only", False))
        if allow_live:
            # An explicit operator confirmation (CLI --allow-live) means the
            # operator's own configured targets are the allowlist.  A service
            # must instead declare allow_live in config AND list the targets.
            allowed = tuple(str(x) for x in sec.get("allowed_targets", []) or [])
            if not allowed:
                allowed = tuple(t.host for t in cfg.targets)
        else:
            allowed = tuple(str(x) for x in sec.get("allowed_targets", []) or [])
        return cls(
            allow_live=bool(allow_live),
            allowed_targets=allowed,
            readonly_only=bool(readonly_only),
        )

    def enforce(self, cfg: Config) -> None:
        if cfg.mode == "live":
            if not self.allow_live:
                raise AccessDenied(
                    "live mode requires explicit confirmation (CLI --allow-live or security.allow_live)"
                )
            if not self.allowed_targets:
                raise AccessDenied("live mode requires a non-empty security.allowed_targets allowlist")
            for target in cfg.targets:
                if target.host not in self.allowed_targets:
                    raise AccessDenied(
                        f"target {target.host!r} is not in security.allowed_targets"
                    )

    def effective_set_enabled(self, cfg: Config) -> bool:
        if self.readonly_only:
            return False
        return bool(cfg.execution.get("enable_set", True))

    def allows_operation(self, operation: str) -> bool:
        return not self.readonly_only or operation in READONLY_OPERATIONS


@dataclass(frozen=True)
class User:
    name: str
    token: str
    role: str = "viewer"

    def can(self, action: str) -> bool:
        if action == "read":
            return True
        if action == "write":
            return self.role in ("operator", "admin")
        if action == "live":
            return self.role == "admin"
        return False


class AuthStore:
    """Per-user tokens/roles from ``config/web.yaml`` (or env JSON).

    This is intentionally a lightweight RBAC placeholder: tokens are compared
    with ``compare_digest`` and never logged.  Production deployments should
    replace it with OIDC / LDAP, not extend it.
    """

    def __init__(self, users: list[User], *, dev_token: str | None = None) -> None:
        self._by_token = {u.token: u for u in users if u.token}
        self.dev_token = dev_token

    @classmethod
    def load(cls, path: str | Path | None = None) -> "AuthStore":
        raw: dict[str, Any] = {}
        p = Path(path) if path else Path(__file__).resolve().parents[2] / "config" / "web.yaml"
        if p.is_file():
            raw = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
        users: list[User] = []
        for item in ((raw.get("auth") or {}).get("users") or []):
            token = str(item.get("token") or "").strip()
            role = str(item.get("role") or "viewer").strip().lower()
            if token and role in ROLES:
                users.append(User(str(item.get("name") or "user"), token, role))
        if not users:
            dev = os.environ.get("SNMP_TEST_API_TOKEN") or secrets.token_urlsafe(24)
            return cls([User("dev-admin", dev, "admin")], dev_token=dev)
        return cls(users)

    def authenticate(self, token: str | None) -> User | None:
        if not token:
            return None
        for candidate, user in self._by_token.items():
            if secrets.compare_digest(candidate, token):
                return user
        return None
