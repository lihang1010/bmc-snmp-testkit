"""Configuration loading, environment interpolation, validation and masking."""

from __future__ import annotations

import copy
import logging
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

ENV_RE = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)(?::([^}]*))?\}")
SECRET_KEY_RE = re.compile(r"(community|auth_key|priv_key|password|passwd|secret|token|engine_id|key)", re.I)

DEFAULT_CONFIG: dict[str, Any] = {
    "version": 1,
    "mode": "mock",
    "mib": "TTY-T1ZDG-v1.0_20261026.mib",
    "targets": [
        {
            "name": "mock-bmc",
            "enabled": True,
            "host": "127.0.0.1",
            "port": 11611,
            "versions": ["v1", "v2c", "v3"],
            "v1": {"community": "private", "read_only_community": "public"},
            "v2c": {"community": "private", "read_only_community": "public"},
            "v3": {
                "user": "bmcuser",
                "auth_protocol": "SHA",
                "auth_key": "authpass123",
                "priv_protocol": "AES128",
                "priv_key": "privpass123",
                "security_level": "authPriv",
            },
            "invalid_credentials": {
                "community": "invalid-community",
                "v3_user": "invalid-user",
                "auth_key": "definitely-wrong-auth-key",
                "priv_key": "definitely-wrong-priv-key",
            },
        }
    ],
    "mock": {
        "bind_host": "127.0.0.1",
        "port": 11611,
        "trap_port": 11612,
        "rows_per_table": 2,
        "communities": {"read_only": "public", "read_write": "private"},
        "v3": {
            "user": "bmcuser",
            "auth_protocol": "SHA",
            "auth_key": "authpass123",
            "priv_protocol": "AES128",
            "priv_key": "privpass123",
        },
        "trap_dest_port": 11612,
    },
    "trap": {"listen_host": "127.0.0.1", "listen_port": 11612, "receive_timeout_s": 5.0},
    "execution": {
        "concurrency": 12,
        "timeout_s": 2.0,
        "retries": 1,
        "rows_per_table": 2,
        "max_cases_per_table": 8,
        "max_varbinds": 20,
        "bulk_max_repetitions": 6,
        "allow_guarded": False,
        "enable_set": True,
        "seed": 20261109,
        "limit": 0,
    },
    "safety": {"policy_file": "config/safety-policy.yaml"},
    "report": {
        "output_dir": "runs",
        "pdu_log_sample_rate": 1.0,
        "log_level": "INFO",
        "trap_expectations_file": "config/trap-expectations.yaml",
    },
}


def _merge(base: dict[str, Any], override: dict[str, Any]) -> dict[str, Any]:
    out = copy.deepcopy(base)
    for key, value in override.items():
        if isinstance(value, dict) and isinstance(out.get(key), dict):
            out[key] = _merge(out[key], value)
        else:
            out[key] = value
    return out


def expand_env(value: Any) -> Any:
    if isinstance(value, str):
        def repl(m: re.Match[str]) -> str:
            return os.environ.get(m.group(1), m.group(2) if m.group(2) is not None else "")
        return ENV_RE.sub(repl, value)
    if isinstance(value, list):
        return [expand_env(v) for v in value]
    if isinstance(value, dict):
        return {k: expand_env(v) for k, v in value.items()}
    return value


def mask_secrets(value: Any) -> Any:
    if isinstance(value, dict):
        return {k: ("***" if SECRET_KEY_RE.search(str(k)) and v not in (None, "", False) else mask_secrets(v)) for k, v in value.items()}
    if isinstance(value, list):
        return [mask_secrets(v) for v in value]
    return value


def collect_secrets(value: Any) -> list[str]:
    out: list[str] = []
    if isinstance(value, dict):
        for k, v in value.items():
            if SECRET_KEY_RE.search(str(k)) and isinstance(v, str) and len(v) >= 4:
                out.append(v)
            else:
                out.extend(collect_secrets(v))
    elif isinstance(value, list):
        for v in value:
            out.extend(collect_secrets(v))
    return list(dict.fromkeys(out))


class CredentialMaskingFilter(logging.Filter):
    """Replace any configured credential literal in log records."""

    def __init__(self, secrets: list[str]) -> None:
        super().__init__()
        self.secrets = [s for s in secrets if s]

    def filter(self, record: logging.LogRecord) -> bool:
        if not self.secrets:
            return True
        try:
            msg = record.getMessage()
        except Exception:
            return True
        for secret in self.secrets:
            if secret in msg:
                msg = msg.replace(secret, "***")
        record.msg = msg
        record.args = ()
        return True


@dataclass
class TargetConfig:
    name: str
    host: str
    port: int
    versions: tuple[str, ...]
    v1: dict[str, Any] = field(default_factory=dict)
    v2c: dict[str, Any] = field(default_factory=dict)
    v3: dict[str, Any] = field(default_factory=dict)
    invalid: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "TargetConfig":
        return cls(
            name=str(data.get("name", "target")),
            host=str(data.get("host", "127.0.0.1")),
            port=int(data.get("port", 161)),
            versions=tuple(str(v) for v in data.get("versions", ["v1", "v2c", "v3"])),
            v1=dict(data.get("v1") or {}),
            v2c=dict(data.get("v2c") or {}),
            v3=dict(data.get("v3") or {}),
            invalid=dict(data.get("invalid_credentials") or {}),
        )

    def community(self, version: str) -> str:
        return str((self.v1 if version == "v1" else self.v2c).get("community", "public"))

    def read_only_community(self, version: str) -> str:
        return str((self.v1 if version == "v1" else self.v2c).get("read_only_community", self.community(version)))


class Config:
    """Validated, path-aware view of ``config.yaml``."""

    def __init__(self, raw: dict[str, Any], path: Path) -> None:
        self.raw = raw
        self.path = Path(path).resolve()
        self.root = self.path.parent.parent if self.path.parent.name == "config" else self.path.parent
        self._secrets = collect_secrets(self.raw)

    @property
    def mode(self) -> str:
        return str(self.raw.get("mode", "mock")).lower()

    @property
    def mib_path(self) -> Path:
        return self.resolve(str(self.raw.get("mib", "TTY-T1ZDG-v1.0_20261026.mib")))

    @property
    def targets(self) -> list[TargetConfig]:
        return [
            TargetConfig.from_dict(t)
            for t in self.raw.get("targets", [])
            if t.get("enabled", True)
        ]

    @property
    def execution(self) -> dict[str, Any]:
        return dict(self.raw.get("execution") or {})

    @property
    def mock(self) -> dict[str, Any]:
        return dict(self.raw.get("mock") or {})

    @property
    def trap(self) -> dict[str, Any]:
        return dict(self.raw.get("trap") or {})

    @property
    def report(self) -> dict[str, Any]:
        return dict(self.raw.get("report") or {})

    @property
    def safety(self) -> dict[str, Any]:
        return dict(self.raw.get("safety") or {})

    @property
    def secrets(self) -> list[str]:
        return self._secrets

    def resolve(self, relative: str) -> Path:
        p = Path(relative)
        return p if p.is_absolute() else (self.root / p)

    def masked(self) -> dict[str, Any]:
        return mask_secrets(self.raw)

    def masking_filter(self) -> CredentialMaskingFilter:
        return CredentialMaskingFilter(self._secrets)

    def validate(self) -> list[str]:
        errors: list[str] = []
        if self.mode not in ("mock", "live"):
            errors.append("mode must be 'mock' or 'live'")
        if not self.mib_path.is_file():
            errors.append(f"MIB file not found: {self.mib_path}")
        targets = self.targets
        if not targets:
            errors.append("at least one enabled target is required")
        for t in targets:
            if not t.host or t.port < 1 or t.port > 65535:
                errors.append(f"target '{t.name}' has invalid host/port")
            for v in t.versions:
                if v not in ("v1", "v2c", "v3"):
                    errors.append(f"target '{t.name}' has unsupported version '{v}'")
            if "v3" in t.versions:
                for key in ("user", "auth_protocol", "auth_key", "priv_protocol", "priv_key"):
                    if not t.v3.get(key):
                        errors.append(f"target '{t.name}' v3.{key} is required")
        ex = self.execution
        if int(ex.get("concurrency", 1)) < 1:
            errors.append("execution.concurrency must be >= 1")
        if float(ex.get("timeout_s", 1)) <= 0:
            errors.append("execution.timeout_s must be > 0")
        return errors


def load_config(path: str | Path | None = None, *, overrides: dict[str, Any] | None = None) -> Config:
    """Load config, interpolate env vars, merge overrides and validate."""
    root = Path(__file__).resolve().parents[2]
    # Default to the offline mock profile.  A live profile must be selected
    # explicitly with `--config`, so a bare CLI invocation can never inherit
    # real-device settings by accident.
    p = Path(path).resolve() if path else root / "config" / "config.example.yaml"
    raw = copy.deepcopy(DEFAULT_CONFIG)
    if p.is_file():
        loaded = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
        raw = _merge(raw, loaded)
    raw = expand_env(raw)
    if overrides:
        raw = _merge(raw, expand_env(overrides))
    cfg = Config(raw, p)
    return cfg


def example_config_dict() -> dict[str, Any]:
    return copy.deepcopy(DEFAULT_CONFIG)
