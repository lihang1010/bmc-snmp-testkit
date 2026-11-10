"""Per-project MIB library.

Each uploaded MIB is stored under ``work/mibs/<sha256[:16]>/`` together with
its own model and case repository.  Content addressing gives natural
de-duplication and keeps one user's MIB from affecting another's cases.
"""

from __future__ import annotations

import hashlib
import json
import re
import threading
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from snmp_test.generator.case_builder import GeneratorOptions, generate_cases
from snmp_test.model.mib_model import build_model
from snmp_test.runner.case_store import CaseStore
from snmp_test.runner.safety import load_policy

MIB_ID_RE = re.compile(r"^[0-9a-f]{16}$")
MAX_MIB_BYTES = 4 * 1024 * 1024


class MibError(ValueError):
    pass


@dataclass(frozen=True)
class MibRecord:
    mib_id: str
    filename: str
    sha256: str
    module_name: str
    root_oid: str
    source_lines: int
    node_count: int
    table_count: int
    case_count: int
    warning_count: int
    uploaded_at: float

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class MibLibrary:
    def __init__(self, root: str | Path, policy_path: str | Path | None = None) -> None:
        self.root = Path(root)
        self.base = self.root / "work" / "mibs"
        self.base.mkdir(parents=True, exist_ok=True)
        self.policy_path = Path(policy_path) if policy_path else self.root / "config" / "safety-policy.yaml"
        self._lock = threading.Lock()
        self._records: dict[str, MibRecord] = {}
        self._load_index()

    def _load_index(self) -> None:
        for meta in sorted(self.base.glob("*/meta.json")):
            try:
                data = json.loads(meta.read_text(encoding="utf-8"))
                if MIB_ID_RE.match(str(data.get("mib_id", ""))):
                    self._records[data["mib_id"]] = MibRecord(**data)
            except Exception:
                continue

    @staticmethod
    def _safe_filename(name: str) -> str:
        cleaned = Path(str(name or "upload.mib").replace("\\", "/")).name
        cleaned = re.sub(r"[^A-Za-z0-9._-]", "_", cleaned)
        return cleaned[:120] or "upload.mib"

    def _dir(self, mib_id: str) -> Path:
        if not MIB_ID_RE.match(mib_id):
            raise MibError("invalid mib_id")
        return self.base / mib_id

    def add(self, filename: str, content: bytes, *, uploaded_by: str = "anonymous") -> MibRecord:
        if not content:
            raise MibError("empty MIB file")
        if len(content) > MAX_MIB_BYTES:
            raise MibError(f"MIB exceeds {MAX_MIB_BYTES} bytes")
        text = content.decode("utf-8", errors="replace")
        if "DEFINITIONS" not in text or "::= BEGIN" not in text.replace("\r", ""):
            raise MibError("content does not look like an ASN.1 MIB (missing DEFINITIONS ::= BEGIN)")
        digest = hashlib.sha256(content).hexdigest()
        mib_id = digest[:16]
        with self._lock:
            if mib_id in self._records:
                return self._records[mib_id]
            folder = self._dir(mib_id)
            folder.mkdir(parents=True, exist_ok=True)
            mib_path = folder / self._safe_filename(filename)
            mib_path.write_bytes(content)  # stored once, treated as read-only afterwards

            model = build_model(mib_path)
            options = GeneratorOptions(
                versions=("v1", "v2c", "v3"),
                policy=load_policy(self.policy_path),
            )
            cases = generate_cases(model, options)
            (folder / "model.json").write_text(model.to_json(), encoding="utf-8")
            CaseStore.from_cases(
                cases,
                {
                    "mib_sha256": model.mib_sha256,
                    "mib_path": str(mib_path),
                    "module_name": model.module_name,
                    "root_oid": model.root_oid,
                    "uploaded_by": uploaded_by,
                    "generator": {"versions": ["v1", "v2c", "v3"], "seed": options.seed},
                    "trap_expectations": 0,
                },
            ).write(folder / "cases.json")
            (folder / "parse-warnings.json").write_text(
                json.dumps(
                    {"total": len(model.warnings), "warnings": model.warnings, "stats": model.stats},
                    indent=2, ensure_ascii=False,
                ),
                encoding="utf-8",
            )
            record = MibRecord(
                mib_id=mib_id,
                filename=mib_path.name,
                sha256=digest,
                module_name=model.module_name,
                root_oid=model.root_oid,
                source_lines=int(model.stats.get("source_lines", 0)),
                node_count=len(model.nodes),
                table_count=len(model.tables),
                case_count=len(cases),
                warning_count=len(model.warnings),
                uploaded_at=time.time(),
            )
            (folder / "meta.json").write_text(
                json.dumps(record.to_dict(), indent=2, ensure_ascii=False), encoding="utf-8"
            )
            self._records[mib_id] = record
            return record

    def get(self, mib_id: str) -> MibRecord:
        if mib_id not in self._records:
            raise MibError(f"MIB {mib_id} not found")
        return self._records[mib_id]

    def list(self) -> list[MibRecord]:
        return sorted(self._records.values(), key=lambda r: r.uploaded_at, reverse=True)

    def mib_path(self, mib_id: str) -> Path:
        record = self.get(mib_id)
        return self._dir(mib_id) / record.filename

    def model_path(self, mib_id: str) -> Path:
        self.get(mib_id)
        return self._dir(mib_id) / "model.json"

    def cases_path(self, mib_id: str) -> Path:
        self.get(mib_id)
        return self._dir(mib_id) / "cases.json"

    def load_cases(self, mib_id: str) -> CaseStore:
        return CaseStore.read(self.cases_path(mib_id))
