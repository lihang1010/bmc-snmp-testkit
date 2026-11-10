"""Result aggregation, pass-rate computation and PDU / run logging."""

from __future__ import annotations

import json
import logging
import time
from pathlib import Path
from typing import Any

from snmp_test.config import Config
from snmp_test.model.types import CaseResult, SnmpResponse

TERMINAL = ("passed", "failed", "error", "skipped", "blocked")


class ResultCollector:
    def __init__(self, cfg: Config, run_id: str, run_dir: str | Path) -> None:
        self.cfg = cfg
        self.run_id = run_id
        self.run_dir = Path(run_dir)
        self.run_dir.mkdir(parents=True, exist_ok=True)
        self.started_at = time.time()
        self.finished_at: float | None = None
        self.results: list[CaseResult] = []
        self.pdu_count = 0
        self.pdu_sample_rate = float(cfg.report.get("pdu_log_sample_rate", 1.0))
        self._pdu_fh = (self.run_dir / "pdus.jsonl").open("a", encoding="utf-8")
        self.logger = self._build_logger()

    def _build_logger(self) -> logging.Logger:
        logger = logging.getLogger(f"snmp_test.run.{self.run_id}")
        logger.setLevel(getattr(logging, str(self.cfg.report.get("log_level", "INFO")).upper(), logging.INFO))
        logger.handlers.clear()
        logger.propagate = False
        masking = self.cfg.masking_filter()
        fh = logging.FileHandler(self.run_dir / "run.log", encoding="utf-8")
        fh.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
        fh.addFilter(masking)
        sh = logging.StreamHandler()
        sh.setLevel(logging.WARNING)  # console stays quiet; run.log keeps everything
        sh.setFormatter(logging.Formatter("%(levelname)s %(message)s"))
        sh.addFilter(masking)
        logger.addHandler(fh)
        logger.addHandler(sh)
        return logger

    def add(self, result: CaseResult) -> None:
        self.results.append(result)
        level = logging.INFO if result.status == "passed" else logging.WARNING
        self.logger.log(
            level,
            "[%s] %s %s/%s target=%s %.1fms %s",
            result.status.upper(),
            result.case_id,
            result.operation,
            result.version,
            result.target,
            result.duration_ms,
            result.message,
        )

    def add_pdu(
        self,
        *,
        case_id: str,
        target: str,
        version: str,
        operation: str,
        response: SnmpResponse | None,
        note: str = "",
    ) -> None:
        self.pdu_count += 1
        if self.pdu_sample_rate < 1.0 and (self.pdu_count % max(2, int(1 / max(self.pdu_sample_rate, 0.01)))):
            return
        entry = {
            "ts": time.time(),
            "case_id": case_id,
            "target": target,
            "version": version,
            "operation": operation,
            "note": note,
            "response": response.to_dict() if response else None,
        }
        self._pdu_fh.write(json.dumps(entry, ensure_ascii=False, default=str) + "\n")
        self._pdu_fh.flush()

    def finish(self) -> None:
        self.finished_at = time.time()

    def close(self) -> None:
        self._pdu_fh.close()
        for handler in list(self.logger.handlers):
            handler.close()
            self.logger.removeHandler(handler)

    # -------------------------------------------------------------- summary
    @staticmethod
    def _rate_group(items: list[CaseResult]) -> dict[str, Any]:
        total = len(items)
        counts = {status: sum(1 for r in items if r.status == status) for status in TERMINAL}
        executed = counts["passed"] + counts["failed"] + counts["error"]
        return {
            "total": total,
            **counts,
            "pass_rate": round(100.0 * counts["passed"] / total, 2) if total else 0.0,
            "effective_pass_rate": round(100.0 * counts["passed"] / executed, 2) if executed else 0.0,
            "duration_ms": round(sum(r.duration_ms for r in items), 2),
        }

    def summary(self) -> dict[str, Any]:
        overall = self._rate_group(self.results)
        by: dict[str, dict[str, Any]] = {}
        for dimension, keyfn in (
            ("by_version", lambda r: r.version),
            ("by_operation", lambda r: r.operation),
            ("by_module", lambda r: r.module or "(global)"),
            ("by_target", lambda r: r.target),
        ):
            groups: dict[str, list[CaseResult]] = {}
            for result in self.results:
                groups.setdefault(keyfn(result), []).append(result)
            by[dimension] = {key: self._rate_group(value) for key, value in sorted(groups.items())}
        return {
            "run_id": self.run_id,
            "started_at": self.started_at,
            "finished_at": self.finished_at or time.time(),
            "duration_s": round((self.finished_at or time.time()) - self.started_at, 3),
            "overall": overall,
            **by,
        }

    def failures(self) -> list[dict[str, Any]]:
        return [r.to_dict() for r in self.results if r.status in ("failed", "error", "blocked")]

    def results_dict(self) -> list[dict[str, Any]]:
        return [r.to_dict() for r in self.results]
