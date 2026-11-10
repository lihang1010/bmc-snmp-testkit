"""Case repository: loading, filtering, selection and stable rerun sets."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable

from snmp_test.model.types import TestCase


@dataclass
class CaseFilter:
    ids: set[str] = field(default_factory=set)
    exclude_ids: set[str] = field(default_factory=set)
    tags_any: set[str] = field(default_factory=set)
    tags_all: set[str] = field(default_factory=set)
    exclude_tags: set[str] = field(default_factory=set)
    versions: set[str] = field(default_factory=set)
    operations: set[str] = field(default_factory=set)
    modules: set[str] = field(default_factory=set)
    categories: set[str] = field(default_factory=set)
    priority_max: int | None = None
    limit: int = 0
    exclude_guarded: bool = False

    def accepts(self, case: TestCase) -> bool:
        if self.ids and case.case_id not in self.ids:
            return False
        if case.case_id in self.exclude_ids:
            return False
        if self.versions and case.version not in self.versions:
            return False
        if self.operations and case.operation not in self.operations:
            return False
        if self.modules and case.module not in self.modules:
            return False
        if self.categories and case.category not in self.categories:
            return False
        if self.priority_max is not None and case.priority > self.priority_max:
            return False
        tags = set(case.tags)
        if self.tags_any and not (tags & self.tags_any):
            return False
        if self.tags_all and not self.tags_all.issubset(tags):
            return False
        if self.exclude_tags and tags & self.exclude_tags:
            return False
        if self.exclude_guarded and "guarded" in tags:
            return False
        return True


class CaseStore:
    def __init__(self, cases: list[TestCase], meta: dict[str, Any] | None = None) -> None:
        self.cases = cases
        self.meta = dict(meta or {})
        self._by_id = {c.case_id: c for c in cases}

    def __len__(self) -> int:
        return len(self.cases)

    def by_id(self, case_id: str) -> TestCase | None:
        return self._by_id.get(case_id)

    def select(self, flt: CaseFilter | None = None) -> list[TestCase]:
        flt = flt or CaseFilter()
        selected = [c for c in self.cases if flt.accepts(c)]
        if flt.limit > 0:
            selected = selected[: flt.limit]
        return selected

    def to_json(self) -> str:
        return json.dumps(
            {
                "schema": 1,
                "meta": self.meta,
                "total": len(self.cases),
                "cases": [c.to_dict() for c in self.cases],
            },
            indent=1,
            ensure_ascii=False,
            sort_keys=True,
        )

    def write(self, path: str | Path) -> Path:
        p = Path(path)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(self.to_json(), encoding="utf-8")
        return p

    @classmethod
    def read(cls, path: str | Path) -> "CaseStore":
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        cases = [TestCase.from_dict(c) for c in data.get("cases", [])]
        return cls(cases, data.get("meta", {}))

    @classmethod
    def from_cases(cls, cases: Iterable[TestCase], meta: dict[str, Any] | None = None) -> "CaseStore":
        return cls(list(cases), meta)


def failed_ids_from_run(path: str | Path) -> set[str]:
    """Read a previous ``results.json`` and return the ids to rerun."""
    p = Path(path)
    if not p.is_file():
        return set()
    data = json.loads(p.read_text(encoding="utf-8"))
    return {
        str(r["case_id"])
        for r in data.get("results", [])
        if r.get("status") in ("failed", "error")
    }


def parse_filter_args(
    *,
    ids: str = "",
    tags: str = "",
    exclude_tags: str = "",
    versions: str = "",
    operations: str = "",
    modules: str = "",
    categories: str = "",
    limit: int = 0,
    rerun: str = "",
) -> CaseFilter:
    def split(value: str) -> set[str]:
        return {x.strip() for x in value.split(",") if x.strip()}

    excluded: set[str] = set()
    if rerun:
        run_dir = Path(rerun)
        candidate = run_dir / "results.json" if run_dir.is_dir() else run_dir
        excluded = failed_ids_from_run(candidate)
    id_set = split(ids) or excluded
    return CaseFilter(
        ids=id_set,
        tags_any=split(tags),
        exclude_tags=split(exclude_tags),
        versions=split(versions),
        operations=split(operations),
        modules=split(modules),
        categories=split(categories),
        limit=limit,
    )
