"""Command line entry point: generate / run / mock-agent / report."""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
import warnings
from pathlib import Path
from typing import Any

warnings.filterwarnings("ignore", category=DeprecationWarning)
warnings.filterwarnings("ignore", message=".*CFB has been moved.*")

from snmp_test.config import load_config
from snmp_test.generator.case_builder import GeneratorOptions, generate_cases
from snmp_test.generator.trap_cases import generate_trap_cases, load_expectations
from snmp_test.model.mib_model import build_model
from snmp_test.model.types import MibModel
from snmp_test.report.writers import write_all
from snmp_test.runner.case_store import CaseFilter, CaseStore, failed_ids_from_run
from snmp_test.runner.executor import make_run_id, run_batch
from snmp_test.runner.safety import load_policy
from snmp_test.snmp.mock_agent import MockAgent

DEFAULT_CASES = Path("cases/generated/cases.json")


def _policy_path(cfg) -> Path:
    return cfg.resolve(str(cfg.safety.get("policy_file", "config/safety-policy.yaml")))


def _generator_options(cfg, policy: dict[str, Any]) -> GeneratorOptions:
    ex = cfg.execution
    versions = tuple(dict.fromkeys(v for t in cfg.targets for v in t.versions)) or ("v1", "v2c", "v3")
    first = cfg.targets[0]
    return GeneratorOptions(
        versions=versions,
        rows_per_table=int(ex.get("rows_per_table", 2)),
        max_cases_per_table=int(ex.get("max_cases_per_table", 8)),
        enable_set=bool(ex.get("enable_set", True)),
        policy=policy,
        wrong_community=str(first.invalid.get("community", "invalid-community")),
        wrong_v3_user=str(first.invalid.get("v3_user", "invalid-user")),
        max_varbinds=int(ex.get("max_varbinds", 20)),
        bulk_max_repetitions=int(ex.get("bulk_max_repetitions", 6)),
        seed=int(ex.get("seed", 20261109)),
    )


def _build_all_cases(cfg, model: MibModel, policy: dict[str, Any]):
    options = _generator_options(cfg, policy)
    base = generate_cases(model, options)
    expectations = load_expectations(cfg.resolve(str(cfg.report.get("trap_expectations_file", "config/trap-expectations.yaml"))))
    traps = generate_trap_cases(expectations, model.mib_sha256, options.versions)
    cases = sorted(base + traps, key=lambda c: (c.priority, c.case_id))
    meta = {
        "mib_sha256": model.mib_sha256,
        "mib_path": str(model.mib_path),
        "module_name": model.module_name,
        "root_oid": model.root_oid,
        "generator": {
            "versions": list(options.versions),
            "rows_per_table": options.rows_per_table,
            "max_cases_per_table": options.max_cases_per_table,
            "enable_set": options.enable_set,
            "seed": options.seed,
        },
        "trap_expectations": len(expectations),
    }
    return cases, meta


def cmd_generate(args: argparse.Namespace) -> int:
    cfg = load_config(args.config)
    errors = cfg.validate()
    if errors:
        print("配置校验失败:", file=sys.stderr)
        for e in errors:
            print("  -", e, file=sys.stderr)
        return 2
    model = build_model(cfg.mib_path)
    policy = load_policy(_policy_path(cfg))
    cases, meta = _build_all_cases(cfg, model, policy)

    out_dir = cfg.resolve(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "model.json").write_text(model.to_json(), encoding="utf-8")
    (out_dir / "parse-warnings.json").write_text(
        json.dumps(
            {"total": len(model.warnings), "warnings": model.warnings, "stats": model.stats},
            indent=2,
            ensure_ascii=False,
        ),
        encoding="utf-8",
    )
    store = CaseStore.from_cases(cases, meta)
    path = store.write(out_dir / "cases.json")
    print(f"[generate] MIB={Path(model.mib_path).name} sha256={model.mib_sha256[:16]}…")
    print(f"[generate] 节点={len(model.nodes)} 表={len(model.tables)} 解析告警={len(model.warnings)}")
    print(f"[generate] 用例={len(cases)}（含 trap/inform {meta['trap_expectations']} 条期望）→ {path}")
    return 0


def _filter_from_args(args: argparse.Namespace, cfg=None) -> CaseFilter:
    def split(value: str | None) -> set[str]:
        return {x.strip() for x in (value or "").split(",") if x.strip()}

    ids = split(args.ids)
    if args.rerun:
        p = Path(args.rerun)
        candidate = p / "results.json" if p.is_dir() else p
        ids |= failed_ids_from_run(candidate)
    return CaseFilter(
        ids=ids,
        tags_any=split(args.tags),
        exclude_tags=split(args.exclude_tags),
        versions=split(args.versions),
        operations=split(args.ops),
        modules=split(args.modules),
        categories=split(args.categories),
        limit=int(args.limit or (int(cfg.execution.get("limit", 0)) if cfg else 0)),
    )


def cmd_run(args: argparse.Namespace) -> int:
    cfg = load_config(args.config)
    if args.mode:
        cfg.raw["mode"] = args.mode
    errors = cfg.validate()
    if errors:
        print("配置校验失败:", file=sys.stderr)
        for e in errors:
            print("  -", e, file=sys.stderr)
        return 2
    if cfg.mode == "live" and not args.allow_live:
        print(
            "拒绝连接真实设备：mode=live 需要显式追加 --allow-live，并确认安全策略与授权。",
            file=sys.stderr,
        )
        return 2

    cases_path = cfg.resolve(args.cases)
    if not cases_path.is_file():
        print(f"未找到用例文件 {cases_path}，请先执行 `snmp-test generate`。", file=sys.stderr)
        return 2
    store = CaseStore.read(cases_path)
    model_path = Path(args.model) if args.model else cases_path.parent / "model.json"
    model = MibModel.from_dict(json.loads(cfg.resolve(str(model_path)).read_text(encoding="utf-8"))) if cfg.resolve(str(model_path)).is_file() else build_model(cfg.mib_path)
    policy = load_policy(_policy_path(cfg))
    flt = _filter_from_args(args, cfg)
    selected = store.select(flt)
    if not selected:
        print("筛选后没有可执行用例。", file=sys.stderr)
        return 2

    run_id = args.run_id or make_run_id()
    runtime, results = asyncio.run(
        run_batch(
            cfg,
            model,
            selected,
            run_id=run_id,
            allow_guarded=True if args.allow_guarded else None,
            enable_set=False if args.no_set else None,
            allow_live=bool(args.allow_live),
            dry_run=args.dry_run,
        )
    )
    try:
        paths = write_all(
            runtime.collector,
            cfg=cfg,
            model=model,
            cases=selected,
            policy=policy,
            extra={
                "mode": cfg.mode,
                "case_filter": {
                    "ids": sorted(flt.ids), "tags_any": sorted(flt.tags_any),
                    "versions": sorted(flt.versions), "operations": sorted(flt.operations),
                    "limit": flt.limit, "rerun": args.rerun or "",
                },
                "dry_run": bool(args.dry_run),
            },
        )
        paths["results_json"] = paths["results_json"]
        summary = runtime.collector.summary()["overall"]
        print(f"[run] run_id={run_id} mode={cfg.mode} 执行={summary['total']} "
              f"通过={summary['passed']} 失败={summary['failed']} 错误={summary['error']} "
              f"跳过={summary['skipped']} 阻断={summary['blocked']} "
              f"通过率={summary['pass_rate']}% 有效通过率={summary['effective_pass_rate']}%")
        print(f"[run] 报告: {paths['report_html']}")
        print(f"[run] 结果: {paths['results_json']}  日志: {paths['run_log']}")
        return 0 if summary["failed"] == 0 and summary["error"] == 0 else 1
    finally:
        runtime.close()


def cmd_mock_agent(args: argparse.Namespace) -> int:
    cfg = load_config(args.config)
    errors = cfg.validate()
    if errors:
        print("配置校验失败:", errors, file=sys.stderr)
        return 2
    model = build_model(cfg.mib_path)

    async def serve() -> None:
        agent = MockAgent(model, cfg)
        await agent.start()
        print(f"[mock-agent] {cfg.mock.get('bind_host')}:{cfg.mock.get('port')} "
              f"运行中，实例 OID {len(agent.datastore)} 个；Ctrl+C 退出。", flush=True)
        try:
            if args.seconds > 0:
                await asyncio.sleep(args.seconds)
            else:
                while True:
                    await asyncio.sleep(1)
        finally:
            await agent.stop()

    try:
        asyncio.run(serve())
    except KeyboardInterrupt:
        pass
    return 0


class _ReplayCollector:
    """Minimal collector-compatible view of an existing results.json."""

    def __init__(self, run_dir: Path, data: dict[str, Any]) -> None:
        self.cfg = None  # type: ignore[assignment]
        self.run_id = str(data.get("run_id", run_dir.name))
        self.run_dir = run_dir
        self._data = data

    def summary(self) -> dict[str, Any]:
        return self._data.get("summary", {})

    def results_dict(self) -> list[dict[str, Any]]:
        return self._data.get("results", [])

    def failures(self) -> list[dict[str, Any]]:
        return self._data.get("failures", [])


def cmd_report(args: argparse.Namespace) -> int:
    cfg = load_config(args.config)
    run_dir = Path(args.run_dir).resolve()
    results_path = run_dir / "results.json"
    if not results_path.is_file():
        print(f"未找到 {results_path}", file=sys.stderr)
        return 2
    data = json.loads(results_path.read_text(encoding="utf-8"))
    collector = _ReplayCollector(run_dir, data)
    collector.cfg = cfg  # type: ignore[assignment]
    model = build_model(cfg.mib_path)
    policy = load_policy(_policy_path(cfg))
    cases = []
    manifest = run_dir / "case-manifest.json"
    if manifest.is_file():
        ids = json.loads(manifest.read_text(encoding="utf-8")).get("case_ids", [])
        store_path = cfg.resolve(args.cases)
        if store_path.is_file():
            loaded = CaseStore.read(store_path)
            cases = [c for c in loaded.cases if c.case_id in set(ids)]
    from snmp_test.report import writers

    preserved = {
        key: value
        for key, value in data.items()
        if key not in ("schema", "run_id", "summary", "results", "failures")
    }
    json_path = writers.write_results_json(collector, {**preserved, "regenerated": True})
    junit = writers.write_junit_xml(collector)
    html_path = writers.write_html_report(
        collector,
        {
            "mode": str(data.get("mode", cfg.mode)),
            "targets": [{"name": t.name, "host": t.host, "port": t.port, "versions": list(t.versions)} for t in cfg.targets],
            "mib": {"name": Path(model.mib_path).name, "sha256": model.mib_sha256, "module": model.module_name, "root": model.root_oid},
            "policy": {"allow_guarded": False, "set_enabled": True, "hard_blocked": []},
            "snapshots": {"case_count": str(len(cases))},
            "extra": {"results_json": str(json_path)},
        },
    )
    print(f"[report] 重新生成: {html_path} / {junit} / {json_path}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="snmp-test",
        description="MIB 驱动的 BMC SNMP 自动化测试框架（默认只连接本地模拟 Agent）",
    )
    parser.add_argument("--config", help="配置文件路径，默认 config/config.example.yaml")
    sub = parser.add_subparsers(dest="command", required=True)

    g = sub.add_parser("generate", help="解析 MIB 并生成用例仓库")
    g.add_argument("--out-dir", default="cases/generated", help="生成目录")
    g.set_defaults(func=cmd_generate)

    r = sub.add_parser("run", help="批量执行用例并输出报告")
    r.add_argument("--cases", default=str(DEFAULT_CASES))
    r.add_argument("--model", default=None)
    r.add_argument("--ids", help="逗号分隔的用例 ID")
    r.add_argument("--tags", help="按标签筛选（任一命中）")
    r.add_argument("--exclude-tags", default="", help="排除标签")
    r.add_argument("--versions", help="v1,v2c,v3")
    r.add_argument("--ops", help="GET,GETNEXT,GETBULK,SET,TRAP,INFORM")
    r.add_argument("--modules", help="模块名")
    r.add_argument("--categories", help="normal,boundary,invalid,access,trap,compat")
    r.add_argument("--limit", type=int, default=0, help="最多执行 N 条（覆盖配置）")
    r.add_argument("--rerun", help="从历史 results.json 或 run 目录重跑失败/错误用例")
    r.add_argument("--run-id", help="指定运行 ID（可重复执行对比）")
    r.add_argument("--mode", choices=["mock", "live"], help="覆盖配置中的运行模式")
    r.add_argument("--allow-live", action="store_true", help="显式确认连接真实设备")
    r.add_argument("--allow-guarded", action="store_true", help="显式放行白名单内的高危 SET（危险）")
    r.add_argument("--no-set", action="store_true", help="本次运行完全禁用 SET")
    r.add_argument("--dry-run", action="store_true", help="只筛选与调度，不发送任何 PDU")
    r.set_defaults(func=cmd_run)

    m = sub.add_parser("mock-agent", help="单独启动本地模拟 Agent")
    m.add_argument("--seconds", type=int, default=0, help="运行 N 秒后退出，0 表示常驻")
    m.set_defaults(func=cmd_mock_agent)

    p = sub.add_parser("report", help="从已有 results.json 重新生成报告")
    p.add_argument("run_dir", help="runs/<run_id> 目录")
    p.add_argument("--cases", default=str(DEFAULT_CASES))
    p.set_defaults(func=cmd_report)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return int(args.func(args) or 0)
    except KeyboardInterrupt:
        print("\n已中断。", file=sys.stderr)
        return 130


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
