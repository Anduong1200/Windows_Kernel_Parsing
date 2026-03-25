"""
FastDiff CLI — Headless entry point for binary diff operations.

No GUI dependencies. All heavy imports are lazy-loaded.

Usage:
    python -m logic_flow.cli info   --export <path.json>
    python -m logic_flow.cli diff   --old <old.json> --new <new.json> [--top-k 20]
    python -m logic_flow.cli bench  --old <old.json> --new <new.json>
    python -m logic_flow.cli export --idb <path.idb> [--out <path.json>]
"""

import argparse
import json
import logging
import sys
import time
from pathlib import Path

logger = logging.getLogger("fastdiff")


# -----------------------------------------------------------------------
# Subcommand: info
# -----------------------------------------------------------------------
def cmd_info(args: argparse.Namespace) -> int:
    """Print summary stats for an export JSON."""
    from .core.protocol_v2 import DriverAnalysisExportV2, validate_export

    path = Path(args.export)
    if not path.exists():
        logger.error(f"File not found: {path}")
        return 1

    with open(path, "r", encoding="utf-8") as f:
        raw = json.load(f)

    errors = validate_export(raw)
    if errors:
        print("[!] Schema validation warnings:")
        for e in errors:
            print(f"   - {e}")

    export = DriverAnalysisExportV2.from_dict(raw)
    m = export.metadata

    print("--- Export Info -----------------------------------")
    print(f"  Schema version : {m.schema_version}")
    print(f"  Binary SHA256  : {m.binary_sha256[:16]}..." if m.binary_sha256 else "  Binary SHA256  : (not set)")
    print(f"  Input file     : {m.input_file}")
    print(f"  Arch / Format  : {m.arch} / {m.file_format}")
    print(f"  Tool           : {m.tool}")
    print(f"  Timestamp      : {m.timestamp}")
    print()
    print(f"  Functions      : {len(export.functions):,}")
    print(f"  Call edges     : {len(export.call_graph):,}")
    print(f"  Strings        : {len(export.strings):,}")
    print(f"  Imports        : {len(export.imports):,}")
    print(f"  Exports        : {len(export.exports):,}")
    print(f"  IOCTLs         : {len(export.driver_interface.ioctls):,}")
    print(f"  Dispatch table : {len(export.driver_interface.dispatch_table):,}")
    n_with_insns = sum(1 for v in export.function_instructions.values() if v)
    print(f"  Funcs w/ insns : {n_with_insns:,}")
    print("---------------------------------------------------")
    return 0


# -----------------------------------------------------------------------
# Subcommand: diff
# -----------------------------------------------------------------------
def cmd_diff(args: argparse.Namespace) -> int:
    """Run the two-stage diff pipeline on two exports."""
    from .core.protocol_v2 import DriverAnalysisExportV2
    from .core.diff_pipeline import DiffPipeline

    old_path = Path(args.old)
    new_path = Path(args.new)
    for p in (old_path, new_path):
        if not p.exists():
            logger.error(f"File not found: {p}")
            return 1

    t0 = time.perf_counter()
    old_export = DriverAnalysisExportV2.load(str(old_path))
    new_export = DriverAnalysisExportV2.load(str(new_path))
    t_load = time.perf_counter() - t0

    pipeline = DiffPipeline(top_k=args.top_k)
    t1 = time.perf_counter()
    report = pipeline.run(old_export, new_export)
    t_diff = time.perf_counter() - t1

    # Print report
    print("\n=== FastDiff Report ===============================")
    print(f"  Old: {old_export.metadata.input_file} ({len(old_export.functions):,} funcs)")
    print(f"  New: {new_export.metadata.input_file} ({len(new_export.functions):,} funcs)")
    print()
    print(f"  Matched        : {len(report.matched):,}")
    print(f"  Unmatched (old): {len(report.unmatched_old):,}")
    print(f"  Unmatched (new): {len(report.unmatched_new):,}")
    print()
    print(f"  Load time      : {t_load:.3f}s")
    print(f"  Diff time      : {t_diff:.3f}s")
    print("==================================================\n")

    # Top changed functions
    changed = [m for m in report.matched if m.score < 1.0]
    changed.sort(key=lambda m: m.score)
    if changed:
        print(f"  Top {min(20, len(changed))} changed functions:")
        for m in changed[:20]:
            print(f"    {m.score:.2f}  {m.name_old:<40s}  {m.match_type}")
        print()

    # Save JSON report if requested
    if args.output:
        report_dict = {
            "matched": [
                {"old_ea": m.old_ea, "new_ea": m.new_ea, "score": m.score,
                 "match_type": m.match_type, "name_old": m.name_old,
                 "name_new": m.name_new}
                for m in report.matched
            ],
            "unmatched_old": report.unmatched_old,
            "unmatched_new": report.unmatched_new,
            "stats": report.stats,
        }
        with open(args.output, "w", encoding="utf-8") as f:
            json.dump(report_dict, f, indent=2)
        print(f"  Report saved to: {args.output}")

    return 0


# -----------------------------------------------------------------------
# Subcommand: bench
# -----------------------------------------------------------------------
def cmd_bench(args: argparse.Namespace) -> int:
    """Run benchmark on a diff pair."""
    from .bench import run_benchmark

    old_path = Path(args.old)
    new_path = Path(args.new)
    for p in (old_path, new_path):
        if not p.exists():
            logger.error(f"File not found: {p}")
            return 1

    results = run_benchmark(str(old_path), str(new_path))

    print("\n=== FastDiff Benchmark ============================")
    for key, val in results.items():
        if isinstance(val, float):
            print(f"  {key:<20s}: {val:.4f}s")
        else:
            print(f"  {key:<20s}: {val}")
    print("==================================================\n")
    return 0


# -----------------------------------------------------------------------
# Main
# -----------------------------------------------------------------------
def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="fastdiff",
        description="FastDiff — Production binary diffing for Windows drivers",
    )
    parser.add_argument(
        "-v", "--verbose", action="store_true", help="Enable debug logging"
    )
    sub = parser.add_subparsers(dest="command", required=True)

    # info
    p_info = sub.add_parser("info", help="Show export summary")
    p_info.add_argument("--export", required=True, help="Path to export JSON")

    # diff
    p_diff = sub.add_parser("diff", help="Diff two binary exports")
    p_diff.add_argument("--old", required=True, help="Old export JSON")
    p_diff.add_argument("--new", required=True, help="New export JSON")
    p_diff.add_argument("--top-k", type=int, default=20, help="Top-K refinement (default: 20)")
    p_diff.add_argument("--output", "-o", default=None, help="Save report JSON to path")

    # bench
    p_bench = sub.add_parser("bench", help="Benchmark diff pipeline")
    p_bench.add_argument("--old", required=True, help="Old export JSON")
    p_bench.add_argument("--new", required=True, help="New export JSON")

    args = parser.parse_args(argv)

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )

    if args.command == "info":
        return cmd_info(args)
    elif args.command == "diff":
        return cmd_diff(args)
    elif args.command == "bench":
        return cmd_bench(args)
    else:
        parser.print_help()
        return 1


if __name__ == "__main__":
    sys.exit(main())
