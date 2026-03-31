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
# Subcommand: security-diff
# -----------------------------------------------------------------------
def cmd_security_diff(args: argparse.Namespace) -> int:
    """Run security-aware diff with guard/sink/IOCTL analysis."""
    from .core.protocol_v2 import DriverAnalysisExportV2
    from .core.diff_pipeline import DiffPipeline
    from .core.security_diff import SecurityDiffEngine

    old_path = Path(args.old)
    new_path = Path(args.new)
    for p in (old_path, new_path):
        if not p.exists():
            logger.error(f"File not found: {p}")
            return 1

    # Run structural diff first
    old_export = DriverAnalysisExportV2.load(str(old_path))
    new_export = DriverAnalysisExportV2.load(str(new_path))

    pipeline = DiffPipeline(top_k=args.top_k)
    diff_report = pipeline.run(old_export, new_export)

    # Run security diff
    engine = SecurityDiffEngine(diff_report=diff_report)
    sec_report = engine.run(old_export, new_export, diff_report)

    # Print security report
    print("\n=== FastDiff Security Report =======================")
    print(f"  Old: {old_export.metadata.input_file}")
    print(f"  New: {new_export.metadata.input_file}")
    print()

    # Findings
    if sec_report.findings:
        print(f"  --- Security Findings ({len(sec_report.findings)}) ---")
        for f in sec_report.findings:
            icon = {"critical": "[!!]", "high": "[!]", "medium": "[*]",
                     "low": "[-]", "info": "[i]"}.get(f.risk.value, "[?]")
            print(f"  {icon} [{f.risk.value.upper():8s}] {f.title}")
            print(f"      {f.detail}")
            if f.related_apis:
                print(f"      APIs: {', '.join(f.related_apis)}")
        print()
    else:
        print("  No security findings.\n")

    # IOCTL deltas
    if sec_report.ioctl_deltas:
        print(f"  --- IOCTL Changes ({len(sec_report.ioctl_deltas)}) ---")
        for d in sec_report.ioctl_deltas:
            print(f"  [{d.change:16s}] code=0x{d.code:08X} method={d.method}")
            if d.old_input_size != d.new_input_size:
                print(f"      input_size: {d.old_input_size} -> {d.new_input_size}")
        print()

    # Dispatch deltas
    if sec_report.dispatch_deltas:
        print(f"  --- Dispatch Table Changes ({len(sec_report.dispatch_deltas)}) ---")
        for d in sec_report.dispatch_deltas:
            print(f"  [{d.change:16s}] MJ={d.major_function} "
                  f"old={d.old_handler} new={d.new_handler}")
        print()

    # Fuzz targets
    if sec_report.fuzz_targets:
        print(f"  --- Fuzz Targets ({len(sec_report.fuzz_targets)}) ---")
        for t in sec_report.fuzz_targets:
            print(f"  P{t.priority} | 0x{t.ioctl_code:08X} | {t.method:12s} | "
                  f"{t.handler_name}")
            print(f"       {t.reason}")
        print()

    print("==================================================\n")

    # Save JSON if requested
    if args.output:
        import json as _json
        out = {
            "findings": [
                {"category": f.category, "risk": f.risk.value, "title": f.title,
                 "detail": f.detail, "func_name": f.func_name,
                 "related_apis": f.related_apis,
                 "old_ea": f.old_ea, "new_ea": f.new_ea}
                for f in sec_report.findings
            ],
            "ioctl_deltas": [
                {"code": d.code, "method": d.method, "change": d.change,
                 "risk": d.risk.value}
                for d in sec_report.ioctl_deltas
            ],
            "fuzz_targets": [
                {"ioctl_code": t.ioctl_code, "method": t.method,
                 "handler_name": t.handler_name, "priority": t.priority,
                 "reason": t.reason, "input_size": t.input_size}
                for t in sec_report.fuzz_targets
            ],
            "stats": sec_report.stats,
        }
        with open(args.output, "w", encoding="utf-8") as f:
            _json.dump(out, f, indent=2)
        print(f"  Report saved to: {args.output}")

    return 0


# -----------------------------------------------------------------------
# Subcommand: index
# -----------------------------------------------------------------------
def cmd_index(args: argparse.Namespace) -> int:
    """Index a binary export into the persistent store."""
    from .core.protocol_v2 import DriverAnalysisExportV2
    from .core.index_store import IndexStore

    export_path = Path(args.export)
    if not export_path.exists():
        logger.error(f"File not found: {export_path}")
        return 1

    export = DriverAnalysisExportV2.load(str(export_path))

    store = IndexStore(args.db)
    try:
        record = store.index_binary(export, family=args.family)

        print("\n=== Indexed Binary ================================")
        print(f"  SHA256      : {record.sha256[:16]}...")
        print(f"  Filename    : {record.filename}")
        print(f"  Family      : {record.driver_family}")
        print(f"  Functions   : {record.func_count:,}")
        print(f"  Imports     : {record.import_count:,}")
        print(f"  Indexed at  : {record.indexed_at}")
        print(f"  DB path     : {args.db}")
        print("===================================================\n")
    finally:
        store.close()

    return 0


# -----------------------------------------------------------------------
# Subcommand: query
# -----------------------------------------------------------------------
def cmd_query(args: argparse.Namespace) -> int:
    """Query the index for similar binaries."""
    from .core.protocol_v2 import DriverAnalysisExportV2
    from .core.index_store import IndexStore
    from .core.query_pipeline import QueryPipeline

    export_path = Path(args.export)
    if not export_path.exists():
        logger.error(f"File not found: {export_path}")
        return 1

    export = DriverAnalysisExportV2.load(str(export_path))

    store = IndexStore(args.db)
    try:
        pipeline = QueryPipeline(store, refine_top_n=args.refine)
        result = pipeline.query_binary(
            export,
            top_k=args.top_k,
            family=args.family,
            skip_refine=args.no_refine,
        )

        print("\n=== FastDiff Query Results =========================")
        print(f"  Target: {result.target_filename}")
        print(f"  Candidates scanned: {result.total_candidates_scanned}")
        print(f"  Functions compared: {result.total_functions_compared}")
        print()

        if result.similar_binaries:
            print(f"  Top {len(result.similar_binaries)} similar binaries:")
            for i, sim in enumerate(result.similar_binaries, 1):
                print(f"  {i:2d}. {sim.filename:<40s} "
                      f"score={sim.overall_score:.2f} "
                      f"family={sim.family:<12s} "
                      f"matched={sim.matched_functions}/{sim.total_functions}")
                if sim.function_hits:
                    for h in sim.function_hits[:3]:
                        print(f"      -> {h.func_name:<36s} sim={h.similarity_score}%")
            print()
        else:
            print("  No similar binaries found.\n")

        for stage, t in result.stage_timings.items():
            print(f"  {stage:<20s}: {t:.3f}s")
        print("===================================================\n")
    finally:
        store.close()

    return 0


# -----------------------------------------------------------------------
# Subcommand: benchmark
# -----------------------------------------------------------------------
def cmd_benchmark(args: argparse.Namespace) -> int:
    """Run benchmark: FastDiff vs BinDiff on a driver pair."""
    from .core.benchmark import run_full_benchmark, format_comparison_report

    old_path = Path(args.old)
    new_path = Path(args.new)
    for p in (old_path, new_path):
        if not p.exists():
            logger.error(f"File not found: {p}")
            return 1

    bindiff_path = args.bindiff if hasattr(args, 'bindiff') else None

    report = run_full_benchmark(
        str(old_path), str(new_path), bindiff_path
    )

    print()
    print(format_comparison_report(report))
    print()

    # Save JSON if requested
    if args.output:
        import json as _json
        out = {
            "ground_truth_size": report.ground_truth_size,
            "fastdiff": {
                "precision": report.fastdiff_result.precision,
                "recall": report.fastdiff_result.recall,
                "f1_score": report.fastdiff_result.f1_score,
                "match_count": report.fastdiff_result.match_count,
                "true_positives": report.fastdiff_result.true_positives,
                "false_positives": report.fastdiff_result.false_positives,
                "wall_clock_secs": report.fastdiff_result.wall_clock_secs,
                "peak_rss_mb": report.fastdiff_result.peak_rss_mb,
            } if report.fastdiff_result else None,
            "bindiff": {
                "precision": report.bindiff_result.precision,
                "recall": report.bindiff_result.recall,
                "f1_score": report.bindiff_result.f1_score,
                "match_count": report.bindiff_result.match_count,
                "true_positives": report.bindiff_result.true_positives,
                "false_positives": report.bindiff_result.false_positives,
            } if report.bindiff_result else None,
            "agreed_matches": len(report.agreed),
            "only_fastdiff": len(report.only_fastdiff),
            "only_bindiff": len(report.only_bindiff),
        }
        with open(args.output, "w", encoding="utf-8") as f:
            _json.dump(out, f, indent=2)
        print(f"  Report saved to: {args.output}")

    return 0


# -----------------------------------------------------------------------
# Subcommand: families
# -----------------------------------------------------------------------
def cmd_families(args: argparse.Namespace) -> int:
    """List indexed driver families and statistics."""
    from .core.index_store import IndexStore
    from .core.driver_families import get_family_description

    store = IndexStore(args.db)
    try:
        stats = store.get_family_stats()
        total_binaries = store.get_binary_count()
        total_sketches = store.get_total_sketch_count()

        print("\n=== Driver Family Index ============================")
        print(f"  Total binaries : {total_binaries:,}")
        print(f"  Total sketches : {total_sketches:,}")
        print()

        if stats:
            print(f"  {'Family':<20s} {'Count':>6s}  Description")
            print("  " + "-" * 60)
            for family, count in stats.items():
                desc = get_family_description(family) if family else "Unclassified"
                print(f"  {family or '(none)':<20s} {count:>6d}  {desc}")
        else:
            print("  No binaries indexed yet.")

        # List recent binaries
        binaries = store.list_binaries(limit=10)
        if binaries:
            print()
            print("  Recent indexed binaries:")
            for b in binaries:
                print(f"    {b.sha256[:12]}.. {b.filename:<30s} "
                      f"family={b.driver_family:<12s} funcs={b.func_count}")

        print("===================================================\n")
    finally:
        store.close()

    return 0


# -----------------------------------------------------------------------
# Subcommand: classify
# -----------------------------------------------------------------------
def cmd_classify(args: argparse.Namespace) -> int:
    """Classify a driver export into a family."""
    from .core.protocol_v2 import DriverAnalysisExportV2
    from .core.driver_families import classify_driver, get_family_description

    export_path = Path(args.export)
    if not export_path.exists():
        logger.error(f"File not found: {export_path}")
        return 1

    export = DriverAnalysisExportV2.load(str(export_path))
    result = classify_driver(export)

    print("\n=== Driver Classification =========================")
    print(f"  Binary     : {export.metadata.input_file}")
    print(f"  Family     : {result.family.value}")
    print(f"  Confidence : {result.confidence:.0%}")
    print(f"  Description: {get_family_description(result.family)}")
    if result.signals:
        print(f"  Signals    : {', '.join(result.signals[:5])}")
    if result.secondary_families:
        secondaries = [f.value for f in result.secondary_families]
        print(f"  Secondary  : {', '.join(secondaries)}")
    print("===================================================\n")
    return 0


# -----------------------------------------------------------------------
# Subcommand: ir-diff
# -----------------------------------------------------------------------
def cmd_ir_diff(args: argparse.Namespace) -> int:
    """Cross-architecture IR-based diff."""
    from .core.protocol_v2 import DriverAnalysisExportV2
    from .core.cross_arch_matcher import CrossArchMatcher

    for p in (args.old, args.new):
        if not Path(p).exists():
            logger.error(f"File not found: {p}")
            return 1

    old_export = DriverAnalysisExportV2.load(args.old)
    new_export = DriverAnalysisExportV2.load(args.new)

    matcher = CrossArchMatcher(fuzzy_threshold=args.threshold)
    report = matcher.match(
        old_export, new_export,
        old_arch=getattr(args, "old_arch", "x64"),
        new_arch=getattr(args, "new_arch", "x64"),
    )

    print(f"\n{'='*62}")
    print("  Cross-Arch IR Diff Report")
    print(f"{'='*62}")
    print(f"  Old: {report.old_file} ({report.old_arch})")
    print(f"  New: {report.new_file} ({report.new_arch})")
    print(f"  Matched:       {report.match_count}")
    print(f"  Unmatched old: {len(report.unmatched_old)}")
    print(f"  Unmatched new: {len(report.unmatched_new)}")
    print(f"  Match rate:    {report.match_rate:.1%}")
    print()

    if report.matched:
        print(f"  {'Old Function':<30s} {'New Function':<30s} {'Sim':>5s}  Type")
        print(f"  {'-'*30} {'-'*30} {'-'*5}  {'-'*15}")
        for m in sorted(report.matched, key=lambda x: x.ir_similarity, reverse=True):
            print(f"  {m.old_name:<30s} {m.new_name:<30s} "
                  f"{m.ir_similarity:5.0%}  {m.match_type}")

    print()
    for k, v in report.stats.items():
        if isinstance(v, float):
            print(f"  {k:<22s}: {v:.3f}s")
    print(f"{'='*62}\n")

    if args.output:
        import json
        data = {
            "old_file": report.old_file,
            "new_file": report.new_file,
            "old_arch": report.old_arch,
            "new_arch": report.new_arch,
            "match_count": report.match_count,
            "match_rate": report.match_rate,
            "matches": [
                {
                    "old_ea": hex(m.old_ea), "new_ea": hex(m.new_ea),
                    "old_name": m.old_name, "new_name": m.new_name,
                    "ir_similarity": m.ir_similarity,
                    "match_type": m.match_type,
                } for m in report.matched
            ],
            "stats": report.stats,
        }
        Path(args.output).write_text(json.dumps(data, indent=2))
        print(f"  Report saved to: {args.output}")

    return 0


# -----------------------------------------------------------------------
# Subcommand: verify
# -----------------------------------------------------------------------
def cmd_verify(args: argparse.Namespace) -> int:
    """Verify function pair equivalence."""
    from .core.protocol_v2 import DriverAnalysisExportV2
    from .core.selective_equivalence import verify_function_pair, batch_verify


    for p in (args.old, args.new):
        if not Path(p).exists():
            logger.error(f"File not found: {p}")
            return 1

    old_export = DriverAnalysisExportV2.load(args.old)
    new_export = DriverAnalysisExportV2.load(args.new)

    old_arch = getattr(args, "old_arch", "x64")
    new_arch = getattr(args, "new_arch", "x64")

    if getattr(args, "all", False):
        # Verify all name-matched pairs
        old_names = {fi.name: fi.ea for fi in old_export.functions.values()
                     if not fi.is_import}
        new_names = {fi.name: fi.ea for fi in new_export.functions.values()
                     if not fi.is_import}
        common = set(old_names) & set(new_names)
        pairs = [(old_names[n], new_names[n]) for n in common]

        if not pairs:
            print("No common function names found.")
            return 0

        results = batch_verify(
            old_export, new_export, pairs,
            old_arch=old_arch, new_arch=new_arch,
        )

        print(f"\n{'='*62}")
        print("  Equivalence Verification Report")
        print(f"{'='*62}")
        print(f"  Pairs verified: {len(results)}")
        eq_count = sum(1 for r in results.values() if r.status == "equivalent")
        diff_count = sum(1 for r in results.values() if r.status == "different")
        inc_count = sum(1 for r in results.values() if r.status == "inconclusive")
        print(f"  Equivalent:     {eq_count}")
        print(f"  Different:      {diff_count}")
        print(f"  Inconclusive:   {inc_count}")
        print()

        name_map = {**{ea: n for n, ea in old_names.items()}}
        for (old_ea, new_ea), result in sorted(
            results.items(),
            key=lambda x: x[1].confidence,
            reverse=True,
        ):
            fname = name_map.get(old_ea, f"sub_{old_ea:X}")
            status_icon = {"equivalent": "+", "different": "!", "inconclusive": "?"}
            icon = status_icon.get(result.status, " ")
            print(f"  [{icon}] {fname:<36s} {result.status:<14s} "
                  f"conf={result.confidence:.0%}")

        print(f"{'='*62}\n")
    else:
        # Single pair verification
        old_ea = getattr(args, "old_ea", None)
        new_ea = getattr(args, "new_ea", None)
        if old_ea is None or new_ea is None:
            logger.error("--old-ea and --new-ea required (or use --all)")
            return 1

        status = verify_function_pair(
            old_export, new_export,
            old_ea, new_ea,
            old_arch=old_arch, new_arch=new_arch,
        )

        old_fi = old_export.functions.get(str(old_ea))
        new_fi = new_export.functions.get(str(new_ea))
        print(f"\n  Verification: {old_fi.name if old_fi else hex(old_ea)} <-> "
              f"{new_fi.name if new_fi else hex(new_ea)}")
        print(f"  Result: {status}\n")

    return 0


# -----------------------------------------------------------------------
# Main
# -----------------------------------------------------------------------
def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="fastdiff",
        description="FastDiff -- Production binary diffing for Windows drivers",
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

    # security-diff
    p_sec = sub.add_parser("security-diff", help="Security-aware diff with guard/sink analysis")
    p_sec.add_argument("--old", required=True, help="Old export JSON")
    p_sec.add_argument("--new", required=True, help="New export JSON")
    p_sec.add_argument("--top-k", type=int, default=20, help="Top-K refinement")
    p_sec.add_argument("--output", "-o", default=None, help="Save security report JSON")

    # bench (legacy)
    p_bench = sub.add_parser("bench", help="Benchmark diff pipeline (legacy)")
    p_bench.add_argument("--old", required=True, help="Old export JSON")
    p_bench.add_argument("--new", required=True, help="New export JSON")

    # index
    p_index = sub.add_parser("index", help="Index a binary export into persistent store")
    p_index.add_argument("--export", required=True, help="Path to export JSON")
    p_index.add_argument("--family", default=None, help="Override driver family (auto-detected if omitted)")
    p_index.add_argument("--db", default="fastdiff_index.db", help="Index database path (default: fastdiff_index.db)")

    # query
    p_query = sub.add_parser("query", help="Query index for similar binaries")
    p_query.add_argument("--export", required=True, help="Target export JSON to search for")
    p_query.add_argument("--top-k", type=int, default=10, help="Return top-K similar binaries")
    p_query.add_argument("--family", default=None, help="Filter by driver family")
    p_query.add_argument("--refine", type=int, default=3, help="Refine top-N candidates with full diff")
    p_query.add_argument("--no-refine", action="store_true", help="Skip Stage 3 refinement")
    p_query.add_argument("--db", default="fastdiff_index.db", help="Index database path")

    # benchmark
    p_bm = sub.add_parser("benchmark", help="Benchmark FastDiff vs BinDiff")
    p_bm.add_argument("--old", required=True, help="Old export JSON")
    p_bm.add_argument("--new", required=True, help="New export JSON")
    p_bm.add_argument("--bindiff", default=None, help="Path to .BinDiff SQLite database")
    p_bm.add_argument("--output", "-o", default=None, help="Save benchmark report JSON")

    # families
    p_fam = sub.add_parser("families", help="List indexed driver families")
    p_fam.add_argument("--db", default="fastdiff_index.db", help="Index database path")

    # classify
    p_cls = sub.add_parser("classify", help="Classify a driver into a family")
    p_cls.add_argument("--export", required=True, help="Path to export JSON")

    # ir-diff (Phase 4: cross-arch)
    p_ir = sub.add_parser("ir-diff", help="Cross-architecture IR-based diff")
    p_ir.add_argument("--old", required=True, help="Old export JSON")
    p_ir.add_argument("--new", required=True, help="New export JSON")
    p_ir.add_argument("--old-arch", default="x64", help="Old binary architecture")
    p_ir.add_argument("--new-arch", default="x64", help="New binary architecture")
    p_ir.add_argument("--threshold", type=float, default=0.65,
                       help="Minimum similarity threshold (0.0-1.0)")
    p_ir.add_argument("--output", "-o", default=None, help="Save report JSON")

    # verify (Phase 4: selective equivalence)
    p_vfy = sub.add_parser("verify", help="Verify function pair equivalence")
    p_vfy.add_argument("--old", required=True, help="Old export JSON")
    p_vfy.add_argument("--new", required=True, help="New export JSON")
    p_vfy.add_argument("--old-ea", type=lambda x: int(x, 0), default=None,
                        help="Old function EA (hex)")
    p_vfy.add_argument("--new-ea", type=lambda x: int(x, 0), default=None,
                        help="New function EA (hex)")
    p_vfy.add_argument("--old-arch", default="x64", help="Old binary architecture")
    p_vfy.add_argument("--new-arch", default="x64", help="New binary architecture")
    p_vfy.add_argument("--all", action="store_true",
                        help="Verify all name-matched pairs")

    args = parser.parse_args(argv)

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )

    dispatch = {
        "info": cmd_info,
        "diff": cmd_diff,
        "security-diff": cmd_security_diff,
        "bench": cmd_bench,
        "index": cmd_index,
        "query": cmd_query,
        "benchmark": cmd_benchmark,
        "families": cmd_families,
        "classify": cmd_classify,
        "ir-diff": cmd_ir_diff,
        "verify": cmd_verify,
    }

    handler = dispatch.get(args.command)
    if handler:
        return handler(args)
    else:
        parser.print_help()
        return 1


if __name__ == "__main__":
    sys.exit(main())

