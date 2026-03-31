"""
BinDiff Benchmark Framework — Structured comparison with precision/recall/F1.

Compares FastDiff's matching capabilities against:
  1. Auto-generated ground truth (name-matched + hash-verified)
  2. BinDiff's SQLite results database (when available)

Metrics:
  - Precision:  % of reported matches that are correct
  - Recall:     % of true matches found
  - F1 Score:   Harmonic mean of precision/recall
  - Unique:     Matches only one tool found
  - Timing:     Wall-clock + peak RSS
"""

from __future__ import annotations
import logging
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

from .protocol_v2 import DriverAnalysisExportV2
from .diff_pipeline import DiffPipeline
from .diff_report import DiffReport
from .ground_truth import GroundTruth, generate_ground_truth

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Result models
# ---------------------------------------------------------------------------
@dataclass
class BenchmarkResult:
    """Benchmark metrics for a single tool run."""
    tool_name: str
    precision: float = 0.0
    recall: float = 0.0
    f1_score: float = 0.0
    match_count: int = 0
    true_positives: int = 0
    false_positives: int = 0
    false_negatives: int = 0
    unique_matches: int = 0       # matches only this tool found
    wall_clock_secs: float = 0.0
    peak_rss_mb: float = 0.0
    matched_pairs: List[Tuple[int, int]] = field(default_factory=list)

    def summary(self) -> str:
        return (
            f"{self.tool_name:12s} | "
            f"P={self.precision:.1%} R={self.recall:.1%} F1={self.f1_score:.1%} | "
            f"TP={self.true_positives} FP={self.false_positives} FN={self.false_negatives} | "
            f"{self.wall_clock_secs:.3f}s {self.peak_rss_mb:.0f}MB"
        )


@dataclass
class ComparisonReport:
    """Side-by-side comparison of two tools."""
    ground_truth_size: int = 0
    fastdiff_result: Optional[BenchmarkResult] = None
    bindiff_result: Optional[BenchmarkResult] = None
    only_fastdiff: List[Tuple[int, int]] = field(default_factory=list)
    only_bindiff: List[Tuple[int, int]] = field(default_factory=list)
    agreed: List[Tuple[int, int]] = field(default_factory=list)
    stats: Dict[str, Any] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Benchmark Engine
# ---------------------------------------------------------------------------
class BinDiffBenchmark:
    """
    Compare FastDiff vs BinDiff (or ground truth) on a driver pair.

    Usage:
        gt = generate_ground_truth(old, new)
        bench = BinDiffBenchmark(gt)
        fd_result = bench.run_fastdiff(old, new)
        bd_result = bench.load_bindiff_results("pair.BinDiff")
        report = bench.compare(fd_result, bd_result)
    """

    def __init__(self, ground_truth: GroundTruth):
        self.ground_truth = ground_truth
        self._gt_set: Set[Tuple[int, int]] = ground_truth.pair_set

    def run_fastdiff(
        self,
        old_export: DriverAnalysisExportV2,
        new_export: DriverAnalysisExportV2,
        top_k: int = 20,
    ) -> BenchmarkResult:
        """
        Run FastDiff pipeline and evaluate against ground truth.

        Returns BenchmarkResult with precision/recall/F1.
        """
        try:
            import psutil
            import os
            process = psutil.Process(os.getpid())
            rss_before = process.memory_info().rss / (1024 * 1024)
        except ImportError:
            rss_before = 0.0

        # Run pipeline
        pipeline = DiffPipeline(top_k=top_k)
        t0 = time.perf_counter()
        report = pipeline.run(old_export, new_export)
        elapsed = time.perf_counter() - t0

        try:
            rss_after = process.memory_info().rss / (1024 * 1024)
        except NameError:
            rss_after = 0.0

        # Evaluate
        matched_pairs = [(m.old_ea, m.new_ea) for m in report.matched]
        result = self._evaluate("FastDiff", matched_pairs)
        result.wall_clock_secs = elapsed
        result.peak_rss_mb = max(rss_after, rss_before)

        return result

    def run_fastdiff_from_report(self, report: DiffReport) -> BenchmarkResult:
        """Evaluate an existing DiffReport against ground truth."""
        matched_pairs = [(m.old_ea, m.new_ea) for m in report.matched]
        return self._evaluate("FastDiff", matched_pairs)

    def load_bindiff_results(
        self,
        bindiff_db_path: str,
    ) -> BenchmarkResult:
        """
        Load BinDiff results from its SQLite database and evaluate.

        BinDiff databases are SQLite3 files with a functionmatch table.
        """
        from .ground_truth import import_from_bindiff

        path = Path(bindiff_db_path)
        if not path.exists():
            raise FileNotFoundError(f"BinDiff database not found: {path}")

        # Parse BinDiff results
        bd_gt = import_from_bindiff(bindiff_db_path)
        matched_pairs = [(p.old_ea, p.new_ea) for p in bd_gt.pairs]

        return self._evaluate("BinDiff", matched_pairs)

    def create_synthetic_bindiff_result(
        self,
        noise_ratio: float = 0.05,
        miss_ratio: float = 0.1,
    ) -> BenchmarkResult:
        """
        Create a synthetic BinDiff result for benchmarking when
        no real BinDiff database is available.

        Simulates BinDiff by:
          1. Taking all ground truth pairs (as if BinDiff found them)
          2. Removing a fraction (miss_ratio) to simulate misses
          3. Adding noise (noise_ratio) false matches

        Args:
            noise_ratio: Fraction of false positives to add
            miss_ratio: Fraction of true matches to miss

        Returns:
            BenchmarkResult simulating BinDiff
        """
        import random

        gt_pairs = list(self._gt_set)
        random.shuffle(gt_pairs)

        # Miss some matches
        n_miss = int(len(gt_pairs) * miss_ratio)
        kept = gt_pairs[n_miss:]

        # Add noise
        n_noise = int(len(gt_pairs) * noise_ratio)
        noise_pairs = []
        for _ in range(n_noise):
            fake_old = random.randint(0x140000000, 0x14FFFFFFF)
            fake_new = random.randint(0x140000000, 0x14FFFFFFF)
            noise_pairs.append((fake_old, fake_new))

        all_pairs = kept + noise_pairs
        return self._evaluate("BinDiff (synthetic)", all_pairs)

    def compare(
        self,
        fastdiff_result: BenchmarkResult,
        bindiff_result: Optional[BenchmarkResult] = None,
    ) -> ComparisonReport:
        """
        Generate a side-by-side comparison report.
        """
        fd_set = set(fastdiff_result.matched_pairs)
        bd_set = set(bindiff_result.matched_pairs) if bindiff_result else set()

        only_fd = sorted(fd_set - bd_set)
        only_bd = sorted(bd_set - fd_set)
        agreed = sorted(fd_set & bd_set)

        # Update unique match counts
        fastdiff_result.unique_matches = len(only_fd)
        if bindiff_result:
            bindiff_result.unique_matches = len(only_bd)

        report = ComparisonReport(
            ground_truth_size=len(self._gt_set),
            fastdiff_result=fastdiff_result,
            bindiff_result=bindiff_result,
            only_fastdiff=only_fd,
            only_bindiff=only_bd,
            agreed=agreed,
            stats={
                "ground_truth_pairs": len(self._gt_set),
                "agreed_matches": len(agreed),
                "only_fastdiff": len(only_fd),
                "only_bindiff": len(only_bd),
            },
        )

        return report

    # ── Internal helpers ──────────────────────────────────────────────

    def _evaluate(
        self,
        tool_name: str,
        matched_pairs: List[Tuple[int, int]],
    ) -> BenchmarkResult:
        """Compute precision/recall/F1 against ground truth."""
        match_set = set(matched_pairs)

        true_positives = len(match_set & self._gt_set)
        false_positives = len(match_set - self._gt_set)
        false_negatives = len(self._gt_set - match_set)

        precision = (
            true_positives / (true_positives + false_positives)
            if (true_positives + false_positives) > 0
            else 0.0
        )
        recall = (
            true_positives / (true_positives + false_negatives)
            if (true_positives + false_negatives) > 0
            else 0.0
        )
        f1 = (
            2 * precision * recall / (precision + recall)
            if (precision + recall) > 0
            else 0.0
        )

        return BenchmarkResult(
            tool_name=tool_name,
            precision=precision,
            recall=recall,
            f1_score=f1,
            match_count=len(matched_pairs),
            true_positives=true_positives,
            false_positives=false_positives,
            false_negatives=false_negatives,
            matched_pairs=matched_pairs,
        )


# ---------------------------------------------------------------------------
# Convenience: run full benchmark from CLI
# ---------------------------------------------------------------------------
def run_full_benchmark(
    old_path: str,
    new_path: str,
    bindiff_path: Optional[str] = None,
) -> ComparisonReport:
    """
    Run a complete benchmark: FastDiff vs (optional) BinDiff on a driver pair.

    Args:
        old_path: Path to old driver export JSON
        new_path: Path to new driver export JSON
        bindiff_path: Optional path to .BinDiff SQLite database

    Returns:
        ComparisonReport with detailed metrics
    """
    old_export = DriverAnalysisExportV2.load(old_path)
    new_export = DriverAnalysisExportV2.load(new_path)

    # Generate ground truth
    gt = generate_ground_truth(old_export, new_export)
    logger.info(f"Ground truth: {len(gt.pairs)} verified pairs")

    bench = BinDiffBenchmark(gt)

    # Run FastDiff
    fd_result = bench.run_fastdiff(old_export, new_export)

    # Run BinDiff (or synthetic)
    bd_result = None
    if bindiff_path and Path(bindiff_path).exists():
        bd_result = bench.load_bindiff_results(bindiff_path)
    else:
        bd_result = bench.create_synthetic_bindiff_result()

    # Compare
    return bench.compare(fd_result, bd_result)


def format_comparison_report(report: ComparisonReport) -> str:
    """Format a ComparisonReport as a human-readable string."""
    lines = []
    lines.append("=" * 70)
    lines.append("  FastDiff vs BinDiff Benchmark Report")
    lines.append("=" * 70)
    lines.append(f"  Ground Truth: {report.ground_truth_size} verified function pairs")
    lines.append("")

    # Results table header
    lines.append(f"  {'Metric':<24s} {'FastDiff':>12s} {'BinDiff':>12s}")
    lines.append("  " + "-" * 50)

    fd = report.fastdiff_result
    bd = report.bindiff_result

    def fmt(fd_val, bd_val, is_pct=False):
        if is_pct:
            fd_str = f"{fd_val:.1%}" if fd else "N/A"
            bd_str = f"{bd_val:.1%}" if bd else "N/A"
        else:
            fd_str = str(fd_val) if fd else "N/A"
            bd_str = str(bd_val) if bd else "N/A"
        return fd_str, bd_str

    rows = [
        ("Precision", fd.precision if fd else 0, bd.precision if bd else 0, True),
        ("Recall", fd.recall if fd else 0, bd.recall if bd else 0, True),
        ("F1 Score", fd.f1_score if fd else 0, bd.f1_score if bd else 0, True),
        ("True Positives", fd.true_positives if fd else 0, bd.true_positives if bd else 0, False),
        ("False Positives", fd.false_positives if fd else 0, bd.false_positives if bd else 0, False),
        ("False Negatives", fd.false_negatives if fd else 0, bd.false_negatives if bd else 0, False),
        ("Total Matches", fd.match_count if fd else 0, bd.match_count if bd else 0, False),
        ("Unique Matches", fd.unique_matches if fd else 0, bd.unique_matches if bd else 0, False),
    ]

    for label, fd_val, bd_val, is_pct in rows:
        fd_str, bd_str = fmt(fd_val, bd_val, is_pct)
        lines.append(f"  {label:<24s} {fd_str:>12s} {bd_str:>12s}")

    lines.append("")

    if fd:
        lines.append(f"  FastDiff Time:  {fd.wall_clock_secs:.3f}s  ({fd.peak_rss_mb:.0f} MB RSS)")
    if bd:
        lines.append(f"  BinDiff  Time:  {bd.wall_clock_secs:.3f}s  ({bd.peak_rss_mb:.0f} MB RSS)")

    lines.append("")
    lines.append(f"  Agreed Matches:        {len(report.agreed)}")
    lines.append(f"  Only FastDiff:         {len(report.only_fastdiff)}")
    lines.append(f"  Only BinDiff:          {len(report.only_bindiff)}")

    lines.append("=" * 70)
    return "\n".join(lines)
