"""
FastDiff Benchmark Harness.

Measures:
  - load_time:    JSON deserialization
  - feature_time: sketch/hash computation
  - diff_time:    full pipeline wall-clock
  - peak_rss:     max resident memory (MB)
"""

from __future__ import annotations
import time
from typing import Any, Dict


def run_benchmark(old_path: str, new_path: str) -> Dict[str, Any]:
    """
    Run a full benchmark on a diff pair.

    Returns dict of metric_name -> value.
    """
    import psutil
    import os

    process = psutil.Process(os.getpid())
    rss_before = process.memory_info().rss / (1024 * 1024)  # MB

    from .core.protocol_v2 import DriverAnalysisExportV2
    from .core.diff_pipeline import DiffPipeline

    # 1. Load time
    t0 = time.perf_counter()
    old_export = DriverAnalysisExportV2.load(old_path)
    t_load_old = time.perf_counter() - t0

    t0 = time.perf_counter()
    new_export = DriverAnalysisExportV2.load(new_path)
    t_load_new = time.perf_counter() - t0

    # 2. Diff time
    pipeline = DiffPipeline()
    t0 = time.perf_counter()
    report = pipeline.run(old_export, new_export)
    t_diff = time.perf_counter() - t0

    # 3. Peak RSS
    rss_after = process.memory_info().rss / (1024 * 1024)
    peak_rss = rss_after  # Approximation (real peak needs sampling)

    return {
        "load_time_old": round(t_load_old, 4),
        "load_time_new": round(t_load_new, 4),
        "diff_time": round(t_diff, 4),
        "total_time": round(t_load_old + t_load_new + t_diff, 4),
        "peak_rss_mb": round(peak_rss, 1),
        "rss_delta_mb": round(rss_after - rss_before, 1),
        "old_func_count": len(old_export.functions),
        "new_func_count": len(new_export.functions),
        "matched": len(report.matched),
        "unmatched_old": len(report.unmatched_old),
        "unmatched_new": len(report.unmatched_new),
        "match_rate": f"{report.match_rate:.1%}",
    }
