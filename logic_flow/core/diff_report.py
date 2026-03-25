"""
Diff Report — Output model for FastDiff pipeline results.

Lightweight dataclasses used by diff_pipeline.py and consumed by CLI/GUI.
"""

from __future__ import annotations
from dataclasses import dataclass, field
from typing import List, Dict, Any


@dataclass(slots=True)
class FunctionMatch:
    """A single function-level match between old and new binary."""
    old_ea: int
    new_ea: int
    score: float            # 0.0 – 1.0  (1.0 = identical)
    match_type: str         # "exact_name" | "exact_hash" | "sketch" | "wl_refined"
    name_old: str = ""
    name_new: str = ""


@dataclass
class DiffReport:
    """Complete diff result."""
    matched: List[FunctionMatch] = field(default_factory=list)
    unmatched_old: List[int] = field(default_factory=list)
    unmatched_new: List[int] = field(default_factory=list)
    stats: Dict[str, Any] = field(default_factory=dict)

    @property
    def match_rate(self) -> float:
        total = len(self.matched) + len(self.unmatched_old)
        return len(self.matched) / total if total > 0 else 0.0

    def summary(self) -> str:
        return (
            f"Matched: {len(self.matched)}, "
            f"Unmatched old: {len(self.unmatched_old)}, "
            f"Unmatched new: {len(self.unmatched_new)}, "
            f"Match rate: {self.match_rate:.1%}"
        )
