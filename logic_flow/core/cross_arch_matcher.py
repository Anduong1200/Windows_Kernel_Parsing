"""
Cross-Architecture Matcher — Match functions across different architectures.

Combines IR normalization with the index store to enable:
  1. Index x64 driver, query with ARM64 build of same driver
  2. Detect same logic compiled for different targets
  3. Identify cross-platform vulnerability patterns

Pipeline:
  Stage 1: Normalize both binaries to arch-independent IR sequences
  Stage 2: Hash-based exact IR match (fast path)
  Stage 3: Histogram + LCS similarity scoring (fuzzy path)
  Stage 4: Optional symbolic equivalence verification (selective)

Integrates with IndexStore for persistent IR sketch storage.
"""

from __future__ import annotations
import logging
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional

from .protocol_v2 import DriverAnalysisExportV2
from .ir_normalizer import (
    IRSequence,
    compare_ir_sequences,
    normalize_export,
)


logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Result models
# ---------------------------------------------------------------------------
@dataclass
class CrossArchMatch:
    """A single cross-architecture function match."""
    old_ea: int
    new_ea: int
    old_name: str
    new_name: str
    old_arch: str
    new_arch: str
    ir_similarity: float           # 0.0-1.0 from IR comparison
    match_type: str = "ir_hash"    # "ir_hash" | "ir_fuzzy" | "verified"
    ir_hash_old: str = ""
    ir_hash_new: str = ""
    verification_status: str = ""  # "" | "equivalent" | "different" | "timeout"

    @property
    def score(self) -> float:
        return self.ir_similarity


@dataclass
class CrossArchReport:
    """Complete cross-architecture comparison result."""
    old_file: str
    new_file: str
    old_arch: str
    new_arch: str
    matched: List[CrossArchMatch] = field(default_factory=list)
    unmatched_old: List[int] = field(default_factory=list)
    unmatched_new: List[int] = field(default_factory=list)
    stats: Dict[str, float] = field(default_factory=dict)

    @property
    def match_count(self) -> int:
        return len(self.matched)

    @property
    def match_rate(self) -> float:
        total = self.match_count + len(self.unmatched_old)
        return self.match_count / total if total > 0 else 0.0

    def summary(self) -> str:
        lines = [
            f"Cross-Arch Diff: {self.old_file} ({self.old_arch}) vs "
            f"{self.new_file} ({self.new_arch})",
            f"  Matched:      {self.match_count}",
            f"  Unmatched old: {len(self.unmatched_old)}",
            f"  Unmatched new: {len(self.unmatched_new)}",
            f"  Match rate:    {self.match_rate:.1%}",
        ]
        for k, v in self.stats.items():
            lines.append(f"  {k}: {v:.3f}s" if isinstance(v, float) else f"  {k}: {v}")
        return "\n".join(lines)


# ---------------------------------------------------------------------------
# Cross-Architecture Matcher
# ---------------------------------------------------------------------------
class CrossArchMatcher:
    """
    Match functions between two binaries from different architectures.

    Usage:
        matcher = CrossArchMatcher()
        report = matcher.match(
            old_export,  # x64 driver
            new_export,  # arm64 driver
            old_arch="x64",
            new_arch="arm64",
        )
    """

    def __init__(
        self,
        exact_threshold: float = 0.90,
        fuzzy_threshold: float = 0.65,
        verify_top_n: int = 0,
    ):
        """
        Args:
            exact_threshold: Minimum IR similarity for auto-match
            fuzzy_threshold: Minimum IR similarity for fuzzy candidates
            verify_top_n: Number of top fuzzy matches to verify symbolically
                          (0 = disabled, requires angr)
        """
        self.exact_threshold = exact_threshold
        self.fuzzy_threshold = fuzzy_threshold
        self.verify_top_n = verify_top_n

    def match(
        self,
        old_export: DriverAnalysisExportV2,
        new_export: DriverAnalysisExportV2,
        old_arch: str = "x64",
        new_arch: str = "x64",
    ) -> CrossArchReport:
        """
        Run the full cross-arch matching pipeline.

        Stages:
          1. Normalize both exports to IR sequences
          2. Exact IR hash matching (fast path)
          3. Name-guided + fuzzy IR scoring (slow path)
          4. Optional symbolic verification on flagged pairs

        Args:
            old_export: First binary export
            new_export: Second binary export
            old_arch: Architecture of old binary
            new_arch: Architecture of new binary

        Returns:
            CrossArchReport with matches and statistics
        """
        t0 = time.perf_counter()

        report = CrossArchReport(
            old_file=old_export.metadata.input_file,
            new_file=new_export.metadata.input_file,
            old_arch=old_arch,
            new_arch=new_arch,
        )

        # ── Stage 1: Normalize ────────────────────────────────────────
        t1 = time.perf_counter()
        old_ir = normalize_export(old_export, arch=old_arch)
        new_ir = normalize_export(new_export, arch=new_arch)
        report.stats["normalize_time"] = time.perf_counter() - t1

        logger.info(
            f"Normalized: {len(old_ir)} ({old_arch}) vs "
            f"{len(new_ir)} ({new_arch}) functions"
        )

        matched_old: set = set()
        matched_new: set = set()

        # ── Stage 2: Exact IR hash match ──────────────────────────────
        t2 = time.perf_counter()
        new_by_hash: Dict[str, List[IRSequence]] = {}
        for seq in new_ir.values():
            if seq.ir_hash:
                new_by_hash.setdefault(seq.ir_hash, []).append(seq)

        for old_ea, old_seq in old_ir.items():
            if old_ea in matched_old:
                continue
            if not old_seq.ir_hash:
                continue

            candidates = new_by_hash.get(old_seq.ir_hash, [])
            for new_seq in candidates:
                if new_seq.func_ea in matched_new:
                    continue

                report.matched.append(CrossArchMatch(
                    old_ea=old_ea,
                    new_ea=new_seq.func_ea,
                    old_name=old_seq.func_name,
                    new_name=new_seq.func_name,
                    old_arch=old_arch,
                    new_arch=new_arch,
                    ir_similarity=1.0,
                    match_type="ir_hash",
                    ir_hash_old=old_seq.ir_hash,
                    ir_hash_new=new_seq.ir_hash,
                ))
                matched_old.add(old_ea)
                matched_new.add(new_seq.func_ea)
                break

        report.stats["exact_hash_time"] = time.perf_counter() - t2
        exact_count = len(report.matched)
        logger.info(f"Stage 2 (exact IR hash): {exact_count} matches")

        # ── Stage 3: Name-guided + fuzzy IR matching ──────────────────
        t3 = time.perf_counter()

        # 3a: Name-guided matching (same name → compare IR)
        new_by_name: Dict[str, List[IRSequence]] = {}
        for seq in new_ir.values():
            if seq.func_ea not in matched_new:
                new_by_name.setdefault(seq.func_name, []).append(seq)

        for old_ea, old_seq in old_ir.items():
            if old_ea in matched_old:
                continue
            name_candidates = new_by_name.get(old_seq.func_name, [])
            for new_seq in name_candidates:
                if new_seq.func_ea in matched_new:
                    continue
                sim = compare_ir_sequences(old_seq, new_seq)
                if sim >= self.fuzzy_threshold:
                    report.matched.append(CrossArchMatch(
                        old_ea=old_ea,
                        new_ea=new_seq.func_ea,
                        old_name=old_seq.func_name,
                        new_name=new_seq.func_name,
                        old_arch=old_arch,
                        new_arch=new_arch,
                        ir_similarity=sim,
                        match_type="ir_name_guided",
                        ir_hash_old=old_seq.ir_hash,
                        ir_hash_new=new_seq.ir_hash,
                    ))
                    matched_old.add(old_ea)
                    matched_new.add(new_seq.func_ea)
                    break

        # 3b: Fuzzy IR matching for remaining functions
        remaining_old = [
            (ea, seq) for ea, seq in old_ir.items()
            if ea not in matched_old and seq.length >= 5
        ]
        remaining_new = [
            seq for ea, seq in new_ir.items()
            if ea not in matched_new and seq.length >= 5
        ]

        for old_ea, old_seq in remaining_old:
            best_sim = 0.0
            best_new: Optional[IRSequence] = None

            for new_seq in remaining_new:
                if new_seq.func_ea in matched_new:
                    continue

                # Quick pre-filter: length ratio
                if old_seq.length > 0 and new_seq.length > 0:
                    ratio = min(old_seq.length, new_seq.length) / max(
                        old_seq.length, new_seq.length
                    )
                    if ratio < 0.3:
                        continue

                sim = compare_ir_sequences(old_seq, new_seq)
                if sim > best_sim:
                    best_sim = sim
                    best_new = new_seq

            if best_new and best_sim >= self.exact_threshold:
                report.matched.append(CrossArchMatch(
                    old_ea=old_ea,
                    new_ea=best_new.func_ea,
                    old_name=old_seq.func_name,
                    new_name=best_new.func_name,
                    old_arch=old_arch,
                    new_arch=new_arch,
                    ir_similarity=best_sim,
                    match_type="ir_fuzzy",
                    ir_hash_old=old_seq.ir_hash,
                    ir_hash_new=best_new.ir_hash,
                ))
                matched_old.add(old_ea)
                matched_new.add(best_new.func_ea)

        report.stats["fuzzy_match_time"] = time.perf_counter() - t3
        fuzzy_count = len(report.matched) - exact_count
        logger.info(f"Stage 3 (name+fuzzy IR): {fuzzy_count} matches")

        # ── Stage 4: Selective symbolic verification ──────────────────
        if self.verify_top_n > 0:
            t4 = time.perf_counter()
            self._stage4_verify(report, old_export, new_export)
            report.stats["verify_time"] = time.perf_counter() - t4

        # ── Build unmatched lists ─────────────────────────────────────
        report.unmatched_old = [
            ea for ea in old_ir if ea not in matched_old
        ]
        report.unmatched_new = [
            ea for ea in new_ir if ea not in matched_new
        ]

        report.stats["total_time"] = time.perf_counter() - t0
        logger.info(report.summary())
        return report

    def _stage4_verify(
        self,
        report: CrossArchReport,
        old_export: DriverAnalysisExportV2,
        new_export: DriverAnalysisExportV2,
    ) -> None:
        """
        Selective symbolic equivalence verification.

        For the top-N fuzzy matches with lowest confidence, use
        symbolic execution to verify equivalence.
        """
        try:
            from .selective_equivalence import verify_function_pair
        except ImportError:
            logger.debug("selective_equivalence not available, skipping Stage 4")
            return

        # Sort fuzzy matches by similarity (ascending) to verify weakest first
        fuzzy_matches = [
            m for m in report.matched
            if m.match_type in ("ir_fuzzy", "ir_name_guided")
        ]
        fuzzy_matches.sort(key=lambda m: m.ir_similarity)

        verified = 0
        for match in fuzzy_matches[:self.verify_top_n]:
            try:
                result = verify_function_pair(
                    old_export, new_export,
                    match.old_ea, match.new_ea,
                    match.old_arch, match.new_arch,
                )
                match.verification_status = result
                verified += 1
                logger.info(
                    f"Verified {match.old_name} <-> {match.new_name}: "
                    f"{result}"
                )
            except Exception as e:
                match.verification_status = f"error: {e}"
                logger.debug(f"Verification failed: {e}")

        logger.info(f"Stage 4: verified {verified} function pairs")


# ---------------------------------------------------------------------------
# Convenience: Same-arch cross-diff using IR (better than opcode hash)
# ---------------------------------------------------------------------------
def ir_diff(
    old_export: DriverAnalysisExportV2,
    new_export: DriverAnalysisExportV2,
    arch: str = "x64",
) -> CrossArchReport:
    """
    Diff two same-arch binaries using IR normalization.

    This provides better matching than raw opcode hash because
    it's resilient to register allocation and instruction scheduling.
    """
    matcher = CrossArchMatcher()
    return matcher.match(old_export, new_export, old_arch=arch, new_arch=arch)
