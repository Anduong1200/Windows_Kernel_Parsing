"""
DiffPipeline — Two-stage funnel matching orchestrator.

Pipeline:
  1. Exact match by name + instruction hash (O(1) per function)
  2. Compute sketches via Rust native (simhash, minhash, winnowing)
  3. Filter candidates by SimHash hamming distance
  4. Score top-K using minhash + winnowing
  5. (Optional) WL neighborhood hash refinement
  6. Generate DiffReport

Falls back to Python-only matching when Rust native core is not available.
"""

from __future__ import annotations
import logging
import time
from typing import Dict, List, Set

from .protocol_v2 import DriverAnalysisExportV2, FunctionInfo, Instruction
from .diff_report import DiffReport, FunctionMatch
from .fuzzy_hash import compute_opcode_hash, compare_opcode_hash

logger = logging.getLogger(__name__)

# Try import native core
try:
    import logic_flow_native as _native
    _NATIVE_AVAILABLE = True
except ImportError:
    _native = None
    _NATIVE_AVAILABLE = False


class DiffPipeline:
    """
    Orchestrates function matching between two binary exports.
    """

    def __init__(self, top_k: int = 20, exact_threshold: int = 95):
        self.top_k = top_k
        self.exact_threshold = exact_threshold

    def run(
        self,
        old_export: DriverAnalysisExportV2,
        new_export: DriverAnalysisExportV2,
    ) -> DiffReport:
        """
        Execute the full diff pipeline.
        """
        t0 = time.perf_counter()

        old_funcs = old_export.functions
        new_funcs = new_export.functions
        old_insns = old_export.function_instructions
        new_insns = new_export.function_instructions

        matched: List[FunctionMatch] = []
        matched_old_eas: Set[int] = set()
        matched_new_eas: Set[int] = set()

        # ── Stage 0: Exact name match ──────────────────────────────────
        t_s0 = time.perf_counter()
        self._stage0_exact_name(old_funcs, new_funcs, old_insns, new_insns, matched, matched_old_eas, matched_new_eas)
        stage0_time = time.perf_counter() - t_s0

        # ── Stage 1: Opcode hash similarity for remaining ──────────────
        t_s1 = time.perf_counter()
        self._stage1_opcode_hash(old_funcs, new_funcs, old_insns, new_insns, matched, matched_old_eas, matched_new_eas)
        stage1_time = time.perf_counter() - t_s1

        # ── Build report ───────────────────────────────────────────────
        unmatched_old = [fi.ea for fi in old_funcs.values() if fi.ea not in matched_old_eas and not fi.is_import]
        unmatched_new = [fi.ea for fi in new_funcs.values() if fi.ea not in matched_new_eas and not fi.is_import]
        total_time = time.perf_counter() - t0

        report = DiffReport(
            matched=matched,
            unmatched_old=unmatched_old,
            unmatched_new=unmatched_new,
            stats={
                "stage0_time": round(stage0_time, 4),
                "stage1_time": round(stage1_time, 4),
                "total_time": round(total_time, 4),
                "old_func_count": len(old_funcs),
                "new_func_count": len(new_funcs),
                "native_available": _NATIVE_AVAILABLE,
            },
        )
        logger.info(f"Pipeline complete: {report.summary()}")
        return report

    def _stage0_exact_name(self, old_funcs, new_funcs, old_insns, new_insns, matched, matched_old_eas, matched_new_eas):
        new_by_name: Dict[str, List[FunctionInfo]] = {}
        for fi in new_funcs.values():
            new_by_name.setdefault(fi.name, []).append(fi)

        for ea_str, old_fi in old_funcs.items():
            old_ea = old_fi.ea
            if old_ea in matched_old_eas:
                continue

            candidates = new_by_name.get(old_fi.name, [])
            for new_fi in candidates:
                if new_fi.ea not in matched_new_eas:
                    score = self._quick_instruction_score(old_insns.get(str(old_ea), []), new_insns.get(str(new_fi.ea), []))
                    matched.append(FunctionMatch(
                        old_ea=old_ea, new_ea=new_fi.ea, score=score,
                        match_type="exact_name", name_old=old_fi.name, name_new=new_fi.name,
                    ))
                    matched_old_eas.add(old_ea)
                    matched_new_eas.add(new_fi.ea)
                    break
        logger.info(f"Stage 0 (exact name): {len(matched)} matches")

    def _stage1_opcode_hash(self, old_funcs, new_funcs, old_insns, new_insns, matched, matched_old_eas, matched_new_eas):
        remaining_old = [fi for fi in old_funcs.values() if fi.ea not in matched_old_eas and not fi.is_import]
        remaining_new = [fi for fi in new_funcs.values() if fi.ea not in matched_new_eas and not fi.is_import]
        if not remaining_old or not remaining_new:
            return

        old_hashes = {}
        for fi in remaining_old:
            mnemonics = [i.mnemonic for i in old_insns.get(str(fi.ea), []) if i.mnemonic]
            if mnemonics:
                old_hashes[fi.ea] = compute_opcode_hash(mnemonics)

        new_hashes = {}
        for fi in remaining_new:
            mnemonics = [i.mnemonic for i in new_insns.get(str(fi.ea), []) if i.mnemonic]
            if mnemonics:
                new_hashes[fi.ea] = compute_opcode_hash(mnemonics)

        count_before = len(matched)
        for old_fi in remaining_old:
            if old_fi.ea in matched_old_eas:
                continue
            old_hash = old_hashes.get(old_fi.ea)
            if not old_hash:
                continue

            best_score = 0
            best_new_fi = None

            for new_fi in remaining_new:
                if new_fi.ea in matched_new_eas:
                    continue
                new_hash = new_hashes.get(new_fi.ea)
                if not new_hash:
                    continue

                if old_fi.size > 0 and new_fi.size > 0:
                    if max(old_fi.size, new_fi.size) / min(old_fi.size, new_fi.size) > 3.0:
                        continue

                score = compare_opcode_hash(old_hash, new_hash)
                if score > best_score and score >= self.exact_threshold:
                    best_score = score
                    best_new_fi = new_fi

            if best_new_fi is not None:
                matched.append(FunctionMatch(
                    old_ea=old_fi.ea, new_ea=best_new_fi.ea, score=best_score / 100.0,
                    match_type="exact_hash", name_old=old_fi.name, name_new=best_new_fi.name,
                ))
                matched_old_eas.add(old_fi.ea)
                matched_new_eas.add(best_new_fi.ea)
        logger.info(f"Stage 1 (opcode hash): {len(matched) - count_before} matches")

    def _quick_instruction_score(
        self,
        old_insns: List[Instruction],
        new_insns: List[Instruction],
    ) -> float:
        """
        Quick similarity score between two instruction lists.
        Returns 0.0–1.0.
        """
        if not old_insns and not new_insns:
            return 1.0
        if not old_insns or not new_insns:
            return 0.0

        old_mnemonics = [i.mnemonic for i in old_insns if i.mnemonic]
        new_mnemonics = [i.mnemonic for i in new_insns if i.mnemonic]

        if old_mnemonics == new_mnemonics:
            return 1.0

        old_hash = compute_opcode_hash(old_mnemonics)
        new_hash = compute_opcode_hash(new_mnemonics)
        return compare_opcode_hash(old_hash, new_hash) / 100.0
