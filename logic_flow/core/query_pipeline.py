"""
Query Pipeline — Multi-stage similarity search.

Pipeline: lookup(binary) → top-K similar → refine

  Stage 1: INDEX LOOKUP  → Exact hash retrieval from IndexStore
  Stage 2: TOP-K FILTER  → Candidate scoring via opcode hash comparison
  Stage 3: REFINE        → DiffPipeline deep comparison on top candidates

Designed for the use case: "Given a new driver, find the most similar
previously-indexed binaries and their function-level delta."
"""

from __future__ import annotations
import logging
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional

from .protocol_v2 import DriverAnalysisExportV2
from .diff_pipeline import DiffPipeline
from .diff_report import DiffReport
from .index_store import IndexStore, BinaryRecord
from .fuzzy_hash import compute_opcode_hash

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Result models
# ---------------------------------------------------------------------------
@dataclass
class FunctionHit:
    """A single function-level similarity hit from the index."""
    binary_sha256: str
    binary_filename: str
    func_ea: int
    func_name: str
    similarity_score: int  # 0–100
    match_source: str = "hash"  # "hash" | "name" | "refined"


@dataclass
class BinarySimilarity:
    """Aggregate similarity score for a candidate binary."""
    sha256: str
    filename: str
    family: str
    overall_score: float      # 0.0–1.0
    matched_functions: int
    total_functions: int
    function_hits: List[FunctionHit] = field(default_factory=list)
    diff_report: Optional[DiffReport] = None  # from refinement stage


@dataclass
class QueryResult:
    """Complete result of a query pipeline execution."""
    target_sha256: str
    target_filename: str
    similar_binaries: List[BinarySimilarity] = field(default_factory=list)
    stage_timings: Dict[str, float] = field(default_factory=dict)
    total_candidates_scanned: int = 0
    total_functions_compared: int = 0

    @property
    def best_match(self) -> Optional[BinarySimilarity]:
        return self.similar_binaries[0] if self.similar_binaries else None

    def summary(self) -> str:
        lines = [
            f"Query: {self.target_filename}",
            f"  Found: {len(self.similar_binaries)} similar binaries",
        ]
        for bs in self.similar_binaries[:5]:
            lines.append(
                f"  - {bs.filename} ({bs.family}) "
                f"score={bs.overall_score:.2f} "
                f"matched={bs.matched_functions}/{bs.total_functions}"
            )
        for stage, t in self.stage_timings.items():
            lines.append(f"  {stage}: {t:.3f}s")
        return "\n".join(lines)


# ---------------------------------------------------------------------------
# Query Pipeline
# ---------------------------------------------------------------------------
class QueryPipeline:
    """
    Multi-stage similarity search pipeline.

    Usage:
        store = IndexStore("index.db")
        pipeline = QueryPipeline(store)
        result = pipeline.query_binary(target_export, top_k=10)
    """

    def __init__(
        self,
        index_store: IndexStore,
        diff_pipeline: Optional[DiffPipeline] = None,
        refine_top_n: int = 3,
    ):
        """
        Args:
            index_store: The indexed binary database
            diff_pipeline: Optional DiffPipeline for Stage 3 refinement
            refine_top_n: Number of top candidates to run full diff on
        """
        self.store = index_store
        self.diff_pipeline = diff_pipeline or DiffPipeline()
        self.refine_top_n = refine_top_n

    def query_binary(
        self,
        target_export: DriverAnalysisExportV2,
        top_k: int = 10,
        family: Optional[str] = None,
        skip_refine: bool = False,
    ) -> QueryResult:
        """
        Execute the full query pipeline.

        Stage 1: Compute sketches for target, lookup exact matches in index
        Stage 2: Score candidate binaries by aggregated hash similarity
        Stage 3: Run DiffPipeline on top-N candidates for detailed analysis

        Args:
            target_export: The binary to compare
            top_k: Return top-K similar binaries
            family: Optional family filter (e.g. "ndis")
            skip_refine: Skip Stage 3 refinement for speed

        Returns:
            QueryResult with ranked similar binaries
        """
        target_sha = target_export.metadata.binary_sha256
        result = QueryResult(
            target_sha256=target_sha,
            target_filename=target_export.metadata.input_file,
        )

        # ── Stage 1: Compute target sketches ───────────────────────
        t0 = time.perf_counter()
        target_sketches = self._compute_target_sketches(target_export)
        result.stage_timings["stage1_sketch"] = time.perf_counter() - t0

        if not target_sketches:
            logger.warning("No function sketches computed for target")
            return result

        # ── Stage 2: Index lookup + candidate scoring ──────────────
        t1 = time.perf_counter()
        candidate_scores = self._stage2_candidate_scoring(
            target_sketches, target_sha, family,
        )
        result.stage_timings["stage2_scoring"] = time.perf_counter() - t1

        result.total_candidates_scanned = len(candidate_scores)
        result.total_functions_compared = sum(
            len(hits) for hits in candidate_scores.values()
        )

        # Build BinarySimilarity records
        binary_records = {}
        for sha in candidate_scores:
            rec = self.store.lookup_binary(sha)
            if rec:
                binary_records[sha] = rec

        similarities: List[BinarySimilarity] = []
        for sha, hits in candidate_scores.items():
            rec = binary_records.get(sha)
            if not rec:
                continue

            # Overall score = weighted average of function similarities
            total_score = sum(h.similarity_score for h in hits)
            avg_score = total_score / max(len(hits), 1) / 100.0
            # Boost by coverage (what fraction of target functions matched)
            coverage = len(hits) / max(len(target_sketches), 1)
            overall = min(avg_score * 0.7 + coverage * 0.3, 1.0)

            similarities.append(BinarySimilarity(
                sha256=sha,
                filename=rec.filename,
                family=rec.driver_family,
                overall_score=overall,
                matched_functions=len(hits),
                total_functions=rec.func_count,
                function_hits=hits,
            ))

        # Sort by overall score descending
        similarities.sort(key=lambda s: s.overall_score, reverse=True)
        similarities = similarities[:top_k]

        # ── Stage 3: Refine top-N with full DiffPipeline ───────────
        if not skip_refine and similarities:
            t2 = time.perf_counter()
            self._stage3_refine(target_export, similarities)
            result.stage_timings["stage3_refine"] = time.perf_counter() - t2

        result.similar_binaries = similarities
        result.stage_timings["total"] = sum(result.stage_timings.values())

        logger.info(result.summary())
        return result

    def query_function(
        self,
        func_ea: int,
        export: DriverAnalysisExportV2,
        top_k: int = 10,
        family: Optional[str] = None,
    ) -> List[FunctionHit]:
        """
        Find similar functions to a single target function across the index.

        Args:
            func_ea: Address of the target function
            export: Export containing the function
            top_k: Number of results
            family: Optional family filter

        Returns:
            List of FunctionHit results
        """
        ea_str = str(func_ea)
        insns = export.function_instructions.get(ea_str, [])
        mnemonics = [i.mnemonic for i in insns if i.mnemonic]
        if not mnemonics:
            return []

        opcode_hash = compute_opcode_hash(mnemonics)
        target_sha = export.metadata.binary_sha256

        # Search by similarity
        similar = self.store.search_similar_functions(
            opcode_hash,
            exclude_sha256=target_sha,
            family=family,
            limit=top_k * 3,  # over-fetch to account for filtering
        )

        hits: List[FunctionHit] = []
        seen_binaries: Dict[str, BinaryRecord] = {}

        for sketch, score in similar:
            if sketch.binary_sha256 not in seen_binaries:
                rec = self.store.lookup_binary(sketch.binary_sha256)
                if rec:
                    seen_binaries[sketch.binary_sha256] = rec

            rec = seen_binaries.get(sketch.binary_sha256)
            hits.append(FunctionHit(
                binary_sha256=sketch.binary_sha256,
                binary_filename=rec.filename if rec else "",
                func_ea=sketch.func_ea,
                func_name=sketch.func_name,
                similarity_score=score,
                match_source="hash",
            ))

        return hits[:top_k]

    # ── Internal stages ───────────────────────────────────────────────

    def _compute_target_sketches(
        self,
        export: DriverAnalysisExportV2,
    ) -> Dict[int, str]:
        """Compute opcode hashes for all non-import functions in target."""
        sketches: Dict[int, str] = {}
        for ea_str, fi in export.functions.items():
            if fi.is_import:
                continue
            insns = export.function_instructions.get(ea_str, [])
            mnemonics = [i.mnemonic for i in insns if i.mnemonic]
            if mnemonics:
                sketches[fi.ea] = compute_opcode_hash(mnemonics)
        return sketches

    def _stage2_candidate_scoring(
        self,
        target_sketches: Dict[int, str],
        target_sha: str,
        family: Optional[str],
    ) -> Dict[str, List[FunctionHit]]:
        """
        For each target function sketch, find similar indexed functions.
        Aggregate hits by binary SHA256.
        """
        candidate_hits: Dict[str, List[FunctionHit]] = {}

        # Cache binary info
        binary_cache: Dict[str, BinaryRecord] = {}

        for func_ea, opcode_hash in target_sketches.items():
            # Exact match
            exact = self.store.search_by_opcode_hash(
                opcode_hash,
                limit=10,
                exclude_sha256=target_sha,
                family=family,
            )

            for sketch in exact:
                if sketch.binary_sha256 not in binary_cache:
                    rec = self.store.lookup_binary(sketch.binary_sha256)
                    if rec:
                        binary_cache[sketch.binary_sha256] = rec

                rec = binary_cache.get(sketch.binary_sha256)
                hit = FunctionHit(
                    binary_sha256=sketch.binary_sha256,
                    binary_filename=rec.filename if rec else "",
                    func_ea=sketch.func_ea,
                    func_name=sketch.func_name,
                    similarity_score=100,  # exact hash match
                    match_source="hash",
                )
                candidate_hits.setdefault(sketch.binary_sha256, []).append(hit)

            # Similar match (same length bucket)
            similar = self.store.search_similar_functions(
                opcode_hash,
                exclude_sha256=target_sha,
                family=family,
                limit=5,
            )

            for sketch, score in similar:
                if score < 60:
                    continue
                # Check if already added as exact
                sha = sketch.binary_sha256
                existing = candidate_hits.get(sha, [])
                if any(h.func_ea == sketch.func_ea for h in existing):
                    continue

                if sha not in binary_cache:
                    rec = self.store.lookup_binary(sha)
                    if rec:
                        binary_cache[sha] = rec

                rec = binary_cache.get(sha)
                hit = FunctionHit(
                    binary_sha256=sha,
                    binary_filename=rec.filename if rec else "",
                    func_ea=sketch.func_ea,
                    func_name=sketch.func_name,
                    similarity_score=score,
                    match_source="hash",
                )
                candidate_hits.setdefault(sha, []).append(hit)

        return candidate_hits

    def _stage3_refine(
        self,
        target_export: DriverAnalysisExportV2,
        similarities: List[BinarySimilarity],
    ) -> None:
        """
        Run full DiffPipeline on top-N candidate binaries
        to get deep comparison results.

        Note: This requires the candidate exports to be loadable.
        We attempt to load from the index store's metadata.
        Refinement is best-effort — if exports aren't available
        on disk, we skip.
        """
        n = min(self.refine_top_n, len(similarities))
        for sim in similarities[:n]:
            # Try to find the export file on disk
            # The filename is stored in the index
            try:
                from pathlib import Path

                # Check common locations for the export JSON
                candidate_path = None
                for search_dir in [".", "samples", "exports"]:
                    candidate = Path(search_dir) / f"{sim.filename}.json"
                    if candidate.exists():
                        candidate_path = candidate
                        break
                    # Try without .json extension if filename already has it
                    candidate = Path(search_dir) / sim.filename
                    if candidate.exists():
                        candidate_path = candidate
                        break

                if candidate_path:
                    candidate_export = DriverAnalysisExportV2.load(
                        str(candidate_path)
                    )
                    report = self.diff_pipeline.run(target_export, candidate_export)
                    sim.diff_report = report

                    # Update matched count from refined report
                    sim.matched_functions = len(report.matched)
                    sim.overall_score = report.match_rate

                    logger.info(
                        f"Refined {sim.filename}: "
                        f"{len(report.matched)} matches, "
                        f"rate={report.match_rate:.1%}"
                    )
                else:
                    logger.debug(
                        f"Export JSON not found for {sim.filename}, "
                        f"skipping refinement"
                    )

            except Exception as e:
                logger.debug(f"Refinement failed for {sim.filename}: {e}")
