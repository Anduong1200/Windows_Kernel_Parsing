"""
Ground Truth — Verified function match pairs for benchmark evaluation.

Sources:
  1. Auto-generated from name matching (symbols must be present)
  2. Imported from BinDiff SQLite database
  3. Manually curated JSON file

Used by benchmark.py to compute precision/recall/F1.
"""

from __future__ import annotations
import json
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

from .protocol_v2 import DriverAnalysisExportV2
from .fuzzy_hash import compute_opcode_hash, compare_opcode_hash

logger = logging.getLogger(__name__)


@dataclass
class MatchPair:
    """A single verified function match."""
    old_ea: int
    new_ea: int
    func_name: str
    confidence: str = "high"  # "high" | "medium" | "low"
    source: str = "auto"     # "auto" | "bindiff" | "manual"


@dataclass
class GroundTruth:
    """Complete ground truth for a binary pair."""
    pairs: List[MatchPair] = field(default_factory=list)
    source: str = "auto_name_match"
    binary_old: str = ""
    binary_new: str = ""
    old_sha256: str = ""
    new_sha256: str = ""

    @property
    def pair_set(self) -> Set[Tuple[int, int]]:
        """Set of (old_ea, new_ea) for fast membership checks."""
        return {(p.old_ea, p.new_ea) for p in self.pairs}

    @property
    def old_ea_set(self) -> Set[int]:
        """Set of old_ea values in ground truth."""
        return {p.old_ea for p in self.pairs}

    @property
    def new_ea_set(self) -> Set[int]:
        """Set of new_ea values in ground truth."""
        return {p.new_ea for p in self.pairs}

    def to_dict(self) -> dict:
        return {
            "source": self.source,
            "binary_old": self.binary_old,
            "binary_new": self.binary_new,
            "old_sha256": self.old_sha256,
            "new_sha256": self.new_sha256,
            "pairs": [
                {
                    "old_ea": p.old_ea,
                    "new_ea": p.new_ea,
                    "func_name": p.func_name,
                    "confidence": p.confidence,
                    "source": p.source,
                }
                for p in self.pairs
            ],
        }

    def save(self, path: str) -> None:
        with open(path, "w", encoding="utf-8") as f:
            json.dump(self.to_dict(), f, indent=2)

    @classmethod
    def load(cls, path: str) -> "GroundTruth":
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        gt = cls(
            source=data.get("source", "manual"),
            binary_old=data.get("binary_old", ""),
            binary_new=data.get("binary_new", ""),
            old_sha256=data.get("old_sha256", ""),
            new_sha256=data.get("new_sha256", ""),
        )
        for p in data.get("pairs", []):
            gt.pairs.append(MatchPair(
                old_ea=p["old_ea"],
                new_ea=p["new_ea"],
                func_name=p.get("func_name", ""),
                confidence=p.get("confidence", "high"),
                source=p.get("source", "manual"),
            ))
        return gt


# ---------------------------------------------------------------------------
# Auto-generation from symbol names
# ---------------------------------------------------------------------------
def generate_ground_truth(
    old_export: DriverAnalysisExportV2,
    new_export: DriverAnalysisExportV2,
    verify_hash: bool = True,
    min_func_size: int = 10,
) -> GroundTruth:
    """
    Auto-generate ground truth from name-matched functions.

    Strategy:
      1. Match functions by exact name (excluding sub_* auto-names)
      2. Optionally verify via opcode hash similarity
      3. Assign confidence: high (hash ≥ 80%), medium (name-only), low (ambiguous)

    Args:
        old_export: Old driver export
        new_export: New driver export
        verify_hash: If True, cross-check with opcode hash
        min_func_size: Minimum function size to include

    Returns:
        GroundTruth with verified pairs
    """
    gt = GroundTruth(
        source="auto_name_match",
        binary_old=old_export.metadata.input_file,
        binary_new=new_export.metadata.input_file,
        old_sha256=old_export.metadata.binary_sha256,
        new_sha256=new_export.metadata.binary_sha256,
    )

    # Build name index for new binary
    new_by_name: Dict[str, List] = {}
    for fi in new_export.functions.values():
        if fi.is_import:
            continue
        if fi.size < min_func_size:
            continue
        new_by_name.setdefault(fi.name, []).append(fi)

    matched_new_eas: Set[int] = set()

    for fi_old in old_export.functions.values():
        if fi_old.is_import:
            continue
        if fi_old.size < min_func_size:
            continue

        # Skip auto-generated names (sub_XXXX)
        if fi_old.name.startswith("sub_"):
            continue

        candidates = new_by_name.get(fi_old.name, [])
        if not candidates:
            continue

        # Pick the best candidate (prefer unmatched)
        best_candidate = None
        best_confidence = "low"
        best_hash_score = 0

        for fi_new in candidates:
            if fi_new.ea in matched_new_eas:
                continue

            confidence = "medium"
            hash_score = 0

            if verify_hash:
                old_insns = old_export.function_instructions.get(str(fi_old.ea), [])
                new_insns = new_export.function_instructions.get(str(fi_new.ea), [])

                old_mnemonics = [i.mnemonic for i in old_insns if i.mnemonic]
                new_mnemonics = [i.mnemonic for i in new_insns if i.mnemonic]

                if old_mnemonics and new_mnemonics:
                    old_hash = compute_opcode_hash(old_mnemonics)
                    new_hash = compute_opcode_hash(new_mnemonics)
                    hash_score = compare_opcode_hash(old_hash, new_hash)

                    if hash_score >= 80:
                        confidence = "high"
                    elif hash_score >= 50:
                        confidence = "medium"
                    else:
                        confidence = "low"
                elif not old_mnemonics and not new_mnemonics:
                    confidence = "medium"
            else:
                confidence = "medium"

            if best_candidate is None or hash_score > best_hash_score:
                best_candidate = fi_new
                best_confidence = confidence
                best_hash_score = hash_score

        if best_candidate is not None:
            gt.pairs.append(MatchPair(
                old_ea=fi_old.ea,
                new_ea=best_candidate.ea,
                func_name=fi_old.name,
                confidence=best_confidence,
                source="auto",
            ))
            matched_new_eas.add(best_candidate.ea)

    logger.info(
        f"Generated ground truth: {len(gt.pairs)} pairs "
        f"(high: {sum(1 for p in gt.pairs if p.confidence == 'high')}, "
        f"medium: {sum(1 for p in gt.pairs if p.confidence == 'medium')}, "
        f"low: {sum(1 for p in gt.pairs if p.confidence == 'low')})"
    )

    return gt


# ---------------------------------------------------------------------------
# BinDiff database import
# ---------------------------------------------------------------------------
def import_from_bindiff(
    bindiff_db_path: str,
    old_export: Optional[DriverAnalysisExportV2] = None,
    new_export: Optional[DriverAnalysisExportV2] = None,
) -> GroundTruth:
    """
    Import ground truth from a BinDiff SQLite database.

    BinDiff databases (*.BinDiff) are SQLite files with tables:
      - function: id, exe_id, address, name, ...
      - functionalgorithm: id, name
      - functionmatch: id, function1, function2, algorithm, similarity, confidence
      - file: id, filename, hash, ...

    Args:
        bindiff_db_path: Path to .BinDiff SQLite database
        old_export: Optional old export for sha256 info
        new_export: Optional new export for sha256 info

    Returns:
        GroundTruth from BinDiff results
    """
    import sqlite3

    path = Path(bindiff_db_path)
    if not path.exists():
        raise FileNotFoundError(f"BinDiff database not found: {path}")

    gt = GroundTruth(
        source="bindiff_import",
        binary_old=old_export.metadata.input_file if old_export else "",
        binary_new=new_export.metadata.input_file if new_export else "",
        old_sha256=old_export.metadata.binary_sha256 if old_export else "",
        new_sha256=new_export.metadata.binary_sha256 if new_export else "",
    )

    conn = sqlite3.connect(str(path))
    try:
        cursor = conn.cursor()

        # Get file info
        cursor.execute("""
            SELECT f.filename
            FROM file f
            ORDER BY f.id
        """)
        files = cursor.fetchall()
        if len(files) >= 2:
            gt.binary_old = gt.binary_old or files[0][0]
            gt.binary_new = gt.binary_new or files[1][0]

        # Get function matches
        # BinDiff schema: functionmatch links two function IDs
        # function table has address, name per exe
        cursor.execute("""
            SELECT
                f1.address AS old_addr,
                f2.address AS new_addr,
                f1.name AS old_name,
                fm.similarity,
                fm.confidence
            FROM functionmatch fm
            JOIN function f1 ON fm.function1 = f1.id
            JOIN function f2 ON fm.function2 = f2.id
            WHERE fm.similarity > 0.3
            ORDER BY fm.similarity DESC
        """)

        for row in cursor.fetchall():
            old_addr, new_addr, func_name, similarity, bd_confidence = row

            # Map BinDiff confidence to our scale
            if bd_confidence >= 0.8:
                confidence = "high"
            elif bd_confidence >= 0.5:
                confidence = "medium"
            else:
                confidence = "low"

            gt.pairs.append(MatchPair(
                old_ea=int(old_addr),
                new_ea=int(new_addr),
                func_name=func_name or "",
                confidence=confidence,
                source="bindiff",
            ))

    finally:
        conn.close()

    logger.info(f"Imported {len(gt.pairs)} pairs from BinDiff: {path.name}")
    return gt
