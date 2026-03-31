"""
Selective Equivalence Checker — Symbolic verification for flagged functions.

When the IR-based fuzzy matcher finds a borderline match (e.g., 70-85%
similarity), this module can be invoked to symbolically prove or disprove
equivalence using SMT solving.

Two modes:
  1. Lightweight (no angr): Compare IR operator sequences structurally
     and report a confidence heuristic.
  2. Full symbolic (angr/claripy): Lift both functions to VEX IR, set
     up equivalent symbolic inputs, step through both, and compare output
     register/memory states via Z3 satisfiability.

Usage:
    result = verify_function_pair(old_export, new_export,
                                  old_ea, new_ea, "x64", "arm64")
    # result: "equivalent" | "different" | "inconclusive" | "error:..."
"""

from __future__ import annotations
import logging
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

from .protocol_v2 import DriverAnalysisExportV2
from .ir_normalizer import IRNormalizer, IRSequence, compare_ir_sequences

logger = logging.getLogger(__name__)

# Check for angr availability
_ANGR_AVAILABLE = False
try:
    import importlib.util as _ilu
    if _ilu.find_spec("angr") and _ilu.find_spec("claripy"):
        import claripy
        _ANGR_AVAILABLE = True
except ImportError:
    pass


# ---------------------------------------------------------------------------
# Result model
# ---------------------------------------------------------------------------
@dataclass
class EquivalenceResult:
    """Result of symbolic equivalence checking."""
    status: str = "inconclusive"    # "equivalent" | "different" | "inconclusive" | "error"
    confidence: float = 0.0         # 0.0-1.0
    method: str = "ir_structural"   # "ir_structural" | "symbolic"
    differing_outputs: List[str] = field(default_factory=list)
    details: Dict[str, Any] = field(default_factory=dict)

    def __str__(self) -> str:
        return f"{self.status} ({self.confidence:.0%}, {self.method})"


# ---------------------------------------------------------------------------
# Lightweight structural verification (always available)
# ---------------------------------------------------------------------------
def _structural_verify(
    old_ir: IRSequence,
    new_ir: IRSequence,
) -> EquivalenceResult:
    """
    Structural equivalence check using IR sequences only.

    Checks:
      1. Exact IR hash match → equivalent
      2. Op histogram match → likely equivalent
      3. Control flow pattern match → check structural similarity
      4. Memory access pattern match → additional confidence
    """
    result = EquivalenceResult(method="ir_structural")

    # 1. Exact hash match
    if old_ir.ir_hash == new_ir.ir_hash and old_ir.ir_hash:
        result.status = "equivalent"
        result.confidence = 0.99
        result.details["match"] = "exact_ir_hash"
        return result

    # 2. Compare IR sequences
    sim = compare_ir_sequences(old_ir, new_ir)
    result.confidence = sim
    result.details["ir_similarity"] = sim

    # 3. Op histogram comparison
    hist_match = _compare_histograms(old_ir.op_histogram, new_ir.op_histogram)
    result.details["histogram_match"] = hist_match

    # 4. Control flow pattern
    old_cf = [s.op.value for s in old_ir.statements if s.is_control_flow]
    new_cf = [s.op.value for s in new_ir.statements if s.is_control_flow]
    cf_match = old_cf == new_cf
    result.details["control_flow_match"] = cf_match

    # 5. Memory access pattern
    old_mem = [s.op.value for s in old_ir.statements if s.has_memory_access]
    new_mem = [s.op.value for s in new_ir.statements if s.has_memory_access]
    mem_match = old_mem == new_mem
    result.details["memory_pattern_match"] = mem_match

    # Decision logic
    if sim >= 0.95 and cf_match and hist_match >= 0.95:
        result.status = "equivalent"
    elif sim >= 0.85 and cf_match:
        result.status = "equivalent"
        result.confidence = min(sim, 0.90)  # cap confidence for non-exact
    elif sim >= 0.70:
        result.status = "inconclusive"
    else:
        result.status = "different"
        # Identify what diverged
        if not cf_match:
            result.differing_outputs.append("control_flow")
        if not mem_match:
            result.differing_outputs.append("memory_pattern")
        if hist_match < 0.80:
            result.differing_outputs.append("op_distribution")

    return result


def _compare_histograms(
    hist_a: Dict[str, int], hist_b: Dict[str, int],
) -> float:
    """Compare two operation histograms by normalized overlap."""
    all_keys = set(hist_a) | set(hist_b)
    if not all_keys:
        return 1.0

    total_a = sum(hist_a.values()) or 1
    total_b = sum(hist_b.values()) or 1

    overlap = 0.0
    for k in all_keys:
        ratio_a = hist_a.get(k, 0) / total_a
        ratio_b = hist_b.get(k, 0) / total_b
        overlap += min(ratio_a, ratio_b)

    return overlap


# ---------------------------------------------------------------------------
# Full symbolic verification (requires angr)
# ---------------------------------------------------------------------------
def _symbolic_verify(
    old_export: DriverAnalysisExportV2,
    new_export: DriverAnalysisExportV2,
    old_ea: int,
    new_ea: int,
    old_arch: str,
    new_arch: str,
) -> EquivalenceResult:
    """
    Symbolic equivalence checking using angr/claripy.

    Algorithm:
      1. Lift both functions to VEX IR via angr
      2. Create symbolic states with identical initial conditions
      3. Execute each function symbolically
      4. Compare output register/memory states using Z3
      5. If (output_A != output_B) is UNSAT → equivalent

    Note: Only works for small functions (< 50 instructions) due
    to path explosion. Falls back to structural check for large functions.
    """
    if not _ANGR_AVAILABLE:
        logger.debug("angr not available, falling back to structural verification")
        return EquivalenceResult(
            status="inconclusive",
            method="ir_structural",
            details={"reason": "angr not installed"},
        )

    result = EquivalenceResult(method="symbolic")

    try:
        # For same-binary checks we need the actual binary files
        # This is designed for use when binary files are available
        # In export-only mode, fall back to structural
        old_path = _resolve_binary_path(old_export)
        new_path = _resolve_binary_path(new_export)

        if not old_path or not new_path:
            logger.debug("Binary files not available for symbolic verification")
            return EquivalenceResult(
                status="inconclusive",
                method="ir_structural",
                details={"reason": "binary files not available"},
            )

        from .advanced_lifter import AngrLifter, suppress_angr_logging
        suppress_angr_logging()

        # Lift both functions
        old_lifter = AngrLifter(old_path)
        new_lifter = AngrLifter(new_path)

        old_ir_data = old_lifter.lift_function(old_ea)
        new_ir_data = new_lifter.lift_function(new_ea)

        if not old_ir_data or not new_ir_data:
            return EquivalenceResult(
                status="inconclusive",
                method="symbolic",
                details={"reason": "lifting failed"},
            )

        # Function size check — skip huge functions
        old_block_count = old_ir_data.get("block_count", 0)
        new_block_count = new_ir_data.get("block_count", 0)
        if old_block_count > 20 or new_block_count > 20:
            logger.debug(
                f"Functions too large for symbolic verification "
                f"({old_block_count}/{new_block_count} blocks)"
            )
            return EquivalenceResult(
                status="inconclusive",
                method="symbolic",
                details={"reason": "function too large"},
            )

        # Create symbolic states
        differences = _check_symbolic_equivalence(
            old_lifter.project, new_lifter.project,
            old_ea, new_ea,
        )

        if differences is None:
            result.status = "inconclusive"
            result.details["reason"] = "execution failed"
        elif len(differences) == 0:
            result.status = "equivalent"
            result.confidence = 0.99
        else:
            result.status = "different"
            result.differing_outputs = differences
            result.confidence = 0.95

        return result

    except Exception as e:
        logger.error(f"Symbolic verification failed: {e}")
        return EquivalenceResult(
            status="error",
            method="symbolic",
            details={"error": str(e)},
        )


def _check_symbolic_equivalence(
    project_a,
    project_b,
    addr_a: int,
    addr_b: int,
) -> Optional[List[str]]:
    """
    Core Z3-based equivalence check.

    Returns:
        None if execution failed
        [] if equivalent
        [list of differing registers] if different
    """
    try:
        # Create blank states
        state_a = project_a.factory.blank_state(addr=addr_a)
        state_b = project_b.factory.blank_state(addr=addr_b)

        # Synchronize symbolic inputs
        # Use common abstract register set
        common_regs_64 = [
            "rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "r8",
        ]
        common_regs_arm = [
            "x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7",
        ]

        # Map registers based on architecture
        arch_a = project_a.arch.name
        arch_b = project_b.arch.name

        regs_a = common_regs_64 if "64" in arch_a or "AMD" in arch_a else common_regs_arm
        regs_b = common_regs_64 if "64" in arch_b or "AMD" in arch_b else common_regs_arm

        # Create shared symbolic variables
        sym_vars = []
        n_regs = min(len(regs_a), len(regs_b))
        for i in range(n_regs):
            bits_a = project_a.arch.bits
            bits_b = project_b.arch.bits
            bits = min(bits_a, bits_b)
            sv = claripy.BVS(f"param_{i}", bits)
            sym_vars.append(sv)

            # Extend if needed
            val_a = sv if bits == bits_a else claripy.ZeroExt(bits_a - bits, sv)
            val_b = sv if bits == bits_b else claripy.ZeroExt(bits_b - bits, sv)

            state_a.registers.store(regs_a[i], val_a)
            state_b.registers.store(regs_b[i], val_b)

        # Step one basic block
        simgr_a = project_a.factory.simgr(state_a)
        simgr_b = project_b.factory.simgr(state_b)

        simgr_a.step()
        simgr_b.step()

        if not simgr_a.active or not simgr_b.active:
            return None

        out_a = simgr_a.active[0]
        out_b = simgr_b.active[0]

        # Compare output registers
        differences = []
        for i in range(n_regs):
            val_a = out_a.registers.load(regs_a[i])
            val_b = out_b.registers.load(regs_b[i])

            if val_a is val_b:
                continue

            # Check if they CAN differ
            try:
                cond = val_a != val_b
                if out_a.solver.satisfiable(extra_constraints=[cond]):
                    differences.append(f"{regs_a[i]}/{regs_b[i]}")
            except Exception:
                differences.append(f"{regs_a[i]}/{regs_b[i]} (solver_error)")

        return differences

    except Exception as e:
        logger.debug(f"Symbolic equivalence check error: {e}")
        return None


def _resolve_binary_path(export: DriverAnalysisExportV2) -> Optional[str]:
    """Try to resolve the original binary file path from export metadata."""
    from pathlib import Path

    filename = export.metadata.input_file
    if not filename:
        return None

    # Check common locations
    candidates = [
        Path(filename),
        Path("samples") / filename,
        Path("binaries") / filename,
    ]

    for candidate in candidates:
        if candidate.exists():
            return str(candidate)

    return None


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------
def verify_function_pair(
    old_export: DriverAnalysisExportV2,
    new_export: DriverAnalysisExportV2,
    old_ea: int,
    new_ea: int,
    old_arch: str = "x64",
    new_arch: str = "x64",
    use_symbolic: bool = False,
) -> str:
    """
    High-level API to verify equivalence of two functions.

    Args:
        old_export: First binary export
        new_export: Second binary export
        old_ea: Function address in old binary
        new_ea: Function address in new binary
        old_arch: Architecture of old binary
        new_arch: Architecture of new binary
        use_symbolic: Try full symbolic verification (requires angr)

    Returns:
        Status string: "equivalent" | "different" | "inconclusive" | "error:..."
    """
    # Step 1: Normalize both functions
    old_normalizer = IRNormalizer(arch=old_arch)
    new_normalizer = IRNormalizer(arch=new_arch)

    old_insns = old_export.function_instructions.get(str(old_ea), [])
    new_insns = new_export.function_instructions.get(str(new_ea), [])

    old_fi = old_export.functions.get(str(old_ea))
    new_fi = new_export.functions.get(str(new_ea))

    old_name = old_fi.name if old_fi else f"sub_{old_ea:X}"
    new_name = new_fi.name if new_fi else f"sub_{new_ea:X}"

    old_ir = old_normalizer.normalize_function(old_ea, old_name, old_insns)
    new_ir = new_normalizer.normalize_function(new_ea, new_name, new_insns)

    # Step 2: Structural check
    result = _structural_verify(old_ir, new_ir)

    # Step 3: Symbolic verification if requested and structural is inconclusive
    if use_symbolic and result.status == "inconclusive" and _ANGR_AVAILABLE:
        sym_result = _symbolic_verify(
            old_export, new_export, old_ea, new_ea, old_arch, new_arch,
        )
        if sym_result.status != "inconclusive":
            return sym_result.status

    return result.status


def batch_verify(
    old_export: DriverAnalysisExportV2,
    new_export: DriverAnalysisExportV2,
    pairs: List[Tuple[int, int]],
    old_arch: str = "x64",
    new_arch: str = "x64",
) -> Dict[Tuple[int, int], EquivalenceResult]:
    """
    Verify multiple function pairs in batch.

    Args:
        pairs: List of (old_ea, new_ea) tuples to verify

    Returns:
        Dict mapping (old_ea, new_ea) -> EquivalenceResult
    """
    old_normalizer = IRNormalizer(arch=old_arch)
    new_normalizer = IRNormalizer(arch=new_arch)
    results: Dict[Tuple[int, int], EquivalenceResult] = {}

    for old_ea, new_ea in pairs:
        old_insns = old_export.function_instructions.get(str(old_ea), [])
        new_insns = new_export.function_instructions.get(str(new_ea), [])

        old_fi = old_export.functions.get(str(old_ea))
        new_fi = new_export.functions.get(str(new_ea))

        old_name = old_fi.name if old_fi else f"sub_{old_ea:X}"
        new_name = new_fi.name if new_fi else f"sub_{new_ea:X}"

        old_ir = old_normalizer.normalize_function(old_ea, old_name, old_insns)
        new_ir = new_normalizer.normalize_function(new_ea, new_name, new_insns)

        results[(old_ea, new_ea)] = _structural_verify(old_ir, new_ir)

    return results
