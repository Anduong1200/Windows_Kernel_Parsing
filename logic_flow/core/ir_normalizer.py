"""
IR Normalizer — Lift native instructions to arch-independent IR operator sequences.

Converts disassembled instructions into a normalized intermediate representation
that is independent of the source architecture. This enables cross-arch matching:
  x86_64 driver  <-->  ARM64 driver  <-->  MIPS driver

Pipeline:
  1. Classify each mnemonic into a canonical IR operator category
  2. Normalize operand types (reg/mem/imm) without arch-specific names
  3. Build an SSA-style operator sequence per function
  4. Hash the IR sequence for fast comparison

Supported arch families: x86/x64, ARM/AArch64, MIPS (extensible)

Zero heavy dependencies — works with exported JSON instruction data.
When angr/pyvex is available, can optionally lift through VEX IR for
higher fidelity.
"""

from __future__ import annotations
import hashlib
import logging
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Canonical IR operator categories
# ---------------------------------------------------------------------------
class IROp(str, Enum):
    """Architecture-independent IR operator categories."""
    # Data movement
    MOV = "MOV"           # register-to-register / load-immediate
    LOAD = "LOAD"         # memory read
    STORE = "STORE"       # memory write
    PUSH = "PUSH"         # stack push
    POP = "POP"           # stack pop
    LEA = "LEA"           # address computation

    # Arithmetic
    ADD = "ADD"
    SUB = "SUB"
    MUL = "MUL"
    DIV = "DIV"
    NEG = "NEG"
    INC = "INC"
    DEC = "DEC"

    # Bitwise
    AND = "AND"
    OR = "OR"
    XOR = "XOR"
    NOT = "NOT"
    SHL = "SHL"           # shift left
    SHR = "SHR"           # shift right (logical)
    SAR = "SAR"           # shift right (arithmetic)
    ROL = "ROL"           # rotate left
    ROR = "ROR"           # rotate right

    # Comparison / test
    CMP = "CMP"
    TEST = "TEST"

    # Control flow
    JMP = "JMP"           # unconditional jump
    JCC = "JCC"           # conditional jump
    CALL = "CALL"         # function call
    RET = "RET"           # return
    NOP = "NOP"           # no-op

    # System / privileged
    SYSCALL = "SYSCALL"
    INT = "INT"           # interrupt / trap
    IO = "IO"             # port I/O

    # Conversion / extension
    EXTEND = "EXTEND"     # sign/zero extend
    TRUNC = "TRUNC"       # truncate

    # Atomic / memory ordering
    XCHG = "XCHG"         # exchange
    LOCK = "LOCK"         # atomic prefix
    FENCE = "FENCE"       # memory barrier

    # Unknown / unmapped
    UNKNOWN = "UNKNOWN"


class OperandKind(str, Enum):
    """Architecture-independent operand classification."""
    REG = "R"
    IMM = "I"
    MEM = "M"
    NONE = "_"


# ---------------------------------------------------------------------------
# Mnemonic -> IROp classification tables (per architecture)
# ---------------------------------------------------------------------------

# x86/x64 mnemonic mapping
_X86_MAP: Dict[str, IROp] = {
    # Data movement
    "mov": IROp.MOV, "movzx": IROp.EXTEND, "movsx": IROp.EXTEND,
    "movsxd": IROp.EXTEND, "cmovz": IROp.MOV, "cmovnz": IROp.MOV,
    "cmova": IROp.MOV, "cmovb": IROp.MOV, "cmovl": IROp.MOV,
    "cmovg": IROp.MOV, "cmovge": IROp.MOV, "cmovle": IROp.MOV,
    "cmovae": IROp.MOV, "cmovbe": IROp.MOV, "cmovs": IROp.MOV,
    "cmovns": IROp.MOV,
    "lea": IROp.LEA,
    "push": IROp.PUSH, "pop": IROp.POP,
    "xchg": IROp.XCHG,
    # Arithmetic
    "add": IROp.ADD, "adc": IROp.ADD,
    "sub": IROp.SUB, "sbb": IROp.SUB,
    "imul": IROp.MUL, "mul": IROp.MUL,
    "idiv": IROp.DIV, "div": IROp.DIV,
    "neg": IROp.NEG, "inc": IROp.INC, "dec": IROp.DEC,
    # Bitwise
    "and": IROp.AND, "or": IROp.OR, "xor": IROp.XOR, "not": IROp.NOT,
    "shl": IROp.SHL, "sal": IROp.SHL, "shr": IROp.SHR, "sar": IROp.SAR,
    "rol": IROp.ROL, "ror": IROp.ROR,
    "bt": IROp.TEST, "bts": IROp.OR, "btr": IROp.AND, "bsf": IROp.TEST,
    "bsr": IROp.TEST,
    # Compare
    "cmp": IROp.CMP, "test": IROp.TEST,
    # Control flow
    "jmp": IROp.JMP, "call": IROp.CALL, "ret": IROp.RET, "retn": IROp.RET,
    "jz": IROp.JCC, "jnz": IROp.JCC, "je": IROp.JCC, "jne": IROp.JCC,
    "ja": IROp.JCC, "jb": IROp.JCC, "jl": IROp.JCC, "jg": IROp.JCC,
    "jge": IROp.JCC, "jle": IROp.JCC, "jae": IROp.JCC, "jbe": IROp.JCC,
    "js": IROp.JCC, "jns": IROp.JCC, "jo": IROp.JCC, "jno": IROp.JCC,
    "jp": IROp.JCC, "jnp": IROp.JCC,
    "loop": IROp.JCC, "loopz": IROp.JCC, "loopnz": IROp.JCC,
    # Nop
    "nop": IROp.NOP,
    # System
    "syscall": IROp.SYSCALL, "sysenter": IROp.SYSCALL,
    "int": IROp.INT, "int3": IROp.INT,
    "in": IROp.IO, "out": IROp.IO,
    # Lock / fence
    "lock": IROp.LOCK, "mfence": IROp.FENCE, "lfence": IROp.FENCE,
    "sfence": IROp.FENCE,
    # Extensions
    "cdq": IROp.EXTEND, "cdqe": IROp.EXTEND, "cwd": IROp.EXTEND,
    "cbw": IROp.EXTEND, "cwde": IROp.EXTEND,
    # x86 string ops (simplified)
    "rep": IROp.NOP, "movsb": IROp.STORE, "movsw": IROp.STORE,
    "movsd": IROp.STORE, "movsq": IROp.STORE,
    "stosb": IROp.STORE, "stosw": IROp.STORE,
    "stosd": IROp.STORE, "stosq": IROp.STORE,
    "lodsb": IROp.LOAD, "lodsw": IROp.LOAD,
    "cmpsb": IROp.CMP, "cmpsw": IROp.CMP,
    "scasb": IROp.CMP, "scasw": IROp.CMP,
    # Set byte
    "setz": IROp.MOV, "setnz": IROp.MOV, "seta": IROp.MOV,
    "setb": IROp.MOV, "setl": IROp.MOV, "setg": IROp.MOV,
    "setge": IROp.MOV, "setle": IROp.MOV, "setae": IROp.MOV,
    "setbe": IROp.MOV,
}

# ARM/AArch64 mnemonic mapping
_ARM_MAP: Dict[str, IROp] = {
    # Data movement
    "mov": IROp.MOV, "movz": IROp.MOV, "movk": IROp.MOV,
    "movn": IROp.MOV, "mvn": IROp.NOT,
    "ldr": IROp.LOAD, "ldp": IROp.LOAD, "ldrb": IROp.LOAD,
    "ldrh": IROp.LOAD, "ldrsb": IROp.LOAD, "ldrsh": IROp.LOAD,
    "ldrsw": IROp.LOAD, "ldur": IROp.LOAD,
    "str": IROp.STORE, "stp": IROp.STORE, "strb": IROp.STORE,
    "strh": IROp.STORE, "stur": IROp.STORE,
    "adr": IROp.LEA, "adrp": IROp.LEA,
    # Arithmetic
    "add": IROp.ADD, "adds": IROp.ADD, "adc": IROp.ADD, "adcs": IROp.ADD,
    "sub": IROp.SUB, "subs": IROp.SUB, "sbc": IROp.SUB, "sbcs": IROp.SUB,
    "mul": IROp.MUL, "madd": IROp.MUL, "msub": IROp.MUL,
    "umull": IROp.MUL, "smull": IROp.MUL,
    "sdiv": IROp.DIV, "udiv": IROp.DIV,
    "neg": IROp.NEG, "negs": IROp.NEG,
    # Bitwise
    "and": IROp.AND, "ands": IROp.AND, "orr": IROp.OR, "orn": IROp.OR,
    "eor": IROp.XOR, "bic": IROp.AND,
    "lsl": IROp.SHL, "lsr": IROp.SHR, "asr": IROp.SAR, "ror": IROp.ROR,
    # Compare
    "cmp": IROp.CMP, "cmn": IROp.CMP, "tst": IROp.TEST,
    # Control flow
    "b": IROp.JMP, "br": IROp.JMP,
    "bl": IROp.CALL, "blr": IROp.CALL,
    "ret": IROp.RET,
    "cbz": IROp.JCC, "cbnz": IROp.JCC,
    "tbz": IROp.JCC, "tbnz": IROp.JCC,
    # Conditional branches (b.eq, b.ne etc mapped to JCC)
    "b.eq": IROp.JCC, "b.ne": IROp.JCC, "b.lt": IROp.JCC,
    "b.gt": IROp.JCC, "b.le": IROp.JCC, "b.ge": IROp.JCC,
    "b.hi": IROp.JCC, "b.lo": IROp.JCC, "b.hs": IROp.JCC,
    "b.ls": IROp.JCC, "b.cs": IROp.JCC, "b.cc": IROp.JCC,
    # Nop
    "nop": IROp.NOP,
    # Extensions
    "sxtb": IROp.EXTEND, "sxth": IROp.EXTEND, "sxtw": IROp.EXTEND,
    "uxtb": IROp.EXTEND, "uxth": IROp.EXTEND,
    # Atomics
    "ldxr": IROp.LOAD, "stxr": IROp.STORE,
    "ldaxr": IROp.LOAD, "stlxr": IROp.STORE,
    "dmb": IROp.FENCE, "dsb": IROp.FENCE, "isb": IROp.FENCE,
    # System
    "svc": IROp.SYSCALL, "hvc": IROp.SYSCALL,
    # Select
    "csel": IROp.MOV, "csinc": IROp.MOV, "csinv": IROp.MOV,
}

# MIPS mnemonic mapping
_MIPS_MAP: Dict[str, IROp] = {
    "move": IROp.MOV, "li": IROp.MOV, "lui": IROp.MOV, "la": IROp.LEA,
    "lw": IROp.LOAD, "lh": IROp.LOAD, "lb": IROp.LOAD, "lbu": IROp.LOAD,
    "lhu": IROp.LOAD, "ld": IROp.LOAD,
    "sw": IROp.STORE, "sh": IROp.STORE, "sb": IROp.STORE, "sd": IROp.STORE,
    "add": IROp.ADD, "addu": IROp.ADD, "addi": IROp.ADD, "addiu": IROp.ADD,
    "sub": IROp.SUB, "subu": IROp.SUB,
    "mul": IROp.MUL, "mult": IROp.MUL, "multu": IROp.MUL,
    "div": IROp.DIV, "divu": IROp.DIV,
    "and": IROp.AND, "andi": IROp.AND, "or": IROp.OR, "ori": IROp.OR,
    "xor": IROp.XOR, "xori": IROp.XOR, "nor": IROp.OR, "not": IROp.NOT,
    "sll": IROp.SHL, "srl": IROp.SHR, "sra": IROp.SAR,
    "sllv": IROp.SHL, "srlv": IROp.SHR, "srav": IROp.SAR,
    "slt": IROp.CMP, "sltu": IROp.CMP, "slti": IROp.CMP, "sltiu": IROp.CMP,
    "beq": IROp.JCC, "bne": IROp.JCC, "bgtz": IROp.JCC, "blez": IROp.JCC,
    "bgez": IROp.JCC, "bltz": IROp.JCC,
    "j": IROp.JMP, "jr": IROp.JMP,
    "jal": IROp.CALL, "jalr": IROp.CALL,
    "nop": IROp.NOP,
    "syscall": IROp.SYSCALL,
}

_ARCH_MAPS: Dict[str, Dict[str, IROp]] = {
    "x64": _X86_MAP,
    "x86": _X86_MAP,
    "AMD64": _X86_MAP,
    "x86_64": _X86_MAP,
    "ARM": _ARM_MAP,
    "AArch64": _ARM_MAP,
    "arm64": _ARM_MAP,
    "MIPS": _MIPS_MAP,
    "mips": _MIPS_MAP,
}


# ---------------------------------------------------------------------------
# IR Statement (normalized)
# ---------------------------------------------------------------------------
@dataclass(slots=True)
class IRStatement:
    """A single normalized IR statement."""
    op: IROp
    operand_pattern: str = ""      # e.g. "R,R" "R,M" "R,I"
    has_memory_access: bool = False
    is_control_flow: bool = False
    original_mnemonic: str = ""

    @property
    def signature(self) -> str:
        """Compact string: 'MOV:R,R' or 'CALL:_'"""
        return f"{self.op.value}:{self.operand_pattern}" if self.operand_pattern else self.op.value

    def __repr__(self) -> str:
        return self.signature


@dataclass
class IRSequence:
    """Normalized IR operator sequence for a function."""
    func_ea: int
    func_name: str
    arch: str
    statements: List[IRStatement] = field(default_factory=list)
    ir_hash: str = ""
    op_histogram: Dict[str, int] = field(default_factory=dict)

    @property
    def length(self) -> int:
        return len(self.statements)

    @property
    def signature_string(self) -> str:
        """Compact semicolon-separated signature for the entire function."""
        return ";".join(s.signature for s in self.statements)

    def compute_hash(self) -> str:
        """Compute a stable hash of the IR sequence."""
        sig = self.signature_string
        self.ir_hash = hashlib.sha256(sig.encode()).hexdigest()[:32]
        return self.ir_hash

    def compute_histogram(self) -> Dict[str, int]:
        """Count each IR op type."""
        hist: Dict[str, int] = {}
        for s in self.statements:
            hist[s.op.value] = hist.get(s.op.value, 0) + 1
        self.op_histogram = hist
        return hist


# ---------------------------------------------------------------------------
# Normalizer engine
# ---------------------------------------------------------------------------
class IRNormalizer:
    """
    Normalize architecture-specific instructions to canonical IR sequences.

    Usage:
        normalizer = IRNormalizer(arch="x64")
        ir_seq = normalizer.normalize_function(func_ea, func_name, instructions)
        print(ir_seq.ir_hash)
    """

    def __init__(self, arch: str = "x64"):
        self.arch = arch
        self._map = _ARCH_MAPS.get(arch, _X86_MAP)
        if arch not in _ARCH_MAPS:
            logger.warning(f"Unknown arch '{arch}', falling back to x86 map")

    def classify_mnemonic(self, mnemonic: str) -> IROp:
        """Classify a single mnemonic into an IR operator category."""
        m = mnemonic.lower().strip()
        # Direct lookup
        if m in self._map:
            return self._map[m]
        # Strip prefix (e.g. 'lock_add' -> 'add', 'rep_stosb' -> 'stosb')
        for prefix in ("lock_", "rep_", "repz_", "repnz_"):
            if m.startswith(prefix):
                base = m[len(prefix):]
                if base in self._map:
                    return self._map[base]
        # ARM conditional suffixes: 'addeq' -> 'add'
        if self.arch in ("ARM", "AArch64", "arm64"):
            for suffix in ("eq", "ne", "lt", "gt", "le", "ge", "hi", "lo", "hs", "ls"):
                if m.endswith(suffix) and m[:-len(suffix)] in self._map:
                    return self._map[m[:-len(suffix)]]
        return IROp.UNKNOWN

    def classify_operand(self, operand_str: str) -> OperandKind:
        """Classify an operand string into reg/imm/mem."""
        if not operand_str:
            return OperandKind.NONE
        s = operand_str.strip().lower()
        # Memory reference: [xxx], dword ptr [xxx], etc.
        if "[" in s or "ptr" in s:
            return OperandKind.MEM
        # Immediate: 0x..., digit, #digit (ARM)
        if s.startswith(("0x", "#")) or (s.lstrip("-").isdigit()):
            return OperandKind.IMM
        # Everything else is a register
        return OperandKind.REG

    def normalize_instruction(
        self,
        mnemonic: str,
        operands: Optional[List] = None,
    ) -> IRStatement:
        """Normalize a single instruction to an IR statement."""
        op = self.classify_mnemonic(mnemonic)

        # Build operand pattern
        if operands:
            kinds = []
            for opnd in operands:
                if hasattr(opnd, "value"):
                    kinds.append(self.classify_operand(str(opnd.value)).value)
                elif isinstance(opnd, str):
                    kinds.append(self.classify_operand(opnd).value)
                elif hasattr(opnd, "is_reg") and opnd.is_reg:
                    kinds.append(OperandKind.REG.value)
                elif hasattr(opnd, "is_imm") and opnd.is_imm:
                    kinds.append(OperandKind.IMM.value)
                else:
                    kinds.append(OperandKind.NONE.value)
            operand_pattern = ",".join(kinds)
        else:
            operand_pattern = ""

        has_memory = op in (IROp.LOAD, IROp.STORE, IROp.PUSH, IROp.POP) or (
            OperandKind.MEM.value in operand_pattern
        )
        is_cf = op in (IROp.JMP, IROp.JCC, IROp.CALL, IROp.RET)

        return IRStatement(
            op=op,
            operand_pattern=operand_pattern,
            has_memory_access=has_memory,
            is_control_flow=is_cf,
            original_mnemonic=mnemonic,
        )

    def normalize_function(
        self,
        func_ea: int,
        func_name: str,
        instructions: list,
        skip_nops: bool = True,
    ) -> IRSequence:
        """
        Normalize all instructions in a function to an IR sequence.

        Args:
            func_ea: Function address
            func_name: Function name
            instructions: List of Instruction dataclass objects
                         (from protocol_v2) or dicts with 'mnemonic' key
            skip_nops: Whether to skip NOP instructions

        Returns:
            IRSequence with normalized statements + hash
        """
        stmts: List[IRStatement] = []
        for insn in instructions:
            if hasattr(insn, "mnemonic"):
                mnemonic = insn.mnemonic
                operands = getattr(insn, "operands", None)
            elif isinstance(insn, dict):
                mnemonic = insn.get("mnemonic", "")
                operands = insn.get("operands", None)
            else:
                continue

            if not mnemonic:
                continue

            stmt = self.normalize_instruction(mnemonic, operands)
            if skip_nops and stmt.op == IROp.NOP:
                continue
            stmts.append(stmt)

        seq = IRSequence(
            func_ea=func_ea,
            func_name=func_name,
            arch=self.arch,
            statements=stmts,
        )
        seq.compute_hash()
        seq.compute_histogram()
        return seq


# ---------------------------------------------------------------------------
# Cross-arch IR similarity comparison
# ---------------------------------------------------------------------------
def compare_ir_sequences(
    seq_a: IRSequence,
    seq_b: IRSequence,
) -> float:
    """
    Compare two IR sequences using a combination of:
      1. Op-histogram cosine similarity (structural shape)
      2. LCS (Longest Common Subsequence) ratio on op sequences
      3. Length similarity

    Returns a score from 0.0 to 1.0.
    """
    if not seq_a.statements or not seq_b.statements:
        return 0.0

    # Weight: histogram=0.4, LCS=0.4, length=0.2
    hist_sim = _histogram_cosine(seq_a.op_histogram, seq_b.op_histogram)
    lcs_ratio = _lcs_ratio(
        [s.op.value for s in seq_a.statements],
        [s.op.value for s in seq_b.statements],
    )
    len_sim = _length_similarity(seq_a.length, seq_b.length)

    return hist_sim * 0.4 + lcs_ratio * 0.4 + len_sim * 0.2


def compare_ir_hashes(hash_a: str, hash_b: str) -> bool:
    """Check if two IR hashes match exactly."""
    return hash_a == hash_b and hash_a != ""


def _histogram_cosine(
    hist_a: Dict[str, int], hist_b: Dict[str, int],
) -> float:
    """Cosine similarity between two op histograms."""
    all_keys = set(hist_a) | set(hist_b)
    if not all_keys:
        return 0.0

    dot = sum(hist_a.get(k, 0) * hist_b.get(k, 0) for k in all_keys)
    mag_a = sum(v * v for v in hist_a.values()) ** 0.5
    mag_b = sum(v * v for v in hist_b.values()) ** 0.5

    if mag_a == 0 or mag_b == 0:
        return 0.0
    return dot / (mag_a * mag_b)


def _lcs_ratio(seq_a: List[str], seq_b: List[str]) -> float:
    """
    LCS ratio = 2 * len(LCS) / (len(a) + len(b)).

    Uses a space-optimized O(n*m) DP approach.
    Capped at 200 elements per sequence for performance.
    """
    a = seq_a[:200]
    b = seq_b[:200]
    n, m = len(a), len(b)
    if n == 0 or m == 0:
        return 0.0

    # O(m) space DP
    prev = [0] * (m + 1)
    for i in range(1, n + 1):
        curr = [0] * (m + 1)
        for j in range(1, m + 1):
            if a[i - 1] == b[j - 1]:
                curr[j] = prev[j - 1] + 1
            else:
                curr[j] = max(prev[j], curr[j - 1])
        prev = curr

    lcs_len = prev[m]
    return (2 * lcs_len) / (n + m)


def _length_similarity(len_a: int, len_b: int) -> float:
    """Similarity based on instruction count ratio."""
    if len_a == 0 and len_b == 0:
        return 1.0
    if len_a == 0 or len_b == 0:
        return 0.0
    return min(len_a, len_b) / max(len_a, len_b)


# ---------------------------------------------------------------------------
# Batch normalization for full exports
# ---------------------------------------------------------------------------
def normalize_export(
    export,
    arch: str = "x64",
    skip_imports: bool = True,
) -> Dict[int, IRSequence]:
    """
    Normalize all functions in a DriverAnalysisExportV2.

    Args:
        export: DriverAnalysisExportV2 instance
        arch: Architecture identifier
        skip_imports: Skip imported functions

    Returns:
        Dict mapping func_ea -> IRSequence
    """
    normalizer = IRNormalizer(arch=arch)
    results: Dict[int, IRSequence] = {}

    for ea_str, fi in export.functions.items():
        if skip_imports and fi.is_import:
            continue
        insns = export.function_instructions.get(ea_str, [])
        if not insns:
            continue
        seq = normalizer.normalize_function(fi.ea, fi.name, insns)
        results[fi.ea] = seq

    logger.info(f"Normalized {len(results)} functions to IR ({arch})")
    return results
