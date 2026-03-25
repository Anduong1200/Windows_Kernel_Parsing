"""
Export Schema v2 — Versioned Data Contract for FastDiff.

This module defines the canonical data structures for binary exports.
All fields are explicitly typed. The schema is disassembler-agnostic:
IDA, Ghidra, or any other tool can produce this format.

ZERO heavy dependencies. Compatible with IDAPython 3.10+.
"""

from __future__ import annotations
from dataclasses import dataclass, field, asdict
from typing import List, Dict, Optional
import json
import hashlib

# ---------------------------------------------------------------------------
# Schema version — bump on breaking changes
# ---------------------------------------------------------------------------
SCHEMA_VERSION = "2.0"


# ---------------------------------------------------------------------------
# Instruction-level data
# ---------------------------------------------------------------------------
@dataclass(slots=True)
class Operand:
    """Single instruction operand."""
    type: int           # IDA o_reg / o_mem / o_imm / ...
    value: str          # Normalized string repr
    is_reg: bool = False
    is_imm: bool = False


@dataclass(slots=True)
class Instruction:
    """Single disassembled instruction with resolved targets."""
    ea: int
    mnemonic: str
    operands: List[Operand] = field(default_factory=list)
    bytes_hex: str = ""
    target_ea: Optional[int] = None
    target_name: Optional[str] = None


# ---------------------------------------------------------------------------
# Function & call-graph
# ---------------------------------------------------------------------------
@dataclass(slots=True)
class FunctionInfo:
    """Function node metadata."""
    ea: int
    name: str
    start_ea: int
    end_ea: int
    size: int
    is_import: bool = False
    is_export: bool = False
    demangled_name: Optional[str] = None


@dataclass(slots=True)
class CallSite:
    """
    A single call-graph edge with callsite resolution.
    callsite_ea = the address of the CALL instruction itself.
    """
    caller_ea: int
    callee_ea: int
    callsite_ea: int
    type: str = "direct"            # "direct" | "indirect" | "callback"
    target_name: Optional[str] = None


# ---------------------------------------------------------------------------
# Strings & imports
# ---------------------------------------------------------------------------
@dataclass(slots=True)
class StringEntry:
    """Extracted string with cross-references back to functions."""
    ea: int
    value: str
    encoding: str = "utf-8"         # "utf-8" | "utf-16" | "ascii"
    xref_funcs: List[int] = field(default_factory=list)


@dataclass(slots=True)
class ImportEntry:
    """Imported API symbol."""
    ea: int
    name: str
    module: str = ""                # DLL / library name
    ordinal: Optional[int] = None


@dataclass(slots=True)
class ExportEntry:
    """Exported symbol."""
    ea: int
    name: str
    ordinal: Optional[int] = None


# ---------------------------------------------------------------------------
# Driver interface (attack surface)
# ---------------------------------------------------------------------------
@dataclass(slots=True)
class DispatchEntry:
    """IRP MajorFunction dispatch table entry."""
    major_function: int             # IRP_MJ_* index
    handler_ea: int
    handler_name: str = ""
    irql: str = "PASSIVE"


@dataclass(slots=True)
class DeviceObject:
    """IoCreateDevice result."""
    name: str = ""
    symlink: Optional[str] = None
    device_type: int = 0
    characteristics: int = 0


@dataclass(slots=True)
class IOCTLEntry:
    """Extracted IOCTL code → handler mapping."""
    code: int
    method: str = "BUFFERED"        # BUFFERED / IN_DIRECT / OUT_DIRECT / NEITHER
    handler_ea: int = 0
    input_size: Optional[int] = None
    output_size: Optional[int] = None


@dataclass(slots=True)
class DriverInterface:
    """Aggregated attack surface model."""
    dispatch_table: List[DispatchEntry] = field(default_factory=list)
    devices: List[DeviceObject] = field(default_factory=list)
    ioctls: List[IOCTLEntry] = field(default_factory=list)
    detected_pools: List[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Metadata
# ---------------------------------------------------------------------------
@dataclass(slots=True)
class ExportMetadata:
    """Top-level metadata envelope."""
    schema_version: str = SCHEMA_VERSION
    binary_sha256: str = ""
    timestamp: str = ""
    tool: str = "IDA Pro"
    input_file: str = ""
    arch: str = "x64"
    file_format: str = "PE"


# ---------------------------------------------------------------------------
# Root export object
# ---------------------------------------------------------------------------
@dataclass
class DriverAnalysisExportV2:
    """
    Complete export from a disassembler.
    This is the single source of truth consumed by the diff pipeline.
    """
    metadata: ExportMetadata = field(default_factory=ExportMetadata)
    functions: Dict[str, FunctionInfo] = field(default_factory=dict)
    call_graph: List[CallSite] = field(default_factory=list)
    function_instructions: Dict[str, List[Instruction]] = field(default_factory=dict)
    strings: List[StringEntry] = field(default_factory=list)
    imports: List[ImportEntry] = field(default_factory=list)
    exports: List[ExportEntry] = field(default_factory=list)
    driver_interface: DriverInterface = field(default_factory=DriverInterface)

    # ----- Serialization -----

    def to_dict(self) -> dict:
        """Convert to plain dict for JSON serialization."""
        return asdict(self)

    def to_json(self, indent: int = 2) -> str:
        """Serialize to JSON string."""
        return json.dumps(self.to_dict(), indent=indent, default=str)

    def save(self, path: str) -> None:
        """Write to file."""
        with open(path, "w", encoding="utf-8") as f:
            f.write(self.to_json())

    # ----- Deserialization -----

    @classmethod
    def from_dict(cls, data: dict) -> "DriverAnalysisExportV2":
        """Parse from raw dict (e.g. loaded JSON)."""
        meta_raw = data.get("metadata", {})
        meta = ExportMetadata(**{
            k: v for k, v in meta_raw.items()
            if k in ExportMetadata.__dataclass_fields__
        })

        # Validate schema version
        if meta.schema_version != SCHEMA_VERSION:
            import warnings
            warnings.warn(
                f"Schema version mismatch: expected {SCHEMA_VERSION}, "
                f"got {meta.schema_version}. Parsing may be lossy."
            )

        # Parse functions
        functions = {}
        for ea_key, fdata in data.get("functions", {}).items():
            fi_kwargs = {k: v for k, v in fdata.items()
                         if k in FunctionInfo.__dataclass_fields__}
            functions[str(ea_key)] = FunctionInfo(**fi_kwargs)

        # Parse call graph
        call_graph = []
        for edge in data.get("call_graph", []):
            cs_kwargs = {k: v for k, v in edge.items()
                         if k in CallSite.__dataclass_fields__}
            call_graph.append(CallSite(**cs_kwargs))

        # Parse instructions
        func_insns: Dict[str, List[Instruction]] = {}
        for ea_key, insns_raw in data.get("function_instructions", {}).items():
            insns = []
            for ir in insns_raw:
                ops = [Operand(**{k: v for k, v in o.items()
                                  if k in Operand.__dataclass_fields__})
                       for o in ir.get("operands", [])]
                insn_kwargs = {k: v for k, v in ir.items()
                               if k in Instruction.__dataclass_fields__
                               and k != "operands"}
                insns.append(Instruction(operands=ops, **insn_kwargs))
            func_insns[str(ea_key)] = insns

        # Parse strings
        strings = [StringEntry(**{k: v for k, v in s.items()
                                   if k in StringEntry.__dataclass_fields__})
                   for s in data.get("strings", [])]

        # Parse imports
        imports = [ImportEntry(**{k: v for k, v in i.items()
                                   if k in ImportEntry.__dataclass_fields__})
                   for i in data.get("imports", [])]

        # Parse exports
        exports = [ExportEntry(**{k: v for k, v in e.items()
                                   if k in ExportEntry.__dataclass_fields__})
                   for e in data.get("exports", [])]

        # Parse driver interface
        di_raw = data.get("driver_interface", {})
        driver_interface = DriverInterface(
            dispatch_table=[DispatchEntry(**{k: v for k, v in d.items()
                                             if k in DispatchEntry.__dataclass_fields__})
                            for d in di_raw.get("dispatch_table", [])],
            devices=[DeviceObject(**{k: v for k, v in d.items()
                                     if k in DeviceObject.__dataclass_fields__})
                     for d in di_raw.get("devices", [])],
            ioctls=[IOCTLEntry(**{k: v for k, v in d.items()
                                  if k in IOCTLEntry.__dataclass_fields__})
                    for d in di_raw.get("ioctls", [])],
            detected_pools=di_raw.get("detected_pools", []),
        )

        return cls(
            metadata=meta,
            functions=functions,
            call_graph=call_graph,
            function_instructions=func_insns,
            strings=strings,
            imports=imports,
            exports=exports,
            driver_interface=driver_interface,
        )

    @classmethod
    def load(cls, path: str) -> "DriverAnalysisExportV2":
        """Load from JSON file."""
        with open(path, "r", encoding="utf-8") as f:
            return cls.from_dict(json.load(f))


# ---------------------------------------------------------------------------
# Validation helpers
# ---------------------------------------------------------------------------
def validate_export(data: dict) -> List[str]:
    """
    Validate a raw dict against schema v2. Returns list of error strings.
    Empty list = valid.
    """
    errors = []

    meta = data.get("metadata")
    if not meta:
        errors.append("Missing 'metadata' field")
    else:
        if meta.get("schema_version") != SCHEMA_VERSION:
            errors.append(
                f"schema_version must be '{SCHEMA_VERSION}', "
                f"got '{meta.get('schema_version')}'"
            )
        if not meta.get("binary_sha256"):
            errors.append("Missing 'metadata.binary_sha256'")

    if "functions" not in data:
        errors.append("Missing 'functions' field")

    if "call_graph" not in data:
        errors.append("Missing 'call_graph' field")

    return errors


def compute_file_sha256(filepath: str) -> str:
    """Compute SHA256 of a file on disk."""
    h = hashlib.sha256()
    with open(filepath, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 16), b""):
            h.update(chunk)
    return h.hexdigest()
