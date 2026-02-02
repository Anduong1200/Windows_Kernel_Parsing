"""
Data Protocol for Logic Flow Analysis (Split Architecture).

Defines the shared data structures (Schema) for communication between:
1. Extractor (IDA Pro) - Dumps this data.
2. Core Engine (External Python) - Consumes this data.

This module must have ZERO heavy dependencies (no networkx, no angr, no scipy).
It must be compatible with IDAPython (Python 3.x).
"""

from typing import List, Dict, Optional, Any, TypedDict, Union

# --- Versioning ---
PROTOCOL_VERSION = "1.0.0"


# --- 1. Instruction Schema (For Fuzzy Hashing) ---
class OperandData(TypedDict):
    """Represents a single instruction operand."""
    type: int          # IDA-specific operand type (o_reg, o_mem, etc.)
    value: str         # String representation or normalized value
    is_reg: bool       # Is it a register?
    is_imm: bool       # Is it an immediate?


class InstructionData(TypedDict):
    """Represents a single disassembled instruction."""
    ea: int            # Effective Address
    mnemonic: str      # E.g., "mov", "call"
    operands: List[OperandData]
    bytes_hex: str     # Hex representation of machine code (e.g., "4889C5")


# --- 2. Graph Schema (Nodes & Edges) ---
class FunctionNodeData(TypedDict):
    """Basic metadata for a function node."""
    ea: int
    name: str
    is_import: bool
    is_export: bool
    demangled_name: Optional[str]


class CallEdgeData(TypedDict):
    """Represents a call graph edge."""
    caller_ea: int
    callee_ea: int
    type: str  # "direct", "indirect", "callback"


class BasicBlockData(TypedDict):
    """Represents a basic block (for detailed CFG analysis if needed)."""
    start_ea: int
    end_ea: int
    successors: List[int]


# --- 3. Root Export Object ---
class DriverAnalysisExport(TypedDict):
    """
    The root JSON object dumped by the IDA Extractor.
    """
    metadata: Dict[str, Any]  # Timestamp, SHA256, File Name, Tool Version
    
    # Global Maps
    functions: Dict[int, FunctionNodeData]  # EA -> Info
    
    # Graph Data
    call_graph: List[CallEdgeData]
    
    # Detailed Data (extracted only for relevant functions)
    # EA -> List[InstructionData]
    # We might not dump ALL instructions for ALL functions to save space,
    # or we might dump everything for full fidelity. 
    # For now, let's assume we dump instructions for the "Anchor Neighborhood".
    function_instructions: Dict[int, List[InstructionData]]
    
    # Strings / Imports for heuristics
    strings: List[Dict[str, Any]] # ea, value
    imports: List[Dict[str, Any]] # ea, name, lib
    
    # Attack Surface Data (New in v3.1)
    driver_interface: 'DriverInterfaceData'


# --- 4. Attack Surface Schema (v3.1) ---
class DispatchEntry(TypedDict):
    """Entry in the MajorFunction dispatch table."""
    irql: str # "PASSIVE", "DISPATCH", etc (inferred)
    major_function: int # IRP_MJ_CREATE (0), etc.
    handler_ea: int
    handler_name: str

class DeviceObjectData(TypedDict):
    """Device object created by the driver."""
    name: str # e.g. "\Device\MyDriver"
    symlink: Optional[str] # e.g. "\DosDevices\MyDriver"
    device_type: int # FILE_DEVICE_*
    characteristics: int

class IOCTLEntry(TypedDict):
    """Extracted IOCTL code and its handling."""
    code: int
    method: str # "BUFFERED", "IN_DIRECT", "OUT_DIRECT", "NEITHER"
    handler_ea: int
    input_size: Optional[int] # Min required size
    output_size: Optional[int] # Max output size

class DriverInterfaceData(TypedDict):
    """Aggregated attack surface model."""
    dispatch_table: List[DispatchEntry]
    devices: List[DeviceObjectData]
    ioctls: List[IOCTLEntry]
    detected_pools: List[str] # Pool tags extracted
