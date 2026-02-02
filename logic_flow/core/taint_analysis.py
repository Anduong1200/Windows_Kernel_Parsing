"""
Data Flow / Taint Analysis Module for Logic Flow Analysis.

Tracks data propagation from input sources (SystemBuffer, IoControlCode)
to sensitive sinks (memory operations, pointer dereferences).

This enables detecting:
- Unchecked user input reaching kernel operations
- Missing input validation
- Potential buffer overflows
"""

import logging
from typing import Dict, List, Set, Optional, Tuple
from dataclasses import dataclass, field
from enum import Enum, auto

logger = logging.getLogger(__name__)


class TaintState(Enum):
    """Taint state for a value or register."""
    CLEAN = auto()      # No taint
    TAINTED = auto()    # Contains user-controlled data
    DERIVED = auto()    # Derived from tainted data (partial taint)
    SANITIZED = auto()  # Was tainted but passed through validation


@dataclass
class TaintedValue:
    """Represents a tainted value in the analysis."""
    source: str                     # Where the taint originated
    source_address: int             # Instruction address where taint started
    state: TaintState = TaintState.TAINTED
    propagation_path: List[int] = field(default_factory=list)  # Instruction addresses


@dataclass
class TaintSink:
    """Represents a location where tainted data reaches a sensitive operation."""
    sink_type: str                  # Type of sensitive operation
    sink_address: int               # Address of sensitive operation
    tainted_values: List[TaintedValue] = field(default_factory=list)
    is_validated: bool = False      # Whether input was validated before reaching sink
    severity: str = "HIGH"          # HIGH, MEDIUM, LOW


class TaintAnalyzer:
    """
    Performs data flow / taint analysis on function code.
    
    Note: Full taint analysis requires Hex-Rays decompiler (ida_hexrays).
    This implementation provides a simplified version using instruction
    patterns for cases where decompiler is not available.
    """
    
    # Default taint sources (common IOCTL input locations)
    DEFAULT_SOURCES = [
        'SystemBuffer',
        'Type3InputBuffer',
        'MdlAddress',
        'InputBufferLength',
        'IoControlCode',
        'UserBuffer',
        'Parameters',
        'DeviceIoControl.InputBuffer'
    ]
    
    # Default taint sinks (sensitive kernel operations)
    DEFAULT_SINKS = [
        # Memory operations
        ('MmMapLockedPages', 'MEMORY_MAP', 'HIGH'),
        ('MmProbeAndLockPages', 'MEMORY_LOCK', 'HIGH'),
        ('ProbeForRead', 'PROBE', 'MEDIUM'),
        ('ProbeForWrite', 'PROBE', 'MEDIUM'),
        
        # Memory copy
        ('RtlCopyMemory', 'MEMORY_COPY', 'HIGH'),
        ('RtlMoveMemory', 'MEMORY_COPY', 'HIGH'),
        ('memcpy', 'MEMORY_COPY', 'HIGH'),
        ('memmove', 'MEMORY_COPY', 'HIGH'),
        
        # Pool allocation (size from user input)
        ('ExAllocatePool', 'ALLOCATION', 'MEDIUM'),
        ('ExAllocatePoolWithTag', 'ALLOCATION', 'MEDIUM'),
        
        # Direct memory access
        ('READ_PORT_UCHAR', 'IO_PORT', 'HIGH'),
        ('WRITE_PORT_UCHAR', 'IO_PORT', 'HIGH'),
    ]
    
    # Sanitizer functions (validation APIs)
    SANITIZERS = [
        'ProbeForRead',
        'ProbeForWrite',
        'SeAccessCheck',
        'IoValidateDeviceIoControlAccess',
        'RtlULongMult',  # Safe integer math
        'RtlULongAdd',
    ]
    
    def __init__(self, ida_provider=None, config=None):
        """
        Initialize taint analyzer.
        
        Args:
            ida_provider: IDA provider for code access
            config: TaintAnalysisConfig from heuristics_config
        """
        self.ida_provider = ida_provider
        self.config = config
        
        # Analysis state
        self._tainted_registers: Dict[str, TaintedValue] = {}
        self._tainted_memory: Dict[int, TaintedValue] = {}
        self._sinks_reached: List[TaintSink] = []
    
    def analyze_function(self, func_ea: int) -> Dict:
        """
        Perform taint analysis on a function.
        
        Args:
            func_ea: Function address
            
        Returns:
            Analysis results dictionary
        """
        if not self.ida_provider:
            return {'error': 'No IDA provider available'}
        
        # Reset state
        self._tainted_registers.clear()
        self._tainted_memory.clear()
        self._sinks_reached.clear()
        
        results = {
            'function': hex(func_ea),
            'taint_sources': [],
            'taint_sinks': [],
            'unvalidated_paths': [],
            'risk_level': 'LOW'
        }
        
        try:
            # Get function bounds
            func = self.ida_provider.get_func(func_ea)
            if not func:
                return results
            
            # Phase 1: Identify taint sources in function
            sources = self._find_taint_sources(func_ea)
            results['taint_sources'] = sources
            
            # Phase 2: Track taint propagation (Fixed-point iteration)
            # We iterate until no new taint information is discovered to handle loops/backward jumps
            max_iterations = 100
            iteration = 0
            changed = True
            
            while changed and iteration < max_iterations:
                changed = False
                state_checksum_before = len(self._tainted_registers) + len(self._tainted_memory)
                
                # We don't propagate from sources every time, we propagate from current state
                # But sources initialized the state, so we just run the propagation function
                # over all instructions again.
                if self._propagate_taint_pass(func_ea):
                    changed = True
                
                state_checksum_after = len(self._tainted_registers) + len(self._tainted_memory)
                if state_checksum_after != state_checksum_before:
                    changed = True
                    
                iteration += 1
            
            if iteration >= max_iterations:
                logger.warning(f"Taint analysis reached max iterations ({max_iterations}) for 0x{func_ea:X}")
            
            # Phase 3: Check for taint reaching sinks
            sinks = self._find_taint_sinks(func_ea)
            results['taint_sinks'] = [self._sink_to_dict(s) for s in sinks]
            
            # Phase 4: Identify unvalidated paths
            unvalidated = [s for s in sinks if not s.is_validated]
            results['unvalidated_paths'] = [{
                'source': s.tainted_values[0].source if s.tainted_values else 'unknown',
                'sink': s.sink_type,
                'sink_address': hex(s.sink_address),
                'severity': s.severity
            } for s in unvalidated]
            
            # Determine overall risk
            if any(s.severity == 'HIGH' for s in unvalidated):
                results['risk_level'] = 'HIGH'
            elif unvalidated:
                results['risk_level'] = 'MEDIUM'
            
        except Exception as e:
            logger.error(f"Taint analysis failed for 0x{func_ea:X}: {e}")
            results['error'] = str(e)
        
        return results
    
    def _find_taint_sources(self, func_ea: int) -> List[Dict]:
        """Find taint sources (user input) in function."""
        sources = []
        
        # Get function disassembly
        instructions = self.ida_provider.get_func_instructions(func_ea)
        
        for insn_ea, mnemonic, operands in instructions:
            operands_str = ' '.join(operands) if operands else ''
            
            # Check for source patterns  
            for source_name in self.DEFAULT_SOURCES:
                if source_name.lower() in operands_str.lower():
                    sources.append({
                        'name': source_name,
                        'address': hex(insn_ea),
                        'instruction': f"{mnemonic} {operands_str}"
                    })
                    
                    # Mark destination register as tainted
                    if mnemonic.lower() in ('mov', 'lea') and operands:
                        dest_reg = operands[0].split(',')[0].strip()
                        self._tainted_registers[dest_reg] = TaintedValue(
                            source=source_name,
                            source_address=insn_ea,
                            propagation_path=[insn_ea]
                        )
        
        return sources
    
    def _propagate_taint_pass(self, func_ea: int) -> bool:
        """
        Single pass of taint propagation through data flow.
        
        Returns:
            True if new taint info was added (used for fixed-point iteration)
        """
        changed = False
        instructions = self.ida_provider.get_func_instructions(func_ea)
        
        for insn_ea, mnemonic, operands in instructions:
            if not operands:
                continue
            
            # Helper to normalize operand (e.g., "[rsp+20h]" -> "MEM_RSP_20")
            def normalize_op(op):
                op = op.strip()
                if '[' in op and ']' in op:
                    # Simple normalization for stack/memory
                    # Only handles basic [reg+offset] patterns
                    clean = op.replace('[', '').replace(']', '').replace('+', '_').replace('-', '_')
                    # Remove size directives like "qword ptr "
                    if ' ptr ' in clean:
                        clean = clean.split(' ptr ')[-1]
                    return f"MEM_{clean}"
                return op.split(',')[0].strip() # Handle cases where split might be wrong

            operands_str = ','.join(operands)
            # Better split that respects brackets? For now assume simple comma split
            # A real parser would be better but expensive
            parts = operands  # IDA provider gives list, reliable
            
            if len(parts) >= 2:
                dest = normalize_op(parts[0])
                src = normalize_op(parts[1])
                
                # Check if source is tainted
                tainted_src = None
                if src in self._tainted_registers:
                    tainted_src = self._tainted_registers[src]
                elif src in self._tainted_memory: # Check memory
                    tainted_src = self._tainted_memory[src]

                if tainted_src:
                    # Check if destination is already tainted with same info
                    is_new_taint = True
                    existing_taint = None
                    
                    if dest.startswith("MEM_"):
                        existing_taint = self._tainted_memory.get(dest)
                    else:
                        existing_taint = self._tainted_registers.get(dest)
                        
                    if existing_taint and existing_taint.source == tainted_src.source:
                        # Simple check: same source, maybe different path?
                        # For fixed point, we care if we gain NEW taint coverage.
                        # Since we OR, if it's there it's there. Simpler analysis.
                        is_new_taint = False

                    if is_new_taint:
                        # Create new tainted value state
                        new_taint = TaintedValue(
                            source=tainted_src.source,
                            source_address=tainted_src.source_address,
                            state=TaintState.DERIVED,
                            propagation_path=tainted_src.propagation_path + [insn_ea]
                        )
                        
                        # Store in register or memory
                        if dest.startswith("MEM_"):
                            self._tainted_memory[dest] = new_taint
                        else:
                            self._tainted_registers[dest] = new_taint
                        changed = True
        return changed
    
    def _find_taint_sinks(self, func_ea: int) -> List[TaintSink]:
        """Find sensitive operations that receive tainted data."""
        sinks = []
        
        # Get cross-references (calls) from function
        xrefs = self.ida_provider.get_func_xrefs_from(func_ea)
        
        for xref_ea, target_ea in xrefs:
            target_name = self.ida_provider.get_func_name(target_ea) or ''
            
            # Check if target is a sink
            for sink_name, sink_type, severity in self.DEFAULT_SINKS:
                if sink_name.lower() in target_name.lower():
                    # Check if any tainted register is used as argument
                    tainted_args = []
                    for reg, taint in self._tainted_registers.items():
                        tainted_args.append(taint)
                    
                    if tainted_args:
                        # Check for sanitization
                        is_validated = self._check_sanitization(
                            tainted_args[0].propagation_path, xref_ea
                        )
                        
                        sinks.append(TaintSink(
                            sink_type=sink_type,
                            sink_address=xref_ea,
                            tainted_values=tainted_args,
                            is_validated=is_validated,
                            severity=severity
                        ))
        
        return sinks
    
    def _check_sanitization(self, path: List[int], sink_addr: int) -> bool:
        """Check if taint was sanitized before reaching sink."""
        # Look for calls to sanitizer functions along the path
        for addr in path:
            # Check if there's a call to a sanitizer near this address
            for sanitizer in self.SANITIZERS:
                # This is simplified - full implementation would trace actual calls
                if self.ida_provider:
                    nearby_calls = self.ida_provider.get_xrefs_from_range(addr, addr + 20)
                    for _, target in nearby_calls:
                        target_name = self.ida_provider.get_func_name(target) or ''
                        if sanitizer.lower() in target_name.lower():
                            return True
        return False
    
    def _sink_to_dict(self, sink: TaintSink) -> Dict:
        """Convert TaintSink to dictionary."""
        return {
            'type': sink.sink_type,
            'address': hex(sink.sink_address),
            'severity': sink.severity,
            'is_validated': sink.is_validated,
            'source_count': len(sink.tainted_values)
        }
    
    def get_vulnerability_report(self, func_ea: int) -> str:
        """Generate human-readable vulnerability report."""
        analysis = self.analyze_function(func_ea)
        
        lines = [
            f"=== Taint Analysis Report for {analysis['function']} ===",
            f"Risk Level: {analysis['risk_level']}",
            "",
            f"Taint Sources ({len(analysis['taint_sources'])}):",
        ]
        
        for src in analysis['taint_sources']:
            lines.append(f"  - {src['name']} at {src['address']}")
        
        lines.append("")
        lines.append(f"Sensitive Sinks ({len(analysis['taint_sinks'])}):")
        
        for sink in analysis['taint_sinks']:
            status = "✓ Validated" if sink['is_validated'] else "⚠ UNVALIDATED"
            lines.append(f"  - [{sink['severity']}] {sink['type']} at {sink['address']} {status}")
        
        if analysis['unvalidated_paths']:
            lines.append("")
            lines.append("⚠ POTENTIAL VULNERABILITIES:")
            for vuln in analysis['unvalidated_paths']:
                lines.append(f"  - {vuln['source']} → {vuln['sink']} (Severity: {vuln['severity']})")
        
        return '\n'.join(lines)
