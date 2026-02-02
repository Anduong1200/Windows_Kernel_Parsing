"""
Double-Fetch Detection Module.
Part of Phase 10 / Module 8: Pwn Capabilities.

Goal: Detect Race Conditions where User Mode memory is fetched twice 
(Time-of-Check vs Time-of-Use / TOCTOU).

Enhanced with:
- UserMode address filtering
- Instruction distance heuristics
- Severity scoring
"""

import logging
from typing import Dict, Any, List, Optional
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)


@dataclass
class MemoryAccess:
    """Represents a single memory access."""
    pc: int                    # Instruction address
    addr: int                  # Memory address accessed
    symbolic_addr: Any = None  # Claripy symbolic address (for constraint solving)
    access_idx: int = 0        # Sequential access index (for distance calc)


@dataclass
class DoubleFetchFinding:
    """Represents a detected double-fetch vulnerability."""
    address: int
    first_access_pc: int
    second_access_pc: int
    instruction_distance: int
    severity: str
    description: str
    is_usermode: bool = False
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "type": "DOUBLE_FETCH",
            "address": hex(self.address),
            "first_access": hex(self.first_access_pc),
            "second_access": hex(self.second_access_pc),
            "instruction_distance": self.instruction_distance,
            "severity": self.severity,
            "is_usermode": self.is_usermode,
            "description": self.description
        }


class DoubleFetchDetector:
    """
    Tracks memory access patterns to find double fetches (TOCTOU vulnerabilities).
    
    Usage:
        detector = DoubleFetchDetector()
        detector.attach_tracker(angr_state)
        # ... run symbolic execution ...
        findings = detector.scan_for_vulnerabilities()
    """
    
    # Thresholds for severity classification
    MIN_DISTANCE_FOR_EXPLOIT = 5      # Min instructions between accesses for "exploitable" rating
    HIGH_SEVERITY_DISTANCE = 20       # Distance threshold for HIGH severity
    MEDIUM_SEVERITY_DISTANCE = 10     # Distance threshold for MEDIUM severity
    
    # UserMode address ranges (x64 Windows)
    USERMODE_MAX = 0x00007FFFFFFFFFFF  # Highest user-mode address on x64
    KERNELMODE_MIN = 0xFFFF800000000000  # Lowest kernel-mode address on x64

    def __init__(self, track_kernel: bool = False):
        """
        Initialize detector.
        
        Args:
            track_kernel: If True, also track kernel-mode addresses (less common for TOCTOU)
        """
        self.access_log: List[MemoryAccess] = []
        self.track_kernel = track_kernel
        self._access_counter = 0

    def attach_tracker(self, state: Any):
        """
        Attach SimInspect breakpoints to trace memory reads.
        
        Args:
            state: angr.SimState to attach to
        """
        try:
            state.inspect.b('mem_read', when='before', action=self._trace_read)
            logger.info("DoubleFetchDetector attached to state")
        except Exception as e:
            logger.error(f"Failed to attach inspector: {e}")

    def _trace_read(self, state):
        """
        Callback for memory reads.
        """
        try:
            read_addr = state.inspect.mem_read_address
            insn_addr = state.addr
            
            # Solve for concrete address
            conc_addr = state.solver.eval(read_addr)
            
            # Filter: Only track UserMode addresses unless track_kernel is True
            if not self.track_kernel:
                if conc_addr > self.USERMODE_MAX:
                    return  # Skip kernel addresses
            
            self._access_counter += 1
            self.access_log.append(MemoryAccess(
                pc=insn_addr,
                addr=conc_addr,
                symbolic_addr=read_addr,
                access_idx=self._access_counter
            ))
        except Exception as e:
            # Silent fail - don't spam logs during symbolic execution
            pass

    def _is_usermode_address(self, addr: int) -> bool:
        """Check if address is in user-mode range."""
        return addr <= self.USERMODE_MAX

    def _calculate_severity(self, distance: int, is_usermode: bool) -> str:
        """
        Calculate severity based on instruction distance and address type.
        
        Larger distances = more time for attacker to race = higher severity.
        """
        if not is_usermode:
            return "LOW"  # Kernel-to-kernel double fetch is less exploitable
        
        if distance < self.MIN_DISTANCE_FOR_EXPLOIT:
            return "INFO"  # Too close together to race
        elif distance >= self.HIGH_SEVERITY_DISTANCE:
            return "HIGH"
        elif distance >= self.MEDIUM_SEVERITY_DISTANCE:
            return "MEDIUM"
        else:
            return "LOW"

    def scan_for_vulnerabilities(self) -> List[DoubleFetchFinding]:
        """
        Analyze the access log for Double Fetch patterns.
        
        Returns:
            List of DoubleFetchFinding objects
        """
        findings = []
        
        # Map: Memory Address -> List of MemoryAccess
        access_map: Dict[int, List[MemoryAccess]] = {}
        for entry in self.access_log:
            if entry.addr not in access_map:
                access_map[entry.addr] = []
            access_map[entry.addr].append(entry)

        for addr, accesses in access_map.items():
            if len(accesses) < 2:
                continue  # Need at least 2 accesses for double-fetch
            
            # Sort by access index to get temporal order
            accesses.sort(key=lambda a: a.access_idx)
            
            # Check each pair of accesses
            for i in range(len(accesses) - 1):
                first = accesses[i]
                second = accesses[i + 1]
                
                # Calculate instruction distance (proxy for "time window")
                distance = second.access_idx - first.access_idx
                
                # Skip if same instruction (e.g., loop accessing same location)
                if first.pc == second.pc:
                    continue
                
                is_usermode = self._is_usermode_address(addr)
                severity = self._calculate_severity(distance, is_usermode)
                
                # Skip INFO-level findings by default
                if severity == "INFO":
                    continue
                
                findings.append(DoubleFetchFinding(
                    address=addr,
                    first_access_pc=first.pc,
                    second_access_pc=second.pc,
                    instruction_distance=distance,
                    severity=severity,
                    is_usermode=is_usermode,
                    description=f"UserMode memory at {hex(addr)} read {len(accesses)} times. "
                                f"Distance: {distance} instructions. Potential TOCTOU race condition."
                ))
        
        # Sort by severity (HIGH first)
        severity_order = {"HIGH": 0, "MEDIUM": 1, "LOW": 2, "INFO": 3}
        findings.sort(key=lambda f: severity_order.get(f.severity, 99))
        
        logger.info(f"DoubleFetch scan complete: {len(findings)} potential vulnerabilities found")
        return findings

    def get_summary(self) -> Dict[str, Any]:
        """Get summary statistics of the access log."""
        unique_addrs = len(set(a.addr for a in self.access_log))
        usermode_addrs = sum(1 for a in self.access_log if self._is_usermode_address(a.addr))
        
        return {
            "total_accesses": len(self.access_log),
            "unique_addresses": unique_addrs,
            "usermode_accesses": usermode_addrs,
            "kernel_accesses": len(self.access_log) - usermode_addrs
        }

    def clear(self):
        """Clear the access log for new analysis."""
        self.access_log.clear()
        self._access_counter = 0

