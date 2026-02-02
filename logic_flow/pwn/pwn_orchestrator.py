"""
Pwn Orchestrator - Automated Vulnerability Pipeline.
Coordinates TaintEngine, SymbolicExecution, and ExploitGenerator.

Data Flow:
1. TaintEngine scans graph for IOCTL-reachable dangerous sinks.
2. For each vulnerable sink, SymbolicExecution finds a path.
3. ExploitGenerator produces the final PoC from the crash state.
"""

import logging
from typing import List, Dict, Any, Optional
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)


@dataclass
class VulnerableSink:
    """Represents a discovered vulnerability target."""
    address: int
    sink_type: str  # e.g., "memcpy", "RtlCopyMemory"
    arg_index: int  # Which argument is tainted
    taint_result: Dict[str, Any]
    description: str = ""


@dataclass
class ExploitCandidate:
    """A fully analyzed exploit candidate with PoC data."""
    sink: VulnerableSink
    path_found: bool
    poc_bytes: Optional[bytes] = None
    ioctl_code: Optional[int] = None
    constraints: List[str] = field(default_factory=list)
    error: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "sink_address": hex(self.sink.address),
            "sink_type": self.sink.sink_type,
            "path_found": self.path_found,
            "poc_hex": self.poc_bytes.hex() if self.poc_bytes else None,
            "ioctl_code": hex(self.ioctl_code) if self.ioctl_code else None,
            "constraints": self.constraints,
            "error": self.error
        }


class PwnOrchestrator:
    """
    Orchestrates the full vulnerability discovery → PoC generation pipeline.
    
    Usage:
        orchestrator = PwnOrchestrator(binary_path, graph, project, cfg)
        results = orchestrator.run_full_pipeline()
    """
    
    # Known dangerous sinks (function name patterns)
    DANGEROUS_SINKS = [
        ("memcpy", 2),      # 3rd arg = size
        ("memmove", 2),
        ("RtlCopyMemory", 2),
        ("RtlMoveMemory", 2),
        ("strcpy", 1),      # 2nd arg = src (can overflow dest)
        ("strncpy", 2),
        ("ExAllocatePool", 1),  # Size arg
        ("ExAllocatePoolWithTag", 1),
        ("ZwWriteFile", 7),    # Buffer ptr
        ("MmMapLockedPages", 0),
    ]
    
    def __init__(self, binary_path: str, graph, project=None, cfg=None):
        """
        Initialize orchestrator.
        
        Args:
            binary_path: Path to driver binary
            graph: LogicGraph from analysis
            project: Optional angr.Project (reused if available)
            cfg: Optional angr CFG (reused if available)
        """
        self.binary_path = binary_path
        self.graph = graph
        self.project = project
        self.cfg = cfg
        
        self._taint_engine = None
        self._sym_manager = None
    
    def _get_taint_engine(self):
        """Lazy-load TaintEngine."""
        if self._taint_engine is None:
            from ..pwn.taint_engine import TaintEngine
            self._taint_engine = TaintEngine(self.project, self.cfg)
        return self._taint_engine
    
    def _get_sym_manager(self):
        """Lazy-load SymbolicExecutionManager."""
        if self._sym_manager is None:
            from ..core.symbolic_execution import SymbolicExecutionManager
            self._sym_manager = SymbolicExecutionManager(self.binary_path)
            self._sym_manager.load()
        return self._sym_manager
    
    def find_dangerous_sinks(self) -> List[VulnerableSink]:
        """
        Scan graph for calls to dangerous functions.
        
        Returns:
            List of VulnerableSink objects with taint analysis results.
        """
        sinks = []
        taint_engine = self._get_taint_engine()
        
        for ea, node in self.graph.nodes.items():
            # Check if node name matches any dangerous sink
            for sink_name, arg_idx in self.DANGEROUS_SINKS:
                if sink_name.lower() in node.name.lower():
                    logger.info(f"Found dangerous sink: {node.name} @ {hex(ea)}")
                    
                    # Run taint analysis on this call site
                    taint_result = taint_engine.check_taint_path(ea, arg_idx)
                    
                    if taint_result.get("status") == "VULNERABLE":
                        sinks.append(VulnerableSink(
                            address=ea,
                            sink_type=sink_name,
                            arg_index=arg_idx,
                            taint_result=taint_result,
                            description=taint_result.get("description", "")
                        ))
        
        logger.info(f"Found {len(sinks)} vulnerable sinks via taint analysis")
        return sinks
    
    def generate_poc_for_sink(self, sink: VulnerableSink, max_time: int = 120) -> ExploitCandidate:
        """
        Run symbolic execution to find path to a vulnerable sink.
        
        Args:
            sink: VulnerableSink to target
            max_time: Max seconds for symbolic exploration
            
        Returns:
            ExploitCandidate with PoC data if path found
        """
        try:
            from ..core.symbolic_execution import generate_poc_for_target, is_available
            
            if not is_available():
                return ExploitCandidate(
                    sink=sink,
                    path_found=False,
                    error="angr not installed"
                )
            
            logger.info(f"Running symbolic execution for {sink.sink_type} @ {hex(sink.address)}")
            
            result = generate_poc_for_target(
                self.binary_path,
                self.graph,
                sink.address,
                max_time
            )
            
            return ExploitCandidate(
                sink=sink,
                path_found=result.target_reached,
                poc_bytes=result.input_bytes,
                ioctl_code=result.ioctl_code,
                constraints=result.constraints,
                error=result.error
            )
            
        except Exception as e:
            logger.error(f"PoC generation failed for {hex(sink.address)}: {e}")
            return ExploitCandidate(
                sink=sink,
                path_found=False,
                error=str(e)
            )
    
    def run_full_pipeline(self, max_sinks: int = 5, max_time_per_sink: int = 120) -> List[ExploitCandidate]:
        """
        Run the complete vulnerability discovery + PoC generation pipeline.
        
        Args:
            max_sinks: Maximum number of sinks to analyze (ranked by priority)
            max_time_per_sink: Max seconds to spend on each sink
            
        Returns:
            List of ExploitCandidates (some may have failed)
        """
        candidates = []
        
        # Step 1: Find all vulnerable sinks via taint analysis
        sinks = self.find_dangerous_sinks()
        
        if not sinks:
            logger.warning("No vulnerable sinks found via taint analysis")
            return candidates
        
        # Step 2: Rank sinks by exploitability (simple heuristic: prefer smaller arg index)
        sinks.sort(key=lambda s: s.arg_index)
        
        # Step 3: Generate PoC for top sinks
        for sink in sinks[:max_sinks]:
            candidate = self.generate_poc_for_sink(sink, max_time_per_sink)
            candidates.append(candidate)
            
            if candidate.path_found and candidate.poc_bytes:
                logger.info(f"✅ PoC FOUND for {sink.sink_type} @ {hex(sink.address)}")
            else:
                logger.warning(f"❌ No PoC for {sink.sink_type} @ {hex(sink.address)}: {candidate.error}")
        
        return candidates
    
    def save_results(self, candidates: List[ExploitCandidate], output_dir: str):
        """
        Save all PoC results to output directory.
        
        Args:
            candidates: List of ExploitCandidates
            output_dir: Directory to save PoC files
        """
        import os
        import json
        
        os.makedirs(output_dir, exist_ok=True)
        
        # Save summary JSON
        summary = {
            "total_sinks": len(candidates),
            "successful_pocs": sum(1 for c in candidates if c.path_found and c.poc_bytes),
            "candidates": [c.to_dict() for c in candidates]
        }
        
        with open(os.path.join(output_dir, "poc_summary.json"), "w") as f:
            json.dump(summary, f, indent=2)
        
        # Save individual PoC binary files
        for i, candidate in enumerate(candidates):
            if candidate.poc_bytes:
                poc_path = os.path.join(output_dir, f"poc_{i}_{candidate.sink.sink_type}.bin")
                with open(poc_path, "wb") as f:
                    f.write(candidate.poc_bytes)
                logger.info(f"Saved PoC to {poc_path}")


# Convenience function for CLI/GUI usage
def run_automated_pwn(binary_path: str, graph, output_dir: str = None) -> Dict[str, Any]:
    """
    One-liner function to run the full Pwn pipeline.
    
    Args:
        binary_path: Path to driver binary
        graph: LogicGraph from analysis
        output_dir: Optional output directory for PoC files
        
    Returns:
        Dict with summary and candidates
    """
    orchestrator = PwnOrchestrator(binary_path, graph)
    candidates = orchestrator.run_full_pipeline()
    
    if output_dir:
        orchestrator.save_results(candidates, output_dir)
    
    return {
        "total_sinks": len(candidates),
        "successful": sum(1 for c in candidates if c.path_found and c.poc_bytes),
        "candidates": [c.to_dict() for c in candidates]
    }
