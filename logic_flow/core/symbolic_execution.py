"""
Symbolic Execution Module for Logic Flow Analysis.

Uses angr for path exploration and constraint solving to generate
Proof-of-Concept (PoC) inputs that reach specific code paths.

IMPORTANT: angr has many dependencies. Install in isolated venv:
    pip install angr

This module provides:
- SymbolicExecutionManager: Load binary, create symbolic state
- GraphToSymbolicBridge: Extract start/target/avoid addresses from LogicGraph
- solve_constraints(): Get concrete input bytes via Z3
"""

import logging
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass, field
from pathlib import Path

logger = logging.getLogger(__name__)

# Try to import angr (optional dependency)
_ANGR_AVAILABLE = False
try:
    import angr
    import claripy
    _ANGR_AVAILABLE = True
except ImportError:
    logger.warning("angr not installed. Symbolic execution disabled. Install with: pip install angr")


def is_available() -> bool:
    """Check if angr is available."""
    return _ANGR_AVAILABLE


@dataclass
class SymbolicResult:
    """Result of symbolic execution."""
    success: bool
    target_reached: bool
    input_bytes: Optional[bytes] = None
    ioctl_code: Optional[int] = None
    constraints: List[str] = field(default_factory=list)
    path_length: int = 0
    error: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'success': self.success,
            'target_reached': self.target_reached,
            'input_bytes': self.input_bytes.hex() if self.input_bytes else None,
            'ioctl_code': hex(self.ioctl_code) if self.ioctl_code else None,
            'constraints': self.constraints,
            'path_length': self.path_length,
            'error': self.error
        }


class SymbolicExecutionManager:
    """
    Manages angr project and symbolic state for driver analysis.
    
    Usage:
        manager = SymbolicExecutionManager("/path/to/driver.sys")
        result = manager.find_path_to(target_addr, avoid_addrs)
    """
    
    # Common IOCTL buffer size
    DEFAULT_BUFFER_SIZE = 0x1000
    
    def __init__(self, binary_path: str, base_addr: int = None):
        """
        Initialize symbolic execution manager.
        
        Args:
            binary_path: Path to binary (driver .sys file)
            base_addr: Optional base address override
        """
        if not _ANGR_AVAILABLE:
            raise RuntimeError("angr is not installed. Install with: pip install angr")
        
        self.binary_path = Path(binary_path)
        if not self.binary_path.exists():
            raise FileNotFoundError(f"Binary not found: {binary_path}")
        
        self.base_addr = base_addr
        self._project = None
        self._symbolic_buffer = None
        self._symbolic_buffer_size = None
        
    def load(self) -> bool:
        """Load the binary into angr."""
        try:
            load_options = {
                'auto_load_libs': False,  # Don't load Windows DLLs
            }
            
            if self.base_addr:
                load_options['main_opts'] = {'base_addr': self.base_addr}
            
            self._project = angr.Project(
                str(self.binary_path),
                load_options=load_options
            )
            
            logger.info(f"Loaded binary: {self.binary_path.name}")
            logger.info(f"Arch: {self._project.arch.name}, Entry: 0x{self._project.entry:X}")
            
            self._hook_kernel_functions()
            return True
            
        except Exception as e:
            logger.error(f"Failed to load binary: {e}")
            return False

    def _hook_kernel_functions(self):
        """Hook common kernel functions with SimProcedures."""
        if not self._project:
            return

        # Define simple procedures that just return success or a new object
        class ReturnSuccess(angr.SimProcedure):
            def run(self):
                return 0  # STATUS_SUCCESS

        class ReturnAllocated(angr.SimProcedure):
            def run(self, pool_type, size, tag):
                return self.state.heap.malloc(size)

        class IofCompleteRequest(angr.SimProcedure):
            def run(self, irp, priority):
                return 0 

        # Map hooks
        hooks = {
            'ExAllocatePool': ReturnAllocated,
            'ExAllocatePoolWithTag': ReturnAllocated,
            'IofCompleteRequest': IofCompleteRequest,
            'KeWaitForSingleObject': ReturnSuccess,
            'ObfDereferenceObject': ReturnSuccess,
            'RtlInitUnicodeString': ReturnSuccess
        }

        for name, procedure in hooks.items():
            try:
                self._project.hook_symbol(name, procedure())
                logger.debug(f"Hooked kernel function: {name}")
            except Exception:
                pass # Symbol might not exist in this binary
    
    def create_ioctl_state(self, dispatch_addr: int, 
                           buffer_size: int = None) -> 'angr.SimState':
        """
        Create a symbolic state for IOCTL dispatch analysis.
        
        Sets up:
        - Symbolic SystemBuffer
        - Symbolic InputBufferLength
        - Symbolic IoControlCode
        
        Args:
            dispatch_addr: Address to start execution
            buffer_size: Size of symbolic input buffer
            
        Returns:
            angr SimState ready for exploration
        """
        if not self._project:
            self.load()
        
        buffer_size = buffer_size or self.DEFAULT_BUFFER_SIZE
        
        # Create symbolic buffer for SystemBuffer
        self._symbolic_buffer = claripy.BVS('input_buffer', buffer_size * 8)
        self._symbolic_buffer_size = claripy.BVS('input_length', 32)
        self._symbolic_ioctl_code = claripy.BVS('ioctl_code', 32)
        
        # Create initial state
        state = self._project.factory.blank_state(addr=dispatch_addr)
        
        # Allocate buffer in symbolic memory
        # Use a canonical kernel address range (x64) to pass MmIsAddressValid checks
        # e.g., 0xFFFF F800 0000 1000
        buffer_addr = 0xFFFFF80000001000
        state.memory.store(buffer_addr, self._symbolic_buffer)
        
        # Store buffer address in common register (rcx for x64)
        if self._project.arch.name == 'AMD64':
            state.regs.rcx = buffer_addr
            state.regs.rdx = self._symbolic_buffer_size
            state.regs.r8 = self._symbolic_ioctl_code
        else:
            # x86 calling convention
            state.stack_push(self._symbolic_ioctl_code)
            state.stack_push(self._symbolic_buffer_size)
            state.stack_push(buffer_addr)
        
        logger.debug(f"Created IOCTL state at 0x{dispatch_addr:X}")
        return state
    
    def find_path_to(self, start_addr: int, target_addr: int,
                     avoid_addrs: List[int] = None,
                     max_time: int = 60) -> SymbolicResult:
        """
        Find a path from start to target, avoiding specified addresses.
        
        Args:
            start_addr: Starting address (e.g., IOCTL dispatcher)
            target_addr: Target address to reach (e.g., vulnerability)
            avoid_addrs: Addresses to avoid (e.g., error handlers)
            max_time: Maximum execution time in seconds
            
        Returns:
            SymbolicResult with concrete input if found
        """
        if not self._project:
            self.load()
        
        avoid_addrs = avoid_addrs or []
        
        try:
            # Create initial state
            state = self.create_ioctl_state(start_addr)
            
            # Create simulation manager
            simgr = self._project.factory.simgr(state)
            
            # Explore
            logger.info(f"Exploring from 0x{start_addr:X} to 0x{target_addr:X}")
            logger.info(f"Avoiding {len(avoid_addrs)} addresses")
            
            simgr.explore(
                find=target_addr,
                avoid=avoid_addrs,
                timeout=max_time
            )
            
            # Check results
            if simgr.found:
                found_state = simgr.found[0]
                logger.info(f"Path found! Path length: {len(found_state.history.bbl_addrs)}")
                
                # Solve constraints to get concrete input
                return self._solve_state(found_state)
            else:
                return SymbolicResult(
                    success=True,
                    target_reached=False,
                    error="No path found to target"
                )
                
        except Exception as e:
            logger.error(f"Symbolic execution failed: {e}")
            return SymbolicResult(
                success=False,
                target_reached=False,
                error=str(e)
            )
    
    def _solve_state(self, state: 'angr.SimState') -> SymbolicResult:
        """
        Solve constraints to get concrete input values.
        
        Args:
            state: Found state with path to target
            
        Returns:
            SymbolicResult with concrete values
        """
        try:
            solver = state.solver
            
            # Get concrete input buffer
            concrete_buffer = None
            if self._symbolic_buffer is not None:
                concrete_buffer = solver.eval(self._symbolic_buffer, cast_to=bytes)
            
            # Get concrete IOCTL code
            concrete_ioctl = None
            if self._symbolic_ioctl_code is not None:
                concrete_ioctl = solver.eval(self._symbolic_ioctl_code)
            
            # Extract constraints as strings
            constraints = []
            for c in state.solver.constraints[:10]:  # Limit to 10
                constraints.append(str(c))
            
            return SymbolicResult(
                success=True,
                target_reached=True,
                input_bytes=concrete_buffer,
                ioctl_code=concrete_ioctl,
                constraints=constraints,
                path_length=len(list(state.history.bbl_addrs))
            )
            
        except Exception as e:
            logger.error(f"Constraint solving failed: {e}")
            return SymbolicResult(
                success=False,
                target_reached=True,
                error=f"Constraint solving failed: {e}"
            )


class GraphToSymbolicBridge:
    """
    Bridge between LogicGraph analysis and symbolic execution.
    
    Extracts start/target/avoid addresses from graph structure
    for use with symbolic execution.
    """
    
    def __init__(self, logic_graph):
        """
        Initialize bridge with a LogicGraph.
        
        Args:
            logic_graph: LogicGraph instance from analysis
        """
        self.graph = logic_graph
    
    def get_dispatch_address(self) -> Optional[int]:
        """Get the IOCTL dispatch function address (start point)."""
        from .logic_graph import FunctionRole
        
        dispatchers = self.graph.get_node_by_role(FunctionRole.IRP_DISPATCHER)
        if dispatchers:
            return dispatchers[0].ea
        
        # Fallback to anchor function
        return self.graph.anchor_function
    
    def get_error_handler_addresses(self) -> List[int]:
        """Get addresses of error handlers (avoid list)."""
        handlers = self.graph.get_error_handlers()
        return [h.ea for h in handlers]
    
    def get_failfast_addresses(self) -> List[int]:
        """Get addresses of FailFast calls (should avoid)."""
        from .logic_graph import FunctionRole
        
        failfasts = self.graph.get_node_by_role(FunctionRole.FAILFAST_GUARD)
        return [f.ea for f in failfasts]
    
    def get_vulnerability_targets(self) -> List[Tuple[int, str]]:
        """
        Get potential vulnerability targets.
        
        Returns:
            List of (address, description) tuples
        """
        targets = []
        
        for ea, node in self.graph.nodes.items():
            # Look for nodes with security-relevant metadata
            if node.metadata.get('has_unchecked_buffer'):
                targets.append((ea, 'Unchecked buffer access'))
            if node.metadata.get('has_arbitrary_write'):
                targets.append((ea, 'Arbitrary write'))
            if node.metadata.get('missing_validation'):
                targets.append((ea, 'Missing input validation'))
            
            # Check for known vulnerable API patterns
            name_lower = node.name.lower()
            if 'memcpy' in name_lower or 'memmove' in name_lower:
                targets.append((ea, 'Memory copy function'))
            if 'mmmaplockedpages' in name_lower:
                targets.append((ea, 'Memory mapping'))
        
        return targets
    
    def prepare_exploration_params(self, target_addr: int) -> Dict[str, Any]:
        """
        Prepare parameters for symbolic exploration.
        
        Args:
            target_addr: Target address to reach
            
        Returns:
            Dictionary with start, find, avoid addresses
        """
        avoid = set()
        avoid.update(self.get_error_handler_addresses())
        avoid.update(self.get_failfast_addresses())
        
        # Remove target from avoid list if present
        avoid.discard(target_addr)
        
        return {
            'start': self.get_dispatch_address(),
            'find': target_addr,
            'avoid': list(avoid)
        }


def generate_poc_for_target(binary_path: str, graph, target_addr: int,
                            max_time: int = 60) -> SymbolicResult:
    """
    High-level function to generate PoC input for a target address.
    
    Args:
        binary_path: Path to driver binary
        graph: LogicGraph from analysis
        target_addr: Target address to reach
        max_time: Maximum exploration time
        
    Returns:
        SymbolicResult with concrete input if successful
    """
    if not _ANGR_AVAILABLE:
        return SymbolicResult(
            success=False,
            target_reached=False,
            error="angr not installed. Install with: pip install angr"
        )
    
    try:
        # Create bridge
        bridge = GraphToSymbolicBridge(graph)
        params = bridge.prepare_exploration_params(target_addr)
        
        # Create manager and explore
        manager = SymbolicExecutionManager(binary_path)
        
        return manager.find_path_to(
            start_addr=params['start'],
            target_addr=params['find'],
            avoid_addrs=params['avoid'],
            max_time=max_time
        )
        
    except Exception as e:
        logger.error(f"PoC generation failed: {e}")
        return SymbolicResult(
            success=False,
            target_reached=False,
            error=str(e)
        )
