"""
Driver-Aware Analysis Module: IOCTL Scanner.
Part of "Next-Gen" Driver Analysis.

Goal: Automatically identify DriverEntry, Dispatch Routines, and IOCTL Codes using Symbolic Execution.
"""

import logging
from typing import Dict, Any, List, Optional

logger = logging.getLogger(__name__)

class IOCTLScanner:
    """
    Scans a Windows Driver to map its Attack Surface (IOCTLs).
    """

    def __init__(self, lifter=None):
        self.lifter = lifter # AngrLifter instance

    def find_dispatch_routine(self) -> Optional[int]:
        """
        Symbolically execute DriverEntry to find the assignment:
        DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] (Offset 0xE0 on x64) = DispatchRoutine
        """
        if not self.lifter or not self.lifter.project:
            logger.warning("No angr project loaded. Cannot find dispatch routine.")
            return None

        found_dispatch = None

        def _mem_write_hook(state):
            nonlocal found_dispatch
            # Check if writing to DriverObject + 0xE0
            # DriverObject is usually 1st arg (rcx/rdx depending on calling conv, Windows x64: rcx)
            # But here we might just track the offset if we know the DriverObject base.
            # Simpler: We check if address ends in 0xE0 and base is the DriverObject param.
            
            try:
                addr = state.inspect.mem_write_address
                val = state.inspect.mem_write_expr
                
                # Heuristic: If we are writing to (DriverObject_Addr + 0xE0)
                # We need to know what DriverObject_Addr is.
                # In entry_state, we can constrain Arg0 to a specific fixed address, e.g., 0xAB000000
                driver_obj_base = 0xAB000000 
                
                target_addr = state.solver.eval(addr)
                if target_addr == (driver_obj_base + 0xE0):
                     # Found it!
                     dispatch_addr = state.solver.eval(val)
                     found_dispatch = dispatch_addr
                     logger.info(f"Hit! Dispatch Routine registered at {hex(dispatch_addr)}")
                     state.inspect.stop = True # Stop simulation
            except:
                pass

        try:
            # Setup State
            driver_obj_base = 0xAB000000
            ENTRY = self.lifter.project.entry
            state = self.lifter.project.factory.entry_state(addr=ENTRY)
            
            # Constrain Arg0 (DriverObject) to fixed base
            # Windows x64 Kernel: RCX = DriverObject
            state.registers.store('rcx', driver_obj_base)
            
            # Hook Memory Writes
            state.inspect.b('mem_write', action=_mem_write_hook)
            
            # Simulate
            simgr = self.lifter.project.factory.simgr(state)
            simgr.run(until=lambda s: found_dispatch is not None)
            
            return found_dispatch

        except Exception as e:
            logger.error(f"Error finding dispatch routine: {e}")
            return None

    def map_ioctl_handlers(self, dispatch_addr: int) -> Dict[str, Any]:
        """
        Given a Dispatch Routine, find all valid IOCTL codes.
        Strategy: Symbolic Exploration of switch tables.
        """
        results = {} # { ioctl_code_int : handler_block_addr }
        
        if not self.lifter: return results

        try:
            state = self.lifter.project.factory.blank_state(addr=dispatch_addr)
            
            # Create Symbolic Variable for IOCTL Code
            # In IRP stack (simplified), IoControlCode is at some offset.
            # For this scan, we treat it as a symbolic register or memory if we knew where it's read.
            # Heuristic: The dispatch routine usually reads [Register + Offset] -> Switch Index.
            # We can symbolize the generic registers or memory.
            
            # BETTER: We don't need to inject it perfectly. We just track constraints on *any* variable 
            # that determines branching.
            # But to map specific codes, we need to know WHICH variable is the IOCTL code.
            
            # Assuming we can identify the generic read of the stack location:
            ioctl_code = state.solver.BVS("IoControlCode", 32)
            
            # (Advanced: Identify where code reads parameters.DeviceIoControl.IoControlCode and inject symbol there)
            # For now, placeholder 'symbolic_exploration':
            
            simgr = self.lifter.project.factory.simgr(state)
            # Explore depth-first or BFS
            simgr.explore(n=50) # Limit depth
            
            for path in simgr.active + simgr.deadended:
                # Extract constraints on ioctl_code
                constraints = path.solver.constraints
                # Evaluate possible values for ioctl_code in this path
                try:
                    solutions = path.solver.eval_upto(ioctl_code, 10, cast_to=int)
                    if len(solutions) == 1:
                        # If the path constraints force IOCTL to be exactly one value, 
                        # it's likely a specific handler case (case 0x222000:)
                        code = solutions[0]
                        results[hex(code)] = hex(path.addr)
                except:
                    pass
                    
        except Exception as e:
            logger.error(f"IOCTL Mapping failed: {e}")
            
        return results
