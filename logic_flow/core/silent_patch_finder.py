"""
Silent Patch Detection Module.
Part of Phase 9 / Module 5: Exploit Hunting.

Goal: Detect added constraints (sanity checks) that indicate a vulnerability fix.
"""

import logging
from typing import Dict, Any, List, Optional, Tuple

logger = logging.getLogger(__name__)

class SilentPatchFinder:
    """
    Analyzes VEX IR differences to find 'Silent Patches'.
    Focuses on added Conditional Jumps (VEX Exits) which often represent 
    new bounds checks or validation logic.
    """

    def __init__(self):
        pass

    def analyze_patch(self, func_old: Dict[str, Any], func_new: Dict[str, Any], block_matches: Dict[str, str]) -> List[Dict[str, Any]]:
        """
        Compare two functions to find added constraints.
        
        Args:
            func_old: JSON IR of reference function
            func_new: JSON IR of target function
            block_matches: Map of Old_Block_Addr -> New_Block_Addr (from Diaphora/BinDiff)
        
        Returns:
            List of detected silent patch indicators.
        """
        findings = []

        # Index blocks for easy lookup
        blocks_old = {b['addr']: b for b in func_old.get('blocks', [])}
        blocks_new = {b['addr']: b for b in func_new.get('blocks', [])}

        for old_addr, new_addr in block_matches.items():
            if old_addr not in blocks_old or new_addr not in blocks_new:
                continue

            b_old = blocks_old[old_addr]
            b_new = blocks_new[new_addr]

            # 1. Extract Guard Conditions (Exit Statements)
            guards_old = self._extract_guards(b_old)
            guards_new = self._extract_guards(b_new)

            # 2. Compare Counts
            if len(guards_new) > len(guards_old):
                # Potential Added Check
                added_guards = guards_new[len(guards_old):] # Rough diff
                findings.append({
                    "type": "ADDED_CONSTRAINT",
                    "description": f"Block {old_addr}->{new_addr} has {len(guards_new) - len(guards_old)} extra checks.",
                    "details": [g['condition'] for g in added_guards],
                    "severity": "HIGH", # Added checks are suspicious
                    "location": new_addr
                })
            
            # 3. Compare Expressions (if counts same but logic changed)
            elif len(guards_new) == len(guards_old) and len(guards_old) > 0:
                for i, (g_old, g_new) in enumerate(zip(guards_old, guards_new)):
                    # Simple string comparison of canonical IR
                    if g_old['condition'] != g_new['condition']:
                        findings.append({
                            "type": "MODIFIED_CONSTRAINT",
                            "description": f"Constraint logic changed in Block {new_addr}",
                            "details": f"Old: {g_old['condition']} -> New: {g_new['condition']}",
                            "severity": "MEDIUM",
                            "location": new_addr
                        })

        return findings

    def _extract_guards(self, block_data: Dict[str, Any]) -> List[Dict[str, str]]:
        """
        Parse block statements to find 'IF (...) GOTO ...' patterns.
        """
        guards = []
        for stmt in block_data.get('statements', []):
            if stmt.get('type') == 'Exit':
                # Our VEXLifter format: "op": "IF (cond) GOTO dest"
                op_str = stmt.get('op', '')
                if op_str.startswith("IF"):
                    # Extract content between IF ( ... )
                    try:
                        start = op_str.find('(') + 1
                        end = op_str.rfind(')')
                        cond = op_str[start:end] # Simplified
                        guards.append({"condition": cond, "raw": op_str})
                    except:
                        guards.append({"condition": op_str, "raw": op_str})
        return guards

    # --- v2.3 Symbolic Constraint Analysis ---

    def analyze_symbolic_constraints(self, state_old: Any, state_new: Any) -> List[Dict[str, Any]]:
        """
        Compare symbolic constraints between two execution states (Old vs New).
        Requires 'angr' execution of the block.
        
        Args:
            state_old: angr.SimState at the exit of the block (Reference)
            state_new: angr.SimState at the exit of the block (Target)
            
        Returns:
            List of semantic differences found via Z3 solver.
        """
        findings = []
        try:
            # This logic assumes the states were executed with identical symbolic inputs.
            # We check if (Constraints_New) > (Constraints_Old).
            
            # Simplified check: New constraints count
            # A real implementation checks logical implication: (C_new => C_old)
            
            cons_old = state_old.solver.constraints
            cons_new = state_new.solver.constraints
            
            if len(cons_new) > len(cons_old):
                # Naive count check
                findings.append({
                    "type": "SYMBOLIC_CONSTRAINT_ADDED",
                    "description": f"New version has {len(cons_new) - len(cons_old)} additional Z3 constraints.",
                    "severity": "HIGH",
                    "details": "This indicates tighter bounds checking (e.g. Size < N)."
                })
                
            # TODO: Advanced checking using solver.is_true()
            # for c in cons_new:
            #     if not state_old.solver.satisfiable(extra_constraints=[c]):
            #          findings.append("New Constraint forbids a case Old allowed!")

        except Exception as e:
            logger.error(f"Symbolic analysis failed: {e}")
            
        return findings

