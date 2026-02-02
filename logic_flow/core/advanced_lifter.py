"""
Advanced Lifter Module using angr and VEX IR.
Part of Module 1: Lifting & Parsing (The Foundation).

Enhanced with:
- Full logging suppression for angr ecosystem
- Batch lifting for multiple functions
- CCall helper function handling
- Summary statistics
"""

import logging
import json
from typing import Dict, Any, List, Optional, Set, Tuple
import os

try:
    import angr
    import pyvex
    import archinfo
    _ANGR_AVAILABLE = True
except ImportError:
    _ANGR_AVAILABLE = False

logger = logging.getLogger(__name__)


def suppress_angr_logging():
    """Suppress all verbose logging from angr and its dependencies."""
    loggers_to_suppress = [
        'angr', 'cle', 'pyvex', 'claripy', 'archinfo',
        'angr.analyses', 'angr.engines', 'angr.state_plugins'
    ]
    for logger_name in loggers_to_suppress:
        logging.getLogger(logger_name).setLevel(logging.ERROR)


class AngrLifter:
    """
    Wraps angr.Project to perform CFG recovery and VEX IR lifting.
    
    Usage:
        lifter = AngrLifter("/path/to/driver.sys")
        ir = lifter.lift_function(0x140001000)
        all_ir = lifter.lift_all_functions()
    """

    def __init__(self, binary_path: str, auto_load_libs: bool = False):
        """
        Initialize angr project.
        
        Args:
            binary_path: Path to the binary file
            auto_load_libs: Whether to auto-load dependent libraries
        """
        if not _ANGR_AVAILABLE:
            raise ImportError("angr framework is not installed. Please install: pip install angr")
        
        if not os.path.exists(binary_path):
            raise FileNotFoundError(f"Binary not found: {binary_path}")

        # Suppress logging BEFORE creating project
        suppress_angr_logging()
        
        self.binary_path = binary_path
        self.project = angr.Project(binary_path, auto_load_libs=auto_load_libs)
        self.cfg = None
        self.functions = {}
        self._lifted_cache: Dict[int, Dict[str, Any]] = {}
        
        logger.info(f"Initialized angr project for: {os.path.basename(binary_path)} [{self.project.arch.name}]")

    def recover_cfg(self, normalize: bool = True, force: bool = False) -> int:
        """
        Recover Control Flow Graph using angr's CFGFast.
        
        Args:
            normalize: Normalize the CFG
            force: Force re-recovery even if already done
            
        Returns:
            Number of functions found
        """
        if self.cfg and not force:
            return len(self.functions)
        
        logger.info("Starting CFG Recovery...")
        self.cfg = self.project.analyses.CFG(normalize=normalize)
        self.functions = self.cfg.functions
        logger.info(f"CFG Recovery complete. Found {len(self.functions)} functions.")
        return len(self.functions)

    def lift_function(self, func_addr: int, use_cache: bool = True) -> Dict[str, Any]:
        """
        Lift a specific function to Canonical VEX IR.
        
        Args:
            func_addr: Address of the function to lift
            use_cache: Use cached result if available
            
        Returns:
            JSON-serializable dictionary representation of the function IR
        """
        # Check cache
        if use_cache and func_addr in self._lifted_cache:
            return self._lifted_cache[func_addr]
        
        if not self.cfg:
            self.recover_cfg()

        try:
            func = self.functions.get(func_addr)
            if not func:
                logger.warning(f"Function at {hex(func_addr)} not found in CFG.")
                return {}

            function_ir = {
                "address": hex(func_addr),
                "name": func.name,
                "size": func.size,
                "block_count": len(list(func.blocks)),
                "blocks": []
            }

            # Iterate through blocks in the function
            for block in func.blocks:
                try:
                    vex_block = block.vex
                    
                    # Canonicalize the block (normalize temp registers)
                    normalized_stmts = self._canonicalize_block(vex_block)

                    block_data = {
                        "addr": hex(block.addr),
                        "size": block.size,
                        "statements": normalized_stmts,
                        "statement_count": len(normalized_stmts),
                        "jumpkind": vex_block.jumpkind,
                        "next": hex(vex_block.next) if isinstance(vex_block.next, int) else str(vex_block.next)
                    }
                    function_ir["blocks"].append(block_data)
                except Exception as e:
                    logger.debug(f"Skipping block at {hex(block.addr)}: {e}")
                    continue

            # Cache result
            self._lifted_cache[func_addr] = function_ir
            return function_ir

        except Exception as e:
            logger.error(f"Error lifting function {hex(func_addr)}: {e}")
            return {}

    def lift_all_functions(self, max_functions: int = None) -> Dict[int, Dict[str, Any]]:
        """
        Lift all functions in the binary to VEX IR.
        
        Args:
            max_functions: Maximum number of functions to lift (for performance)
            
        Returns:
            Dictionary mapping function address -> IR data
        """
        if not self.cfg:
            self.recover_cfg()
        
        results = {}
        count = 0
        
        for func_addr in self.functions:
            if max_functions and count >= max_functions:
                break
            
            ir = self.lift_function(func_addr)
            if ir:
                results[func_addr] = ir
                count += 1
        
        logger.info(f"Lifted {len(results)} functions to VEX IR")
        return results

    def get_function_summary(self, func_addr: int) -> Dict[str, Any]:
        """
        Get a quick summary of a function without full lifting.
        
        Args:
            func_addr: Function address
            
        Returns:
            Summary dictionary
        """
        if not self.cfg:
            self.recover_cfg()
        
        func = self.functions.get(func_addr)
        if not func:
            return {}
        
        return {
            "address": hex(func_addr),
            "name": func.name,
            "size": func.size,
            "block_count": len(list(func.blocks)),
            "is_plt": func.is_plt,
            "is_simprocedure": func.is_simprocedure,
            "has_return": func.has_return,
            "returning": func.returning
        }

    def _canonicalize_block(self, vex_block) -> List[Dict[str, Any]]:
        """
        Convert VEX statements to a canonical JSON format.
        Renames temporary variables (t10, t45) to sequential (t0, t1...) 
        to ensure semantic matching between different compilations.
        """
        canonical_stmts = []
        temp_map = {}  # Map original temp ID -> Canonical ID (0, 1, 2...)
        next_temp_id = 0

        def get_canonical_temp(orig_temp):
            nonlocal next_temp_id
            if orig_temp not in temp_map:
                temp_map[orig_temp] = next_temp_id
                next_temp_id += 1
            return f"t{temp_map[orig_temp]}"

        for stmt in vex_block.statements:
            stmt_type = type(stmt).__name__
            stmt_data = {"type": stmt_type}

            try:
                # 1. WRITETMP (tX = ...)
                if stmt_type == 'WrTmp':
                    target_temp = get_canonical_temp(stmt.tmp)
                    rhs_expr = self._serialize_expression(stmt.data, get_canonical_temp)
                    
                    stmt_data["op"] = f"{target_temp} = {rhs_expr}"
                    stmt_data["canonical_lhs"] = target_temp
                    stmt_data["canonical_rhs_expr"] = rhs_expr

                # 2. PUT (Register Write)
                elif stmt_type == 'Put':
                    reg_name = self.project.arch.register_names.get(stmt.offset, f"reg_{stmt.offset}")
                    rhs_expr = self._serialize_expression(stmt.data, get_canonical_temp)
                    
                    stmt_data["op"] = f"{reg_name} = {rhs_expr}"
                    stmt_data["target_reg"] = reg_name

                # 3. STORE (Memory Write)
                elif stmt_type == 'Store':
                    addr_expr = self._serialize_expression(stmt.addr, get_canonical_temp)
                    data_expr = self._serialize_expression(stmt.data, get_canonical_temp)
                    
                    stmt_data["op"] = f"MEM[{addr_expr}] = {data_expr}"
                    stmt_data["is_store"] = True
                
                # 4. EXIT (Conditional Jump)
                elif stmt_type == 'Exit':
                    cond_expr = self._serialize_expression(stmt.guard, get_canonical_temp)
                    dst = hex(stmt.dst.value) if hasattr(stmt.dst, 'value') else str(stmt.dst)
                    stmt_data["op"] = f"IF ({cond_expr}) GOTO {dst}"

                # 5. IMark (Instruction Marker) - useful for debugging
                elif stmt_type == 'IMark':
                    stmt_data["op"] = f"IMark({hex(stmt.addr)}, {stmt.len})"
                    stmt_data["insn_addr"] = hex(stmt.addr)
                    stmt_data["insn_len"] = stmt.len

                else:
                    # Other statements (AbiHint, etc.)
                    stmt_data["raw"] = str(stmt)

            except Exception as e:
                stmt_data["error"] = str(e)
                stmt_data["raw"] = str(stmt)

            canonical_stmts.append(stmt_data)

        return canonical_stmts

    def _serialize_expression(self, expr, temp_mapper) -> str:
        """Helper to serialize VEX expressions to string."""
        expr_type = type(expr).__name__
        
        try:
            if expr_type == 'RdTmp':
                return temp_mapper(expr.tmp)
            elif expr_type == 'Const':
                return str(expr.con)
            elif expr_type == 'Get':
                reg_name = self.project.arch.register_names.get(expr.offset, f"reg_{expr.offset}")
                return reg_name
            elif expr_type == 'Binop':
                arg1 = self._serialize_expression(expr.args[0], temp_mapper)
                arg2 = self._serialize_expression(expr.args[1], temp_mapper)
                return f"({arg1} {expr.op} {arg2})"
            elif expr_type == 'Unop':
                arg = self._serialize_expression(expr.args[0], temp_mapper)
                return f"{expr.op}({arg})"
            elif expr_type == 'Load':
                addr = self._serialize_expression(expr.addr, temp_mapper)
                return f"MEM[{addr}]"
            elif expr_type == 'CCall':
                # Helper function call - serialize arguments
                args = [self._serialize_expression(a, temp_mapper) for a in expr.args]
                return f"CALL({expr.cee.name}, {', '.join(args)})"
            elif expr_type == 'ITE':
                # If-Then-Else expression
                cond = self._serialize_expression(expr.cond, temp_mapper)
                true_val = self._serialize_expression(expr.iftrue, temp_mapper)
                false_val = self._serialize_expression(expr.iffalse, temp_mapper)
                return f"ITE({cond}, {true_val}, {false_val})"
        except Exception:
            pass
        
        return str(expr)

    def clear_cache(self):
        """Clear the lifted function cache."""
        self._lifted_cache.clear()


def is_available() -> bool:
    """Check if angr is available."""
    return _ANGR_AVAILABLE

