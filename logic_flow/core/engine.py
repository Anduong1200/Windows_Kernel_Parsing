"""
Core Analysis Engine (Split Architecture).

The "Brain" of the tool. 
- Loads raw data (JSON protocol) extracted from IDA.
- Reconstructs LogicGraph.
- Runs heavy analysis algorithms (Rust, Angr, FuzzyHash) in this safe external process.
"""

import logging
from typing import Dict, Any, Optional
from .logic_graph import LogicGraph, FunctionNode, FunctionRole
from .diff_reflecting import compare_logic_flows, find_semantic_candidates
from .fuzzy_hash import FunctionHasher
from .taint_analysis import TaintAnalyzer
from .protocol import DriverAnalysisExport, FunctionNodeData

# Try import native core
try:
    import logic_flow_native
    _NATIVE_AVAILABLE = True
except ImportError:
    _NATIVE_AVAILABLE = False


logger = logging.getLogger(__name__)

class CoreAnalysisEngine:
    """
    Orchestrates the analysis logic on exported data.
    """
    
    def __init__(self):
        self.hasher = FunctionHasher()
        self.taint_engine = TaintAnalyzer()
        
    def process_analysis(self, raw_data: Dict[str, Any], anchor_address: Optional[int] = None) -> Dict[str, Any]:
        """
        Main pipeline: Raw JSON -> Enriched Analysis Result.
        
        Args:
            raw_data: The JSON exported by IDA extract_driver_data
            anchor_address: Override anchor if needed
            
        Returns:
            Dict compatible with old 'logic_graph' dict expected by GUI
        """
        logger.info("Starting Core Engine Analysis...")
        
        # 1. Reconstruct Logic Graph
        graph = self._reconstruct_graph(raw_data, anchor_address)
        
        # 2. Run Heuristics & Role Analysis (Refinement)
        self._refine_function_roles(graph, raw_data.get('function_instructions', {}))
        
        # 3. Compute Fuzzy Hashes
        self._compute_hashes(graph, raw_data.get('function_instructions', {}))
        
        # 4. Extract Attack Surface (New)
        from ..surface.extractor import generate_driver_model
        interface_model = generate_driver_model(graph, raw_data)
        
        # Attach to graph metadata for now, or return strictly
        graph.metadata['driver_interface'] = interface_model

        # 4. MODULE 1: Angr Lifting & VEX IR Normalization
        # Attempt to load binary for deep analysis if path is available
        metadata = raw_data.get('metadata', {})
        binary_path = metadata.get('input_file') or metadata.get('file_path')
        lifter = None
        
        if binary_path:
            try:
                from .advanced_lifter import AngrLifter
                from .ioctl_scanner import IOCTLScanner
                from ..pwn.taint_engine import TaintEngine
                from ..pwn.double_fetch import DoubleFetchDetector
                
                logger.info(f"Binary path found: {binary_path}. Initiating Deep Analysis (Lifting -> Context -> Pwn)...")
                
                import os
                if os.path.exists(binary_path):
                    # --- Module 1: Lifting ---
                    lifter = AngrLifter(binary_path, auto_load_libs=False)
                    lifter.recover_cfg(normalize=True)
                    
                    # Lift functions in graph
                    for ea, node in graph.nodes.items():
                        ir_data = lifter.lift_function(ea)
                        if ir_data:
                            node.metadata['vex_ir'] = ir_data
                    
                    logger.info("VEX Lifting complete.")

                    # --- Module 2: Driver Context (IOCTL) ---
                    logger.info("Running IOCTL Scanner...")
                    scanner = IOCTLScanner(lifter)
                    dispatch_routines = scanner.find_dispatch_routine() # Simplified: returns one or None
                    
                    ioctl_map = {}
                    if dispatch_routines:
                        logger.info(f"Found Dispatch Routine at {hex(dispatch_routines)}")
                        # Mark node role
                        if dispatch_routines in graph.nodes:
                            graph.nodes[dispatch_routines].role = FunctionRole.IRP_DISPATCHER
                            
                        ioctl_map = scanner.map_ioctl_handlers(dispatch_routines)
                        logger.info(f"Mapped {len(ioctl_map)} IOCTLs.")
                        
                        # Apply to graph
                        for code, handler_addr_hex in ioctl_map.items():
                            try:
                                handler_ea = int(handler_addr_hex, 16)
                                if handler_ea in graph.nodes:
                                    graph.nodes[handler_ea].role = FunctionRole.IOCTL_HANDLER
                                    graph.nodes[handler_ea].metadata['ioctl_code'] = code
                            except:
                                pass
                    else:
                        logger.info("No Dispatch Routine found (symbolic execution limit).")

                    # --- Module 9: Taint Analysis (Pwn) ---
                    logger.info("Running Taint Engine on Sinks...")
                    taint_engine = TaintEngine(project=lifter.project, cfg=lifter.cfg)
                    
                    # Scan all nodes for potential sinks (heuristic name match)
                    # Real implementation would look for Calls to Import 'RtlCopyMemory'
                    for ea, node in graph.nodes.items():
                         # Demo Heuristic: If it calls memcpy
                         # We rely on 'raw_data' xrefs or check instruction text?
                         # For now, simplistic check if node matches potential sink role
                         pass

                    # --- Module 8: Double Fetch ---
                    # (Instantiate only, run on specific request or high-value targets)
                    # df_detector = DoubleFetchDetector() 

                else:
                    logger.warning(f"Binary file not found locally: {binary_path}. Skipping Deep Analysis.")
                    
            except ImportError as e:
                logger.warning(f"Deep Analysis modules not fully available: {e}")
            except Exception as e:
                logger.error(f"Deep Analysis failed: {e}")

        # 5. Return in format expected by GUI/Diff
        return {
            "logic_graph": graph,
            "graph_dict": graph.to_dict(),
            "anchor_function": raw_data.get("anchor_ea"),
            "metadata": raw_data.get("metadata", {}),
        }

    def _reconstruct_graph(self, raw_data: Dict[str, Any], anchor_ea: Optional[int]) -> LogicGraph:

        """Rebuild LogicGraph object from raw export."""
        # Find anchor
        if anchor_ea is None:
            # Try to parse from raw_data (hex string like "0x140001000")
            anchor_str = raw_data.get('anchor_ea', '0x0')
            if isinstance(anchor_str, str) and anchor_str.startswith('0x'):
                anchor_ea = int(anchor_str, 16)
            elif isinstance(anchor_str, int):
                anchor_ea = anchor_str
            else:
                anchor_ea = 0
                
        graph = LogicGraph(anchor_function=anchor_ea)
        
        # Add Nodes
        functions = raw_data.get('functions', {})
        logger.info(f"Reconstructing graph with {len(functions)} functions...")
        
        # Debug: Log first 10 function addresses to verify extraction
        func_addrs = list(functions.keys())[:10]
        logger.debug(f"Sample function addresses: {func_addrs}")
        
        for ea_key, func_data in functions.items():
            # Keys can be int or str depending on serialization
            ea = int(ea_key) if isinstance(ea_key, str) else ea_key
            node = FunctionNode(
                ea=ea,
                name=func_data.get('name', f'sub_{ea:X}'),
                role=FunctionRole.UNKNOWN, # Will refine later
                is_import=func_data.get('is_import', False),
                is_export=func_data.get('is_export', False)
            )
            graph.add_node(ea, node)
            
        # Add Edges
        call_graph = raw_data.get('call_graph', [])
        for edge in call_graph:
            caller = edge.get('caller_ea')
            callee = edge.get('callee_ea')
            edge_type = edge.get('type', 'direct')
            if caller and callee:
                graph.add_edge(caller, callee, edge_type)
        
        logger.info(f"Graph reconstructed: {len(graph.nodes)} nodes, {len(graph.edges)} edges")
        return graph

    def _refine_function_roles(self, graph: LogicGraph, instructions: Dict[str, Any] = None):
        """
        Re-run semantic role classification on the reconstructed graph.
        Enhanced to use offline instruction analysis if available.
        """
        # 1. Simple name-based heuristics (ported from IDA script)
        for ea, node in graph.nodes.items():
            name_lower = node.name.lower()
            if any(x in name_lower for x in ['error', 'fail', 'abort', 'panic']):
                node.role = FunctionRole.ERROR_HANDLER
                node.is_error_handler = True
            elif any(x in name_lower for x in ['validate', 'check', 'verify']):
                node.role = FunctionRole.VALIDATION_ROUTINE
            elif any(x in name_lower for x in ['alloc', 'malloc', 'pool']):
                node.role = FunctionRole.RESOURCE_MANAGER
            elif any(x in name_lower for x in ['landing', 'dispatch', 'ioctl', 'irp']): # Added landing for older symbols
                node.role = FunctionRole.IRP_DISPATCHER
            elif any(x in name_lower for x in ['cleanup', 'free', 'release']):
                node.role = FunctionRole.CLEANUP_HANDLER

            # 2. Instruction-based Feature Extraction (Offline Semantic Analysis)
            # If we have extracted instructions with target names, we can verify roles robustly
            if instructions:
                ea_str = str(ea)
                if ea_str in instructions:
                    insns = instructions[ea_str]
                    for insn in insns:
                        # insn is a dict containing 'mnemonic', 'target_name', etc.
                        tgt = insn.get('target_name', '')
                        if not tgt: continue
                        
                        # Normalize target name
                        tgt_lower = tgt.lower()
                        
                        # FailFast Detection
                        if any(x in tgt_lower for x in ['failfast', 'bugcheck', 'raise']):
                            node.has_failfast = True
                            if node.role == FunctionRole.UNKNOWN:
                                node.role = FunctionRole.FAILFAST_GUARD
                        
                        # Completion Detection
                        if 'completerequest' in tgt_lower:
                            node.has_complete_request = True
                            
                        # Handle/Resource Detection
                        if any(x in tgt_lower for x in ['createfile', 'openfile']):
                            node.has_handle_acquire = True
                        if any(x in tgt_lower for x in ['close', 'dereference']):
                            node.has_handle_release = True
                        if any(x in tgt_lower for x in ['accesscheck', 'probe']):
                            node.has_handle_validation = True
                            node.role = FunctionRole.VALIDATION_ROUTINE
                        
                        # Dispatcher specific
                        if 'iocalldriver' in tgt_lower:
                             # Often dispatchers call other drivers
                             pass


    def _compute_hashes(self, graph: LogicGraph, instructions: Dict[str, Any]):
        """Compute fuzzy hashes using extracted instruction data."""
        from .fuzzy_hash import compute_opcode_hash
        
        # instructions key is str(ea) because JSON keys are strings
        for ea, node in graph.nodes.items():
            ea_str = str(ea)
            if ea_str in instructions:
                insns = instructions[ea_str]
                # Extract mnemonics for hashing
                mnemonics = [insn.get('mnemonic', '') for insn in insns if 'mnemonic' in insn]
                if mnemonics:
                    # Compute hash and store in metadata
                    op_hash = compute_opcode_hash(mnemonics)
                    node.metadata['opcode_hash'] = op_hash
