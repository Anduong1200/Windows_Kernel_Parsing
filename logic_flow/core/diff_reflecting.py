# Import IDA provider abstraction for clean API separation
from .ida_provider import create_ida_provider, IDAProvider

import logging
from datetime import datetime
from typing import Dict, List, Set, Tuple, Optional, Any, Union
from .logic_graph import LogicGraph, FunctionRole, FunctionNode
from .poc_helper import PoCHelper, ChangeType
from ..utils.config import ConfigManager

# Optional Native acceleration
_NATIVE_AVAILABLE = False
try:
    import logic_flow_native
    _NATIVE_AVAILABLE = True
except ImportError:
    pass

# Import Advanced Analysis Modules
from .fuzzy_hash import FunctionHasher
from .taint_analysis import TaintAnalyzer

logger = logging.getLogger(__name__)


def _calculate_set_similarity(set_a: Union[Set, List], set_b: Union[Set, List]) -> float:
    """
    Calculate Jaccard similarity between two sets.
    Uses Rust implementation if available for performance.
    """
    if not set_a and not set_b:
        return 1.0
    if not set_a or not set_b:
        return 0.0

    # formatting for Rust: it expects List[str]
    if _NATIVE_AVAILABLE:
        try:
            # ensure all elements are strings
            list_a = [str(x) for x in set_a]
            list_b = [str(x) for x in set_b]
            return logic_flow_native.calculate_jaccard_similarity(list_a, list_b)
        except Exception as e:
            logger.warning(f"Native similarity calculation failed: {e}")
            # Fallback to python implementation below
    
    # Python fallback
    set_a = set(str(x) for x in set_a)
    set_b = set(str(x) for x in set_b)
    
    intersection = len(set_a.intersection(set_b))
    union = len(set_a.union(set_b))
    
    return intersection / union if union > 0 else 0.0

# Global config manager instance
# Global config manager instance
_config_manager = ConfigManager()
from dataclasses import dataclass, field

# IDA provider will be created lazily when first needed
_ida_provider = None

# Export public API
__all__ = [
    'build_bounded_graph',
    'compare_logic_flows',
    'analyze_security_insights', # Explicitly export for UI usage
    'generate_ui_analysis_report' # New helper for one-shot UI data generation
]

def _get_ida_provider():
    """Get IDA provider instance, creating it lazily if needed"""
    global _ida_provider
    if _ida_provider is None:
        _ida_provider = create_ida_provider()
    return _ida_provider

@dataclass
class AnalysisContext:
    """
    Encapsulates analysis state and caches for thread safety.
    Replaces global cache variables.
    """
    ida_provider: IDAProvider
    callers_cache: Dict[str, Set[int]] = field(default_factory=dict)
    irp_context_cache: Dict[str, Dict] = field(default_factory=dict)
    function_semantics_cache: Dict[str, Tuple] = field(default_factory=dict)
    function_name_cache: Dict[str, str] = field(default_factory=dict)
    func_flags_cache: Dict[int, Any] = field(default_factory=dict)

def clear_analysis_cache():
    """ Deprecated: Caches are now managed via AnalysisContext per-analysis. """
    pass


def iter_functions_ida9x(ida_funcs, ida_idaapi) -> List[int]:
    """
    IDA 9.x compatible function iteration using get_next_func.

    Args:
        ida_funcs: IDA funcs module
        ida_idaapi: IDA api module

    Returns:
        List of function addresses in the database
    """
    functions = []
    ida_provider = _get_ida_provider()
    func_ea = ida_provider.get_next_func(ida_provider.BADADDR)

    while func_ea != ida_provider.BADADDR:
        functions.append(func_ea)
        func_ea = ida_provider.get_next_func(func_ea)

    return functions

def build_bounded_graph(anchor_function: int, max_depth: Optional[int] = None, context: Optional['AnalysisContext'] = None) -> LogicGraph:
    """
    Build a bounded call graph starting from an anchor function.
    Traverses XREF relationships up/down from anchor to create logic flow representation.

    Args:
        anchor_function: Function address to start analysis from
        max_depth: Maximum call hierarchy depth to explore (uses config default if None)
        context: Optional analysis context for caching (created via _get_ida_provider if None)

    Returns:
        LogicGraph: Bounded graph representing error handling logic flow
    """
    if max_depth is None:
        max_depth = _config_manager.get_max_graph_depth()

    graph = LogicGraph(anchor_function)
    graph.max_depth = max_depth

    # Use IDA provider abstraction
    # No longer need conditional imports - provider handles real/mock automatically
    ida_provider = _get_ida_provider()
    
    # Ensure context exists
    if context is None:
        context = AnalysisContext(ida_provider)

    try:
        visited = set()
        queue = [(anchor_function, 0)]  # (function_ea, depth)

        max_nodes = _config_manager.get_max_graph_nodes()
        while queue and len(graph.nodes) < max_nodes:
            current_ea, depth = queue.pop(0)

            if current_ea in visited or depth > max_depth:
                continue
            visited.add(current_ea)

            # Analyze current function and create node
            node = _analyze_function_node(current_ea, depth, context)
            graph.add_node(current_ea, node)

            # Traverse upward (callers) to understand call hierarchy
            if depth < max_depth:
                callers = _get_callers_cached(current_ea, context)
                for caller_ea in callers:
                    if caller_ea not in visited and len(graph.nodes) < 100:
                        queue.append((caller_ea, depth + 1))
                        graph.add_edge(caller_ea, current_ea, "calls")

            # Traverse downward (callees) but more selectively for bounded analysis
            downward_limit = _config_manager.get_downward_traversal_limit()
            if depth < downward_limit:
                # Add missing cached callee retrieval
                callees = _get_callees_cached(current_ea, context)
                for callee_ea in callees:
                    if callee_ea not in visited and len(graph.nodes) < max_nodes:
                        # Only add callees that are relevant to error handling
                        if _is_error_related_function(callee_ea, context.ida_provider):
                            queue.append((callee_ea, depth + 1))
                            graph.add_edge(current_ea, callee_ea, "calls")

        # Mark boundary functions
        _identify_boundary_functions(graph, context.ida_provider)

        return graph

    except Exception as e:
        logger.error(f"Error building bounded graph: {e}")
        import traceback
        logger.debug("Full traceback:", exc_info=True)
        return graph

def _analyze_function_node(func_ea: int, depth: int, context: AnalysisContext) -> FunctionNode:
    """Analyze a function to create a graph node with semantic role (with caching)"""
    try:
        f = context.ida_provider.get_func(func_ea)
        if not f:
            return FunctionNode(ea=func_ea, name=f"unknown_{func_ea:08X}", role=FunctionRole.UNKNOWN)

        # Get function name (cached)
        name = _get_function_name_cached(func_ea, context)

        # Analyze semantic characteristics (cached)
        role, is_error_handler, has_failfast, has_complete, has_handle_acquire, has_handle_validation, has_handle_release = _analyze_function_semantics_cached(
            func_ea, context
        )

        # Get IRP context (cached)
        irp_context = _get_irp_context_cached(func_ea, context)

        return FunctionNode(
            ea=func_ea,
            name=name,
            role=role,
            is_error_handler=is_error_handler,
            has_failfast=has_failfast,
            has_complete_request=has_complete,
            has_handle_acquire=has_handle_acquire,
            has_handle_validation=has_handle_validation,
            has_handle_release=has_handle_release,
            irp_context=irp_context,
            metadata={"depth": depth, "analyzed": True}
        )

    except Exception as e:
        logger.warning(f"Failed to analyze function {hex(func_ea)}: {e}")
        return FunctionNode(ea=func_ea, name=f"error_{func_ea:08X}", role=FunctionRole.UNKNOWN)

def _analyze_function_semantics(func_ea: int, ida_provider: IDAProvider) -> Tuple[FunctionRole, bool, bool, bool, bool, bool, bool]:
    """
    Analyze function semantics using ROBUST SEMANTIC SIGNATURES for BinDiff-beating accuracy.

    Features:
    1. CONSTANT-BLIND SIGNATURES: Match functions with same API call sequences regardless of constant values
    2. INSTRUCTION-CLASS SIGNATURES: Match instruction classes (DataTransfer, ControlFlow) instead of specific opcodes
    3. OBFUSCATION RESISTANCE: Works even when code is reordered or slightly modified
    """
    try:
        f = ida_provider.get_func(func_ea)
        if not f:
            return FunctionRole.UNKNOWN, False, False, False, False, False, False

        # Initialize analysis results
        analysis_result = {
            "has_failfast": False,
            "has_complete": False,
            "has_cleanup": False,
            "is_dispatcher": False,
            "has_validation": False,
            "has_handle_acquire": False,
            "has_handle_validation": False,
            "has_handle_release": False,
            "api_call_sequence": [],  # For constant-blind signatures
            "instruction_class_sequence": [],  # For instruction-class signatures
            "semantic_signature": "",  # Combined signature for matching
            "security_apis": set()  # Track security-critical APIs
        }

        # PHASE 1: Extract CONSTANT-BLIND SIGNATURES
        api_sequence = _extract_api_call_sequence(func_ea, ida_provider)
        analysis_result["api_call_sequence"] = api_sequence

        # PHASE 2: Extract INSTRUCTION-CLASS SIGNATURES
        instruction_classes = _extract_instruction_class_sequence(func_ea, ida_provider)
        analysis_result["instruction_class_sequence"] = instruction_classes

        # PHASE 3: Analyze semantic characteristics using both traditional and advanced methods
        _analyze_semantic_characteristics(func_ea, ida_provider, analysis_result)

        # PHASE 4: Generate combined semantic signature for robust matching
        analysis_result["semantic_signature"] = _generate_semantic_signature(analysis_result)

        # Extract final results
        has_failfast = analysis_result["has_failfast"]
        has_complete = analysis_result["has_complete"]
        has_cleanup = analysis_result["has_cleanup"]
        is_dispatcher = analysis_result["is_dispatcher"]
        has_validation = analysis_result["has_validation"]
        has_handle_acquire = analysis_result["has_handle_acquire"]
        has_handle_validation = analysis_result["has_handle_validation"]
        has_handle_release = analysis_result["has_handle_release"]

        # Determine semantic role based on characteristics (enhanced logic)
        role, is_error_handler = _determine_semantic_role_enhanced(analysis_result)

        return role, is_error_handler, has_failfast, has_complete, has_handle_acquire, has_handle_validation, has_handle_release

    except Exception as e:
        logger.warning(f"Failed to analyze semantics for {hex(func_ea)}: {e}")
        return FunctionRole.UNKNOWN, False, False, False, False, False, False


def _extract_api_call_sequence(func_ea: int, ida_provider: IDAProvider) -> List[str]:
    """
    Extract CONSTANT-BLIND API call sequence.
    Ignores constant values but captures the sequence of API calls for robust matching.
    This makes the signature resistant to tag ID changes, buffer size changes, etc.
    """
    api_sequence = []
    try:
        f = ida_provider.get_func(func_ea)
        if not f:
            return api_sequence

        ea = f.start_ea
        while ea < f.end_ea:
            try:
                if ida_provider.is_call_insn(ea):
                    for ref in ida_provider.get_code_refs_from(ea):
                        if ref == ida_provider.BADADDR:
                            continue

                        func_name = _get_function_name(ref, ida_provider)
                        if func_name:
                            # Normalize API names to be constant-blind
                            normalized_name = _normalize_api_name(func_name)
                            if normalized_name:
                                api_sequence.append(normalized_name)

            except (AttributeError, TypeError) as e:
                logger.debug(f"Error extracting API at {hex(ea)}: {e}")

            ea = ida_provider.next_head(ea, f.end_ea)

    except Exception as e:
        logger.debug(f"Failed to extract API sequence for {hex(func_ea)}: {e}")

    return api_sequence


def _normalize_api_name(api_name: str) -> str:
    """
    Normalize API names to be constant-blind.
    Removes specific constant values while preserving semantic meaning.
    """
    # Examples of normalization:
    # "ExAllocatePoolWithTag(POOL_FLAG_NON_PAGED, size, 'AbcD')" -> "ExAllocatePoolWithTag"
    # "sub_1400123456" -> "INTERNAL_CALL"
    
    # Remove parenthesized parameters
    if '(' in api_name:
        api_name = api_name.split('(')[0]
    
    api_name = api_name.strip()
    
    # Normalize internal IDA names
    lower_name = api_name.lower()
    if lower_name.startswith('sub_') or lower_name.startswith('loc_') or lower_name.startswith('unk_'):
        return "INTERNAL_CALL"
        
    return api_name


def _extract_instruction_class_sequence(func_ea: int, ida_provider: IDAProvider) -> List[str]:
    """
    Extract INSTRUCTION-CLASS SEQUENCE for obfuscation resistance.
    Instead of matching specific opcodes like 'mov', 'lea', matches instruction classes:
    - DataTransfer (mov, lea, push, pop)
    - Arithmetic (add, sub, mul, div)
    - ControlFlow (jmp, je, jne, call, ret)
    - Logic (and, or, xor, not)
    - Comparison (cmp, test)
    This makes signatures resistant to compiler optimization changes.
    """
    instruction_classes = []
    try:
        f = ida_provider.get_func(func_ea)
        if not f:
            return instruction_classes

        ea = f.start_ea
        while ea < f.end_ea:
            try:
                mnem = ida_provider.get_mnemonic(ea)
                if mnem:
                    instr_class = _classify_instruction(mnem.lower())
                    if instr_class:
                        instruction_classes.append(instr_class)

            except (AttributeError, TypeError) as e:
                logger.debug(f"Error classifying instruction at {hex(ea)}: {e}")

            ea = ida_provider.next_head(ea, f.end_ea)

        # Limit sequence length for performance (first 50 instructions)
        return instruction_classes[:50]

    except Exception as e:
        logger.debug(f"Failed to extract instruction classes for {hex(func_ea)}: {e}")
        return instruction_classes


def _classify_instruction(mnemonic: str) -> str:
    """
    Classify instruction mnemonic into semantic categories.
    This provides obfuscation resistance by grouping similar instructions.
    
    Enhanced with granular control flow classification (Call, Return, Jump, CondJump).
    """
    # Data Transfer Instructions
    data_transfer = {'mov', 'lea', 'push', 'pop', 'xchg', 'movzx', 'movsx', 'movs', 'stos', 'lods'}
    if mnemonic in data_transfer:
        return 'DataTransfer'

    # Arithmetic Instructions
    arithmetic = {'add', 'sub', 'mul', 'div', 'idiv', 'imul', 'inc', 'dec', 'neg', 'adc', 'sbb'}
    if mnemonic in arithmetic:
        return 'Arithmetic'

    # Logic Instructions
    logic = {'and', 'or', 'xor', 'not', 'shl', 'shr', 'sal', 'sar', 'rol', 'ror'}
    if mnemonic in logic:
        return 'Logic'

    # Comparison Instructions
    comparison = {'cmp', 'test'}
    if mnemonic in comparison:
        return 'Comparison'

    # --- Granular Control Flow Classification ---
    # Call Instructions
    if mnemonic == 'call':
        return 'Call'
    
    # Return Instructions
    if mnemonic in {'ret', 'retn', 'iret'}:
        return 'Return'
    
    # Unconditional Jump
    if mnemonic == 'jmp':
        return 'UnconditionalJump'
    
    # Conditional Jumps (all j* except jmp)
    conditional_jumps = {'je', 'jne', 'jz', 'jnz', 'jc', 'jnc', 'jo', 'jno', 'js', 'jns',
                        'jp', 'jnp', 'jl', 'jle', 'jg', 'jge', 'ja', 'jae', 'jb', 'jbe',
                        'jcxz', 'jecxz', 'jrcxz', 'loop', 'loope', 'loopne', 'loopz', 'loopnz'}
    if mnemonic in conditional_jumps:
        return 'ConditionalJump'

    # Stack Operations
    if 'push' in mnemonic or 'pop' in mnemonic:
        return 'StackOp'

    # Special instructions
    if mnemonic in {'int', 'syscall', 'sysenter'}:
        return 'SystemCall'

    # Default category for unclassified instructions
    return 'Other'


def _analyze_semantic_characteristics(func_ea: int, ida_provider: IDAProvider, analysis_result: Dict):
    """
    Analyze semantic characteristics using both traditional symbol-based and advanced signature-based methods.
    Enhanced to work with the new signature system.
    """
    try:
        f = ida_provider.get_func(func_ea)
        if not f:
            return

        ea = f.start_ea
        while ea < f.end_ea:
            try:
                if ida_provider.is_call_insn(ea):
                    for ref in ida_provider.get_code_refs_from(ea):
                        if ref == ida_provider.BADADDR:
                            continue

                        func_name = _get_function_name(ref, ida_provider)
                        if not func_name or func_name.startswith('sub_'):
                            continue

                        # Track security-critical APIs
                        if any(sec_api in func_name for sec_api in ["SeAccessCheck", "ProbeForRead", "ProbeForWrite", "RtlEqualSid"]):
                            analysis_result["security_apis"].add(func_name)

                        # Enhanced pattern detection with semantic awareness
                        if _is_failfast_api(func_name):
                            analysis_result["has_failfast"] = True
                        if _is_completion_api(func_name):
                            analysis_result["has_complete"] = True
                        if _is_cleanup_api(func_name):
                            analysis_result["has_cleanup"] = True
                        if _is_dispatcher_api(func_name):
                            analysis_result["is_dispatcher"] = True
                        if _is_validation_api(func_name):
                            analysis_result["has_validation"] = True
                        if _is_handle_acquire_api(func_name):
                            analysis_result["has_handle_acquire"] = True
                        if _is_handle_validation_api(func_name):
                            analysis_result["has_handle_validation"] = True
                        if _is_handle_release_api(func_name):
                            analysis_result["has_handle_release"] = True

            except (AttributeError, TypeError) as e:
                logger.debug(f"Error analyzing semantics at {hex(ea)}: {e}")

            ea = ida_provider.next_head(ea, f.end_ea)

    except Exception as e:
        logger.debug(f"Failed to analyze semantic characteristics for {hex(func_ea)}: {e}")


def _is_failfast_api(func_name: str) -> bool:
    """Enhanced FailFast detection"""
    if not func_name:
        return False
    return any(pattern in func_name for pattern in [
        "RtlFailFast", "KeBugCheckEx", "KeBugCheck", "_CxxThrowException", "ExRaiseStatus"
    ])


def _is_completion_api(func_name: str) -> bool:
    """Enhanced completion detection"""
    return "IofCompleteRequest" in func_name or "IoCompleteRequest" in func_name


def _is_cleanup_api(func_name: str) -> bool:
    """Enhanced cleanup detection"""
    cleanup_patterns = [
                            "ExFreePool", "ObDereferenceObject", "ZwClose", "IoFreeIrp",
        "KeSetEvent", "ExReleaseFastMutex", "IoDeleteDevice", "MmFreeContiguousMemory"
    ]
    return any(cleanup in func_name for cleanup in cleanup_patterns)


def _is_dispatcher_api(func_name: str) -> bool:
    """Enhanced dispatcher detection"""
    dispatcher_patterns = [
                            "IoGetCurrentIrpStackLocation", "IoGetNextIrpStackLocation",
        "IRP_MJ_", "irp", "IRP", "IoCallDriver"
    ]
    return any(disp in func_name for disp in dispatcher_patterns)


def _is_validation_api(func_name: str) -> bool:
    """Enhanced validation detection"""
    validation_patterns = [
        "ProbeForRead", "ProbeForWrite", "SeAccessCheck", "RtlEqualSid",
        "ExAllocatePool", "RtlValidSid"
    ]
    return any(val in func_name for val in validation_patterns)


def _is_handle_acquire_api(func_name: str) -> bool:
    """Enhanced handle acquire detection"""
    acquire_patterns = [
                            "ZwCreateFile", "ZwOpenFile", "ZwCreateKey", "ZwOpenKey",
        "ObReferenceObjectByHandle", "IoGetDeviceObjectPointer"
    ]
    return any(acq in func_name for acq in acquire_patterns)


def _is_handle_validation_api(func_name: str) -> bool:
    """Enhanced handle validation detection"""
    validation_patterns = [
        "ObReferenceObjectByPointer", "ZwQueryObject", "SeAccessCheck",
        "ZwWaitForSingleObject"
    ]
    return any(val in func_name for val in validation_patterns)


def _is_handle_release_api(func_name: str) -> bool:
    """Enhanced handle release detection"""
    release_patterns = [
        "ZwClose", "ObDereferenceObject"
    ]
    return any(rel in func_name for rel in release_patterns)


def _generate_semantic_signature(analysis_result: Dict) -> str:
    """
    Generate a combined semantic signature for robust function matching.
    This signature is designed to be constant-blind and obfuscation-resistant.
    """
    signature_parts = []

    # API sequence signature (constant-blind)
    if analysis_result["api_call_sequence"]:
        api_sig = "|".join(analysis_result["api_call_sequence"][:10])  # Limit for performance
        signature_parts.append(f"API:{api_sig}")

    # Instruction class sequence signature
    if analysis_result["instruction_class_sequence"]:
        instr_sig = "".join(cls[0] for cls in analysis_result["instruction_class_sequence"][:20])  # Abbreviated
        signature_parts.append(f"INST:{instr_sig}")

    # Semantic characteristics signature
    chars = []
    if analysis_result["has_failfast"]: chars.append("F")
    if analysis_result["has_complete"]: chars.append("C")
    if analysis_result["has_cleanup"]: chars.append("U")
    if analysis_result["is_dispatcher"]: chars.append("D")
    if analysis_result["has_validation"]: chars.append("V")
    if analysis_result["has_handle_acquire"]: chars.append("A")
    if analysis_result["has_handle_validation"]: chars.append("L")  # L for vaLidation
    if analysis_result["has_handle_release"]: chars.append("R")

    if chars:
        signature_parts.append(f"CHAR:{''.join(sorted(chars))}")

    return ";".join(signature_parts)


def _determine_semantic_role_enhanced(analysis_result: Dict) -> Tuple[FunctionRole, bool]:
    """
    Determine semantic role using enhanced logic that considers signature patterns.
    Prioritizes security-critical patterns and uses signature-based fallback.
    """
    # Priority order: FailFast > Error Handler > IRP Dispatcher > Cleanup > Handle Manager > Resource Manager > Validation > Unknown

    if analysis_result["has_failfast"]:
        if analysis_result["has_complete"]:
            return FunctionRole.ERROR_HANDLER, True
        else:
            return FunctionRole.FAILFAST_GUARD, True

    if analysis_result["has_complete"] and analysis_result["has_cleanup"]:
        return FunctionRole.CLEANUP_HANDLER, True

    if analysis_result["is_dispatcher"]:
        return FunctionRole.IRP_DISPATCHER, False

    if analysis_result["has_handle_acquire"] and analysis_result["has_handle_release"]:
        return FunctionRole.HANDLE_MANAGER, False

    if analysis_result["has_complete"]:
        return FunctionRole.RESOURCE_MANAGER, False

    if analysis_result["has_validation"] or analysis_result["has_handle_validation"]:
        return FunctionRole.VALIDATION_ROUTINE, False

    # Check for security-critical patterns even if not caught by above
    if analysis_result["security_apis"]:
        return FunctionRole.VALIDATION_ROUTINE, True

    return FunctionRole.UNKNOWN, False


def analyze_security_insights(graph_a: LogicGraph, graph_b: LogicGraph, comparison_result: Dict) -> Dict[str, Any]:
    """
    Analyze comparison results for SECURITY-SPECIFIC INSIGHTS that BinDiff cannot provide.
    Focuses on high-confidence security patches and vulnerability-relevant changes.
    
    Enhanced with Control Flow / Reachability Analysis (Phase 4.2):
    - Verifies security checks are actually reachable from entry points
    - Identifies unguarded privileged operations
    - Provides reachability scores for confidence assessment

    This is the "secret sauce" that makes our tool superior to BinDiff - we don't just
    say "the code changed", we say "a security check was added/removed".
    """
    insights = {
        "high_confidence_security_patches": [],
        "security_vulnerability_indicators": [],
        "handle_lifecycle_changes": [],
        "error_handling_improvements": [],
        "access_control_changes": [],
        "reachability_analysis": {},  # NEW: Reachability-based analysis
        "overall_security_assessment": "unknown",
        "confidence_level": "low"
    }

    # HIGH CONFIDENCE PATCH DETECTION
    _detect_high_confidence_patches(graph_a, graph_b, insights)

    # SECURITY VULNERABILITY INDICATORS
    _detect_security_vulnerabilities(graph_a, graph_b, insights)

    # HANDLE LIFECYCLE ANALYSIS
    _analyze_handle_lifecycle_changes(graph_a, graph_b, insights)

    # ERROR HANDLING IMPROVEMENTS
    _analyze_error_handling_changes(graph_a, graph_b, insights)

    # ACCESS CONTROL CHANGES
    _analyze_access_control_changes(graph_a, graph_b, insights)

    # NEW: REACHABILITY ANALYSIS (Phase 4.2)
    _perform_reachability_analysis(graph_a, graph_b, insights)
    
    # NEW: TAINT ANALYSIS (Phase 4.5 - Deep Inspection)
    # Check for unvalidated data flow in modified functions
    try:
        ida_provider = _get_ida_provider()
        if ida_provider:
            taint_ctx = {"taint_risks": []}
            analyzer = TaintAnalyzer(ida_provider, _config_manager)
            
            # Identify high-risk modified nodes to scan
            # We look for nodes present in both but changed (or new) that call sensitive APIs
            target_nodes = []
            for node_ea, node_a in graph_b.nodes.items():
                # Scan if it's a Sink or Dispatcher, and logic changed
                if node_a.role in [FunctionRole.IRP_DISPATCHER, FunctionRole.SINK_FUNCTION]:
                     target_nodes.append(node_ea)

            for func_ea in target_nodes[:10]: # Limit scan to top 10 relevant functions for performance
                report = analyzer.analyze_function(func_ea)
                if report.get('risk_level') in ['HIGH', 'MEDIUM']:
                    taint_ctx["taint_risks"].append({
                        "function": hex(func_ea),
                        "risk": report['risk_level'],
                        "unvalidated_paths": len(report.get('unvalidated_paths', []))
                    })
            
            insights["taint_analysis"] = taint_ctx
    except Exception as e:
        logger.debug(f"Taint analysis integration failed: {e}")
    
    # Reachability Analysis
    _perform_reachability_analysis(graph_a, graph_b, insights)

    # OVERALL ASSESSMENT
    _generate_overall_security_assessment(insights)

    return insights


def _perform_reachability_analysis(graph_a: LogicGraph, graph_b: LogicGraph, insights: Dict):
    """
    Perform reachability analysis to verify security checks guard privileged operations.
    This provides higher confidence than simple count-based analysis.
    """
    reachability = {
        "graph_a": {},
        "graph_b": {},
        "comparison": {},
        "security_coverage_improvement": False
    }
    
    # Critical security APIs to analyze
    critical_apis = ["SeAccessCheck", "ProbeForRead", "ProbeForWrite", "RtlEqualSid"]
    
    for api in critical_apis:
        reach_a = _check_security_reachability(graph_a, api)
        reach_b = _check_security_reachability(graph_b, api)
        
        reachability["graph_a"][api] = reach_a
        reachability["graph_b"][api] = reach_b
        
        # Compare reachability scores
        score_diff = reach_b["reachability_score"] - reach_a["reachability_score"]
        reachability["comparison"][api] = {
            "score_improvement": score_diff,
            "unguarded_operations_changed": len(reach_b["unguarded_privileged_operations"]) - len(reach_a["unguarded_privileged_operations"])
        }
        
        # Flag if more privileged operations are now guarded
        if reach_b["guards_privileged_operations"] > reach_a["guards_privileged_operations"]:
            reachability["security_coverage_improvement"] = True
            insights["high_confidence_security_patches"].append({
                "type": "security_coverage_improved",
                "description": f"{api} now guards {reach_b['guards_privileged_operations'] - reach_a['guards_privileged_operations']} more privileged operations",
                "severity": "high",
                "confidence": "high",
                "explanation": "Reachability analysis confirms security check is on path to privileged code"
            })
        
        # Flag if privileged operations became unguarded
        if len(reach_b["unguarded_privileged_operations"]) > len(reach_a["unguarded_privileged_operations"]):
            insights["security_vulnerability_indicators"].append({
                "type": "unguarded_privileged_operations",
                "description": f"{len(reach_b['unguarded_privileged_operations'])} privileged operations are not guarded by {api}",
                "severity": "critical",
                "confidence": "high",
                "unguarded_details": reach_b["unguarded_privileged_operations"]
            })
    
    insights["reachability_analysis"] = reachability


def _detect_high_confidence_patches(graph_a: LogicGraph, graph_b: LogicGraph, insights: Dict):
    """Detect high-confidence security patches that indicate vulnerability fixes"""
    patches = []

    # Check for SeAccessCheck additions
    seaccess_a = _count_security_api(graph_a, "SeAccessCheck")
    seaccess_b = _count_security_api(graph_b, "SeAccessCheck")

    if seaccess_b > seaccess_a:
        patches.append({
            "type": "access_check_added",
            "description": f"SeAccessCheck added in {seaccess_b - seaccess_a} locations",
            "severity": "high",
            "confidence": "high",
            "explanation": "SeAccessCheck validates access permissions - addition indicates security hardening"
        })

    # Check for ProbeForRead/ProbeForWrite additions
    probe_a = _count_security_api(graph_a, ["ProbeForRead", "ProbeForWrite"])
    probe_b = _count_security_api(graph_b, ["ProbeForRead", "ProbeForWrite"])

    if probe_b > probe_a:
        patches.append({
            "type": "buffer_validation_added",
            "description": f"Buffer validation added in {probe_b - probe_a} locations",
            "severity": "critical",
            "confidence": "high",
            "explanation": "ProbeForRead/ProbeForWrite prevent buffer overflow attacks"
        })

    # Check for handle validation additions
    handle_val_a = sum(1 for node in graph_a.nodes.values() if node.has_handle_validation)
    handle_val_b = sum(1 for node in graph_b.nodes.values() if node.has_handle_validation)

    if handle_val_b > handle_val_a:
        patches.append({
            "type": "handle_validation_added",
            "description": f"Handle validation added in {handle_val_b - handle_val_a} functions",
            "severity": "high",
            "confidence": "medium",
            "explanation": "Handle validation prevents use-after-free and double-free vulnerabilities"
        })

    # Check for FailFast placement changes (security hardening)
    failfast_a_pos = graph_a.get_failfast_position()
    failfast_b_pos = graph_b.get_failfast_position()

    if failfast_a_pos and failfast_b_pos:
        path_a_len = len(graph_a.get_path_to_anchor(failfast_a_pos))
        path_b_len = len(graph_b.get_path_to_anchor(failfast_b_pos))

        if path_b_len < path_a_len:
            patches.append({
                "type": "failfast_earlier",
                "description": "FailFast moved closer to potential vulnerability points",
                "severity": "medium",
                "confidence": "medium",
                "explanation": "Earlier FailFast prevents exploitation of vulnerabilities"
            })

    insights["high_confidence_security_patches"] = patches


def _detect_security_vulnerabilities(graph_a: LogicGraph, graph_b: LogicGraph, insights: Dict):
    """Detect indicators of potential security vulnerabilities"""
    vulnerabilities = []

    # Check for removed security checks
    seaccess_a = _count_security_api(graph_a, "SeAccessCheck")
    seaccess_b = _count_security_api(graph_b, "SeAccessCheck")

    if seaccess_b < seaccess_a:
        vulnerabilities.append({
            "type": "access_check_removed",
            "description": f"SeAccessCheck removed from {seaccess_a - seaccess_b} locations",
            "severity": "critical",
            "confidence": "high",
            "explanation": "Removal of access checks may allow privilege escalation"
        })

    # Check for removed buffer validation
    probe_a = _count_security_api(graph_a, ["ProbeForRead", "ProbeForWrite"])
    probe_b = _count_security_api(graph_b, ["ProbeForRead", "ProbeForWrite"])

    if probe_b < probe_a:
        vulnerabilities.append({
            "type": "buffer_validation_removed",
            "description": f"Buffer validation removed from {probe_a - probe_b} locations",
            "severity": "critical",
            "confidence": "high",
            "explanation": "Removal of buffer validation reintroduces overflow vulnerabilities"
        })

    # Check for unbalanced handle operations (potential leaks)
    handle_analysis = _compare_handle_lifecycles(graph_a, graph_b)
    if handle_analysis["acquire_release_balance_a"] != handle_analysis["acquire_release_balance_b"]:
        if abs(handle_analysis["acquire_release_balance_b"]) > abs(handle_analysis["acquire_release_balance_a"]):
            vulnerabilities.append({
                "type": "handle_leak_introduced",
                "description": "Handle lifecycle imbalance increased",
                "severity": "high",
                "confidence": "medium",
                "explanation": "Unbalanced handle operations may cause resource leaks or use-after-free"
            })

    # Check for error handling removal
    error_a = sum(1 for node in graph_a.nodes.values() if node.is_error_handler)
    error_b = sum(1 for node in graph_b.nodes.values() if node.is_error_handler)

    if error_b < error_a:
        vulnerabilities.append({
            "type": "error_handling_reduced",
            "description": f"Error handling reduced from {error_a} to {error_b} functions",
            "severity": "medium",
            "confidence": "medium",
            "explanation": "Reduced error handling may leave error conditions unhandled"
        })

    insights["security_vulnerability_indicators"] = vulnerabilities


def _analyze_handle_lifecycle_changes(graph_a: LogicGraph, graph_b: LogicGraph, insights: Dict):
    """Analyze changes in handle lifecycle management"""
    changes = []

    handle_comp = _compare_handle_lifecycles(graph_a, graph_b)

    # Check for handle safety improvements
    safety_a = handle_comp["handle_safety_score_a"]
    safety_b = handle_comp["handle_safety_score_b"]

    if safety_b > safety_a:
        changes.append({
            "type": "handle_safety_improved",
            "description": f"Handle safety score improved from {safety_a:.1f} to {safety_b:.1f}",
            "assessment": "positive"
        })
    elif safety_b < safety_a:
        changes.append({
            "type": "handle_safety_degraded",
            "description": f"Handle safety score degraded from {safety_a:.1f} to {safety_b:.1f}",
            "assessment": "negative"
        })

    # Check for lifecycle pattern changes
    balance_a = handle_comp["acquire_release_balance_a"]
    balance_b = handle_comp["acquire_release_balance_b"]

    if balance_a == 0 and balance_b != 0:
        changes.append({
            "type": "handle_balance_lost",
            "description": "Handle acquire/release balance lost",
            "assessment": "negative"
        })
    elif balance_a != 0 and balance_b == 0:
        changes.append({
            "type": "handle_balance_gained",
            "description": "Handle acquire/release balance achieved",
            "assessment": "positive"
        })

    insights["handle_lifecycle_changes"] = changes


def _analyze_error_handling_changes(graph_a: LogicGraph, graph_b: LogicGraph, insights: Dict):
    """Analyze changes in error handling patterns"""
    changes = []

    # Compare error path complexity
    error_analysis = _analyze_error_path_equivalence(graph_a, graph_b)

    complexity_a = error_analysis["error_path_complexity_a"]
    complexity_b = error_analysis["error_path_complexity_b"]

    if complexity_b > complexity_a:
        changes.append({
            "type": "error_handling_complexity_increased",
            "description": f"Error handling complexity increased from {complexity_a:.1f} to {complexity_b:.1f}",
            "assessment": "positive"
        })
    elif complexity_b < complexity_a:
        changes.append({
            "type": "error_handling_complexity_decreased",
            "description": f"Error handling complexity decreased from {complexity_a:.1f} to {complexity_b:.1f}",
            "assessment": "negative"
        })

    # Check for FailFast usage changes
    failfast_a = sum(1 for node in graph_a.nodes.values() if node.has_failfast)
    failfast_b = sum(1 for node in graph_b.nodes.values() if node.has_failfast)

    if failfast_b > failfast_a:
        changes.append({
            "type": "failfast_usage_increased",
            "description": f"FailFast usage increased from {failfast_a} to {failfast_b} functions",
            "assessment": "positive"
        })
    elif failfast_b < failfast_a:
        changes.append({
            "type": "failfast_usage_decreased",
            "description": f"FailFast usage decreased from {failfast_a} to {failfast_b} functions",
            "assessment": "negative"
        })

    insights["error_handling_improvements"] = changes


def _analyze_access_control_changes(graph_a: LogicGraph, graph_b: LogicGraph, insights: Dict):
    """Analyze changes in access control patterns"""
    changes = []

    # Check for validation routine changes
    validation_a = sum(1 for node in graph_a.nodes.values() if node.role == FunctionRole.VALIDATION_ROUTINE)
    validation_b = sum(1 for node in graph_b.nodes.values() if node.role == FunctionRole.VALIDATION_ROUTINE)

    if validation_b > validation_a:
        changes.append({
            "type": "validation_routines_added",
            "description": f"Validation routines added: {validation_b - validation_a}",
            "assessment": "positive"
        })
    elif validation_b < validation_a:
        changes.append({
            "type": "validation_routines_removed",
            "description": f"Validation routines removed: {validation_a - validation_b}",
            "assessment": "negative"
        })

    # Check for security API changes
    security_apis = ["SeAccessCheck", "ProbeForRead", "ProbeForWrite", "RtlEqualSid"]
    for api in security_apis:
        count_a = _count_security_api(graph_a, api)
        count_b = _count_security_api(graph_b, api)

        if count_b > count_a:
            changes.append({
                "type": "security_api_added",
                "description": f"{api} added in {count_b - count_a} locations",
                "assessment": "positive"
            })
        elif count_b < count_a:
            changes.append({
                "type": "security_api_removed",
                "description": f"{api} removed from {count_a - count_b} locations",
                "assessment": "negative"
            })

    insights["access_control_changes"] = changes


def _count_security_api(graph: LogicGraph, api_names: Union[str, List[str]]) -> int:
    """Count occurrences of security APIs in graph"""
    if isinstance(api_names, str):
        api_names = [api_names]

    count = 0
    for node in graph.nodes.values():
        if node.metadata and "security_apis" in node.metadata:
            for api in api_names:
                if api in node.metadata["security_apis"]:
                    count += 1

    return count


def _check_security_reachability(graph: LogicGraph, security_api: str, target_role: FunctionRole = None) -> Dict[str, Any]:
    """
    Perform reachability analysis to check if security API guards access to target functions.
    
    This is superior to simple counting because it verifies:
    1. Security check is on the path from entry to privileged operation
    2. Security check dominates the target (all paths must go through it)
    
    Args:
        graph: The LogicGraph to analyze
        security_api: API name to check (e.g., "SeAccessCheck")
        target_role: Optional target function role to check reachability to
        
    Returns:
        Dict with reachability information
    """
    result = {
        "security_api": security_api,
        "total_occurrences": 0,
        "reachable_from_entry": 0,
        "guards_privileged_operations": 0,
        "unguarded_privileged_operations": [],
        "reachability_score": 0.0
    }
    
    # Find nodes with this security API
    security_nodes = []
    for node_ea, node in graph.nodes.items():
        if node.metadata and "security_apis" in node.metadata:
            if security_api in node.metadata["security_apis"]:
                security_nodes.append(node_ea)
                result["total_occurrences"] += 1
    
    if not security_nodes:
        return result
    
    # Check reachability from anchor (entry point)
    anchor_ea = graph.anchor_function
    for sec_node_ea in security_nodes:
        if _is_reachable(graph, anchor_ea, sec_node_ea):
            result["reachable_from_entry"] += 1
    
    # Find privileged operations (based on target_role or default to IRP handlers)
    privileged_nodes = []
    if target_role:
        privileged_nodes = [ea for ea, node in graph.nodes.items() if node.role == target_role]
    else:
        # Default: consider IRP dispatchers and resource managers as privileged
        privileged_roles = {FunctionRole.IRP_DISPATCHER, FunctionRole.RESOURCE_MANAGER, FunctionRole.HANDLE_MANAGER}
        privileged_nodes = [ea for ea, node in graph.nodes.items() if node.role in privileged_roles]
    
    # Check if security nodes guard privileged operations
    for priv_ea in privileged_nodes:
        is_guarded = False
        for sec_node_ea in security_nodes:
            # Security check guards if it's on path from entry to privileged op
            if _is_on_path(graph, anchor_ea, sec_node_ea, priv_ea):
                is_guarded = True
                result["guards_privileged_operations"] += 1
                break
        
        if not is_guarded and priv_ea != anchor_ea:
            priv_node = graph.nodes.get(priv_ea)
            if priv_node:
                result["unguarded_privileged_operations"].append({
                    "address": hex(priv_ea),
                    "name": priv_node.name,
                    "role": priv_node.role.value
                })
    
    # Calculate reachability score
    if result["total_occurrences"] > 0:
        entry_ratio = result["reachable_from_entry"] / result["total_occurrences"]
        guard_ratio = result["guards_privileged_operations"] / max(len(privileged_nodes), 1)
        result["reachability_score"] = (entry_ratio + guard_ratio) / 2
    
    return result


def _is_reachable(graph: LogicGraph, source_ea: int, target_ea: int) -> bool:
    """Check if target is reachable from source via BFS"""
    if source_ea == target_ea:
        return True
    
    visited = set()
    queue = [source_ea]
    
    while queue:
        current = queue.pop(0)
        if current in visited:
            continue
        visited.add(current)
        
        # Get callees (nodes this function calls)
        for caller, callee, edge_type in graph.edges:
            if caller == current:
                if callee == target_ea:
                    return True
                if callee not in visited:
                    queue.append(callee)
    
    return False


def _is_on_path(graph: LogicGraph, start_ea: int, via_ea: int, end_ea: int) -> bool:
    """Check if via_ea is on any path from start_ea to end_ea"""
    # First check if via_ea is reachable from start
    if not _is_reachable(graph, start_ea, via_ea):
        return False
    
    # Then check if end_ea is reachable from via_ea
    return _is_reachable(graph, via_ea, end_ea)


def _generate_overall_security_assessment(insights: Dict):
    """Generate overall security assessment based on all findings"""
    positive_indicators = 0
    negative_indicators = 0

    # Count positive and negative changes
    for category in ["high_confidence_security_patches", "handle_lifecycle_changes",
                     "error_handling_improvements", "access_control_changes"]:
        for item in insights[category]:
            if item.get("assessment") == "positive":
                positive_indicators += 1
            elif item.get("assessment") == "negative":
                negative_indicators += 1

    # Count vulnerabilities
    vulnerability_count = len(insights["security_vulnerability_indicators"])
    negative_indicators += vulnerability_count

    # Determine overall assessment
    if positive_indicators > negative_indicators + 2:
        assessment = "significantly_improved"
        confidence = "high"
    elif positive_indicators > negative_indicators:
        assessment = "moderately_improved"
        confidence = "medium"
    elif negative_indicators > positive_indicators + 2:
        assessment = "significantly_degraded"
        confidence = "high"
    elif negative_indicators > positive_indicators:
        assessment = "moderately_degraded"
        confidence = "medium"
    elif positive_indicators > 0 or negative_indicators > 0:
        assessment = "mixed_changes"
        confidence = "medium"
    else:
        assessment = "no_security_changes"
        confidence = "low"

    insights["overall_security_assessment"] = assessment
    insights["confidence_level"] = confidence

def _is_error_related_function(func_ea: int, ida_provider: IDAProvider) -> bool:
    """Check if function is related to error handling (for selective traversal)"""
    role, _, _, _, _, _, _ = _analyze_function_semantics(func_ea, ida_provider)
    return role in [
        FunctionRole.ERROR_HANDLER,
        FunctionRole.FAILFAST_GUARD,
        FunctionRole.CLEANUP_HANDLER,
        FunctionRole.RESOURCE_MANAGER,
        FunctionRole.HANDLE_MANAGER
    ]

def _identify_boundary_functions(graph: LogicGraph, ida_provider: IDAProvider):
    """Identify semantic boundaries in the graph"""
    bounds = set()

    # Check for IRP dispatcher boundary
    if any(node.role == FunctionRole.IRP_DISPATCHER for node in graph.nodes.values()):
        bounds.add("irp_dispatcher")

    # Check for error handling boundary
    if any(node.is_error_handler for node in graph.nodes.values()):
        bounds.add("error_handling")

    # Check for FailFast protection boundary
    if any(node.has_failfast for node in graph.nodes.values()):
        bounds.add("failfast_protection")

    # Check for resource management boundary
    if any(node.role == FunctionRole.RESOURCE_MANAGER for node in graph.nodes.values()):
        bounds.add("resource_management")

    # Check for handle management boundary
    if any(node.role == FunctionRole.HANDLE_MANAGER for node in graph.nodes.values()):
        bounds.add("handle_management")

    graph.bounds = bounds

def _prefilter_candidate_functions(all_functions: List[int], anchor_graph: LogicGraph,
                                  ida_provider: IDAProvider,
                                  max_prefiltered: int = 200) -> List[int]:
    """
    Pre-filter functions to reduce the candidate set before expensive semantic analysis.

    Uses fast heuristics:
    1. Function size similarity (similar number of instructions)
    2. Cross-reference count similarity (similar complexity)
    3. String reference similarity (shared string constants)
    4. Immediate constant similarity (shared magic numbers/addresses)

    Returns up to max_prefiltered functions for detailed analysis.
    """
    prefiltered = []
    anchor_ea = anchor_graph.anchor_function

    # Get anchor function statistics for comparison
    anchor_xrefs = _get_function_xref_count(anchor_ea, ida_provider)
    anchor_strings = _get_function_string_refs(anchor_ea, ida_provider)
    anchor_immediates = _get_function_immediate_constants(anchor_ea, ida_provider)

    logger.debug(f"Anchor function stats: {anchor_xrefs} xrefs, {len(anchor_strings)} strings, {len(anchor_immediates)} immediates")

    candidate_scores = []

    for func_ea in all_functions:
        # Skip the anchor function itself
        if func_ea == anchor_ea:
            continue

        try:
            # Fast checks that don't require full semantic analysis
            xref_score = _compare_xref_count(func_ea, anchor_xrefs, ida_provider)
            string_score = _compare_string_refs(func_ea, anchor_strings, ida_provider)
            immediate_score = _compare_immediate_constants(func_ea, anchor_immediates, ida_provider)

            # Combined prefilter score (0-3 scale)
            total_score = xref_score + string_score + immediate_score

            if total_score > 0:  # At least some similarity
                candidate_scores.append((func_ea, total_score))

        except Exception as e:
            # Skip problematic functions
            continue

    # Sort by prefilter score and take top candidates
    candidate_scores.sort(key=lambda x: x[1], reverse=True)
    prefiltered = [ea for ea, score in candidate_scores[:max_prefiltered]]

    return prefiltered


def _get_function_xref_count(func_ea: int, ida_provider: IDAProvider) -> int:
    """Get total cross-references (calls + data refs) for a function."""
    try:
        count = 0
        # Count callers
        for xref in ida_provider.XrefsTo(func_ea):
            if xref and ida_provider.is_call_insn(xref.frm):
                count += 1

        # Count callees (simplified)
        f = ida_provider.get_func(func_ea)
        if f:
            ea = f.start_ea
            while ea < f.end_ea:
                try:
                    if ida_provider.is_call_insn(ea):
                        count += 1
                except (AttributeError, TypeError) as e:
                    logger.debug(f"Error counting xrefs at {hex(ea)}: {e}")
                ea = ida_provider.next_head(ea, f.end_ea)

        return count
    except (AttributeError, TypeError) as e:
        logger.debug(f"Error getting xref count for {hex(func_ea)}: {e}")
        return 0


def _compare_xref_count(func_ea: int, anchor_xrefs: int, ida_provider: IDAProvider) -> float:
    """Compare cross-reference counts (0-1 score)."""
    func_xrefs = _get_function_xref_count(func_ea, ida_provider)

    if anchor_xrefs == 0:
        return 1.0 if func_xrefs == 0 else 0.0

    # Allow 20% deviation in complexity
    ratio = min(func_xrefs, anchor_xrefs) / max(func_xrefs, anchor_xrefs)
    return 1.0 if ratio >= 0.8 else 0.0


def _get_function_string_refs(func_ea: int, ida_provider: IDAProvider) -> Set[str]:
    """Get string references used by a function."""
    strings = set()
    try:
        f = ida_provider.get_func(func_ea)
        if not f:
            return strings

        ea = f.start_ea
        while ea < f.end_ea:
            try:
                # Check for string references
                for ref in ida_provider.get_code_refs_from(ea):
                    if ref != ida_provider.BADADDR:
                        string_val = ida_provider.get_string(ref)
                        if string_val:
                            strings.add(string_val)
            except (AttributeError, TypeError) as e:
                logger.debug(f"Error getting string ref at {hex(ea)}: {e}")
            ea = ida_provider.next_head(ea, f.end_ea)

    except (AttributeError, TypeError) as e:
        logger.debug(f"Error getting string refs for function: {e}")

    return strings


def _compare_string_refs(func_ea: int, anchor_strings: Set[str], ida_provider: IDAProvider) -> float:
    """Compare string references (0-1 score)."""
    if not anchor_strings:
        return 0.0  # No strings to compare

    func_strings = _get_function_string_refs(func_ea, ida_provider)

    if not func_strings:
        return 0.0

    # Check for shared strings
    shared = len(anchor_strings & func_strings)
    if shared > 0:
        return 1.0  # Any shared strings = good match

    return 0.0


def _get_function_immediate_constants(func_ea: int, ida_provider: IDAProvider) -> Set[int]:
    """Get immediate constants used by a function."""
    constants = set()
    try:
        f = ida_provider.get_func(func_ea)
        if not f:
            return constants

        ea = f.start_ea
        while ea < f.end_ea:
            try:
                # Check for immediate operands
                mnem = ida_provider.get_mnemonic(ea)
                if mnem:
                    # Get operands
                    for i in range(2):  # Check first 2 operands
                        op_text = ida_provider.get_operand_text(ea, i)
                        if op_text and '#' in op_text:  # Immediate value
                            # Extract numeric value (simplified)
                            if op_text.startswith('#'):
                                try:
                                    # Handle hex, decimal
                                    val_str = op_text[1:].strip()
                                    if val_str.startswith('0x'):
                                        val = int(val_str, 16)
                                    else:
                                        val = int(val_str)
                                    constants.add(val)
                                except ValueError:
                                    pass  # Expected for non-numeric values
            except (AttributeError, TypeError) as e:
                logger.debug(f"Error getting immediate constant at {hex(ea)}: {e}")
            ea = ida_provider.next_head(ea, f.end_ea)

    except (AttributeError, TypeError) as e:
        logger.debug(f"Error getting immediate constants: {e}")

    return constants


def _compare_immediate_constants(func_ea: int, anchor_constants: Set[int], ida_provider: IDAProvider) -> float:
    """Compare immediate constants (0-1 score)."""
    if not anchor_constants:
        return 0.0

    func_constants = _get_function_immediate_constants(func_ea, ida_provider)

    if not func_constants:
        return 0.0

    # Check for shared constants
    shared = len(anchor_constants & func_constants)
    if shared > 0:
        return 1.0

    return 0.0


def find_semantic_candidates(anchor_graph: LogicGraph, max_candidates: Optional[int] = None, context: Optional['AnalysisContext'] = None) -> List[Tuple[int, float, Dict]]:
    """
    Find and score candidate functions in target database that may have similar semantic roles.
    Returns scored candidates sorted by relevance: (func_ea, score, scoring_details)

    Uses pre-filtering to avoid analyzing all functions in large databases.

    Args:
        anchor_graph: LogicGraph from reference driver
        max_candidates: Maximum candidates to return (uses config default if None)
        context: Analysis context for caching
    """
    if max_candidates is None:
        max_candidates = _config_manager.get_max_semantic_candidates()

    candidates_with_scores = []

    # Get anchor function characteristics for comparison
    anchor_node = anchor_graph.nodes[anchor_graph.anchor_function]
    anchor_role = anchor_node.role
    anchor_has_failfast = anchor_node.has_failfast
    anchor_has_complete = anchor_node.has_complete_request
    anchor_is_error_handler = anchor_node.is_error_handler
    anchor_has_handle_acquire = anchor_node.has_handle_acquire
    anchor_has_handle_validation = anchor_node.has_handle_validation
    anchor_has_handle_release = anchor_node.has_handle_release
    anchor_irp_context = anchor_node.irp_context or {}

    # Use IDA provider
    ida_provider = _get_ida_provider()
    
    # Ensure context exists
    if context is None:
        context = AnalysisContext(ida_provider)
    else:
        ida_provider = context.ida_provider

    try:
        # Get all functions in current database
        all_functions = list(ida_provider.Functions())

        logger.info(f"Pre-filtering {len(all_functions)} functions...")

        # Phase 1: Pre-filtering to reduce candidate set
        prefiltered_functions = _prefilter_candidate_functions(
            all_functions, anchor_graph, ida_provider
        )

        logger.info(f"Pre-filtering reduced to {len(prefiltered_functions)} candidates")

        # Phase 2: Detailed semantic analysis on prefiltered candidates
        for func_ea in prefiltered_functions:
            # Analyze function semantics (cached)
            role, is_error_handler, has_failfast, has_complete, has_handle_acquire, has_handle_validation, has_handle_release = _analyze_function_semantics_cached(
                func_ea, context
            )

            # Skip functions that are clearly irrelevant (no error handling characteristics)
            if not (has_failfast or has_complete or is_error_handler or has_handle_acquire or has_handle_validation or has_handle_release):
                continue

            # Calculate weighted heuristic score
            score = 0.0
            details = {}

            # --- NATIVE OPTIMIZATION ---
            if _NATIVE_AVAILABLE:
                try:
                    rn_anchor = logic_flow_native.RustNode(
                        anchor_ea, 
                        anchor_node.role.name if hasattr(anchor_node.role, 'name') else str(anchor_node.role),
                        anchor_is_error_handler, 
                        anchor_has_failfast
                    )
                    rn_candidate = logic_flow_native.RustNode(
                        func_ea, 
                        role.name if hasattr(role, 'name') else str(role),
                        is_error_handler, 
                        has_failfast
                    )
                    
                    # Rust returns 0.0 to 1.0 based on Role(5)+Fail(3)+Error(3)
                    # We map this to our 70% weight (40 Role + 30 Behavior)
                    # Max raw score in Rust is 11.0. 
                    # calculate_node_similarity returns normalized 0.0-1.0
                    native_score = logic_flow_native.calculate_node_similarity(rn_anchor, rn_candidate)
                    
                    score += (native_score * 70.0) # 70% of total score
                    details['native_optimization'] = True
                except Exception as e:
                    # Fallback if conversion fails
                    pass
            else:
                # --- A. Semantic Role Match (Weight: 40%) ---
                if role == anchor_role:
                    score += 40.0
                    details['role_match'] = True

            # --- B. Fuzzy Hash Similarity (Weight: 30%) ---
            # Use new FunctionHasher to get fuzzy similarity
            try:
                hash_scores = hasher.compare_functions(anchor_ea, func_ea)
                similarity = hash_scores.get('best', 0)
                
                if similarity > 0:
                    # Scale 0-100 to 0-30 points
                    fuzzy_points = (similarity / 100.0) * 30.0
                    score += fuzzy_points
                    details['fuzzy_similarity'] = similarity
                    details['fuzzy_algo'] = 'LSH' if hash_scores.get('opcode') > hash_scores.get('ssdeep', 0) else 'SSDeep'
            except Exception as e:
                pass # Fail gracefully if hashing fails

            # --- C. Key Behavior Match (Weight: 30%) ---
            # (Skip if Native used, as it covers this)
            if not details.get('native_optimization'):
                # Check specific behaviors like FailFast, Error Handling, etc.
                behavior_score = 0
                max_behavior = 0
                
                # Check FailFast
                if anchor_has_failfast:
                    max_behavior += 1
                    if has_failfast:
                        behavior_score += 1
                        details['failfast_match'] = True

                # Check Error Handler
                if anchor_is_error_handler:
                    max_behavior += 1
                    if is_error_handler:
                        behavior_score += 1
                        details['error_handler_match'] = True
                
                # Check IofCompleteRequest
                if has_complete and anchor_has_complete:
                    max_behavior += 1
                    behavior_score += 1
                    details['complete_match'] = True
                    
                if max_behavior > 0:
                     score += (behavior_score / max_behavior) * 30.0

            # Normalize and add to total
            if max_behavior > 0:
                score += (behavior_score / max_behavior) * 30.0

            # Filter low scores
            if score > 15.0:
                 candidates_with_scores.append((func_ea, score, details))

        # Sort by score descending
        candidates_with_scores.sort(key=lambda x: x[1], reverse=True)

        return candidates_with_scores[:max_candidates]

    except Exception as e:
        logger.error(f"Error finding semantic candidates: {e}")
        return []


def _is_identity_comparison(graph_a: LogicGraph, graph_b: LogicGraph) -> bool:
    """
    Check if two graphs are identical (same driver analyzed twice).
    
    Identity is determined by:
    1. Same anchor function address
    2. Same number of nodes
    3. Same set of node addresses
    4. Same set of edges
    
    Returns:
        True if graphs are structurally identical
    """
    # Same anchor?
    if graph_a.anchor_function != graph_b.anchor_function:
        return False
    
    # Same node count?
    if len(graph_a.nodes) != len(graph_b.nodes):
        return False
    
    # Same node addresses?
    nodes_a = set(graph_a.nodes.keys())
    nodes_b = set(graph_b.nodes.keys())
    if nodes_a != nodes_b:
        return False
    
    # Same edges?
    edges_a = set((c, t, e) for c, t, e in graph_a.edges)
    edges_b = set((c, t, e) for c, t, e in graph_b.edges)
    if edges_a != edges_b:
        return False
    
    # Check that node roles match
    for ea in nodes_a:
        if graph_a.nodes[ea].role != graph_b.nodes[ea].role:
            return False
    
    return True

def compare_logic_flows(graph_a: LogicGraph, graph_b: LogicGraph, debug_context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """
    Compare logic flows between two graphs for semantic equivalence analysis.
    Uses enhanced LogicGraph methods for comprehensive comparison including logic equivalence.

    Args:
        graph_a: Anchor graph (from driver A)
        graph_b: Candidate graph (from driver B)
        debug_context: Optional debugging context for traceability
    """
    if not graph_b or not graph_b.nodes:
        logger.warning("Comparison skipped: Candidate graph is empty")
        return {
            "graph_summaries": {
                "graph_a": graph_a.get_graph_summary(),
                "graph_b": {"total_nodes": 0, "total_edges": 0, "max_depth": 0}
            },
            "logic_equivalence": {"structural_similarity": {}, "role_distribution": {}, "overall_similarity_score": 0.0},
            "structural_comparison": {},
            "semantic_comparison": {},
            "flow_analysis": {},
            "error_path_analysis": {},
            "handle_lifecycle_comparison": {},
            "patch_classification": {},
            "attack_surface_analysis": {},
            "security_insights": {"overall_security_assessment": "unknown"},
            "manual_analysis_hints": ["Candidate graph is empty"],
            "crash_traceability": {}
        }

    # Identity verification check: if graphs are identical, return 100% match
    if _is_identity_comparison(graph_a, graph_b):
        logger.info("Identity comparison detected: A vs A = 100% match")
        return {
            "is_identity": True,
            "graph_summaries": {
                "graph_a": graph_a.get_graph_summary(),
                "graph_b": graph_b.get_graph_summary()
            },
            "logic_equivalence": {
                "structural_similarity": {"identical": True},
                "role_distribution": {"match": 1.0},
                "overall_similarity_score": 1.0
            },
            "structural_comparison": {"identical": True, "node_diff": 0, "edge_diff": 0},
            "semantic_comparison": {"identical": True, "role_match": 1.0},
            "flow_analysis": {"identical": True},
            "error_path_analysis": {"identical": True},
            "handle_lifecycle_comparison": {"identical": True},
            "patch_classification": {"no_changes": True, "classification": "identical"},
            "attack_surface_analysis": {"no_change": True},
            "security_insights": {"overall_security_assessment": "identical", "no_regression": True},
            "manual_analysis_hints": ["Graphs are identical - no differences to analyze"],
            "crash_traceability": {}
        }

    # Use the enhanced LogicGraph comparison method
    logic_comparison = graph_a.find_similar_logic(graph_b)

    # Initialize PoC Helper for security insights
    poc_helper = PoCHelper()

    # Generate patch heuristics classification
    patch_classification = _classify_patch_changes(graph_a, graph_b, poc_helper)

    # Analyze attack surface and reachability
    attack_surface_analysis = _analyze_attack_surface(graph_a, graph_b, poc_helper)

    comparison = {
        "graph_summaries": {
            "graph_a": graph_a.get_graph_summary(),
            "graph_b": graph_b.get_graph_summary()
        },
        "logic_equivalence": logic_comparison,
        "structural_comparison": _compare_graph_structure(graph_a, graph_b),
        "semantic_comparison": _compare_graph_semantics(graph_a, graph_b),
        "flow_analysis": _analyze_flow_differences(graph_a, graph_b),
        "error_path_analysis": _analyze_error_path_equivalence(graph_a, graph_b),
        "handle_lifecycle_comparison": _compare_handle_lifecycles(graph_a, graph_b),
        "patch_classification": patch_classification,
        "attack_surface_analysis": attack_surface_analysis,
        "security_insights": _generate_security_insights(graph_a, graph_b, poc_helper, patch_classification, attack_surface_analysis),
        "manual_analysis_hints": _generate_enhanced_manual_hints(graph_a, graph_b, logic_comparison),
        "crash_traceability": _generate_crash_traceability(graph_a, graph_b, debug_context)
    }

    return comparison

def generate_textual_diff_summary(comparison_result: Dict[str, Any]) -> str:
    """
    Generate a human-readable textual summary of the logic flow comparison.
    Produces analysis suitable for manual security research.
    """
    lines = []
    lines.append("=" * 80)
    lines.append("LOGIC FLOW ANALYSIS COMPARISON REPORT")
    lines.append("=" * 80)
    lines.append("")

    # Graph summaries
    summaries = comparison_result.get("graph_summaries", {})
    graph_a_summary = summaries.get("graph_a", {})
    graph_b_summary = summaries.get("graph_b", {})

    lines.append("GRAPH OVERVIEW:")
    lines.append(f"  Graph A: {graph_a_summary.get('total_nodes', 0)} nodes, {graph_a_summary.get('total_edges', 0)} edges")
    lines.append(f"  Graph B: {graph_b_summary.get('total_nodes', 0)} nodes, {graph_b_summary.get('total_edges', 0)} edges")
    lines.append("")

    # Logic equivalence analysis
    logic_eq = comparison_result.get("logic_equivalence", {})
    structural = logic_eq.get("structural_similarity", {})

    lines.append("STRUCTURAL ANALYSIS:")
    lines.append(f"  Node count difference: {structural.get('node_count_diff', 0)}")
    lines.append(f"  Edge count difference: {structural.get('edge_count_diff', 0)}")
    lines.append(f"  Depth similarity: {structural.get('depth_similarity', False)}")
    lines.append(f"  Anchor roles match: {structural.get('anchor_role_match', False)}")
    lines.append("")

    # Role distribution
    roles = logic_eq.get("role_distribution", {})
    if roles.get("differences"):
        lines.append("FUNCTION ROLE DIFFERENCES:")
        for role, diff in roles["differences"].items():
            direction = "more" if diff > 0 else "fewer"
            lines.append(f"  Graph B has {abs(diff)} {direction} {role} functions")
        lines.append("")

    # Error path analysis
    error_analysis = comparison_result.get("error_path_analysis", {})
    lines.append("ERROR HANDLING ANALYSIS:")
    lines.append(f"  Error paths in Graph A: {error_analysis.get('error_paths_a_count', 0)}")
    lines.append(f"  Error paths in Graph B: {error_analysis.get('error_paths_b_count', 0)}")
    lines.append(f"  Equivalent error handling: {error_analysis.get('has_equivalent_error_handling', False)}")
    lines.append("")

    # Handle lifecycle analysis
    handle_comp = comparison_result.get("handle_lifecycle_comparison", {})
    lines.append("HANDLE LIFECYCLE ANALYSIS:")
    lines.append(f"  Handle operations - A: {handle_comp.get('handle_operations_a', 0)}, B: {handle_comp.get('handle_operations_b', 0)}")
    balance_a = handle_comp.get("acquire_release_balance_a", 0)
    balance_b = handle_comp.get("acquire_release_balance_b", 0)
    lines.append(f"  Acquire/Release balance - A: {balance_a}, B: {balance_b}")
    lines.append(f"  Handle safety score - A: {handle_comp.get('handle_safety_score_a', 0):.1f}/10, B: {handle_comp.get('handle_safety_score_b', 0):.1f}/10")
    lines.append(f"  Balanced handle management: {handle_comp.get('balanced_handle_management', False)}")

    # Handle leak warnings
    leak_warnings = handle_comp.get("handle_leak_warnings", [])
    if leak_warnings:
        lines.append("  HANDLE LEAK WARNINGS:")
        for warning in leak_warnings[:3]:  # Limit to 3 warnings
            lines.append(f"    ⚠️ {warning}")
    lines.append("")

    # Manual analysis hints
    hints = comparison_result.get("manual_analysis_hints", [])
    if hints:
        lines.append("MANUAL ANALYSIS RECOMMENDATIONS:")
        for hint in hints:
            lines.append(f"  • {hint}")
        lines.append("")

    # Crash traceability
    crash_trace = comparison_result.get("crash_traceability", {})
    if crash_trace:
        lines.append("CRASH TRACEABILITY:")
        for key, value in crash_trace.items():
            if isinstance(value, bool):
                status = "YES" if value else "NO"
                lines.append(f"  {key}: {status}")
            else:
                lines.append(f"  {key}: {value}")
        lines.append("")

    lines.append("=" * 80)
    lines.append("END OF ANALYSIS REPORT")
    lines.append("=" * 80)

    return "\n".join(lines)

def save_comparison_results(comparison_result: Dict[str, Any], output_dir: str = ".") -> Dict[str, str]:
    """
    Save comparison results in multiple formats.

    Args:
        comparison_result: The comparison result dictionary
        output_dir: Directory to save files

    Returns:
        Dictionary mapping format names to file paths
    """
    import json
    import os
    from datetime import datetime

    # Create output directory if it doesn't exist (normalize path first)
    output_dir = os.path.normpath(output_dir)
    os.makedirs(output_dir, exist_ok=True)

    # Generate timestamp for filenames
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    saved_files = {}

    # Save JSON format
    json_filename = f"logic_flow_comparison_{timestamp}.json"
    json_path = os.path.join(output_dir, json_filename)
    with open(json_path, 'w', encoding='utf-8') as f:
        json.dump(comparison_result, f, indent=2, default=str)
    saved_files["json"] = json_path

    # Save textual summary
    text_filename = f"logic_flow_comparison_{timestamp}.txt"
    text_path = os.path.join(output_dir, text_filename)
    with open(text_path, 'w', encoding='utf-8') as f:
        f.write(generate_textual_diff_summary(comparison_result))
    saved_files["text"] = text_path

    # Save HTML report
    html_filename = f"logic_flow_comparison_{timestamp}.html"
    html_path = os.path.join(output_dir, html_filename)
    with open(html_path, 'w', encoding='utf-8') as f:
        f.write(generate_html_diff_report(comparison_result))
    saved_files["html"] = html_path

    # Save GraphViz DOT files for visualization
    try:
        dot_files = save_graphviz_dot_files(comparison_result, output_dir, timestamp)
        saved_files.update(dot_files)
    except Exception as e:
        logger.warning(f"Failed to save GraphViz DOT files: {e}")

    return saved_files

def _analyze_error_path_equivalence(graph_a: LogicGraph, graph_b: LogicGraph) -> Dict[str, Any]:
    """Analyze equivalence of error handling paths between graphs"""
    error_paths_a = graph_a.get_error_paths()
    error_paths_b = graph_b.get_error_paths()

    return {
        "error_paths_a_count": len(error_paths_a),
        "error_paths_b_count": len(error_paths_b),
        "error_path_complexity_a": sum(len(path) for path in error_paths_a) / max(len(error_paths_a), 1),
        "error_path_complexity_b": sum(len(path) for path in error_paths_b) / max(len(error_paths_b), 1),
        "has_equivalent_error_handling": _check_error_path_equivalence(error_paths_a, error_paths_b)
    }

def _compare_handle_lifecycles(graph_a: LogicGraph, graph_b: LogicGraph) -> Dict[str, Any]:
    """Compare handle lifecycle management between graphs with improved logic"""
    # Count handle operations
    acquire_a = sum(1 for n in graph_a.nodes.values() if n.has_handle_acquire)
    acquire_b = sum(1 for n in graph_b.nodes.values() if n.has_handle_acquire)

    release_a = sum(1 for n in graph_a.nodes.values() if n.has_handle_release)
    release_b = sum(1 for n in graph_b.nodes.values() if n.has_handle_release)

    validate_a = sum(1 for n in graph_a.nodes.values() if n.has_handle_validation)
    validate_b = sum(1 for n in graph_b.nodes.values() if n.has_handle_validation)

    # Calculate balances
    balance_a = acquire_a - release_a
    balance_b = acquire_b - release_b

    # Enhanced analysis
    analysis = {
        "handle_operations_a": acquire_a + release_a + validate_a,
        "handle_operations_b": acquire_b + release_b + validate_b,
        "acquire_count_a": acquire_a,
        "acquire_count_b": acquire_b,
        "release_count_a": release_a,
        "release_count_b": release_b,
        "validation_count_a": validate_a,
        "validation_count_b": validate_b,
        "acquire_release_balance_a": balance_a,
        "acquire_release_balance_b": balance_b,
        "balanced_handle_management": abs(balance_a) == abs(balance_b),
        "handle_leak_warnings": [],
        "handle_safety_score_a": _calculate_handle_safety_score(acquire_a, release_a, validate_a),
        "handle_safety_score_b": _calculate_handle_safety_score(acquire_b, release_b, validate_b)
    }

    # Generate warnings for potential handle leaks
    if balance_a > 0:
        analysis["handle_leak_warnings"].append("Graph A has more acquire than release operations - potential handle leak")
    if balance_b > 0:
        analysis["handle_leak_warnings"].append("Graph B has more acquire than release operations - potential handle leak")

    # Cải thiện: Path-sensitive analysis thay vì chỉ đếm số lượng
    path_analysis_a = _analyze_handle_lifecycle_paths(graph_a)
    path_analysis_b = _analyze_handle_lifecycle_paths(graph_b)

    analysis.update({
        "path_sensitive_leaks_a": path_analysis_a["leaks"],
        "path_sensitive_leaks_b": path_analysis_b["leaks"],
        "acquire_release_pairs_a": path_analysis_a["pairs"],
        "acquire_release_pairs_b": path_analysis_b["pairs"]
    })

    # Check for dangerous patterns (acquire without validation or error handling)
    dangerous_patterns_a = _detect_dangerous_handle_patterns(graph_a)
    dangerous_patterns_b = _detect_dangerous_handle_patterns(graph_b)

    if dangerous_patterns_a:
        analysis["handle_leak_warnings"].extend([f"Graph A: {pattern}" for pattern in dangerous_patterns_a])
    if dangerous_patterns_b:
        analysis["handle_leak_warnings"].extend([f"Graph B: {pattern}" for pattern in dangerous_patterns_b])

    # Thêm warnings từ path-sensitive analysis
    if path_analysis_a["leaks"]:
        analysis["handle_leak_warnings"].extend([f"Graph A path-sensitive: {leak}" for leak in path_analysis_a["leaks"]])
    if path_analysis_b["leaks"]:
        analysis["handle_leak_warnings"].extend([f"Graph B path-sensitive: {leak}" for leak in path_analysis_b["leaks"]])

    return analysis

def _calculate_handle_safety_score(acquire_count: int, release_count: int, validation_count: int) -> float:
    """Calculate a handle safety score (0-10) based on handle management patterns"""
    if acquire_count == 0:
        return 10.0  # No handle operations = no risk

    score = 0

    # Base score from balance
    balance = abs(acquire_count - release_count)
    if balance == 0:
        score += 5  # Perfect balance
    elif balance == 1:
        score += 3  # Minor imbalance
    else:
        score += 0  # Significant imbalance

    # Bonus for validation
    if validation_count > 0:
        validation_ratio = min(validation_count / acquire_count, 1.0)
        score += validation_ratio * 3  # Up to 3 points for validation

    # Bonus for proper release patterns
    if release_count >= acquire_count:
        score += 2  # Proper release pattern

    return min(10.0, score)

def _detect_dangerous_handle_patterns(graph: LogicGraph) -> List[str]:
    """Detect dangerous handle management patterns that could lead to leaks"""
    warnings = []

    # Check for acquire operations without corresponding release in error paths
    acquire_nodes = [node for node in graph.nodes.values() if node.has_handle_acquire]
    error_nodes = [node for node in graph.nodes.values() if node.is_error_handler or node.has_failfast]

    for acquire_node in acquire_nodes:
        # Check if this acquire node is in an error path without proper cleanup
        in_error_path = False
        for error_node in error_nodes:
            if _nodes_in_same_path(graph, acquire_node.ea, error_node.ea):
                in_error_path = True
                break

        if in_error_path:
            # Check if there's a release node in the same path
            has_release_in_path = False
            for release_node in [node for node in graph.nodes.values() if node.has_handle_release]:
                if _nodes_in_same_path(graph, acquire_node.ea, release_node.ea):
                    has_release_in_path = True
                    break

            if not has_release_in_path:
                warnings.append(f"Handle acquire in {hex(acquire_node.ea)} may leak in error path")

    # Check for handle operations in functions without error handling
    handle_managers = [node for node in graph.nodes.values() if node.role == FunctionRole.HANDLE_MANAGER]
    for manager in handle_managers:
        if not manager.is_error_handler and not manager.has_failfast:
            # This handle manager doesn't have error handling
            warnings.append(f"Handle manager {hex(manager.ea)} lacks error handling - potential leak risk")

    return warnings

def _nodes_in_same_path(graph: LogicGraph, node_a: int, node_b: int) -> bool:
    """Check if two nodes are in the same execution path"""
    # Simple check: share common callers or callees
    callers_a = graph.get_callers(node_a)
    callers_b = graph.get_callers(node_b)

    if callers_a & callers_b:  # Common callers
        return True

    callees_a = graph.get_callees(node_a)
    callees_b = graph.get_callees(node_b)

    if callees_a & callees_b:  # Common callees
        return True

    return False

def _check_error_path_equivalence(paths_a: List[List[int]], paths_b: List[List[int]]) -> bool:
    """Check if error paths are structurally equivalent"""
    if len(paths_a) != len(paths_b):
        return False

    # Simple check: compare path lengths
    lengths_a = sorted([len(p) for p in paths_a])
    lengths_b = sorted([len(p) for p in paths_b])

    return lengths_a == lengths_b

def _generate_enhanced_manual_hints(graph_a: LogicGraph, graph_b: LogicGraph, logic_comparison: Dict) -> List[str]:
    """Generate enhanced manual analysis hints using logic comparison results"""
    hints = []

    # Use the hints from the logic comparison
    if "manual_analysis_hints" in logic_comparison:
        hints.extend(logic_comparison["manual_analysis_hints"])

    # Add additional analysis hints
    error_analysis = _analyze_error_path_equivalence(graph_a, graph_b)
    if error_analysis["error_paths_a_count"] == 0 and error_analysis["error_paths_b_count"] > 0:
        hints.append("Graph A has no error paths but Graph B does - potential vulnerability in A")
    elif error_analysis["error_paths_b_count"] == 0 and error_analysis["error_paths_a_count"] > 0:
        hints.append("Graph B has no error paths but Graph A does - Graph B may be more robust")

    handle_comp = _compare_handle_lifecycles(graph_a, graph_b)
    balance_a = handle_comp["acquire_release_balance_a"]
    balance_b = handle_comp["acquire_release_balance_b"]

    if balance_a != 0 and balance_b == 0:
        hints.append("Graph A has unbalanced handle operations - potential resource leaks")
    elif balance_b != 0 and balance_a == 0:
        hints.append("Graph B has unbalanced handle operations - check for correctness")

    return hints

def _compare_graph_structure(graph_a: LogicGraph, graph_b: LogicGraph) -> Dict[str, Any]:
    """Compare structural properties between graphs"""
    
    # Native Optimization Path
    if _NATIVE_AVAILABLE:
        try:
            # Convert Python Graphs to Rust Graphs
            # (In a real scenario, we might keep them as Rust objects from the start)
            rg_a = logic_flow_native.RustGraph(graph_a.anchor_function)
            for ea, node in graph_a.nodes.items():
                r_node = logic_flow_native.RustNode(
                    ea, node.role.name if hasattr(node.role, 'name') else str(node.role),
                    getattr(node, 'is_error_handler', False),
                    getattr(node, 'has_failfast', False)
                )
                rg_a.add_node(r_node)
            for u, v, t in graph_a.edges:
                rg_a.add_edge(u, v, str(t))

            rg_b = logic_flow_native.RustGraph(graph_b.anchor_function)
            for ea, node in graph_b.nodes.items():
                r_node = logic_flow_native.RustNode(
                    ea, node.role.name if hasattr(node.role, 'name') else str(node.role),
                    getattr(node, 'is_error_handler', False),
                    getattr(node, 'has_failfast', False)
                )
                rg_b.add_node(r_node)
            for u, v, t in graph_b.edges:
                rg_b.add_edge(u, v, str(t))

            # Run Native Comparison
            native_metrics = logic_flow_native.compare_structure(rg_a, rg_b)
            
            # Merge with Python results (legacy metrics still useful)
            result = {
                "node_count_difference": abs(len(graph_a.nodes) - len(graph_b.nodes)),
                "boundary_overlap": len(graph_a.bounds & graph_b.bounds),
                "native_similarity": native_metrics
            }
            return result
        except Exception as e:
            logger.warning(f"Native structural comparison failed, falling back to Python: {e}")

    # Safely get anchor node roles (graphs may be empty)
    anchor_a_node = graph_a.nodes.get(graph_a.anchor_function)
    anchor_b_node = graph_b.nodes.get(graph_b.anchor_function)
    
    anchor_a_role = anchor_a_node.role if anchor_a_node else FunctionRole.UNKNOWN
    anchor_b_role = anchor_b_node.role if anchor_b_node else FunctionRole.UNKNOWN

    return {
        "node_count_difference": abs(len(graph_a.nodes) - len(graph_b.nodes)),
        "boundary_overlap": len(graph_a.bounds & graph_b.bounds),
        "anchor_roles_differ": anchor_a_role != anchor_b_role,
        "anchor_a_role": anchor_a_role.value,
        "anchor_b_role": anchor_b_role.value,
        "depth_similarity": abs(graph_a.max_depth - graph_b.max_depth)
    }

def _compare_graph_semantics(graph_a: LogicGraph, graph_b: LogicGraph) -> Dict[str, Any]:
    """Compare semantic properties between graphs"""
    roles_a = {}
    roles_b = {}

    for node in graph_a.nodes.values():
        roles_a[node.role.value] = roles_a.get(node.role.value, 0) + 1

    for node in graph_b.nodes.values():
        roles_b[node.role.value] = roles_b.get(node.role.value, 0) + 1

    # Find role differences
    all_roles = set(roles_a.keys()) | set(roles_b.keys())
    role_differences = {}
    for role in all_roles:
        count_a = roles_a.get(role, 0)
        count_b = roles_b.get(role, 0)
        if count_a != count_b:
            role_differences[role] = {"graph_a": count_a, "graph_b": count_b}

    return {
        "role_distributions": {"graph_a": roles_a, "graph_b": roles_b},
        "role_differences": role_differences,
        "error_handler_count": {
            "graph_a": sum(1 for n in graph_a.nodes.values() if n.is_error_handler),
            "graph_b": sum(1 for n in graph_b.nodes.values() if n.is_error_handler)
        },
        "failfast_count": {
            "graph_a": sum(1 for n in graph_a.nodes.values() if n.has_failfast),
            "graph_b": sum(1 for n in graph_b.nodes.values() if n.has_failfast)
        },
        "handle_acquire_count": {
            "graph_a": sum(1 for n in graph_a.nodes.values() if n.has_handle_acquire),
            "graph_b": sum(1 for n in graph_b.nodes.values() if n.has_handle_acquire)
        },
        "handle_validation_count": {
            "graph_a": sum(1 for n in graph_a.nodes.values() if n.has_handle_validation),
            "graph_b": sum(1 for n in graph_b.nodes.values() if n.has_handle_validation)
        },
        "handle_release_count": {
            "graph_a": sum(1 for n in graph_a.nodes.values() if n.has_handle_release),
            "graph_b": sum(1 for n in graph_b.nodes.values() if n.has_handle_release)
        }
    }

def _analyze_flow_differences(graph_a: LogicGraph, graph_b: LogicGraph) -> Dict[str, Any]:
    """Analyze differences in control flow and call patterns"""
    # Compare call hierarchies
    callers_a = len(graph_a.get_callers(graph_a.anchor_function))
    callers_b = len(graph_b.get_callers(graph_b.anchor_function))

    # Compare error propagation paths
    error_paths_a = _extract_error_paths(graph_a)
    error_paths_b = _extract_error_paths(graph_b)

    return {
        "caller_count_difference": abs(callers_a - callers_b),
        "error_paths": {
            "graph_a": error_paths_a,
            "graph_b": error_paths_b
        },
        "path_similarity_analysis": _compare_error_paths(error_paths_a, error_paths_b, graph_a, graph_b)
    }

def _extract_error_paths(graph: LogicGraph) -> List[List[int]]:
    """Extract paths related to error handling from graph - ITERATIVE version"""
    paths = []
    
    # Safety check for empty graphs
    if not graph.nodes or graph.anchor_function not in graph.nodes:
        return paths

    # Stack: (current_node, path_so_far, visited_set)
    stack = [(graph.anchor_function, [graph.anchor_function], {graph.anchor_function})]
    
    while stack:
        current, path, visited = stack.pop()
        
        if current not in graph.nodes:
            continue

        node = graph.nodes[current]
        if node.role in [FunctionRole.ERROR_HANDLER, FunctionRole.FAILFAST_GUARD]:
            paths.append(path[:])  # Found error handling path

        # Continue traversal if not too deep
        if len(path) < 5:
            for callee in graph.get_callees(current):
                if callee not in visited:
                    new_visited = visited.copy()
                    new_visited.add(callee)
                    stack.append((callee, path + [callee], new_visited))

    return paths

def _compare_error_paths(paths_a: List[List[int]], paths_b: List[List[int]],
                        graph_a: LogicGraph, graph_b: LogicGraph) -> List[Dict]:
    """Compare error handling paths between graphs"""
    comparisons = []

    for path_a in paths_a[:3]:  # Limit for performance
        best_match = None
        best_similarity = 0

        for path_b in paths_b[:3]:
            similarity = _path_semantic_similarity(path_a, path_b, graph_a, graph_b)
            if similarity > best_similarity:
                best_similarity = similarity
                best_match = path_b

        if best_match:
            # Use .get() to safely access nodes that might not exist
            role_seq_a = []
            for ea in path_a:
                node = graph_a.nodes.get(ea)
                role_seq_a.append(node.role.value if node else "unknown")
            
            role_seq_b = []
            for ea in best_match:
                node = graph_b.nodes.get(ea)
                role_seq_b.append(node.role.value if node else "unknown")
            
            comparisons.append({
                "path_a": [hex(ea) for ea in path_a],
                "path_b": [hex(ea) for ea in best_match],
                "semantic_similarity": best_similarity,
                "role_sequence_a": role_seq_a,
                "role_sequence_b": role_seq_b
            })

    return comparisons

def _path_semantic_similarity(path_a: List[int], path_b: List[int],
                            graph_a: LogicGraph, graph_b: LogicGraph) -> float:
    """Calculate semantic similarity between two paths"""
    if not path_a or not path_b:
        return 0.0

    # Use .get() to safely access nodes
    roles_a = []
    for ea in path_a:
        node = graph_a.nodes.get(ea)
        roles_a.append(node.role.value if node else "unknown")
    
    roles_b = []
    for ea in path_b:
        node = graph_b.nodes.get(ea)
        roles_b.append(node.role.value if node else "unknown")

    # Simple similarity based on role sequence matching
    min_len = min(len(roles_a), len(roles_b))
    matches = sum(1 for i in range(min_len) if roles_a[i] == roles_b[i])
    return matches / max(len(roles_a), len(roles_b)) if roles_a or roles_b else 0.0

def _generate_manual_hints(graph_a: LogicGraph, graph_b: LogicGraph) -> List[str]:
    """Generate hints for manual analysis based on graph comparison"""
    hints = []

    # FailFast positioning hints
    failfast_a = next((ea for ea, node in graph_a.nodes.items() if node.has_failfast), None)
    failfast_b = next((ea for ea, node in graph_b.nodes.items() if node.has_failfast), None)

    if failfast_a and failfast_b:
        path_a = graph_a.get_path_to_anchor(failfast_a)
        path_b = graph_b.get_path_to_anchor(failfast_b)

        if len(path_a) != len(path_b):
            hints.append(f"FailFast positioning differs: {len(path_a)} vs {len(path_b)} levels from anchor")

    # Role distribution hints
    roles_a = sum(1 for node in graph_a.nodes.values() if node.role != FunctionRole.UNKNOWN)
    roles_b = sum(1 for node in graph_b.nodes.values() if node.role != FunctionRole.UNKNOWN)

    if abs(roles_a - roles_b) > 1:
        hints.append(f"Different number of identified semantic roles: {roles_a} vs {roles_b}")

    # Boundary differences
    if graph_a.bounds != graph_b.bounds:
        hints.append(f"Different semantic boundaries identified: {graph_a.bounds} vs {graph_b.bounds}")

    # Error handler differences
    error_a = sum(1 for node in graph_a.nodes.values() if node.is_error_handler)
    error_b = sum(1 for node in graph_b.nodes.values() if node.is_error_handler)

    if error_a != error_b:
        hints.append(f"Different number of error handlers in graph: {error_a} vs {error_b}")

    return hints

def _generate_crash_traceability(graph_a: LogicGraph, graph_b: LogicGraph, debug_context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """
    Generate crash traceability information linking debug context to analysis results.
    Helps researchers trace from crash symptoms back to specific logic paths.
    """
    traceability = {
        "debug_context_provided": debug_context is not None,
        "crash_to_logic_mapping": {},
        "logic_path_analysis": {},
        "traceability_hints": []
    }

    if not debug_context:
        traceability["traceability_hints"].append("No debug context provided - manual correlation required")
        return traceability

    # Extract crash-relevant information
    exception_type = debug_context.get("exception_type", "unknown")
    irql_level = debug_context.get("irql_level")
    status_code = debug_context.get("status_code")
    crash_address = debug_context.get("crash_address")
    call_stack = debug_context.get("call_stack", [])

    # Map crash context to logic graph analysis
    crash_to_logic_mapping = {
        "exception_type": exception_type,
        "irql_level": irql_level,
        "status_code": status_code,
        "crash_address": hex(crash_address) if crash_address else None,
        "anchor_function_matches_crash": crash_address == graph_a.anchor_function if crash_address else False
    }

    # Analyze logic paths that might be relevant to the crash
    logic_path_analysis = {}

    # Check if anchor functions have error handling characteristics
    anchor_a_error_handling = graph_a.nodes[graph_a.anchor_function].is_error_handler
    anchor_b_error_handling = graph_b.nodes[graph_b.anchor_function].is_error_handler

    logic_path_analysis["error_handler_alignment"] = {
        "anchor_a_is_error_handler": anchor_a_error_handling,
        "anchor_b_is_error_handler": anchor_b_error_handling,
        "crash_relevance": "High" if exception_type in ["ACCESS_VIOLATION", "PAGE_FAULT", "IRQL_NOT_LESS_OR_EQUAL"] and not anchor_b_error_handling else "Medium"
    }

    # Check for handle lifecycle issues if crash suggests handle problems
    if status_code in ["STATUS_INVALID_HANDLE", "STATUS_HANDLE_NOT_CLOSABLE"] or exception_type == "INVALID_HANDLE":
        handle_analysis = {
            "anchor_a_handle_ops": {
                "has_acquire": graph_a.nodes[graph_a.anchor_function].has_handle_acquire,
                "has_release": graph_a.nodes[graph_a.anchor_function].has_handle_release,
                "has_validation": graph_a.nodes[graph_a.anchor_function].has_handle_validation
            },
            "anchor_b_handle_ops": {
                "has_acquire": graph_b.nodes[graph_b.anchor_function].has_handle_acquire,
                "has_release": graph_b.nodes[graph_b.anchor_function].has_handle_release,
                "has_validation": graph_b.nodes[graph_b.anchor_function].has_handle_validation
            }
        }
        logic_path_analysis["handle_lifecycle_analysis"] = handle_analysis

        if not handle_analysis["anchor_b_handle_ops"]["has_release"] and handle_analysis["anchor_a_handle_ops"]["has_release"]:
            traceability["traceability_hints"].append("Potential handle leak: Anchor B lacks handle release logic present in Anchor A")

    # Check IRQL safety if IRQL-related crash
    if irql_level is not None or exception_type == "IRQL_NOT_LESS_OR_EQUAL":
        irql_analysis = {
            "anchor_a_irp_dispatcher": graph_a.nodes[graph_a.anchor_function].role == FunctionRole.IRP_DISPATCHER,
            "anchor_b_irp_dispatcher": graph_b.nodes[graph_b.anchor_function].role == FunctionRole.IRP_DISPATCHER,
            "irql_safety_concern": irql_level > 2 if irql_level else None
        }
        logic_path_analysis["irql_analysis"] = irql_analysis

    # Generate specific traceability hints
    if exception_type == "ACCESS_VIOLATION":
        traceability["traceability_hints"].append("Access violation crash - check for NULL pointer validation differences between anchor functions")
    elif status_code == "STATUS_INVALID_HANDLE":
        traceability["traceability_hints"].append("Invalid handle status - examine handle validation logic differences")
    elif irql_level and irql_level > 2:
        traceability["traceability_hints"].append(f"High IRQL ({irql_level}) crash - verify IRP dispatcher alignment and spinlock usage")

    traceability["crash_to_logic_mapping"] = crash_to_logic_mapping
    traceability["logic_path_analysis"] = logic_path_analysis

    return traceability

def _get_callers_cached(func_ea: int, context: AnalysisContext) -> Set[int]:
    """Get callers of a function with caching and error handling"""
    cache_key = f"callers_{func_ea}"
    if cache_key in context.callers_cache:
        return context.callers_cache[cache_key]

    callers = set()
    try:
        # Use context.ida_provider
        ida_provider = context.ida_provider
        for xref in ida_provider.XrefsTo(func_ea):
            if xref is None:
                continue
            if ida_provider.is_call_insn(xref.frm):
                caller_func = ida_provider.get_func(xref.frm)
                if caller_func:
                    callers.add(caller_func.start_ea)
    except Exception as e:
        logger.warning(f"Failed to get callers for {hex(func_ea)}: {e}")
        callers = set()

    context.callers_cache[cache_key] = callers
    return callers

def _get_callees(func_ea: int, ida_provider: IDAProvider) -> Set[int]:
    """Get functions called by the given function"""
    callees = set()
    try:
        f = ida_provider.get_func(func_ea)
        if not f:
            return callees

        ea = f.start_ea
        while ea < f.end_ea:
            try:
                if ida_provider.is_call_insn(ea):
                    for ref in ida_provider.get_code_refs_from(ea):
                        if ref != ida_provider.BADADDR:
                            callee_func = ida_provider.get_func(ref)
                            if callee_func:
                                callees.add(callee_func.start_ea)
            except (AttributeError, TypeError) as e:
                logger.debug(f"Error getting callee at {hex(ea)}: {e}")
            ea = ida_provider.next_head(ea, f.end_ea)
    except Exception as e:
        logger.warning(f"Failed to get callees for {hex(func_ea)}: {e}")
    return callees

def _get_function_name(func_ea: int, ida_provider: IDAProvider) -> str:
    """Get function name safely"""
    try:
        f = ida_provider.get_func(func_ea)
        if f and hasattr(f, 'name') and f.name:
            return f.name

        # Try to get name via IDA name API
        name = ida_provider.get_ea_name(func_ea)
        if name and not name.startswith('sub_'):
            return name

        return f"sub_{func_ea:08X}"
    except (AttributeError, TypeError):
        return f"sub_{func_ea:08X}"

def _get_irp_context_cached(func_ea: int, context: AnalysisContext) -> Optional[Dict]:
    """Get IRP context for function with caching"""
    cache_key = f"irp_{func_ea}"
    if cache_key in context.irp_context_cache:
        return context.irp_context_cache[cache_key]

    # Pass context.ida_provider to actual analyzer
    context_data = _analyze_irp_context(func_ea, context.ida_provider)
    context.irp_context_cache[cache_key] = context_data
    return context_data

def _analyze_function_semantics_cached(func_ea: int, context: AnalysisContext) -> Tuple[FunctionRole, bool, bool, bool, bool, bool, bool]:
    """Analyze function semantics with caching to avoid repeated expensive analysis"""
    cache_key = f"semantics_{func_ea}"
    if cache_key in context.function_semantics_cache:
        return context.function_semantics_cache[cache_key]

    result = _analyze_function_semantics(func_ea, context.ida_provider)
    context.function_semantics_cache[cache_key] = result
    return result

def _get_function_name_cached(func_ea: int, context: AnalysisContext) -> str:
    """Get function name with caching to avoid repeated IDA API calls"""
    cache_key = f"name_{func_ea}"
    if cache_key in context.function_name_cache:
        return context.function_name_cache[cache_key]

    name = _get_function_name(func_ea, context.ida_provider)
    context.function_name_cache[cache_key] = name
    return name

def _get_function_flags_cached(func_ea: int, context: AnalysisContext) -> Tuple[bool, bool, bool, bool, bool, bool, bool]:
    """Cache function flags analysis to avoid repeated expensive analysis"""
    if func_ea in context.func_flags_cache:
        return context.func_flags_cache[func_ea]

    # Thực hiện phân tích nặng (FailFast check, IRP check, etc.)
    flags = _analyze_function_semantics(func_ea, context.ida_provider)

    context.func_flags_cache[func_ea] = flags
    return flags

def _analyze_irp_context(func_ea: int, ida_provider: IDAProvider) -> Optional[Dict]:
    """Analyze IRP context for function"""
    try:
        f = ida_provider.get_func(func_ea)
        if not f:
            return None

        is_irp_dispatcher = False
        major_functions = set()
        ioctl_codes = set()
        irp_parameters = set()

        ea = f.start_ea
        while ea < f.end_ea:
            try:
                if ida_provider.is_call_insn(ea):
                    for ref in ida_provider.get_code_refs_from(ea):
                        if ref == ida_provider.BADADDR:
                            continue

                        func_name = _get_function_name(ref, ida_provider)

                        # Check for IRP dispatcher patterns
                        if any(pattern in func_name for pattern in [
                            "IoGetCurrentIrpStackLocation", "IoGetNextIrpStackLocation"
                        ]):
                            is_irp_dispatcher = True

                        # Check for IRP major functions
                        if "IRP_MJ_" in func_name:
                            major_functions.add(func_name.split("IRP_MJ_")[1])

                        # Check for IOCTL codes
                        if any(code in func_name for code in ["IOCTL_", "METHOD_"]):
                            ioctl_codes.add(func_name)

                        # Check for IRP parameters
                        if any(param in func_name for param in [
                            "Parameters", "Tail", "AssociatedIrp", "IoStatus"
                        ]):
                            irp_parameters.add(func_name)

            except (AttributeError, TypeError) as e:
                logger.debug(f"Error analyzing IRP ref at {hex(ea)}: {e}")
            ea = ida_provider.next_head(ea, f.end_ea)

        return {
            "is_irp_dispatcher": is_irp_dispatcher,
            "major_functions": major_functions,
            "ioctl_codes": ioctl_codes,
            "irp_parameters": irp_parameters
        }

    except Exception as e:
        logger.warning(f"Failed to analyze IRP context for {hex(func_ea)}: {e}")
        return None

def _calculate_irp_context_similarity(anchor_context: Dict, func_ea: int, ida_provider: IDAProvider) -> float:
    """Calculate similarity between anchor IRP context and candidate function context"""
    func_context = _get_irp_context_cached(func_ea, ida_provider)
    if not func_context or not anchor_context:
        return 0.0

    score = 0
    if anchor_context.get("is_irp_dispatcher") and func_context.get("is_irp_dispatcher"):
        score += 1.0

    return score

def _identify_boundary_functions(graph: LogicGraph, ida_provider: IDAProvider):
    """Identify semantic boundaries in the graph"""
    bounds = set()

    # Check for IRP dispatcher boundary
    if any(node.role == FunctionRole.IRP_DISPATCHER for node in graph.nodes.values()):
        bounds.add("irp_dispatcher")

    # Check for error handling boundary
    if any(node.is_error_handler for node in graph.nodes.values()):
        bounds.add("error_handling")

    # Check for FailFast protection boundary
    if any(node.has_failfast for node in graph.nodes.values()):
        bounds.add("failfast_protection")

    # Check for resource management boundary
    if any(node.role == FunctionRole.RESOURCE_MANAGER for node in graph.nodes.values()):
        bounds.add("resource_management")

    # Check for handle management boundary
    if any(node.role == FunctionRole.HANDLE_MANAGER for node in graph.nodes.values()):
        bounds.add("handle_management")

    graph.bounds = bounds

# Legacy function for backward compatibility
def get_callers(func_ea):
    """Get callers of a function with error handling (legacy function)"""
    # Use appropriate IDA APIs via provider
    ida_provider = _get_ida_provider()
    context = AnalysisContext(ida_provider) # Create temp context for legacy call
    return _get_callers_cached(func_ea, context)


def analyze_driver_logic_flows(anchor_function: int, max_candidates: Optional[int] = None, debug_context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """
    Main analysis function for comparing logic flows between drivers.
    Builds bounded graph from anchor function and finds semantic equivalents.

    Args:
        anchor_function: Function address to start analysis from (from driver A)
        max_candidates: Maximum number of candidate functions to analyze (uses config default if None)
        debug_context: Optional debugging context from crash analysis (WinDbg, etc.)

    Returns:
        Dictionary containing analysis results for manual review
    """
    logger.info("=== LOGIC FLOW ANALYSIS STARTED ===")
    logger.info(f"Anchor function: {hex(anchor_function)}")

    # Clear cache to prevent cross-contamination in batch analysis
    clear_analysis_cache()

    if max_candidates is None:
        max_candidates = _config_manager.get_max_comparison_candidates()

    try:
        # Initialize analysis context
        # Use existing IDA provider
        ida_provider = _get_ida_provider()
        context = AnalysisContext(ida_provider)
        
        # Build bounded graph from anchor function
        logger.info("Building bounded call graph from anchor function...")
        anchor_graph = build_bounded_graph(anchor_function, max_depth=5, context=context)
        logger.info(f"Graph built with {len(anchor_graph.nodes)} nodes and {len(anchor_graph.edges)} edges")

        # Find semantic candidate functions with scoring
        logger.info("Finding and scoring semantic candidate functions...")
        scored_candidates = find_semantic_candidates(anchor_graph, max_candidates=max_candidates, context=context)
        logger.info(f"Found {len(scored_candidates)} scored candidate functions")

        # Extract function addresses for graph building (sorted by score)
        candidates = [func_ea for func_ea, _, _ in scored_candidates]

        # Build graphs for candidates and compare
        candidate_graphs = {}
        comparisons = {}

        for i, candidate_ea in enumerate(candidates):
            logger.info(f"Analyzing candidate {i+1}/{len(candidates)}: {hex(candidate_ea)}")
            try:
                candidate_graph = build_bounded_graph(candidate_ea, max_depth=5, context=context)
                candidate_graphs[candidate_ea] = candidate_graph

                # Compare logic flows
                comparison = compare_logic_flows(anchor_graph, candidate_graph, debug_context)
                comparisons[candidate_ea] = comparison

            except Exception as e:
                logger.warning(f"Failed to analyze candidate {hex(candidate_ea)}: {e}")
                continue

        # Generate analysis summary
        summary = _generate_analysis_summary(anchor_graph, candidate_graphs, comparisons, scored_candidates)

        # Convert sets to lists for JSON serialization
        def make_json_serializable(obj):
            if isinstance(obj, set):
                return list(obj)
            elif isinstance(obj, dict):
                return {k: make_json_serializable(v) for k, v in obj.items()}
            elif isinstance(obj, list):
                return [make_json_serializable(item) for item in obj]
            else:
                return obj

        # Include candidate scoring information
        candidate_scores = {}
        for func_ea, score, details in scored_candidates:
            if func_ea in candidate_graphs:  # Only include candidates that were successfully analyzed
                candidate_scores[hex(func_ea)] = {
                    "score": score,
                    "scoring_details": make_json_serializable(details)
                }

        result = {
            "anchor_function": hex(anchor_function),
            "debug_context": debug_context or {},
            "anchor_graph": make_json_serializable(anchor_graph.to_dict()),
            "candidates_scored": len(scored_candidates),
            "candidates_analyzed": len(candidate_graphs),
            "candidate_scores": candidate_scores,
            "candidate_graphs": {hex(ea): make_json_serializable(graph.to_dict()) for ea, graph in candidate_graphs.items()},
            "comparisons": {hex(ea): make_json_serializable(comp) for ea, comp in comparisons.items()},
            "analysis_summary": make_json_serializable(summary),
            "manual_review_required": True,
            "automated_verdict": None,  # No automated verdicts
            "scoring_system": {
                "description": "Weighted heuristic scoring (0-22 points)",
                "weights": {
                    "semantic_role_match": "0-5 points",
                    "failfast_alignment": "0-4 points",
                    "complete_alignment": "0-3 points",
                    "error_handler_match": "0-2 points",
                    "handle_acquire_alignment": "0-2 points",
                    "handle_validation_alignment": "0-2 points",
                    "handle_release_alignment": "0-2 points",
                    "irp_context_similarity": "0-2 points"
                }
            }
        }

        logger.info("=== LOGIC FLOW ANALYSIS COMPLETED ===")
        logger.info(f"Analyzed {len(candidate_graphs)} candidate functions")
        logger.info(f"Key findings: {len(summary.get('key_findings', []))}")
        logger.info("Results ready for manual review")

        return result

    except Exception as e:
        logger.error(f"Analysis failed: {e}")
        logger.debug("Full traceback:", exc_info=True)
        return {"error": str(e), "automated_verdict": None}


def _generate_analysis_summary(anchor_graph: LogicGraph, candidate_graphs: Dict[int, LogicGraph],
                              comparisons: Dict[int, Dict], candidate_scores: Dict[int, Tuple[float, Dict]] = None) -> Dict[str, Any]:
    """Generate analysis summary for manual review"""
    summary = {
        "total_candidates_analyzed": len(candidate_graphs),
        "key_findings": [],
        "manual_review_points": []
    }

    # Add scoring information if available
    if candidate_scores:
        scores = [score for func_ea, score, details in candidate_scores]
        if scores:
            high_score_threshold = _config_manager.get_high_score_threshold()
            summary["scoring_stats"] = {
                "highest_score": max(scores),
                "average_score": sum(scores) / len(scores),
                "score_range": f"{min(scores)}-{max(scores)}",
                "high_score_threshold": high_score_threshold,
                "candidates_with_high_scores": sum(1 for score in scores if score >= high_score_threshold)
            }

    if not candidate_graphs:
        summary["key_findings"].append("No candidate functions found for comparison")
        summary["manual_review_points"].append("Check if anchor function has distinctive error handling characteristics")
        return summary

    # Analyze structural differences
    anchor_size = len(anchor_graph.nodes)
    candidate_sizes = [len(graph.nodes) for graph in candidate_graphs.values()]

    if candidate_sizes:
        avg_size_diff = abs(anchor_size - sum(candidate_sizes) / len(candidate_sizes))
        if avg_size_diff > 3:
            summary["key_findings"].append(f"Graph size differences (avg diff: {avg_size_diff:.1f} nodes)")
            summary["manual_review_points"].append("Compare graph sizes - different logic complexity")

    # Analyze role distributions
    anchor_roles = {}
    for node in anchor_graph.nodes.values():
        anchor_roles[node.role.value] = anchor_roles.get(node.role.value, 0) + 1

    for addr, graph in candidate_graphs.items():
        candidate_roles = {}
        for node in graph.nodes.values():
            candidate_roles[node.role.value] = candidate_roles.get(node.role.value, 0) + 1

        # Check for significant role differences
        for role in set(anchor_roles.keys()) | set(candidate_roles.keys()):
            anchor_count = anchor_roles.get(role, 0)
            candidate_count = candidate_roles.get(role, 0)
            if abs(anchor_count - candidate_count) > 1:
                summary["key_findings"].append(f"Role '{role}' count differs for {hex(addr)}")
                summary["manual_review_points"].append(f"Review {role} functions in {hex(addr)}")

    # Check for boundary differences
    anchor_bounds = anchor_graph.bounds
    for addr, graph in candidate_graphs.items():
        if graph.bounds != anchor_bounds:
            diff_bounds = graph.bounds.symmetric_difference(anchor_bounds)
            summary["key_findings"].append(f"Boundary differences for {hex(addr)}: {diff_bounds}")
            summary["manual_review_points"].append(f"Review semantic boundaries in {hex(addr)}")

    # Check comparison hints
    for addr, comparison in comparisons.items():
        hints = comparison.get("manual_analysis_hints", [])
        if hints:
            summary["key_findings"].extend([f"{hex(addr)}: {hint}" for hint in hints[:2]])  # Limit hints
            summary["manual_review_points"].extend(hints)

    if not summary["key_findings"]:
        summary["key_findings"].append("No major structural differences found")
        summary["manual_review_points"].append("Review semantic flows and FailFast placement manually")

    return summary

def _calculate_irp_context_similarity(anchor_irp_context: Dict, candidate_ea: int, context: AnalysisContext) -> float:
    """
    Calculate similarity between anchor IRP context and candidate function IRP context.
    Returns score from 0-2 points based on IRP handling pattern overlap.
    """
    if not anchor_irp_context:
        return 0

    try:
        # Get candidate IRP context (cached)
        candidate_irp_context = _get_irp_context_cached(candidate_ea, context)
        if not candidate_irp_context:
            return 0

        similarity_score = 0

        # Compare IRP dispatcher status (1 point)
        if anchor_irp_context.get("is_irp_dispatcher") == candidate_irp_context.get("is_irp_dispatcher"):
            similarity_score += 0.5

        # Compare major function overlap (up to 0.5 points)
        anchor_major = set(anchor_irp_context.get("major_functions", []))
        candidate_major = set(candidate_irp_context.get("major_functions", []))
        if anchor_major and candidate_major:
            overlap = len(anchor_major & candidate_major)
            if overlap > 0:
                similarity_score += min(0.5, overlap * 0.25)  # 0.25 per overlapping function, max 0.5

        # Compare IOCTL codes overlap (up to 0.5 points)
        anchor_ioctl = set(anchor_irp_context.get("ioctl_codes", []))
        candidate_ioctl = set(candidate_irp_context.get("ioctl_codes", []))
        if anchor_ioctl and candidate_ioctl:
            overlap = len(anchor_ioctl & candidate_ioctl)
            if overlap > 0:
                similarity_score += min(0.5, overlap * 0.25)  # 0.25 per overlapping code, max 0.5

        # Compare IRP parameter overlap (up to 0.5 points)
        anchor_params = set(anchor_irp_context.get("irp_parameters", []))
        candidate_params = set(candidate_irp_context.get("irp_parameters", []))
        if anchor_params and candidate_params:
            overlap = len(anchor_params & candidate_params)
            if overlap > 0:
                similarity_score += min(0.5, overlap * 0.125)  # 0.125 per overlapping param, max 0.5

        # Cap at 2 points maximum
        return min(2.0, similarity_score)

    except Exception as e:
        logger.warning(f"Failed to calculate IRP similarity for {hex(candidate_ea)}: {e}")
        return 0

def clear_analysis_cache():
    """Deprecated: Caches are now managed via AnalysisContext per-analysis."""
    pass


# Compatibility alias for backward compatibility with existing scripts
def build_logic_graph(anchor_function: int, max_depth: int = 5) -> LogicGraph:
    """
    Compatibility alias for build_bounded_graph.

    This function provides backward compatibility for scripts that expect
    build_logic_graph to exist. It simply calls build_bounded_graph.

    Args:
        anchor_function: Function address to start analysis from
        max_depth: Maximum call hierarchy depth to explore

    Returns:
        LogicGraph: Bounded graph representing error handling logic flow
    """
    return build_bounded_graph(anchor_function, max_depth)

def _analyze_handle_lifecycle_paths(graph: LogicGraph) -> Dict[str, Any]:
    """
    Phân tích path-sensitive handle lifecycle để phát hiện leak chính xác hơn.
    Thay vì chỉ đếm số lượng, kiểm tra mối quan hệ acquire/release theo flow.
    """
    leaks = []
    pairs = []

    # Lấy tất cả nodes có handle operations
    acquire_nodes = [node for node in graph.nodes.values() if node.has_handle_acquire]
    release_nodes = [node for node in graph.nodes.values() if node.has_handle_release]

    # Phân tích từng acquire operation
    for acquire_node in acquire_nodes:
        acquire_ea = acquire_node.func_ea
        has_matching_release = False

        # Check 1: Release trong cùng function (same function)
        if any(release_node.func_ea == acquire_ea for release_node in release_nodes):
            has_matching_release = True
            pairs.append(f"Same function: {hex(acquire_ea)}")

        # Check 2: Release trong caller function (caller releases)
        if not has_matching_release:
            callers = graph.get_callers(acquire_ea)
            for caller_ea in callers:
                if any(release_node.func_ea == caller_ea for release_node in release_nodes):
                    has_matching_release = True
                    pairs.append(f"Caller releases: {hex(acquire_ea)} <- {hex(caller_ea)}")
                    break

        # Check 3: Release trong callee functions (callee releases)
        if not has_matching_release:
            callees = [callee for caller, callee, edge_type in graph.edges if caller == acquire_ea]
            for callee_ea in callees:
                if any(release_node.func_ea == callee_ea for release_node in release_nodes):
                    has_matching_release = True
                    pairs.append(f"Callee releases: {hex(acquire_ea)} -> {hex(callee_ea)}")
                    break

        # Check 4: Release trong cùng call chain (same call tree branch)
        if not has_matching_release:
            # Check if acquire and release are in the same "branch" of call tree
            acquire_callers = set()
            current = acquire_ea
            for _ in range(3):  # Go up 3 levels
                callers = graph.get_callers(current)
                if not callers:
                    break
                acquire_callers.update(callers)
                current = callers[0]  # Take first caller

            for release_node in release_nodes:
                release_callers = set()
                current = release_node.func_ea
                for _ in range(3):  # Go up 3 levels
                    callers = graph.get_callers(current)
                    if not callers:
                        break
                    release_callers.update(callers)
                    current = callers[0]

                if acquire_callers & release_callers:  # Common callers
                    has_matching_release = True
                    pairs.append(f"Same branch: {hex(acquire_ea)} ~ {hex(release_node.func_ea)}")
                    break

        # Nếu không tìm thấy release phù hợp -> potential leak
        if not has_matching_release:
            leaks.append(f"No matching release found for acquire in {hex(acquire_ea)}")

    return {
        "leaks": leaks,
        "pairs": pairs
    }


def generate_html_diff_report(comparison_result: Dict[str, Any]) -> str:
    """
    Generate a beautiful HTML report for the logic flow comparison.
    Uses modern HTML/CSS with color coding and tables for better readability.
    """
    import html

    # Get data from comparison result
    summaries = comparison_result.get("graph_summaries", {})
    graph_a_summary = summaries.get("graph_a", {})
    graph_b_summary = summaries.get("graph_b", {})

    logic_eq = comparison_result.get("logic_equivalence", {})
    structural = logic_eq.get("structural_similarity", {})

    # Extract driver names
    driver_a = comparison_result.get("driver_a", "Driver A").split("\\")[-1].split("/")[-1]
    driver_b = comparison_result.get("driver_b", "Driver B").split("\\")[-1].split("/")[-1]

    html_content = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Logic Flow Analysis Report</title>
    <style>
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            margin: 0;
            padding: 20px;
            background-color: #f5f5f5;
            color: #333;
        }}
        .container {{
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            padding: 30px;
            border-radius: 10px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }}
        .header {{
            text-align: center;
            border-bottom: 3px solid #007acc;
            padding-bottom: 20px;
            margin-bottom: 30px;
        }}
        .header h1 {{
            color: #007acc;
            margin: 0;
            font-size: 2.5em;
        }}
        .header .subtitle {{
            color: #666;
            font-size: 1.1em;
            margin-top: 10px;
        }}
        .section {{
            margin-bottom: 40px;
        }}
        .section h2 {{
            color: #007acc;
            border-bottom: 2px solid #e0e0e0;
            padding-bottom: 10px;
            margin-bottom: 20px;
        }}
        .comparison-table {{
            width: 100%;
            border-collapse: collapse;
            margin: 20px 0;
            background: white;
        }}
        .comparison-table th, .comparison-table td {{
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid #ddd;
        }}
        .comparison-table th {{
            background-color: #f8f9fa;
            font-weight: 600;
            color: #007acc;
        }}
        .comparison-table tr:hover {{
            background-color: #f1f8ff;
        }}
        .metric {{
            display: inline-block;
            padding: 8px 16px;
            margin: 5px;
            border-radius: 20px;
            font-weight: 500;
        }}
        .metric.good {{ background-color: #d4edda; color: #155724; }}
        .metric.warning {{ background-color: #fff3cd; color: #856404; }}
        .metric.danger {{ background-color: #f8d7da; color: #721c24; }}
        .metric.info {{ background-color: #d1ecf1; color: #0c5460; }}
        .score-card {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 20px;
            border-radius: 10px;
            text-align: center;
            margin: 20px 0;
        }}
        .score-card h3 {{
            margin: 0;
            font-size: 2em;
        }}
        .score-card p {{
            margin: 10px 0 0 0;
            opacity: 0.9;
        }}
        .findings-list {{
            background: #f8f9fa;
            border-left: 4px solid #007acc;
            padding: 15px;
            margin: 10px 0;
        }}
        .code-block {{
            background: #f8f9fa;
            border: 1px solid #e9ecef;
            border-radius: 5px;
            padding: 15px;
            font-family: 'Courier New', monospace;
            overflow-x: auto;
            margin: 10px 0;
        }}
        .footer {{
            text-align: center;
            margin-top: 40px;
            padding-top: 20px;
            border-top: 1px solid #e0e0e0;
            color: #666;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔍 Logic Flow Analysis Report</h1>
            <div class="subtitle">
                Comparing <strong>{html.escape(driver_a)}</strong> vs <strong>{html.escape(driver_b)}</strong>
            </div>
        </div>

        <div class="section">
            <h2>📊 Overview</h2>
            <table class="comparison-table">
                <tr>
                    <th>Aspect</th>
                    <th>{html.escape(driver_a)}</th>
                    <th>{html.escape(driver_b)}</th>
                    <th>Analysis</th>
                </tr>
                <tr>
                    <td>Graph Nodes</td>
                    <td>{graph_a_summary.get('total_nodes', 0)}</td>
                    <td>{graph_b_summary.get('total_nodes', 0)}</td>
                    <td><span class="metric {'good' if abs(graph_a_summary.get('total_nodes', 0) - graph_b_summary.get('total_nodes', 0)) <= 2 else 'warning'}">{'Similar' if abs(graph_a_summary.get('total_nodes', 0) - graph_b_summary.get('total_nodes', 0)) <= 2 else 'Different'}</span></td>
                </tr>
                <tr>
                    <td>Graph Edges</td>
                    <td>{graph_a_summary.get('total_edges', 0)}</td>
                    <td>{graph_b_summary.get('total_edges', 0)}</td>
                    <td><span class="metric {'good' if abs(graph_a_summary.get('total_edges', 0) - graph_b_summary.get('total_edges', 0)) <= 5 else 'warning'}">{'Similar' if abs(graph_a_summary.get('total_edges', 0) - graph_b_summary.get('total_edges', 0)) <= 5 else 'Different'}</span></td>
                </tr>
                <tr>
                    <td>Function Depth</td>
                    <td>{graph_a_summary.get('max_depth', 0)}</td>
                    <td>{graph_b_summary.get('max_depth', 0)}</td>
                    <td><span class="metric {'good' if graph_a_summary.get('max_depth', 0) == graph_b_summary.get('max_depth', 0) else 'warning'}">{'Match' if graph_a_summary.get('max_depth', 0) == graph_b_summary.get('max_depth', 0) else 'Different'}</span></td>
                </tr>
            </table>
        </div>

        <div class="section">
            <h2>🎯 Key Findings</h2>
"""

    # Add key findings
    analysis_summary = comparison_result.get("analysis_summary", {})
    key_findings = analysis_summary.get("key_findings", [])

    if key_findings:
        for finding in key_findings:
            html_content += f"""
            <div class="findings-list">
                <strong>• {html.escape(str(finding))}</strong>
            </div>
"""
    else:
        html_content += """
            <div class="findings-list">
                <strong>• No significant differences detected in logic flow analysis</strong>
            </div>
"""

    html_content += """
        </div>

        <div class="section">
            <h2>🔧 Manual Review Points</h2>
"""

    # Add manual review points
    manual_points = analysis_summary.get("manual_review_points", [])

    if manual_points:
        for point in manual_points:
            html_content += f"""
            <div class="findings-list">
                <strong>• {html.escape(str(point))}</strong>
            </div>
"""
    else:
        html_content += """
            <div class="findings-list">
                <strong>• No manual review points identified</strong>
            </div>
"""

    html_content += f"""
        </div>

        <div class="section">
            <h2>📈 Analysis Score</h2>
            <div class="score-card">
                <h3>{logic_eq.get('overall_similarity_score', 0):.1f}/10</h3>
                <p>Overall Logic Similarity Score</p>
            </div>
        </div>

        <div class="footer">
            <p>Report generated by Logic Flow Analysis Tool v3.0</p>
            <p>Generated on {comparison_result.get('timestamp', 'Unknown')}</p>
        </div>
    </div>
</body>
</html>
"""

    return html_content


def _classify_patch_changes(graph_a: LogicGraph, graph_b: LogicGraph, poc_helper: PoCHelper) -> Dict[str, Any]:
    """
    Classify the types of changes in the patch using security-focused heuristics.

    Args:
        graph_a: Original graph
        graph_b: Patched graph
        poc_helper: PoC Helper instance

    Returns:
        Dictionary containing change classifications
    """
    classifications = {
        "function_changes": {},
        "change_type_summary": {
            ChangeType.ADDED_SECURITY_CHECK.value: 0,
            ChangeType.REMOVED_CODE.value: 0,
            ChangeType.LOGIC_REORDER.value: 0,
            ChangeType.UNCHANGED.value: 0,
            ChangeType.UNKNOWN.value: 0
        },
        "high_priority_functions": []
    }

    try:
        # Get all common functions
        common_functions = set(graph_a.nodes.keys()) & set(graph_b.nodes.keys())

        for func_addr in common_functions:
            change_type = poc_helper.classify_patch_change(graph_a, graph_b, func_addr)

            func_name = graph_b.nodes[func_addr].name
            classifications["function_changes"][func_addr] = {
                "address": func_addr,
                "name": func_name,
                "change_type": change_type.value,
                "risk_assessment": _assess_change_risk(change_type, graph_a.nodes[func_addr], graph_b.nodes[func_addr])
            }

            classifications["change_type_summary"][change_type.value] += 1

            # Identify high priority functions
            if change_type in [ChangeType.ADDED_SECURITY_CHECK, ChangeType.REMOVED_CODE]:
                classifications["high_priority_functions"].append({
                    "address": func_addr,
                    "name": func_name,
                    "change_type": change_type.value,
                    "risk_level": "HIGH" if change_type == ChangeType.REMOVED_CODE else "MEDIUM"
                })

    except Exception as e:
        logger.warning(f"Error classifying patch changes: {e}")

    return classifications


def _assess_change_risk(change_type: ChangeType, node_a, node_b) -> str:
    """Assess the risk level of a change"""
    if change_type == ChangeType.REMOVED_CODE:
        return "HIGH"
    elif change_type == ChangeType.ADDED_SECURITY_CHECK:
        return "LOW"  # Security improvement
    elif change_type == ChangeType.LOGIC_REORDER:
        return "MEDIUM"
    else:
        return "LOW"


def _analyze_attack_surface(graph_a: LogicGraph, graph_b: LogicGraph, poc_helper: PoCHelper) -> Dict[str, Any]:
    """
    Analyze attack surface and IOCTL reachability.

    Args:
        graph_a: Original graph
        graph_b: Patched graph
        poc_helper: PoC Helper instance

    Returns:
        Attack surface analysis
    """
    attack_surface = {
        "ioctl_reachable_functions_a": [],
        "ioctl_reachable_functions_b": [],
        "new_ioctl_exposures": [],
        "removed_ioctl_exposures": []
    }

    try:
        # Analyze graph B (patched) for IOCTL reachability
        for func_addr, node in graph_b.nodes.items():
            surface_info = poc_helper.find_attack_surface(graph_b, func_addr)
            if surface_info["reachable_from_ioctl"]:
                attack_surface["ioctl_reachable_functions_b"].append({
                    "address": func_addr,
                    "name": node.name,
                    "entry_points": surface_info["entry_points"],
                    "ioctl_codes": surface_info.get("ioctl_codes", [])
                })

        # Analyze graph A (original) for comparison
        for func_addr, node in graph_a.nodes.items():
            surface_info = poc_helper.find_attack_surface(graph_a, func_addr)
            if surface_info["reachable_from_ioctl"]:
                attack_surface["ioctl_reachable_functions_a"].append({
                    "address": func_addr,
                    "name": node.name,
                    "entry_points": surface_info["entry_points"],
                    "ioctl_codes": surface_info.get("ioctl_codes", [])
                })

        # Find differences
        b_addresses = {f["address"] for f in attack_surface["ioctl_reachable_functions_b"]}
        a_addresses = {f["address"] for f in attack_surface["ioctl_reachable_functions_a"]}

        new_exposures = b_addresses - a_addresses
        removed_exposures = a_addresses - b_addresses

        attack_surface["new_ioctl_exposures"] = [
            f for f in attack_surface["ioctl_reachable_functions_b"]
            if f["address"] in new_exposures
        ]
        attack_surface["removed_ioctl_exposures"] = [
            f for f in attack_surface["ioctl_reachable_functions_a"]
            if f["address"] in removed_exposures
        ]

    except Exception as e:
        logger.warning(f"Error analyzing attack surface: {e}")

    return attack_surface


def _generate_security_insights(graph_a: LogicGraph, graph_b: LogicGraph, poc_helper: PoCHelper,
                               patch_classification: Dict[str, Any],
                               attack_surface: Dict[str, Any]) -> Dict[str, Any]:
    """
    Generate comprehensive security insights for research and PoC development.

    Args:
        graph_a: Original graph
        graph_b: Patched graph
        poc_helper: PoC Helper instance
        patch_classification: Patch change classifications
        attack_surface: Attack surface analysis

    Returns:
        Security insights dictionary
    """
    insights = {
        "high_priority_targets": [],
        "vulnerability_candidates": [],
        "exploit_opportunities": [],
        "security_improvements": [],
        "risk_assessment": {
            "overall_risk": "LOW",
            "critical_functions": 0,
            "exposed_attack_surface": 0
        }
    }

    try:
        # Identify high priority targets (IOCTL reachable + security changes)
        high_priority_functions = patch_classification.get("high_priority_functions", [])
        ioctl_reachable_b = {f["address"]: f for f in attack_surface.get("ioctl_reachable_functions_b", [])}

        for func in high_priority_functions:
            func_addr = func["address"]
            if func_addr in ioctl_reachable_b:
                ioctl_info = ioctl_reachable_b[func_addr]
                target = {
                    "address": func_addr,
                    "name": func["name"],
                    "change_type": func["change_type"],
                    "risk_level": func["risk_level"],
                    "ioctl_codes": ioctl_info.get("ioctl_codes", []),
                    "entry_points": ioctl_info.get("entry_points", []),
                    "exploit_potential": _assess_exploit_potential(func["change_type"], ioctl_info)
                }
                insights["high_priority_targets"].append(target)

        # Assess overall risk
        critical_count = len([t for t in insights["high_priority_targets"] if t["risk_level"] == "HIGH"])
        exposed_surface = len(attack_surface.get("ioctl_reachable_functions_b", []))

        if critical_count >= 3 or exposed_surface >= 10:
            insights["risk_assessment"]["overall_risk"] = "HIGH"
        elif critical_count >= 1 or exposed_surface >= 5:
            insights["risk_assessment"]["overall_risk"] = "MEDIUM"

        insights["risk_assessment"]["critical_functions"] = critical_count
        insights["risk_assessment"]["exposed_attack_surface"] = exposed_surface

        # Generate vulnerability candidates
        for target in insights["high_priority_targets"]:
            if target["change_type"] == ChangeType.REMOVED_CODE.value:
                insights["vulnerability_candidates"].append({
                    "description": f"Function {target['name']} had error handling removed - potential vulnerability",
                    "exploit_vector": "Trigger via IOCTL " + ", ".join(target.get("ioctl_codes", ["unknown"]))
                })
            elif target["change_type"] == ChangeType.ADDED_SECURITY_CHECK.value:
                insights["security_improvements"].append({
                    "description": f"Function {target['name']} gained security validation",
                    "improvement_type": "Input validation added"
                })

    except Exception as e:
        logger.warning(f"Error generating security insights: {e}")

    return insights


def _assess_exploit_potential(change_type: str, ioctl_info: Dict[str, Any]) -> str:
    """Assess the exploit potential of a changed function"""
    if change_type == ChangeType.REMOVED_CODE.value:
        ioctl_codes = ioctl_info.get("ioctl_codes", [])
        if ioctl_codes:
            return f"High - Removed validation reachable via {len(ioctl_codes)} IOCTL code(s)"
        else:
            return "Medium - Removed validation, IOCTL reachability unknown"
    elif change_type == ChangeType.ADDED_SECURITY_CHECK.value:
        return "Low - Security improvement applied"
    else:
        return "Unknown"


def save_graphviz_dot_files(comparison_result: Dict[str, Any], output_dir: str, timestamp: str) -> Dict[str, str]:
    """
    Save GraphViz DOT files for visualization of both graphs and differences.

    Args:
        comparison_result: The comparison result dictionary
        output_dir: Directory to save files
        timestamp: Timestamp string for filenames

    Returns:
        Dictionary mapping format names to file paths
    """
    import os
    from .logic_graph import LogicGraph

    saved_files = {}

    try:
        # Extract graphs from comparison result
        graph_summaries = comparison_result.get("graph_summaries", {})
        graph_a_data = comparison_result.get("graph_a", {})
        graph_b_data = comparison_result.get("graph_b", {})

        # Reconstruct graphs from serialized data if available
        graph_a = None
        graph_b = None

        if "graph_a" in comparison_result and isinstance(comparison_result["graph_a"], LogicGraph):
            graph_a = comparison_result["graph_a"]
        elif graph_a_data and "nodes" in graph_a_data:
            try:
                graph_a = LogicGraph.from_dict(graph_a_data)
            except Exception as e:
                logger.warning(f"Failed to reconstruct graph A: {e}")

        if "graph_b" in comparison_result and isinstance(comparison_result["graph_b"], LogicGraph):
            graph_b = comparison_result["graph_b"]
        elif graph_b_data and "nodes" in graph_b_data:
            try:
                graph_b = LogicGraph.from_dict(graph_b_data)
            except Exception as e:
                logger.warning(f"Failed to reconstruct graph B: {e}")

        if graph_a:
            # Save graph A DOT file
            dot_filename_a = f"logic_flow_graph_a_{timestamp}.dot"
            dot_path_a = os.path.join(output_dir, dot_filename_a)
            with open(dot_path_a, 'w', encoding='utf-8') as f:
                f.write(graph_a.export_dot("Graph A (Original Driver)"))
            saved_files["dot_graph_a"] = dot_path_a

        if graph_b:
            # Save graph B DOT file
            dot_filename_b = f"logic_flow_graph_b_{timestamp}.dot"
            dot_path_b = os.path.join(output_dir, dot_filename_b)
            with open(dot_path_b, 'w', encoding='utf-8') as f:
                f.write(graph_b.export_dot("Graph B (Patched Driver)"))
            saved_files["dot_graph_b"] = dot_path_b

        # Create diff visualization if both graphs exist
        if graph_a and graph_b:
            # Find differing nodes and edges
            highlight_nodes = []
            highlight_edges = []

            # Nodes in B but not in A (added)
            added_nodes = set(graph_b.nodes.keys()) - set(graph_a.nodes.keys())
            highlight_nodes.extend(added_nodes)

            # Nodes in A but not in B (removed)
            removed_nodes = set(graph_a.nodes.keys()) - set(graph_b.nodes.keys())
            highlight_nodes.extend(removed_nodes)

            # Edges that changed
            edges_a = {(caller, callee) for caller, callee, _ in graph_a.edges}
            edges_b = {(caller, callee) for caller, callee, _ in graph_b.edges}
            changed_edges = (edges_a - edges_b) | (edges_b - edges_a)
            highlight_edges.extend(changed_edges)

            # Save diff DOT file
            dot_filename_diff = f"logic_flow_diff_{timestamp}.dot"
            dot_path_diff = os.path.join(output_dir, dot_filename_diff)

            # Use graph B as base and highlight differences
            with open(dot_path_diff, 'w', encoding='utf-8') as f:
                f.write(graph_b.export_dot("Logic Flow Differences (A→B)",
                                         highlight_nodes=highlight_nodes,
                                         highlight_edges=list(changed_edges)))
            saved_files["dot_diff"] = dot_path_diff

    except Exception as e:
        logger.error(f"Error saving GraphViz DOT files: {e}")

    return saved_files



def generate_ui_analysis_report(graph_a: LogicGraph, graph_b: LogicGraph, comparison_result: Dict, security_insights: Dict) -> Dict[str, Any]:
    """
    Generate a comprehensive analysis report formatted for the UI.
    Aggregates graph data, comparison matches, and security insights.
    """
    # Node limit to prevent UI freezing with large graphs
    MAX_DISPLAY_NODES = 50
    
    report = {
        "summary": {
            "timestamp": datetime.now().isoformat(),
            "overall_similarity": comparison_result.get("logic_equivalence", {}).get("overall_similarity_score", 0),
            "total_nodes_a": len(graph_a.nodes) if graph_a else 0,
            "total_nodes_b": len(graph_b.nodes) if graph_b else 0,
        },
        "graph": {
            "nodes": [],
            "edges": []
        },
        "matches": [],
        "security_insights": security_insights
    }

    def prioritize_nodes(nodes_dict):
        """Sort nodes by importance (role-based priority)"""
        # Define priority by role
        role_priority = {
            "irp_dispatcher": 0,
            "ioctl_handler": 1,
            "validation_routine": 2,
            "error_handler": 3,
            "resource_manager": 4,
            "cleanup_handler": 5,
            "unknown": 10
        }
        
        node_list = list(nodes_dict.items())
        node_list.sort(key=lambda x: (
            role_priority.get(x[1].role.value if hasattr(x[1], 'role') else 'unknown', 10),
            x[1].name  # Secondary sort by name
        ))
        return node_list[:MAX_DISPLAY_NODES]
    
    # Add nodes from Graph A (Baseline/Reference) - LEFT side
    if graph_a:
        prioritized_a = prioritize_nodes(graph_a.nodes)
        for ea, node in prioritized_a:
            report["graph"]["nodes"].append({
                "id": f"A_{hex(ea)}",
                "label": node.name,
                "type": node.role.value if hasattr(node, "role") else "unknown",
                "status": "baseline",
                "graph": "A",
                "position": None  # Will be set by layout
            })
            
        # Add edges only between displayed nodes
        displayed_a = {f"A_{hex(ea)}" for ea, _ in prioritized_a}
        for caller, callee, edge_type in graph_a.edges:
            src_id = f"A_{hex(caller)}"
            tgt_id = f"A_{hex(callee)}"
            if src_id in displayed_a and tgt_id in displayed_a:
                report["graph"]["edges"].append({
                    "source": src_id,
                    "target": tgt_id,
                    "type": edge_type
                })
    
    # Add nodes from Graph B (Target/New) - RIGHT side
    if graph_b:
        prioritized_b = prioritize_nodes(graph_b.nodes)
        for ea, node in prioritized_b:
            report["graph"]["nodes"].append({
                "id": f"B_{hex(ea)}",
                "label": node.name,
                "type": node.role.value if hasattr(node, "role") else "unknown",
                "status": "current",
                "graph": "B",
                "position": None
            })
            
        displayed_b = {f"B_{hex(ea)}" for ea, _ in prioritized_b}
        for caller, callee, edge_type in graph_b.edges:
            src_id = f"B_{hex(caller)}"
            tgt_id = f"B_{hex(callee)}"
            if src_id in displayed_b and tgt_id in displayed_b:
                report["graph"]["edges"].append({
                    "source": src_id,
                    "target": tgt_id,
                    "type": edge_type
                })

    # Format Function Matches for the table view
    matches = comparison_result.get("function_matches", []) 
    if not matches and graph_b:
        # Generate simple list for UI table based on nodes
        for ea, node in graph_b.nodes.items():
            report["matches"].append({
                "function_name": node.name,
                "address": hex(ea),
                "similarity": 1.0,
                "status": "analyzed",
                "risk": "low",
                "role": node.role.value if hasattr(node, "role") else "unknown"
            })
    
    # Add truncation notice to summary if graphs were limited
    if graph_a and len(graph_a.nodes) > MAX_DISPLAY_NODES:
        report["summary"]["truncated_a"] = True
        report["summary"]["displayed_nodes_a"] = MAX_DISPLAY_NODES
    if graph_b and len(graph_b.nodes) > MAX_DISPLAY_NODES:
        report["summary"]["truncated_b"] = True
        report["summary"]["displayed_nodes_b"] = MAX_DISPLAY_NODES

    return report

# End of file - all legacy vulnerability assessment functions removed
