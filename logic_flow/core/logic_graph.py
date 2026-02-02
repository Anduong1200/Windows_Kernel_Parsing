"""
Logic Graph Module for Windows Kernel Driver Analysis

This module provides data structures and algorithms for modeling bounded call graphs
representing error handling and resource management logic flows in kernel drivers.
"""

import logging
from dataclasses import dataclass, field
from typing import Dict, List, Set, Optional, Tuple, Any
from enum import Enum

logger = logging.getLogger(__name__)

# Import IDA modules conditionally
try:
    import ida_xref
except ImportError:
    # For standalone usage without IDA
    pass

# Import IDA provider abstraction
from .ida_provider import IDAProvider
from ..utils.config import ConfigManager

# Global config manager instance
_config_manager = ConfigManager()

# Configuration constants (using config values where available)
MAX_GRAPH_NODES = _config_manager.get_max_graph_nodes()  # Maximum number of nodes in logic graph

class FunctionRole(Enum):
    """Semantic roles that functions can play in error handling logic"""
    ERROR_HANDLER = "error_handler"
    CLEANUP_HANDLER = "cleanup_handler"
    FAILFAST_GUARD = "failfast_guard"
    RESOURCE_MANAGER = "resource_manager"
    VALIDATION_ROUTINE = "validation_routine"
    IRP_DISPATCHER = "irp_dispatcher"
    HANDLE_MANAGER = "handle_manager"
    UNKNOWN = "unknown"

@dataclass
class FunctionNode:
    """Represents a function in the logic graph"""
    ea: int
    name: str = ""
    role: FunctionRole = FunctionRole.UNKNOWN
    is_error_handler: bool = False
    has_failfast: bool = False
    has_complete_request: bool = False
    has_handle_acquire: bool = False
    has_handle_validation: bool = False
    has_handle_release: bool = False
    error_codes_written: Set[str] = field(default_factory=set)  # NTSTATUS values like STATUS_ACCESS_VIOLATION
    irp_context: Optional[Dict] = None
    metadata: Dict = field(default_factory=dict)
    
    # Split Architecture Fields (Protocol V1.0)
    is_import: bool = False
    is_export: bool = False
    demangled_name: Optional[str] = None

@dataclass
class LogicGraph:
    """Bounded call graph representing error handling logic flow"""
    anchor_function: int
    nodes: Dict[int, FunctionNode] = field(default_factory=dict)
    edges: List[Tuple[int, int, str]] = field(default_factory=list)  # (caller, callee, edge_type)
    max_depth: int = 5
    bounds: Set[str] = field(default_factory=set)  # Semantic boundaries

    # Optimized string matching sets for O(1) lookup - significant performance improvement
    _FAILFAST_SYMBOLS = frozenset([
        "RtlFailFast", "KeBugCheckEx", "KeBugCheck", "_CxxThrowException", "ExRaiseStatus"
    ])

    _CLEANUP_SYMBOLS = frozenset([
        "ExFreePool", "ExFreePoolWithTag", "ObDereferenceObject", "ZwClose",
        "IoFreeIrp", "KeSetEvent", "ExReleaseFastMutex", "IoDeleteDevice",
        "ExFreePoolWithQuotaTag", "MmFreeContiguousMemory", "RtlFreeUnicodeString"
    ])

    _DISPATCHER_SYMBOLS = frozenset([
        "IoGetCurrentIrpStackLocation", "IoGetNextIrpStackLocation",
        "IRP_MJ_", "irp", "IRP", "IoCallDriver"
    ])

    _HANDLE_SYMBOLS = frozenset([
        "ZwCreate", "ZwOpen", "ObReferenceObjectByHandle",
        "IoGetDeviceObjectPointer", "ZwClose", "ObDereferenceObject"
    ])

    _VALIDATION_SYMBOLS = frozenset([
        "ProbeForRead", "ProbeForWrite", "SeAccessCheck", "RtlEqualSid"
    ])

    _HANDLE_ACQUIRE_SYMBOLS = frozenset([
        "ZwCreateFile", "ZwOpenFile", "ZwCreateKey", "ZwOpenKey",
        "ObReferenceObjectByHandle", "IoGetDeviceObjectPointer"
    ])

    _HANDLE_RELEASE_SYMBOLS = frozenset([
        "ZwClose", "ObDereferenceObject"
    ])

    _HANDLE_VALIDATE_SYMBOLS = frozenset([
        "ObReferenceObjectByPointer", "ZwQueryObject",
        "SeAccessCheck", "ZwWaitForSingleObject"
    ])

    def add_node(self, func_ea: int, node: FunctionNode):
        """Add a function node to the graph"""
        self.nodes[func_ea] = node

    def add_edge(self, caller_ea: int, callee_ea: int, edge_type: str = "calls"):
        """Add a call relationship edge"""
        if caller_ea in self.nodes and callee_ea in self.nodes:
            # Check for duplicates
            edge = (caller_ea, callee_ea, edge_type)
            if edge not in self.edges:
                self.edges.append(edge)

    def get_node_by_role(self, role: FunctionRole) -> List[FunctionNode]:
        """Get all nodes with a specific semantic role"""
        return [node for node in self.nodes.values() if node.role == role]

    def get_callers(self, func_ea: int) -> List[int]:
        """Get all callers of a function in this graph"""
        return [caller for caller, callee, _ in self.edges if callee == func_ea]

    def get_callees(self, func_ea: int) -> List[int]:
        """Get all callees of a function in this graph"""
        return [callee for caller, callee, _ in self.edges if caller == func_ea]

    def get_failfast_position(self) -> Optional[int]:
        """Find the position of FailFast in the logic flow"""
        failfast_nodes = self.get_node_by_role(FunctionRole.FAILFAST_GUARD)
        return failfast_nodes[0].ea if failfast_nodes else None

    def get_error_handlers(self) -> List[FunctionNode]:
        """Get all error handler nodes"""
        return [node for node in self.nodes.values() if node.is_error_handler]

    def get_path_to_anchor(self, target_ea: int) -> List[int]:
        """Find path from target function back to anchor"""
        # Simple BFS to find path to anchor
        visited = set()
        queue = [(target_ea, [target_ea])]

        while queue:
            current, path = queue.pop(0)
            if current == self.anchor_function:
                return path

            if current in visited:
                continue
            visited.add(current)

            for caller in self.get_callers(current):
                if caller not in visited:
                    queue.append((caller, path + [caller]))

        return []

    def get_graph_summary(self) -> Dict[str, Any]:
        """Get summary statistics of the graph"""
        role_counts = {}
        for node in self.nodes.values():
            role_counts[node.role.value] = role_counts.get(node.role.value, 0) + 1

        return {
            "anchor_function": hex(self.anchor_function),
            "total_nodes": len(self.nodes),
            "total_edges": len(self.edges),
            "max_depth": self.max_depth,
            "role_distribution": role_counts,
            "boundary_functions": list(self.bounds),
            "error_handlers": len(self.get_error_handlers()),
            "failfast_nodes": sum(1 for n in self.nodes.values() if n.has_failfast),
            "irp_dispatchers": sum(1 for n in self.nodes.values() if n.role == FunctionRole.IRP_DISPATCHER),
            "handle_acquire_nodes": sum(1 for n in self.nodes.values() if n.has_handle_acquire),
            "handle_validation_nodes": sum(1 for n in self.nodes.values() if n.has_handle_validation),
            "handle_release_nodes": sum(1 for n in self.nodes.values() if n.has_handle_release)
        }

    def get_error_paths(self) -> List[List[int]]:
        """
        Find all paths from anchor function to error handlers or FailFast calls.
        Returns list of paths, where each path is a list of function addresses.
        """
        error_paths = []
        error_nodes = []

        # Collect all error-related nodes
        for node in self.nodes.values():
            if node.has_failfast or node.is_error_handler or node.has_complete_request:
                error_nodes.append(node.ea)

        # Find paths from anchor to each error node
        for error_ea in error_nodes:
            path = self.get_path_to_anchor(error_ea)
            if path:
                error_paths.append(path)

        return error_paths

    def get_failfast_candidates(self) -> List[FunctionNode]:
        """
        Get all functions that contain FailFast calls or are likely FailFast guards.
        """
        candidates = []
        for node in self.nodes.values():
            if node.has_failfast or node.role == FunctionRole.FAILFAST_GUARD:
                candidates.append(node)
        return candidates

    def find_entry_points(self, target_node: int) -> List[Dict[str, Any]]:
        """
        Perform reverse BFS to find entry points (IOCTL handlers, dispatchers) that can reach target node.
        Enhanced with better IOCTL code extraction and attack surface analysis.

        Args:
            target_node: Target function address to find entry points for

        Returns:
            List of entry points with reachability information
        """
        entry_points = []
        visited = set()
        queue = [(target_node, [])]  # (current_node, path)
        path_lengths = {}  # Track shortest path to each node

        while queue:
            current, path = queue.pop(0)
            if current in visited:
                continue
            visited.add(current)

            current_path = path + [current]
            current_node = self.nodes.get(current)

            # Check if current node is an entry point
            if current_node and self._is_entry_point(current_node):
                # Extract IOCTL codes with enhanced analysis
                ioctl_codes = self._extract_ioctl_codes(current)

                # Calculate attack surface metrics
                attack_surface_info = self._analyze_attack_surface(current, current_path)

                entry_points.append({
                    "address": current,
                    "name": current_node.name,
                    "type": current_node.role.value,
                    "path_length": len(current_path),
                    "path": current_path,
                    "ioctl_codes": ioctl_codes,
                    "attack_surface": attack_surface_info,
                    "security_relevance": self._assess_security_relevance(current_node, ioctl_codes)
                })

            # Continue reverse traversal with path length optimization
            for caller in self.get_callers(current):
                if caller not in visited:
                    # Only explore if this path is shorter than previously found
                    if caller not in path_lengths or len(current_path) + 1 < path_lengths[caller]:
                        path_lengths[caller] = len(current_path) + 1
                        queue.append((caller, current_path))

        # Sort by path length (shortest paths first - more direct reachability)
        entry_points.sort(key=lambda x: x["path_length"])

        return entry_points

    def _is_entry_point(self, node: FunctionNode) -> bool:
        """
        Check if a node represents an entry point with enhanced detection.

        Entry points are functions that can be directly triggered from user-mode
        through IOCTL calls, device I/O, or other kernel interfaces.
        """
        entry_point_roles = {
            FunctionRole.IRP_DISPATCHER,
            FunctionRole.HANDLE_MANAGER  # Handle managers can be entry points for handle operations
        }

        # Direct role match
        if node.role in entry_point_roles:
            return True

        # Enhanced detection based on function characteristics
        func_name = node.name.lower()

        # Check for common IOCTL dispatcher patterns
        ioctl_patterns = [
            "dispatch", "ioctl", "irp_mj_", "device_control",
            "create", "close", "read", "write", "cleanup"
        ]

        if any(pattern in func_name for pattern in ioctl_patterns):
            return True

        # Check for handle acquisition functions (entry points for handle-based attacks)
        if node.has_handle_acquire and not node.has_handle_release:
            return True

        return False

    def _extract_ioctl_codes(self, function_addr: int) -> List[str]:
        """
        Extract IOCTL codes that can reach this function with enhanced analysis.

        This performs static analysis to identify IOCTL codes associated with
        the dispatcher function.
        """
        ioctl_codes = []
        function_node = self.nodes.get(function_addr)

        if not function_node:
            return ["IOCTL_UNKNOWN"]

        try:
            # Get callees to analyze IOCTL handling patterns
            callees = self.get_callees(function_addr)

            # Look for IOCTL code patterns in the function's context
            # This is a simplified implementation - in practice, this would
            # require more sophisticated static analysis

            # Check function name for IOCTL patterns
            func_name = function_node.name.lower()
            if "ioctl" in func_name or "device_control" in func_name:
                ioctl_codes.append("IOCTL_DEVICE_CONTROL")

            # Check for IRP_MJ patterns
            for callee in callees:
                callee_node = self.nodes.get(callee)
                if callee_node:
                    callee_name = callee_node.name.lower()
                    if "irp_mj_" in callee_name:
                        # Extract the major function code
                        mj_code = callee_name.split("irp_mj_")[-1].upper()
                        ioctl_codes.append(f"IRP_MJ_{mj_code}")

            # If no specific codes found, check for generic patterns
            if not ioctl_codes:
                # Look for switch/case patterns that might indicate IOCTL codes
                if len(callees) > 3:  # Multiple branches suggest IOCTL handling
                    ioctl_codes.append("IOCTL_MULTIPLE_CODES")
                else:
                    ioctl_codes.append("IOCTL_UNKNOWN")

        except Exception as e:
            logger.warning(f"Error extracting IOCTL codes for 0x{function_addr:08X}: {e}")
            ioctl_codes = ["IOCTL_ANALYSIS_ERROR"]

        return ioctl_codes

    def _analyze_attack_surface(self, entry_point_addr: int, path: List[int]) -> Dict[str, Any]:
        """
        Analyze the attack surface exposed by this entry point.

        Args:
            entry_point_addr: Address of the entry point function
            path: Path from entry point to target

        Returns:
            Attack surface analysis
        """
        surface_info = {
            "exposure_level": "LOW",
            "input_validation": False,
            "dangerous_operations": [],
            "path_complexity": len(path),
            "security_boundaries": 0
        }

        try:
            entry_node = self.nodes.get(entry_point_addr)
            if not entry_node:
                return surface_info

            # Analyze path for security-relevant operations
            validation_found = False
            dangerous_ops = []

            for addr in path:
                node = self.nodes.get(addr)
                if node:
                    # Check for validation routines
                    if node.role == FunctionRole.VALIDATION_ROUTINE:
                        validation_found = True

                    # Check for dangerous operations
                    if self._is_dangerous_operation(node):
                        dangerous_ops.append(node.name)

                    # Count security boundaries (error handlers, failfast)
                    if node.role in [FunctionRole.ERROR_HANDLER, FunctionRole.FAILFAST_GUARD]:
                        surface_info["security_boundaries"] += 1

            surface_info["input_validation"] = validation_found
            surface_info["dangerous_operations"] = dangerous_ops

            # Assess exposure level
            if len(dangerous_ops) > 0 and not validation_found:
                surface_info["exposure_level"] = "HIGH"
            elif len(dangerous_ops) > 0 or not validation_found:
                surface_info["exposure_level"] = "MEDIUM"

        except Exception as e:
            logger.warning(f"Error analyzing attack surface for 0x{entry_point_addr:08X}: {e}")

        return surface_info

    def _is_dangerous_operation(self, node: FunctionNode) -> bool:
        """Check if a function performs potentially dangerous operations."""
        if not node:
            return False

        func_name = node.name.lower()

        # Memory operations
        dangerous_patterns = [
            "memcpy", "memmove", "memset", "strcpy", "strncpy",
            "exallocatepool", "exfree", "rtlcopy", "rtlmov",
            "zw", "nt"  # Native API calls can be dangerous
        ]

        return any(pattern in func_name for pattern in dangerous_patterns)

    def _assess_security_relevance(self, node: FunctionNode, ioctl_codes: List[str]) -> Dict[str, Any]:
        """
        Assess the security relevance of an entry point.

        Args:
            node: Entry point function node
            ioctl_codes: Associated IOCTL codes

        Returns:
            Security relevance assessment
        """
        relevance = {
            "is_security_critical": False,
            "handles_sensitive_data": False,
            "has_privilege_checks": False,
            "risk_factors": []
        }

        if not node:
            return relevance

        # Check for privilege/security-related patterns
        func_name = node.name.lower()

        security_indicators = [
            "access", "privilege", "security", "admin", "kernel",
            "handle", "token", "process", "thread"
        ]

        if any(indicator in func_name for indicator in security_indicators):
            relevance["is_security_critical"] = True
            relevance["risk_factors"].append("Security-related function name")

        # Check for handle operations (potential for handle spraying/leaks)
        if node.has_handle_acquire or node.has_handle_release:
            relevance["handles_sensitive_data"] = True
            relevance["risk_factors"].append("Handle operations")

        # Check for validation
        if node.role == FunctionRole.VALIDATION_ROUTINE:
            relevance["has_privilege_checks"] = True

        # IOCTL-specific risk assessment
        if "IRP_MJ_DEVICE_CONTROL" in ioctl_codes or "IOCTL_DEVICE_CONTROL" in ioctl_codes:
            relevance["risk_factors"].append("Direct device IOCTL handling")

        return relevance

    def find_similar_logic(self, other_graph: 'LogicGraph') -> Dict[str, Any]:
        """
        Compare this graph with another to find similar logic patterns.
        Implements logic equivalence checking for error handling paths.

        Returns comparison results including structural similarity and role distribution.
        """
        comparison = {
            "structural_similarity": self._compare_structure(other_graph),
            "role_distribution": self._compare_roles(other_graph),
            "error_path_similarity": self._compare_error_paths(other_graph),
            "failfast_alignment": self._compare_failfast_patterns(other_graph),
            "irp_handling_similarity": self._compare_irp_patterns(other_graph),
            "manual_analysis_hints": []
        }

        # Generate analysis hints
        comparison["manual_analysis_hints"] = self._generate_comparison_hints(other_graph, comparison)

        # --- Fix for missing Overall Score in UI ---
        # Calculate weighted overall similarity score (0.0 to 10.0)
        
        # 1. Structural Score (0-1)
        struct_sim = 0.0
        struct = comparison["structural_similarity"]
        if struct["depth_similarity"] and struct["anchor_role_match"]:
             struct_sim = 1.0
        
        # Normalize diffs
        max_nodes = max(struct.get("node_count_diff", 0) + 20, 20) # Avoid div/0
        node_sim = 1.0 - min(abs(struct.get("node_count_diff", 0)) / max_nodes, 1.0)
        struct_sim = (struct_sim + node_sim) / 2
        
        # 2. Role Score (0-1)
        role_diffs = sum(abs(x) for x in comparison["role_distribution"].get("differences", {}).values())
        total_roles = sum(comparison["role_distribution"].get("self_distribution", {}).values()) + 1
        role_sim = 1.0 - min(role_diffs / total_roles, 1.0)
        
        # 3. Error Path Score (0-1)
        error_sim = comparison["error_path_similarity"]
        
        # Weighted Total
        # Structure: 20%, Roles: 30%, Error Paths: 50% (Logic flow focus)
        overall_score = (struct_sim * 0.2 + role_sim * 0.3 + error_sim * 0.5) * 10.0
        
        comparison["overall_similarity_score"] = round(overall_score, 1)

        return comparison

    def _compare_structure(self, other: 'LogicGraph') -> Dict[str, Any]:
        """Compare basic structural properties"""
        self_summary = self.get_graph_summary()
        other_summary = other.get_graph_summary()

        return {
            "node_count_diff": self_summary["total_nodes"] - other_summary["total_nodes"],
            "edge_count_diff": self_summary["total_edges"] - other_summary["total_edges"],
            "depth_similarity": self.max_depth == other.max_depth,
            "anchor_role_match": (
                self.nodes.get(self.anchor_function) and other.nodes.get(other.anchor_function) and
                self.nodes[self.anchor_function].role == other.nodes[other.anchor_function].role
            )
        }

    def _compare_roles(self, other: 'LogicGraph') -> Dict[str, Any]:
        """Compare function role distributions"""
        self_roles = self.get_graph_summary()["role_distribution"]
        other_roles = other.get_graph_summary()["role_distribution"]

        differences = {}
        for role in set(self_roles.keys()) | set(other_roles.keys()):
            self_count = self_roles.get(role, 0)
            other_count = other_roles.get(role, 0)
            if self_count != other_count:
                differences[role] = other_count - self_count

        return {
            "self_distribution": self_roles,
            "other_distribution": other_roles,
            "differences": differences
        }

    def _compare_error_paths(self, other: 'LogicGraph') -> float:
        """Compare error handling path structures"""
        self_paths = self.get_error_paths()
        other_paths = other.get_error_paths()

        if not self_paths and not other_paths:
            return 1.0  # Both have no error paths
        if not self_paths or not other_paths:
            return 0.0  # One has error paths, other doesn't

        # Simple similarity based on path lengths
        self_lengths = [len(path) for path in self_paths]
        other_lengths = [len(path) for path in other_paths]

        avg_self = sum(self_lengths) / len(self_lengths) if self_lengths else 0
        avg_other = sum(other_lengths) / len(other_lengths) if other_lengths else 0

        # Similarity score based on average path length difference
        max_diff = max(avg_self, avg_other) or 1
        diff = abs(avg_self - avg_other)
        return 1.0 - (diff / max_diff)

    def _compare_failfast_patterns(self, other: 'LogicGraph') -> Dict[str, Any]:
        """Compare FailFast usage patterns"""
        self_failfast = self.get_failfast_candidates()
        other_failfast = other.get_failfast_candidates()

        return {
            "self_failfast_count": len(self_failfast),
            "other_failfast_count": len(other_failfast),
            "position_alignment": self._compare_failfast_positions(other, other_failfast)
        }

    def _compare_irp_patterns(self, other: 'LogicGraph') -> float:
        """Compare IRP handling patterns"""
        self_irp = sum(1 for n in self.nodes.values() if n.has_complete_request)
        other_irp = sum(1 for n in other.nodes.values() if n.has_complete_request)

        total_nodes = len(self.nodes) + len(other.nodes)
        if total_nodes == 0:
            return 1.0

        return 1.0 - abs(self_irp - other_irp) / (total_nodes / 2)

    def _compare_failfast_positions(self, other_graph: 'LogicGraph', other_failfast: List[FunctionNode]) -> bool:
        """Check if FailFast positions are structurally similar"""
        self_failfast = self.get_failfast_candidates()
        if not self_failfast or not other_failfast:
            return len(self_failfast) == len(other_failfast)

        # Compare relative depths from anchor
        self_positions = [len(self.get_path_to_anchor(f.ea)) for f in self_failfast]
        other_positions = [len(other_graph.get_path_to_anchor(f.ea)) for f in other_failfast]

        return sorted(self_positions) == sorted(other_positions)

    def _generate_comparison_hints(self, other: 'LogicGraph', comparison: Dict[str, Any]) -> List[str]:
        """Generate manual analysis hints based on comparison results"""
        hints = []

        # Structural differences (use .get() for safety with empty comparisons)
        struct = comparison.get("structural_similarity", {})
        node_diff = struct.get("node_count_diff", 0)
        if node_diff > 5:
            hints.append(f"Large structural difference: {node_diff} more nodes in {'first' if node_diff > 0 else 'second'} graph")

        # Role distribution differences
        roles = comparison.get("role_distribution", {})
        for role, diff in roles.get("differences", {}).items():
            if abs(diff) > 1:
                direction = "more" if diff > 0 else "fewer"
                hints.append(f"Second graph has {abs(diff)} {direction} {role} functions")

        # Error path analysis
        error_sim = comparison.get("error_path_similarity", 1.0)
        if error_sim < 0.5:
            hints.append("Error handling paths are structurally different - manual review required")

        # FailFast analysis
        ff = comparison.get("failfast_alignment", {})
        if ff.get("self_failfast_count", 0) != ff.get("other_failfast_count", 0):
            hints.append(f"FailFast usage differs: {ff.get('self_failfast_count', 0)} vs {ff.get('other_failfast_count', 0)} functions")

        return hints

    def to_json(self) -> str:
        """Serialize the logic graph to JSON format"""
        import json
        return json.dumps(self.to_dict(), indent=2, default=str)

    def to_dict(self) -> Dict[str, Any]:
        """Convert the logic graph to a dictionary for serialization"""
        return {
            "anchor_function": hex(self.anchor_function),
            "max_depth": self.max_depth,
            "bounds": list(self.bounds),
            "summary": self.get_graph_summary(),
            "error_paths": [[hex(addr) for addr in path] for path in self.get_error_paths()],
            "failfast_candidates": [
                {
                    "address": hex(node.ea),
                    "name": node.name,
                    "role": node.role.value,
                    "has_failfast": node.has_failfast
                }
                for node in self.get_failfast_candidates()
            ],
            "nodes": [
                {
                    "address": hex(node.ea),
                    "name": node.name,
                    "role": node.role.value,
                    "is_error_handler": node.is_error_handler,
                    "has_failfast": node.has_failfast,
                    "has_complete_request": node.has_complete_request,
                    "has_handle_acquire": node.has_handle_acquire,
                    "has_handle_validation": node.has_handle_validation,
                    "has_handle_release": node.has_handle_release,
                    "error_codes_written": list(node.error_codes_written),
                    "irp_context": node.irp_context,
                    "metadata": node.metadata
                }
                for node in self.nodes.values()
            ],
            "edges": [
                {
                    "caller": hex(caller),
                    "callee": hex(callee),
                    "edge_type": edge_type
                }
                for caller, callee, edge_type in self.edges
            ]
        }
    
    def to_cytoscape_json(self, diff_status: Dict[int, str] = None) -> Dict[str, Any]:
        """
        Convert the logic graph to Cytoscape.js JSON format for web visualization.
        
        Args:
            diff_status: Optional dict mapping node addresses to diff status:
                        'removed' (red), 'added' (green), 'modified' (orange), 'unchanged' (grey)
        
        Returns:
            Cytoscape.js compatible JSON with nodes and edges
        """
        diff_status = diff_status or {}
        
        # Color mapping for diff visualization
        STATUS_COLORS = {
            'removed': '#ef4444',    # Red
            'added': '#22c55e',      # Green  
            'modified': '#f97316',   # Orange
            'unchanged': '#6b7280',  # Grey
            'anchor': '#3b82f6',     # Blue (anchor function)
        }
        
        ROLE_SHAPES = {
            FunctionRole.ERROR_HANDLER: 'diamond',
            FunctionRole.FAILFAST_GUARD: 'triangle',
            FunctionRole.IRP_DISPATCHER: 'hexagon',
            FunctionRole.VALIDATION_ROUTINE: 'rectangle',
            FunctionRole.RESOURCE_MANAGER: 'ellipse',
            FunctionRole.CLEANUP_HANDLER: 'octagon',
            FunctionRole.UNKNOWN: 'ellipse',
        }
        
        cyto_nodes = []
        cyto_edges = []
        
        for ea, node in self.nodes.items():
            # Determine node color based on diff status
            status = diff_status.get(ea, 'unchanged')
            if ea == self.anchor_function:
                color = STATUS_COLORS['anchor']
                status = 'anchor'
            else:
                color = STATUS_COLORS.get(status, STATUS_COLORS['unchanged'])
            
            shape = ROLE_SHAPES.get(node.role, 'ellipse')
            
            cyto_nodes.append({
                'data': {
                    'id': hex(ea),
                    'label': node.name[:30] + '...' if len(node.name) > 30 else node.name,
                    'fullName': node.name,
                    'address': hex(ea),
                    'role': node.role.value if hasattr(node.role, 'value') else str(node.role),
                    'isErrorHandler': node.is_error_handler,
                    'hasFailfast': node.has_failfast,
                    'diffStatus': status,
                    'color': color,
                    'shape': shape,
                }
            })
        
        for caller, callee, edge_type in self.edges:
            cyto_edges.append({
                'data': {
                    'id': f"{hex(caller)}-{hex(callee)}",
                    'source': hex(caller),
                    'target': hex(callee),
                    'edgeType': edge_type,
                }
            })
        
        return {
            'elements': {
                'nodes': cyto_nodes,
                'edges': cyto_edges
            },
            'metadata': {
                'anchorFunction': hex(self.anchor_function),
                'nodeCount': len(self.nodes),
                'edgeCount': len(self.edges),
                'maxDepth': self.max_depth,
            }
        }

    def build_from_anchor(self, ida_provider: IDAProvider) -> bool:
        """Build the logic graph starting from anchor function using IDA APIs"""
        try:
            visited = set()
            queue = [(self.anchor_function, 0)]  # (function_ea, depth)

            while queue and len(self.nodes) < MAX_GRAPH_NODES:  # Limit graph size
                current_ea, depth = queue.pop(0)

                if current_ea in visited or depth > self.max_depth:
                    continue
                visited.add(current_ea)

                # Analyze and add current function node
                role = self._analyze_function_role(current_ea, ida_provider)
                irp_ctx = self._get_irp_context(current_ea, ida_provider)
                error_codes = self._detect_error_codes(current_ea, ida_provider)

                # Check for error handler characteristics
                is_error_handler = (role in [FunctionRole.ERROR_HANDLER, FunctionRole.FAILFAST_GUARD])
                has_failfast = role == FunctionRole.FAILFAST_GUARD
                has_complete = role in [FunctionRole.ERROR_HANDLER, FunctionRole.RESOURCE_MANAGER]

                # Check for handle operations
                has_handle_acquire = self._has_handle_operation(current_ea, ida_provider, acquire=True)
                has_handle_validation = self._has_handle_operation(current_ea, ida_provider, acquire=False, validate=True)
                has_handle_release = self._has_handle_operation(current_ea, ida_provider, release=True)

                node = FunctionNode(
                    ea=current_ea,
                    name=self._get_function_name(current_ea, ida_provider),
                    role=role,
                    is_error_handler=is_error_handler,
                    has_failfast=has_failfast,
                    has_complete_request=has_complete,
                    has_handle_acquire=has_handle_acquire,
                    has_handle_validation=has_handle_validation,
                    has_handle_release=has_handle_release,
                    error_codes_written=error_codes,
                    irp_context=irp_ctx,
                    metadata={"depth": depth}
                )
                self.add_node(current_ea, node)

                # Traverse callers (upward in call hierarchy)
                callers = self._get_callers(current_ea, ida_provider)
                for caller_ea in callers:
                    if caller_ea not in visited and len(self.nodes) < MAX_GRAPH_NODES:
                        queue.append((caller_ea, depth + 1))
                        self.add_edge(caller_ea, current_ea, "caller")

                # Traverse callees (downward in call hierarchy) - limited
                if depth < 2:  # Only go down 2 levels to keep graph bounded
                    callees = self._get_callees(current_ea, ida_provider)
                    for callee_ea in callees:
                        if callee_ea not in visited and len(self.nodes) < MAX_GRAPH_NODES:
                            queue.append((callee_ea, depth + 1))
                            self.add_edge(current_ea, callee_ea, "callee")

            # Set semantic bounds based on what we found
            if self.get_node_by_role(FunctionRole.IRP_DISPATCHER):
                self.bounds.add("irp_dispatcher")
            if self.get_node_by_role(FunctionRole.ERROR_HANDLER):
                self.bounds.add("error_handling")
            if self.get_node_by_role(FunctionRole.FAILFAST_GUARD):
                self.bounds.add("failfast_protection")

            return True

        except Exception as e:
            logger.error(f"Failed to build logic graph: {e}")
            return False

    def _analyze_function_role(self, func_ea: int, ida_provider: IDAProvider) -> FunctionRole:
        """Analyze the semantic role of a function with robust symbol-independent detection"""
        try:
            f = ida_funcs.get_func(func_ea)
            if not f:
                return FunctionRole.UNKNOWN

            # Initialize detection flags
            analysis_result = {
                "has_failfast": False,
                "has_complete": False,
                "has_cleanup": False,
                "is_dispatcher": False,
                "has_handle_ops": False,
                "has_validation": False,
                "symbol_based_detection": True,
                "pattern_based_detection": False
            }

            # First pass: Symbol-based detection (when symbols are available)
            symbol_based = self._analyze_function_by_symbols(func_ea, ida_funcs, idaapi, analysis_result)

            # Second pass: Pattern-based detection (instruction patterns, xrefs, etc.)
            if not symbol_based:
                analysis_result["symbol_based_detection"] = False
                self._analyze_function_by_patterns(func_ea, ida_funcs, idaapi, analysis_result)
                analysis_result["pattern_based_detection"] = True

            # Determine role based on analysis results
            return self._determine_role_from_analysis(analysis_result)

        except Exception as e:
            # Log error but don't crash
            logger.warning(f"Error analyzing function {hex(func_ea)}: {e}")
            return FunctionRole.UNKNOWN

    def _analyze_function_by_symbols(self, func_ea: int, ida_provider: IDAProvider, analysis_result: Dict) -> bool:
        """Analyze function using symbol names (traditional string matching)"""
        f = ida_funcs.get_func(func_ea)
        if not f:
            return False

        found_symbols = False
        ea = f.start_ea
        while ea < f.end_ea:
            try:
                if idaapi.is_call_insn(ea):
                    for ref in idaapi.CodeRefsFrom(ea, 0):
                        if ref == idaapi.BADADDR:
                            continue

                        func_name = self._get_function_name_at_address(ref, ida_funcs, idaapi)
                        if not func_name or func_name.startswith('sub_'):
                            continue

                        found_symbols = True

                        # Detect patterns by symbol names
                        if self._is_failfast_symbol(func_name):
                            analysis_result["has_failfast"] = True
                        if self._is_complete_symbol(func_name):
                            analysis_result["has_complete"] = True
                        if self._is_cleanup_symbol(func_name):
                            analysis_result["has_cleanup"] = True
                        if self._is_dispatcher_symbol(func_name):
                            analysis_result["is_dispatcher"] = True
                        if self._is_handle_symbol(func_name):
                            analysis_result["has_handle_ops"] = True
                        if self._is_validation_symbol(func_name):
                            analysis_result["has_validation"] = True

            except (AttributeError, IndexError, TypeError) as e:
                logger.debug(f"Error reading byte at {hex(ea)}: {e}")
            ea = idaapi.next_head(ea, f.end_ea)

        # Also check for int 29h pattern (works even without symbols)
        if self._has_int29_pattern(func_ea, ida_funcs, idaapi):
            analysis_result["has_failfast"] = True
            found_symbols = True

        return found_symbols

    def _analyze_function_by_patterns(self, func_ea: int, ida_funcs, idaapi, analysis_result: Dict) -> None:
        """Analyze function using instruction patterns and cross-references (symbol-independent)"""
        f = ida_funcs.get_func(func_ea)
        if not f:
            return

        # Check for FailFast patterns (int 29h, specific instruction sequences)
        if self._has_failfast_patterns(func_ea, ida_funcs, idaapi):
            analysis_result["has_failfast"] = True

        # Check for completion patterns (IRP completion sequences)
        if self._has_completion_patterns(func_ea, ida_funcs, idaapi):
            analysis_result["has_complete"] = True

        # Check for cleanup patterns (resource cleanup sequences)
        if self._has_cleanup_patterns(func_ea, ida_funcs, idaapi):
            analysis_result["has_cleanup"] = True

        # Check for dispatcher patterns (IRP dispatcher characteristics)
        if self._has_dispatcher_patterns(func_ea, ida_funcs, idaapi):
            analysis_result["is_dispatcher"] = True

        # Check for handle operation patterns
        if self._has_handle_patterns(func_ea, ida_funcs, idaapi):
            analysis_result["has_handle_ops"] = True

        # Check for validation patterns
        if self._has_validation_patterns(func_ea, ida_funcs, idaapi):
            analysis_result["has_validation"] = True

    def _determine_role_from_analysis(self, analysis: Dict) -> FunctionRole:
        """Determine function role from analysis results with priority ordering"""
        # Priority order: FailFast > Error Handler > IRP Dispatcher > Cleanup > Handle Manager > Resource Manager > Validation > Unknown

        if analysis["has_failfast"]:
            return FunctionRole.FAILFAST_GUARD
        elif analysis["has_complete"] and analysis["has_cleanup"]:
            return FunctionRole.ERROR_HANDLER
        elif analysis["has_complete"] and analysis["is_dispatcher"]:
            return FunctionRole.IRP_DISPATCHER
        elif analysis["has_cleanup"]:
            return FunctionRole.CLEANUP_HANDLER
        elif analysis["has_handle_ops"]:
            return FunctionRole.HANDLE_MANAGER
        elif analysis["has_complete"]:
            return FunctionRole.RESOURCE_MANAGER
        elif analysis["is_dispatcher"]:
            return FunctionRole.IRP_DISPATCHER
        elif analysis["has_validation"]:
            return FunctionRole.VALIDATION_ROUTINE
        else:
            return FunctionRole.UNKNOWN

    # Optimized helper methods for symbol-based detection - O(1) lookup using frozensets
    def _is_failfast_symbol(self, func_name: str) -> bool:
        return any(pattern in func_name for pattern in self._FAILFAST_SYMBOLS)

    def _is_complete_symbol(self, func_name: str) -> bool:
        return "IofCompleteRequest" in func_name or "IoCompleteRequest" in func_name

    def _is_cleanup_symbol(self, func_name: str) -> bool:
        # Tối ưu: Check nhanh O(1) thay vì O(N) loop
        return func_name in self._CLEANUP_SYMBOLS

    def _is_dispatcher_symbol(self, func_name: str) -> bool:
        # Tối ưu: Check nhanh O(1) thay vì O(N) loop
        return any(disp in func_name for disp in self._DISPATCHER_SYMBOLS)

    def _is_handle_symbol(self, func_name: str) -> bool:
        # Tối ưu: Check nhanh O(1) thay vì O(N) loop
        return any(handle in func_name for handle in self._HANDLE_SYMBOLS)

    def _is_validation_symbol(self, func_name: str) -> bool:
        # Tối ưu: Check nhanh O(1) thay vì O(N) loop
        return any(val in func_name for val in self._VALIDATION_SYMBOLS)

    # Pattern-based detection methods (symbol-independent)
    def _has_int29_pattern(self, func_ea: int, ida_provider: IDAProvider) -> bool:
        """Check for int 29h (FailFast interrupt) pattern"""
        f = ida_funcs.get_func(func_ea)
        if not f:
            return False

        ea = f.start_ea
        while ea < f.end_ea:
            try:
                if idaapi.get_byte(ea) == 0xCD and idaapi.get_byte(ea + 1) == 0x29:
                    return True
            except (AttributeError, IndexError, TypeError) as e:
                logger.debug(f"Error checking int29 at {hex(ea)}: {e}")
            ea = idaapi.next_head(ea, f.end_ea)
        return False

    def _has_failfast_patterns(self, func_ea: int, ida_funcs, idaapi) -> bool:
        """Check for FailFast instruction patterns (symbol-independent)"""
        # Check for int 29h
        if self._has_int29_pattern(func_ea, ida_funcs, idaapi):
            return True

        # Check for other FailFast patterns (like calling certain addresses frequently)
        # This is a simplified implementation - real implementation would analyze more patterns
        return False

    def _has_completion_patterns(self, func_ea: int, ida_funcs, idaapi) -> bool:
        """Check for IRP completion patterns (symbol-independent)"""
        f = ida_funcs.get_func(func_ea)
        if not f:
            return False

        # Look for patterns typical of IRP completion functions
        # This would need more sophisticated analysis in a real implementation
        call_count = 0
        ea = f.start_ea
        while ea < f.end_ea:
            try:
                if idaapi.is_call_insn(ea):
                    call_count += 1
                    if call_count > 5:  # Many calls might indicate completion logic
                        # Check if function ends with return pattern
                        return True
            except (AttributeError, TypeError) as e:
                logger.debug(f"Error checking call at {hex(ea)}: {e}")
            ea = idaapi.next_head(ea, f.end_ea)

        return False

    def _has_cleanup_patterns(self, func_ea: int, ida_funcs, idaapi) -> bool:
        """Check for cleanup patterns (symbol-independent)"""
        # Simplified: functions with many calls and no obvious input validation
        # Real implementation would analyze register usage, stack operations, etc.
        f = ida_funcs.get_func(func_ea)
        if not f:
            return False

        call_count = 0
        ea = f.start_ea
        while ea < f.end_ea:
            try:
                if idaapi.is_call_insn(ea):
                    call_count += 1
            except (AttributeError, TypeError) as e:
                logger.debug(f"Error checking cleanup at {hex(ea)}: {e}")
            ea = idaapi.next_head(ea, f.end_ea)

        # Functions with 3+ calls are likely doing cleanup operations
        return call_count >= 3

    def _has_dispatcher_patterns(self, func_ea: int, ida_funcs, idaapi) -> bool:
        """Check for IRP dispatcher patterns (symbol-independent)"""
        f = ida_funcs.get_func(func_ea)
        if not f:
            return False

        # Check for switch-like patterns (IRP major function dispatch)
        # Look for comparison instructions followed by jumps
        cmp_count = 0
        jmp_count = 0
        ea = f.start_ea
        while ea < f.end_ea:
            try:
                mnem = idaapi.ua_mnem(ea)
                if mnem:
                    if 'cmp' in mnem.lower():
                        cmp_count += 1
                    elif 'j' in mnem.lower() and mnem.lower() != 'jmp':  # conditional jumps
                        jmp_count += 1
            except (AttributeError, TypeError) as e:
                logger.debug(f"Error checking dispatcher at {hex(ea)}: {e}")
            ea = idaapi.next_head(ea, f.end_ea)

        # Many comparisons and conditional jumps suggest dispatcher logic
        return cmp_count >= 3 and jmp_count >= 3

    def _has_handle_patterns(self, func_ea: int, ida_funcs, idaapi) -> bool:
        """Check for handle operation patterns (symbol-independent)"""
        f = ida_funcs.get_func(func_ea)
        if not f:
            return False

        # Look for patterns typical of handle operations
        # Many calls, potential error checking, etc.
        call_count = 0
        mov_count = 0
        ea = f.start_ea
        while ea < f.end_ea:
            try:
                mnem = idaapi.ua_mnem(ea)
                if mnem:
                    if 'call' in mnem.lower():
                        call_count += 1
                    elif 'mov' in mnem.lower():
                        mov_count += 1
            except (AttributeError, TypeError) as e:
                logger.debug(f"Error checking handle at {hex(ea)}: {e}")
            ea = idaapi.next_head(ea, f.end_ea)

        # Handle functions typically have several calls and data movement
        return call_count >= 2 and mov_count >= 5

    def _has_validation_patterns(self, func_ea: int, ida_funcs, idaapi) -> bool:
        """Check for validation patterns (symbol-independent)"""
        f = ida_funcs.get_func(func_ea)
        if not f:
            return False

        # Look for validation patterns: comparisons, conditional returns
        cmp_count = 0
        ret_count = 0
        jcc_count = 0

        ea = f.start_ea
        while ea < f.end_ea:
            try:
                mnem = idaapi.ua_mnem(ea)
                if mnem:
                    if 'cmp' in mnem.lower() or 'test' in mnem.lower():
                        cmp_count += 1
                    elif 'ret' in mnem.lower():
                        ret_count += 1
                    elif any(j in mnem.lower() for j in ['je', 'jne', 'jz', 'jnz', 'jc', 'jnc']):
                        jcc_count += 1
            except (AttributeError, TypeError) as e:
                logger.debug(f"Error checking validation at {hex(ea)}: {e}")
            ea = idaapi.next_head(ea, f.end_ea)

        # Validation functions typically have comparisons and conditional returns
        return cmp_count >= 2 and (ret_count >= 1 or jcc_count >= 2)

    def _has_handle_operation(self, func_ea: int, ida_funcs, idaapi, acquire: bool = False, release: bool = False, validate: bool = False) -> bool:
        """Check if function performs handle operations"""
        try:
            f = ida_funcs.get_func(func_ea)
            if not f:
                return False

            ea = f.start_ea
            while ea < f.end_ea:
                try:
                    if idaapi.is_call_insn(ea):
                        for ref in idaapi.CodeRefsFrom(ea, 0):
                            if ref == idaapi.BADADDR:
                                continue

                            func_name = self._get_function_name_at_address(ref, ida_funcs, idaapi)
                            if not func_name:
                                continue

                            if acquire and any(acq in func_name for acq in self._HANDLE_ACQUIRE_SYMBOLS):
                                return True

                            if release and any(rel in func_name for rel in self._HANDLE_RELEASE_SYMBOLS):
                                return True

                            if validate and any(val in func_name for val in self._HANDLE_VALIDATE_SYMBOLS):
                                return True

                except (AttributeError, TypeError) as e:
                    logger.debug(f"Error checking handle ref at {hex(ea)}: {e}")
                ea = idaapi.next_head(ea, f.end_ea)

        except Exception as e:
            logger.warning(f"Error checking handle operations in {hex(func_ea)}: {e}")

        return False

    def _get_function_name_at_address(self, ea: int, ida_funcs, idaapi) -> str:
        """Get function name at a specific address with proper IDA API usage"""
        try:
            # Try to get function name directly
            name = idaapi.get_name(ea)
            if name:
                return name

            # Try to get from imports/exports
            func = ida_funcs.get_func(ea)
            if func:
                name = idaapi.get_name(func.start_ea)
                if name:
                    return name

            return ""
        except (AttributeError, TypeError):
            return ""

    def _detect_error_codes(self, func_ea: int, ida_funcs, idaapi) -> Set[str]:
        """Detect NTSTATUS error codes written to IRP->IoStatus.Status"""
        error_codes = set()
        try:
            f = ida_funcs.get_func(func_ea)
            if not f:
                return error_codes

            ea = f.start_ea
            while ea < f.end_ea:
                try:
                    # Look for mov instructions writing to memory
                    # This is a simplified pattern - real implementation would need more sophisticated analysis
                    if idaapi.get_byte(ea) == 0xC7:  # mov dword ptr
                        # Check if this might be writing an NTSTATUS value
                        # In real kernel drivers, this would be: mov [rax+IoStatus.Status], STATUS_XXX
                        # We look for common NTSTATUS patterns
                        pass

                    # Check for immediate values that look like NTSTATUS codes
                    # NTSTATUS codes are typically in range 0x80000000-0xFFFFFFFF for errors
                    # or 0x00000000-0x3FFFFFFF for success
                    mnem = idaapi.ua_mnem(ea)
                    if mnem and ('mov' in mnem.lower() or 'lea' in mnem.lower()):
                        op1 = idaapi.ua_outop1(ea)
                        op2 = idaapi.ua_outop2(ea)

                        # Check operands for STATUS_ patterns
                        for op in [op1, op2]:
                            if op:
                                op_str = str(op)
                                if 'STATUS_' in op_str:
                                    # Extract status code name
                                    if 'STATUS_ACCESS_VIOLATION' in op_str:
                                        error_codes.add('STATUS_ACCESS_VIOLATION')
                                    elif 'STATUS_INVALID_HANDLE' in op_str:
                                        error_codes.add('STATUS_INVALID_HANDLE')
                                    elif 'STATUS_INSUFFICIENT_RESOURCES' in op_str:
                                        error_codes.add('STATUS_INSUFFICIENT_RESOURCES')
                                    elif 'STATUS_UNSUCCESSFUL' in op_str:
                                        error_codes.add('STATUS_UNSUCCESSFUL')
                                    # Add more status codes as needed

                except (AttributeError, TypeError) as e:
                    logger.debug(f"Error checking error code at {hex(ea)}: {e}")
                ea = idaapi.next_head(ea, f.end_ea)

        except Exception as e:
            logger.warning(f"Error detecting error codes in {hex(func_ea)}: {e}")

        return error_codes

    def _get_callers(self, func_ea: int, ida_funcs, idaapi) -> Set[int]:
        """Get callers of a function"""
        callers = set()
        try:
            for xref in ida_xref.XrefsTo(func_ea, ida_xref.XREF_FAR):
                if xref is None:
                    continue
                if idaapi.is_call_insn(xref.frm):
                    caller_func = ida_funcs.get_func(xref.frm)
                    if caller_func:
                        callers.add(caller_func.start_ea)
        except Exception as e:
            logger.warning(f"Failed to get callers for {hex(func_ea)}: {e}")
        return callers

    def _get_callees(self, func_ea: int, ida_funcs, idaapi) -> Set[int]:
        """Get functions called by the given function"""
        callees = set()
        try:
            f = ida_funcs.get_func(func_ea)
            if not f:
                return callees

            ea = f.start_ea
            while ea < f.end_ea:
                try:
                    if idaapi.is_call_insn(ea):
                        for ref in idaapi.CodeRefsFrom(ea, idaapi.dr_O):
                            if ref != idaapi.BADADDR:
                                callee_func = ida_funcs.get_func(ref)
                                if callee_func:
                                    callees.add(callee_func.start_ea)
                except (AttributeError, TypeError) as e:
                    logger.debug(f"Error getting callee at {hex(ea)}: {e}")
                ea = idaapi.next_head(ea, f.end_ea)
        except Exception as e:
            logger.warning(f"Failed to get callees for {hex(func_ea)}: {e}")
        return callees

    def _get_function_name(self, func_ea: int, ida_provider: IDAProvider) -> str:
        """Get function name"""
        try:
            f = ida_funcs.get_func(func_ea)
            if f and hasattr(f, 'name'):
                return f.name
            return f"sub_{func_ea:08X}"
        except (AttributeError, TypeError):
            return f"sub_{func_ea:08X}"

    def _get_irp_context(self, func_ea: int, ida_funcs, idaapi) -> Optional[Dict]:
        """Get IRP context for function"""
        try:
            f = ida_funcs.get_func(func_ea)
            if not f:
                return None

            # Simplified IRP context (would need full implementation)
            return {
                "is_irp_dispatcher": self._is_irp_dispatcher(func_ea, ida_funcs, idaapi),
                "hierarchy_depth": 0,  # Would need proper calculation
                "callers": list(self._get_callers(func_ea, ida_funcs, idaapi)),
                "irp_lifecycle": {"major_functions": set(), "ioctl_codes": set(), "irp_parameters": set()},
                "error_conditions": {"error_codes": set(), "validation_patterns": set(), "security_checks": set()}
            }
        except (AttributeError, TypeError) as e:
            logger.debug(f"Error getting IRP context for {hex(func_ea)}: {e}")
            return None

    def _is_irp_dispatcher(self, func_ea: int, ida_funcs, idaapi) -> bool:
        """Check if function is IRP dispatcher"""
        try:
            f = ida_funcs.get_func(func_ea)
            if not f:
                return False

            ea = f.start_ea
            while ea < f.end_ea:
                try:
                    if idaapi.is_call_insn(ea):
                        for ref in idaapi.CodeRefsFrom(ea, idaapi.dr_O):
                            if ref != idaapi.BADADDR:
                                ref_str = hex(ref)
                                if any(pattern in ref_str for pattern in ["IoGetCurrentIrpStackLocation", "irp", "IRP"]):
                                    return True
                except (AttributeError, TypeError) as e:
                    logger.debug(f"Error checking IRP dispatcher ref at {hex(ea)}: {e}")
                ea = idaapi.next_head(ea, f.end_ea)
            return False
        except (AttributeError, TypeError) as e:
            logger.debug(f"Error checking IRP dispatcher for {hex(func_ea)}: {e}")
            return False

    def to_dict(self) -> Dict:
        """Convert graph to dictionary for serialization"""
        # Helper for recursive serialization of sets/complex types
        def safe_serialize(obj):
            if isinstance(obj, set):
                return list(obj)
            if isinstance(obj, bytes):
                # Handle binary data - convert to hex string to avoid JSON crash
                return obj.hex()
            if isinstance(obj, dict):
                return {k: safe_serialize(v) for k, v in obj.items()}
            if isinstance(obj, list):
                return [safe_serialize(v) for v in obj]
            return obj

        return {
            "anchor_function": hex(self.anchor_function),
            "nodes": {
                hex(ea): {
                    "name": node.name,
                    "role": node.role.value,
                    "is_error_handler": node.is_error_handler,
                    "has_failfast": node.has_failfast,
                    "has_complete_request": node.has_complete_request,
                    "has_handle_acquire": node.has_handle_acquire,
                    "has_handle_validation": node.has_handle_validation,
                    "has_handle_release": node.has_handle_release,
                    "error_codes_written": list(node.error_codes_written),
                    "irp_context": safe_serialize(node.irp_context),
                    "metadata": safe_serialize(node.metadata)
                } for ea, node in self.nodes.items()
            },
            "edges": [(hex(caller), hex(callee), edge_type) for caller, callee, edge_type in self.edges],
            "max_depth": self.max_depth,
            "bounds": list(self.bounds)
        }

    @classmethod
    def from_dict(cls, data: Dict) -> 'LogicGraph':
        """Create graph from dictionary. Returns empty graph if data is invalid or incomplete."""
        # Handle empty or incomplete data
        if not data or "anchor_function" not in data:
            logger.warning("LogicGraph.from_dict received empty or incomplete data, returning empty graph")
            return cls(anchor_function=0)
        
        try:
            anchor_val = data["anchor_function"]
            # Handle both int and hex string formats
            if isinstance(anchor_val, int):
                anchor_ea = anchor_val
            elif isinstance(anchor_val, str):
                anchor_ea = int(anchor_val, 16) if anchor_val.startswith('0x') else int(anchor_val)
            else:
                anchor_ea = 0
            graph = cls(anchor_function=anchor_ea)
        except (ValueError, TypeError) as e:
            logger.warning(f"Invalid anchor_function in data: {e}")
            return cls(anchor_function=0)
            
        graph.max_depth = data.get("max_depth", 5)
        graph.bounds = set(data.get("bounds", []))

        # Reconstruct nodes
        for ea_hex, node_data in data.get("nodes", {}).items():
            ea = int(ea_hex, 16)
            # Safely convert role string back to enum, defaulting to UNKNOWN if invalid
            try:
                role_str = node_data["role"]
                role = FunctionRole(role_str) if role_str in [r.value for r in FunctionRole] else FunctionRole.UNKNOWN
            except (ValueError, KeyError):
                role = FunctionRole.UNKNOWN

            node = FunctionNode(
                ea=ea,
                name=node_data.get("name", f"sub_{ea:08X}"),
                role=role,
                is_error_handler=node_data.get("is_error_handler", False),
                has_failfast=node_data.get("has_failfast", False),
                has_complete_request=node_data.get("has_complete_request", False),
                has_handle_acquire=node_data.get("has_handle_acquire", False),
                has_handle_validation=node_data.get("has_handle_validation", False),
                has_handle_release=node_data.get("has_handle_release", False),
                error_codes_written=set(node_data.get("error_codes_written", [])),
                irp_context=node_data.get("irp_context"),
                metadata=node_data.get("metadata", {})
            )
            graph.add_node(ea, node)

        # Reconstruct edges
        for edge_data in data.get("edges", []):
            if len(edge_data) >= 3:
                caller_hex, callee_hex, edge_type = edge_data[0], edge_data[1], edge_data[2]
                caller = int(caller_hex, 16)
                callee = int(callee_hex, 16)
                graph.add_edge(caller, callee, edge_type)

        return graph


    def export_dot(self, title: str = "Logic Flow Graph", highlight_nodes: List[int] = None,
                   highlight_edges: List[Tuple[int, int]] = None) -> str:
        """
        Export the logic graph to GraphViz DOT format for visualization.

        Args:
            title: Title for the graph
            highlight_nodes: List of node addresses to highlight (red color)
            highlight_edges: List of (caller, callee) tuples to highlight

        Returns:
            DOT format string that can be rendered with GraphViz
        """
        dot_lines = []
        dot_lines.append(f'digraph "{title}" {{')
        dot_lines.append('    // Graph attributes')
        dot_lines.append('    rankdir=TB;')
        dot_lines.append('    node [shape=box, style=filled, fontname="Arial", fontsize=10];')
        dot_lines.append('    edge [fontname="Arial", fontsize=8];')
        dot_lines.append('')

        # Prepare highlight sets
        highlight_nodes = set(highlight_nodes or [])
        highlight_edges = set(highlight_edges or [])

        # Define node colors based on roles
        role_colors = {
            FunctionRole.ERROR_HANDLER: 'lightcoral',
            FunctionRole.CLEANUP_HANDLER: 'lightblue',
            FunctionRole.FAILFAST_GUARD: 'red',
            FunctionRole.RESOURCE_MANAGER: 'lightgreen',
            FunctionRole.VALIDATION_ROUTINE: 'yellow',
            FunctionRole.IRP_DISPATCHER: 'orange',
            FunctionRole.HANDLE_MANAGER: 'purple',
            FunctionRole.UNKNOWN: 'lightgray'
        }

        # Add nodes
        dot_lines.append('    // Nodes')
        for ea, node in self.nodes.items():
            # Determine node color
            if ea in highlight_nodes:
                color = 'red'
                fontcolor = 'white'
            else:
                color = role_colors.get(node.role, 'lightgray')
                fontcolor = 'black'

            # Create node label
            label_parts = [node.name or f'0x{ea:08X}']

            # Add role info
            if node.role != FunctionRole.UNKNOWN:
                label_parts.append(f'[{node.role.value}]')

            # Add capability indicators
            capabilities = []
            if node.is_error_handler:
                capabilities.append('ERR')
            if node.has_failfast:
                capabilities.append('FAILFAST')
            if node.has_handle_acquire:
                capabilities.append('ACQUIRE')
            if node.has_handle_release:
                capabilities.append('RELEASE')
            if node.has_handle_validation:
                capabilities.append('VALIDATE')

            if capabilities:
                label_parts.append(f"({', '.join(capabilities)})")

            label = '\\n'.join(label_parts)

            # Escape special characters in label
            label = label.replace('"', '\\"').replace('\n', '\\n')

            dot_lines.append(f'    "0x{ea:08X}" [label="{label}", fillcolor="{color}", fontcolor="{fontcolor}"];')

        dot_lines.append('')

        # Add edges with different styles
        dot_lines.append('    // Edges')
        for caller, callee, edge_type in self.edges:
            # Determine edge style
            if (caller, callee) in highlight_edges:
                color = 'red'
                penwidth = '3'
            else:
                color = 'black'
                penwidth = '1'

            # Different arrow styles for different edge types
            if edge_type == 'calls':
                arrowhead = 'normal'
            elif edge_type == 'error_flow':
                arrowhead = 'dot'
                color = 'red'
            elif edge_type == 'cleanup_flow':
                arrowhead = 'odot'
                color = 'blue'
            else:
                arrowhead = 'normal'

            dot_lines.append(f'    "0x{caller:08X}" -> "0x{callee:08X}" [label="{edge_type}", color="{color}", penwidth={penwidth}, arrowhead={arrowhead}];')

        dot_lines.append('')
        dot_lines.append('    // Legend')
        dot_lines.append('    subgraph cluster_legend {{')
        dot_lines.append('        label="Legend";')
        dot_lines.append('        fontsize=12;')
        dot_lines.append('        "legend_normal" [label="Normal Call", shape=plaintext];')
        dot_lines.append('        "legend_error" [label="Error Flow", shape=plaintext, fontcolor=red];')
        dot_lines.append('        "legend_cleanup" [label="Cleanup Flow", shape=plaintext, fontcolor=blue];')
        dot_lines.append('    }}')

        dot_lines.append('}')
        return '\n'.join(dot_lines)

    def compare_with_graph(self, other_graph: 'LogicGraph') -> Dict[str, Any]:
        """Compare this graph with another for semantic equivalence analysis"""
        comparison = {
            "structural_similarity": self._compare_structural(other_graph),
            "role_distribution": self._compare_roles(other_graph),
            "path_analysis": self._compare_paths(other_graph),
            "semantic_patterns": self._compare_semantic_patterns(other_graph),
            "manual_analysis_hints": self._generate_analysis_hints(other_graph)
        }
        return comparison

    def _compare_structural(self, other: 'LogicGraph') -> Dict[str, Any]:
        """Compare structural properties between graphs"""
        return {
            "node_count_similarity": abs(len(self.nodes) - len(other.nodes)),
            "depth_similarity": abs(self.max_depth - other.max_depth),
            "boundary_functions_overlap": len(self.bounds & other.bounds),
            "anchor_roles_match": self.nodes[self.anchor_function].role == other.nodes[other.anchor_function].role
        }

    def _compare_roles(self, other: 'LogicGraph') -> Dict[str, Any]:
        """Compare function role distributions"""
        roles_a = {}
        roles_b = {}

        for node in self.nodes.values():
            roles_a[node.role.value] = roles_a.get(node.role.value, 0) + 1

        for node in other.nodes.values():
            roles_b[node.role.value] = roles_b.get(node.role.value, 0) + 1

        differences = {}
        all_roles = set(roles_a.keys()) | set(roles_b.keys())
        for role in all_roles:
            count_a = roles_a.get(role, 0)
            count_b = roles_b.get(role, 0)
            if count_a != count_b:
                differences[role] = abs(count_a - count_b)

        return {
            "role_distributions": {"graph_a": roles_a, "graph_b": roles_b},
            "role_differences": differences
        }

    def _compare_paths(self, other: 'LogicGraph') -> Dict[str, Any]:
        """Compare execution paths between graphs"""
        # Simple path comparison - in real implementation would be more sophisticated
        paths_a = self._extract_paths()
        paths_b = other._extract_paths()

        matched_paths = 0
        path_similarities = []

        for path_a in paths_a[:5]:  # Limit for performance
            best_match = None
            best_score = 0

            for path_b in paths_b[:5]:
                score = self._path_similarity(path_a, path_b)
                if score > best_score:
                    best_score = score
                    best_match = path_b

            if best_match:
                matched_paths += 1
                path_similarities.append({
                    "path_a": path_a,
                    "path_b": best_match,
                    "similarity_score": best_score,
                    "semantic_flow_a": [self.nodes[ea].role.value for ea in path_a],
                    "semantic_flow_b": [other.nodes[ea].role.value for ea in best_match]
                })

        return {
            "total_paths": len(paths_a),
            "matched_paths": matched_paths,
            "path_similarities": path_similarities
        }

    def _extract_paths(self) -> List[List[int]]:
        """Extract execution paths from graph (simplified) - ITERATIVE version"""
        paths = []
        
        if self.anchor_function not in self.nodes:
            return paths

        # Stack: (current_node, path_so_far)
        stack = [(self.anchor_function, [self.anchor_function])]
        
        while stack:
            current, path = stack.pop()
            callees = self.get_callees(current)
            
            if not callees:  # Leaf node
                paths.append(path)
                continue

            for callee in callees[:3]:  # Limit branching
                if callee not in path:  # Avoid cycles
                    stack.append((callee, path + [callee]))

        return paths

    def _path_similarity(self, path_a: List[int], path_b: List[int]) -> float:
        """Calculate similarity between two paths"""
        if not path_a or not path_b:
            return 0.0

        # Simple similarity based on role sequence
        roles_a = [self.nodes[ea].role.value for ea in path_a]
        roles_b = [self.nodes[ea].role.value for ea in path_b]

        # Longest common subsequence length
        m, n = len(roles_a), len(roles_b)
        dp = [[0] * (n + 1) for _ in range(m + 1)]

        for i in range(1, m + 1):
            for j in range(1, n + 1):
                if roles_a[i-1] == roles_b[j-1]:
                    dp[i][j] = dp[i-1][j-1] + 1
                else:
                    dp[i][j] = max(dp[i-1][j], dp[i][j-1])

        lcs_length = dp[m][n]
        return lcs_length / max(len(roles_a), len(roles_b))

    def _compare_semantic_patterns(self, other: 'LogicGraph') -> Dict[str, Any]:
        """Compare semantic patterns between graphs"""
        failfast_a = self.get_failfast_position()
        failfast_b = other.get_failfast_position()

        cleanup_a = [node.ea for node in self.get_node_by_role(FunctionRole.CLEANUP_HANDLER)]
        cleanup_b = [node.ea for node in other.get_node_by_role(FunctionRole.CLEANUP_HANDLER)]

        return {
            "pattern_differences": {
                "failfast_placement": failfast_a != failfast_b,
                "cleanup_sequences": set(cleanup_a) != set(cleanup_b),
                "error_propagation": self._compare_error_propagation(other)
            }
        }

    def _compare_error_propagation(self, other: 'LogicGraph') -> bool:
        """Compare error propagation patterns (simplified)"""
        error_handlers_a = len(self.get_error_handlers())
        error_handlers_b = len(other.get_error_handlers())
        return error_handlers_a != error_handlers_b

    def _generate_analysis_hints(self, other: 'LogicGraph') -> List[str]:
        """Generate hints for manual analysis"""
        hints = []

        # FailFast positioning hints
        failfast_a = self.get_failfast_position()
        failfast_b = other.get_failfast_position()

        if failfast_a and failfast_b:
            path_a = self.get_path_to_anchor(failfast_a)
            path_b = other.get_path_to_anchor(failfast_b)

            if len(path_a) != len(path_b):
                hints.append(f"FailFast depth differs: {len(path_a)} vs {len(path_b)} levels from anchor")

        # Role distribution hints
        roles_a = sum(1 for node in self.nodes.values() if node.role != FunctionRole.UNKNOWN)
        roles_b = sum(1 for node in other.nodes.values() if node.role != FunctionRole.UNKNOWN)

        if abs(roles_a - roles_b) > 2:
            hints.append(f"Significant difference in identified function roles: {roles_a} vs {roles_b}")

        # Boundary differences
        if self.bounds != other.bounds:
            hints.append(f"Different semantic boundaries: {self.bounds} vs {other.bounds}")

        return hints