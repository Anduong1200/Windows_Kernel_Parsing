"""
Reliability Utilities for Logic Flow Analysis.

Provides robust handling for:
- Non-UTF8/Binary data
- Exception logging with full tracebacks
- Disconnected graph detection
- Data validation
"""

import logging
import traceback
from typing import Any, Dict, List, Optional, Set, Union
from functools import wraps

logger = logging.getLogger(__name__)


# ==============================================================================
# Exception Handling with Full Tracebacks
# ==============================================================================

def log_exception(context: str, e: Exception, level: int = logging.ERROR):
    """
    Log an exception with full traceback.
    
    Args:
        context: Description of what was happening
        e: The exception
        level: Logging level (default ERROR)
    """
    full_traceback = traceback.format_exc()
    logger.log(level, f"{context}: {e}\n{full_traceback}")


def with_exception_logging(context: str):
    """
    Decorator that logs full tracebacks for any exceptions.
    
    Usage:
        @with_exception_logging("Analyzing function")
        def analyze_function(func_ea):
            ...
    """
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            try:
                return func(*args, **kwargs)
            except Exception as e:
                log_exception(f"{context} in {func.__name__}", e)
                raise
        return wrapper
    return decorator


def safe_execute(func, *args, default=None, context: str = "", **kwargs):
    """
    Execute a function safely, logging any exceptions.
    
    Args:
        func: Function to execute
        *args: Arguments to pass
        default: Return value on exception
        context: Description for logging
        **kwargs: Keyword arguments
        
    Returns:
        Function result or default on exception
    """
    try:
        return func(*args, **kwargs)
    except Exception as e:
        log_exception(context or f"Executing {func.__name__}", e, logging.WARNING)
        return default


# ==============================================================================
# Safe String Handling (Non-UTF8/Binary Data)
# ==============================================================================

def safe_decode(data: Union[bytes, str], encoding: str = 'utf-8') -> str:
    """
    Safely decode bytes to string, handling non-UTF8 data.
    
    Args:
        data: Bytes or string to decode
        encoding: Target encoding
        
    Returns:
        Decoded string with invalid chars replaced
    """
    if isinstance(data, str):
        return data
    
    if isinstance(data, bytes):
        return data.decode(encoding, errors='replace')
    
    return str(data)


def safe_encode(data: Union[str, bytes], encoding: str = 'utf-8') -> bytes:
    """
    Safely encode string to bytes.
    
    Args:
        data: String or bytes to encode
        encoding: Target encoding
        
    Returns:
        Encoded bytes
    """
    if isinstance(data, bytes):
        return data
    
    if isinstance(data, str):
        return data.encode(encoding, errors='replace')
    
    return str(data).encode(encoding, errors='replace')


def sanitize_for_json(obj: Any) -> Any:
    """
    Sanitize an object for JSON serialization.
    
    Handles:
    - Bytes -> hex string
    - Sets -> lists
    - Non-UTF8 strings
    - None values
    
    Args:
        obj: Object to sanitize
        
    Returns:
        JSON-serializable version
    """
    if obj is None:
        return None
    
    if isinstance(obj, bytes):
        return obj.hex()
    
    if isinstance(obj, set):
        return list(obj)
    
    if isinstance(obj, str):
        # Ensure valid UTF-8
        return obj.encode('utf-8', errors='replace').decode('utf-8')
    
    if isinstance(obj, dict):
        return {safe_decode(k) if isinstance(k, bytes) else str(k): sanitize_for_json(v) 
                for k, v in obj.items()}
    
    if isinstance(obj, (list, tuple)):
        return [sanitize_for_json(item) for item in obj]
    
    return obj


# ==============================================================================
# Disconnected Graph Handling
# ==============================================================================

def is_graph_connected(nodes: Dict[int, Any], edges: List[tuple], anchor: int) -> bool:
    """
    Check if all nodes in a graph are reachable from the anchor.
    
    Args:
        nodes: Dictionary of node_ea -> node
        edges: List of (caller, callee, edge_type) tuples
        anchor: Anchor function address
        
    Returns:
        True if graph is fully connected from anchor
    """
    if not nodes:
        return True
    
    if anchor not in nodes:
        return False
    
    # Try native BFS if available
    try:
        import logic_flow_native
        
        # Build adjacency list for Rust (requires string keys)
        # We need to construct the full graph for traversal
        adj_map = {}
        for ea in nodes:
            adj_map[str(ea)] = []
            
        for caller, callee, _ in edges:
            c_str, t_str = str(caller), str(callee)
            if c_str in adj_map:
                adj_map[c_str].append(t_str)
            if t_str in adj_map:
                adj_map[t_str].append(c_str)  # Undirected for connectivity
                
        visited_nodes = logic_flow_native.bfs_traversal(str(anchor), adj_map, None)
        return len(visited_nodes) == len(nodes)
        
    except ImportError:
        # Fallback to Python implementation
        pass
    except Exception as e:
        logger.warning(f"Native BFS failed: {e}")
        # Fallback to Python implementation

    # Build adjacency list (bidirectional for connectivity check)
    adjacency = {ea: set() for ea in nodes}
    for caller, callee, _ in edges:
        if caller in adjacency and callee in adjacency:
            adjacency[caller].add(callee)
            adjacency[callee].add(caller)
    
    # BFS from anchor
    visited = set()
    queue = [anchor]
    
    while queue:
        current = queue.pop(0)
        if current in visited:
            continue
        visited.add(current)
        queue.extend(adjacency.get(current, set()) - visited)
    
    return len(visited) == len(nodes)


def find_disconnected_components(nodes: Dict[int, Any], edges: List[tuple], anchor: int) -> List[Set[int]]:
    """
    Find disconnected components in a graph.
    
    Args:
        nodes: Dictionary of node_ea -> node
        edges: List of (caller, callee, edge_type) tuples
        anchor: Anchor function address
        
    Returns:
        List of sets, each containing node addresses in a component
    """
    if not nodes:
        return []
    
    # Build adjacency list
    adjacency = {ea: set() for ea in nodes}
    for caller, callee, _ in edges:
        if caller in adjacency and callee in adjacency:
            adjacency[caller].add(callee)
            adjacency[callee].add(caller)
    
    # Find all components via BFS
    components = []
    unvisited = set(nodes.keys())
    
    while unvisited:
        start = anchor if anchor in unvisited else next(iter(unvisited))
        component = set()
        queue = [start]
        
        while queue:
            current = queue.pop(0)
            if current in component or current not in unvisited:
                continue
            component.add(current)
            unvisited.discard(current)
            queue.extend(adjacency.get(current, set()) - component)
        
        components.append(component)
    
    return components


def connect_disconnected_graph(nodes: Dict[int, Any], edges: List[tuple], anchor: int) -> List[tuple]:
    """
    Add synthetic edges to connect disconnected components to anchor.
    
    Args:
        nodes: Dictionary of node_ea -> node
        edges: List of (caller, callee, edge_type) tuples
        anchor: Anchor function address
        
    Returns:
        New edges list with synthetic connections
    """
    components = find_disconnected_components(nodes, edges, anchor)
    
    if len(components) <= 1:
        return edges  # Already connected
    
    new_edges = list(edges)
    
    # Find the component containing anchor
    anchor_component = None
    for comp in components:
        if anchor in comp:
            anchor_component = comp
            break
    
    if not anchor_component:
        anchor_component = components[0]
    
    # Connect other components to anchor
    for comp in components:
        if comp is anchor_component:
            continue
        
        # Pick first node from component and connect to anchor
        node = next(iter(comp))
        new_edges.append((anchor, node, "synthetic_connection"))
        logger.info(f"Added synthetic edge: {hex(anchor)} -> {hex(node)}")
    
    return new_edges


# ==============================================================================
# Data Validation
# ==============================================================================

def validate_address(value: Any) -> Optional[int]:
    """
    Validate and convert an address value.
    
    Handles:
    - Integer
    - Hex string ("0x1234")
    - Decimal string ("1234")
    
    Returns:
        Integer address or None if invalid
    """
    if isinstance(value, int):
        return value
    
    if isinstance(value, str):
        try:
            if value.startswith("0x") or value.startswith("0X"):
                return int(value, 16)
            return int(value)
        except ValueError:
            return None
    
    return None


def validate_graph_data(data: Dict) -> tuple:
    """
    Validate graph serialization data.
    
    Args:
        data: Dictionary from LogicGraph.to_dict()
        
    Returns:
        Tuple of (is_valid, errors_list)
    """
    errors = []
    
    if not isinstance(data, dict):
        return False, ["Data is not a dictionary"]
    
    # Check required fields
    if "anchor_function" not in data:
        errors.append("Missing 'anchor_function' field")
    
    # Validate anchor
    anchor = validate_address(data.get("anchor_function"))
    if anchor is None:
        errors.append(f"Invalid anchor_function: {data.get('anchor_function')}")
    
    # Validate nodes
    nodes = data.get("nodes", [])
    if isinstance(nodes, list):
        for i, node in enumerate(nodes):
            if not isinstance(node, dict):
                errors.append(f"Node {i} is not a dictionary")
            elif "address" not in node:
                errors.append(f"Node {i} missing 'address' field")
    
    # Validate edges
    edges = data.get("edges", [])
    if isinstance(edges, list):
        for i, edge in enumerate(edges):
            if not isinstance(edge, dict):
                errors.append(f"Edge {i} is not a dictionary")
            elif "caller" not in edge or "callee" not in edge:
                errors.append(f"Edge {i} missing caller/callee")
    
    return len(errors) == 0, errors
