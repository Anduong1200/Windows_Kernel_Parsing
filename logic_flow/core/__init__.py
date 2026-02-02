"""
Core analysis logic for Windows kernel driver analysis.
"""

from .logic_graph import LogicGraph, FunctionNode, FunctionRole
from .analyzer import build_bounded_graph, find_semantic_candidates, analyze_logic_flows, get_bundled_script_path
from .heuristics_config import HeuristicsConfig, get_config, set_config
from .fuzzy_hash import FunctionHasher, is_available as fuzzy_hash_available
from .taint_analysis import TaintAnalyzer
from .disasm_provider import (
    DisassemblerProvider, DisassemblerType,
    GhidraHeadlessProvider, 
    create_provider, auto_detect_provider
)

__all__ = [
    "LogicGraph",
    "FunctionNode",
    "FunctionRole",
    "build_bounded_graph",
    "find_semantic_candidates",
    "analyze_logic_flows",
    "get_bundled_script_path",
    "HeuristicsConfig",
    "get_config",
    "set_config",
    "FunctionHasher",
    "fuzzy_hash_available",
    "TaintAnalyzer",
    "DisassemblerProvider",
    "DisassemblerType",
    "GhidraHeadlessProvider",
    "create_provider",
    "auto_detect_provider"
]
