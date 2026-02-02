"""
Externalized Heuristics Configuration for Logic Flow Analysis.

All "magic numbers" and scoring weights are defined here for easy tuning.
This allows adjusting analysis sensitivity without modifying core algorithms.
"""

from dataclasses import dataclass, field
from typing import Dict, List, Set
import json
import os


@dataclass
class ScoringWeights:
    """Weights for semantic candidate scoring."""
    
    # Core matching weights (0-100 scale)
    name_exact_match: int = 100      # Function names match exactly
    name_pattern_match: int = 50     # Function name contains pattern
    
    # API call weights
    api_call_sequence_match: int = 30   # Same API call sequence
    api_call_set_overlap: int = 15      # Overlapping API calls
    
    # Structural weights
    instruction_count_delta_penalty: float = 0.1  # Per instruction difference
    xref_count_match: int = 10          # Similar xref counts
    
    # Role-based weights
    role_match: int = 25                # Same FunctionRole
    error_handler_bonus: int = 15       # Both are error handlers
    
    # IRP Context weights
    irp_context_match: int = 5          # Similar IRP handling
    
    # Fuzzy Hash weights (NEW)
    fuzzy_hash_threshold: int = 70      # Minimum TLSH score to consider match
    fuzzy_hash_exact: int = 40          # Bonus for hash score > 90
    fuzzy_hash_similar: int = 20        # Bonus for hash score 70-90


@dataclass
class FunctionRolePatterns:
    """Patterns for classifying function roles."""
    
    # Error handler patterns
    error_patterns: List[str] = field(default_factory=lambda: [
        'error', 'fail', 'abort', 'panic', 'bugcheck', 'crash',
        'invalid', 'exception', 'fatal', 'assert'
    ])
    
    # Validation patterns
    validation_patterns: List[str] = field(default_factory=lambda: [
        'validate', 'check', 'verify', 'probe', 'test', 'assert',
        'require', 'ensure', 'confirm', 'sanitize'
    ])
    
    # Resource management patterns
    resource_patterns: List[str] = field(default_factory=lambda: [
        'alloc', 'malloc', 'pool', 'buffer', 'memory',
        'acquire', 'obtain', 'get_resource'
    ])
    
    # Dispatcher patterns
    dispatcher_patterns: List[str] = field(default_factory=lambda: [
        'dispatch', 'ioctl', 'irp', 'handler', 'process',
        'handle_request', 'device_control'
    ])
    
    # Cleanup patterns
    cleanup_patterns: List[str] = field(default_factory=lambda: [
        'cleanup', 'free', 'release', 'unload', 'complete',
        'done', 'finish', 'destroy', 'close'
    ])
    
    # FailFast API names (exact matches)
    failfast_apis: Set[str] = field(default_factory=lambda: {
        'KeBugCheck', 'KeBugCheckEx', 'RtlFailFast',
        'FatalError', 'abort', '__fastfail'
    })
    
    # Completion APIs
    completion_apis: Set[str] = field(default_factory=lambda: {
        'IoCompleteRequest', 'IoComplete', 'CompleteRequest',
        'WdfRequestComplete', 'WdfRequestCompleteWithInformation'
    })
    
    # Security-sensitive APIs (for vulnerability detection)
    security_apis: Set[str] = field(default_factory=lambda: {
        'SeAccessCheck', 'SeSinglePrivilegeCheck', 'SePrivilegeCheck',
        'RtlValidSecurityDescriptor', 'ZwQuerySecurityObject',
        'ObCheckSecurityAccess', 'IoCheckShareAccess'
    })


@dataclass
class AnalysisLimits:
    """Limits to prevent resource exhaustion."""
    
    max_graph_depth: int = 10           # Maximum traversal depth
    max_nodes_per_graph: int = 500      # Stop adding nodes after this
    max_candidates: int = 50            # Maximum semantic candidates
    max_paths_to_compare: int = 100     # Limit path comparisons
    
    # Timeouts (seconds)
    function_analysis_timeout: int = 5
    graph_build_timeout: int = 30
    comparison_timeout: int = 60


@dataclass
class FuzzyHashConfig:
    """Configuration for fuzzy hashing (TLSH/SSDeep)."""
    
    # Which algorithm to use
    algorithm: str = "tlsh"             # "tlsh" or "ssdeep"
    
    # Minimum function size to hash (bytes)
    min_function_size: int = 50
    
    # Score thresholds (TLSH: lower = more similar, 0 = identical)
    # We invert TLSH scores to 0-100 scale where 100 = identical
    match_threshold: int = 70           # Consider as potential match
    strong_match_threshold: int = 90    # Strong similarity
    
    # Cache settings
    cache_hashes: bool = True


@dataclass 
class TaintAnalysisConfig:
    """Configuration for data flow / taint analysis."""
    
    # Enable/disable features
    enabled: bool = True
    
    # Taint sources (input points)
    taint_sources: List[str] = field(default_factory=lambda: [
        'SystemBuffer', 'Type3InputBuffer', 'MdlAddress',
        'InputBufferLength', 'IoControlCode', 'UserBuffer'
    ])
    
    # Taint sinks (sensitive operations)
    taint_sinks: List[str] = field(default_factory=lambda: [
        'MmMapLockedPages', 'MmProbeAndLockPages',
        'ProbeForRead', 'ProbeForWrite',
        'ExAllocatePool', 'RtlCopyMemory', 'memcpy'
    ])
    
    # Maximum instructions to trace
    max_trace_depth: int = 100


class HeuristicsConfig:
    """
    Main configuration class. Loads from JSON file or uses defaults.
    """
    
    def __init__(self, config_path: str = None):
        self.scoring = ScoringWeights()
        self.patterns = FunctionRolePatterns()
        self.limits = AnalysisLimits()
        self.fuzzy_hash = FuzzyHashConfig()
        self.taint = TaintAnalysisConfig()
        
        if config_path and os.path.exists(config_path):
            self.load(config_path)
    
    def load(self, path: str):
        """Load configuration from JSON file."""
        try:
            with open(path, 'r') as f:
                data = json.load(f)
            
            if 'scoring' in data:
                for k, v in data['scoring'].items():
                    if hasattr(self.scoring, k):
                        setattr(self.scoring, k, v)
            
            if 'limits' in data:
                for k, v in data['limits'].items():
                    if hasattr(self.limits, k):
                        setattr(self.limits, k, v)
            
            if 'fuzzy_hash' in data:
                for k, v in data['fuzzy_hash'].items():
                    if hasattr(self.fuzzy_hash, k):
                        setattr(self.fuzzy_hash, k, v)
                        
        except Exception as e:
            print(f"Warning: Failed to load heuristics config: {e}")
    
    def save(self, path: str):
        """Save current configuration to JSON file."""
        data = {
            'scoring': self.scoring.__dict__,
            'limits': self.limits.__dict__,
            'fuzzy_hash': self.fuzzy_hash.__dict__
        }
        with open(path, 'w') as f:
            json.dump(data, f, indent=2, default=list)
    
    def to_dict(self) -> Dict:
        """Convert config to dictionary."""
        return {
            'scoring': self.scoring.__dict__,
            'patterns': {
                'error_patterns': self.patterns.error_patterns,
                'validation_patterns': self.patterns.validation_patterns,
                'failfast_apis': list(self.patterns.failfast_apis),
                'security_apis': list(self.patterns.security_apis)
            },
            'limits': self.limits.__dict__,
            'fuzzy_hash': self.fuzzy_hash.__dict__,
            'taint': self.taint.__dict__
        }


# Global default config instance
_default_config = None

def get_config() -> HeuristicsConfig:
    """Get the global heuristics configuration."""
    global _default_config
    if _default_config is None:
        _default_config = HeuristicsConfig()
    return _default_config

def set_config(config: HeuristicsConfig):
    """Set the global heuristics configuration."""
    global _default_config
    _default_config = config

# BACKWARD COMPATIBILITY: Expose HEURISTICS dictionary for legacy verification
# This reconstructs the dictionary format that might be expected by older code
_compat_config = get_config()
HEURISTICS = {
    'SCORING': _compat_config.scoring.__dict__,
    'LIMITS': _compat_config.limits.__dict__,
    'PATTERNS': {
        'ERROR': _compat_config.patterns.error_patterns,
        'VALIDATION': _compat_config.patterns.validation_patterns,
        'MALLOC': _compat_config.patterns.resource_patterns,
        'DISPATCHER': _compat_config.patterns.dispatcher_patterns,
        'CLEANUP': _compat_config.patterns.cleanup_patterns,
        'FAILFAST': list(_compat_config.patterns.failfast_apis),
        'COMPLETION': list(_compat_config.patterns.completion_apis),
    }
}
