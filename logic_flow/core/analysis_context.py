"""
Analysis Context for Thread-Safe State Management.

Replaces global caches with a proper context class that:
- Stores all analysis state in one place
- Provides thread-safe access
- Supports context isolation for parallel analyses
- Enables easy state cleanup
"""

import threading
import logging
from typing import Dict, Any, Optional, List
from dataclasses import dataclass, field
from contextlib import contextmanager
from datetime import datetime

logger = logging.getLogger(__name__)


@dataclass
class AnalysisState:
    """
    Immutable snapshot of analysis state.
    
    Used for passing state between components without mutation risks.
    """
    driver_path: str
    anchor_function: Optional[str] = None
    logic_graph: Optional[Dict] = None
    comparison_result: Optional[Dict] = None
    security_insights: Optional[Dict] = None
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())


class AnalysisContext:
    """
    Thread-safe context for managing analysis state.
    
    Replaces scattered global caches with a unified, thread-safe container.
    Each analysis session gets its own context, enabling parallel processing.
    
    Usage:
        # Create context for an analysis
        ctx = AnalysisContext(driver_a_path, driver_b_path)
        
        # Store results
        ctx.set_graph('driver_a', graph_data)
        ctx.set_comparison(comparison_result)
        
        # Access results
        graph = ctx.get_graph('driver_a')
        
        # Get snapshot for passing to other components
        state = ctx.get_state()
    """
    
    # Class-level registry for active contexts (for debugging/cleanup)
    _active_contexts: Dict[str, 'AnalysisContext'] = {}
    _registry_lock = threading.Lock()
    
    def __init__(self, driver_a_path: str, driver_b_path: str = None):
        """
        Initialize analysis context.
        
        Args:
            driver_a_path: Path to primary/baseline driver
            driver_b_path: Path to secondary/target driver (optional)
        """
        self.context_id = f"{id(self)}_{datetime.now().strftime('%H%M%S%f')}"
        self.driver_a_path = driver_a_path
        self.driver_b_path = driver_b_path
        self.created_at = datetime.now()
        
        # Thread-safe state storage
        self._lock = threading.RLock()  # Reentrant lock for nested access
        
        # Cached data
        self._graphs: Dict[str, Dict] = {}  # 'driver_a', 'driver_b' -> LogicGraph dict
        self._comparison: Optional[Dict] = None
        self._security_insights: Optional[Dict] = None
        self._anchor_function: Optional[str] = None
        self._ida_client = None
        self._metadata: Dict[str, Any] = {}
        
        # Register this context
        with self._registry_lock:
            self._active_contexts[self.context_id] = self
        
        logger.debug(f"Created AnalysisContext {self.context_id}")
    
    def __enter__(self):
        """Context manager entry."""
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit with cleanup."""
        self.cleanup()
        return False
    
    # =========================================================================
    # Graph Storage
    # =========================================================================
    
    def set_graph(self, key: str, graph: Dict):
        """
        Store a logic graph.
        
        Args:
            key: 'driver_a' or 'driver_b'
            graph: LogicGraph dictionary
        """
        with self._lock:
            self._graphs[key] = graph
            logger.debug(f"[{self.context_id}] Stored graph: {key}")
    
    def get_graph(self, key: str) -> Optional[Dict]:
        """
        Retrieve a logic graph.
        
        Args:
            key: 'driver_a' or 'driver_b'
            
        Returns:
            LogicGraph dictionary or None
        """
        with self._lock:
            return self._graphs.get(key)
    
    def has_both_graphs(self) -> bool:
        """Check if both driver graphs are available."""
        with self._lock:
            return 'driver_a' in self._graphs and 'driver_b' in self._graphs
    
    # =========================================================================
    # Comparison & Insights
    # =========================================================================
    
    def set_comparison(self, comparison: Dict):
        """Store comparison result."""
        with self._lock:
            self._comparison = comparison
    
    def get_comparison(self) -> Optional[Dict]:
        """Get comparison result."""
        with self._lock:
            return self._comparison
    
    def set_security_insights(self, insights: Dict):
        """Store security insights."""
        with self._lock:
            self._security_insights = insights
    
    def get_security_insights(self) -> Optional[Dict]:
        """Get security insights."""
        with self._lock:
            return self._security_insights
    
    # =========================================================================
    # Anchor Function
    # =========================================================================
    
    def set_anchor_function(self, name: str):
        """Set the anchor function name."""
        with self._lock:
            self._anchor_function = name
    
    def get_anchor_function(self) -> Optional[str]:
        """Get the anchor function name."""
        with self._lock:
            return self._anchor_function
    
    # =========================================================================
    # IDA Client
    # =========================================================================
    
    def set_ida_client(self, client):
        """Store IDA client reference for reuse."""
        with self._lock:
            self._ida_client = client
    
    def get_ida_client(self):
        """Get IDA client if available."""
        with self._lock:
            return self._ida_client
    
    # =========================================================================
    # Metadata
    # =========================================================================
    
    def set_metadata(self, key: str, value: Any):
        """Store arbitrary metadata."""
        with self._lock:
            self._metadata[key] = value
    
    def get_metadata(self, key: str, default: Any = None) -> Any:
        """Get metadata value."""
        with self._lock:
            return self._metadata.get(key, default)
    
    # =========================================================================
    # State Management
    # =========================================================================
    
    def get_state(self) -> AnalysisState:
        """
        Get immutable snapshot of current state.
        
        Returns:
            AnalysisState snapshot
        """
        with self._lock:
            return AnalysisState(
                driver_path=self.driver_a_path,
                anchor_function=self._anchor_function,
                logic_graph=self._graphs.get('driver_a'),
                comparison_result=self._comparison,
                security_insights=self._security_insights
            )
    
    def to_dict(self) -> Dict[str, Any]:
        """
        Export context to dictionary.
        
        Returns:
            Dictionary representation of context
        """
        with self._lock:
            return {
                'context_id': self.context_id,
                'driver_a': self.driver_a_path,
                'driver_b': self.driver_b_path,
                'anchor_function': self._anchor_function,
                'has_graph_a': 'driver_a' in self._graphs,
                'has_graph_b': 'driver_b' in self._graphs,
                'has_comparison': self._comparison is not None,
                'has_insights': self._security_insights is not None,
                'created_at': self.created_at.isoformat(),
                'metadata': dict(self._metadata)
            }
    
    def cleanup(self):
        """
        Clean up resources and unregister context.
        
        Call this when done with the context to free memory.
        """
        with self._lock:
            # Close IDA client if present
            if self._ida_client:
                try:
                    self._ida_client.close()
                except Exception as e:
                    logger.warning(f"Error closing IDA client: {e}")
                self._ida_client = None
            
            # Clear caches
            self._graphs.clear()
            self._comparison = None
            self._security_insights = None
            self._metadata.clear()
        
        # Unregister
        with self._registry_lock:
            self._active_contexts.pop(self.context_id, None)
        
        logger.debug(f"Cleaned up AnalysisContext {self.context_id}")
    
    # =========================================================================
    # Class Methods
    # =========================================================================
    
    @classmethod
    def get_active_contexts(cls) -> List[str]:
        """Get list of active context IDs."""
        with cls._registry_lock:
            return list(cls._active_contexts.keys())
    
    @classmethod
    def cleanup_all(cls):
        """Clean up all active contexts."""
        with cls._registry_lock:
            contexts = list(cls._active_contexts.values())
        
        for ctx in contexts:
            ctx.cleanup()
        
        logger.info(f"Cleaned up {len(contexts)} analysis contexts")


# Thread-local storage for current context
_current_context = threading.local()


def get_current_context() -> Optional[AnalysisContext]:
    """Get the current thread's analysis context."""
    return getattr(_current_context, 'context', None)


def set_current_context(ctx: AnalysisContext):
    """Set the current thread's analysis context."""
    _current_context.context = ctx


@contextmanager
def analysis_context(driver_a_path: str, driver_b_path: str = None):
    """
    Context manager for analysis operations.
    
    Usage:
        with analysis_context("driver_a.sys", "driver_b.sys") as ctx:
            ctx.set_graph('driver_a', graph)
            # ... do work ...
        # Context automatically cleaned up
    """
    ctx = AnalysisContext(driver_a_path, driver_b_path)
    old_context = get_current_context()
    set_current_context(ctx)
    
    try:
        yield ctx
    finally:
        set_current_context(old_context)
        ctx.cleanup()
