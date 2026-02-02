"""
Batch Processing Utilities for Logic Flow Analysis.

Provides safe parallel execution for driver analysis using ProcessPoolExecutor
to ensure complete isolation of IDA instances.
"""

import os
import json
import logging
import multiprocessing
import tempfile
import shutil
import time
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from concurrent.futures import ProcessPoolExecutor, as_completed

# Configure logger for this module
logger = logging.getLogger(__name__)


@dataclass
class AnalysisResult:
    """Result from a single driver analysis."""
    driver_path: str
    success: bool
    anchor_function: Optional[str] = None
    node_count: int = 0
    edge_count: int = 0
    logic_graph: Optional[Dict] = None
    error: Optional[str] = None
    duration_seconds: float = 0.0
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())


def _run_single_analysis_safe(
    driver_path: str, 
    ida_path: str,
    anchor_function: str,
    progress_queue: Optional[Any] = None
) -> Dict[str, Any]:
    """
    Pure top-level wrapper function for analyzing a single driver.
    Must be top-level for pickling support in ProcessPoolExecutor.
    
    Handles:
    1. Process Isolation (Safe from global state contamination)
    2. Temp Directory Isolation (Unique workspace per analysis)
    3. Exception Safety (Catches all crashes)
    """
    start_time = time.time()
    
    # Create unique isolation directory for this process
    # This prevents IDA instances from stomping on each other's IDB files
    process_name = multiprocessing.current_process().name
    isolation_dir = tempfile.mkdtemp(prefix=f"ida_iso_{os.getpid()}_")
    
    try:
        from .analyzer import IDAAnalysisRunner
        
        # Override temp directory logic if possible, or reliance on CWD
        # For now, we rely on IDAAnalysisRunner handling paths correctly.
        # Ideally, we would tell IDA to use this isolation_dir for its database.
        
        # Note: We can instantiate valid objects here because we are in a fresh process
        runner = IDAAnalysisRunner(ida_path)
        
        # Run the analysis
        # We assume run_analysis handles the actual IDA spawn
        result = runner.run_analysis(driver_path, {
            "anchor_function": anchor_function
        })
        
        duration = time.time() - start_time
        
        # Check for logic errors passed back in the result dict
        if 'error' in result:
             # Construct failure result
            final_result = {
                "driver_path": driver_path,
                "success": False,
                "error": result['error'],
                "duration_seconds": duration,
                "timestamp": datetime.now().isoformat()
            }
        else:
            # Construct success result
            graph_data = result.get('logic_graph', {})
            final_result = {
                "driver_path": driver_path,
                "success": True,
                "anchor_function": result.get('anchor_function'),
                "node_count": len(graph_data.get('nodes', [])),
                "edge_count": len(graph_data.get('edges', [])),
                "logic_graph": graph_data,
                "duration_seconds": duration,
                "timestamp": datetime.now().isoformat()
            }

    except Exception as e:
        # Catch-all for crash/exception in the worker process
        duration = time.time() - start_time
        final_result = {
            "driver_path": driver_path,
            "success": False,
            "error": str(e),
            "duration_seconds": duration,
            "timestamp": datetime.now().isoformat()
        }
    
    finally:
        # Cleanup isolation directory
        try:
            shutil.rmtree(isolation_dir, ignore_errors=True)
        except Exception:
            pass
            
        # Report progress
        if progress_queue:
            progress_queue.put(1)
            
    return final_result


class BatchReportAggregator:
    """Thread-safe aggregator for merging results."""
    
    def __init__(self):
        # Since we are aggregating in the main process, simple list/dict is fine
        # We don't need locks if we process results sequentially as they arrive
        self._results: List[AnalysisResult] = []
        self._start_time = datetime.now()
        self._errors: List[Dict] = []
    
    def add_result(self, result_dict: Dict[str, Any]):
        """Safely add a result dictionary from a worker."""
        # Convert dict back to dataclass
        try:
            res = AnalysisResult(
                driver_path=result_dict['driver_path'],
                success=result_dict['success'],
                anchor_function=result_dict.get('anchor_function'),
                node_count=result_dict.get('node_count', 0),
                edge_count=result_dict.get('edge_count', 0),
                logic_graph=result_dict.get('logic_graph'),
                error=result_dict.get('error'),
                duration_seconds=result_dict.get('duration_seconds', 0.0),
                timestamp=result_dict.get('timestamp')
            )
            self._results.append(res)
            
            if not res.success:
                 self._errors.append({
                    'driver': res.driver_path,
                    'error': res.error,
                    'timestamp': res.timestamp
                })
                
        except Exception as e:
            logger.error(f"Failed to aggregate result: {e}")
            
    def get_report(self) -> Dict[str, Any]:
        """Generate summary report."""
        end_time = datetime.now()
        duration = (end_time - self._start_time).total_seconds()
        
        return {
            'batch_id': self._start_time.strftime('%Y%m%d_%H%M%S'),
            'summary': {
                'total_drivers': len(self._results),
                'successful': sum(1 for r in self._results if r.success),
                'failed': sum(1 for r in self._results if not r.success),
                'duration_seconds': round(duration, 2),
                'start_time': self._start_time.isoformat(),
                'end_time': end_time.isoformat()
            },
            'results': [
                {
                    'driver': r.driver_path,
                    'success': r.success,
                    'anchor': r.anchor_function,
                    'nodes': r.node_count,
                    'edges': r.edge_count,
                    'error': r.error,
                    'duration': r.duration_seconds
                }
                for r in self._results
            ],
            'errors': self._errors
        }
        
    def save_report(self, output_path: str):
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(self.get_report(), f, indent=2)

    def clear(self):
        self._results.clear()
        self._errors.clear()
        self._start_time = datetime.now()


class BatchAnalysisRunner:
    """
    Orchestrates parallel driver analysis using ProcessPoolExecutor.
    """
    
    def __init__(self, ida_path: str, max_workers: int = None):
        """
        Args:
            ida_path: Path to IDA executable
            max_workers: Defaults to CPU count if None
        """
        self.ida_path = ida_path
        self.max_workers = max_workers or os.cpu_count()
        self.aggregator = BatchReportAggregator()
        self._cancelled = False
        
        # Use Manager for sharing Loop/Queue objects safely
        self._manager = multiprocessing.Manager()
    
    def analyze_drivers(self, driver_paths: List[str], anchor_function: str,
                        progress_callback: Optional[callable] = None) -> Dict[str, Any]:
        """
        Run parallel analysis.
        """
        self.aggregator.clear()
        self._cancelled = False
        total = len(driver_paths)
        
        # Create a shared Queue for progress updates
        progress_queue = self._manager.Queue()
        
        # Initialize Cache
        from .cache_manager import AnalysisCache
        cache = AnalysisCache()
        
        logger.info(f"Starting batch analysis of {total} drivers with {self.max_workers} workers.")
        
        with ProcessPoolExecutor(max_workers=self.max_workers) as executor:
            future_to_driver = {}
            
            # 1. OPTIMIZATION: Check Cache First
            for driver_path in driver_paths:
                cached_result = cache.get_cached_result(driver_path, anchor_function)
                
                if cached_result:
                    # Cache HIT: Add directly to aggregator
                    # Ensure the result structure matches what aggregator expects
                    # The cached blob is the exact dict we returned from _run_single_analysis_safe (mostly)
                    # We might need to ensure 'driver_path' is correct if the file moved (hash same, path diff)
                    # But here driver_path is known.
                    
                    # We need to normalize cached result to include runtime fields if missing
                    cached_result['driver_path'] = driver_path # Ensure path matches current request
                    cached_result['timestamp'] = datetime.now().isoformat() # Update timestamp to "now" for report? Or keep original? user likely prefers "checked now".
                    
                    self.aggregator.add_result(cached_result)
                    
                    # Report progress immediately
                    completed += 1
                    if progress_callback:
                        progress_callback(completed, total)
                else:
                    # Cache MISS: Submit to Executor
                    future = executor.submit(
                        _run_single_analysis_safe, 
                        driver_path, 
                        self.ida_path, 
                        anchor_function,
                        progress_queue
                    )
                    future_to_driver[future] = driver_path

            # 2. Process Futures (Cache Misses)
            for future in as_completed(future_to_driver):
                if self._cancelled:
                    executor.shutdown(wait=False, cancel_futures=True)
                    break
                
                path = future_to_driver[future]
                try:
                    result_dict = future.result()
                    self.aggregator.add_result(result_dict)
                    
                    # SAVE TO CACHE if successful
                    if result_dict.get('success'):
                        cache.cache_result(path, anchor_function, result_dict)
                        
                except Exception as e:
                    logger.error(f"Executor wrapper failed for {path}: {e}")
                    self.aggregator.add_error(path, str(e))
                
                completed += 1
                if progress_callback:
                    progress_callback(completed, total)

        return self.aggregator.get_report()

    def cancel(self):
        self._cancelled = True


# Convenience function remains similar
def run_batch_analysis(ida_path: str, driver_paths: List[str], 
                       anchor_function: str, output_path: str = None,
                       max_workers: int = None) -> Dict[str, Any]:
    runner = BatchAnalysisRunner(ida_path, max_workers)
    report = runner.analyze_drivers(driver_paths, anchor_function)
    
    if output_path:
        runner.aggregator.save_report(output_path)
    
    return report
