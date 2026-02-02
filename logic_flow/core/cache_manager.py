"""
Smart Analysis Caching System.

Uses SQLite to cache analysis results to avoid redundant processing of the same drivers.
Persists results based on File Hash + Anchor Function + Tool Version.
"""

import sqlite3
import hashlib
import json
import logging
import os
from datetime import datetime
from typing import Dict, Any, Optional
from pathlib import Path

logger = logging.getLogger(__name__)

# Current Tool Version - change this to invalidate all old cache entries
TOOL_VERSION = "2.1.0"
CACHE_DB_NAME = "analysis_cache.db"

class AnalysisCache:
    """
    Manages a local SQLite database for caching analysis results.
    """
    
    def __init__(self, cache_dir: Optional[str] = None):
        """
        Initialize cache manager.
        
        Args:
            cache_dir: Directory to store cache DB. Defaults to user's .gemini/logic_flow or similar.
                       If None, uses a default local folder.
        """
        if cache_dir:
            self.db_path = Path(cache_dir) / CACHE_DB_NAME
        else:
            # Default to a .cache directory in specific user loc or project root
            # Using project root/.cache for simplicity in this context
            self.db_path = Path("D:/examinate/18/logic_flow_cache") / CACHE_DB_NAME
            
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    def _init_db(self):
        """Initialize the SQLite schema."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                # Create table
                # We key by file_hash AND anchor_function. 
                # Diff tool version invalidates the record logically (we overwrite or ignore).
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS analysis_results (
                        file_hash TEXT,
                        anchor_function TEXT,
                        tool_version TEXT,
                        timestamp TEXT,
                        result_json TEXT,
                        PRIMARY KEY (file_hash, anchor_function)
                    )
                """)
                conn.commit()
        except Exception as e:
            logger.error(f"Failed to initialize cache DB: {e}")

    def get_file_hash(self, file_path: str) -> Optional[str]:
        """Compute SHA256 hash of a file efficiently."""
        try:
            sha256_hash = hashlib.sha256()
            with open(file_path, "rb") as f:
                # Read in chunks for large files
                for byte_block in iter(lambda: f.read(4096), b""):
                    sha256_hash.update(byte_block)
            return sha256_hash.hexdigest()
        except Exception as e:
            logger.warning(f"Failed to hash file {file_path}: {e}")
            return None

    def get_cached_result(self, file_path: str, anchor_function: str) -> Optional[Dict[str, Any]]:
        """
        Retrieve a cached result if it exists and matches the current tool version.
        
        Args:
            file_path: Path to the driver file
            anchor_function: Anchor function used
            
        Returns:
            Result dict or None if miss/invalid
        """
        file_hash = self.get_file_hash(file_path)
        if not file_hash:
            return None
            
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    SELECT result_json, tool_version 
                    FROM analysis_results 
                    WHERE file_hash = ? AND anchor_function = ?
                """, (file_hash, anchor_function))
                
                row = cursor.fetchone()
                
                if row:
                    result_json, cached_version = row
                    
                    # Version Check (Cache Invalidation)
                    if cached_version != TOOL_VERSION:
                        logger.debug(f"Cache miss (Version mismatch: {cached_version} != {TOOL_VERSION})")
                        return None
                        
                    # Cache Hit
                    logger.info(f"Cache HIT for {Path(file_path).name}")
                    return json.loads(result_json)
                    
        except Exception as e:
            logger.warning(f"Cache lookup failed: {e}")
            
        return None

    def cache_result(self, file_path: str, anchor_function: str, result: Dict[str, Any]):
        """
        Save an analysis result to the cache.
        
        Args:
            file_path: Path to the driver file
            anchor_function: Anchor function used
            result: The result dictionary to store
        """
        file_hash = self.get_file_hash(file_path)
        if not file_hash:
            return

        try:
            json_blob = json.dumps(result)
            timestamp = datetime.now().isoformat()
            
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                # Upsert (Replace if exists)
                cursor.execute("""
                    INSERT OR REPLACE INTO analysis_results 
                    (file_hash, anchor_function, tool_version, timestamp, result_json)
                    VALUES (?, ?, ?, ?, ?)
                """, (file_hash, anchor_function, TOOL_VERSION, timestamp, json_blob))
                conn.commit()
                logger.debug(f"Cached result for {Path(file_path).name}")
                
        except Exception as e:
            logger.warning(f"Failed to write to cache: {e}")
