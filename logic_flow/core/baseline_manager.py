"""
Baseline Manager for Logic Flow Analysis

Manages saving and loading baseline signatures to enable efficient
comparisons without re-analyzing the reference driver.
"""

import os
import json
import logging
from pathlib import Path
from typing import Dict, List, Optional, Any
from datetime import datetime

from .logic_graph import LogicGraph
from ..utils.config import ConfigManager

logger = logging.getLogger(__name__)


class BaselineSignature:
    """Represents a saved baseline signature"""

    def __init__(self, name: str, driver_path: str, graph: LogicGraph,
                 metadata: Optional[Dict[str, Any]] = None):
        self.name = name
        self.driver_path = driver_path
        self.graph = graph
        self.metadata = metadata or {}
        self.created_at = datetime.now().isoformat()
        self.signature_id = f"{name}_{int(datetime.now().timestamp())}"

    def to_dict(self) -> Dict[str, Any]:
        """Convert signature to dictionary for serialization"""
        return {
            "signature_id": self.signature_id,
            "name": self.name,
            "driver_path": self.driver_path,
            "created_at": self.created_at,
            "metadata": self.metadata,
            "graph_data": self.graph.to_dict()
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'BaselineSignature':
        """Create signature from dictionary"""
        graph = LogicGraph.from_dict(data["graph_data"])
        signature = cls(
            name=data["name"],
            driver_path=data["driver_path"],
            graph=graph,
            metadata=data.get("metadata", {})
        )
        signature.created_at = data.get("created_at", signature.created_at)
        signature.signature_id = data.get("signature_id", signature.signature_id)
        return signature


class BaselineManager:
    """
    Manages baseline signatures for efficient driver comparisons.

    Allows saving baseline signatures from reference drivers and loading them
    for subsequent comparisons without re-analysis.
    """

    def __init__(self):
        self.config_manager = ConfigManager()
        self.baselines_dir = self.config_manager.get_config_value('baselines_dir')
        if not self.baselines_dir:
            self.baselines_dir = self.config_manager.config_dir / "baselines"
            self.config_manager.set_config_value('baselines_dir', str(self.baselines_dir))

        self.baselines_dir = Path(self.baselines_dir)
        self.baselines_dir.mkdir(exist_ok=True)

        # Cache loaded signatures
        self._signature_cache: Dict[str, BaselineSignature] = {}

    def save_baseline(self, name: str, driver_path: str, graph: LogicGraph,
                     metadata: Optional[Dict[str, Any]] = None) -> str:
        """
        Save a baseline signature.

        Args:
            name: Human-readable name for the baseline
            driver_path: Path to the driver file
            graph: LogicGraph to save as baseline
            metadata: Optional metadata

        Returns:
            Path to the saved signature file
        """
        signature = BaselineSignature(name, driver_path, graph, metadata)

        # Save to file
        filename = f"{signature.signature_id}.json"
        filepath = self.baselines_dir / filename

        try:
            with open(filepath, 'w', encoding='utf-8') as f:
                json.dump(signature.to_dict(), f, indent=2, default=str)

            logger.info(f"Saved baseline signature: {name} -> {filepath}")

            # Add to cache
            self._signature_cache[signature.signature_id] = signature

            return str(filepath)

        except Exception as e:
            logger.error(f"Failed to save baseline {name}: {e}")
            raise

    def load_baseline(self, signature_id: str) -> Optional[BaselineSignature]:
        """
        Load a baseline signature by ID.

        Args:
            signature_id: Signature ID to load

        Returns:
            BaselineSignature if found, None otherwise
        """
        # Check cache first
        if signature_id in self._signature_cache:
            return self._signature_cache[signature_id]

        # Load from file
        filepath = self.baselines_dir / f"{signature_id}.json"
        if not filepath.exists():
            return None

        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                data = json.load(f)

            signature = BaselineSignature.from_dict(data)

            # Add to cache
            self._signature_cache[signature_id] = signature

            logger.info(f"Loaded baseline signature: {signature.name}")
            return signature

        except Exception as e:
            logger.error(f"Failed to load baseline {signature_id}: {e}")
            return None

    def list_baselines(self) -> List[Dict[str, Any]]:
        """
        List all available baseline signatures.

        Returns:
            List of baseline info dictionaries
        """
        baselines = []

        try:
            for filepath in self.baselines_dir.glob("*.json"):
                try:
                    with open(filepath, 'r', encoding='utf-8') as f:
                        data = json.load(f)

                    baselines.append({
                        "signature_id": data.get("signature_id", filepath.stem),
                        "name": data.get("name", "Unknown"),
                        "driver_path": data.get("driver_path", "Unknown"),
                        "created_at": data.get("created_at", "Unknown"),
                        "filepath": str(filepath)
                    })

                except Exception as e:
                    logger.warning(f"Failed to read baseline file {filepath}: {e}")

        except Exception as e:
            logger.error(f"Failed to list baselines: {e}")

        # Sort by creation date (newest first)
        baselines.sort(key=lambda x: x.get("created_at", ""), reverse=True)

        return baselines

    def delete_baseline(self, signature_id: str) -> bool:
        """
        Delete a baseline signature.

        Args:
            signature_id: Signature ID to delete

        Returns:
            True if deleted successfully, False otherwise
        """
        try:
            # Remove from cache
            if signature_id in self._signature_cache:
                del self._signature_cache[signature_id]

            # Delete file
            filepath = self.baselines_dir / f"{signature_id}.json"
            if filepath.exists():
                filepath.unlink()
                logger.info(f"Deleted baseline signature: {signature_id}")
                return True
            else:
                logger.warning(f"Baseline file not found: {signature_id}")
                return False

        except Exception as e:
            logger.error(f"Failed to delete baseline {signature_id}: {e}")
            return False

    def get_baseline_info(self, signature_id: str) -> Optional[Dict[str, Any]]:
        """
        Get information about a baseline signature.

        Args:
            signature_id: Signature ID

        Returns:
            Dictionary with baseline info, or None if not found
        """
        signature = self.load_baseline(signature_id)
        if not signature:
            return None

        return {
            "signature_id": signature.signature_id,
            "name": signature.name,
            "driver_path": signature.driver_path,
            "created_at": signature.created_at,
            "metadata": signature.metadata,
            "graph_summary": signature.graph.get_graph_summary()
        }
