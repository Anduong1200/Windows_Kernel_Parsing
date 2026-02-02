"""
Similarity Search Engine for 1-Day Exploit Hunting.
Part of Phase 9 / Module 6: Exploit Hunting.

Goal: Find variants of known vulnerable functions using semantic vectorization and cosine similarity.
"""

import logging
import math
import json
from typing import List, Dict, Any, Tuple
from .diaphora_heuristics import DiaphoraMatcher

logger = logging.getLogger(__name__)

class FunctionVector:
    """
    Represents a function's semantic properties as a numerical vector.
    Components:
    0: Node Count
    1: Edge Count
    2: Cyclomatic Complexity (Edges - Nodes + 2)
    3: Small Primes Product (SPP) Logic Hash (normalized/log scale)
    4: Topology Hash (Integer representation of hash)
    5: Feature Flags (e.g., has_call_to_memcpy) - Binary 0/1
    """
    def __init__(self, vector: List[float], meta: Dict[str, Any]):
        self.vector = vector
        self.meta = meta  # {driver_name, func_addr, func_name}

class SimilarityEngine:
    """
    Vector Database and Search Engine for Semantic Function Matching.
    """
    
    def __init__(self):
        self.db: List[FunctionVector] = []
        self.matcher = DiaphoraMatcher()
        
    def vectorize_function(self, func_graph: Any, meta: Dict[str, Any]) -> FunctionVector:
        """
        Convert a Graph/Function object into a fixed-length vector.
        """
        # 1. Extract Heuristics using Module 2
        fp = self.matcher.calculate_function_fingerprint(func_graph)
        
        # 2. Normalize/Transform components
        # Log scale for sizes to reduce impact of massive functions vs large functions
        v_nodes = math.log(fp['node_count'] + 1)
        # Reconstruct edges if not explicitly returned by fingerprint (fp currently just has counts)
        # For now, let's assume we pass a rich object or extend fingerprint. 
        # Using fingerprint data:
        v_insns = math.log(fp['instruction_count'] + 1)
        
        # SPP is huge, use log or module. Log is good for magnitude.
        spp_val = int(fp['spp'])
        v_spp = math.log(spp_val + 1) if spp_val > 0 else 0
        
        # Topo Hash is hex string -> convert first 8 chars to float for "locality" (rough heuristic)
        # A true locality-sensitive hash would be better, but this is a "Pseudo" vector.
        v_topo = int(fp['topo_hash'][:8], 16) / 0xFFFFFFFF
        
        vector = [v_nodes, v_insns, v_spp, v_topo]
        
        return FunctionVector(vector, meta)

    def index_driver(self, driver_name: str, functions: List[Any]):
        """
        Add all functions from a driver to the search index (Heuristic Mode).
        """
        count = 0
        for func in functions:
            # Assume func has .addr and .name
            meta = {
                "driver": driver_name,
                "addr": func.addr if hasattr(func, 'addr') else 0,
                "name": func.name if hasattr(func, 'name') else "sub_X"
            }
            vec = self.vectorize_function(func, meta)
            self.db.append(vec)
            count += 1
        logger.info(f"Indexed {count} functions from {driver_name} (Heuristic Mode)")

    # --- v2.3 ML Capabilities ---
    
    def init_ml_backend(self):
        """Initialize FAISS and Transformer model if available."""
        try:
            import faiss
            from sentence_transformers import SentenceTransformer
            self.ml_model = SentenceTransformer('all-MiniLM-L6-v2')
            self.faiss_index = None # Will init based on dimension
            self.ml_ready = True
            logger.info("ML Backend initialized (FAISS + SentenceTransformers).")
        except ImportError:
            logger.warning("ML libraries (faiss/sentence-transformers) not found. ML Search disabled.")
            self.ml_ready = False

    def embed_function(self, ir_text: str) -> List[float]:
        """Generate Dense Embedding from IR Text."""
        if not hasattr(self, 'ml_ready') or not self.ml_ready:
            return []
        return self.ml_model.encode(ir_text).tolist()

    def build_faiss_index(self, dimension: int = 384):
        """Create FAISS index."""
        if self.ml_ready and self.faiss_index is None:
            import faiss
            self.faiss_index = faiss.IndexFlatL2(dimension)
    
    def add_to_faiss(self, embedding: List[float], meta: Dict[str, Any]):
        """Add vector to FAISS."""
        if self.ml_ready and self.faiss_index:
            # Note: FAISS usually requires numpy arrays. 
            # In a real impl we'd batch this. Placeholder logic.
            pass

    # ----------------------------

    def find_similar_functions(self, query_func: Any, top_k: int = 5, threshold: float = 0.85) -> List[Dict[str, Any]]:
        """
        Search for functions semantically similar to the query function.
        Uses Cosine Similarity on Heuristic Vectors.
        """
        query_vec = self.vectorize_function(query_func, {}).vector
        results = []
        
        for item in self.db:
            score = self._cosine_similarity(query_vec, item.vector)
            if score >= threshold:
                results.append({
                    "score": score,
                    "driver": item.meta['driver'],
                    "function": item.meta['name'],
                    "address": hex(item.meta['addr']),
                    "vector_debug": item.vector
                })
        
        # Sort by score descending
        results.sort(key=lambda x: x['score'], reverse=True)
        return results[:top_k]

    def _cosine_similarity(self, v1: List[float], v2: List[float]) -> float:
        """Calculate Cosine Similarity between two vectors."""
        if len(v1) != len(v2):
            return 0.0
            
        dot_product = sum(a * b for a, b in zip(v1, v2))
        norm_v1 = math.sqrt(sum(a * a for a in v1))
        norm_v2 = math.sqrt(sum(b * b for b in v2))
        
        if norm_v1 == 0 or norm_v2 == 0:
            return 0.0
            
        return dot_product / (norm_v1 * norm_v2)

    def save_db(self, path: str):
        """Save vector DB to JSON."""
        data = []
        for item in self.db:
            data.append({
                "vec": item.vector,
                "meta": item.meta
            })
        with open(path, 'w') as f:
            json.dump(data, f)
            
    def load_db(self, path: str):
        """Load vector DB from JSON."""
        with open(path, 'r') as f:
            data = json.load(f)
        self.db = []
        for d in data:
            self.db.append(FunctionVector(d['vec'], d['meta']))
