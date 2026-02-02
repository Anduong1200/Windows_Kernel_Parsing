"""
Fuzzy Hashing Module for Function Similarity Detection.

Implements TLSH (Trend Micro Locality Sensitive Hash) and SSDeep for
comparing function bytecode similarity independent of address differences.

This enables detecting similar functions even when:
- Code is compiled with different optimizations
- Constants have changed
- Minor modifications have been made
"""

import logging
from typing import Optional, Dict, Tuple, List
from dataclasses import dataclass

logger = logging.getLogger(__name__)

# Try to import TLSH library
_TLSH_AVAILABLE = False
try:
    import tlsh
    _TLSH_AVAILABLE = True
except ImportError:
    logger.warning("tlsh library not installed. Install with: pip install py-tlsh")

# Try to import SSDeep library  
_SSDEEP_AVAILABLE = False
try:
    import ssdeep
    _SSDEEP_AVAILABLE = True
except ImportError:
    logger.debug("ssdeep library not installed (optional)")


@dataclass
class FunctionHash:
    """Container for function hash data."""
    address: int
    name: str
    size: int
    tlsh_hash: Optional[str] = None
    ssdeep_hash: Optional[str] = None
    instruction_hash: Optional[str] = None  # Custom opcode-based hash


def is_available() -> bool:
    """Check if any fuzzy hashing library is available."""
    return _TLSH_AVAILABLE or _SSDEEP_AVAILABLE


def get_available_algorithms() -> List[str]:
    """Return list of available hashing algorithms."""
    algos = []
    if _TLSH_AVAILABLE:
        algos.append("tlsh")
    if _SSDEEP_AVAILABLE:
        algos.append("ssdeep")
    algos.append("opcode")  # Always available (custom implementation)
    return algos


def compute_tlsh(data: bytes) -> Optional[str]:
    """
    Compute TLSH hash of binary data.
    
    Args:
        data: Raw bytes to hash (typically function bytecode)
        
    Returns:
        TLSH hash string or None if data too small
    """
    if not _TLSH_AVAILABLE:
        return None
    
    if len(data) < 50:  # TLSH needs minimum data
        return None
    
    try:
        h = tlsh.hash(data)
        return h if h else None
    except Exception as e:
        logger.debug(f"TLSH computation failed: {e}")
        return None


def compute_ssdeep(data: bytes) -> Optional[str]:
    """
    Compute SSDeep fuzzy hash of binary data.
    
    Args:
        data: Raw bytes to hash
        
    Returns:
        SSDeep hash string or None
    """
    if not _SSDEEP_AVAILABLE:
        return None
    
    try:
        return ssdeep.hash(data)
    except Exception as e:
        logger.debug(f"SSDeep computation failed: {e}")
        return None


def compute_opcode_hash(opcodes: List[str]) -> str:
    """
    Compute a simple hash based on opcode sequence.
    This is a fallback when TLSH/SSDeep are not available.
    
    Args:
        opcodes: List of instruction mnemonics
        
    Returns:
        Hash string
    """
    import hashlib
    
    # Normalize opcodes to instruction classes for resistance to minor changes
    normalized = []
    for op in opcodes:
        op_lower = op.lower()
        if op_lower in ('mov', 'lea', 'push', 'pop', 'xchg'):
            normalized.append('T')  # Transfer
        elif op_lower in ('add', 'sub', 'mul', 'div', 'inc', 'dec'):
            normalized.append('A')  # Arithmetic
        elif op_lower in ('call', 'ret', 'retn'):
            normalized.append('C')  # Call/Return
        elif op_lower in ('jmp', 'je', 'jne', 'jz', 'jnz', 'jg', 'jl', 'ja', 'jb'):
            normalized.append('J')  # Jump
        elif op_lower in ('and', 'or', 'xor', 'not', 'shl', 'shr'):
            normalized.append('L')  # Logic
        elif op_lower in ('cmp', 'test'):
            normalized.append('P')  # comPare
        else:
            normalized.append('X')  # Other
    
    # Create hash of normalized sequence
    # Create a simplified fuzzy signature (LSH-like)
    # Count transitions between instruction classes (Bigrams)
    # Format: "TA:12|AJ:5|..."
    
    bigrams = {}
    for i in range(len(normalized) - 1):
        pair = normalized[i] + normalized[i+1]
        bigrams[pair] = bigrams.get(pair, 0) + 1
        
    # Sort and create string
    sorted_grams = sorted(bigrams.items())
    sig_parts = [f"{g}:{c}" for g, c in sorted_grams]
    
    # Also include length bucket to distinguish wildly different sizes
    len_bucket = min(len(normalized) // 10, 99)
    
    return f"L{len_bucket}|" + "|".join(sig_parts)


def compare_tlsh(hash1: str, hash2: str) -> int:
    """
    Compare two TLSH hashes.
    
    Args:
        hash1: First TLSH hash
        hash2: Second TLSH hash
        
    Returns:
        Similarity score 0-100 (100 = identical)
        TLSH returns distance (0 = identical), we invert to similarity
    """
    if not _TLSH_AVAILABLE or not hash1 or not hash2:
        return 0
    
    try:
        # TLSH diff returns distance: 0 = identical, higher = different
        distance = tlsh.diff(hash1, hash2)
        
        # Convert distance to similarity (0-100)
        # TLSH distances typically range 0-400+
        # Map 0 -> 100, 100 -> 75, 200 -> 50, 400 -> 0
        similarity = max(0, 100 - (distance // 4))
        return similarity
    except Exception as e:
        logger.debug(f"TLSH comparison failed: {e}")
        return 0


def compare_ssdeep(hash1: str, hash2: str) -> int:
    """
    Compare two SSDeep hashes.
    
    Args:
        hash1: First SSDeep hash
        hash2: Second SSDeep hash
        
    Returns:
        Similarity score 0-100 (100 = identical)
    """
    if not _SSDEEP_AVAILABLE or not hash1 or not hash2:
        return 0
    
    try:
        return ssdeep.compare(hash1, hash2)
    except Exception as e:
        logger.debug(f"SSDeep comparison failed: {e}")
        return 0


def compare_opcode_hash(hash1: str, hash2: str) -> int:
    """
    Compare two opcode hashes.
    
    Args:
        hash1: First opcode hash
        hash2: Second opcode hash
        
    Returns:
        Similarity score 0-100
    """
    if hash1 == hash2:
        return 100
    
    # LSH format: L10|TA:5|AJ:2...
    if not hash1 or "|" not in hash1 or not hash2 or "|" not in hash2:
        return 0

    try:
        parts1 = hash1.split('|')
        parts2 = hash2.split('|')
        
        # Parse bigrams into dicts
        def parse_sig(parts):
            counts = {}
            for p in parts:
                if ':' in p:
                    k, v = p.split(':')
                    counts[k] = int(v)
            return counts
            
        dict1 = parse_sig(parts1)
        dict2 = parse_sig(parts2)
        
        if not dict1 or not dict2:
            return 0
            
        # Weighted Jaccard / Cosine-like similarity
        all_keys = set(dict1.keys()) | set(dict2.keys())
        intersection = 0
        union = 0
        
        for k in all_keys:
            v1 = dict1.get(k, 0)
            v2 = dict2.get(k, 0)
            intersection += min(v1, v2)
            union += max(v1, v2)
            
        if union == 0:
            return 100
            
        return int((intersection / union) * 100)
    except:
        return 0


class FunctionHasher:
    """
    High-level interface for hashing functions and comparing similarity.
    """
    
    def __init__(self, ida_provider=None, config=None):
        """
        Initialize hasher.
        
        Args:
            ida_provider: IDA provider for reading function bytes
            config: HeuristicsConfig for thresholds
        """
        self.ida_provider = ida_provider
        self.config = config
        self._cache: Dict[int, FunctionHash] = {}
    
    def hash_function(self, func_ea: int) -> Optional[FunctionHash]:
        """
        Compute fuzzy hash for a function.
        
        Args:
            func_ea: Function address
            
        Returns:
            FunctionHash object with computed hashes
        """
        # Check cache
        if func_ea in self._cache:
            return self._cache[func_ea]
        
        if not self.ida_provider:
            return None
        
        try:
            # Get function info
            func_name = self.ida_provider.get_func_name(func_ea) or f"sub_{func_ea:X}"
            func_bytes = self.ida_provider.get_func_bytes(func_ea)
            
            if not func_bytes or len(func_bytes) < 10:
                return None
            
            # Compute hashes
            fh = FunctionHash(
                address=func_ea,
                name=func_name,
                size=len(func_bytes),
                tlsh_hash=compute_tlsh(func_bytes),
                ssdeep_hash=compute_ssdeep(func_bytes)
            )
            
            # Compute opcode hash using instructions
            opcodes = self.ida_provider.get_func_opcodes(func_ea)
            if opcodes:
                fh.instruction_hash = compute_opcode_hash(opcodes)
            
            self._cache[func_ea] = fh
            return fh
            
        except Exception as e:
            logger.debug(f"Failed to hash function 0x{func_ea:X}: {e}")
            return None
    
    def compare_functions(self, func_a: int, func_b: int) -> Dict[str, int]:
        """
        Compare two functions using all available hash algorithms.
        
        Args:
            func_a: First function address
            func_b: Second function address
            
        Returns:
            Dictionary of algorithm -> similarity score (0-100)
        """
        hash_a = self.hash_function(func_a)
        hash_b = self.hash_function(func_b)
        
        result = {
            'tlsh': 0,
            'ssdeep': 0,
            'opcode': 0,
            'best': 0
        }
        
        if not hash_a or not hash_b:
            return result
        
        # TLSH comparison
        if hash_a.tlsh_hash and hash_b.tlsh_hash:
            result['tlsh'] = compare_tlsh(hash_a.tlsh_hash, hash_b.tlsh_hash)
        
        # SSDeep comparison
        if hash_a.ssdeep_hash and hash_b.ssdeep_hash:
            result['ssdeep'] = compare_ssdeep(hash_a.ssdeep_hash, hash_b.ssdeep_hash)
        
        # Opcode comparison
        if hash_a.instruction_hash and hash_b.instruction_hash:
            result['opcode'] = compare_opcode_hash(hash_a.instruction_hash, hash_b.instruction_hash)
        
        # Best score
        result['best'] = max(result['tlsh'], result['ssdeep'], result['opcode'])
        
        return result
    
    def find_similar_functions(self, target_ea: int, candidates: List[int], 
                               threshold: int = 70) -> List[Tuple[int, int]]:
        """
        Find functions similar to target from a list of candidates.
        
        Args:
            target_ea: Target function address
            candidates: List of candidate function addresses
            threshold: Minimum similarity score (0-100)
            
        Returns:
            List of (address, score) tuples sorted by score descending
        """
        results = []
        
        for candidate_ea in candidates:
            if candidate_ea == target_ea:
                continue
            
            scores = self.compare_functions(target_ea, candidate_ea)
            best_score = scores['best']
            
            if best_score >= threshold:
                results.append((candidate_ea, best_score))
        
        # Sort by score descending
        results.sort(key=lambda x: x[1], reverse=True)
        return results
    
    def clear_cache(self):
        """Clear the hash cache."""
        self._cache.clear()
