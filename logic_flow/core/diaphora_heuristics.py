"""
Diaphora-inspired Heuristics for Semantic Function Matching.
Part of Module 2 (v2.1): Semantic Diffing.
"""

import logging
import hashlib
from typing import List, Dict, Any, Tuple, Optional

logger = logging.getLogger(__name__)

# Diaphora's classic primes for mnemonics (Subset for demo)
# Maps common x86 mnemonics to small primes
MNEMONIC_PRIMES = {
    'mov': 2, 'lea': 3, 'push': 5, 'pop': 7,
    'call': 11, 'ret': 13, 'xor': 17, 'test': 19,
    'cmp': 23, 'jz': 29, 'jnz': 31, 'jmp': 37,
    'add': 41, 'sub': 43, 'inc': 47, 'dec': 53,
    'imul': 59, 'idiv': 61, 'and': 67, 'or': 71,
    'shl': 73, 'shr': 79, 'nop': 83
}

class DiaphoraMatcher:
    """
    Implements heuristic matching strategies to find similar functions
    between two binaries (reference vs target).
    """

    def __init__(self):
        self.mnemonics_map = MNEMONIC_PRIMES

    def calculate_small_primes_product(self, instructions: List[str]) -> int:
        """
        Calculate the 'Small Primes Product' (SPP) for a sequence of instructions.
        SPP is commutative: Order of instructions (within a block) generally matters 
        less for basic block semantics, or we can use it for the whole function 
        to get a "bag of instructions" signature.
        
        Args:
            instructions: List of mnemonic strings (e.g., ['mov', 'xor', 'call'])
        
        Returns:
            Large integer product. (Note: Can get very large, Python handles arbitrarily large ints).
        """
        product = 1
        for mnemonic in instructions:
            # Normalize mnemonic
            mnem = mnemonic.lower().split()[0] # handle 'rep movsd' etc
            prime = self.mnemonics_map.get(mnem, 1) # Default to 1 (identity) if unknown
            product *= prime
        return product

    def calculate_topology_hash(self, nodes: int, edges: int, out_degree_histogram: List[int]) -> str:
        """
        Generate a hash representing the Graph Topology.
        
        Args:
            nodes: Total basic blocks
            edges: Total edges
            out_degree_histogram: List of out-degrees sorted or bucketed
        """
        # Create a string signature
        sig = f"N{nodes}E{edges}H{'-'.join(map(str, sorted(out_degree_histogram)))}"
        return hashlib.md5(sig.encode()).hexdigest()

    def calculate_function_fingerprint(self, func_graph: Any) -> Dict[str, Any]:
        """
        Generate a complete fingerprint for a function (using Angr CFG or LogicGraph).
        
        Args:
            func_graph: Expected to be an object with .nodes, .edges or similar.
                        Ideally compatible with our LogicGraph or Angr Function.
        """
        # Adapt extractors based on object type
        # For now assuming generic logic
        
        instruction_list = []
        node_count = 0
        edge_count = 0
        out_degrees = []

        is_angr = hasattr(func_graph, 'blocks') # Angr Function
        is_logic_graph = hasattr(func_graph, 'to_dict') # Our LogicGraph
        
        if is_angr:
            node_count = len(list(func_graph.blocks))
            # Angr graph extraction (simplified)
            # Need to iterate blocks and count instructions
            for block in func_graph.blocks:
                # get capstone instructions if available, or VEX
                # This depends on what's lifted. Assuming capstone for mnemonics
                if hasattr(block, 'capstone'):
                    for insn in block.capstone.insns:
                        instruction_list.append(insn.mnemonic)
                
                # Out degree
                out_degrees.append(len(list(func_graph.graph.successors(block))))
                
        elif is_logic_graph:
            # This is harder as LogicGraph is function-call graph, not basic-block graph usually
            # But maybe we are doing sub-graph matching?
            # Or maybe func_graph IS the whole graph?
            # Let's assume passed object represents 'Function' level details
            pass 

        # 1. SPP
        spp = self.calculate_small_primes_product(instruction_list)
        
        # 2. Topology
        topo_hash = self.calculate_topology_hash(node_count, edge_count, out_degrees)

        return {
            "spp": str(spp), # Stringify big int
            "topo_hash": topo_hash,
            "node_count": node_count,
            "instruction_count": len(instruction_list)
        }

    def compare_fingerprints(self, fp1: Dict, fp2: Dict) -> float:
        """
        Compare two fingerprints and return a similarity score (0.0 to 1.0).
        """
        score = 0.0
        
        # 1. Exact Topology Match (High Confidence)
        if fp1['topo_hash'] == fp2['topo_hash']:
            score += 0.4
            
        # 2. SPP Match (Instruction Set Match)
        if fp1['spp'] == fp2['spp']:
            score += 0.4
        
        # 3. Size similarity
        if fp1['node_count'] > 0 and fp2['node_count'] > 0:
            count_diff = abs(fp1['node_count'] - fp2['node_count'])
            if count_diff == 0:
                score += 0.2
            elif count_diff < 3:
                score += 0.1
                
        return min(score, 1.0)
