
import sys
import os
import logging

# Add project root to path
sys.path.append(os.path.abspath(r"d:\examinate\18\project"))

# Configure logging
logging.basicConfig(level=logging.INFO)

from logic_flow.core.ida_provider import MockIDAProvider, IDAProvider
from logic_flow.core import diff_reflecting

def verify_refactor():
    print("Verifying diff_reflecting.py refactor...")
    
    # 1. Create Mock Provider
    provider = MockIDAProvider()
    print(f"Provider created: {provider}")

    # 2. Verify basic provider methods
    print(f"Mnemonic at 0x1000: {provider.get_mnemonic(0x1000)}")
    print(f"String at 0x1000: {provider.get_string(0x1000)}")

    # 3. Test build_bounded_graph (which triggers deep analysis)
    # Mock address: 0x1000 (NtCreateFile)
    try:
        print("Testing build_bounded_graph with explicit Context...")
        
        # Create AnalysisContext with our mock provider
        context = diff_reflecting.AnalysisContext(provider)
        
        # Build graph using context
        graph = diff_reflecting.build_bounded_graph(0x1000, max_depth=2, context=context)
        print(f"Graph built successfully. Nodes: {len(graph.nodes)}")
        
    except Exception as e:
        print(f"FAILED: build_bounded_graph raised exception: {e}")
        import traceback
        traceback.print_exc()
        return False

    # 4. Test find_semantic_candidates
    try:
        print("Testing find_semantic_candidates with explicit Context...")
        candidates = diff_reflecting.find_semantic_candidates(graph, max_candidates=5, context=context)
        print(f"Candidates found: {len(candidates)}")
    except Exception as e:
        print(f"FAILED: find_semantic_candidates raised exception: {e}")
        import traceback
        traceback.print_exc()
        return False

    print("VERIFICATION SUCCESSFUL: Refactor seems stable.")
    return True

if __name__ == "__main__":
    verify_refactor()
