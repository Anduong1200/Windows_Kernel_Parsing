
import sys
import os

# Add project root to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from logic_flow.core.logic_graph import LogicGraph, FunctionNode, FunctionRole

def test_self_comparison():
    print("Initializing Graph A...")
    graph_a = LogicGraph("GraphA")
    
    # Add Anchor
    anchor_ea = 0x140001000
    node_a = FunctionNode(anchor_ea, "DriverEntry", FunctionRole.IRP_DISPATCHER)
    graph_a.add_node(node_a.ea, node_a)
    graph_a.anchor_function = anchor_ea
    
    # Add Callee
    callee_ea = 0x140001200
    node_callee = FunctionNode(callee_ea, "DispatchDeviceControl", FunctionRole.IRP_DISPATCHER)
    graph_a.add_node(node_callee.ea, node_callee)
    graph_a.add_edge(anchor_ea, callee_ea, "calls")

    print(f"Graph A created with {len(graph_a.nodes)} nodes.")

    # Self Compare
    print("Running self-comparison (A vs A)...")
    comparison = graph_a.find_similar_logic(graph_a)
    
    score = comparison.get("overall_similarity_score", 0.0)
    print(f"Overall Similarity Score: {score}")

    if score == 10.0:
        print("SUCCESS: Self-comparison score is 10.0")
    else:
        print(f"FAILURE: Expected 10.0, got {score}")
        sys.exit(1)

if __name__ == "__main__":
    test_self_comparison()
