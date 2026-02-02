import unittest
import sys
import os

# Adjust path to import logic_flow
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from logic_flow.core.logic_graph import LogicGraph, FunctionNode, FunctionRole

class TestLogicGraph(unittest.TestCase):
    def setUp(self):
        """Setup a fresh graph before each test"""
        self.graph = LogicGraph(anchor_function=0x1000)

    def test_create_graph_nodes_edges(self):
        """Test Case 1: Create graph, add 3 nodes and 2 edges"""
        # Create 3 nodes
        node1 = FunctionNode(ea=0x1000, name="FunctionA", role=FunctionRole.IRP_DISPATCHER)
        node2 = FunctionNode(ea=0x2000, name="FunctionB", role=FunctionRole.VALIDATION_ROUTINE)
        node3 = FunctionNode(ea=0x3000, name="FunctionC", role=FunctionRole.ERROR_HANDLER)

        self.graph.add_node(0x1000, node1)
        self.graph.add_node(0x2000, node2)
        self.graph.add_node(0x3000, node3)

        # Create 2 edges: A -> B, B -> C
        self.graph.add_edge(0x1000, 0x2000, "calls")
        self.graph.add_edge(0x2000, 0x3000, "calls")

        # Verify counts
        self.assertEqual(len(self.graph.nodes), 3)
        self.assertEqual(len(self.graph.edges), 2)
        
        # Verify structure
        self.assertIn(0x1000, self.graph.get_callers(0x2000))
        self.assertIn(0x3000, self.graph.get_callees(0x2000))
    
    def test_serialization_round_trip_equality(self):
        """Test Case 2: Export graph to dict, reload, and verify equality"""
        # Setup complex graph data
        org_node = FunctionNode(
            ea=0x1000, 
            name="Anchor", 
            role=FunctionRole.IRP_DISPATCHER, 
            is_error_handler=True,
            error_codes_written={"STATUS_UNSUCCESSFUL"}
        )
        # Fix role if DRIVER_ENTRY doesn't exist in enum definition I saw earlier
        # org_node.role = FunctionRole.CLEANUP_HANDLER 
        
        self.graph.add_node(0x1000, org_node)
        self.graph.add_edge(0x1000, 0x1000, "recursive_call") # Edge to self

        # 1. Export to dict
        data = self.graph.to_dict()

        # 2. Load back
        new_graph = LogicGraph.from_dict(data)

        # 3. Compare Data
        # Equality check for Anchor
        self.assertEqual(self.graph.anchor_function, new_graph.anchor_function)
        
        # Equality check for Node content
        org_node_data = self.graph.nodes[0x1000]
        new_node_data = new_graph.nodes[0x1000]
        
        self.assertEqual(org_node_data.name, new_node_data.name)
        self.assertEqual(org_node_data.role, new_node_data.role)
        self.assertEqual(org_node_data.is_error_handler, new_node_data.is_error_handler)
        # Set equality works regardless of order
        self.assertEqual(org_node_data.error_codes_written, new_node_data.error_codes_written) 
        
        # Equality check for Edges
        # Edges are list of tuples, order preserved usually
        self.assertEqual(self.graph.edges, new_graph.edges)

if __name__ == '__main__':
    unittest.main()
