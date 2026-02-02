
import sys
import os
import json
import unittest
from datetime import datetime

# Adjust path to import logic_flow
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from logic_flow.core.logic_graph import LogicGraph, FunctionNode, FunctionRole

class TestLogicGraphFixes(unittest.TestCase):
    def setUp(self):
        self.graph = LogicGraph(anchor_function=0x1000)

    def test_add_edge_deduplication(self):
        print("\nTesting Edge Deduplication...")
        self.graph.add_node(0x1000, FunctionNode(ea=0x1000, name="Anchor"))
        self.graph.add_node(0x2000, FunctionNode(ea=0x2000, name="Target"))
        
        # Add duplicate edges
        self.graph.add_edge(0x1000, 0x2000, "calls")
        self.graph.add_edge(0x1000, 0x2000, "calls")
        self.graph.add_edge(0x1000, 0x2000, "calls")
        
        self.assertEqual(len(self.graph.edges), 1, "Should have only 1 edge")
        print("✅ Edge deduplication passed.")

    def test_serialization_of_sets(self):
        print("\nTesting Serialization of Sets...")
        node = FunctionNode(ea=0x1000, name="Anchor")
        node.error_codes_written.add("STATUS_ACCESS_DENIED")
        node.irp_context = {
            "major_functions": {"IRP_MJ_READ", "IRP_MJ_WRITE"}  # Set inside dict
        }
        self.graph.add_node(0x1000, node)
        
        # Test to_dict
        data = self.graph.to_dict()
        
        # Verify error_codes_written is list
        key = hex(0x1000)
        self.assertIsInstance(data["nodes"][key]["error_codes_written"], list)
        self.assertIn("STATUS_ACCESS_DENIED", data["nodes"][key]["error_codes_written"])
        
        # Verify irp_context set conversion
        irp_ctx = data["nodes"][key]["irp_context"]
        self.assertIsInstance(irp_ctx["major_functions"], list)
        self.assertIn("IRP_MJ_READ", irp_ctx["major_functions"])
        
        # Verify JSON dump (crucial for IDA coms)
        try:
            json_str = json.dumps(data)
            print("✅ JSON dump passed (Sets serialized correctly).")
        except TypeError as e:
            self.fail(f"JSON dump failed: {e}")

    def test_round_trip(self):
        print("\nTesting Round Trip (to_dict -> from_dict)...")
        node = FunctionNode(ea=0x1000, name="Anchor")
        node.error_codes_written.add("STATUS_SUCCESS")
        self.graph.add_node(0x1000, node)
        
        data = self.graph.to_dict()
        new_graph = LogicGraph.from_dict(data)
        
        new_node = new_graph.nodes[0x1000]
        self.assertIn("STATUS_SUCCESS", new_node.error_codes_written)
        self.assertIsInstance(new_node.error_codes_written, set)
        print("✅ Round trip passed.")

if __name__ == '__main__':
    unittest.main()
