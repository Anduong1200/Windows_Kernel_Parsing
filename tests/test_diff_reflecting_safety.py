
import sys
import os
import unittest
import logging

# Add project root to path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from logic_flow.core.diff_reflecting import _is_failfast_api, compare_logic_flows
from logic_flow.core.logic_graph import LogicGraph

class TestDiffReflectingSafety(unittest.TestCase):
    def test_is_failfast_api_safety(self):
        """Test null/empty safety for _is_failfast_api"""
        print("\nTesting _is_failfast_api safety...")
        self.assertFalse(_is_failfast_api(None), "Should handle None gracefully")
        self.assertFalse(_is_failfast_api(""), "Should handle empty string")
        self.assertTrue(_is_failfast_api("RtlFailFast"), "Should identify RtlFailFast")
        self.assertFalse(_is_failfast_api("NormalFunc"), "Should return False for normal func")
        print("PASS")

    def test_compare_logic_flows_empty_graph(self):
        """Test compare_logic_flows with empty candidate graph"""
        print("\nTesting compare_logic_flows empty graph safety...")
        g1 = LogicGraph(0x1000)
        # Add some mock nodes to g1 so it's not empty (though it doesn't matter for this test)
        g1.add_node(0x1000, None) 
        
        g2 = LogicGraph(0x2000)
        # g2 is empty
        
        # Should not crash
        try:
            result = compare_logic_flows(g1, g2)
            self.assertIsInstance(result, dict)
            self.assertEqual(result["security_insights"]["overall_security_assessment"], "unknown")
            self.assertIn("Candidate graph is empty", result["manual_analysis_hints"])
            print("PASS")
        except Exception as e:
            self.fail(f"compare_logic_flows raised exception on empty graph: {e}")

if __name__ == '__main__':
    logging.basicConfig(level=logging.ERROR)
    unittest.main()
