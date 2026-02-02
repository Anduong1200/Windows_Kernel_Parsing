
import unittest
import sys
import os
import logging
from typing import List

# Ensure we can import from project root
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class TestNativeBinding(unittest.TestCase):
    """
    Test suite for Rust native extension integration.
    Verifies that logic_flow_native can be imported and functions work as expected.
    """

    def setUp(self):
        self.native_available = False
        try:
            import logic_flow_native
            self.module = logic_flow_native
            self.native_available = True
            logger.info("Successfully imported logic_flow_native")
        except ImportError:
            logger.warning("logic_flow_native not found. Skipping native tests.")
            self.module = None

    def test_import(self):
        """Verify module import works (pass if skipped due to missing build)."""
        if not self.native_available:
            self.skipTest("Native module not built/installed")
        self.assertIsNotNone(self.module)

    def test_jaccard_similarity(self):
        """Test rust_calculate_jaccard_similarity correctness."""
        if not self.native_available:
            self.skipTest("Native module not built/installed")
            
        set_a = ["func_1", "func_2", "func_3"]
        set_b = ["func_2", "func_3", "func_4"]
        
        # Expected: Intersection = 2 (func_2, func_3), Union = 4
        # Jaccard = 2/4 = 0.5
        
        result = self.module.calculate_jaccard_similarity(set_a, set_b)
        self.assertAlmostEqual(result, 0.5, places=4)
        
        # Test empty sets
        self.assertEqual(self.module.calculate_jaccard_similarity([], []), 0.0)
        self.assertEqual(self.module.calculate_jaccard_similarity(set_a, []), 0.0)

    def test_bfs_traversal(self):
        """Test rust_bfs_traversal correctness."""
        if not self.native_available:
            self.skipTest("Native module not built/installed")

        # Graph structure:
        # A -> B
        # A -> C
        # B -> D
        # C -> E
        # E -> F
        adjacency = {
            "A": ["B", "C"],
            "B": ["D"],
            "C": ["E"],
            "E": ["F"],
            "D": [],
            "F": []
        }
        
        # Traversal from A (depth None = infinite)
        visited = self.module.bfs_traversal("A", adjacency, None)
        self.assertEqual(len(visited), 6)
        self.assertIn("F", visited)
        
        # Traversal with depth limit 1 (A -> B, C)
        visited_limited = self.module.bfs_traversal("A", adjacency, 1)
        # Should contain A, B, C (3 nodes)
        self.assertEqual(len(visited_limited), 3) 
        self.assertNotIn("D", visited_limited)
        self.assertNotIn("E", visited_limited)

if __name__ == '__main__':
    unittest.main()
