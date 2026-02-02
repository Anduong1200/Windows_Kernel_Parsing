
import sys
import os
import unittest

# Adjust path to import logic_flow
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from logic_flow.core.ida_provider import MockIDAProvider, IDAFunction

class TestMockIDAProvider(unittest.TestCase):
    def setUp(self):
        self.provider = MockIDAProvider()

    def test_get_func(self):
        """Test retrieving function info from mock provider"""
        # 0x1000 is initialized in MockIDAProvider._init_mock_data as NtCreateFile
        func = self.provider.get_func(0x1000)
        
        self.assertIsNotNone(func)
        self.assertIsInstance(func, IDAFunction)
        self.assertEqual(func.start_ea, 0x1000)
        self.assertEqual(func.end_ea, 0x1100)
        
        # Test non-existent function
        func_bad = self.provider.get_func(0xDEADBEEF)
        self.assertIsNone(func_bad)

    def test_xrefs_to(self):
        """Test retrieving cross-references"""
        # 0x3000 (ErrorHandler) is called by 0x1000 (NtCreateFile) in mock data
        xrefs = list(self.provider.XrefsTo(0x3000))
        
        self.assertTrue(len(xrefs) > 0)
        self.assertEqual(xrefs[0].frm, 0x1000)
        self.assertEqual(xrefs[0].to, 0x3000)
        
    def test_get_ea_name(self):
        """Test name retrieval"""
        name = self.provider.get_ea_name(0x1000)
        self.assertEqual(name, "NtCreateFile")
        
        # Fallback name
        name_fallback = self.provider.get_ea_name(0x9999)
        self.assertEqual(name_fallback, "sub_00009999")

if __name__ == '__main__':
    unittest.main()
