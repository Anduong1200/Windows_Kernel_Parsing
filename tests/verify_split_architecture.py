
import sys
import os
import json
import logging
from datetime import datetime

# Setup paths
project_root = os.path.dirname(os.path.abspath(__file__))
if project_root not in sys.path:
    sys.path.insert(0, project_root)

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')
logger = logging.getLogger("Verifier")

def verify_split_architecture():
    """
    Simulate the end-to-end flow of the Split Architecture:
    1. Mock JSON data from 'IDA Extractor'.
    2. Feed to 'Core Analysis Engine'.
    3. Verify Output 'LogicGraph'.
    """
    logger.info("--- Starting Split Architecture Verification ---")
    
    # 1. Mock Data (Protocol V1.0)
    # Simulating what logic_flow/core/ida_analysis_script.py would dump
    mock_anchor_ea = 0x140001000
    mock_callee_ea = 0x140002000
    
    mock_export = {
        "metadata": {
            "timestamp": datetime.now().isoformat(),
            "input_file": "test_driver.sys"
        },
        "functions": {
            str(mock_anchor_ea): {
                "ea": mock_anchor_ea,
                "name": "DriverEntry",
                "is_import": False,
                "is_export": True,
                "demangled_name": "DriverEntry"
            },
            str(mock_callee_ea): {
                "ea": mock_callee_ea,
                "name": "RtlInitUnicodeString",
                "is_import": True,
                "is_export": False,
                "demangled_name": None
            }
        },
        "call_graph": [
            {
                "caller_ea": mock_anchor_ea,
                "callee_ea": mock_callee_ea,
                "type": "direct"
            }
        ],
        "function_instructions": {
            str(mock_anchor_ea): [
                # Mock instructions for Fuzzy Hash testing
                {"ea": mock_anchor_ea, "mnemonic": "mov", "bytes_hex": "4889C5"},
                {"ea": mock_anchor_ea+3, "mnemonic": "call", "bytes_hex": "E800000000"}
            ]
        }
    }
    
    logger.info("1. Mock Data Created (DriverEntry -> RtlInitUnicodeString)")
    
    # 2. Instantiate Core Engine
    try:
        from logic_flow.core.engine import CoreAnalysisEngine
        from logic_flow.core.logic_graph import LogicGraph, FunctionRole
        
        engine = CoreAnalysisEngine()
        logger.info("2. CoreAnalysisEngine Instantiated")
        
    except ImportError as e:
        logger.error(f"Failed to import Core Engine: {e}")
        return False

    # 3. Process Data
    try:
        result_dict = engine.process_analysis(mock_export, anchor_address=mock_anchor_ea)
        logger.info("3. Analysis Processed Successfully")
        
        # 4. Verify Output
        if not result_dict:
            logger.error("Engine returned Empty result")
            return False
            
        # Check Node Count
        nodes = result_dict.get('nodes', {})
        if len(nodes) != 2:
            logger.error(f"Expected 2 nodes, got {len(nodes)}")
            return False
            
        # Check Anchor
        expected_anchor_str = hex(mock_anchor_ea)
        result_anchor = result_dict.get('anchor_function')
        
        # Normalize comparison (handle potential 0x vs 0X or L suffix)
        if str(result_anchor).lower() != expected_anchor_str.lower():
             logger.error(f"Anchor mismatch: Got {result_anchor}, Expected {expected_anchor_str}")
             return False

        # Check Edges
        edges = result_dict.get('edges', [])
        if len(edges) != 1:
            logger.error(f"Expected 1 edge, got {len(edges)}")
            return False
            
        logger.info("4. Output Verification Passed (Nodes, Edges, Anchor)")
        print("\n✅ SPLIT ARCHITECTURE VERIFIED SUCCESSFUL")
        return True
        
    except Exception as e:
        logger.error(f"Analysis failed: {e}")
        import traceback
        traceback.print_exc()
        return False

if __name__ == "__main__":
    success = verify_split_architecture()
    sys.exit(0 if success else 1)
