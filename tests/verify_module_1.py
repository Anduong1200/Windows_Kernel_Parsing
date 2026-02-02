
import sys
import os
import logging

# Setup paths
project_root = os.path.dirname(os.path.abspath(__file__))
if project_root not in sys.path:
    sys.path.insert(0, project_root)

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("VerifyModule1")

def verify_module_1():
    """
    Verify AngrLifter on a real binary.
    """
    logger.info("--- Verifying Module 1: Lifting & Parsing ---")
    
    # Target binary (from user logs)
    binary_path = r"d:\examinate\18\AsusPTPFilter.sys"
    
    if not os.path.exists(binary_path):
        logger.error(f"Test binary not found: {binary_path}")
        # Try to find any .sys file in current dir or parent
        for root, dirs, files in os.walk(r"d:\examinate\18"):
            for f in files:
                if f.endswith(".sys"):
                    binary_path = os.path.join(root, f)
                    logger.info(f"Found alternative binary: {binary_path}")
                    break
            if os.path.exists(binary_path): break
    
    if not os.path.exists(binary_path):
        logger.error("No .sys file found for testing.")
        return False

    try:
        from logic_flow.core.advanced_lifter import AngrLifter
        
        logger.info(f"Initializing AngrLifter for {binary_path}...")
        lifter = AngrLifter(binary_path, auto_load_libs=False)
        
        logger.info("Recovering CFG (this may take a moment)...")
        lifter.recover_cfg(normalize=True)
        
        # Get first function
        if not lifter.functions:
            logger.error("No functions found in CFG.")
            return False
            
        first_func_addr = list(lifter.functions.keys())[0]
        func_name = lifter.functions[first_func_addr].name
        logger.info(f"Lifting Function: {func_name} @ {hex(first_func_addr)}")
        
        ir_data = lifter.lift_function(first_func_addr)
        
        if not ir_data:
            logger.error("Lifted IR is empty.")
            return False
            
        logger.info(f"Lifted Data Keys: {ir_data.keys()}")
        blocks = ir_data.get('blocks', [])
        logger.info(f"Block Count: {len(blocks)}")
        
        if blocks:
            stmts = blocks[0].get('statements', [])
            logger.info(f"First Block Statements ({len(stmts)}):")
            for i, stmt in enumerate(stmts[:5]):
                logger.info(f"  [{i}] {stmt}")
                
        print("\n✅ MODULE 1 VERIFICATION SUCCESSFUL")
        return True
        
    except ImportError:
        logger.error("Angr not installed. Skipping verification.")
        return False
    except Exception as e:
        logger.error(f"Verification failed: {e}")
        import traceback
        traceback.print_exc()
        return False

if __name__ == "__main__":
    success = verify_module_1()
    sys.exit(0 if success else 1)
