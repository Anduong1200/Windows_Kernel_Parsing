
import sys
import os
import logging
from dataclasses import dataclass

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')
logger = logging.getLogger("NDIS_Audit_Demo")

# Mock classes to simulate the complex Graph structure without loading the full engine
@dataclass
class MockNode:
    name: str

class MockGraph:
    def __init__(self):
        self.nodes = {}

    def add_node(self, address, name):
        self.nodes[address] = MockNode(name)

# Import the actual TaintEngine from the project
try:
    from logic_flow.pwn.taint_engine import TaintEngine, logger as taint_logger
    # Silence the internal logger for cleaner demo output
    taint_logger.setLevel(logging.WARNING)
except ImportError:
    print("Error: Could not import logic_flow. Make sure you are in the project root.")
    sys.exit(1)

def demo_audit_ndis_driver():
    print("="*60)
    print("  DEMO: Security Audit for NDIS Lightweight Filter Driver")
    print("  Target: MyMonitorDriver.sys (Hypothetical)")
    print("="*60)

    # 1. Setup the Analysis Graph (Simulated)
    # in a real run, this comes from 'engine.py' analyzing the binary
    print("[*] Loading Control Flow Graph (CFG)...")
    graph = MockGraph()
    
    # Add some standard NDIS functions
    graph.add_node(0x140001000, "DriverEntry")
    graph.add_node(0x140001200, "FilterAttach")
    graph.add_node(0x140001500, "FilterReceiveNetBufferLists")
    
    # Add a vulnerable sink (Dangerous function)
    # This represents a common mistake: copying packet data using a size from the packet itself
    vulnerable_addr = 0x140001850
    graph.add_node(vulnerable_addr, "RtlCopyMemory") 

    print(f"[*] Graph loaded: {len(graph.nodes)} nodes identified.")

    # 2. Initialize Taint Engine
    # We pass None for project/cfg because the TaintEngine in this repo 
    # has a mock mode for demonstration (as seen in source code).
    print("[*] Initializing Taint Engine (Data-Flow Analysis)...")
    engine = TaintEngine(project=None, cfg=None)

    # 3. Scan for IOCTL Vulnerabilities (Taint Sources -> Sinks)
    print("\n[*] Scanning for Tainted Data Flows (User -> Kernel)...")
    
    # In a real scan, we iterate all sensitive API calls. 
    # Here we focus on the RtlCopyMemory we found.
    
    print(f" -> Analyzing call to RtlCopyMemory at {hex(vulnerable_addr)}...")
    
    # Arg index 2 is 'Length'. If Length is tainted by user, it's a buffer overflow.
    report = engine.check_taint_path(vulnerable_addr, arg_index=2)

    # 4. Interpret Results
    if report['status'] == 'VULNERABLE':
        print("\n [!] CRITICAL VULNERABILITY DETECTED!")
        print(f"     Type:        {report['description']}")
        print(f"     Location:    {report['sink']}")
        print(f"     Source:      {report['source']}")
        print("\n [Analysis Explanation]")
        print(" The analyzer found a path from the 'FilterReceiveNetBufferLists' (Input)")
        print(" to 'RtlCopyMemory' size argument without proper validation bounds.")
        print(" An attacker could create a malformed WiFi packet with a fake 'Size' field")
        print(" causing the driver to overwrite Kernel memory (BSOD or RCE).")
    else:
        print("\n [OK] No taint path found.")

    print("\n" + "="*60)

if __name__ == "__main__":
    demo_audit_ndis_driver()
