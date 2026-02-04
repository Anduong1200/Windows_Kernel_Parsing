"""
Driver Interface Extractor.

Refines raw data from IDA into a structured Driver Interface Model.
"""
from typing import Dict, Any, List
from ..core.protocol import DriverInterfaceData, DispatchEntry, DeviceObjectData, IOCTLEntry
from ..core.logic_graph import LogicGraph, FunctionRole

class InterfaceExtractor:
    """
    Analyzes the LogicGraph and raw interface data to build a complete driver model.
    """
    def __init__(self, graph: LogicGraph, raw_interface: Dict[str, Any]):
        self.graph = graph
        self.raw_stats = raw_interface
        self.model: DriverInterfaceData = {
            "dispatch_table": [],
            "devices": [],
            "ioctls": [],
            "detected_pools": []
        }

    def refine_model(self) -> DriverInterfaceData:
        """Run refinement passes."""
        self._parse_dispatch_table()
        self._find_hidden_ioctls()
        return self.model

    def _parse_dispatch_table(self):
        """Refine dispatch table entries."""
        raw_table = self.raw_stats.get('dispatch_table', [])
        for entry in raw_table:
            # Type check/conversion
            processed: DispatchEntry = {
                "irql": entry.get('irql', 'PASSIVE'),
                "major_function": entry.get('major_function', -1),
                "handler_ea": entry.get('handler_ea', 0),
                "handler_name": entry.get('handler_name', 'sub_unknown')
            }
            
            # Retrieve node from graph to check role
            if processed['handler_ea'] in self.graph.nodes:
                node = self.graph.nodes[processed['handler_ea']]
                if node.role == FunctionRole.UNKNOWN:
                     # Heuristic: If it's in the dispatch table, it's a Dispatch routine
                     node.role = FunctionRole.IRP_DISPATCHER
            
            self.model['dispatch_table'].append(processed)

    def _find_hidden_ioctls(self):
        """
        Attempt to find IOCTLs by analyzing instructions in dispatch handlers.
        Looks for:
        1. `cmp` instructions with immediate values that match IOCTL patterns
        2. `test` instructions for access checks
        3. `switch` patterns (jump tables)
        """
        # Find IRP_MJ_DEVICE_CONTROL handler (major function 14)
        device_control_handlers = [
            e for e in self.model['dispatch_table']
            if e.get('major_function') == 14  # IRP_MJ_DEVICE_CONTROL
        ]
        
        if not device_control_handlers:
            return
        
        # Retrieve function instructions from raw_stats (passed from IDA export)
        func_instructions = self.raw_stats.get('function_instructions', {})
        
        for handler in device_control_handlers:
            handler_ea = handler.get('handler_ea', 0)
            handler_ea_str = str(handler_ea)
            
            if handler_ea_str not in func_instructions:
                continue
            
            insns = func_instructions[handler_ea_str]
            self._scan_for_ioctl_codes(insns, handler_ea)
    
    def _scan_for_ioctl_codes(self, insns: List[Dict], handler_ea: int):
        """
        Scan instruction list for IOCTL code patterns.
        
        IOCTL codes typically:
        - Are 32-bit values
        - Have specific bit patterns (device type, function, method, access)
        - Appear in `cmp` or `test` instructions
        """
        # IOCTL code structure: (DeviceType << 16) | (Access << 14) | (Function << 2) | Method
        # Common device types: FILE_DEVICE_UNKNOWN (0x22), custom (0x8000+)
        
        for insn in insns:
            mnem = insn.get('mnemonic', '').lower()
            
            # Look for comparison instructions
            if mnem not in ['cmp', 'sub', 'test', 'je', 'jne', 'jz', 'jnz']:
                continue
            
            # Check operands for immediate values
            for op in insn.get('operands', []):
                if op.get('type') == 5:  # Immediate operand (IDA type o_imm)
                    value = op.get('value', 0)
                    if isinstance(value, str):
                        try:
                            value = int(value, 16) if value.startswith('0x') else int(value)
                        except:
                            continue
                    
                    # Check if value looks like an IOCTL code
                    if self._is_likely_ioctl(value):
                        ioctl_entry: IOCTLEntry = {
                            "code": value,
                            "method": self._decode_ioctl_method(value),
                            "handler_ea": handler_ea,
                            "input_size": 0,  # Would need further analysis
                            "output_size": 0
                        }
                        # Avoid duplicates
                        if not any(e['code'] == value for e in self.model['ioctls']):
                            self.model['ioctls'].append(ioctl_entry)
    
    def _is_likely_ioctl(self, value: int) -> bool:
        """
        Heuristic to determine if a value is likely an IOCTL code.
        """
        if value <= 0 or value > 0xFFFFFFFF:
            return False
        
        # Device type is in bits 16-31
        device_type = (value >> 16) & 0xFFFF
        
        # Common device types for kernel drivers
        # FILE_DEVICE_UNKNOWN = 0x22
        # Custom devices typically use 0x8000+
        if device_type == 0x22 or device_type >= 0x8000:
            return True
        
        # Also check for common WDM device types (0x01-0x50)
        if 0x01 <= device_type <= 0x50:
            return True
        
        return False
    
    def _decode_ioctl_method(self, code: int) -> str:
        """Decode the buffering method from IOCTL code."""
        method = code & 0x3
        methods = {
            0: "METHOD_BUFFERED",
            1: "METHOD_IN_DIRECT",
            2: "METHOD_OUT_DIRECT",
            3: "METHOD_NEITHER"
        }
        return methods.get(method, "UNKNOWN")

def generate_driver_model(graph: LogicGraph, raw_data: Dict[str, Any]) -> DriverInterfaceData:
    """Helper to run extraction."""
    raw_interface = raw_data.get('driver_interface', {})
    # Also pass function_instructions for IOCTL scanning
    raw_interface['function_instructions'] = raw_data.get('function_instructions', {})
    extractor = InterfaceExtractor(graph, raw_interface)
    return extractor.refine_model()

