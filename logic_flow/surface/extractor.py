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
        Attempt to find IOCTLs not implicitly found by simple scanning.
        This would involve analyzing the DispatchDeviceControl function's graph 
        to looking for switch/cmp chains.
        
        Currently a placeholder for advanced logic.
        """
        # TODO: Walk the graph of any function labeled IRP_MJ_DEVICE_CONTROL
        pass

def generate_driver_model(graph: LogicGraph, raw_data: Dict[str, Any]) -> DriverInterfaceData:
    """Helper to run extraction."""
    extractor = InterfaceExtractor(graph, raw_data.get('driver_interface', {}))
    return extractor.refine_model()
