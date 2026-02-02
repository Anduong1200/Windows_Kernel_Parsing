
"""
Cytoscape.js Exporter for Logic Flow Analysis.
Part of Module 3 (v2.1): Visualization.
"""

import json
import os
from typing import Dict, Any, List

class CytoscapeExporter:
    """
    Exports LogicGraph data to Cytoscape.js JSON format.
    Generates standalone HTML reports.
    """
    
    # Semantic Colors
    COLOR_IDENTICAL = '#4ade80'  # Green-400
    COLOR_SYNTAX_CHG = '#facc15' # Yellow-400
    COLOR_LOGIC_CHG = '#ef4444'  # Red-500
    COLOR_DEFAULT = '#94a3b8'    # Slate-400

    def __init__(self):
        pass

    def convert_to_elements(self, graph_dict: Dict[str, Any], diff_results: Dict[str, str] = None, pane_prefix: str = "") -> Dict[str, List]:
        """
        Convert LogicGraph dict to Cytoscape elements.
        Args:
            pane_prefix: Prefix for IDs to collision-proof split views (e.g., 'left_', 'right_').
        """
        nodes = []
        edges = []
        
        diff_results = diff_results or {}

        # Process Nodes
        for node in graph_dict.get('nodes', []):
            ea = node['address']
            name = node['name']
            role = node['role']
            meta = node.get('metadata', {})
            
            # Determine Color
            diff_status = diff_results.get(ea, 'unknown')
            color = self.COLOR_DEFAULT
            if diff_status == 'identical':
                color = self.COLOR_IDENTICAL
            elif diff_status == 'syntax':
                color = self.COLOR_SYNTAX_CHG
            elif diff_status == 'logic':
                color = self.COLOR_LOGIC_CHG
            
            # Determine Shape (Logic-Aware)
            # Diamond for Conditional/Decision, Rect for Action
            shape = 'rectangle' # Default
            # Heuristic: If VEX IR contains "IF (...) GOTO", it's a Decision node
            vex_ir = meta.get('vex_ir', {})
            if vex_ir:
                 for block in vex_ir.get('blocks', []):
                     for stmt in block.get('statements', []):
                         if "IF (" in stmt.get('op', ''):
                             shape = 'diamond'
                             break
            
            # Create Node Element
            nodes.append({
                "data": {
                    "id": f"{pane_prefix}{ea}",
                    "original_id": ea,
                    "label": name,
                    "role": role,
                    "color": color,
                    "shape": shape,
                    "diffStatus": diff_status,
                    "metadata": meta
                }
            })

        # Process Edges
        for edge in graph_dict.get('edges', []):
            source = edge['caller']
            target = edge['callee']
            edge_type = edge['edge_type']
            
            edges.append({
                "data": {
                    "id": f"{pane_prefix}{source}_{target}",
                    "source": f"{pane_prefix}{source}",
                    "target": f"{pane_prefix}{target}",
                    "label": edge_type
                }
            })
            
        return {"nodes": nodes, "edges": edges}

    def generate_html_report(self, output_path: str, graph_data: Dict[str, Any], diff_data: Dict[str, str] = None):
        """Generate single graph report."""
        elements = self.convert_to_elements(graph_data, diff_data)
        self._write_html(output_path, elements, mode="single")

    def generate_split_view_report(self, output_path: str, graph_old: Dict, graph_new: Dict, diff_data: Dict = None):
        """
        Generate Split-View comparison report (Left=Old, Right=New).
        """
        elements_left = self.convert_to_elements(graph_old, diff_data, pane_prefix="old_")
        elements_right = self.convert_to_elements(graph_new, diff_data, pane_prefix="new_")
        
        # Combine elements? No, two instances are better for Split View control.
        # But for simplistic implementation, let's pass them as separate data blocks to the template.
        self._write_html(output_path, {"left": elements_left, "right": elements_right}, mode="split")

    def _write_html(self, output_path: str, data: Any, mode: str = "single"):
        
        json_data = json.dumps(data)
        
        # Layout Config
        layout_opts = "{ name: 'dagre', rankDir: 'TB' }" 
        
        # Common Scripts
        scripts = """
        <script src="https://cdnjs.cloudflare.com/ajax/libs/cytoscape/3.27.0/cytoscape.min.js"></script>
        <script src="https://cdnjs.cloudflare.com/ajax/libs/dagre/0.8.5/dagre.min.js"></script>
        <script src="https://cdn.jsdelivr.net/npm/cytoscape-dagre@2.5.0/cytoscape-dagre.min.js"></script>
        """
        
        # Styles
        styles = f"""
        body {{ font-family: 'Segoe UI', sans-serif; margin: 0; padding: 0; overflow: hidden; background-color: #0f172a; color: white; }}
        .legend {{ position: absolute; bottom: 20px; left: 20px; background: rgba(30,41,59,0.8); padding: 10px; border-radius: 5px; z-index: 100; }}
        .dot {{ height: 10px; width: 10px; border-radius: 50%; display: inline-block; margin-right: 5px; }}
        #info-panel {{
            position: absolute; top: 20px; right: 20px; width: 300px;
            background: rgba(30, 41, 59, 0.9); padding: 20px; border-radius: 8px; border: 1px solid #334155;
            display: none; z-index: 100;
        }}
        """

        body_content = ""
        init_script = ""

        if mode == "single":
            styles += "#cy { width: 100vw; height: 100vh; }"
            body_content = '<div id="cy"></div>'
            init_script = f"""
                var elements = {json_data};
                var cy = cytoscape({{
                    container: document.getElementById('cy'),
                    elements: elements,
                    style: {self._get_style()},
                    layout: {layout_opts}
                }});
                setupEvents(cy);
            """
        elif mode == "split":
            styles += """
            #container { display: flex; width: 100vw; height: 100vh; }
            #left-pane, #right-pane { width: 50%; height: 100%; border-right: 1px solid #334155; position: relative; }
            .pane-label { position: absolute; top: 10px; left: 10px; background: rgba(0,0,0,0.5); padding: 5px; border-radius: 3px; font-weight: bold; z-index: 10; }
            """
            body_content = """
            <div id="container">
                <div id="left-pane"><div class="pane-label">VULNERABLE (Old)</div></div>
                <div id="right-pane"><div class="pane-label">PATCHED (New)</div></div>
            </div>
            """
            init_script = f"""
                var data = {json_data};
                
                var cy1 = cytoscape({{
                    container: document.getElementById('left-pane'),
                    elements: data.left,
                    style: {self._get_style()},
                    layout: {layout_opts}
                }});
                
                var cy2 = cytoscape({{
                    container: document.getElementById('right-pane'),
                    elements: data.right,
                    style: {self._get_style()},
                    layout: {layout_opts}
                }});
                
                // Sync Pan/Zoom
                cy1.on('pan zoom', function() {{ cy2.viewport(cy1.zoom(), cy1.pan()); }});
                cy2.on('pan zoom', function() {{ cy1.viewport(cy2.zoom(), cy2.pan()); }});
                
                setupEvents(cy1);
                setupEvents(cy2);
            """

        html = f"""<!DOCTYPE html>
<html>
<head>
    <title>Logic Flow Analysis</title>
    {scripts}
    <style>{styles}</style>
</head>
<body>
    {body_content}
    
    <div class="legend">
        <div><span class="dot" style="background:{self.COLOR_IDENTICAL}"></span>Identical</div>
        <div><span class="dot" style="background:{self.COLOR_SYNTAX_CHG}"></span>Syntactic Change</div>
        <div><span class="dot" style="background:{self.COLOR_LOGIC_CHG}"></span>Logic Change</div>
    </div>

    <div id="info-panel">
        <h2 id="node-name">Function</h2>
        <p><strong>Address:</strong> <span id="node-addr"></span></p>
        <p><strong>Role:</strong> <span id="node-role"></span></p>
        <p><strong>Status:</strong> <span id="node-status"></span></p>
        <div id="node-meta"></div>
    </div>

    <script>
        function setupEvents(inst) {{
            inst.on('tap', 'node', function(evt){{
                var node = evt.target;
                document.getElementById('info-panel').style.display = 'block';
                document.getElementById('node-name').innerText = node.data('label');
                document.getElementById('node-addr').innerText = node.data('original_id');
                document.getElementById('node-role').innerText = node.data('role');
                document.getElementById('node-status').innerText = (node.data('diffStatus') || 'N/A').toUpperCase();
                document.getElementById('node-meta').innerText = JSON.stringify(node.data('metadata'), null, 2);
            }});
        }}
        
        {init_script}
    </script>
</body>
</html>
"""
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(html)
        print(f"Report generated: {output_path}")

    def _get_style(self):
        """Return Cytoscape style JSON string."""
        return """[
            {
                selector: 'node',
                style: {
                    'background-color': 'data(color)',
                    'label': 'data(label)',
                    'shape': 'data(shape)',
                    'color': '#fff',
                    'text-valign': 'center',
                    'text-halign': 'center',
                    'width': 60,
                    'height': 60,
                    'font-size': '12px'
                }
            },
            {
                selector: 'edge',
                style: {
                    'width': 2,
                    'line-color': '#475569',
                    'target-arrow-color': '#475569',
                    'target-arrow-shape': 'triangle',
                    'curve-style': 'bezier',
                    'label': 'data(label)',
                    'color': '#94a3b8',
                    'font-size': '10px'
                }
            }
        ]"""


