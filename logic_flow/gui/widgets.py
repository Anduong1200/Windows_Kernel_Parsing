"""
Custom GUI Widgets for Logic Flow Analysis Tool
Provides modern, Fluent Design-inspired widgets for the application.
"""

import os
import math
from PyQt6.QtWidgets import (
    QFrame, QPushButton, QLineEdit, QTextEdit, QProgressBar,
    QLabel, QWidget, QVBoxLayout, QHBoxLayout, QFileDialog, QMenu, QDialog,
    QGroupBox, QComboBox, QMessageBox, QGraphicsView, QGraphicsScene,
    QGraphicsItem, QGraphicsRectItem, QGraphicsPathItem, QGraphicsSimpleTextItem,
    QScrollArea, QTableWidget, QTableWidgetItem, QHeaderView, QGraphicsObject
)
from PyQt6.QtGui import (
    QAction, QTextOption, QCursor, QPainter, QBrush, QPen, QColor, 
    QFont, QPainterPath, QIcon, QPixmap, QPolygonF
)
from PyQt6.QtCore import Qt, pyqtSignal, QTimer, QSize, QSettings, QRectF, QPointF, QLineF

from ..utils.qt_helper import optimize_widget


class ModernCard(QFrame):
    """Modern card widget with Fluent Design styling"""

    def __init__(self, title="", icon=None, parent=None):
        super().__init__(parent)
        
        # Main layout for the card
        self.main_layout = QVBoxLayout(self)
        self.main_layout.setContentsMargins(0, 0, 0, 0)
        self.main_layout.setSpacing(0)

        # Style the card
        self.setStyleSheet("""
            ModernCard {
                background-color: #0D1117;
                border: 1px solid #30363D;
                border-radius: 8px;
            }
        """)

        # Header section
        self.header = QWidget()
        self.header.setStyleSheet("""
            QWidget {
                background-color: #161B22;
                border-top-left-radius: 8px;
                border-top-right-radius: 8px;
                border-bottom: 1px solid #30363D;
            }
        """)
        header_layout = QHBoxLayout(self.header)
        header_layout.setContentsMargins(16, 12, 16, 12)
        header_layout.setSpacing(10)

        # Icon if provided
        if icon:
            icon_label = QLabel()
            if isinstance(icon, QIcon):
                icon_label.setPixmap(icon.pixmap(20, 20))
            else:
                icon_label.setPixmap(icon)
            header_layout.addWidget(icon_label)

        # Title
        title_label = QLabel(title)
        font = title_label.font()
        font.setWeight(QFont.Weight.Bold)
        font.setPointSize(10)
        title_label.setFont(font)
        title_label.setStyleSheet("color: #E6EDF3; border: none; background: transparent;")
        header_layout.addWidget(title_label)
        
        header_layout.addStretch()
        self.main_layout.addWidget(self.header)

        # Content container
        self.content_widget = QWidget()
        self.content_widget.setStyleSheet("background: transparent; border: none;")
        self.content_layout = QVBoxLayout(self.content_widget)
        self.content_layout.setContentsMargins(16, 16, 16, 16)
        self.content_layout.setSpacing(16)
        
        self.main_layout.addWidget(self.content_widget)

        optimize_widget(self)


class GraphVisualizationWidget(QGraphicsView):
    """Interactive graph visualization widget for function flow analysis"""

    node_selected = pyqtSignal(str)  # Emits node ID when selected
    node_double_clicked = pyqtSignal(str)  # Emits node ID when double-clicked

    def __init__(self, parent=None):
        super().__init__(parent)
        self.scene = QGraphicsScene(self)
        self.setScene(self.scene)

        # Configure view
        self.setRenderHint(QPainter.RenderHint.Antialiasing)
        self.setRenderHint(QPainter.RenderHint.SmoothPixmapTransform)
        self.setViewportUpdateMode(QGraphicsView.ViewportUpdateMode.FullViewportUpdate)
        self.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAsNeeded)
        self.setVerticalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAsNeeded)
        self.setTransformationAnchor(QGraphicsView.ViewportAnchor.AnchorUnderMouse)
        self.setResizeAnchor(QGraphicsView.ViewportAnchor.AnchorViewCenter)
        self.setDragMode(QGraphicsView.DragMode.RubberBandDrag)

        # Style
        self.setStyleSheet("""
            QGraphicsView {
                background-color: #0D1117;
                border: 1px solid #30363D;
                border-radius: 8px;
            }
        """)

        # Graph data
        self.nodes = {}
        self.edges = []
        self.selected_nodes = set()

        optimize_widget(self)

    def clear_graph(self):
        """Clear all nodes and edges"""
        self.scene.clear()
        self.nodes.clear()
        self.edges.clear()
        self.selected_nodes.clear()

    def add_node(self, node_id, label, node_type="normal", position=(0, 0)):
        """Add a node to the graph"""
        if node_id in self.nodes:
            return self.nodes[node_id]

        # Create node based on type
        node = GraphNode(node_id, label, node_type, position)
        node.node_selected.connect(self.on_node_selected)
        node.node_double_clicked.connect(self.on_node_double_clicked)

        self.scene.addItem(node)
        self.nodes[node_id] = node
        return node

    def add_edge(self, source_id, target_id, label=""):
        """Add an edge between two nodes"""
        if source_id not in self.nodes or target_id not in self.nodes:
            return None

        source_node = self.nodes[source_id]
        target_node = self.nodes[target_id]

        edge = GraphEdge(source_node, target_node, label)
        self.scene.addItem(edge)
        self.edges.append(edge)

        # Ensure edge is drawn behind nodes
        edge.setZValue(-1)

        return edge

    def load_graph_data(self, graph_data):
        """Load graph data from analysis results"""
        self.clear_graph()

        if not graph_data or "nodes" not in graph_data:
            return

        # Add nodes
        for node_data in graph_data.get("nodes", []):
            node_id = node_data.get("id", "")
            label = node_data.get("label", node_id)
            node_type = node_data.get("type", "normal")
            position = node_data.get("position", (0, 0))

            self.add_node(node_id, label, node_type, position)

        # Add edges
        for edge_data in graph_data.get("edges", []):
            source_id = edge_data.get("source", "")
            target_id = edge_data.get("target", "")
            label = edge_data.get("label", "")

            self.add_edge(source_id, target_id, label)

        # Auto-layout if no positions specified
        self.auto_layout()

        # Fit view to content
        self.fitInView(self.scene.sceneRect(), Qt.AspectRatioMode.KeepAspectRatio)

    def auto_layout(self):
        """Simple auto-layout for nodes without positions"""
        if not self.nodes:
            return

        import math
        # Simple circular layout
        nodes_list = list(self.nodes.values())
        center_x = 0
        center_y = 0
        radius = 200

        for i, node in enumerate(nodes_list):
            angle = (2 * 3.14159 * i) / len(nodes_list)
            x = center_x + radius * math.cos(angle)
            y = center_y + radius * math.sin(angle)
            node.setPos(x, y)

    def zoom_in(self):
        """Zoom in"""
        self.scale(1.2, 1.2)

    def zoom_out(self):
        """Zoom out"""
        self.scale(0.8, 0.8)

    def fit_to_view(self):
        """Fit graph to view"""
        if not self.scene.sceneRect().isEmpty():
            self.fitInView(self.scene.sceneRect(), Qt.AspectRatioMode.KeepAspectRatio)

    def wheelEvent(self, event):
        """Handle mouse wheel for zooming"""
        if event.modifiers() & Qt.KeyboardModifier.ControlModifier:
            zoom_factor = 1.2 if event.angleDelta().y() > 0 else 0.8
            self.scale(zoom_factor, zoom_factor)
            event.accept()
        else:
            super().wheelEvent(event)

    def mousePressEvent(self, event):
        """Handle mouse press for panning"""
        if event.button() == Qt.MouseButton.MiddleButton:
            self.setDragMode(QGraphicsView.DragMode.ScrollHandDrag)
            event.accept()
        else:
            super().mousePressEvent(event)

    def mouseReleaseEvent(self, event):
        """Handle mouse release"""
        if event.button() == Qt.MouseButton.MiddleButton:
            self.setDragMode(QGraphicsView.DragMode.RubberBandDrag)
            event.accept()
        else:
            super().mouseReleaseEvent(event)

    def on_node_selected(self, node_id):
        """Handle node selection"""
        self.node_selected.emit(node_id)

    def on_node_double_clicked(self, node_id):
        """Handle node double-click"""
        self.node_double_clicked.emit(node_id)


class GraphNode(QGraphicsItem):
    """Graph node item"""

    node_selected = pyqtSignal(str)
    node_double_clicked = pyqtSignal(str)

    def __init__(self, node_id, label, node_type="normal", position=(0, 0)):
        super().__init__()
        self.node_id = node_id
        self.label = label
        self.node_type = node_type

        # Node appearance based on type
        self.colors = {
            "entry": "#3FB950",
            "exit": "#F85149",
            "decision": "#D29922",
            "call": "#58A6FF",
            "normal": "#8B949E"
        }

        self.color = self.colors.get(node_type, "#8B949E")
        self.setPos(position[0], position[1])
        self.setFlag(QGraphicsItem.GraphicsItemFlag.ItemIsSelectable)
        self.setFlag(QGraphicsItem.GraphicsItemFlag.ItemIsMovable)
        self.setZValue(1)

    def boundingRect(self):
        """Return bounding rectangle"""
        return QRectF(-50, -25, 100, 50)

    def paint(self, painter, option, widget):
        """Paint the node"""
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)

        # Node shape (rounded rectangle)
        rect = self.boundingRect()
        painter.setBrush(QBrush(QColor(self.color)))
        painter.setPen(QPen(QColor("#30363D"), 2))
        painter.drawRoundedRect(rect, 8, 8)

        # Selection highlight
        if self.isSelected():
            painter.setPen(QPen(QColor("#1F6FEB"), 3))
            painter.setBrush(Qt.BrushStyle.NoBrush)
            painter.drawRoundedRect(rect.adjusted(-2, -2, 2, 2), 10, 10)

        # Label
        painter.setPen(QPen(QColor("#E6EDF3")))
        painter.setFont(QFont("Segoe UI", 9))
        painter.drawText(rect, Qt.AlignmentFlag.AlignCenter, self.label[:20])  # Truncate long labels

    def mousePressEvent(self, event):
        """Handle mouse press"""
        super().mousePressEvent(event)
        self.node_selected.emit(self.node_id)

    def mouseDoubleClickEvent(self, event):
        """Handle mouse double-click"""
        self.node_double_clicked.emit(self.node_id)


class GraphEdge(QGraphicsItem):
    """Graph edge item"""

    def __init__(self, source_node, target_node, label=""):
        super().__init__()
        self.source_node = source_node
        self.target_node = target_node
        self.label = label
        self.color = QColor("#8B949E")

    def boundingRect(self):
        """Return bounding rectangle"""
        source_pos = self.source_node.pos()
        target_pos = self.target_node.pos()

        # Create bounding rect that encompasses both nodes
        min_x = min(source_pos.x(), target_pos.x())
        min_y = min(source_pos.y(), target_pos.y())
        max_x = max(source_pos.x(), target_pos.x())
        max_y = max(source_pos.y(), target_pos.y())

        return QRectF(min_x - 50, min_y - 25, max_x - min_x + 100, max_y - min_y + 50)

    def paint(self, painter, option, widget):
        """Paint the edge"""
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)

        source_pos = self.source_node.pos()
        target_pos = self.target_node.pos()

        # Calculate edge line
        source_center = QPointF(source_pos.x(), source_pos.y())
        target_center = QPointF(target_pos.x(), target_pos.y())

        # Draw arrow
        painter.setPen(QPen(self.color, 2))
        painter.setBrush(QBrush(self.color))

        # Line
        line = QLineF(source_center, target_center)
        painter.drawLine(line)

        # Arrow head
        import math
        angle = line.angle()
        arrow_size = 10

        # Calculate arrow head points
        arrow_p1 = target_center + QPointF(
            -arrow_size * math.cos(math.radians(angle + 150)),
            -arrow_size * math.sin(math.radians(angle + 150))
        )
        arrow_p2 = target_center + QPointF(
            -arrow_size * math.cos(math.radians(angle - 150)),
            -arrow_size * math.sin(math.radians(angle - 150))
        )

        arrow_head = QPolygonF([target_center, arrow_p1, arrow_p2])
        painter.drawPolygon(arrow_head)


class FunctionComparisonTable(QWidget):
    """Advanced function comparison table with sorting, filtering, and virtual scrolling"""

    function_selected = pyqtSignal(dict)  # Emits function data when selected

    def __init__(self, parent=None):
        super().__init__(parent)
        self.comparison_data = []
        self.filtered_data = []
        self.sort_column = 2  # Similarity score by default
        self.sort_order = Qt.SortOrder.DescendingOrder
        self.current_filter = {}

        self.setup_ui()
        optimize_widget(self)

    def setup_ui(self):
        """Setup the table UI"""
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(12)

        # Controls row
        controls_layout = QHBoxLayout()
        controls_layout.setSpacing(12)

        # Search box
        self.search_edit = ModernLineEdit("Search functions...")
        self.search_edit.textChanged.connect(self.on_search_changed)
        controls_layout.addWidget(self.search_edit)

        # Similarity filter
        controls_layout.addWidget(ModernLabel("Similarity:", "body"))

        self.similarity_combo = QComboBox()
        self.similarity_combo.addItems(["All", "High (>80%)", "Medium (50-80%)", "Low (<50%)"])
        self.similarity_combo.currentTextChanged.connect(self.on_filter_changed)
        self.similarity_combo.setStyleSheet("""
            QComboBox {
                background-color: #161B22;
                border: 1px solid #30363D;
                border-radius: 6px;
                padding: 6px;
                color: #E6EDF3;
                min-width: 100px;
            }
        """)
        controls_layout.addWidget(self.similarity_combo)

        # Match type filter
        controls_layout.addWidget(ModernLabel("Match Type:", "body"))

        self.match_type_combo = QComboBox()
        self.match_type_combo.addItems(["All Types", "Exact Match", "Structural Match", "Partial Match"])
        self.match_type_combo.currentTextChanged.connect(self.on_filter_changed)
        self.match_type_combo.setStyleSheet(self.similarity_combo.styleSheet())
        controls_layout.addWidget(self.match_type_combo)

        controls_layout.addStretch()

        # Results count
        self.results_count_label = ModernLabel("0 results", "caption")
        self.results_count_label.setStyleSheet("color: #8B949E;")
        controls_layout.addWidget(self.results_count_label)

        layout.addLayout(controls_layout)

        # Table widget
        self.table = QTableWidget()
        self.table.setAlternatingRowColors(True)
        self.table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.table.setSortingEnabled(True)
        self.table.horizontalHeader().setSortIndicatorShown(True)

        # Set table style
        self.table.setStyleSheet("""
            QTableWidget {
                background-color: #161B22;
                border: 1px solid #30363D;
                border-radius: 8px;
                gridline-color: #30363D;
                selection-background-color: #1F6FEB;
            }
            QTableWidget::item {
                padding: 8px;
                border-bottom: 1px solid #30363D;
                color: #E6EDF3;
            }
            QTableWidget::item:selected {
                background-color: #1F6FEB;
                color: white;
            }
            QHeaderView::section {
                background-color: #1C2128;
                color: #E6EDF3;
                padding: 12px 8px;
                border: none;
                border-bottom: 1px solid #30363D;
                font-weight: 600;
            }
            QHeaderView::section:hover {
                background-color: #21262D;
            }
        """)

        # Set up columns
        columns = ["Rank", "Function Name", "Address", "Similarity", "Match Type", "Security Risk", "Actions"]
        self.table.setColumnCount(len(columns))
        self.table.setHorizontalHeaderLabels(columns)

        # Set column widths
        self.table.setColumnWidth(0, 60)   # Rank
        self.table.setColumnWidth(1, 200)  # Function Name
        self.table.setColumnWidth(2, 120)  # Address
        self.table.setColumnWidth(3, 150)  # Similarity
        self.table.setColumnWidth(4, 120)  # Match Type
        self.table.setColumnWidth(5, 140)  # Security Risk
        self.table.setColumnWidth(6, 120)  # Actions

        # Connect signals
        self.table.itemSelectionChanged.connect(self.on_selection_changed)
        self.table.itemDoubleClicked.connect(self.on_item_double_clicked)

        layout.addWidget(self.table)

    def load_comparison_data(self, comparison_results):
        """Load comparison data into the table"""
        self.comparison_data = comparison_results or []
        self.apply_filters_and_sorting()

    def apply_filters_and_sorting(self):
        """Apply current filters and sorting to data"""
        # Apply filters
        self.filtered_data = self.comparison_data[:]

        # Search filter
        search_text = self.search_edit.text().strip().lower()
        if search_text:
            self.filtered_data = [
                item for item in self.filtered_data
                if search_text in item.get("candidate_name", "").lower() or
                   search_text in item.get("candidate_address", "").lower()
            ]

        # Similarity filter
        similarity_filter = self.similarity_combo.currentText()
        if similarity_filter != "All":
            if similarity_filter == "High (>80%)":
                self.filtered_data = [item for item in self.filtered_data if item.get("score", 0) > 8.0]
            elif similarity_filter == "Medium (50-80%)":
                self.filtered_data = [item for item in self.filtered_data if 5.0 <= item.get("score", 0) <= 8.0]
            elif similarity_filter == "Low (<50%)":
                self.filtered_data = [item for item in self.filtered_data if item.get("score", 0) < 5.0]

        # Apply sorting
        if self.sort_column == 3:  # Similarity score
            reverse = self.sort_order == Qt.SortOrder.DescendingOrder
            self.filtered_data.sort(key=lambda x: x.get("score", 0), reverse=reverse)
        elif self.sort_column == 1:  # Function name
            reverse = self.sort_order == Qt.SortOrder.DescendingOrder
            self.filtered_data.sort(key=lambda x: x.get("candidate_name", "").lower(), reverse=reverse)

        # Update table
        self.update_table_display()

    def update_table_display(self):
        """Update the table display with filtered data"""
        self.table.setRowCount(len(self.filtered_data))

        for row, item in enumerate(self.filtered_data):
            # Rank
            rank_item = QTableWidgetItem(str(row + 1))
            rank_item.setData(Qt.ItemDataRole.UserRole, item)
            self.table.setItem(row, 0, rank_item)

            # Function Name
            func_name = item.get("candidate_name", "Unknown")
            name_item = QTableWidgetItem(func_name)
            name_item.setToolTip(func_name)
            self.table.setItem(row, 1, name_item)

            # Address
            address = item.get("candidate_address", "0x00000000")
            addr_item = QTableWidgetItem(f"0x{address:08X}" if isinstance(address, int) else str(address))
            self.table.setItem(row, 2, addr_item)

            # Similarity Score
            score = item.get("score", 0)
            score_item = QTableWidgetItem(f"{score:.1f}")
            score_item.setData(Qt.ItemDataRole.UserRole, score)  # For sorting

            # Color code based on score
            if score > 8.0:
                score_item.setBackground(QColor("#3FB950"))
            elif score > 5.0:
                score_item.setBackground(QColor("#D29922"))
            else:
                score_item.setBackground(QColor("#F85149"))

            self.table.setItem(row, 3, score_item)

            # Match Type
            match_type = self.determine_match_type(item)
            type_item = QTableWidgetItem(match_type)
            self.table.setItem(row, 4, type_item)

            # Security Risk
            risk_level = self.calculate_risk_level(item)
            risk_item = QTableWidgetItem(risk_level)

            # Color code risk level
            if risk_level == "Critical":
                risk_item.setBackground(QColor("#F85149"))
            elif risk_level == "High":
                risk_item.setBackground(QColor("#D29922"))
            elif risk_level == "Medium":
                risk_item.setBackground(QColor("#D29922"))
            else:
                risk_item.setBackground(QColor("#3FB950"))

            self.table.setItem(row, 5, risk_item)

            # Actions
            actions_widget = self.create_actions_widget(item)
            self.table.setCellWidget(row, 6, actions_widget)

        # Update results count
        self.results_count_label.setText(f"{len(self.filtered_data)} results")

        # Resize rows to content
        self.table.resizeRowsToContents()

    def determine_match_type(self, item):
        """Determine match type based on item data"""
        score = item.get("score", 0)
        if score > 9.0:
            return "Exact Match"
        elif score > 7.0:
            return "Structural Match"
        else:
            return "Partial Match"

    def calculate_risk_level(self, item):
        """Calculate security risk level"""
        score = item.get("score", 0)
        # This is a simplified risk calculation
        if score > 8.5:
            return "Critical"
        elif score > 7.0:
            return "High"
        elif score > 5.0:
            return "Medium"
        else:
            return "Low"

    def create_actions_widget(self, item):
        """Create actions widget for table row"""
        actions_widget = QWidget()
        actions_layout = QHBoxLayout(actions_widget)
        actions_layout.setContentsMargins(4, 4, 4, 4)
        actions_layout.setSpacing(4)

        # View details button
        view_btn = ModernButton("View", button_type="outline")
        view_btn.setFixedSize(50, 24)
        view_btn.clicked.connect(lambda: self.on_view_details(item))
        actions_layout.addWidget(view_btn)

        # Export button
        export_btn = ModernButton("Export", button_type="outline")
        export_btn.setFixedSize(50, 24)
        export_btn.clicked.connect(lambda: self.on_export_item(item))
        actions_layout.addWidget(export_btn)

        return actions_widget

    def on_search_changed(self, text):
        """Handle search text changes"""
        self.apply_filters_and_sorting()

    def on_filter_changed(self):
        """Handle filter changes"""
        self.apply_filters_and_sorting()

    def on_selection_changed(self):
        """Handle row selection changes"""
        current_row = self.table.currentRow()
        if current_row >= 0 and current_row < len(self.filtered_data):
            selected_item = self.filtered_data[current_row]
            self.function_selected.emit(selected_item)

    def on_item_double_clicked(self, item):
        """Handle item double-click"""
        row = item.row()
        if row >= 0 and row < len(self.filtered_data):
            selected_item = self.filtered_data[row]
            self.on_view_details(selected_item)

    def on_view_details(self, item):
        """Handle view details action"""
        # Emit signal or show details dialog
        self.function_selected.emit(item)
        # Could show a detailed dialog here

    def on_export_item(self, item):
        """Handle export item action"""
        # Implement export functionality
        QMessageBox.information(self, "Export", f"Export functionality for {item.get('candidate_name', 'Unknown')}")

    def clear_data(self):
        """Clear all data"""
        self.comparison_data = []
        self.filtered_data = []
        self.table.setRowCount(0)
        self.results_count_label.setText("0 results")

        # Set ObjectName to apply QSS style from qt_helper.py
        self.setObjectName("modernCard")

        # Initialize main layout
        self._main_layout = QVBoxLayout(self)
        self._main_layout.setContentsMargins(1, 1, 1, 1) # Thin border
        self._main_layout.setSpacing(0)

        # Content Container
        self._container = QWidget()
        self._container_layout = QVBoxLayout(self._container)
        self._container_layout.setContentsMargins(16, 16, 16, 16)
        self._container_layout.setSpacing(12)

        # Header (Optional)
        if title:
            header = QWidget()
            header.setStyleSheet("background-color: #1C2128; border-top-left-radius: 8px; border-top-right-radius: 8px; border-bottom: 1px solid #30363D;") # Using bg_tertiary and surface_border
            header_layout = QHBoxLayout(header)
            header_layout.setContentsMargins(16, 8, 16, 8)
            header_layout.setSpacing(10)

            if icon:
                icon_label = QLabel()
                icon_label.setPixmap(icon.pixmap(18, 18))
                icon_label.setFixedSize(20, 20)
                header_layout.addWidget(icon_label)

            title_label = ModernLabel(title, "cardTitle")
            header_layout.addWidget(title_label)
            header_layout.addStretch()
            
            self._main_layout.addWidget(header)

        self._main_layout.addWidget(self._container)
        
        # Public content layout for adding widgets
        self.content_layout = self._container_layout
        self.content_widget = self._container

    def add_widget(self, widget):
        """Add widget to card content"""
        self.content_layout.addWidget(widget)


class ModernButton(QPushButton):
    """Modern button with Fluent Design styling"""

    def __init__(self, text="", icon=None, button_type="primary", parent=None):
        super().__init__(text, parent)
        self.button_type = button_type
        
        # Apply styling based on button type
        if button_type == "primary":
            self.setStyleSheet("""
                QPushButton {
                    background-color: #238636;
                    border: 1px solid #238636;
                    border-radius: 6px;
                    color: #FFFFFF;
                    font-weight: 600;
                    padding: 6px 16px;
                    font-size: 13px;
                }
                QPushButton:hover {
                    background-color: #2EA043;
                }
                QPushButton:pressed {
                    background-color: #1B7F2F;
                }
                QPushButton:disabled {
                    background-color: #21262D;
                    border-color: #30363D;
                    color: #8B949E;
                }
            """)
        elif button_type == "outline":
            self.setStyleSheet("""
                QPushButton {
                    background-color: #21262D;
                    border: 1px solid #30363D;
                    border-radius: 6px;
                    color: #C9D1D9;
                    font-weight: 500;
                    padding: 6px 12px;
                    font-size: 13px;
                }
                QPushButton:hover {
                    background-color: #30363D;
                    border-color: #8B949E;
                }
                QPushButton:pressed {
                    background-color: #161B22;
                }
                QPushButton:disabled {
                    color: #484F58;
                    border-color: #21262D;
                }
            """)
        elif button_type == "danger":
            self.setStyleSheet("""
                QPushButton {
                    background-color: #DA3633;
                    border: 1px solid #DA3633;
                    border-radius: 6px;
                    color: #FFFFFF;
                    font-weight: 600;
                    padding: 6px 16px;
                    font-size: 13px;
                }
                QPushButton:hover {
                    background-color: #F85149;
                }
                QPushButton:pressed {
                    background-color: #B62324;
                }
            """)
        
        if icon:
            if isinstance(icon, str):
                from . import resources
                # Map string names to resource functions
                icon_map = {
                    "search": resources.get_search_icon,
                    "folder": resources.get_folder_icon, 
                    "load": resources.get_load_icon,
                    "save": resources.get_save_icon,
                    "settings": resources.get_settings_icon,
                    "bug": resources.get_bug_icon,
                    "play": resources.get_play_icon,
                    "clear": resources.get_clear_icon,
                    "sun": resources.get_sun_icon,
                    "moon": resources.get_moon_icon,
                    "chart": resources.get_chart_icon,
                    "shield": resources.get_shield_icon,
                    "list": resources.get_list_icon,
                }
                
                if icon in icon_map:
                    self.setIcon(icon_map[icon](16))
                else:
                    # Fallback or log warning
                    pass
            else:
                self.setIcon(icon)
        
        optimize_widget(self)


class GraphVisualizationWidget(QGraphicsView):
    """Interactive graph visualization widget for function flow analysis"""

    node_selected = pyqtSignal(str)  # Emits node ID when selected
    node_double_clicked = pyqtSignal(str)  # Emits node ID when double-clicked

    def __init__(self, parent=None):
        super().__init__(parent)
        self.scene = QGraphicsScene(self)
        self.setScene(self.scene)

        # Configure view
        self.setRenderHint(QPainter.RenderHint.Antialiasing)
        self.setRenderHint(QPainter.RenderHint.SmoothPixmapTransform)
        self.setViewportUpdateMode(QGraphicsView.ViewportUpdateMode.FullViewportUpdate)
        self.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAsNeeded)
        self.setVerticalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAsNeeded)
        self.setTransformationAnchor(QGraphicsView.ViewportAnchor.AnchorUnderMouse)
        self.setResizeAnchor(QGraphicsView.ViewportAnchor.AnchorViewCenter)
        self.setDragMode(QGraphicsView.DragMode.RubberBandDrag)

        # Style
        self.setStyleSheet("""
            QGraphicsView {
                background-color: #0D1117;
                border: 1px solid #30363D;
                border-radius: 8px;
            }
        """)

        # Graph data
        self.nodes = {}
        self.edges = []
        self.selected_nodes = set()

        optimize_widget(self)

    def clear_graph(self):
        """Clear all nodes and edges"""
        self.scene.clear()
        self.nodes.clear()
        self.edges.clear()
        self.selected_nodes.clear()

    def add_node(self, node_id, label, node_type="normal", position=(0, 0)):
        """Add a node to the graph"""
        if node_id in self.nodes:
            return self.nodes[node_id]

        # Create node based on type
        node = GraphNode(node_id, label, node_type, position)
        node.node_selected.connect(self.on_node_selected)
        node.node_double_clicked.connect(self.on_node_double_clicked)

        self.scene.addItem(node)
        self.nodes[node_id] = node
        return node

    def add_edge(self, source_id, target_id, label=""):
        """Add an edge between two nodes"""
        if source_id not in self.nodes or target_id not in self.nodes:
            return None

        source_node = self.nodes[source_id]
        target_node = self.nodes[target_id]

        edge = GraphEdge(source_node, target_node, label)
        self.scene.addItem(edge)
        self.edges.append(edge)

        # Ensure edge is drawn behind nodes
        edge.setZValue(-1)

        return edge

    def load_graph_data(self, graph_data):
        """Load graph data from analysis results"""
        self.clear_graph()

        if not graph_data or "nodes" not in graph_data:
            return

        # Add nodes
        for node_data in graph_data.get("nodes", []):
            node_id = node_data.get("id", "")
            label = node_data.get("label", node_id)
            node_type = node_data.get("type", "normal")
            position = node_data.get("position", (0, 0))

            self.add_node(node_id, label, node_type, position)

        # Add edges
        for edge_data in graph_data.get("edges", []):
            source_id = edge_data.get("source", "")
            target_id = edge_data.get("target", "")
            label = edge_data.get("label", "")

            self.add_edge(source_id, target_id, label)

        # Auto-layout if no positions specified
        self.auto_layout()

        # Fit view to content
        self.fitInView(self.scene.sceneRect(), Qt.AspectRatioMode.KeepAspectRatio)

    def auto_layout(self):
        """Simple auto-layout for nodes without positions"""
        if not self.nodes:
            return

        import math
        # Simple circular layout
        nodes_list = list(self.nodes.values())
        center_x = 0
        center_y = 0
        radius = 200

        for i, node in enumerate(nodes_list):
            angle = (2 * 3.14159 * i) / len(nodes_list)
            x = center_x + radius * math.cos(angle)
            y = center_y + radius * math.sin(angle)
            node.setPos(x, y)

    def zoom_in(self):
        """Zoom in"""
        self.scale(1.2, 1.2)

    def zoom_out(self):
        """Zoom out"""
        self.scale(0.8, 0.8)

    def fit_to_view(self):
        """Fit graph to view"""
        if not self.scene.sceneRect().isEmpty():
            self.fitInView(self.scene.sceneRect(), Qt.AspectRatioMode.KeepAspectRatio)

    def wheelEvent(self, event):
        """Handle mouse wheel for zooming"""
        if event.modifiers() & Qt.KeyboardModifier.ControlModifier:
            zoom_factor = 1.2 if event.angleDelta().y() > 0 else 0.8
            self.scale(zoom_factor, zoom_factor)
            event.accept()
        else:
            super().wheelEvent(event)

    def mousePressEvent(self, event):
        """Handle mouse press for panning"""
        if event.button() == Qt.MouseButton.MiddleButton:
            self.setDragMode(QGraphicsView.DragMode.ScrollHandDrag)
            event.accept()
        else:
            super().mousePressEvent(event)

    def mouseReleaseEvent(self, event):
        """Handle mouse release"""
        if event.button() == Qt.MouseButton.MiddleButton:
            self.setDragMode(QGraphicsView.DragMode.RubberBandDrag)
            event.accept()
        else:
            super().mouseReleaseEvent(event)

    def on_node_selected(self, node_id):
        """Handle node selection"""
        self.node_selected.emit(node_id)

    def on_node_double_clicked(self, node_id):
        """Handle node double-click"""
        self.node_double_clicked.emit(node_id)


class GraphNode(QGraphicsItem):
    """Graph node item"""

    node_selected = pyqtSignal(str)
    node_double_clicked = pyqtSignal(str)

    def __init__(self, node_id, label, node_type="normal", position=(0, 0)):
        super().__init__()
        self.node_id = node_id
        self.label = label
        self.node_type = node_type

        # Node appearance based on type
        self.colors = {
            "entry": "#3FB950",
            "exit": "#F85149",
            "decision": "#D29922",
            "call": "#58A6FF",
            "normal": "#8B949E"
        }

        self.color = self.colors.get(node_type, "#8B949E")
        self.setPos(position[0], position[1])
        self.setFlag(QGraphicsItem.GraphicsItemFlag.ItemIsSelectable)
        self.setFlag(QGraphicsItem.GraphicsItemFlag.ItemIsMovable)
        self.setZValue(1)

    def boundingRect(self):
        """Return bounding rectangle"""
        return QRectF(-50, -25, 100, 50)

    def paint(self, painter, option, widget):
        """Paint the node"""
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)

        # Node shape (rounded rectangle)
        rect = self.boundingRect()
        painter.setBrush(QBrush(QColor(self.color)))
        painter.setPen(QPen(QColor("#30363D"), 2))
        painter.drawRoundedRect(rect, 8, 8)

        # Selection highlight
        if self.isSelected():
            painter.setPen(QPen(QColor("#1F6FEB"), 3))
            painter.setBrush(Qt.BrushStyle.NoBrush)
            painter.drawRoundedRect(rect.adjusted(-2, -2, 2, 2), 10, 10)

        # Label
        painter.setPen(QPen(QColor("#E6EDF3")))
        painter.setFont(QFont("Segoe UI", 9))
        painter.drawText(rect, Qt.AlignmentFlag.AlignCenter, self.label[:20])  # Truncate long labels

    def mousePressEvent(self, event):
        """Handle mouse press"""
        super().mousePressEvent(event)
        self.node_selected.emit(self.node_id)

    def mouseDoubleClickEvent(self, event):
        """Handle mouse double-click"""
        self.node_double_clicked.emit(self.node_id)


class GraphEdge(QGraphicsItem):
    """Graph edge item"""

    def __init__(self, source_node, target_node, label=""):
        super().__init__()
        self.source_node = source_node
        self.target_node = target_node
        self.label = label
        self.color = QColor("#8B949E")

    def boundingRect(self):
        """Return bounding rectangle"""
        source_pos = self.source_node.pos()
        target_pos = self.target_node.pos()

        # Create bounding rect that encompasses both nodes
        min_x = min(source_pos.x(), target_pos.x())
        min_y = min(source_pos.y(), target_pos.y())
        max_x = max(source_pos.x(), target_pos.x())
        max_y = max(source_pos.y(), target_pos.y())

        return QRectF(min_x - 50, min_y - 25, max_x - min_x + 100, max_y - min_y + 50)

    def paint(self, painter, option, widget):
        """Paint the edge"""
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)

        source_pos = self.source_node.pos()
        target_pos = self.target_node.pos()

        # Calculate edge line
        source_center = QPointF(source_pos.x(), source_pos.y())
        target_center = QPointF(target_pos.x(), target_pos.y())

        # Draw arrow
        painter.setPen(QPen(self.color, 2))
        painter.setBrush(QBrush(self.color))

        # Line
        line = QLineF(source_center, target_center)
        painter.drawLine(line)

        # Arrow head
        import math
        angle = line.angle()
        arrow_size = 10

        # Calculate arrow head points
        arrow_p1 = target_center + QPointF(
            -arrow_size * math.cos(math.radians(angle + 150)),
            -arrow_size * math.sin(math.radians(angle + 150))
        )
        arrow_p2 = target_center + QPointF(
            -arrow_size * math.cos(math.radians(angle - 150)),
            -arrow_size * math.sin(math.radians(angle - 150))
        )

        arrow_head = QPolygonF([target_center, arrow_p1, arrow_p2])
        painter.drawPolygon(arrow_head)


class FunctionComparisonTable(QWidget):
    """Advanced function comparison table with sorting, filtering, and virtual scrolling"""

    function_selected = pyqtSignal(dict)  # Emits function data when selected

    def __init__(self, parent=None):
        super().__init__(parent)
        self.comparison_data = []
        self.filtered_data = []
        self.sort_column = 2  # Similarity score by default
        self.sort_order = Qt.SortOrder.DescendingOrder
        self.current_filter = {}

        self.setup_ui()
        optimize_widget(self)

    def setup_ui(self):
        """Setup the table UI"""
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(12)

        # Controls row
        controls_layout = QHBoxLayout()
        controls_layout.setSpacing(12)

        # Search box
        self.search_edit = ModernLineEdit("Search functions...")
        self.search_edit.textChanged.connect(self.on_search_changed)
        controls_layout.addWidget(self.search_edit)

        # Similarity filter
        controls_layout.addWidget(ModernLabel("Similarity:", "body"))

        self.similarity_combo = QComboBox()
        self.similarity_combo.addItems(["All", "High (>80%)", "Medium (50-80%)", "Low (<50%)"])
        self.similarity_combo.currentTextChanged.connect(self.on_filter_changed)
        self.similarity_combo.setStyleSheet("""
            QComboBox {
                background-color: #161B22;
                border: 1px solid #30363D;
                border-radius: 6px;
                padding: 6px;
                color: #E6EDF3;
                min-width: 100px;
            }
        """)
        controls_layout.addWidget(self.similarity_combo)

        # Match type filter
        controls_layout.addWidget(ModernLabel("Match Type:", "body"))

        self.match_type_combo = QComboBox()
        self.match_type_combo.addItems(["All Types", "Exact Match", "Structural Match", "Partial Match"])
        self.match_type_combo.currentTextChanged.connect(self.on_filter_changed)
        self.match_type_combo.setStyleSheet(self.similarity_combo.styleSheet())
        controls_layout.addWidget(self.match_type_combo)

        controls_layout.addStretch()

        # Results count
        self.results_count_label = ModernLabel("0 results", "caption")
        self.results_count_label.setStyleSheet("color: #8B949E;")
        controls_layout.addWidget(self.results_count_label)

        layout.addLayout(controls_layout)

        # Table widget
        self.table = QTableWidget()
        self.table.setAlternatingRowColors(True)
        self.table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.table.setSortingEnabled(True)
        self.table.horizontalHeader().setSortIndicatorShown(True)

        # Set table style
        self.table.setStyleSheet("""
            QTableWidget {
                background-color: #161B22;
                border: 1px solid #30363D;
                border-radius: 8px;
                gridline-color: #30363D;
                selection-background-color: #1F6FEB;
            }
            QTableWidget::item {
                padding: 8px;
                border-bottom: 1px solid #30363D;
                color: #E6EDF3;
            }
            QTableWidget::item:selected {
                background-color: #1F6FEB;
                color: white;
            }
            QHeaderView::section {
                background-color: #1C2128;
                color: #E6EDF3;
                padding: 12px 8px;
                border: none;
                border-bottom: 1px solid #30363D;
                font-weight: 600;
            }
            QHeaderView::section:hover {
                background-color: #21262D;
            }
        """)

        # Set up columns
        columns = ["Rank", "Function Name", "Address", "Similarity", "Match Type", "Security Risk", "Actions"]
        self.table.setColumnCount(len(columns))
        self.table.setHorizontalHeaderLabels(columns)

        # Set column widths
        self.table.setColumnWidth(0, 60)   # Rank
        self.table.setColumnWidth(1, 200)  # Function Name
        self.table.setColumnWidth(2, 120)  # Address
        self.table.setColumnWidth(3, 150)  # Similarity
        self.table.setColumnWidth(4, 120)  # Match Type
        self.table.setColumnWidth(5, 140)  # Security Risk
        self.table.setColumnWidth(6, 120)  # Actions

        # Connect signals
        self.table.itemSelectionChanged.connect(self.on_selection_changed)
        self.table.itemDoubleClicked.connect(self.on_item_double_clicked)

        layout.addWidget(self.table)

    def load_comparison_data(self, comparison_results):
        """Load comparison data into the table"""
        self.comparison_data = comparison_results or []
        self.apply_filters_and_sorting()

    def apply_filters_and_sorting(self):
        """Apply current filters and sorting to data"""
        # Apply filters
        self.filtered_data = self.comparison_data[:]

        # Search filter
        search_text = self.search_edit.text().strip().lower()
        if search_text:
            self.filtered_data = [
                item for item in self.filtered_data
                if search_text in item.get("candidate_name", "").lower() or
                   search_text in item.get("candidate_address", "").lower()
            ]

        # Similarity filter
        similarity_filter = self.similarity_combo.currentText()
        if similarity_filter != "All":
            if similarity_filter == "High (>80%)":
                self.filtered_data = [item for item in self.filtered_data if item.get("score", 0) > 8.0]
            elif similarity_filter == "Medium (50-80%)":
                self.filtered_data = [item for item in self.filtered_data if 5.0 <= item.get("score", 0) <= 8.0]
            elif similarity_filter == "Low (<50%)":
                self.filtered_data = [item for item in self.filtered_data if item.get("score", 0) < 5.0]

        # Apply sorting
        if self.sort_column == 3:  # Similarity score
            reverse = self.sort_order == Qt.SortOrder.DescendingOrder
            self.filtered_data.sort(key=lambda x: x.get("score", 0), reverse=reverse)
        elif self.sort_column == 1:  # Function name
            reverse = self.sort_order == Qt.SortOrder.DescendingOrder
            self.filtered_data.sort(key=lambda x: x.get("candidate_name", "").lower(), reverse=reverse)

        # Update table
        self.update_table_display()

    def update_table_display(self):
        """Update the table display with filtered data"""
        self.table.setRowCount(len(self.filtered_data))

        for row, item in enumerate(self.filtered_data):
            # Rank
            rank_item = QTableWidgetItem(str(row + 1))
            rank_item.setData(Qt.ItemDataRole.UserRole, item)
            self.table.setItem(row, 0, rank_item)

            # Function Name
            func_name = item.get("candidate_name", "Unknown")
            name_item = QTableWidgetItem(func_name)
            name_item.setToolTip(func_name)
            self.table.setItem(row, 1, name_item)

            # Address
            address = item.get("candidate_address", "0x00000000")
            addr_item = QTableWidgetItem(f"0x{address:08X}" if isinstance(address, int) else str(address))
            self.table.setItem(row, 2, addr_item)

            # Similarity Score
            score = item.get("score", 0)
            score_item = QTableWidgetItem(f"{score:.1f}")
            score_item.setData(Qt.ItemDataRole.UserRole, score)  # For sorting

            # Color code based on score
            if score > 8.0:
                score_item.setBackground(QColor("#3FB950"))
            elif score > 5.0:
                score_item.setBackground(QColor("#D29922"))
            else:
                score_item.setBackground(QColor("#F85149"))

            self.table.setItem(row, 3, score_item)

            # Match Type
            match_type = self.determine_match_type(item)
            type_item = QTableWidgetItem(match_type)
            self.table.setItem(row, 4, type_item)

            # Security Risk
            risk_level = self.calculate_risk_level(item)
            risk_item = QTableWidgetItem(risk_level)

            # Color code risk level
            if risk_level == "Critical":
                risk_item.setBackground(QColor("#F85149"))
            elif risk_level == "High":
                risk_item.setBackground(QColor("#D29922"))
            elif risk_level == "Medium":
                risk_item.setBackground(QColor("#D29922"))
            else:
                risk_item.setBackground(QColor("#3FB950"))

            self.table.setItem(row, 5, risk_item)

            # Actions
            actions_widget = self.create_actions_widget(item)
            self.table.setCellWidget(row, 6, actions_widget)

        # Update results count
        self.results_count_label.setText(f"{len(self.filtered_data)} results")

        # Resize rows to content
        self.table.resizeRowsToContents()

    def determine_match_type(self, item):
        """Determine match type based on item data"""
        score = item.get("score", 0)
        if score > 9.0:
            return "Exact Match"
        elif score > 7.0:
            return "Structural Match"
        else:
            return "Partial Match"

    def calculate_risk_level(self, item):
        """Calculate security risk level"""
        score = item.get("score", 0)
        # This is a simplified risk calculation
        if score > 8.5:
            return "Critical"
        elif score > 7.0:
            return "High"
        elif score > 5.0:
            return "Medium"
        else:
            return "Low"

    def create_actions_widget(self, item):
        """Create actions widget for table row"""
        actions_widget = QWidget()
        actions_layout = QHBoxLayout(actions_widget)
        actions_layout.setContentsMargins(4, 4, 4, 4)
        actions_layout.setSpacing(4)

        # View details button
        view_btn = ModernButton("View", button_type="outline")
        view_btn.setFixedSize(50, 24)
        view_btn.clicked.connect(lambda: self.on_view_details(item))
        actions_layout.addWidget(view_btn)

        # Export button
        export_btn = ModernButton("Export", button_type="outline")
        export_btn.setFixedSize(50, 24)
        export_btn.clicked.connect(lambda: self.on_export_item(item))
        actions_layout.addWidget(export_btn)

        return actions_widget

    def on_search_changed(self, text):
        """Handle search text changes"""
        self.apply_filters_and_sorting()

    def on_filter_changed(self):
        """Handle filter changes"""
        self.apply_filters_and_sorting()

    def on_selection_changed(self):
        """Handle row selection changes"""
        current_row = self.table.currentRow()
        if current_row >= 0 and current_row < len(self.filtered_data):
            selected_item = self.filtered_data[current_row]
            self.function_selected.emit(selected_item)

    def on_item_double_clicked(self, item):
        """Handle item double-click"""
        row = item.row()
        if row >= 0 and row < len(self.filtered_data):
            selected_item = self.filtered_data[row]
            self.on_view_details(selected_item)

    def on_view_details(self, item):
        """Handle view details action"""
        # Emit signal or show details dialog
        self.function_selected.emit(item)
        # Could show a detailed dialog here

    def on_export_item(self, item):
        """Handle export item action"""
        # Implement export functionality
        QMessageBox.information(self, "Export", f"Export functionality for {item.get('candidate_name', 'Unknown')}")

    def clear_data(self):
        """Clear all data"""
        self.comparison_data = []
        self.filtered_data = []
        self.table.setRowCount(0)
        self.results_count_label.setText("0 results")

        self.setup_styling()

        if icon:
            self.setIcon(icon)
            if text:
                self.setIconSize(QSize(16, 16))
        
        # Add hand cursor for better UX
        self.setCursor(QCursor(Qt.CursorShape.PointingHandCursor))

    def setup_styling(self):
        """Setup button styling based on type"""
        # This ID triggers specific styles in qt_helper.py's QSS
        self.setObjectName(f"modernButton_{self.button_type}")
        self.setMinimumHeight(36) # Taller buttons look more modern


class ModernLineEdit(QLineEdit):
    """Modern line edit"""
    def __init__(self, placeholder="", parent=None):
        super().__init__(parent)
        self.setPlaceholderText(placeholder)
        self.setObjectName("modernLineEdit")
        self.setMinimumHeight(34)
        optimize_widget(self)


class GraphVisualizationWidget(QGraphicsView):
    """Interactive graph visualization widget for function flow analysis"""

    node_selected = pyqtSignal(str)  # Emits node ID when selected
    node_double_clicked = pyqtSignal(str)  # Emits node ID when double-clicked

    def __init__(self, parent=None):
        super().__init__(parent)
        self.scene = QGraphicsScene(self)
        self.setScene(self.scene)

        # Configure view
        self.setRenderHint(QPainter.RenderHint.Antialiasing)
        self.setRenderHint(QPainter.RenderHint.SmoothPixmapTransform)
        self.setViewportUpdateMode(QGraphicsView.ViewportUpdateMode.FullViewportUpdate)
        self.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAsNeeded)
        self.setVerticalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAsNeeded)
        self.setTransformationAnchor(QGraphicsView.ViewportAnchor.AnchorUnderMouse)
        self.setResizeAnchor(QGraphicsView.ViewportAnchor.AnchorViewCenter)
        self.setDragMode(QGraphicsView.DragMode.RubberBandDrag)

        # Style
        self.setStyleSheet("""
            QGraphicsView {
                background-color: #0D1117;
                border: 1px solid #30363D;
                border-radius: 8px;
            }
        """)

        # Graph data
        self.nodes = {}
        self.edges = []
        self.selected_nodes = set()

        optimize_widget(self)

    def clear_graph(self):
        """Clear all nodes and edges"""
        self.scene.clear()
        self.nodes.clear()
        self.edges.clear()
        self.selected_nodes.clear()

    def add_node(self, node_id, label, node_type="normal", position=(0, 0)):
        """Add a node to the graph"""
        if node_id in self.nodes:
            return self.nodes[node_id]

        # Create node based on type
        node = GraphNode(node_id, label, node_type, position)
        node.node_selected.connect(self.on_node_selected)
        node.node_double_clicked.connect(self.on_node_double_clicked)

        self.scene.addItem(node)
        self.nodes[node_id] = node
        return node

    def add_edge(self, source_id, target_id, label=""):
        """Add an edge between two nodes"""
        if source_id not in self.nodes or target_id not in self.nodes:
            return None

        source_node = self.nodes[source_id]
        target_node = self.nodes[target_id]

        edge = GraphEdge(source_node, target_node, label)
        self.scene.addItem(edge)
        self.edges.append(edge)

        # Ensure edge is drawn behind nodes
        edge.setZValue(-1)

        return edge

    def load_graph_data(self, graph_data):
        """Load graph data from analysis results"""
        self.clear_graph()

        if not graph_data or "nodes" not in graph_data:
            return

        # Add nodes
        for node_data in graph_data.get("nodes", []):
            node_id = node_data.get("id", "")
            label = node_data.get("label", node_id)
            node_type = node_data.get("type", "normal")
            position = node_data.get("position", (0, 0))

            self.add_node(node_id, label, node_type, position)

        # Add edges
        for edge_data in graph_data.get("edges", []):
            source_id = edge_data.get("source", "")
            target_id = edge_data.get("target", "")
            label = edge_data.get("label", "")

            self.add_edge(source_id, target_id, label)

        # Auto-layout if no positions specified
        self.auto_layout()

        # Fit view to content
        self.fitInView(self.scene.sceneRect(), Qt.AspectRatioMode.KeepAspectRatio)

    def auto_layout(self):
        """Simple auto-layout for nodes without positions"""
        if not self.nodes:
            return

        import math
        # Simple circular layout
        nodes_list = list(self.nodes.values())
        center_x = 0
        center_y = 0
        radius = 200

        for i, node in enumerate(nodes_list):
            angle = (2 * 3.14159 * i) / len(nodes_list)
            x = center_x + radius * math.cos(angle)
            y = center_y + radius * math.sin(angle)
            node.setPos(x, y)

    def zoom_in(self):
        """Zoom in"""
        self.scale(1.2, 1.2)

    def zoom_out(self):
        """Zoom out"""
        self.scale(0.8, 0.8)

    def fit_to_view(self):
        """Fit graph to view"""
        if not self.scene.sceneRect().isEmpty():
            self.fitInView(self.scene.sceneRect(), Qt.AspectRatioMode.KeepAspectRatio)

    def wheelEvent(self, event):
        """Handle mouse wheel for zooming"""
        if event.modifiers() & Qt.KeyboardModifier.ControlModifier:
            zoom_factor = 1.2 if event.angleDelta().y() > 0 else 0.8
            self.scale(zoom_factor, zoom_factor)
            event.accept()
        else:
            super().wheelEvent(event)

    def mousePressEvent(self, event):
        """Handle mouse press for panning"""
        if event.button() == Qt.MouseButton.MiddleButton:
            self.setDragMode(QGraphicsView.DragMode.ScrollHandDrag)
            event.accept()
        else:
            super().mousePressEvent(event)

    def mouseReleaseEvent(self, event):
        """Handle mouse release"""
        if event.button() == Qt.MouseButton.MiddleButton:
            self.setDragMode(QGraphicsView.DragMode.RubberBandDrag)
            event.accept()
        else:
            super().mouseReleaseEvent(event)

    def on_node_selected(self, node_id):
        """Handle node selection"""
        self.node_selected.emit(node_id)

    def on_node_double_clicked(self, node_id):
        """Handle node double-click"""
        self.node_double_clicked.emit(node_id)


class GraphNode(QGraphicsItem):
    """Graph node item"""

    node_selected = pyqtSignal(str)
    node_double_clicked = pyqtSignal(str)

    def __init__(self, node_id, label, node_type="normal", position=(0, 0)):
        super().__init__()
        self.node_id = node_id
        self.label = label
        self.node_type = node_type

        # Node appearance based on type
        self.colors = {
            "entry": "#3FB950",
            "exit": "#F85149",
            "decision": "#D29922",
            "call": "#58A6FF",
            "normal": "#8B949E"
        }

        self.color = self.colors.get(node_type, "#8B949E")
        self.setPos(position[0], position[1])
        self.setFlag(QGraphicsItem.GraphicsItemFlag.ItemIsSelectable)
        self.setFlag(QGraphicsItem.GraphicsItemFlag.ItemIsMovable)
        self.setZValue(1)

    def boundingRect(self):
        """Return bounding rectangle"""
        return QRectF(-50, -25, 100, 50)

    def paint(self, painter, option, widget):
        """Paint the node"""
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)

        # Node shape (rounded rectangle)
        rect = self.boundingRect()
        painter.setBrush(QBrush(QColor(self.color)))
        painter.setPen(QPen(QColor("#30363D"), 2))
        painter.drawRoundedRect(rect, 8, 8)

        # Selection highlight
        if self.isSelected():
            painter.setPen(QPen(QColor("#1F6FEB"), 3))
            painter.setBrush(Qt.BrushStyle.NoBrush)
            painter.drawRoundedRect(rect.adjusted(-2, -2, 2, 2), 10, 10)

        # Label
        painter.setPen(QPen(QColor("#E6EDF3")))
        painter.setFont(QFont("Segoe UI", 9))
        painter.drawText(rect, Qt.AlignmentFlag.AlignCenter, self.label[:20])  # Truncate long labels

    def mousePressEvent(self, event):
        """Handle mouse press"""
        super().mousePressEvent(event)
        self.node_selected.emit(self.node_id)

    def mouseDoubleClickEvent(self, event):
        """Handle mouse double-click"""
        self.node_double_clicked.emit(self.node_id)


class GraphEdge(QGraphicsItem):
    """Graph edge item"""

    def __init__(self, source_node, target_node, label=""):
        super().__init__()
        self.source_node = source_node
        self.target_node = target_node
        self.label = label
        self.color = QColor("#8B949E")

    def boundingRect(self):
        """Return bounding rectangle"""
        source_pos = self.source_node.pos()
        target_pos = self.target_node.pos()

        # Create bounding rect that encompasses both nodes
        min_x = min(source_pos.x(), target_pos.x())
        min_y = min(source_pos.y(), target_pos.y())
        max_x = max(source_pos.x(), target_pos.x())
        max_y = max(source_pos.y(), target_pos.y())

        return QRectF(min_x - 50, min_y - 25, max_x - min_x + 100, max_y - min_y + 50)

    def paint(self, painter, option, widget):
        """Paint the edge"""
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)

        source_pos = self.source_node.pos()
        target_pos = self.target_node.pos()

        # Calculate edge line
        source_center = QPointF(source_pos.x(), source_pos.y())
        target_center = QPointF(target_pos.x(), target_pos.y())

        # Draw arrow
        painter.setPen(QPen(self.color, 2))
        painter.setBrush(QBrush(self.color))

        # Line
        line = QLineF(source_center, target_center)
        painter.drawLine(line)

        # Arrow head
        import math
        angle = line.angle()
        arrow_size = 10

        # Calculate arrow head points
        arrow_p1 = target_center + QPointF(
            -arrow_size * math.cos(math.radians(angle + 150)),
            -arrow_size * math.sin(math.radians(angle + 150))
        )
        arrow_p2 = target_center + QPointF(
            -arrow_size * math.cos(math.radians(angle - 150)),
            -arrow_size * math.sin(math.radians(angle - 150))
        )

        arrow_head = QPolygonF([target_center, arrow_p1, arrow_p2])
        painter.drawPolygon(arrow_head)


class FunctionComparisonTable(QWidget):
    """Advanced function comparison table with sorting, filtering, and virtual scrolling"""

    function_selected = pyqtSignal(dict)  # Emits function data when selected

    def __init__(self, parent=None):
        super().__init__(parent)
        self.comparison_data = []
        self.filtered_data = []
        self.sort_column = 2  # Similarity score by default
        self.sort_order = Qt.SortOrder.DescendingOrder
        self.current_filter = {}

        self.setup_ui()
        optimize_widget(self)

    def setup_ui(self):
        """Setup the table UI"""
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(12)

        # Controls row
        controls_layout = QHBoxLayout()
        controls_layout.setSpacing(12)

        # Search box
        self.search_edit = ModernLineEdit("Search functions...")
        self.search_edit.textChanged.connect(self.on_search_changed)
        controls_layout.addWidget(self.search_edit)

        # Similarity filter
        controls_layout.addWidget(ModernLabel("Similarity:", "body"))

        self.similarity_combo = QComboBox()
        self.similarity_combo.addItems(["All", "High (>80%)", "Medium (50-80%)", "Low (<50%)"])
        self.similarity_combo.currentTextChanged.connect(self.on_filter_changed)
        self.similarity_combo.setStyleSheet("""
            QComboBox {
                background-color: #161B22;
                border: 1px solid #30363D;
                border-radius: 6px;
                padding: 6px;
                color: #E6EDF3;
                min-width: 100px;
            }
        """)
        controls_layout.addWidget(self.similarity_combo)

        # Match type filter
        controls_layout.addWidget(ModernLabel("Match Type:", "body"))

        self.match_type_combo = QComboBox()
        self.match_type_combo.addItems(["All Types", "Exact Match", "Structural Match", "Partial Match"])
        self.match_type_combo.currentTextChanged.connect(self.on_filter_changed)
        self.match_type_combo.setStyleSheet(self.similarity_combo.styleSheet())
        controls_layout.addWidget(self.match_type_combo)

        controls_layout.addStretch()

        # Results count
        self.results_count_label = ModernLabel("0 results", "caption")
        self.results_count_label.setStyleSheet("color: #8B949E;")
        controls_layout.addWidget(self.results_count_label)

        layout.addLayout(controls_layout)

        # Table widget
        self.table = QTableWidget()
        self.table.setAlternatingRowColors(True)
        self.table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.table.setSortingEnabled(True)
        self.table.horizontalHeader().setSortIndicatorShown(True)

        # Set table style
        self.table.setStyleSheet("""
            QTableWidget {
                background-color: #161B22;
                border: 1px solid #30363D;
                border-radius: 8px;
                gridline-color: #30363D;
                selection-background-color: #1F6FEB;
            }
            QTableWidget::item {
                padding: 8px;
                border-bottom: 1px solid #30363D;
                color: #E6EDF3;
            }
            QTableWidget::item:selected {
                background-color: #1F6FEB;
                color: white;
            }
            QHeaderView::section {
                background-color: #1C2128;
                color: #E6EDF3;
                padding: 12px 8px;
                border: none;
                border-bottom: 1px solid #30363D;
                font-weight: 600;
            }
            QHeaderView::section:hover {
                background-color: #21262D;
            }
        """)

        # Set up columns
        columns = ["Rank", "Function Name", "Address", "Similarity", "Match Type", "Security Risk", "Actions"]
        self.table.setColumnCount(len(columns))
        self.table.setHorizontalHeaderLabels(columns)

        # Set column widths
        self.table.setColumnWidth(0, 60)   # Rank
        self.table.setColumnWidth(1, 200)  # Function Name
        self.table.setColumnWidth(2, 120)  # Address
        self.table.setColumnWidth(3, 150)  # Similarity
        self.table.setColumnWidth(4, 120)  # Match Type
        self.table.setColumnWidth(5, 140)  # Security Risk
        self.table.setColumnWidth(6, 120)  # Actions

        # Connect signals
        self.table.itemSelectionChanged.connect(self.on_selection_changed)
        self.table.itemDoubleClicked.connect(self.on_item_double_clicked)

        layout.addWidget(self.table)

    def load_comparison_data(self, comparison_results):
        """Load comparison data into the table"""
        self.comparison_data = comparison_results or []
        self.apply_filters_and_sorting()

    def apply_filters_and_sorting(self):
        """Apply current filters and sorting to data"""
        # Apply filters
        self.filtered_data = self.comparison_data[:]

        # Search filter
        search_text = self.search_edit.text().strip().lower()
        if search_text:
            self.filtered_data = [
                item for item in self.filtered_data
                if search_text in item.get("candidate_name", "").lower() or
                   search_text in item.get("candidate_address", "").lower()
            ]

        # Similarity filter
        similarity_filter = self.similarity_combo.currentText()
        if similarity_filter != "All":
            if similarity_filter == "High (>80%)":
                self.filtered_data = [item for item in self.filtered_data if item.get("score", 0) > 8.0]
            elif similarity_filter == "Medium (50-80%)":
                self.filtered_data = [item for item in self.filtered_data if 5.0 <= item.get("score", 0) <= 8.0]
            elif similarity_filter == "Low (<50%)":
                self.filtered_data = [item for item in self.filtered_data if item.get("score", 0) < 5.0]

        # Apply sorting
        if self.sort_column == 3:  # Similarity score
            reverse = self.sort_order == Qt.SortOrder.DescendingOrder
            self.filtered_data.sort(key=lambda x: x.get("score", 0), reverse=reverse)
        elif self.sort_column == 1:  # Function name
            reverse = self.sort_order == Qt.SortOrder.DescendingOrder
            self.filtered_data.sort(key=lambda x: x.get("candidate_name", "").lower(), reverse=reverse)

        # Update table
        self.update_table_display()

    def update_table_display(self):
        """Update the table display with filtered data"""
        self.table.setRowCount(len(self.filtered_data))

        for row, item in enumerate(self.filtered_data):
            # Rank
            rank_item = QTableWidgetItem(str(row + 1))
            rank_item.setData(Qt.ItemDataRole.UserRole, item)
            self.table.setItem(row, 0, rank_item)

            # Function Name
            func_name = item.get("candidate_name", "Unknown")
            name_item = QTableWidgetItem(func_name)
            name_item.setToolTip(func_name)
            self.table.setItem(row, 1, name_item)

            # Address
            address = item.get("candidate_address", "0x00000000")
            addr_item = QTableWidgetItem(f"0x{address:08X}" if isinstance(address, int) else str(address))
            self.table.setItem(row, 2, addr_item)

            # Similarity Score
            score = item.get("score", 0)
            score_item = QTableWidgetItem(f"{score:.1f}")
            score_item.setData(Qt.ItemDataRole.UserRole, score)  # For sorting

            # Color code based on score
            if score > 8.0:
                score_item.setBackground(QColor("#3FB950"))
            elif score > 5.0:
                score_item.setBackground(QColor("#D29922"))
            else:
                score_item.setBackground(QColor("#F85149"))

            self.table.setItem(row, 3, score_item)

            # Match Type
            match_type = self.determine_match_type(item)
            type_item = QTableWidgetItem(match_type)
            self.table.setItem(row, 4, type_item)

            # Security Risk
            risk_level = self.calculate_risk_level(item)
            risk_item = QTableWidgetItem(risk_level)

            # Color code risk level
            if risk_level == "Critical":
                risk_item.setBackground(QColor("#F85149"))
            elif risk_level == "High":
                risk_item.setBackground(QColor("#D29922"))
            elif risk_level == "Medium":
                risk_item.setBackground(QColor("#D29922"))
            else:
                risk_item.setBackground(QColor("#3FB950"))

            self.table.setItem(row, 5, risk_item)

            # Actions
            actions_widget = self.create_actions_widget(item)
            self.table.setCellWidget(row, 6, actions_widget)

        # Update results count
        self.results_count_label.setText(f"{len(self.filtered_data)} results")

        # Resize rows to content
        self.table.resizeRowsToContents()

    def determine_match_type(self, item):
        """Determine match type based on item data"""
        score = item.get("score", 0)
        if score > 9.0:
            return "Exact Match"
        elif score > 7.0:
            return "Structural Match"
        else:
            return "Partial Match"

    def calculate_risk_level(self, item):
        """Calculate security risk level"""
        score = item.get("score", 0)
        # This is a simplified risk calculation
        if score > 8.5:
            return "Critical"
        elif score > 7.0:
            return "High"
        elif score > 5.0:
            return "Medium"
        else:
            return "Low"

    def create_actions_widget(self, item):
        """Create actions widget for table row"""
        actions_widget = QWidget()
        actions_layout = QHBoxLayout(actions_widget)
        actions_layout.setContentsMargins(4, 4, 4, 4)
        actions_layout.setSpacing(4)

        # View details button
        view_btn = ModernButton("View", button_type="outline")
        view_btn.setFixedSize(50, 24)
        view_btn.clicked.connect(lambda: self.on_view_details(item))
        actions_layout.addWidget(view_btn)

        # Export button
        export_btn = ModernButton("Export", button_type="outline")
        export_btn.setFixedSize(50, 24)
        export_btn.clicked.connect(lambda: self.on_export_item(item))
        actions_layout.addWidget(export_btn)

        return actions_widget

    def on_search_changed(self, text):
        """Handle search text changes"""
        self.apply_filters_and_sorting()

    def on_filter_changed(self):
        """Handle filter changes"""
        self.apply_filters_and_sorting()

    def on_selection_changed(self):
        """Handle row selection changes"""
        current_row = self.table.currentRow()
        if current_row >= 0 and current_row < len(self.filtered_data):
            selected_item = self.filtered_data[current_row]
            self.function_selected.emit(selected_item)

    def on_item_double_clicked(self, item):
        """Handle item double-click"""
        row = item.row()
        if row >= 0 and row < len(self.filtered_data):
            selected_item = self.filtered_data[row]
            self.on_view_details(selected_item)

    def on_view_details(self, item):
        """Handle view details action"""
        # Emit signal or show details dialog
        self.function_selected.emit(item)
        # Could show a detailed dialog here

    def on_export_item(self, item):
        """Handle export item action"""
        # Implement export functionality
        QMessageBox.information(self, "Export", f"Export functionality for {item.get('candidate_name', 'Unknown')}")

    def clear_data(self):
        """Clear all data"""
        self.comparison_data = []
        self.filtered_data = []
        self.table.setRowCount(0)
        self.results_count_label.setText("0 results")


class ModernTextEdit(QTextEdit):
    """Modern text edit"""
    def __init__(self, placeholder="", parent=None):
        super().__init__(parent)
        self.setPlaceholderText(placeholder)
        self.setObjectName("modernTextEdit")
        self.setMinimumHeight(80)
        self.setWordWrapMode(QTextOption.WrapMode.WordWrap)
        optimize_widget(self)


class GraphVisualizationWidget(QGraphicsView):
    """Interactive graph visualization widget for function flow analysis"""

    node_selected = pyqtSignal(str)  # Emits node ID when selected
    node_double_clicked = pyqtSignal(str)  # Emits node ID when double-clicked

    def __init__(self, parent=None):
        super().__init__(parent)
        self.scene = QGraphicsScene(self)
        self.setScene(self.scene)

        # Configure view
        self.setRenderHint(QPainter.RenderHint.Antialiasing)
        self.setRenderHint(QPainter.RenderHint.SmoothPixmapTransform)
        self.setViewportUpdateMode(QGraphicsView.ViewportUpdateMode.FullViewportUpdate)
        self.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAsNeeded)
        self.setVerticalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAsNeeded)
        self.setTransformationAnchor(QGraphicsView.ViewportAnchor.AnchorUnderMouse)
        self.setResizeAnchor(QGraphicsView.ViewportAnchor.AnchorViewCenter)
        self.setDragMode(QGraphicsView.DragMode.RubberBandDrag)

        # Style
        self.setStyleSheet("""
            QGraphicsView {
                background-color: #0D1117;
                border: 1px solid #30363D;
                border-radius: 8px;
            }
        """)

        # Graph data
        self.nodes = {}
        self.edges = []
        self.selected_nodes = set()

        optimize_widget(self)

    def clear_graph(self):
        """Clear all nodes and edges"""
        self.scene.clear()
        self.nodes.clear()
        self.edges.clear()
        self.selected_nodes.clear()

    def add_node(self, node_id, label, node_type="normal", position=(0, 0)):
        """Add a node to the graph"""
        if node_id in self.nodes:
            return self.nodes[node_id]

        # Create node based on type
        node = GraphNode(node_id, label, node_type, position)
        node.node_selected.connect(self.on_node_selected)
        node.node_double_clicked.connect(self.on_node_double_clicked)

        self.scene.addItem(node)
        self.nodes[node_id] = node
        return node

    def add_edge(self, source_id, target_id, label=""):
        """Add an edge between two nodes"""
        if source_id not in self.nodes or target_id not in self.nodes:
            return None

        source_node = self.nodes[source_id]
        target_node = self.nodes[target_id]

        edge = GraphEdge(source_node, target_node, label)
        self.scene.addItem(edge)
        self.edges.append(edge)

        # Ensure edge is drawn behind nodes
        edge.setZValue(-1)

        return edge

    def load_graph_data(self, graph_data):
        """Load graph data from analysis results"""
        self.clear_graph()

        if not graph_data or "nodes" not in graph_data:
            return

        # Add nodes
        for node_data in graph_data.get("nodes", []):
            node_id = node_data.get("id", "")
            label = node_data.get("label", node_id)
            node_type = node_data.get("type", "normal")
            position = node_data.get("position", (0, 0))

            self.add_node(node_id, label, node_type, position)

        # Add edges
        for edge_data in graph_data.get("edges", []):
            source_id = edge_data.get("source", "")
            target_id = edge_data.get("target", "")
            label = edge_data.get("label", "")

            self.add_edge(source_id, target_id, label)

        # Auto-layout if no positions specified
        self.auto_layout()

        # Fit view to content
        self.fitInView(self.scene.sceneRect(), Qt.AspectRatioMode.KeepAspectRatio)

    def auto_layout(self):
        """Simple auto-layout for nodes without positions"""
        if not self.nodes:
            return

        import math
        # Simple circular layout
        nodes_list = list(self.nodes.values())
        center_x = 0
        center_y = 0
        radius = 200

        for i, node in enumerate(nodes_list):
            angle = (2 * 3.14159 * i) / len(nodes_list)
            x = center_x + radius * math.cos(angle)
            y = center_y + radius * math.sin(angle)
            node.setPos(x, y)

    def zoom_in(self):
        """Zoom in"""
        self.scale(1.2, 1.2)

    def zoom_out(self):
        """Zoom out"""
        self.scale(0.8, 0.8)

    def fit_to_view(self):
        """Fit graph to view"""
        if not self.scene.sceneRect().isEmpty():
            self.fitInView(self.scene.sceneRect(), Qt.AspectRatioMode.KeepAspectRatio)

    def wheelEvent(self, event):
        """Handle mouse wheel for zooming"""
        if event.modifiers() & Qt.KeyboardModifier.ControlModifier:
            zoom_factor = 1.2 if event.angleDelta().y() > 0 else 0.8
            self.scale(zoom_factor, zoom_factor)
            event.accept()
        else:
            super().wheelEvent(event)

    def mousePressEvent(self, event):
        """Handle mouse press for panning"""
        if event.button() == Qt.MouseButton.MiddleButton:
            self.setDragMode(QGraphicsView.DragMode.ScrollHandDrag)
            event.accept()
        else:
            super().mousePressEvent(event)

    def mouseReleaseEvent(self, event):
        """Handle mouse release"""
        if event.button() == Qt.MouseButton.MiddleButton:
            self.setDragMode(QGraphicsView.DragMode.RubberBandDrag)
            event.accept()
        else:
            super().mouseReleaseEvent(event)

    def on_node_selected(self, node_id):
        """Handle node selection"""
        self.node_selected.emit(node_id)

    def on_node_double_clicked(self, node_id):
        """Handle node double-click"""
        self.node_double_clicked.emit(node_id)


class GraphNode(QGraphicsItem):
    """Graph node item"""

    node_selected = pyqtSignal(str)
    node_double_clicked = pyqtSignal(str)

    def __init__(self, node_id, label, node_type="normal", position=(0, 0)):
        super().__init__()
        self.node_id = node_id
        self.label = label
        self.node_type = node_type

        # Node appearance based on type
        self.colors = {
            "entry": "#3FB950",
            "exit": "#F85149",
            "decision": "#D29922",
            "call": "#58A6FF",
            "normal": "#8B949E"
        }

        self.color = self.colors.get(node_type, "#8B949E")
        self.setPos(position[0], position[1])
        self.setFlag(QGraphicsItem.GraphicsItemFlag.ItemIsSelectable)
        self.setFlag(QGraphicsItem.GraphicsItemFlag.ItemIsMovable)
        self.setZValue(1)

    def boundingRect(self):
        """Return bounding rectangle"""
        return QRectF(-50, -25, 100, 50)

    def paint(self, painter, option, widget):
        """Paint the node"""
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)

        # Node shape (rounded rectangle)
        rect = self.boundingRect()
        painter.setBrush(QBrush(QColor(self.color)))
        painter.setPen(QPen(QColor("#30363D"), 2))
        painter.drawRoundedRect(rect, 8, 8)

        # Selection highlight
        if self.isSelected():
            painter.setPen(QPen(QColor("#1F6FEB"), 3))
            painter.setBrush(Qt.BrushStyle.NoBrush)
            painter.drawRoundedRect(rect.adjusted(-2, -2, 2, 2), 10, 10)

        # Label
        painter.setPen(QPen(QColor("#E6EDF3")))
        painter.setFont(QFont("Segoe UI", 9))
        painter.drawText(rect, Qt.AlignmentFlag.AlignCenter, self.label[:20])  # Truncate long labels

    def mousePressEvent(self, event):
        """Handle mouse press"""
        super().mousePressEvent(event)
        self.node_selected.emit(self.node_id)

    def mouseDoubleClickEvent(self, event):
        """Handle mouse double-click"""
        self.node_double_clicked.emit(self.node_id)


class GraphEdge(QGraphicsItem):
    """Graph edge item"""

    def __init__(self, source_node, target_node, label=""):
        super().__init__()
        self.source_node = source_node
        self.target_node = target_node
        self.label = label
        self.color = QColor("#8B949E")

    def boundingRect(self):
        """Return bounding rectangle"""
        source_pos = self.source_node.pos()
        target_pos = self.target_node.pos()

        # Create bounding rect that encompasses both nodes
        min_x = min(source_pos.x(), target_pos.x())
        min_y = min(source_pos.y(), target_pos.y())
        max_x = max(source_pos.x(), target_pos.x())
        max_y = max(source_pos.y(), target_pos.y())

        return QRectF(min_x - 50, min_y - 25, max_x - min_x + 100, max_y - min_y + 50)

    def paint(self, painter, option, widget):
        """Paint the edge"""
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)

        source_pos = self.source_node.pos()
        target_pos = self.target_node.pos()

        # Calculate edge line
        source_center = QPointF(source_pos.x(), source_pos.y())
        target_center = QPointF(target_pos.x(), target_pos.y())

        # Draw arrow
        painter.setPen(QPen(self.color, 2))
        painter.setBrush(QBrush(self.color))

        # Line
        line = QLineF(source_center, target_center)
        painter.drawLine(line)

        # Arrow head
        import math
        angle = line.angle()
        arrow_size = 10

        # Calculate arrow head points
        arrow_p1 = target_center + QPointF(
            -arrow_size * math.cos(math.radians(angle + 150)),
            -arrow_size * math.sin(math.radians(angle + 150))
        )
        arrow_p2 = target_center + QPointF(
            -arrow_size * math.cos(math.radians(angle - 150)),
            -arrow_size * math.sin(math.radians(angle - 150))
        )

        arrow_head = QPolygonF([target_center, arrow_p1, arrow_p2])
        painter.drawPolygon(arrow_head)


class FunctionComparisonTable(QWidget):
    """Advanced function comparison table with sorting, filtering, and virtual scrolling"""

    function_selected = pyqtSignal(dict)  # Emits function data when selected

    def __init__(self, parent=None):
        super().__init__(parent)
        self.comparison_data = []
        self.filtered_data = []
        self.sort_column = 2  # Similarity score by default
        self.sort_order = Qt.SortOrder.DescendingOrder
        self.current_filter = {}

        self.setup_ui()
        optimize_widget(self)

    def setup_ui(self):
        """Setup the table UI"""
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(12)

        # Controls row
        controls_layout = QHBoxLayout()
        controls_layout.setSpacing(12)

        # Search box
        self.search_edit = ModernLineEdit("Search functions...")
        self.search_edit.textChanged.connect(self.on_search_changed)
        controls_layout.addWidget(self.search_edit)

        # Similarity filter
        controls_layout.addWidget(ModernLabel("Similarity:", "body"))

        self.similarity_combo = QComboBox()
        self.similarity_combo.addItems(["All", "High (>80%)", "Medium (50-80%)", "Low (<50%)"])
        self.similarity_combo.currentTextChanged.connect(self.on_filter_changed)
        self.similarity_combo.setStyleSheet("""
            QComboBox {
                background-color: #161B22;
                border: 1px solid #30363D;
                border-radius: 6px;
                padding: 6px;
                color: #E6EDF3;
                min-width: 100px;
            }
        """)
        controls_layout.addWidget(self.similarity_combo)

        # Match type filter
        controls_layout.addWidget(ModernLabel("Match Type:", "body"))

        self.match_type_combo = QComboBox()
        self.match_type_combo.addItems(["All Types", "Exact Match", "Structural Match", "Partial Match"])
        self.match_type_combo.currentTextChanged.connect(self.on_filter_changed)
        self.match_type_combo.setStyleSheet(self.similarity_combo.styleSheet())
        controls_layout.addWidget(self.match_type_combo)

        controls_layout.addStretch()

        # Results count
        self.results_count_label = ModernLabel("0 results", "caption")
        self.results_count_label.setStyleSheet("color: #8B949E;")
        controls_layout.addWidget(self.results_count_label)

        layout.addLayout(controls_layout)

        # Table widget
        self.table = QTableWidget()
        self.table.setAlternatingRowColors(True)
        self.table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.table.setSortingEnabled(True)
        self.table.horizontalHeader().setSortIndicatorShown(True)

        # Set table style
        self.table.setStyleSheet("""
            QTableWidget {
                background-color: #161B22;
                border: 1px solid #30363D;
                border-radius: 8px;
                gridline-color: #30363D;
                selection-background-color: #1F6FEB;
            }
            QTableWidget::item {
                padding: 8px;
                border-bottom: 1px solid #30363D;
                color: #E6EDF3;
            }
            QTableWidget::item:selected {
                background-color: #1F6FEB;
                color: white;
            }
            QHeaderView::section {
                background-color: #1C2128;
                color: #E6EDF3;
                padding: 12px 8px;
                border: none;
                border-bottom: 1px solid #30363D;
                font-weight: 600;
            }
            QHeaderView::section:hover {
                background-color: #21262D;
            }
        """)

        # Set up columns
        columns = ["Rank", "Function Name", "Address", "Similarity", "Match Type", "Security Risk", "Actions"]
        self.table.setColumnCount(len(columns))
        self.table.setHorizontalHeaderLabels(columns)

        # Set column widths
        self.table.setColumnWidth(0, 60)   # Rank
        self.table.setColumnWidth(1, 200)  # Function Name
        self.table.setColumnWidth(2, 120)  # Address
        self.table.setColumnWidth(3, 150)  # Similarity
        self.table.setColumnWidth(4, 120)  # Match Type
        self.table.setColumnWidth(5, 140)  # Security Risk
        self.table.setColumnWidth(6, 120)  # Actions

        # Connect signals
        self.table.itemSelectionChanged.connect(self.on_selection_changed)
        self.table.itemDoubleClicked.connect(self.on_item_double_clicked)

        layout.addWidget(self.table)

    def load_comparison_data(self, comparison_results):
        """Load comparison data into the table"""
        self.comparison_data = comparison_results or []
        self.apply_filters_and_sorting()

    def apply_filters_and_sorting(self):
        """Apply current filters and sorting to data"""
        # Apply filters
        self.filtered_data = self.comparison_data[:]

        # Search filter
        search_text = self.search_edit.text().strip().lower()
        if search_text:
            self.filtered_data = [
                item for item in self.filtered_data
                if search_text in item.get("candidate_name", "").lower() or
                   search_text in item.get("candidate_address", "").lower()
            ]

        # Similarity filter
        similarity_filter = self.similarity_combo.currentText()
        if similarity_filter != "All":
            if similarity_filter == "High (>80%)":
                self.filtered_data = [item for item in self.filtered_data if item.get("score", 0) > 8.0]
            elif similarity_filter == "Medium (50-80%)":
                self.filtered_data = [item for item in self.filtered_data if 5.0 <= item.get("score", 0) <= 8.0]
            elif similarity_filter == "Low (<50%)":
                self.filtered_data = [item for item in self.filtered_data if item.get("score", 0) < 5.0]

        # Apply sorting
        if self.sort_column == 3:  # Similarity score
            reverse = self.sort_order == Qt.SortOrder.DescendingOrder
            self.filtered_data.sort(key=lambda x: x.get("score", 0), reverse=reverse)
        elif self.sort_column == 1:  # Function name
            reverse = self.sort_order == Qt.SortOrder.DescendingOrder
            self.filtered_data.sort(key=lambda x: x.get("candidate_name", "").lower(), reverse=reverse)

        # Update table
        self.update_table_display()

    def update_table_display(self):
        """Update the table display with filtered data"""
        self.table.setRowCount(len(self.filtered_data))

        for row, item in enumerate(self.filtered_data):
            # Rank
            rank_item = QTableWidgetItem(str(row + 1))
            rank_item.setData(Qt.ItemDataRole.UserRole, item)
            self.table.setItem(row, 0, rank_item)

            # Function Name
            func_name = item.get("candidate_name", "Unknown")
            name_item = QTableWidgetItem(func_name)
            name_item.setToolTip(func_name)
            self.table.setItem(row, 1, name_item)

            # Address
            address = item.get("candidate_address", "0x00000000")
            addr_item = QTableWidgetItem(f"0x{address:08X}" if isinstance(address, int) else str(address))
            self.table.setItem(row, 2, addr_item)

            # Similarity Score
            score = item.get("score", 0)
            score_item = QTableWidgetItem(f"{score:.1f}")
            score_item.setData(Qt.ItemDataRole.UserRole, score)  # For sorting

            # Color code based on score
            if score > 8.0:
                score_item.setBackground(QColor("#3FB950"))
            elif score > 5.0:
                score_item.setBackground(QColor("#D29922"))
            else:
                score_item.setBackground(QColor("#F85149"))

            self.table.setItem(row, 3, score_item)

            # Match Type
            match_type = self.determine_match_type(item)
            type_item = QTableWidgetItem(match_type)
            self.table.setItem(row, 4, type_item)

            # Security Risk
            risk_level = self.calculate_risk_level(item)
            risk_item = QTableWidgetItem(risk_level)

            # Color code risk level
            if risk_level == "Critical":
                risk_item.setBackground(QColor("#F85149"))
            elif risk_level == "High":
                risk_item.setBackground(QColor("#D29922"))
            elif risk_level == "Medium":
                risk_item.setBackground(QColor("#D29922"))
            else:
                risk_item.setBackground(QColor("#3FB950"))

            self.table.setItem(row, 5, risk_item)

            # Actions
            actions_widget = self.create_actions_widget(item)
            self.table.setCellWidget(row, 6, actions_widget)

        # Update results count
        self.results_count_label.setText(f"{len(self.filtered_data)} results")

        # Resize rows to content
        self.table.resizeRowsToContents()

    def determine_match_type(self, item):
        """Determine match type based on item data"""
        score = item.get("score", 0)
        if score > 9.0:
            return "Exact Match"
        elif score > 7.0:
            return "Structural Match"
        else:
            return "Partial Match"

    def calculate_risk_level(self, item):
        """Calculate security risk level"""
        score = item.get("score", 0)
        # This is a simplified risk calculation
        if score > 8.5:
            return "Critical"
        elif score > 7.0:
            return "High"
        elif score > 5.0:
            return "Medium"
        else:
            return "Low"

    def create_actions_widget(self, item):
        """Create actions widget for table row"""
        actions_widget = QWidget()
        actions_layout = QHBoxLayout(actions_widget)
        actions_layout.setContentsMargins(4, 4, 4, 4)
        actions_layout.setSpacing(4)

        # View details button
        view_btn = ModernButton("View", button_type="outline")
        view_btn.setFixedSize(50, 24)
        view_btn.clicked.connect(lambda: self.on_view_details(item))
        actions_layout.addWidget(view_btn)

        # Export button
        export_btn = ModernButton("Export", button_type="outline")
        export_btn.setFixedSize(50, 24)
        export_btn.clicked.connect(lambda: self.on_export_item(item))
        actions_layout.addWidget(export_btn)

        return actions_widget

    def on_search_changed(self, text):
        """Handle search text changes"""
        self.apply_filters_and_sorting()

    def on_filter_changed(self):
        """Handle filter changes"""
        self.apply_filters_and_sorting()

    def on_selection_changed(self):
        """Handle row selection changes"""
        current_row = self.table.currentRow()
        if current_row >= 0 and current_row < len(self.filtered_data):
            selected_item = self.filtered_data[current_row]
            self.function_selected.emit(selected_item)

    def on_item_double_clicked(self, item):
        """Handle item double-click"""
        row = item.row()
        if row >= 0 and row < len(self.filtered_data):
            selected_item = self.filtered_data[row]
            self.on_view_details(selected_item)

    def on_view_details(self, item):
        """Handle view details action"""
        # Emit signal or show details dialog
        self.function_selected.emit(item)
        # Could show a detailed dialog here

    def on_export_item(self, item):
        """Handle export item action"""
        # Implement export functionality
        QMessageBox.information(self, "Export", f"Export functionality for {item.get('candidate_name', 'Unknown')}")

    def clear_data(self):
        """Clear all data"""
        self.comparison_data = []
        self.filtered_data = []
        self.table.setRowCount(0)
        self.results_count_label.setText("0 results")


class ModernProgressBar(QProgressBar):
    """Modern progress bar"""
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setObjectName("modernProgressBar")
        self.setMinimumHeight(4) # Slimmer progress bar
        self.setTextVisible(False)
        self.setStyleSheet("""
            QProgressBar {
                border: none;
                background-color: #1C2128; /* bg_tertiary */
                border-radius: 2px;
            }
            QProgressBar::chunk {
                background-color: #1F6FEB; /* accent_primary */
                border-radius: 2px;
            }
        """)
        optimize_widget(self)


class GraphVisualizationWidget(QGraphicsView):
    """Interactive graph visualization widget for function flow analysis"""

    node_selected = pyqtSignal(str)  # Emits node ID when selected
    node_double_clicked = pyqtSignal(str)  # Emits node ID when double-clicked

    def __init__(self, parent=None):
        super().__init__(parent)
        self.scene = QGraphicsScene(self)
        self.setScene(self.scene)

        # Configure view
        self.setRenderHint(QPainter.RenderHint.Antialiasing)
        self.setRenderHint(QPainter.RenderHint.SmoothPixmapTransform)
        self.setViewportUpdateMode(QGraphicsView.ViewportUpdateMode.FullViewportUpdate)
        self.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAsNeeded)
        self.setVerticalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAsNeeded)
        self.setTransformationAnchor(QGraphicsView.ViewportAnchor.AnchorUnderMouse)
        self.setResizeAnchor(QGraphicsView.ViewportAnchor.AnchorViewCenter)
        self.setDragMode(QGraphicsView.DragMode.RubberBandDrag)

        # Style
        self.setStyleSheet("""
            QGraphicsView {
                background-color: #0D1117;
                border: 1px solid #30363D;
                border-radius: 8px;
            }
        """)

        # Graph data
        self.nodes = {}
        self.edges = []
        self.selected_nodes = set()

        optimize_widget(self)

    def clear_graph(self):
        """Clear all nodes and edges"""
        self.scene.clear()
        self.nodes.clear()
        self.edges.clear()
        self.selected_nodes.clear()

    def add_node(self, node_id, label, node_type="normal", position=(0, 0)):
        """Add a node to the graph"""
        if node_id in self.nodes:
            return self.nodes[node_id]

        # Create node based on type
        node = GraphNode(node_id, label, node_type, position)
        node.node_selected.connect(self.on_node_selected)
        node.node_double_clicked.connect(self.on_node_double_clicked)

        self.scene.addItem(node)
        self.nodes[node_id] = node
        return node

    def add_edge(self, source_id, target_id, label=""):
        """Add an edge between two nodes"""
        if source_id not in self.nodes or target_id not in self.nodes:
            return None

        source_node = self.nodes[source_id]
        target_node = self.nodes[target_id]

        edge = GraphEdge(source_node, target_node, label)
        self.scene.addItem(edge)
        self.edges.append(edge)

        # Ensure edge is drawn behind nodes
        edge.setZValue(-1)

        return edge

    def load_graph_data(self, graph_data):
        """Load graph data from analysis results"""
        self.clear_graph()

        if not graph_data or "nodes" not in graph_data:
            return

        # Add nodes
        for node_data in graph_data.get("nodes", []):
            node_id = node_data.get("id", "")
            label = node_data.get("label", node_id)
            node_type = node_data.get("type", "normal")
            position = node_data.get("position", (0, 0))

            self.add_node(node_id, label, node_type, position)

        # Add edges
        for edge_data in graph_data.get("edges", []):
            source_id = edge_data.get("source", "")
            target_id = edge_data.get("target", "")
            label = edge_data.get("label", "")

            self.add_edge(source_id, target_id, label)

        # Auto-layout if no positions specified
        self.auto_layout()

        # Fit view to content
        self.fitInView(self.scene.sceneRect(), Qt.AspectRatioMode.KeepAspectRatio)

    def auto_layout(self):
        """Simple auto-layout for nodes without positions"""
        if not self.nodes:
            return

        import math
        # Simple circular layout
        nodes_list = list(self.nodes.values())
        center_x = 0
        center_y = 0
        radius = 200

        for i, node in enumerate(nodes_list):
            angle = (2 * 3.14159 * i) / len(nodes_list)
            x = center_x + radius * math.cos(angle)
            y = center_y + radius * math.sin(angle)
            node.setPos(x, y)

    def zoom_in(self):
        """Zoom in"""
        self.scale(1.2, 1.2)

    def zoom_out(self):
        """Zoom out"""
        self.scale(0.8, 0.8)

    def fit_to_view(self):
        """Fit graph to view"""
        if not self.scene.sceneRect().isEmpty():
            self.fitInView(self.scene.sceneRect(), Qt.AspectRatioMode.KeepAspectRatio)

    def wheelEvent(self, event):
        """Handle mouse wheel for zooming"""
        if event.modifiers() & Qt.KeyboardModifier.ControlModifier:
            zoom_factor = 1.2 if event.angleDelta().y() > 0 else 0.8
            self.scale(zoom_factor, zoom_factor)
            event.accept()
        else:
            super().wheelEvent(event)

    def mousePressEvent(self, event):
        """Handle mouse press for panning"""
        if event.button() == Qt.MouseButton.MiddleButton:
            self.setDragMode(QGraphicsView.DragMode.ScrollHandDrag)
            event.accept()
        else:
            super().mousePressEvent(event)

    def mouseReleaseEvent(self, event):
        """Handle mouse release"""
        if event.button() == Qt.MouseButton.MiddleButton:
            self.setDragMode(QGraphicsView.DragMode.RubberBandDrag)
            event.accept()
        else:
            super().mouseReleaseEvent(event)

    def on_node_selected(self, node_id):
        """Handle node selection"""
        self.node_selected.emit(node_id)

    def on_node_double_clicked(self, node_id):
        """Handle node double-click"""
        self.node_double_clicked.emit(node_id)


class GraphNode(QGraphicsItem):
    """Graph node item"""

    node_selected = pyqtSignal(str)
    node_double_clicked = pyqtSignal(str)

    def __init__(self, node_id, label, node_type="normal", position=(0, 0)):
        super().__init__()
        self.node_id = node_id
        self.label = label
        self.node_type = node_type

        # Node appearance based on type
        self.colors = {
            "entry": "#3FB950",
            "exit": "#F85149",
            "decision": "#D29922",
            "call": "#58A6FF",
            "normal": "#8B949E"
        }

        self.color = self.colors.get(node_type, "#8B949E")
        self.setPos(position[0], position[1])
        self.setFlag(QGraphicsItem.GraphicsItemFlag.ItemIsSelectable)
        self.setFlag(QGraphicsItem.GraphicsItemFlag.ItemIsMovable)
        self.setZValue(1)

    def boundingRect(self):
        """Return bounding rectangle"""
        return QRectF(-50, -25, 100, 50)

    def paint(self, painter, option, widget):
        """Paint the node"""
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)

        # Node shape (rounded rectangle)
        rect = self.boundingRect()
        painter.setBrush(QBrush(QColor(self.color)))
        painter.setPen(QPen(QColor("#30363D"), 2))
        painter.drawRoundedRect(rect, 8, 8)

        # Selection highlight
        if self.isSelected():
            painter.setPen(QPen(QColor("#1F6FEB"), 3))
            painter.setBrush(Qt.BrushStyle.NoBrush)
            painter.drawRoundedRect(rect.adjusted(-2, -2, 2, 2), 10, 10)

        # Label
        painter.setPen(QPen(QColor("#E6EDF3")))
        painter.setFont(QFont("Segoe UI", 9))
        painter.drawText(rect, Qt.AlignmentFlag.AlignCenter, self.label[:20])  # Truncate long labels

    def mousePressEvent(self, event):
        """Handle mouse press"""
        super().mousePressEvent(event)
        self.node_selected.emit(self.node_id)

    def mouseDoubleClickEvent(self, event):
        """Handle mouse double-click"""
        self.node_double_clicked.emit(self.node_id)


class GraphEdge(QGraphicsItem):
    """Graph edge item"""

    def __init__(self, source_node, target_node, label=""):
        super().__init__()
        self.source_node = source_node
        self.target_node = target_node
        self.label = label
        self.color = QColor("#8B949E")

    def boundingRect(self):
        """Return bounding rectangle"""
        source_pos = self.source_node.pos()
        target_pos = self.target_node.pos()

        # Create bounding rect that encompasses both nodes
        min_x = min(source_pos.x(), target_pos.x())
        min_y = min(source_pos.y(), target_pos.y())
        max_x = max(source_pos.x(), target_pos.x())
        max_y = max(source_pos.y(), target_pos.y())

        return QRectF(min_x - 50, min_y - 25, max_x - min_x + 100, max_y - min_y + 50)

    def paint(self, painter, option, widget):
        """Paint the edge"""
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)

        source_pos = self.source_node.pos()
        target_pos = self.target_node.pos()

        # Calculate edge line
        source_center = QPointF(source_pos.x(), source_pos.y())
        target_center = QPointF(target_pos.x(), target_pos.y())

        # Draw arrow
        painter.setPen(QPen(self.color, 2))
        painter.setBrush(QBrush(self.color))

        # Line
        line = QLineF(source_center, target_center)
        painter.drawLine(line)

        # Arrow head
        import math
        angle = line.angle()
        arrow_size = 10

        # Calculate arrow head points
        arrow_p1 = target_center + QPointF(
            -arrow_size * math.cos(math.radians(angle + 150)),
            -arrow_size * math.sin(math.radians(angle + 150))
        )
        arrow_p2 = target_center + QPointF(
            -arrow_size * math.cos(math.radians(angle - 150)),
            -arrow_size * math.sin(math.radians(angle - 150))
        )

        arrow_head = QPolygonF([target_center, arrow_p1, arrow_p2])
        painter.drawPolygon(arrow_head)


class FunctionComparisonTable(QWidget):
    """Advanced function comparison table with sorting, filtering, and virtual scrolling"""

    function_selected = pyqtSignal(dict)  # Emits function data when selected

    def __init__(self, parent=None):
        super().__init__(parent)
        self.comparison_data = []
        self.filtered_data = []
        self.sort_column = 2  # Similarity score by default
        self.sort_order = Qt.SortOrder.DescendingOrder
        self.current_filter = {}

        self.setup_ui()
        optimize_widget(self)

    def setup_ui(self):
        """Setup the table UI"""
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(12)

        # Controls row
        controls_layout = QHBoxLayout()
        controls_layout.setSpacing(12)

        # Search box
        self.search_edit = ModernLineEdit("Search functions...")
        self.search_edit.textChanged.connect(self.on_search_changed)
        controls_layout.addWidget(self.search_edit)

        # Similarity filter
        controls_layout.addWidget(ModernLabel("Similarity:", "body"))

        self.similarity_combo = QComboBox()
        self.similarity_combo.addItems(["All", "High (>80%)", "Medium (50-80%)", "Low (<50%)"])
        self.similarity_combo.currentTextChanged.connect(self.on_filter_changed)
        self.similarity_combo.setStyleSheet("""
            QComboBox {
                background-color: #161B22;
                border: 1px solid #30363D;
                border-radius: 6px;
                padding: 6px;
                color: #E6EDF3;
                min-width: 100px;
            }
        """)
        controls_layout.addWidget(self.similarity_combo)

        # Match type filter
        controls_layout.addWidget(ModernLabel("Match Type:", "body"))

        self.match_type_combo = QComboBox()
        self.match_type_combo.addItems(["All Types", "Exact Match", "Structural Match", "Partial Match"])
        self.match_type_combo.currentTextChanged.connect(self.on_filter_changed)
        self.match_type_combo.setStyleSheet(self.similarity_combo.styleSheet())
        controls_layout.addWidget(self.match_type_combo)

        controls_layout.addStretch()

        # Results count
        self.results_count_label = ModernLabel("0 results", "caption")
        self.results_count_label.setStyleSheet("color: #8B949E;")
        controls_layout.addWidget(self.results_count_label)

        layout.addLayout(controls_layout)

        # Table widget
        self.table = QTableWidget()
        self.table.setAlternatingRowColors(True)
        self.table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.table.setSortingEnabled(True)
        self.table.horizontalHeader().setSortIndicatorShown(True)

        # Set table style
        self.table.setStyleSheet("""
            QTableWidget {
                background-color: #161B22;
                border: 1px solid #30363D;
                border-radius: 8px;
                gridline-color: #30363D;
                selection-background-color: #1F6FEB;
            }
            QTableWidget::item {
                padding: 8px;
                border-bottom: 1px solid #30363D;
                color: #E6EDF3;
            }
            QTableWidget::item:selected {
                background-color: #1F6FEB;
                color: white;
            }
            QHeaderView::section {
                background-color: #1C2128;
                color: #E6EDF3;
                padding: 12px 8px;
                border: none;
                border-bottom: 1px solid #30363D;
                font-weight: 600;
            }
            QHeaderView::section:hover {
                background-color: #21262D;
            }
        """)

        # Set up columns
        columns = ["Rank", "Function Name", "Address", "Similarity", "Match Type", "Security Risk", "Actions"]
        self.table.setColumnCount(len(columns))
        self.table.setHorizontalHeaderLabels(columns)

        # Set column widths
        self.table.setColumnWidth(0, 60)   # Rank
        self.table.setColumnWidth(1, 200)  # Function Name
        self.table.setColumnWidth(2, 120)  # Address
        self.table.setColumnWidth(3, 150)  # Similarity
        self.table.setColumnWidth(4, 120)  # Match Type
        self.table.setColumnWidth(5, 140)  # Security Risk
        self.table.setColumnWidth(6, 120)  # Actions

        # Connect signals
        self.table.itemSelectionChanged.connect(self.on_selection_changed)
        self.table.itemDoubleClicked.connect(self.on_item_double_clicked)

        layout.addWidget(self.table)

    def load_comparison_data(self, comparison_results):
        """Load comparison data into the table"""
        self.comparison_data = comparison_results or []
        self.apply_filters_and_sorting()

    def apply_filters_and_sorting(self):
        """Apply current filters and sorting to data"""
        # Apply filters
        self.filtered_data = self.comparison_data[:]

        # Search filter
        search_text = self.search_edit.text().strip().lower()
        if search_text:
            self.filtered_data = [
                item for item in self.filtered_data
                if search_text in item.get("candidate_name", "").lower() or
                   search_text in item.get("candidate_address", "").lower()
            ]

        # Similarity filter
        similarity_filter = self.similarity_combo.currentText()
        if similarity_filter != "All":
            if similarity_filter == "High (>80%)":
                self.filtered_data = [item for item in self.filtered_data if item.get("score", 0) > 8.0]
            elif similarity_filter == "Medium (50-80%)":
                self.filtered_data = [item for item in self.filtered_data if 5.0 <= item.get("score", 0) <= 8.0]
            elif similarity_filter == "Low (<50%)":
                self.filtered_data = [item for item in self.filtered_data if item.get("score", 0) < 5.0]

        # Apply sorting
        if self.sort_column == 3:  # Similarity score
            reverse = self.sort_order == Qt.SortOrder.DescendingOrder
            self.filtered_data.sort(key=lambda x: x.get("score", 0), reverse=reverse)
        elif self.sort_column == 1:  # Function name
            reverse = self.sort_order == Qt.SortOrder.DescendingOrder
            self.filtered_data.sort(key=lambda x: x.get("candidate_name", "").lower(), reverse=reverse)

        # Update table
        self.update_table_display()

    def update_table_display(self):
        """Update the table display with filtered data"""
        self.table.setRowCount(len(self.filtered_data))

        for row, item in enumerate(self.filtered_data):
            # Rank
            rank_item = QTableWidgetItem(str(row + 1))
            rank_item.setData(Qt.ItemDataRole.UserRole, item)
            self.table.setItem(row, 0, rank_item)

            # Function Name
            func_name = item.get("candidate_name", "Unknown")
            name_item = QTableWidgetItem(func_name)
            name_item.setToolTip(func_name)
            self.table.setItem(row, 1, name_item)

            # Address
            address = item.get("candidate_address", "0x00000000")
            addr_item = QTableWidgetItem(f"0x{address:08X}" if isinstance(address, int) else str(address))
            self.table.setItem(row, 2, addr_item)

            # Similarity Score
            score = item.get("score", 0)
            score_item = QTableWidgetItem(f"{score:.1f}")
            score_item.setData(Qt.ItemDataRole.UserRole, score)  # For sorting

            # Color code based on score
            if score > 8.0:
                score_item.setBackground(QColor("#3FB950"))
            elif score > 5.0:
                score_item.setBackground(QColor("#D29922"))
            else:
                score_item.setBackground(QColor("#F85149"))

            self.table.setItem(row, 3, score_item)

            # Match Type
            match_type = self.determine_match_type(item)
            type_item = QTableWidgetItem(match_type)
            self.table.setItem(row, 4, type_item)

            # Security Risk
            risk_level = self.calculate_risk_level(item)
            risk_item = QTableWidgetItem(risk_level)

            # Color code risk level
            if risk_level == "Critical":
                risk_item.setBackground(QColor("#F85149"))
            elif risk_level == "High":
                risk_item.setBackground(QColor("#D29922"))
            elif risk_level == "Medium":
                risk_item.setBackground(QColor("#D29922"))
            else:
                risk_item.setBackground(QColor("#3FB950"))

            self.table.setItem(row, 5, risk_item)

            # Actions
            actions_widget = self.create_actions_widget(item)
            self.table.setCellWidget(row, 6, actions_widget)

        # Update results count
        self.results_count_label.setText(f"{len(self.filtered_data)} results")

        # Resize rows to content
        self.table.resizeRowsToContents()

    def determine_match_type(self, item):
        """Determine match type based on item data"""
        score = item.get("score", 0)
        if score > 9.0:
            return "Exact Match"
        elif score > 7.0:
            return "Structural Match"
        else:
            return "Partial Match"

    def calculate_risk_level(self, item):
        """Calculate security risk level"""
        score = item.get("score", 0)
        # This is a simplified risk calculation
        if score > 8.5:
            return "Critical"
        elif score > 7.0:
            return "High"
        elif score > 5.0:
            return "Medium"
        else:
            return "Low"

    def create_actions_widget(self, item):
        """Create actions widget for table row"""
        actions_widget = QWidget()
        actions_layout = QHBoxLayout(actions_widget)
        actions_layout.setContentsMargins(4, 4, 4, 4)
        actions_layout.setSpacing(4)

        # View details button
        view_btn = ModernButton("View", button_type="outline")
        view_btn.setFixedSize(50, 24)
        view_btn.clicked.connect(lambda: self.on_view_details(item))
        actions_layout.addWidget(view_btn)

        # Export button
        export_btn = ModernButton("Export", button_type="outline")
        export_btn.setFixedSize(50, 24)
        export_btn.clicked.connect(lambda: self.on_export_item(item))
        actions_layout.addWidget(export_btn)

        return actions_widget

    def on_search_changed(self, text):
        """Handle search text changes"""
        self.apply_filters_and_sorting()

    def on_filter_changed(self):
        """Handle filter changes"""
        self.apply_filters_and_sorting()

    def on_selection_changed(self):
        """Handle row selection changes"""
        current_row = self.table.currentRow()
        if current_row >= 0 and current_row < len(self.filtered_data):
            selected_item = self.filtered_data[current_row]
            self.function_selected.emit(selected_item)

    def on_item_double_clicked(self, item):
        """Handle item double-click"""
        row = item.row()
        if row >= 0 and row < len(self.filtered_data):
            selected_item = self.filtered_data[row]
            self.on_view_details(selected_item)

    def on_view_details(self, item):
        """Handle view details action"""
        # Emit signal or show details dialog
        self.function_selected.emit(item)
        # Could show a detailed dialog here

    def on_export_item(self, item):
        """Handle export item action"""
        # Implement export functionality
        QMessageBox.information(self, "Export", f"Export functionality for {item.get('candidate_name', 'Unknown')}")

    def clear_data(self):
        """Clear all data"""
        self.comparison_data = []
        self.filtered_data = []
        self.table.setRowCount(0)
        self.results_count_label.setText("0 results")


class ModernLabel(QLabel):
    """Modern label"""
    def __init__(self, text="", label_type="body", parent=None):
        super().__init__(text, parent)
        self.label_type = label_type
        self.setObjectName(f"{label_type}") # e.g., "cardTitle", "subtitle"
        optimize_widget(self)


class GraphVisualizationWidget(QGraphicsView):
    """Interactive graph visualization widget for function flow analysis"""

    node_selected = pyqtSignal(str)  # Emits node ID when selected
    node_double_clicked = pyqtSignal(str)  # Emits node ID when double-clicked

    def __init__(self, parent=None):
        super().__init__(parent)
        self.scene = QGraphicsScene(self)
        self.setScene(self.scene)

        # Configure view
        self.setRenderHint(QPainter.RenderHint.Antialiasing)
        self.setRenderHint(QPainter.RenderHint.SmoothPixmapTransform)
        self.setViewportUpdateMode(QGraphicsView.ViewportUpdateMode.FullViewportUpdate)
        self.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAsNeeded)
        self.setVerticalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAsNeeded)
        self.setTransformationAnchor(QGraphicsView.ViewportAnchor.AnchorUnderMouse)
        self.setResizeAnchor(QGraphicsView.ViewportAnchor.AnchorViewCenter)
        self.setDragMode(QGraphicsView.DragMode.RubberBandDrag)

        # Style
        self.setStyleSheet("""
            QGraphicsView {
                background-color: #0D1117;
                border: 1px solid #30363D;
                border-radius: 8px;
            }
        """)

        # Graph data
        self.nodes = {}
        self.edges = []
        self.selected_nodes = set()

        optimize_widget(self)

    def clear_graph(self):
        """Clear all nodes and edges"""
        self.scene.clear()
        self.nodes.clear()
        self.edges.clear()
        self.selected_nodes.clear()

    def add_node(self, node_id, label, node_type="normal", position=(0, 0)):
        """Add a node to the graph"""
        if node_id in self.nodes:
            return self.nodes[node_id]

        # Create node based on type
        node = GraphNode(node_id, label, node_type, position)
        node.node_selected.connect(self.on_node_selected)
        node.node_double_clicked.connect(self.on_node_double_clicked)

        self.scene.addItem(node)
        self.nodes[node_id] = node
        return node

    def add_edge(self, source_id, target_id, label=""):
        """Add an edge between two nodes"""
        if source_id not in self.nodes or target_id not in self.nodes:
            return None

        source_node = self.nodes[source_id]
        target_node = self.nodes[target_id]

        edge = GraphEdge(source_node, target_node, label)
        self.scene.addItem(edge)
        self.edges.append(edge)

        # Ensure edge is drawn behind nodes
        edge.setZValue(-1)

        return edge

    def load_graph_data(self, graph_data):
        """Load graph data from analysis results"""
        self.clear_graph()

        if not graph_data or "nodes" not in graph_data:
            return

        # Add nodes
        for node_data in graph_data.get("nodes", []):
            node_id = node_data.get("id", "")
            label = node_data.get("label", node_id)
            node_type = node_data.get("type", "normal")
            position = node_data.get("position", (0, 0))

            self.add_node(node_id, label, node_type, position)

        # Add edges
        for edge_data in graph_data.get("edges", []):
            source_id = edge_data.get("source", "")
            target_id = edge_data.get("target", "")
            label = edge_data.get("label", "")

            self.add_edge(source_id, target_id, label)

        # Auto-layout if no positions specified
        self.auto_layout()

        # Fit view to content
        self.fitInView(self.scene.sceneRect(), Qt.AspectRatioMode.KeepAspectRatio)

    def auto_layout(self):
        """Simple auto-layout for nodes without positions"""
        if not self.nodes:
            return

        import math
        # Simple circular layout
        nodes_list = list(self.nodes.values())
        center_x = 0
        center_y = 0
        radius = 200

        for i, node in enumerate(nodes_list):
            angle = (2 * 3.14159 * i) / len(nodes_list)
            x = center_x + radius * math.cos(angle)
            y = center_y + radius * math.sin(angle)
            node.setPos(x, y)

    def zoom_in(self):
        """Zoom in"""
        self.scale(1.2, 1.2)

    def zoom_out(self):
        """Zoom out"""
        self.scale(0.8, 0.8)

    def fit_to_view(self):
        """Fit graph to view"""
        if not self.scene.sceneRect().isEmpty():
            self.fitInView(self.scene.sceneRect(), Qt.AspectRatioMode.KeepAspectRatio)

    def wheelEvent(self, event):
        """Handle mouse wheel for zooming"""
        if event.modifiers() & Qt.KeyboardModifier.ControlModifier:
            zoom_factor = 1.2 if event.angleDelta().y() > 0 else 0.8
            self.scale(zoom_factor, zoom_factor)
            event.accept()
        else:
            super().wheelEvent(event)

    def mousePressEvent(self, event):
        """Handle mouse press for panning"""
        if event.button() == Qt.MouseButton.MiddleButton:
            self.setDragMode(QGraphicsView.DragMode.ScrollHandDrag)
            event.accept()
        else:
            super().mousePressEvent(event)

    def mouseReleaseEvent(self, event):
        """Handle mouse release"""
        if event.button() == Qt.MouseButton.MiddleButton:
            self.setDragMode(QGraphicsView.DragMode.RubberBandDrag)
            event.accept()
        else:
            super().mouseReleaseEvent(event)

    def on_node_selected(self, node_id):
        """Handle node selection"""
        self.node_selected.emit(node_id)

    def on_node_double_clicked(self, node_id):
        """Handle node double-click"""
        self.node_double_clicked.emit(node_id)


class GraphNode(QGraphicsItem):
    """Graph node item"""

    node_selected = pyqtSignal(str)
    node_double_clicked = pyqtSignal(str)

    def __init__(self, node_id, label, node_type="normal", position=(0, 0)):
        super().__init__()
        self.node_id = node_id
        self.label = label
        self.node_type = node_type

        # Node appearance based on type
        self.colors = {
            "entry": "#3FB950",
            "exit": "#F85149",
            "decision": "#D29922",
            "call": "#58A6FF",
            "normal": "#8B949E"
        }

        self.color = self.colors.get(node_type, "#8B949E")
        self.setPos(position[0], position[1])
        self.setFlag(QGraphicsItem.GraphicsItemFlag.ItemIsSelectable)
        self.setFlag(QGraphicsItem.GraphicsItemFlag.ItemIsMovable)
        self.setZValue(1)

    def boundingRect(self):
        """Return bounding rectangle"""
        return QRectF(-50, -25, 100, 50)

    def paint(self, painter, option, widget):
        """Paint the node"""
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)

        # Node shape (rounded rectangle)
        rect = self.boundingRect()
        painter.setBrush(QBrush(QColor(self.color)))
        painter.setPen(QPen(QColor("#30363D"), 2))
        painter.drawRoundedRect(rect, 8, 8)

        # Selection highlight
        if self.isSelected():
            painter.setPen(QPen(QColor("#1F6FEB"), 3))
            painter.setBrush(Qt.BrushStyle.NoBrush)
            painter.drawRoundedRect(rect.adjusted(-2, -2, 2, 2), 10, 10)

        # Label
        painter.setPen(QPen(QColor("#E6EDF3")))
        painter.setFont(QFont("Segoe UI", 9))
        painter.drawText(rect, Qt.AlignmentFlag.AlignCenter, self.label[:20])  # Truncate long labels

    def mousePressEvent(self, event):
        """Handle mouse press"""
        super().mousePressEvent(event)
        self.node_selected.emit(self.node_id)

    def mouseDoubleClickEvent(self, event):
        """Handle mouse double-click"""
        self.node_double_clicked.emit(self.node_id)


class GraphEdge(QGraphicsItem):
    """Graph edge item"""

    def __init__(self, source_node, target_node, label=""):
        super().__init__()
        self.source_node = source_node
        self.target_node = target_node
        self.label = label
        self.color = QColor("#8B949E")

    def boundingRect(self):
        """Return bounding rectangle"""
        source_pos = self.source_node.pos()
        target_pos = self.target_node.pos()

        # Create bounding rect that encompasses both nodes
        min_x = min(source_pos.x(), target_pos.x())
        min_y = min(source_pos.y(), target_pos.y())
        max_x = max(source_pos.x(), target_pos.x())
        max_y = max(source_pos.y(), target_pos.y())

        return QRectF(min_x - 50, min_y - 25, max_x - min_x + 100, max_y - min_y + 50)

    def paint(self, painter, option, widget):
        """Paint the edge"""
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)

        source_pos = self.source_node.pos()
        target_pos = self.target_node.pos()

        # Calculate edge line
        source_center = QPointF(source_pos.x(), source_pos.y())
        target_center = QPointF(target_pos.x(), target_pos.y())

        # Draw arrow
        painter.setPen(QPen(self.color, 2))
        painter.setBrush(QBrush(self.color))

        # Line
        line = QLineF(source_center, target_center)
        painter.drawLine(line)

        # Arrow head
        import math
        angle = line.angle()
        arrow_size = 10

        # Calculate arrow head points
        arrow_p1 = target_center + QPointF(
            -arrow_size * math.cos(math.radians(angle + 150)),
            -arrow_size * math.sin(math.radians(angle + 150))
        )
        arrow_p2 = target_center + QPointF(
            -arrow_size * math.cos(math.radians(angle - 150)),
            -arrow_size * math.sin(math.radians(angle - 150))
        )

        arrow_head = QPolygonF([target_center, arrow_p1, arrow_p2])
        painter.drawPolygon(arrow_head)


class FunctionComparisonTable(QWidget):
    """Advanced function comparison table with sorting, filtering, and virtual scrolling"""

    function_selected = pyqtSignal(dict)  # Emits function data when selected

    def __init__(self, parent=None):
        super().__init__(parent)
        self.comparison_data = []
        self.filtered_data = []
        self.sort_column = 2  # Similarity score by default
        self.sort_order = Qt.SortOrder.DescendingOrder
        self.current_filter = {}

        self.setup_ui()
        optimize_widget(self)

    def setup_ui(self):
        """Setup the table UI"""
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(12)

        # Controls row
        controls_layout = QHBoxLayout()
        controls_layout.setSpacing(12)

        # Search box
        self.search_edit = ModernLineEdit("Search functions...")
        self.search_edit.textChanged.connect(self.on_search_changed)
        controls_layout.addWidget(self.search_edit)

        # Similarity filter
        controls_layout.addWidget(ModernLabel("Similarity:", "body"))

        self.similarity_combo = QComboBox()
        self.similarity_combo.addItems(["All", "High (>80%)", "Medium (50-80%)", "Low (<50%)"])
        self.similarity_combo.currentTextChanged.connect(self.on_filter_changed)
        self.similarity_combo.setStyleSheet("""
            QComboBox {
                background-color: #161B22;
                border: 1px solid #30363D;
                border-radius: 6px;
                padding: 6px;
                color: #E6EDF3;
                min-width: 100px;
            }
        """)
        controls_layout.addWidget(self.similarity_combo)

        # Match type filter
        controls_layout.addWidget(ModernLabel("Match Type:", "body"))

        self.match_type_combo = QComboBox()
        self.match_type_combo.addItems(["All Types", "Exact Match", "Structural Match", "Partial Match"])
        self.match_type_combo.currentTextChanged.connect(self.on_filter_changed)
        self.match_type_combo.setStyleSheet(self.similarity_combo.styleSheet())
        controls_layout.addWidget(self.match_type_combo)

        controls_layout.addStretch()

        # Results count
        self.results_count_label = ModernLabel("0 results", "caption")
        self.results_count_label.setStyleSheet("color: #8B949E;")
        controls_layout.addWidget(self.results_count_label)

        layout.addLayout(controls_layout)

        # Table widget
        self.table = QTableWidget()
        self.table.setAlternatingRowColors(True)
        self.table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.table.setSortingEnabled(True)
        self.table.horizontalHeader().setSortIndicatorShown(True)

        # Set table style
        self.table.setStyleSheet("""
            QTableWidget {
                background-color: #161B22;
                border: 1px solid #30363D;
                border-radius: 8px;
                gridline-color: #30363D;
                selection-background-color: #1F6FEB;
            }
            QTableWidget::item {
                padding: 8px;
                border-bottom: 1px solid #30363D;
                color: #E6EDF3;
            }
            QTableWidget::item:selected {
                background-color: #1F6FEB;
                color: white;
            }
            QHeaderView::section {
                background-color: #1C2128;
                color: #E6EDF3;
                padding: 12px 8px;
                border: none;
                border-bottom: 1px solid #30363D;
                font-weight: 600;
            }
            QHeaderView::section:hover {
                background-color: #21262D;
            }
        """)

        # Set up columns
        columns = ["Rank", "Function Name", "Address", "Similarity", "Match Type", "Security Risk", "Actions"]
        self.table.setColumnCount(len(columns))
        self.table.setHorizontalHeaderLabels(columns)

        # Set column widths
        self.table.setColumnWidth(0, 60)   # Rank
        self.table.setColumnWidth(1, 200)  # Function Name
        self.table.setColumnWidth(2, 120)  # Address
        self.table.setColumnWidth(3, 150)  # Similarity
        self.table.setColumnWidth(4, 120)  # Match Type
        self.table.setColumnWidth(5, 140)  # Security Risk
        self.table.setColumnWidth(6, 120)  # Actions

        # Connect signals
        self.table.itemSelectionChanged.connect(self.on_selection_changed)
        self.table.itemDoubleClicked.connect(self.on_item_double_clicked)

        layout.addWidget(self.table)

    def load_comparison_data(self, comparison_results):
        """Load comparison data into the table"""
        self.comparison_data = comparison_results or []
        self.apply_filters_and_sorting()

    def apply_filters_and_sorting(self):
        """Apply current filters and sorting to data"""
        # Apply filters
        self.filtered_data = self.comparison_data[:]

        # Search filter
        search_text = self.search_edit.text().strip().lower()
        if search_text:
            self.filtered_data = [
                item for item in self.filtered_data
                if search_text in item.get("candidate_name", "").lower() or
                   search_text in item.get("candidate_address", "").lower()
            ]

        # Similarity filter
        similarity_filter = self.similarity_combo.currentText()
        if similarity_filter != "All":
            if similarity_filter == "High (>80%)":
                self.filtered_data = [item for item in self.filtered_data if item.get("score", 0) > 8.0]
            elif similarity_filter == "Medium (50-80%)":
                self.filtered_data = [item for item in self.filtered_data if 5.0 <= item.get("score", 0) <= 8.0]
            elif similarity_filter == "Low (<50%)":
                self.filtered_data = [item for item in self.filtered_data if item.get("score", 0) < 5.0]

        # Apply sorting
        if self.sort_column == 3:  # Similarity score
            reverse = self.sort_order == Qt.SortOrder.DescendingOrder
            self.filtered_data.sort(key=lambda x: x.get("score", 0), reverse=reverse)
        elif self.sort_column == 1:  # Function name
            reverse = self.sort_order == Qt.SortOrder.DescendingOrder
            self.filtered_data.sort(key=lambda x: x.get("candidate_name", "").lower(), reverse=reverse)

        # Update table
        self.update_table_display()

    def update_table_display(self):
        """Update the table display with filtered data"""
        self.table.setRowCount(len(self.filtered_data))

        for row, item in enumerate(self.filtered_data):
            # Rank
            rank_item = QTableWidgetItem(str(row + 1))
            rank_item.setData(Qt.ItemDataRole.UserRole, item)
            self.table.setItem(row, 0, rank_item)

            # Function Name
            func_name = item.get("candidate_name", "Unknown")
            name_item = QTableWidgetItem(func_name)
            name_item.setToolTip(func_name)
            self.table.setItem(row, 1, name_item)

            # Address
            address = item.get("candidate_address", "0x00000000")
            addr_item = QTableWidgetItem(f"0x{address:08X}" if isinstance(address, int) else str(address))
            self.table.setItem(row, 2, addr_item)

            # Similarity Score
            score = item.get("score", 0)
            score_item = QTableWidgetItem(f"{score:.1f}")
            score_item.setData(Qt.ItemDataRole.UserRole, score)  # For sorting

            # Color code based on score
            if score > 8.0:
                score_item.setBackground(QColor("#3FB950"))
            elif score > 5.0:
                score_item.setBackground(QColor("#D29922"))
            else:
                score_item.setBackground(QColor("#F85149"))

            self.table.setItem(row, 3, score_item)

            # Match Type
            match_type = self.determine_match_type(item)
            type_item = QTableWidgetItem(match_type)
            self.table.setItem(row, 4, type_item)

            # Security Risk
            risk_level = self.calculate_risk_level(item)
            risk_item = QTableWidgetItem(risk_level)

            # Color code risk level
            if risk_level == "Critical":
                risk_item.setBackground(QColor("#F85149"))
            elif risk_level == "High":
                risk_item.setBackground(QColor("#D29922"))
            elif risk_level == "Medium":
                risk_item.setBackground(QColor("#D29922"))
            else:
                risk_item.setBackground(QColor("#3FB950"))

            self.table.setItem(row, 5, risk_item)

            # Actions
            actions_widget = self.create_actions_widget(item)
            self.table.setCellWidget(row, 6, actions_widget)

        # Update results count
        self.results_count_label.setText(f"{len(self.filtered_data)} results")

        # Resize rows to content
        self.table.resizeRowsToContents()

    def determine_match_type(self, item):
        """Determine match type based on item data"""
        score = item.get("score", 0)
        if score > 9.0:
            return "Exact Match"
        elif score > 7.0:
            return "Structural Match"
        else:
            return "Partial Match"

    def calculate_risk_level(self, item):
        """Calculate security risk level"""
        score = item.get("score", 0)
        # This is a simplified risk calculation
        if score > 8.5:
            return "Critical"
        elif score > 7.0:
            return "High"
        elif score > 5.0:
            return "Medium"
        else:
            return "Low"

    def create_actions_widget(self, item):
        """Create actions widget for table row"""
        actions_widget = QWidget()
        actions_layout = QHBoxLayout(actions_widget)
        actions_layout.setContentsMargins(4, 4, 4, 4)
        actions_layout.setSpacing(4)

        # View details button
        view_btn = ModernButton("View", button_type="outline")
        view_btn.setFixedSize(50, 24)
        view_btn.clicked.connect(lambda: self.on_view_details(item))
        actions_layout.addWidget(view_btn)

        # Export button
        export_btn = ModernButton("Export", button_type="outline")
        export_btn.setFixedSize(50, 24)
        export_btn.clicked.connect(lambda: self.on_export_item(item))
        actions_layout.addWidget(export_btn)

        return actions_widget

    def on_search_changed(self, text):
        """Handle search text changes"""
        self.apply_filters_and_sorting()

    def on_filter_changed(self):
        """Handle filter changes"""
        self.apply_filters_and_sorting()

    def on_selection_changed(self):
        """Handle row selection changes"""
        current_row = self.table.currentRow()
        if current_row >= 0 and current_row < len(self.filtered_data):
            selected_item = self.filtered_data[current_row]
            self.function_selected.emit(selected_item)

    def on_item_double_clicked(self, item):
        """Handle item double-click"""
        row = item.row()
        if row >= 0 and row < len(self.filtered_data):
            selected_item = self.filtered_data[row]
            self.on_view_details(selected_item)

    def on_view_details(self, item):
        """Handle view details action"""
        # Emit signal or show details dialog
        self.function_selected.emit(item)
        # Could show a detailed dialog here

    def on_export_item(self, item):
        """Handle export item action"""
        # Implement export functionality
        QMessageBox.information(self, "Export", f"Export functionality for {item.get('candidate_name', 'Unknown')}")

    def clear_data(self):
        """Clear all data"""
        self.comparison_data = []
        self.filtered_data = []
        self.table.setRowCount(0)
        self.results_count_label.setText("0 results")


class FileSelectionWidget(QWidget):
    """Modern file selection widget"""
    file_selected = pyqtSignal(str)

    def __init__(self, title, file_filter, widget_id="", parent=None):
        super().__init__(parent)
        self.title = title
        self.file_filter = file_filter
        self.widget_id = widget_id or title.lower().replace(" ", "_")
        self.selected_file = ""
        self.recent_files = []
        self.max_recent_files = 5
        self.load_recent_files()
        self.setup_ui()

    def setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(6)

        title_label = ModernLabel(self.title, "body") # Changed to body for cleaner look inside card
        title_label.setStyleSheet("font-weight: 600; color: #E6EDF3;") # text_primary
        layout.addWidget(title_label)

        # Container for input + buttons
        input_container = QHBoxLayout()
        input_container.setContentsMargins(0, 0, 0, 0)
        input_container.setSpacing(8)

        self.file_path_edit = ModernLineEdit("No file selected")
        self.file_path_edit.setReadOnly(True)
        input_container.addWidget(self.file_path_edit)

        browse_btn = ModernButton("Browse", button_type="secondary")
        browse_btn.clicked.connect(self.browse_file)
        input_container.addWidget(browse_btn)

        layout.addLayout(input_container)

        # Tools row (Recent / Clear)
        tools_layout = QHBoxLayout()
        tools_layout.setSpacing(10)

        self.recent_btn = ModernButton("Recent", button_type="outline")
        self.recent_btn.setFixedHeight(28) # Smaller aux buttons
        self.recent_btn.clicked.connect(self.show_recent_menu)
        self.recent_btn.setEnabled(len(self.recent_files) > 0)
        tools_layout.addWidget(self.recent_btn)

        clear_btn = ModernButton("Clear", button_type="outline")
        clear_btn.setFixedHeight(28)
        clear_btn.clicked.connect(self.clear_selection)
        tools_layout.addWidget(clear_btn)

        tools_layout.addStretch()
        layout.addLayout(tools_layout)

        self.setAcceptDrops(True)

    def browse_file(self):
        file_path, _ = QFileDialog.getOpenFileName(self, f"Select {self.title}", "", self.file_filter)
        if file_path:
            self.set_selected_file(file_path)

    def clear_selection(self):
        self.selected_file = ""
        self.file_path_edit.setText("No file selected")
        self.file_selected.emit("")

    def set_selected_file(self, file_path):
        if os.path.exists(file_path):
            self.selected_file = file_path
            self.file_path_edit.setText(os.path.basename(file_path))
            self.add_to_recent_files(file_path)
            self.file_selected.emit(file_path)

    def dragEnterEvent(self, event):
        if event.mimeData().hasUrls(): event.accept()
        else: event.ignore()

    def dropEvent(self, event):
        if event.mimeData().hasUrls():
            file_path = event.mimeData().urls()[0].toLocalFile()
            if os.path.isfile(file_path):
                self.set_selected_file(file_path)
            event.accept()
        else: event.ignore()

    def load_recent_files(self):
        settings = QSettings("LogicFlowAnalysis", "RecentFiles")
        recent_files_str = settings.value(f"{self.widget_id}_recent", "")
        if recent_files_str:
            self.recent_files = [f for f in recent_files_str.split("|||") if f and os.path.exists(f)]

    def save_recent_files(self):
        settings = QSettings("LogicFlowAnalysis", "RecentFiles")
        recent_files_str = "|||".join(self.recent_files)
        settings.setValue(f"{self.widget_id}_recent", recent_files_str)

    def add_to_recent_files(self, file_path):
        if file_path in self.recent_files:
            self.recent_files.remove(file_path)
        self.recent_files.insert(0, file_path)
        self.recent_files = self.recent_files[:self.max_recent_files]
        self.save_recent_files()
        self.recent_btn.setEnabled(len(self.recent_files) > 0)

    def show_recent_menu(self):
        if not self.recent_files: return
        menu = QMenu(self)
        # Apply dark style to menu - using design system colors
        menu.setStyleSheet(f"""
            QMenu {{ background-color: #161B22; border: 1px solid #30363D; color: #E6EDF3; }} /* surface_default, surface_border, text_primary */
            QMenu::item {{ padding: 5px 20px; }} 
            QMenu::item:selected {{ background-color: #1F6FEB; color: white; }} /* accent_primary */
        """)
        for file_path in self.recent_files:
            if os.path.exists(file_path):
                file_name = os.path.basename(file_path)
                action = QAction(file_name, self)
                action.setToolTip(file_path)
                action.triggered.connect(lambda checked, path=file_path: self.set_selected_file(path))
                menu.addAction(action)
        if menu.actions():
            menu.exec(self.recent_btn.mapToGlobal(self.recent_btn.rect().bottomLeft()))


class BatchAnalysisDialog(QDialog):
    """Dialog for configuring batch analysis"""
    analysis_requested = pyqtSignal(list, str, str)

    def __init__(self, baseline_manager, parent=None):
        super().__init__(parent)
        self.baseline_manager = baseline_manager
        self.baseline_signature = None
        self.setup_ui()

    def populate_baselines(self):
        """Populate baseline combo box"""
        baselines = self.baseline_manager.list_baselines()
        for baseline in baselines:
            # Assumes baseline is a dict with 'name' and 'path' or similar
            # If string, use directly. Adjust based on BaselineManager implementation.
            display_text = baseline.get("name", "Unknown Baseline") if isinstance(baseline, dict) else str(baseline)
            user_data = baseline
            self.baseline_combo.addItem(display_text, user_data)

    def setup_ui(self):
        self.setWindowTitle("Batch Analysis Configuration")
        self.setModal(True)
        self.resize(600, 500)
        
        # Style dialog - using design system colors
        self.setStyleSheet("QDialog { background-color: #0D1117; color: #E6EDF3; }") # bg_primary, text_primary

        layout = QVBoxLayout(self)
        layout.setSpacing(16)

        title = ModernLabel("Batch Logic Flow Analysis", "cardTitle")
        title.setStyleSheet("font-size: 16px; color: #E6EDF3; margin-bottom: 10px;") # title font size, text_primary
        layout.addWidget(title)

        desc = ModernLabel("Compare a baseline driver against multiple target drivers.", "body")
        layout.addWidget(desc)

        # Baseline Group
        baseline_group = QGroupBox("Baseline Driver")
        baseline_layout = QVBoxLayout(baseline_group)
        self.baseline_combo = QComboBox()
        self.baseline_combo.addItem("Select baseline...", "")
        self.populate_baselines()
        self.baseline_combo.currentIndexChanged.connect(self.on_baseline_selected)
        baseline_layout.addWidget(self.baseline_combo)
        self.baseline_info = ModernLabel("", "caption")
        self.baseline_info.setStyleSheet("color: #6E7681; font-style: italic;") # text_tertiary
        baseline_layout.addWidget(self.baseline_info)
        layout.addWidget(baseline_group)

        # Target Group
        target_group = QGroupBox("Target Drivers")
        target_layout = QVBoxLayout(target_group)
        
        dir_layout = QHBoxLayout()
        self.target_dir_edit = ModernLineEdit("No directory selected")
        self.target_dir_edit.setReadOnly(True)
        dir_layout.addWidget(self.target_dir_edit)
        browse_dir_btn = ModernButton("Browse", button_type="secondary")
        browse_dir_btn.clicked.connect(self.browse_target_directory)
        dir_layout.addWidget(browse_dir_btn)
        target_layout.addLayout(dir_layout)

        filter_layout = QHBoxLayout()
        filter_layout.addWidget(ModernLabel("File filter:", "body"))
        self.file_filter_edit = ModernLineEdit("*.sys")
        filter_layout.addWidget(self.file_filter_edit)
        target_layout.addLayout(filter_layout)

        self.files_preview = ModernTextEdit("No files selected")
        self.files_preview.setMaximumHeight(80)
        target_layout.addWidget(self.files_preview)
        layout.addWidget(target_group)

        # Output Group
        output_group = QGroupBox("Output Directory")
        output_layout = QHBoxLayout(output_group)
        self.output_dir_edit = ModernLineEdit("No directory selected")
        self.output_dir_edit.setReadOnly(True)
        output_layout.addWidget(self.output_dir_edit)
        browse_output_btn = ModernButton("Browse", button_type="secondary")
        browse_output_btn.clicked.connect(self.browse_output_directory)
        output_layout.addWidget(browse_output_btn)
        layout.addWidget(output_group)

        layout.addStretch()

        # Action Buttons
        button_layout = QHBoxLayout()
        analyze_btn = ModernButton("Start Batch Analysis", button_type="primary")
        analyze_btn.clicked.connect(self.start_batch_analysis)
        button_layout.addWidget(analyze_btn)
        
        cancel_btn = ModernButton("Cancel", button_type="outline")
        cancel_btn.clicked.connect(self.reject)
        button_layout.addWidget(cancel_btn)
        layout.addLayout(button_layout)
        
        optimize_widget(self)

    def on_baseline_selected(self, index):
        """Handle baseline selection change"""
        baseline_data = self.baseline_combo.itemData(index)
        if baseline_data and baseline_data != "":
            # Display baseline info
            if isinstance(baseline_data, dict):
                self.baseline_info.setText(f"Loaded: {baseline_data.get('name', 'Unknown')}")
                self.baseline_signature = baseline_data
            else:
                self.baseline_info.setText(f"Selected: {baseline_data}")
                self.baseline_signature = baseline_data
        else:
            self.baseline_info.setText("")
            self.baseline_signature = None

    def browse_target_directory(self):
        """Browse for target directory containing drivers"""
        directory = QFileDialog.getExistingDirectory(self, "Select Target Directory")
        if directory:
            self.target_dir_edit.setText(directory)
            self.update_files_preview()

    def update_files_preview(self):
        """Update the files preview based on target directory and filter"""
        target_dir = self.target_dir_edit.text()
        file_filter = self.file_filter_edit.text() or "*.sys"
        
        if target_dir and os.path.isdir(target_dir):
            import glob
            pattern = os.path.join(target_dir, file_filter)
            files = glob.glob(pattern)
            if files:
                preview_text = f"Found {len(files)} files:\n" + "\n".join(os.path.basename(f) for f in files[:10])
                if len(files) > 10:
                    preview_text += f"\n... and {len(files) - 10} more"
                self.files_preview.setText(preview_text)
            else:
                self.files_preview.setText(f"No files matching '{file_filter}' found")
        else:
            self.files_preview.setText("No files selected")

    def browse_output_directory(self):
        """Browse for output directory"""
        directory = QFileDialog.getExistingDirectory(self, "Select Output Directory")
        if directory:
            self.output_dir_edit.setText(directory)

    def start_batch_analysis(self):
        """Start the batch analysis"""
        if not self.baseline_signature:
            QMessageBox.warning(self, "Error", "Please select a baseline driver first.")
            return
        
        target_dir = self.target_dir_edit.text()
        if not target_dir or not os.path.isdir(target_dir):
            QMessageBox.warning(self, "Error", "Please select a valid target directory.")
            return
        
        output_dir = self.output_dir_edit.text()
        if not output_dir:
            QMessageBox.warning(self, "Error", "Please select an output directory.")
            return
        
        # Get list of target files
        import glob
        file_filter = self.file_filter_edit.text() or "*.sys"
        pattern = os.path.join(target_dir, file_filter)
        target_files = glob.glob(pattern)
        
        if not target_files:
            QMessageBox.warning(self, "Error", f"No files matching '{file_filter}' found in target directory.")
            return
        
        # Emit signal and close dialog
        self.analysis_requested.emit(target_files, str(self.baseline_signature), output_dir)
        self.accept()


class GraphVisualizationWidget(QGraphicsView):
    """Interactive graph visualization widget for function flow analysis"""

    node_selected = pyqtSignal(str)  # Emits node ID when selected
    node_double_clicked = pyqtSignal(str)  # Emits node ID when double-clicked

    def __init__(self, parent=None):
        super().__init__(parent)
        self.scene = QGraphicsScene(self)
        self.setScene(self.scene)

        # Configure view
        self.setRenderHint(QPainter.RenderHint.Antialiasing)
        self.setRenderHint(QPainter.RenderHint.SmoothPixmapTransform)
        self.setViewportUpdateMode(QGraphicsView.ViewportUpdateMode.FullViewportUpdate)
        self.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAsNeeded)
        self.setVerticalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAsNeeded)
        self.setTransformationAnchor(QGraphicsView.ViewportAnchor.AnchorUnderMouse)
        self.setResizeAnchor(QGraphicsView.ViewportAnchor.AnchorViewCenter)
        self.setDragMode(QGraphicsView.DragMode.RubberBandDrag)

        # Style
        self.setStyleSheet("""
            QGraphicsView {
                background-color: #0D1117;
                border: 1px solid #30363D;
                border-radius: 8px;
            }
        """)

        # Graph data
        self.nodes = {}
        self.edges = []
        self.selected_nodes = set()

        optimize_widget(self)
        self.show_empty_state()

    def clear_graph(self):
        """Clear all nodes and edges"""
        self.scene.clear()
        self.nodes.clear()
        self.edges.clear()
        self.selected_nodes.clear()
        self.show_empty_state()

    def show_empty_state(self, message="Initial state: No graph loaded"):
        """Show empty state message"""
        self.scene.clear()
        
        # Create text item
        text_item = self.scene.addText(message)
        text_item.setDefaultTextColor(QColor("#8B949E"))
        font = QFont("Segoe UI", 14)
        text_item.setFont(font)
        
        # Center in view
        # We need to approximate center since view might resize
        # For now, just place at 0,0 and we rely on fit_to_view usually
        text_item.setPos(-text_item.boundingRect().width()/2, -text_item.boundingRect().height()/2)


    def add_node(self, node_id, label, node_type="normal", position=(0, 0)):
        """Add a node to the graph"""
        if node_id in self.nodes:
            return self.nodes[node_id]

        # Create node based on type
        node = GraphNode(node_id, label, node_type, position)
        node.node_selected.connect(self.on_node_selected)
        node.node_double_clicked.connect(self.on_node_double_clicked)

        self.scene.addItem(node)
        self.nodes[node_id] = node
        return node

    def add_edge(self, source_id, target_id, label="", edge_type="direct"):
        """Add an edge between two nodes with optional type for coloring"""
        if source_id not in self.nodes or target_id not in self.nodes:
            return None

        source_node = self.nodes[source_id]
        target_node = self.nodes[target_id]

        edge = GraphEdge(source_node, target_node, label, edge_type)
        self.scene.addItem(edge)
        self.edges.append(edge)

        # Ensure edge is drawn behind nodes
        edge.setZValue(-1)

        return edge

    def load_graph_data(self, graph_data):
        """Load graph data from analysis results with A/B separation"""
        self.clear_graph()

        if not graph_data or "nodes" not in graph_data:
            return

        # Separate nodes by graph (A = baseline, B = target)
        nodes_a = []
        nodes_b = []
        
        for node_data in graph_data.get("nodes", []):
            node_id = node_data.get("id", "")
            label = node_data.get("label", node_id)
            node_type = node_data.get("type", "normal")
            graph = node_data.get("graph", "B")  # Default to B for backwards compat

            self.add_node(node_id, label, node_type, (0, 0))
            
            if graph == "A":
                nodes_a.append(node_id)
            else:
                nodes_b.append(node_id)

        # Add edges with type for coloring
        for edge_data in graph_data.get("edges", []):
            source_id = edge_data.get("source", "")
            target_id = edge_data.get("target", "")
            label = edge_data.get("label", "")
            edge_type = edge_data.get("type", "direct")

            self.add_edge(source_id, target_id, label, edge_type)

        # Side-by-side layout for A/B comparison
        self.layout_side_by_side(nodes_a, nodes_b)

        # Fit view to content
        self.fitInView(self.scene.sceneRect(), Qt.AspectRatioMode.KeepAspectRatio)
    
    def layout_side_by_side(self, nodes_a, nodes_b):
        """Layout nodes in two columns: Graph A (left) and Graph B (right)"""
        import math
        
        spacing = 120
        gap_between_graphs = 300  # Horizontal gap between A and B
        
        # Header Styling
        header_font = QFont("Segoe UI", 14, QFont.Weight.Bold)
        
        # Layout Graph A (left side)
        if nodes_a:
            # Add Graph A Header
            header_a = self.scene.addSimpleText("📊 Graph A (Baseline)")
            header_a.setFont(header_font)
            header_a.setBrush(QBrush(QColor("#58A6FF")))  # Blue tint
            header_a.setPos(0, -80)

            cols = max(1, int(math.ceil(math.sqrt(len(nodes_a)))))
            for i, node_id in enumerate(nodes_a):
                if node_id in self.nodes:
                    row = i // cols
                    col = i % cols
                    x = col * spacing
                    y = row * spacing
                    self.nodes[node_id].setPos(x, y)
        
        # Calculate offset for Graph B
        offset_x = 0
        if nodes_a:
            cols_a = max(1, int(math.ceil(math.sqrt(len(nodes_a)))))
            offset_x = cols_a * spacing + gap_between_graphs
            
            # Draw Separator Line
            max_height = max(len(nodes_a), len(nodes_b)) * spacing / cols_a if cols_a else 1000
            line_x = offset_x - gap_between_graphs / 2
            sep_line = self.scene.addLine(line_x, -100, line_x, max_height + 100)
            sep_line.setPen(QPen(QColor("#30363D"), 2, Qt.PenStyle.DashLine))
        
        # Layout Graph B (right side)
        if nodes_b:
            # Add Graph B Header
            header_b = self.scene.addSimpleText("📊 Graph B (Target)")
            header_b.setFont(header_font)
            header_b.setBrush(QBrush(QColor("#3FB950")))  # Green tint
            header_b.setPos(offset_x, -80)

            cols = max(1, int(math.ceil(math.sqrt(len(nodes_b)))))
            for i, node_id in enumerate(nodes_b):
                if node_id in self.nodes:
                    row = i // cols
                    col = i % cols
                    x = offset_x + col * spacing
                    y = row * spacing
                    self.nodes[node_id].setPos(x, y)

    def auto_layout(self):
        """Improved auto-layout for nodes - scales with count"""
        if not self.nodes:
            return

        import math
        nodes_list = list(self.nodes.values())
        node_count = len(nodes_list)
        
        # For very large graphs, use grid layout instead of circular
        if node_count > 100:
            # Grid layout - more readable for large graphs
            cols = int(math.ceil(math.sqrt(node_count)))
            spacing = 150  # Space between nodes
            
            for i, node in enumerate(nodes_list):
                row = i // cols
                col = i % cols
                x = col * spacing
                y = row * spacing
                node.setPos(x, y)
        else:
            # Circular layout for smaller graphs
            center_x = 0
            center_y = 0
            # Dynamic radius based on node count (min 200, scales with count)
            radius = max(200, node_count * 15)

            for i, node in enumerate(nodes_list):
                angle = (2 * math.pi * i) / node_count
                x = center_x + radius * math.cos(angle)
                y = center_y + radius * math.sin(angle)
                node.setPos(x, y)

    def zoom_in(self):
        """Zoom in"""
        self.scale(1.2, 1.2)

    def zoom_out(self):
        """Zoom out"""
        self.scale(0.8, 0.8)

    def fit_to_view(self):
        """Fit graph to view"""
        if not self.scene.sceneRect().isEmpty():
            self.fitInView(self.scene.sceneRect(), Qt.AspectRatioMode.KeepAspectRatio)

    def wheelEvent(self, event):
        """Handle mouse wheel for zooming"""
        if event.modifiers() & Qt.KeyboardModifier.ControlModifier:
            zoom_factor = 1.2 if event.angleDelta().y() > 0 else 0.8
            self.scale(zoom_factor, zoom_factor)
            event.accept()
        else:
            super().wheelEvent(event)

    def mousePressEvent(self, event):
        """Handle mouse press for panning"""
        if event.button() == Qt.MouseButton.MiddleButton:
            self.setDragMode(QGraphicsView.DragMode.ScrollHandDrag)
            event.accept()
        else:
            super().mousePressEvent(event)

    def mouseReleaseEvent(self, event):
        """Handle mouse release"""
        if event.button() == Qt.MouseButton.MiddleButton:
            self.setDragMode(QGraphicsView.DragMode.RubberBandDrag)
            event.accept()
        else:
            super().mouseReleaseEvent(event)

    def on_node_selected(self, node_id):
        """Handle node selection"""
        self.node_selected.emit(node_id)

    def on_node_double_clicked(self, node_id):
        """Handle node double-click"""
        self.node_double_clicked.emit(node_id)


class GraphNode(QGraphicsObject):
    """Graph node item - uses QGraphicsObject to support signals"""

    node_selected = pyqtSignal(str)
    node_double_clicked = pyqtSignal(str)

    def __init__(self, node_id, label, node_type="normal", position=(0, 0)):
        super().__init__()
        self.node_id = node_id
        self.label = label
        self.node_type = node_type

        # Node appearance based on type
        self.colors = {
            "entry": "#3FB950",
            "exit": "#F85149",
            "decision": "#D29922",
            "call": "#58A6FF",
            "normal": "#8B949E",
            # Diff colors
            "added": "#3FB950",      # Green
            "removed": "#F85149",    # Red
            "modified": "#D29922",   # Orange
            "unchanged": "#21262D"   # Dark Gray (faded)
        }

        self.color = self.colors.get(node_type, "#8B949E")
        self.setPos(position[0], position[1])
        self.setFlag(QGraphicsItem.GraphicsItemFlag.ItemIsSelectable)
        self.setFlag(QGraphicsItem.GraphicsItemFlag.ItemIsMovable)
        self.setZValue(1)

    def boundingRect(self):
        """Return bounding rectangle"""
        return QRectF(-50, -25, 100, 50)

    def paint(self, painter, option, widget):
        """Paint the node"""
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)

        # Node properties
        rect = self.boundingRect()
        color = QColor(self.color)
        pen = QPen(QColor("#30363D"), 2)
        
        # Selection highlight
        if self.isSelected():
            pen = QPen(QColor("#1F6FEB"), 3)

        painter.setPen(pen)
        painter.setBrush(QBrush(color))

        # Draw shape based on type
        if "decision" in self.node_type or "jump" in self.node_type:
            # Draw Diamond
            path = QPainterPath()
            path.moveTo(rect.center().x(), rect.top())
            path.lineTo(rect.right(), rect.center().y())
            path.lineTo(rect.center().x(), rect.bottom())
            path.lineTo(rect.left(), rect.center().y())
            path.closeSubpath()
            painter.drawPath(path)
        else:
            # Draw Rounded Rectangle
            painter.drawRoundedRect(rect, 8, 8)

        # Label
        painter.setPen(QPen(QColor("#E6EDF3")))
        painter.setFont(QFont("Segoe UI", 9))
        painter.drawText(rect, Qt.AlignmentFlag.AlignCenter, self.label[:25])  # Check for truncate


class GraphEdge(QGraphicsItem):
    """Graph edge item with colored directional arrows"""
    
    # Edge type color mapping
    EDGE_COLORS = {
        "direct": "#3B82F6",    # Blue - direct calls
        "indirect": "#F59E0B", # Orange - indirect/computed
        "xref": "#10B981",     # Green - cross references
        "true": "#3FB950",     # Green - conditional true
        "false": "#F85149",    # Red - conditional false
        "default": "#6B7280"   # Gray - unknown
    }

    def __init__(self, source_node, target_node, label="", edge_type="direct"):
        super().__init__()
        self.source_node = source_node
        self.target_node = target_node
        self.label = label
        self.edge_type = edge_type
        self.color = QColor(self.EDGE_COLORS.get(edge_type, self.EDGE_COLORS["default"]))
        self.setZValue(-1)

    def boundingRect(self):
        """Return bounding rectangle"""
        source_pos = self.source_node.pos()
        target_pos = self.target_node.pos()
        min_x = min(source_pos.x(), target_pos.x())
        min_y = min(source_pos.y(), target_pos.y())
        max_x = max(source_pos.x(), target_pos.x())
        max_y = max(source_pos.y(), target_pos.y())
        return QRectF(min_x - 100, min_y - 100, max_x - min_x + 200, max_y - min_y + 200)

    def paint(self, painter, option, widget):
        """Paint the edge with curved bezier line and arrow"""
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)

        source_pos = self.source_node.pos()
        target_pos = self.target_node.pos()

        # Simple node center calculation (assuming node size ~100x50)
        source_center = QPointF(source_pos.x(), source_pos.y())
        target_center = QPointF(target_pos.x(), target_pos.y())

        # Determine start/end points at node boundaries
        # Rough approximation: center to center, then shorten
        line_vec = target_center - source_center
        length = math.sqrt(line_vec.x()**2 + line_vec.y()**2)
        
        if length < 1:
            return

        # Shorten line to touch node edges (approx 40px radius)
        shorten = 40
        unit_vec = line_vec / length
        source_edge = source_center + unit_vec * shorten
        target_edge = target_center - unit_vec * shorten

        # Draw Curved Path (Bezier)
        path = QPainterPath()
        path.moveTo(source_edge)
        
        # Control points for smooth curve
        # Curve intensity depends on distance
        curve_dist = length * 0.3
        
        # Logic for curve direction to look like flowchart
        # If mainly vertical
        if abs(line_vec.y()) > abs(line_vec.x()):
             ctrl1 = source_edge + QPointF(0, curve_dist)
             ctrl2 = target_edge - QPointF(0, curve_dist)
        else:
             # Mainly horizontal
             ctrl1 = source_edge + QPointF(curve_dist, 0)
             ctrl2 = target_edge - QPointF(curve_dist, 0)

        path.cubicTo(ctrl1, ctrl2, target_edge)

        # Draw Path
        pen = QPen(self.color, 2)
        pen.setCapStyle(Qt.PenCapStyle.RoundCap)
        painter.setPen(pen)
        painter.setBrush(Qt.BrushStyle.NoBrush)
        painter.drawPath(path)

        # Draw Arrowhead
        arrow_size = 15  # Larger arrowhead
        angle = math.atan2(line_vec.y(), line_vec.x())
        
        # Use target_edge for arrow tip
        arrow_p1 = target_edge - QPointF(
            arrow_size * math.cos(angle - math.pi/6),
            arrow_size * math.sin(angle - math.pi/6)
        )
        arrow_p2 = target_edge - QPointF(
            arrow_size * math.cos(angle + math.pi/6),
            arrow_size * math.sin(angle + math.pi/6)
        )

        painter.setBrush(QBrush(self.color))
        painter.drawPolygon(QPolygonF([target_edge, arrow_p1, arrow_p2]))
        
        # Draw Label if exists
        if self.label:
            painter.setPen(QPen(QColor("#E6EDF3")))
            mid_point = path.pointAtPercent(0.5)
            painter.drawText(mid_point, self.label)


class FunctionComparisonTable(QWidget):
    """Advanced function comparison table with sorting, filtering, and virtual scrolling"""

    function_selected = pyqtSignal(dict)  # Emits function data when selected

    def __init__(self, parent=None):
        super().__init__(parent)
        self.comparison_data = []
        self.filtered_data = []
        self.sort_column = 2  # Similarity score by default
        self.sort_order = Qt.SortOrder.DescendingOrder
        self.current_filter = {}

        self.setup_ui()
        optimize_widget(self)

    def setup_ui(self):
        """Setup the table UI"""
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(12)

        # Controls row
        controls_layout = QHBoxLayout()
        controls_layout.setSpacing(12)

        # Search box
        self.search_edit = ModernLineEdit("Search functions...")
        self.search_edit.textChanged.connect(self.on_search_changed)
        controls_layout.addWidget(self.search_edit)

        # Similarity filter
        controls_layout.addWidget(ModernLabel("Similarity:", "body"))

        self.similarity_combo = QComboBox()
        self.similarity_combo.addItems(["All", "High (>80%)", "Medium (50-80%)", "Low (<50%)"])
        self.similarity_combo.currentTextChanged.connect(self.on_filter_changed)
        self.similarity_combo.setStyleSheet("""
            QComboBox {
                background-color: #161B22;
                border: 1px solid #30363D;
                border-radius: 6px;
                padding: 6px;
                color: #E6EDF3;
                min-width: 100px;
            }
        """)
        controls_layout.addWidget(self.similarity_combo)

        # Match type filter
        controls_layout.addWidget(ModernLabel("Match Type:", "body"))

        self.match_type_combo = QComboBox()
        self.match_type_combo.addItems(["All Types", "Exact Match", "Structural Match", "Partial Match"])
        self.match_type_combo.currentTextChanged.connect(self.on_filter_changed)
        self.match_type_combo.setStyleSheet(self.similarity_combo.styleSheet())
        controls_layout.addWidget(self.match_type_combo)

        controls_layout.addStretch()

        # Results count
        self.results_count_label = ModernLabel("0 results", "caption")
        self.results_count_label.setStyleSheet("color: #8B949E;")
        controls_layout.addWidget(self.results_count_label)

        layout.addLayout(controls_layout)

        # Table widget
        self.table = QTableWidget()
        self.table.setAlternatingRowColors(True)
        self.table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.table.setSortingEnabled(True)
        self.table.horizontalHeader().setSortIndicatorShown(True)

        # Set table style
        self.table.setStyleSheet("""
            QTableWidget {
                background-color: #161B22;
                border: 1px solid #30363D;
                border-radius: 8px;
                gridline-color: #30363D;
                selection-background-color: #1F6FEB;
            }
            QTableWidget::item {
                padding: 8px;
                border-bottom: 1px solid #30363D;
                color: #E6EDF3;
            }
            QTableWidget::item:selected {
                background-color: #1F6FEB;
                color: white;
            }
            QHeaderView::section {
                background-color: #1C2128;
                color: #E6EDF3;
                padding: 12px 8px;
                border: none;
                border-bottom: 1px solid #30363D;
                font-weight: 600;
            }
            QHeaderView::section:hover {
                background-color: #21262D;
            }
        """)

        # Set up columns
        columns = ["Rank", "Function Name", "Address", "Similarity", "Match Type", "Security Risk", "Actions"]
        self.table.setColumnCount(len(columns))
        self.table.setHorizontalHeaderLabels(columns)

        # Set column widths
        self.table.setColumnWidth(0, 60)   # Rank
        self.table.setColumnWidth(1, 200)  # Function Name
        self.table.setColumnWidth(2, 120)  # Address
        self.table.setColumnWidth(3, 150)  # Similarity
        self.table.setColumnWidth(4, 120)  # Match Type
        self.table.setColumnWidth(5, 140)  # Security Risk
        self.table.setColumnWidth(6, 120)  # Actions

        # Connect signals
        self.table.itemSelectionChanged.connect(self.on_selection_changed)
        self.table.itemDoubleClicked.connect(self.on_item_double_clicked)

        layout.addWidget(self.table)

    def load_comparison_data(self, comparison_results):
        """Load comparison data into the table"""
        self.comparison_data = comparison_results or []
        self.apply_filters_and_sorting()

    def apply_filters_and_sorting(self):
        """Apply current filters and sorting to data"""
        # Apply filters
        self.filtered_data = self.comparison_data[:]

        # Search filter
        search_text = self.search_edit.text().strip().lower()
        if search_text:
            self.filtered_data = [
                item for item in self.filtered_data
                if search_text in item.get("candidate_name", "").lower() or
                   search_text in item.get("candidate_address", "").lower()
            ]

        # Similarity filter
        similarity_filter = self.similarity_combo.currentText()
        if similarity_filter != "All":
            if similarity_filter == "High (>80%)":
                self.filtered_data = [item for item in self.filtered_data if item.get("score", 0) > 8.0]
            elif similarity_filter == "Medium (50-80%)":
                self.filtered_data = [item for item in self.filtered_data if 5.0 <= item.get("score", 0) <= 8.0]
            elif similarity_filter == "Low (<50%)":
                self.filtered_data = [item for item in self.filtered_data if item.get("score", 0) < 5.0]

        # Apply sorting
        if self.sort_column == 3:  # Similarity score
            reverse = self.sort_order == Qt.SortOrder.DescendingOrder
            self.filtered_data.sort(key=lambda x: x.get("score", 0), reverse=reverse)
        elif self.sort_column == 1:  # Function name
            reverse = self.sort_order == Qt.SortOrder.DescendingOrder
            self.filtered_data.sort(key=lambda x: x.get("candidate_name", "").lower(), reverse=reverse)

        # Update table
        self.update_table_display()

    def update_table_display(self):
        """Update the table display with filtered data"""
        self.table.setRowCount(len(self.filtered_data))

        for row, item in enumerate(self.filtered_data):
            # Rank
            rank_item = QTableWidgetItem(str(row + 1))
            rank_item.setData(Qt.ItemDataRole.UserRole, item)
            self.table.setItem(row, 0, rank_item)

            # Function Name - handle both key formats
            func_name = item.get("function_name") or item.get("candidate_name") or "Unknown"
            name_item = QTableWidgetItem(func_name)
            name_item.setToolTip(func_name)
            self.table.setItem(row, 1, name_item)

            # Address - handle both formats
            address = item.get("address") or item.get("candidate_address") or "0x00000000"
            if isinstance(address, int):
                addr_str = f"0x{address:08X}"
            else:
                addr_str = str(address)
            addr_item = QTableWidgetItem(addr_str)
            self.table.setItem(row, 2, addr_item)

            # Similarity Score - handle both formats (score 0-10 or similarity 0-1)
            score = item.get("score") or item.get("similarity", 0)
            if isinstance(score, float) and score <= 1.0:
                # Convert 0-1 to percentage
                display_score = score * 100
            else:
                display_score = float(score) * 10 if score <= 10 else score
            
            score_item = QTableWidgetItem(f"{display_score:.1f}%")
            score_item.setData(Qt.ItemDataRole.UserRole, display_score)

            # Color code based on percentage
            if display_score > 80:
                score_item.setBackground(QColor("#3FB950"))  # Green
            elif display_score > 50:
                score_item.setBackground(QColor("#D29922"))  # Yellow
            else:
                score_item.setBackground(QColor("#F85149"))  # Red

            self.table.setItem(row, 3, score_item)

            # Match Type
            match_type = item.get("status") or self.determine_match_type(item)
            type_item = QTableWidgetItem(match_type)
            self.table.setItem(row, 4, type_item)

            # Security Risk
            risk = item.get("risk", "low")
            risk_item = QTableWidgetItem(risk.capitalize())
            if risk.lower() == "high":
                risk_item.setForeground(QColor("#F85149"))
            elif risk.lower() == "medium":
                risk_item.setForeground(QColor("#D29922"))
            else:
                risk_item.setForeground(QColor("#8B949E"))
            self.table.setItem(row, 5, risk_item)

            # Actions button
            actions_widget = QWidget()
            actions_layout = QHBoxLayout(actions_widget)
            actions_layout.setContentsMargins(4, 2, 4, 2)
            actions_layout.setSpacing(4)

            view_btn = QPushButton("View")
            view_btn.setFixedSize(45, 24)
            view_btn.setStyleSheet("""
                QPushButton {
                    background-color: #21262D;
                    border: 1px solid #30363D;
                    border-radius: 4px;
                    color: #58A6FF;
                    font-size: 11px;
                }
                QPushButton:hover {
                    background-color: #30363D;
                }
            """)
            view_btn.clicked.connect(lambda checked, r=row: self.on_view_function(r))
            actions_layout.addWidget(view_btn)

            export_btn = QPushButton("Exp")
            export_btn.setFixedSize(35, 24)
            export_btn.setStyleSheet("""
                QPushButton {
                    background-color: #21262D;
                    border: 1px solid #30363D;
                    border-radius: 4px;
                    color: #8B949E;
                    font-size: 11px;
                }
                QPushButton:hover {
                    background-color: #30363D;
                }
            """)
            export_btn.clicked.connect(lambda checked, r=row: self.on_export_function(r))
            actions_layout.addWidget(export_btn)

            self.table.setCellWidget(row, 6, actions_widget)

        # Update result count
        self.results_count_label.setText(f"{len(self.filtered_data)} results")
        
        # Resize rows to content
        self.table.resizeRowsToContents()

    def determine_match_type(self, item):
        """Determine match type based on item data"""
        score = item.get("score", 0)
        if score > 9.0:
            return "Exact Match"
        elif score > 7.0:
            return "Structural Match"
        else:
            return "Partial Match"

    def calculate_risk_level(self, item):
        """Calculate security risk level"""
        score = item.get("score", 0)
        # This is a simplified risk calculation
        if score > 8.5:
            return "Critical"
        elif score > 7.0:
            return "High"
        elif score > 5.0:
            return "Medium"
        else:
            return "Low"

    def create_actions_widget(self, item):
        """Create actions widget for table row"""
        actions_widget = QWidget()
        actions_layout = QHBoxLayout(actions_widget)
        actions_layout.setContentsMargins(4, 4, 4, 4)
        actions_layout.setSpacing(4)

        # View details button
        view_btn = ModernButton("View", button_type="outline")
        view_btn.setFixedSize(50, 24)
        view_btn.clicked.connect(lambda: self.on_view_details(item))
        actions_layout.addWidget(view_btn)

        # Export button
        export_btn = ModernButton("Export", button_type="outline")
        export_btn.setFixedSize(50, 24)
        export_btn.clicked.connect(lambda: self.on_export_item(item))
        actions_layout.addWidget(export_btn)

        return actions_widget

    def on_search_changed(self, text):
        """Handle search text changes"""
        self.apply_filters_and_sorting()

    def on_filter_changed(self):
        """Handle filter changes"""
        self.apply_filters_and_sorting()

    def on_selection_changed(self):
        """Handle row selection changes"""
        current_row = self.table.currentRow()
        if current_row >= 0 and current_row < len(self.filtered_data):
            selected_item = self.filtered_data[current_row]
            self.function_selected.emit(selected_item)

    def on_item_double_clicked(self, item):
        """Handle item double-click"""
        row = item.row()
        if row >= 0 and row < len(self.filtered_data):
            selected_item = self.filtered_data[row]
            self.on_view_details(selected_item)

    def on_view_details(self, item):
        """Handle view details action"""
        # Emit signal or show details dialog
        self.function_selected.emit(item)
        # Could show a detailed dialog here

    def on_export_item(self, item):
        """Handle export item action"""
        # Implement export functionality
        QMessageBox.information(self, "Export", f"Export functionality for {item.get('candidate_name', 'Unknown')}")

    def on_view_function(self, row: int):
        """Handle View button click by row index."""
        if 0 <= row < len(self.filtered_data):
            item = self.filtered_data[row]
            self.on_view_details(item)
    
    def on_export_function(self, row: int):
        """Handle Export button click by row index."""
        if 0 <= row < len(self.filtered_data):
            item = self.filtered_data[row]
            self.on_export_item(item)

    def clear_data(self):
        """Clear all data"""
        self.comparison_data = []
        self.filtered_data = []
        self.table.setRowCount(0)
        self.results_count_label.setText("0 results")

    def populate_baselines(self):
        baselines = self.baseline_manager.list_baselines()
        for baseline in baselines:
            display_text = f"{baseline['name']} ({os.path.basename(baseline['driver_path'])})"
            self.baseline_combo.addItem(display_text, baseline['signature_id'])

    def on_baseline_selected(self, index):
        if index <= 0:
            self.baseline_info.setText("")
            self.baseline_signature = None
            return
        signature_id = self.baseline_combo.itemData(index)
        if signature_id:
            info = self.baseline_manager.get_baseline_info(signature_id)
            if info:
                self.baseline_signature = self.baseline_manager.load_baseline(signature_id)
                self.baseline_info.setText(f"Driver: {info['driver_path']}")

    def browse_target_directory(self):
        directory = QFileDialog.getExistingDirectory(self, "Select Target Drivers Directory")
        if directory:
            self.target_dir_edit.setText(directory)
            self.update_files_preview()

    def browse_output_directory(self):
        directory = QFileDialog.getExistingDirectory(self, "Select Output Directory")
        if directory: self.output_dir_edit.setText(directory)

    def update_files_preview(self):
        target_dir = self.target_dir_edit.text()
        file_filter = self.file_filter_edit.text()
        if not target_dir or target_dir == "No directory selected": return
        try:
            import glob
            files = glob.glob(os.path.join(target_dir, file_filter))
            if files:
                preview = f"Found {len(files)} files:\n" + "\n".join([os.path.basename(f) for f in sorted(files)[:5]])
                if len(files) > 5: preview += f"\n... and {len(files)-5} more"
                self.files_preview.setText(preview)
            else: self.files_preview.setText("No matching files found")
        except Exception as e: self.files_preview.setText(f"Error: {e}")

    def start_batch_analysis(self):
        if not self.baseline_signature:
            QMessageBox.warning(self, "Error", "Please select a baseline signature")
            return
        if self.target_dir_edit.text() == "No directory selected":
            QMessageBox.warning(self, "Error", "Please select a target directory")
            return
        if self.output_dir_edit.text() == "No directory selected":
            QMessageBox.warning(self, "Error", "Please select an output directory")
            return

        import glob
        files = glob.glob(os.path.join(self.target_dir_edit.text(), self.file_filter_edit.text()))
        if not files:
            QMessageBox.warning(self, "Error", "No target files found")
            return

        self.analysis_requested.emit(files, self.output_dir_edit.text(), self.baseline_signature.name)
class SecurityInsightsWidget(QWidget):
    """
    Widget for displaying security analysis insights.
    Shows categorized cards for patches, vulnerabilities, and other findings.
    """
    def __init__(self, parent=None):
        super().__init__(parent)
        self.layout = QVBoxLayout(self)
        self.layout.setContentsMargins(0, 0, 0, 0)
        self.layout.setSpacing(16)
        
        # Risk Header
        self.header_widget = QWidget()
        header_layout = QHBoxLayout(self.header_widget)
        header_layout.setContentsMargins(16, 16, 16, 16)
        self.header_widget.setStyleSheet("""
            QWidget {
                background-color: #161B22;
                border: 1px solid #30363D;
                border-radius: 8px;
            }
        """)
        
        self.risk_label = QLabel("Overall Risk: Unknown")
        self.risk_label.setStyleSheet("font-size: 16px; font-weight: bold; color: #8B949E;")
        header_layout.addWidget(self.risk_label)
        
        self.layout.addWidget(self.header_widget)

        # Scroll area for insights list
        self.scroll_area = QScrollArea()
        self.scroll_area.setWidgetResizable(True)
        self.scroll_area.setFrameShape(QFrame.Shape.NoFrame)
        self.scroll_area.setStyleSheet("background: transparent;")
        
        self.content_widget = QWidget()
        self.content_layout = QVBoxLayout(self.content_widget)
        self.content_layout.setSpacing(12)
        self.content_layout.addStretch() # Push content up
        
        self.scroll_area.setWidget(self.content_widget)
        self.layout.addWidget(self.scroll_area)

        optimize_widget(self)

    def update_insights(self, insights: dict):
        """Populate the widget with insight cards"""
        # Clear existing items (except stretch)
        while self.content_layout.count() > 1:
            item = self.content_layout.takeAt(0)
            if item.widget():
                item.widget().deleteLater()
                
        # Update Header
        risk = insights.get('overall_risk', 'UNKNOWN')
        color = "#8B949E"
        if risk == "CRITICAL": color = "#F85149"
        elif risk == "HIGH": color = "#D29922"
        elif risk == "MEDIUM": color = "#A371F7"
        elif risk == "LOW": color = "#3FB950"
        
        self.risk_label.setText(f"Overall Risk: {risk}")
        self.risk_label.setStyleSheet(f"font-size: 16px; font-weight: bold; color: {color}; border: none; background: transparent;")
        self.header_widget.setStyleSheet(f"""
            QWidget {{
                background-color: #161B22;
                border: 1px solid {color};
                border-radius: 8px;
            }}
        """)

        # Add Insights
        findings = sorted(insights.get('findings', []), key=lambda x: x.get('confidence', 0), reverse=True)
        
        if not findings:
            lbl = QLabel("No significant security insights found.")
            lbl.setStyleSheet("color: #8B949E; padding: 20px;")
            lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
            self.content_layout.insertWidget(0, lbl)
            return

        for finding in findings:
            card = self.create_finding_card(finding)
            self.content_layout.insertWidget(self.content_layout.count() - 1, card)

    def create_finding_card(self, finding: dict):
        """Create a card for a single finding"""
        card = QWidget()
        card.setStyleSheet("""
            QWidget {
                background-color: #0D1117;
                border: 1px solid #30363D;
                border-radius: 6px;
            }
            QWidget:hover {
                background-color: #161B22;
                border-color: #58A6FF;
            }
        """)
        layout = QVBoxLayout(card)
        layout.setContentsMargins(12, 12, 12, 12)
        
        # Header: Type | Confidence
        header = QHBoxLayout()
        f_type = finding.get('type', 'Info').upper()
        conf = finding.get('confidence', 0)
        
        type_lbl = QLabel(f_type)
        type_lbl.setStyleSheet("font-weight: bold; color: #E6EDF3; border: none; background: transparent;")
        
        conf_lbl = QLabel(f"Confidence: {conf:.0%}")
        conf_lbl.setStyleSheet("color: #8B949E; font-size: 11px; border: none; background: transparent;")
        
        header.addWidget(type_lbl)
        header.addStretch()
        header.addWidget(conf_lbl)
        layout.addLayout(header)
        
        # Description
        desc = QLabel(finding.get('description', 'No description'))
        desc.setWordWrap(True)
        desc.setStyleSheet("color: #C9D1D9; margin-top: 4px; border: none; background: transparent;")
        layout.addWidget(desc)
        
        # Details (Address / Function)
        details_txt = ""
        if 'address' in finding:
            details_txt += f"Address: {hex(finding['address'])} "
        if 'related_function' in finding:
            details_txt += f"Function: {finding['related_function']}"
            
        if details_txt:
            det = QLabel(details_txt)
            det.setStyleSheet("color: #8B949E; font-family: Consolas; font-size: 11px; margin-top: 8px; border: none; background: transparent;")
            layout.addWidget(det)
            
        return card

class SimpleChartWidget(QWidget):
    """Simple Donut Chart Widget for Similarity Distribution"""
    def __init__(self, title="Similarity Distribution", parent=None):
        super().__init__(parent)
        self.title = title
        # Default data
        self.data = {"Match": 0, "Partial": 0, "No Match": 100} 
        self.colors = {
            "Match": QColor("#238636"),   # GitHub Green
            "Partial": QColor("#D29922"), # GitHub Orange
            "No Match": QColor("#DA3633") # GitHub Red
        }
        self.setMinimumSize(300, 250)
        self.setStyleSheet("background: transparent;")

    def set_data(self, data):
        """Update chart data. data: {'Match': count, ...}"""
        self.data = data
        self.update() # Trigger repaint

    def paintEvent(self, event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        
        rect = self.rect()
        center = rect.center()
        # Radius logic
        min_side = min(rect.width(), rect.height())
        outer_radius = min_side * 0.35
        inner_radius = outer_radius * 0.60 # Create donut hole
        
        # Draw Title
        painter.setPen(QColor("#FFFFFF"))
        font = painter.font()
        font.setBold(True)
        font.setPointSize(10)
        painter.setFont(font)
        painter.drawText(QRect(0, 5, rect.width(), 30), Qt.AlignmentFlag.AlignCenter, self.title)
        
        # Calculate totals
        total = sum(self.data.values())
        if total == 0:
            # Draw empty gray circle
            painter.setBrush(QColor("#30363D"))
            painter.setPen(Qt.PenStyle.NoPen)
            painter.drawEllipse(center, outer_radius, outer_radius)
            return

        start_angle = 90 * 16 # Start from top
        
        # Draw Donut Slices
        for label, value in self.data.items():
            if value == 0: continue
            
            # Angle is in 1/16th of a degree
            span_angle = int((value / total) * 360 * 16)
            
            # Set color
            color = self.colors.get(label, QColor("#8B949E"))
            painter.setBrush(color)
            painter.setPen(Qt.PenStyle.NoPen)
            
            # Draw pie slice
            painter.drawPie(int(center.x() - outer_radius), int(center.y() - outer_radius), 
                          int(outer_radius * 2), int(outer_radius * 2), 
                          start_angle, -span_angle)
            
            start_angle -= span_angle
            
        # Draw inner circle (Hole) to make it a Donut
        painter.setBrush(QColor("#0D1117")) # Match background color (approx)
        painter.setPen(Qt.PenStyle.NoPen)
        painter.drawEllipse(center, inner_radius, inner_radius)
        
        # Draw Center Text (Total Functions)
        font.setPointSize(14)
        font.setBold(True)
        painter.setFont(font)
        painter.setPen(QColor("#FFFFFF"))
        painter.drawText(QRect(int(center.x() - inner_radius), int(center.y() - inner_radius), 
                             int(inner_radius*2), int(inner_radius*2)), 
                       Qt.AlignmentFlag.AlignCenter, str(total))
        
        font.setPointSize(8)
        font.setBold(False)
        painter.setFont(font)
        painter.setPen(QColor("#8B949E"))
        painter.drawText(QRect(int(center.x() - inner_radius), int(center.y() + 10), 
                             int(inner_radius*2), 20), 
                       Qt.AlignmentFlag.AlignCenter, "Funcs")

        # Draw Legend at bottom
        legend_y = int(center.y() + outer_radius + 20)
        font.setPointSize(9)
        painter.setFont(font)
        
        # Layout legend items specifically
        # Simple row layout: [Color] Match  [Color] Partial  [Color] No M.
        
        # Approximate widths
        item_width = 80
        total_legend_width = 3 * item_width
        start_x = int(center.x() - total_legend_width / 2)
        
        current_x = start_x
        order = ["Match", "Partial", "No Match"]
        
        for label in order:
            val = self.data.get(label, 0)
            col = self.colors.get(label)
            
            # Draw dot
            painter.setBrush(col)
            painter.setPen(Qt.PenStyle.NoPen)
            painter.drawEllipse(current_x, legend_y, 8, 8)
            
            # Draw text
            painter.setPen(QColor("#C9D1D9"))
            painter.drawText(current_x + 12, legend_y + 9, f"{label} ({val})")
            
            current_x += item_width + 10


class MetadataComparisonWidget(QWidget):
    """Side-by-side metadata comparison for two driver files."""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setMinimumSize(400, 200)
        self.setStyleSheet("background: transparent;")
        
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        
        # Title
        title = QLabel("📋 File Metadata Comparison")
        title.setStyleSheet("font-size: 14px; font-weight: bold; color: #E6EDF3; padding: 8px 0;")
        layout.addWidget(title)
        
        # Table
        self.table = QTableWidget(5, 3)  # 5 rows, 3 columns (Field, A, B)
        self.table.setHorizontalHeaderLabels(["Property", "Driver A", "Driver B"])
        self.table.verticalHeader().setVisible(False)
        self.table.horizontalHeader().setStretchLastSection(True)
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.table.setStyleSheet("""
            QTableWidget {
                background-color: #0D1117;
                border: 1px solid #30363D;
                border-radius: 6px;
                gridline-color: #21262D;
            }
            QTableWidget::item {
                padding: 8px;
                color: #C9D1D9;
            }
            QHeaderView::section {
                background-color: #161B22;
                color: #8B949E;
                padding: 8px;
                border: none;
                font-weight: bold;
            }
        """)
        
        # Initialize rows
        fields = ["File Size", "Architecture", "Entry Point", "Functions", "Edges"]
        for i, field in enumerate(fields):
            self.table.setItem(i, 0, QTableWidgetItem(field))
        
        layout.addWidget(self.table)
    
    def set_metadata(self, metadata_a: dict, metadata_b: dict):
        """Update the table with metadata from both drivers."""
        # Driver A
        self.table.setItem(0, 1, QTableWidgetItem(metadata_a.get("file_size", "N/A")))
        self.table.setItem(1, 1, QTableWidgetItem(metadata_a.get("arch", "x64")))
        self.table.setItem(2, 1, QTableWidgetItem(metadata_a.get("entry_point", "N/A")))
        self.table.setItem(3, 1, QTableWidgetItem(str(metadata_a.get("func_count", 0))))
        self.table.setItem(4, 1, QTableWidgetItem(str(metadata_a.get("edge_count", 0))))
        
        # Driver B
        self.table.setItem(0, 2, QTableWidgetItem(metadata_b.get("file_size", "N/A")))
        self.table.setItem(1, 2, QTableWidgetItem(metadata_b.get("arch", "x64")))
        self.table.setItem(2, 2, QTableWidgetItem(metadata_b.get("entry_point", "N/A")))
        self.table.setItem(3, 2, QTableWidgetItem(str(metadata_b.get("func_count", 0))))
        self.table.setItem(4, 2, QTableWidgetItem(str(metadata_b.get("edge_count", 0))))
        
        # Highlight differences
        for row in range(5):
            item_a = self.table.item(row, 1)
            item_b = self.table.item(row, 2)
            if item_a and item_b and item_a.text() != item_b.text():
                item_a.setBackground(QColor("#3D2920"))  # Orange tint
                item_b.setBackground(QColor("#3D2920"))


class ColorPickerDialog(QDialog):
    """Dialog for customizing graph edge colors."""
    
    colors_changed = pyqtSignal(dict)  # Emits new color mapping
    
    def __init__(self, current_colors: dict = None, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Customize Edge Colors")
        self.setFixedSize(350, 280)
        self.setStyleSheet("""
            QDialog {
                background-color: #161B22;
                border: 1px solid #30363D;
            }
            QLabel {
                color: #C9D1D9;
                font-size: 13px;
            }
            QPushButton {
                background-color: #21262D;
                border: 1px solid #30363D;
                border-radius: 6px;
                padding: 8px 16px;
                color: #C9D1D9;
            }
            QPushButton:hover {
                background-color: #30363D;
            }
        """)
        
        # Default colors
        self.colors = current_colors or {
            "direct": "#58A6FF",
            "indirect": "#F78166",
            "conditional": "#7EE787"
        }
        
        layout = QVBoxLayout(self)
        layout.setSpacing(16)
        layout.setContentsMargins(24, 24, 24, 24)
        
        # Title
        title = QLabel("🎨 Edge Color Configuration")
        title.setStyleSheet("font-size: 16px; font-weight: bold; color: #E6EDF3;")
        layout.addWidget(title)
        
        # Color rows
        self.color_buttons = {}
        edge_types = [
            ("direct", "Direct Calls", "#58A6FF"),
            ("indirect", "Indirect Calls", "#F78166"),
            ("conditional", "Conditional Jumps", "#7EE787")
        ]
        
        for key, label_text, default_color in edge_types:
            row = QHBoxLayout()
            label = QLabel(label_text)
            label.setFixedWidth(150)
            
            btn = QPushButton()
            btn.setFixedSize(60, 30)
            color = self.colors.get(key, default_color)
            btn.setStyleSheet(f"background-color: {color}; border-radius: 4px;")
            btn.clicked.connect(lambda checked, k=key, b=btn: self._pick_color(k, b))
            
            self.color_buttons[key] = btn
            row.addWidget(label)
            row.addWidget(btn)
            row.addStretch()
            layout.addLayout(row)
        
        layout.addStretch()
        
        # Buttons
        btn_layout = QHBoxLayout()
        
        reset_btn = QPushButton("Reset Defaults")
        reset_btn.clicked.connect(self._reset_defaults)
        btn_layout.addWidget(reset_btn)
        
        btn_layout.addStretch()
        
        apply_btn = QPushButton("Apply")
        apply_btn.setStyleSheet("background-color: #238636; color: white;")
        apply_btn.clicked.connect(self._apply_and_close)
        btn_layout.addWidget(apply_btn)
        
        layout.addLayout(btn_layout)
    
    def _pick_color(self, key, button):
        from PyQt6.QtWidgets import QColorDialog
        color = QColorDialog.getColor(QColor(self.colors[key]), self, f"Pick {key} color")
        if color.isValid():
            self.colors[key] = color.name()
            button.setStyleSheet(f"background-color: {color.name()}; border-radius: 4px;")
    
    def _reset_defaults(self):
        defaults = {"direct": "#58A6FF", "indirect": "#F78166", "conditional": "#7EE787"}
        self.colors = defaults.copy()
        for key, btn in self.color_buttons.items():
            btn.setStyleSheet(f"background-color: {defaults[key]}; border-radius: 4px;")
    
    def _apply_and_close(self):
        self.colors_changed.emit(self.colors)
        self.accept()