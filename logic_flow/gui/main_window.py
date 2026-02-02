"""
Main Window for Logic Flow Analysis Tool

Provides the primary GUI interface for the analysis application.
"""

import sys
import os
import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Optional, Dict, Any

from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QLabel, QProgressBar, QFrame, QSplitter, QScrollArea,
    QGroupBox, QFormLayout, QTabWidget, QTreeWidget, QTreeWidgetItem,
    QStatusBar, QSystemTrayIcon, QMenu, QMessageBox, QFileDialog, QSpinBox, QCompleter, QInputDialog, QComboBox, QLineEdit,
    QTableWidget, QHeaderView
)
from PyQt6.QtCore import (
    Qt, QThread, pyqtSignal, QTimer, QPropertyAnimation,
    QEasingCurve, QRect, QSize, QPoint, QPointF, QSettings, QThreadPool
)
from PyQt6.QtGui import (
    QFont, QIcon, QPixmap, QColor, QPalette, QPainter,
    QBrush, QPen, QAction, QFontDatabase, QPainterPath,
    QTextOption
)

from .widgets import (
    ModernCard, ModernButton, ModernLineEdit, ModernTextEdit,
    ModernProgressBar, ModernLabel, FileSelectionWidget, BatchAnalysisDialog,
    GraphVisualizationWidget, FunctionComparisonTable, SecurityInsightsWidget, SimpleChartWidget,
    MetadataComparisonWidget, ColorPickerDialog
)
from .resources import (
    get_search_icon, get_folder_icon, get_settings_icon, get_bug_icon,
    get_play_icon, get_save_icon, get_clear_icon, get_load_icon,
    get_sun_icon, get_moon_icon, get_chart_icon, get_shield_icon, get_list_icon
)
from ..utils.qt_helper import (
    setup_qt_environment, optimize_widget, optimize_application,
    optimize_scroll_area, optimize_text_edit, create_performance_timer,
    batch_widget_updates, deferred_update, Worker
)
from ..utils.config import ConfigManager
from ..core.analyzer import IDAAnalysisRunner
from ..core.baseline_manager import BaselineManager
from .log_viewer import SystemLogWidget, IDALogViewer, UnifiedLogWidget
from .poc_widget import PoCResultWidget

logger = logging.getLogger(__name__)


class BatchAnalysisWorker(QThread):
    """Worker thread for batch analysis operations"""

    progress_updated = pyqtSignal(int, int, str, str)  # current, total, driver_name, status
    batch_finished = pyqtSignal(dict)
    error_occurred = pyqtSignal(str)

    def __init__(self, batch_analyzer, target_files, output_dir, baseline_name):
        super().__init__()
        self.batch_analyzer = batch_analyzer
        self.target_files = target_files
        self.output_dir = output_dir
        self.baseline_name = baseline_name

    def run(self):
        """Run batch analysis in background thread"""
        try:
            results = self.batch_analyzer.run_batch_analysis(
                self.target_files, self.output_dir, self.baseline_name,
                progress_callback=self.progress_updated.emit
            )
            self.batch_finished.emit(results)
        except Exception as e:
            self.error_occurred.emit(str(e))


class AnalysisWorker(QThread):
    """Worker thread for analysis operations"""

    progress_updated = pyqtSignal(int, str)
    analysis_finished = pyqtSignal(dict)
    error_occurred = pyqtSignal(str)

    def __init__(self, driver_a_path: str, driver_b_path: str, ida_path: str, anchor_function: str, debug_context: Optional[Dict[str, Any]]):
        super().__init__()
        self.driver_a_path = driver_a_path
        self.driver_b_path = driver_b_path
        self.ida_path = ida_path
        self.anchor_function = anchor_function
        self.debug_context = debug_context


    def run(self):
        """Run analysis in background thread"""
        try:
            self.progress_updated.emit(0, "Initializing analysis...")

            # Check for cancellation
            if self.isInterruptionRequested():
                self.progress_updated.emit(0, "Analysis cancelled")
                return

            # Create IDA analysis runner
            runner = IDAAnalysisRunner(self.ida_path)

            # Phase 1: Analysis (Simulating A/B or Single Export)
            # For V3 UI, we treat Driver A as Anchor/Baseline and B as Target
            
            # Export Driver A (Baseline)
            self.progress_updated.emit(10, "Analyzing Driver A (Reference)...")
            res_a = runner.run_analysis(self.driver_a_path, {
                "operation": "logic_flow_export",
                "anchor_function": self.anchor_function,
                "debug_context": self.debug_context
            })
            if "error" in res_a: raise RuntimeError(f"Driver A Analysis failed: {res_a['error']}")
            
            # Export Driver B (Target)
            self.progress_updated.emit(40, "Analyzing Driver B (Target)...")
            res_b = runner.run_analysis(self.driver_b_path, {
                "operation": "logic_flow_export", 
                "anchor_function": self.anchor_function, # Assuming same anchor name/pattern
                "debug_context": self.debug_context
            })
            if "error" in res_b: raise RuntimeError(f"Driver B Analysis failed: {res_b['error']}")

            # Phase 2: Local Processing with Core Engine
            self.progress_updated.emit(70, "Processing with Core Engine...")
            
            from ..core.logic_graph import LogicGraph
            from ..core import analyzer
            from ..core import diff_reflecting
            
            # Use reconstruct_logic_graph to ensure binary path override
            
            # Process Driver A
            graph_a = analyzer.reconstruct_logic_graph(res_a, binary_path=self.driver_a_path)
            if graph_a is None:
                raise RuntimeError("Failed to process Driver A - no LogicGraph generated")
            
            # Process Driver B
            graph_b = analyzer.reconstruct_logic_graph(res_b, binary_path=self.driver_b_path)
            if graph_b is None:
                raise RuntimeError("Failed to process Driver B - no LogicGraph generated")
            
            logger.info(f"Graph A: {len(graph_a.nodes)} nodes, Graph B: {len(graph_b.nodes)} nodes")
            
            # Run Comparison
            self.progress_updated.emit(80, "Comparing Logic Flows...")
            comparison = diff_reflecting.compare_logic_flows(graph_a, graph_b)
            
            # Run Security Insights
            insights = diff_reflecting.analyze_security_insights(graph_a, graph_b, comparison)
            
            # Generate UI Report
            self.progress_updated.emit(90, "Generating Report...")
            report = diff_reflecting.generate_ui_analysis_report(graph_a, graph_b, comparison, insights)
            
            self.progress_updated.emit(100, "Analysis Completed")
            self.analysis_finished.emit(report)

        except Exception as e:
            import traceback
            full_traceback = traceback.format_exc()
            logger.error(f"Analysis failed: {str(e)}\n{full_traceback}")
            self.error_occurred.emit(str(e))


    def generate_logic_flow_report(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """Generate analysis report"""
        if not results or "error" in results:
            return {
                "analysis_type": "logic_flow_analysis",
                "status": "failed",
                "error": results.get("error", "Unknown error") if isinstance(results, dict) else "No results"
            }

        # Handle new two-pass analysis format
        if results.get("mode") == "compare":
            return {
                "analysis_type": "logic_flow_analysis",
                "status": "completed",
                "baseline_anchor": results.get("baseline_anchor", "unknown"),
                "current_anchor": results.get("current_anchor", "unknown"),
                "candidates_analyzed": results.get("candidates_analyzed", 0),
                "total_candidates_found": results.get("total_candidates_found", 0),
                "key_findings": results.get("analysis_summary", {}).get("key_findings", []),
                "manual_review_points": results.get("analysis_summary", {}).get("manual_review_points", []),
                "scoring_stats": results.get("analysis_summary", {}).get("scoring_stats", {})
            }

        # Fallback for old format (backward compatibility)
        return {
            "analysis_type": "logic_flow_analysis",
            "status": "completed",
            "anchor_function": hex(results.get("anchor_function", 0)),
            "candidates_analyzed": len(results.get("comparisons", {})),
            "key_findings": results.get("analysis_summary", {}).get("key_findings", []),
            "manual_review_points": results.get("analysis_summary", {}).get("manual_review_points", [])
        }


class LogicFlowAnalysisGUI(QMainWindow):
    """Modern PyQt6 GUI for Logic Flow Analysis Tool"""

    def __init__(self):
        super().__init__()
        self.analysis_worker = None
        self.current_results = None
        self.config_manager = ConfigManager()
        self.baseline_manager = BaselineManager()
        self.threadpool = QThreadPool()

        # Theme state
        self.dark_mode = True

        # Initialize paths
        self.driver_a_path = ""
        self.driver_b_path = ""
        self.ida_path = self.config_manager.get_ida_path()

        # Debug context
        self.debug_context = {}

        # Setup UI
        self.setup_ui()
        self.update_analysis_button_state()
        self.setup_connections()

        # Set initial IDA path in selector if found
        if self.ida_path:
            self.ida_path_selector.set_selected_file(self.ida_path)

    def setup_ui(self):
        """Setup the modern GUI interface with three-panel layout"""
        self.setWindowTitle("Windows Kernel Driver Logic Flow Analysis Tool")
        self.setMinimumSize(1400, 900)
        self.resize(1600, 1000)

        # Setup window attributes
        self.setWindowFlag(Qt.WindowType.WindowMaximizeButtonHint, True)
        self.setWindowFlag(Qt.WindowType.WindowMinimizeButtonHint, True)
        self.setAttribute(Qt.WidgetAttribute.WA_TranslucentBackground, False)

        # Create central widget
        central_widget = QWidget()
        optimize_widget(central_widget)
        self.setCentralWidget(central_widget)

        # Main vertical layout
        main_layout = QVBoxLayout(central_widget)
        main_layout.setContentsMargins(0, 0, 0, 0)
        main_layout.setSpacing(0)

        # Top navigation bar
        self.setup_top_navigation(main_layout)

        # Main content area with horizontal splitter
        self.main_splitter = QSplitter(Qt.Orientation.Horizontal)
        self.main_splitter.setOpaqueResize(True)
        self.main_splitter.setChildrenCollapsible(True)
        main_layout.addWidget(self.main_splitter, 1)

        # Left sidebar
        self.setup_left_sidebar(self.main_splitter)

        # Center content area
        self.setup_center_content(self.main_splitter)

        # Right panel
        self.setup_right_panel(self.main_splitter)

        # Set initial splitter sizes
        self.main_splitter.setSizes([280, 800, 320])

        # Bottom status bar
        self.setup_bottom_status_bar(main_layout)

    def setup_top_navigation(self, parent_layout):
        """Setup top navigation bar"""
        # Top navigation container
        nav_container = QWidget()
        nav_container.setFixedHeight(56)
        nav_container.setObjectName("topNavigation")
        nav_container.setStyleSheet("""
            QWidget#topNavigation {
                background-color: #161B22;
                border-bottom: 1px solid #30363D;
                padding: 0 24px;
            }
        """)

        nav_layout = QHBoxLayout(nav_container)
        nav_layout.setContentsMargins(0, 0, 0, 0)
        nav_layout.setSpacing(16)

        # App logo and title
        logo_widget = QWidget()
        logo_layout = QHBoxLayout(logo_widget)
        logo_layout.setContentsMargins(0, 0, 0, 0)
        logo_layout.setSpacing(12)

        # Logo icon (simplified for now)
        logo_label = QLabel()
        logo_label.setPixmap(get_chart_icon(24).pixmap(24, 24))
        logo_layout.addWidget(logo_label)

        title_label = ModernLabel("Logic Flow Analysis", "title")
        title_label.setStyleSheet("font-size: 18px; font-weight: 600; color: #E6EDF3;")
        logo_layout.addWidget(title_label)

        nav_layout.addWidget(logo_widget)
        nav_layout.addStretch()  # Add stretch to center the search bar

        # Global search bar with enhanced functionality
        self.global_search = ModernLineEdit("Search functions, drivers, results...")
        self.global_search.setFixedWidth(320)
        self.global_search.setObjectName("globalSearch")
        self.global_search.setStyleSheet("""
            QLineEdit#globalSearch {
                background-color: #0D1117;
                border: 1px solid #30363D;
                border-radius: 8px;
                padding: 8px 12px;
                font-size: 13px;
                color: #E6EDF3;
            }
            QLineEdit#globalSearch:focus {
                border: 1px solid #58A6FF;
                background-color: #161B22;
            }
        """)

        # Add search functionality
        self.global_search.textChanged.connect(self.on_global_search_changed)
        self.global_search.returnPressed.connect(self.perform_global_search)

        # Add search icon to the left
        search_icon = QLabel()
        search_icon.setPixmap(get_search_icon(16).pixmap(16, 16))
        search_icon.setStyleSheet("padding-left: 8px; color: #8B949E;")
        self.global_search.setTextMargins(24, 0, 0, 0)  # Make room for icon

        # Overlay the search icon
        search_container = QWidget()
        search_container.setFixedWidth(320)
        search_layout = QHBoxLayout(search_container)
        search_layout.setContentsMargins(0, 0, 0, 0)
        search_layout.setSpacing(0)

        search_icon_widget = QWidget()
        search_icon_widget.setFixedWidth(24)
        search_icon_layout = QHBoxLayout(search_icon_widget)
        search_icon_layout.setContentsMargins(8, 0, 0, 0)
        search_icon_layout.addWidget(search_icon)
        search_layout.addWidget(search_icon_widget)
        search_layout.addWidget(self.global_search)

        nav_layout.addWidget(search_container)

        nav_layout.addStretch()

        # Left sidebar toggle button (always visible)
        self.left_sidebar_toggle_btn = ModernButton("☰", None, button_type="outline")
        self.left_sidebar_toggle_btn.setFixedSize(40, 40)
        self.left_sidebar_toggle_btn.setToolTip("Toggle left sidebar")
        self.left_sidebar_toggle_btn.clicked.connect(self.toggle_sidebar)
        nav_layout.addWidget(self.left_sidebar_toggle_btn)

        # Right panel toggle button (always visible)
        self.right_panel_toggle_btn = ModernButton("☷", None, button_type="outline")
        self.right_panel_toggle_btn.setFixedSize(40, 40)
        self.right_panel_toggle_btn.setToolTip("Toggle right panel")
        self.right_panel_toggle_btn.clicked.connect(self.toggle_right_panel)
        nav_layout.addWidget(self.right_panel_toggle_btn)

        # Theme toggle button
        self.theme_toggle_btn = ModernButton("", get_sun_icon(20), button_type="outline")
        self.theme_toggle_btn.setFixedSize(40, 40)
        self.theme_toggle_btn.setToolTip("Toggle theme (Light/Dark)")
        self.theme_toggle_btn.clicked.connect(self.toggle_theme)
        nav_layout.addWidget(self.theme_toggle_btn)

        # Settings menu button
        self.settings_btn = ModernButton("", get_settings_icon(20), button_type="outline")
        self.settings_btn.setFixedSize(40, 40)
        self.settings_btn.setToolTip("Settings")
        self.settings_btn.clicked.connect(self.show_settings_menu)
        nav_layout.addWidget(self.settings_btn)
        
        # Color Picker button
        self.color_picker_btn = ModernButton("🎨", None, button_type="outline")
        self.color_picker_btn.setFixedSize(40, 40)
        self.color_picker_btn.setToolTip("Customize Edge Colors")
        self.color_picker_btn.clicked.connect(self.show_color_picker)
        nav_layout.addWidget(self.color_picker_btn)

        parent_layout.addWidget(nav_container)

    def setup_left_sidebar(self, splitter):
        """Setup collapsible left sidebar"""
        sidebar_widget = QWidget()
        sidebar_widget.setMinimumWidth(320)  # Increased from Fixed 280 for better visibility
        sidebar_widget.setObjectName("leftSidebar")
        sidebar_widget.setStyleSheet("""
            QWidget#leftSidebar {
                background-color: #161B22;
                border-right: 1px solid #30363D;
            }
        """)

        sidebar_layout = QVBoxLayout(sidebar_widget)
        sidebar_layout.setContentsMargins(0, 0, 0, 0)
        sidebar_layout.setSpacing(0)

        # Sidebar header
        sidebar_header = QWidget()
        sidebar_header.setFixedHeight(48)
        sidebar_header.setStyleSheet("background-color: #1C2128; border-bottom: 1px solid #30363D;")
        header_layout = QHBoxLayout(sidebar_header)
        header_layout.setContentsMargins(16, 0, 16, 0)

        sidebar_title = ModernLabel("Workspace", "subtitle")
        header_layout.addWidget(sidebar_title)
        header_layout.addStretch()

        # Collapse button
        self.sidebar_collapse_btn = ModernButton("", get_clear_icon(16), button_type="outline")
        self.sidebar_collapse_btn.setFixedSize(32, 32)
        self.sidebar_collapse_btn.setToolTip("Collapse sidebar")
        self.sidebar_collapse_btn.clicked.connect(self.toggle_sidebar)
        header_layout.addWidget(self.sidebar_collapse_btn)

        sidebar_layout.addWidget(sidebar_header)

        # Scrollable content area
        scroll_area = QScrollArea()
        optimize_scroll_area(scroll_area)
        scroll_area.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAsNeeded) # Allow horizontal if needed
        scroll_area.setWidgetResizable(True)

        scroll_widget = QWidget()
        optimize_widget(scroll_widget)
        scroll_layout = QVBoxLayout(scroll_widget)
        scroll_layout.setContentsMargins(16, 16, 24, 16) # Increased right padding for scrollbar
        scroll_layout.setSpacing(24)

        # Analysis Workspace section
        self.setup_analysis_workspace_section(scroll_layout)

        # Baseline section
        self.setup_baseline_section(scroll_layout)

        # Configuration section
        self.setup_configuration_section(scroll_layout)

        # Debug Context section
        self.setup_debug_section(scroll_layout)

        scroll_area.setWidget(scroll_widget)
        sidebar_layout.addWidget(scroll_area)

        splitter.addWidget(sidebar_widget)

    def setup_analysis_workspace_section(self, parent_layout):
        """Setup Analysis Workspace section in sidebar"""
        workspace_card = ModernCard("Analysis Workspace", get_folder_icon(20))
        workspace_layout = workspace_card.content_layout

        # Recent analyses list
        recent_label = ModernLabel("Recent Analyses", "body")
        recent_label.setStyleSheet("font-weight: 600; color: #E6EDF3;")
        workspace_layout.addWidget(recent_label)

        # Placeholder for recent analyses - will be populated later
        self.recent_analyses_list = QWidget()
        recent_layout = QVBoxLayout(self.recent_analyses_list)
        recent_layout.setContentsMargins(0, 0, 0, 0)
        recent_layout.setSpacing(8)

        # Add some placeholder recent analyses
        for i in range(3):
            recent_item = QWidget()
            recent_item.setStyleSheet("""
                QWidget {
                    background-color: #1C2128;
                    border-radius: 6px;
                    padding: 8px;
                }
                QWidget:hover {
                    background-color: #21262D;
                }
            """)
            item_layout = QHBoxLayout(recent_item)
            item_layout.setContentsMargins(8, 8, 8, 8)

            item_icon = QLabel()
            item_icon.setPixmap(get_chart_icon(16).pixmap(16, 16))
            item_layout.addWidget(item_icon)

            item_text = ModernLabel(f"Analysis {i+1} - Driver Comparison", "caption")
            item_layout.addWidget(item_text)
            item_layout.addStretch()

            recent_layout.addWidget(recent_item)

        workspace_layout.addWidget(self.recent_analyses_list)



        parent_layout.addWidget(workspace_card)

    def setup_baseline_section(self, parent_layout):
        """Setup Baseline Management section"""
        baseline_card = ModernCard("Baseline Actions", get_settings_icon(20))
        layout = baseline_card.content_layout
        
        save_btn = ModernButton("Save Current as Baseline", "save", button_type="outline")
        save_btn.clicked.connect(self.save_baseline)
        save_btn.setToolTip("Save the current state of Graph A as a baseline")
        layout.addWidget(save_btn)
        
        load_btn = ModernButton("Load Baseline", "folder", button_type="outline")
        load_btn.clicked.connect(self.load_baseline)
        load_btn.setToolTip("Load a previously saved baseline into Graph A")
        layout.addWidget(load_btn)
        
        parent_layout.addWidget(baseline_card)

    def save_baseline(self):
        """Save current graph state as baseline"""
        if not hasattr(self, 'current_results') or not self.current_results:
            QMessageBox.warning(self, "No Analysis", "Please run an analysis first before saving a baseline.")
            return

        from PyQt6.QtWidgets import QFileDialog
        import json
        
        file_path, _ = QFileDialog.getSaveFileName(
            self, "Save Baseline", "", "JSON Files (*.json)"
        )
        
        if file_path:
            try:
                # Save only graph data for now, ideally specific to Graph A
                # Assuming current_results['graph'] contains the combined or split data
                with open(file_path, 'w') as f:
                    json.dump(self.current_results, f, indent=2)
                self.log_message(f"✅ Baseline saved to {file_path}")
            except Exception as e:
                self.log_message(f"❌ Failed to save baseline: {str(e)}")
                QMessageBox.critical(self, "Error", f"Failed to save baseline: {str(e)}")

    def load_baseline(self):
        """Load a baseline JSON"""
        from PyQt6.QtWidgets import QFileDialog
        import json
        
        file_path, _ = QFileDialog.getOpenFileName(
            self, "Load Baseline", "", "JSON Files (*.json)"
        )
        
        if file_path:
            try:
                with open(file_path, 'r') as f:
                    data = json.load(f)
                
                # Check structure
                if "graph" in data:
                    self.current_results = data # Update current results
                    self.on_analysis_finished(data) # Reload UI
                    self.log_message(f"✅ Baseline loaded from {file_path}")
                else:
                    raise ValueError("Invalid baseline file format")
                    
            except Exception as e:
                self.log_message(f"❌ Failed to load baseline: {str(e)}")
                QMessageBox.critical(self, "Error", f"Failed to load baseline: {str(e)}")

    def setup_configuration_section(self, parent_layout):
        """Setup Configuration section in sidebar"""
        config_card = ModernCard("Configuration", get_settings_icon(20))
        config_layout = config_card.content_layout

        # Driver A/B selection cards
        drivers_label = ModernLabel("Driver Selection", "body")
        drivers_label.setStyleSheet("font-weight: 600; color: #E6EDF3;")
        config_layout.addWidget(drivers_label)

        # Driver A card
        self.driver_a_card = self.create_driver_selection_card("Driver A", "Reference Driver", "#3FB950")
        config_layout.addWidget(self.driver_a_card)

        config_layout.addSpacing(12)

        # Driver B card
        self.driver_b_card = self.create_driver_selection_card("Driver B", "Target Driver", "#1F6FEB")
        config_layout.addWidget(self.driver_b_card)

        config_layout.addSpacing(16)

        # IDA Pro settings
        ida_label = ModernLabel("IDA Pro Settings", "body")
        ida_label.setStyleSheet("font-weight: 600; color: #E6EDF3;")
        config_layout.addWidget(ida_label)

        self.ida_path_selector = FileSelectionWidget(
            "IDA Pro Executable",
            "IDA Executable (ida.exe);;All files (*.*)",
            "ida_path"
        )
        self.ida_path_selector.file_selected.connect(self.on_ida_selected)
        config_layout.addWidget(self.ida_path_selector)

        # Anchor function selector
        anchor_label = ModernLabel("Anchor Function", "body")
        anchor_label.setStyleSheet("font-weight: 600; color: #E6EDF3; margin-top: 16px;")
        config_layout.addWidget(anchor_label)

        from PyQt6.QtWidgets import QComboBox
        self.anchor_function_combo = QComboBox()
        self.anchor_function_combo.setEditable(True)
        self.anchor_function_combo.setPlaceholderText("Function name or hex address")
        self.anchor_function_combo.setToolTip("Select from fetched functions or type manually")
        self.anchor_function_combo.addItems([
            "",
            "IoctlHandler",
            "DispatchDeviceControl",
            "DispatchRead",
            "DispatchWrite",
            "DriverEntry"
        ])
        self.anchor_function_combo.setStyleSheet("""
            QComboBox {
                background-color: #0D1117;
                border: 1px solid #30363D;
                border-radius: 6px;
                padding: 8px;
                color: #E6EDF3;
                min-height: 36px;
            }
            QComboBox:focus {
                border: 1px solid #58A6FF;
            }
            QComboBox::drop-down {
                border: none;
                width: 20px;
            }
            QComboBox::down-arrow {
                image: url(down_arrow.png);
                width: 12px;
                height: 12px;
            }
        """)
        config_layout.addWidget(self.anchor_function_combo)

        self.fetch_functions_btn = ModernButton("Fetch Functions", get_search_icon(16), button_type="outline")
        self.fetch_functions_btn.clicked.connect(self.fetch_functions_from_driver_a)
        self.fetch_functions_btn.setEnabled(False)
        config_layout.addWidget(self.fetch_functions_btn)

        parent_layout.addWidget(config_card)

    def setup_debug_section(self, parent_layout):
        """Setup Debug Context section in sidebar"""
        debug_card = ModernCard("Debug Context", get_bug_icon(20))
        debug_layout = debug_card.content_layout

        debug_info = ModernLabel("Context from WinDbg crash analysis", "caption")
        debug_info.setStyleSheet("color: #8B949E;")
        debug_layout.addWidget(debug_info)

        # Collapsible debug context form
        self.debug_context_widget = QWidget()
        debug_form_layout = QVBoxLayout(self.debug_context_widget)
        debug_form_layout.setContentsMargins(0, 0, 0, 0)
        debug_form_layout.setSpacing(8)

        # Create form container
        form_widget = QWidget()
        form_layout = QFormLayout(form_widget)
        form_layout.setContentsMargins(0, 0, 0, 0)
        form_layout.setSpacing(8)

        # Exception Type
        self.exception_edit = ModernLineEdit("e.g., EXCEPTION_ACCESS_VIOLATION")
        form_layout.addRow("Exception Type:", self.exception_edit)

        # IRQL Level
        self.irql_edit = ModernLineEdit("e.g., 0 (PASSIVE_LEVEL)")
        form_layout.addRow("IRQL Level:", self.irql_edit)

        # Status Code
        self.status_edit = ModernLineEdit("e.g., 0xC0000005")
        form_layout.addRow("Status Code:", self.status_edit)

        # Crash Address
        self.crash_addr_edit = ModernLineEdit("e.g., 0xFFFFF80012345678")
        form_layout.addRow("Crash Address:", self.crash_addr_edit)

        # Call Stack
        self.callstack_edit = ModernLineEdit("Comma-separated addresses")
        form_layout.addRow("Call Stack:", self.callstack_edit)

        # Notes
        self.notes_edit = ModernTextEdit("Additional debug information")
        form_layout.addRow("Debug Notes:", self.notes_edit)

        debug_form_layout.addWidget(form_widget)
        debug_layout.addWidget(self.debug_context_widget)

        parent_layout.addWidget(debug_card)

    def create_driver_selection_card(self, driver_label, description, accent_color):
        """Create a modern driver selection card with enhanced features"""
        card = QWidget()
        card.setFixedHeight(100)
        card.setObjectName("driverCard")
        card.setStyleSheet(f"""
            QWidget#driverCard {{
                background-color: #1C2128;
                border: 2px dashed {accent_color};
                border-radius: 12px;
                padding: 16px;
            }}
            QWidget#driverCard:hover {{
                background-color: #21262D;
                border-style: solid;
            }}
        """)

        card_layout = QVBoxLayout(card)
        card_layout.setContentsMargins(16, 12, 16, 12)
        card_layout.setSpacing(8)

        # Header with icon and title
        header_layout = QHBoxLayout()
        header_layout.setSpacing(12)

        # Driver icon
        driver_icon = QLabel()
        driver_icon.setPixmap(get_folder_icon(24).pixmap(24, 24))
        driver_icon.setStyleSheet(f"opacity: 0.8;")
        header_layout.addWidget(driver_icon)

        # Title and description column
        title_column = QVBoxLayout()
        title_column.setSpacing(2)

        driver_title = ModernLabel(driver_label, "body")
        driver_title.setStyleSheet(f"font-weight: 700; color: {accent_color}; font-size: 14px;")
        title_column.addWidget(driver_title)

        desc_label = ModernLabel(description, "caption")
        desc_label.setStyleSheet("color: #8B949E;")
        title_column.addWidget(desc_label)

        header_layout.addLayout(title_column)
        header_layout.addStretch()

        # Status indicator
        status_widget = QWidget()
        status_widget.setFixedSize(12, 12)
        status_widget.setStyleSheet(f"""
            QWidget {{
                background-color: #30363D;
                border-radius: 6px;
                border: 2px solid #1C2128;
            }}
        """)
        header_layout.addWidget(status_widget)

        card_layout.addLayout(header_layout)

        # File info section (initially hidden)
        self.file_info_widget = QWidget()
        self.file_info_widget.setVisible(False)
        file_info_layout = QVBoxLayout(self.file_info_widget)
        file_info_layout.setContentsMargins(0, 0, 0, 0)
        file_info_layout.setSpacing(4)

        # File name and size
        file_name_label = ModernLabel("No file selected", "caption")
        file_name_label.setStyleSheet("color: #E6EDF3; font-weight: 500;")
        file_name_label.setWordWrap(True)
        file_info_layout.addWidget(file_name_label)

        file_details_label = ModernLabel("", "caption")
        file_details_label.setStyleSheet("color: #6E7681;")
        file_info_layout.addWidget(file_details_label)

        card_layout.addWidget(self.file_info_widget)

        # Action hint
        action_hint = ModernLabel("Drop .sys file here or click to browse", "caption")
        action_hint.setStyleSheet("color: #6E7681; font-style: italic; text-align: center;")
        action_hint.setAlignment(Qt.AlignmentFlag.AlignCenter)
        card_layout.addWidget(action_hint)

        # Progress indicator for file loading (initially hidden)
        self.file_loading_progress = ModernProgressBar()
        self.file_loading_progress.setVisible(False)
        self.file_loading_progress.setFixedHeight(3)
        card_layout.addWidget(self.file_loading_progress)

        # Store references for later updates
        card.file_name_label = file_name_label
        card.file_details_label = file_details_label
        card.status_indicator = status_widget
        card.action_hint = action_hint
        card.file_info_widget = self.file_info_widget
        card.loading_progress = self.file_loading_progress

        # Make card interactive
        card.setAcceptDrops(True)
        card.mousePressEvent = lambda e, card=card, driver=driver_label: self.on_driver_card_clicked(card, driver)
        card.dragEnterEvent = lambda e, driver=driver_label: self.on_driver_card_drag_enter(e, driver)
        card.dropEvent = lambda e, driver=driver_label: self.on_driver_card_drop(e, driver)

        # Add hover animations
        card.enterEvent = lambda e, card=card: self.on_card_hover_enter(card)
        card.leaveEvent = lambda e, card=card: self.on_card_hover_leave(card)

        return card

    def on_card_hover_enter(self, card):
        """Handle card hover enter - simple visual feedback"""
        # Qt QSS doesn't support transform/box-shadow, use border color instead
        pass  # Hover is handled by :hover pseudo-selector in QSS

    def on_card_hover_leave(self, card):
        """Handle card hover leave"""
        pass  # Hover is handled by :hover pseudo-selector in QSS

    def setup_analysis_dashboard_tab(self):
        """Setup Analysis Dashboard tab"""
        dashboard_widget = QWidget()
        dashboard_layout = QVBoxLayout(dashboard_widget)
        dashboard_layout.setContentsMargins(24, 24, 24, 24)
        dashboard_layout.setSpacing(24)

        # Header
        header_layout = QHBoxLayout()
        header_layout.addWidget(ModernLabel("Analysis Dashboard", "headline_large"))
        header_layout.addStretch()

        # Quick stats cards
        stats_layout = QHBoxLayout()
        stats_layout.setSpacing(16)

        # Store references to value labels for updating
        self.metric_labels = {}
        
        # Create metric cards with stored references
        self.metric_labels["functions"] = self.create_metric_card("Functions Analyzed", "0", "#58A6FF", stats_layout)
        self.metric_labels["similarities"] = self.create_metric_card("Similarities Found", "0", "#3FB950", stats_layout)
        self.metric_labels["risks"] = self.create_metric_card("Risk Candidates", "0", "#D29922", stats_layout)
        self.metric_labels["time"] = self.create_metric_card("Analysis Time", "0s", "#A371F7", stats_layout)

        dashboard_layout.addLayout(header_layout)
        dashboard_layout.addLayout(stats_layout)

    def create_metric_card(self, title, value, color, parent_layout):
        """Create a metric card and return the value label for updates"""
        card = QWidget()
        card.setFixedSize(180, 100)
        card.setStyleSheet(f"""
            QWidget {{
                background-color: #161B22;
                border: 1px solid #30363D;
                border-radius: 12px;
                border-left: 4px solid {color};
            }}
        """)
        
        card_layout = QVBoxLayout(card)
        card_layout.setContentsMargins(16, 12, 16, 12)
        card_layout.setSpacing(4)
        
        # Title label
        title_label = QLabel(title)
        title_label.setStyleSheet("color: #8B949E; font-size: 11px; font-weight: 500; border: none;")
        card_layout.addWidget(title_label)
        
        # Value label (this is what we return and store)
        value_label = QLabel(value)
        value_label.setStyleSheet(f"color: {color}; font-size: 28px; font-weight: 700; border: none;")
        card_layout.addWidget(value_label)
        
        card_layout.addStretch()
        parent_layout.addWidget(card)
        
        return value_label  # Return for later updates

        # Charts Section
        chart_layout = QHBoxLayout()
        chart_layout.setSpacing(24)
        
        # Similarity Distribution Chart
        self.similarity_chart = SimpleChartWidget("Match Distribution")
        chart_layout.addWidget(self.similarity_chart)
        
        # Metadata Comparison Widget
        self.metadata_widget = MetadataComparisonWidget()
        chart_layout.addWidget(self.metadata_widget)
        
        dashboard_layout.addLayout(chart_layout)
        dashboard_layout.addStretch()
        charts_widget = QWidget()
        charts_widget.setFixedHeight(300)
        charts_widget.setStyleSheet("""
            QWidget {
                background-color: #161B22;
                border: 1px solid #30363D;
                border-radius: 8px;
                padding: 16px;
            }
        """)
        charts_layout = QVBoxLayout(charts_widget)

        charts_title = ModernLabel("Analysis Overview", "title")
        charts_layout.addWidget(charts_title)

        # Placeholder for charts
        chart_placeholder = ModernLabel("Charts will be displayed here after analysis", "body")
        chart_placeholder.setStyleSheet("color: #8B949E; text-align: center; padding: 40px;")
        chart_placeholder.setAlignment(Qt.AlignmentFlag.AlignCenter)
        charts_layout.addWidget(chart_placeholder)

        dashboard_layout.addWidget(charts_widget)

        self.main_tab_widget.addTab(dashboard_widget, "Dashboard")

    def setup_graph_comparison_tab(self):
        """Setup Graph Comparison tab"""
        graph_widget = QWidget()
        graph_layout = QVBoxLayout(graph_widget)
        graph_layout.setContentsMargins(24, 24, 24, 24)

        # Header with controls
        header_layout = QHBoxLayout()
        header_layout.addWidget(ModernLabel("Graph Comparison", "headline_large"))
        header_layout.addStretch()

        # View mode selector
        mode_layout = QHBoxLayout()
        mode_layout.setSpacing(8)

        mode_label = ModernLabel("View Mode:", "body")
        mode_layout.addWidget(mode_label)

        self.view_mode_combo = QComboBox()
        self.view_mode_combo.addItems(["Side-by-Side", "Overlay", "Unified Diff"])
        self.view_mode_combo.currentIndexChanged.connect(self.on_view_mode_changed)
        self.view_mode_combo.setStyleSheet("""
            QComboBox {
                background-color: #161B22;
                border: 1px solid #30363D;
                border-radius: 6px;
                padding: 6px 12px;
                color: #E6EDF3;
                min-width: 130px;
            }
            QComboBox::drop-down {
                border: none;
                width: 20px;
            }
            QComboBox::down-arrow {
                image: none;
                border-left: 4px solid transparent;
                border-right: 4px solid transparent;
                border-top: 5px solid #8B949E;
            }
            QComboBox QAbstractItemView {
                background-color: #161B22;
                border: 1px solid #30363D;
                selection-background-color: #21262D;
                color: #E6EDF3;
            }
        """)
        mode_layout.addWidget(self.view_mode_combo)

        header_layout.addLayout(mode_layout)
        graph_layout.addLayout(header_layout)

        # Graph visualization area
        graph_controls_layout = QHBoxLayout()
        graph_controls_layout.setSpacing(8)

        # Zoom controls
        zoom_in_btn = ModernButton("+", button_type="outline")
        zoom_in_btn.setFixedSize(32, 32)
        zoom_in_btn.setToolTip("Zoom In")
        zoom_in_btn.clicked.connect(lambda: self.graph_view.zoom_in() if hasattr(self, 'graph_view') else None)
        graph_controls_layout.addWidget(zoom_in_btn)

        zoom_out_btn = ModernButton("-", button_type="outline")
        zoom_out_btn.setFixedSize(32, 32)
        zoom_out_btn.setToolTip("Zoom Out")
        zoom_out_btn.clicked.connect(lambda: self.graph_view.zoom_out() if hasattr(self, 'graph_view') else None)
        graph_controls_layout.addWidget(zoom_out_btn)

        fit_view_btn = ModernButton("Fit", button_type="outline")
        fit_view_btn.setFixedSize(60, 32)
        fit_view_btn.setToolTip("Fit to View")
        fit_view_btn.clicked.connect(lambda: self.graph_view.fit_to_view() if hasattr(self, 'graph_view') else None)
        graph_controls_layout.addWidget(fit_view_btn)

        graph_controls_layout.addStretch()

        # View mode controls
        overlay_btn = ModernButton("Overlay", button_type="outline")
        overlay_btn.clicked.connect(self.toggle_graph_overlay)
        graph_controls_layout.addWidget(overlay_btn)

        graph_layout.addLayout(graph_controls_layout)

        # Graph visualization widget
        self.graph_view = GraphVisualizationWidget()
        self.graph_view.setMinimumHeight(500)
        self.graph_view.node_selected.connect(self.on_graph_node_selected)
        self.graph_view.node_double_clicked.connect(self.on_graph_node_double_clicked)

        graph_layout.addWidget(self.graph_view)

        # Legend Bar
        legend_frame = QFrame()
        legend_frame.setStyleSheet("""
            QFrame {
                background-color: #0D1117;
                border-top: 1px solid #30363D;
                border-radius: 0px;
            }
        """)
        legend_layout = QHBoxLayout(legend_frame)
        legend_layout.setContentsMargins(16, 8, 16, 8)
        legend_layout.setSpacing(24)
        
        legend_layout.addWidget(ModernLabel("Legend:", "body_bold"))
        
        def add_legend_item(color, name):
            item = QWidget()
            item_layout = QHBoxLayout(item)
            item_layout.setContentsMargins(0, 0, 0, 0)
            item_layout.setSpacing(6)
            
            indicator = QWidget()
            indicator.setFixedSize(12, 12)
            indicator.setStyleSheet(f"background-color: {color}; border-radius: 6px;")
            item_layout.addWidget(indicator)
            
            label = QLabel(name)
            label.setStyleSheet("color: #8B949E; font-size: 11px;")
            item_layout.addWidget(label)
            
            legend_layout.addWidget(item)

        add_legend_item("#3B82F6", "Direct Call")
        add_legend_item("#F59E0B", "Indirect Call")
        add_legend_item("#10B981", "Xref")
        add_legend_item("#3FB950", "Conditional (True)")
        add_legend_item("#F85149", "Conditional (False)")
        
        legend_layout.addStretch()
        graph_layout.addWidget(legend_frame)

        self.main_tab_widget.addTab(graph_widget, "Graph")

        self.main_tab_widget.addTab(graph_widget, "Graph")

    def setup_edr_tab(self):
        """Setup EDR Simulator tab"""
        edr_widget = QWidget()
        edr_layout = QVBoxLayout(edr_widget)
        edr_layout.setContentsMargins(24, 24, 24, 24)
        edr_layout.setSpacing(16)
        
        # Header
        header = QHBoxLayout()
        header.addWidget(ModernLabel("EDR Simulator (Preventive Defense)", "headline_large"))
        header.addStretch()
        
        # Generation Button
        self.gen_rules_btn = ModernButton("Generate Signatures from Analysis", "shield", button_type="primary")
        self.gen_rules_btn.clicked.connect(self.generate_edr_rules)
        header.addWidget(self.gen_rules_btn)
        edr_layout.addLayout(header)
        
        # Main Content Layout
        content_layout = QHBoxLayout()
        
        # Left Panel: Test Console
        test_panel = ModernCard("Runtime Monitor Simulation", get_bug_icon(20))
        test_layout = test_panel.content_layout
        
        test_layout.addWidget(ModernLabel("Simulate IOCTL Request:", "body_bold"))
        
        input_row = QHBoxLayout()
        self.ioctl_input = QLineEdit()
        self.ioctl_input.setPlaceholderText("e.g. 0x222003")
        self.ioctl_input.setStyleSheet("""
            QLineEdit {
                background-color: #0D1117;
                border: 1px solid #30363D;
                border-radius: 6px;
                color: #E6EDF3;
                padding: 8px;
            }
        """)
        input_row.addWidget(self.ioctl_input)
        
        test_btn = ModernButton("Send Request", "play", button_type="primary")
        test_btn.clicked.connect(self.test_edr_ioctl)
        input_row.addWidget(test_btn)
        
        test_layout.addLayout(input_row)
        
        # Result Area
        self.edr_status_label = QLabel("Ready")
        self.edr_status_label.setStyleSheet("color: #8B949E; font-size: 14px; margin-top: 10px;")
        self.edr_status_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        test_layout.addWidget(self.edr_status_label)
        
        test_layout.addStretch()
        content_layout.addWidget(test_panel, 1)
        
        # Right Panel: Active Rules
        rules_panel = ModernCard("Active Detection Rules", get_list_icon(20))
        rules_layout = rules_panel.content_layout
        
        self.rules_table = QTableWidget()
        self.rules_table.setColumnCount(3)
        self.rules_table.setHorizontalHeaderLabels(["ID", "Severity", "Target"])
        self.rules_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.rules_table.verticalHeader().setVisible(False)
        self.rules_table.setStyleSheet("""
            QTableWidget {
                background-color: #0D1117;
                border: 1px solid #30363D;
                border-radius: 6px;
                color: #C9D1D9;
            }
            QHeaderView::section {
                background-color: #161B22;
                color: #8B949E;
                padding: 8px;
                border: none;
            }
        """)
        rules_layout.addWidget(self.rules_table)
        
        content_layout.addWidget(rules_panel, 2)
        edr_layout.addLayout(content_layout)
        
        self.main_tab_widget.addTab(edr_widget, "EDR Simulator")
        
        # Setup additional tabs
        self.setup_log_viewer_tab()
        self.setup_poc_tab()

    def setup_log_viewer_tab(self):
        """Setup Log Viewer tab with All Logs, System Log and IDA Log sub-tabs."""
        log_widget = QWidget()
        log_layout = QVBoxLayout(log_widget)
        log_layout.setContentsMargins(16, 16, 16, 16)
        log_layout.setSpacing(16)
        
        # Title
        title = QLabel("📜 Log Viewer")
        title.setStyleSheet("font-size: 18px; font-weight: bold; color: #E6EDF3;")
        log_layout.addWidget(title)
        
        # Sub-tab widget for different log views
        log_tab = QTabWidget()
        log_tab.setStyleSheet("""
            QTabWidget::pane {
                border: 1px solid #30363D;
                border-radius: 6px;
                background: #0D1117;
            }
            QTabBar::tab {
                background: #21262D;
                color: #8B949E;
                padding: 8px 16px;
                border-top-left-radius: 6px;
                border-top-right-radius: 6px;
                margin-right: 2px;
            }
            QTabBar::tab:selected {
                background: #0D1117;
                color: #58A6FF;
            }
        """)
        
        # All Logs (Unified)
        self.unified_log_widget = UnifiedLogWidget()
        log_tab.addTab(self.unified_log_widget, "📊 All Logs")
        
        # System Log (Python logging)
        self.system_log_widget = SystemLogWidget()
        log_tab.addTab(self.system_log_widget, "🐍 System")
        
        # IDA Log Viewer
        self.ida_log_widget = IDALogViewer()
        log_tab.addTab(self.ida_log_widget, "🔍 IDA")
        
        log_layout.addWidget(log_tab)
        
        self.main_tab_widget.addTab(log_widget, "Log Viewer")
    
    def setup_poc_tab(self):
        """Setup PoC Generator tab for symbolic execution results."""
        poc_widget = QWidget()
        poc_layout = QVBoxLayout(poc_widget)
        poc_layout.setContentsMargins(16, 16, 16, 16)
        poc_layout.setSpacing(16)
        
        # Title
        title = QLabel("🎯 PoC Generator")
        title.setStyleSheet("font-size: 18px; font-weight: bold; color: #E6EDF3;")
        poc_layout.addWidget(title)
        
        # Info
        info = QLabel("Generate Proof-of-Concept input bytes to reach target addresses via symbolic execution.")
        info.setStyleSheet("color: #8B949E; font-size: 13px;")
        poc_layout.addWidget(info)
        
        # PoC Result Widget
        self.poc_result_widget = PoCResultWidget()
        poc_layout.addWidget(self.poc_result_widget)
        
        self.main_tab_widget.addTab(poc_widget, "PoC Generator")

    # EDR Logic Integration
    def generate_edr_rules(self):
        """Generate EDR rules from current analysis"""
        if not hasattr(self, 'current_results') or not self.current_results:
             QMessageBox.warning(self, "No Data", "Please run analysis first.")
             return
             
        try:
            from ..edr.signatures import RuleGenerator
            from ..edr.monitor import EDRMonitor
            
            insights = self.current_results.get("security_insights", [])
            generator = RuleGenerator()
            rules = generator.generate_rules(insights)
            
            # Initialize Monitor if needed
            if not hasattr(self, 'edr_monitor'):
                self.edr_monitor = EDRMonitor()
                
            self.edr_monitor.load_rules(rules)
            
            # Update Table
            self.rules_table.setRowCount(len(rules))
            for i, rule in enumerate(rules):
                self.rules_table.setItem(i, 0, QTableWidgetItem(rule['id']))
                
                sev_item = QTableWidgetItem(rule['severity'])
                if rule['severity'] == "CRITICAL":
                    sev_item.setForeground(QColor("#F85149"))
                elif rule['severity'] == "HIGH":
                    sev_item.setForeground(QColor("#D29922"))
                self.rules_table.setItem(i, 1, sev_item)
                
                self.rules_table.setItem(i, 2, QTableWidgetItem(rule.get('target_ioctl') or "Behavior"))
                
            self.log_message(f"🛡️ Generated {len(rules)} EDR signatures.")
            QMessageBox.information(self, "Success", f"Generated {len(rules)} detection rules.")
            
        except Exception as e:
            self.log_message(f"❌ EDR Gen Error: {e}")

    def test_edr_ioctl(self):
        """Test an IOCTL against the EDR monitor"""
        if not hasattr(self, 'edr_monitor'):
            QMessageBox.warning(self, "Init Required", "Please generate rules first.")
            return
            
        ioctl_str = self.ioctl_input.text()
        if not ioctl_str: return
        
        result = self.edr_monitor.check_ioctl(ioctl_str)
        
        if result['action'] == "BLOCK":
            self.edr_status_label.setStyleSheet("color: #F85149; font-size: 18px; font-weight: bold; background-color: #3e1b1b; padding: 10px; border-radius: 6px;")
            self.edr_status_label.setText(f"🚫 BLOCKED: {result['rule']['severity']}")
        elif result['action'] == "ALERT":
             self.edr_status_label.setStyleSheet("color: #D29922; font-size: 18px; font-weight: bold; background-color: #3e2c00; padding: 10px; border-radius: 6px;")
             self.edr_status_label.setText(f"⚠️ ALERT: {result['rule']['severity']}")
        else:
             self.edr_status_label.setStyleSheet("color: #3FB950; font-size: 18px; font-weight: bold; background-color: #0f2e15; padding: 10px; border-radius: 6px;")
             self.edr_status_label.setText("✅ ALLOWED")

    def setup_function_matches_tab(self):
        """Setup Function Matches tab"""
        matches_widget = QWidget()
        matches_layout = QVBoxLayout(matches_widget)
        matches_layout.setContentsMargins(24, 24, 24, 24)

        # Header with filters
        header_layout = QHBoxLayout()
        header_layout.addWidget(ModernLabel("Function Matches", "headline_large"))
        header_layout.addStretch()

        # Filter controls
        filter_layout = QHBoxLayout()
        filter_layout.setSpacing(12)

        filter_label = ModernLabel("Filter:", "body")
        filter_layout.addWidget(filter_label)

        self.similarity_filter = QComboBox()
        self.similarity_filter.addItems(["All", "High (>80%)", "Medium (50-80%)", "Low (<50%)"])
        self.similarity_filter.setStyleSheet("""
            QComboBox {
                background-color: #161B22;
                border: 1px solid #30363D;
                border-radius: 6px;
                padding: 6px;
                color: #E6EDF3;
            }
        """)
        filter_layout.addWidget(self.similarity_filter)

        self.match_type_filter = QComboBox()
        self.match_type_filter.addItems(["All Types", "Exact Match", "Structural Match", "Partial Match"])
        self.match_type_filter.setStyleSheet(self.similarity_filter.styleSheet())
        filter_layout.addWidget(self.match_type_filter)

        header_layout.addLayout(filter_layout)
        matches_layout.addLayout(header_layout)

        # Function comparison table
        self.function_comparison_table = FunctionComparisonTable()
        self.function_comparison_table.function_selected.connect(self.on_function_selected)
        matches_layout.addWidget(self.function_comparison_table)

        self.main_tab_widget.addTab(matches_widget, "Functions")

    def setup_security_insights_tab(self):
        """Setup Security Insights tab"""
        security_widget = QWidget()
        security_layout = QVBoxLayout(security_widget)
        security_layout.setContentsMargins(24, 24, 24, 24)
        security_layout.setSpacing(24)

        # Header
        header_layout = QHBoxLayout()
        header_layout.addWidget(ModernLabel("Security Insights", "headline_large"))
        header_layout.addStretch()
        security_layout.addLayout(header_layout)

        # Risk overview cards
        risk_cards_layout = QHBoxLayout()
        risk_cards_layout.setSpacing(16)

        self.create_risk_card("Overall Risk Score", "Low", "#3FB950", risk_cards_layout)
        self.create_risk_card("Critical Functions", "0", "#F85149", risk_cards_layout)
        self.create_risk_card("Attack Surface", "Minimal", "#D29922", risk_cards_layout)

        security_layout.addLayout(risk_cards_layout)

        # Insights content area
        self.security_insights_widget = SecurityInsightsWidget()
        security_layout.addWidget(self.security_insights_widget)

        self.main_tab_widget.addTab(security_widget, "Security")

    def setup_raw_results_tab(self):
        """Setup Raw Results tab"""
        raw_widget = QWidget()
        raw_layout = QVBoxLayout(raw_widget)
        raw_layout.setContentsMargins(24, 24, 24, 24)

        # Header with export options
        header_layout = QHBoxLayout()
        header_layout.addWidget(ModernLabel("Raw Results", "headline_large"))
        header_layout.addStretch()

        # Export buttons
        export_layout = QHBoxLayout()
        export_layout.setSpacing(8)

        self.export_json_btn = ModernButton("Export JSON", get_save_icon(16), button_type="outline")
        self.export_json_btn.clicked.connect(lambda: self.export_results("json"))
        export_layout.addWidget(self.export_json_btn)

        self.export_csv_btn = ModernButton("Export CSV", get_save_icon(16), button_type="outline")
        self.export_csv_btn.clicked.connect(lambda: self.export_results("csv"))
        export_layout.addWidget(self.export_csv_btn)

        header_layout.addLayout(export_layout)
        raw_layout.addLayout(header_layout)

        # Results text area (moved from old results panel)
        self.results_text = ModernTextEdit()
        self.results_text.setReadOnly(True)

        # Optimize font for performance
        font = QFont("Consolas", 9)
        font.setStyleHint(QFont.StyleHint.Monospace)
        font.setFixedPitch(True)
        self.results_text.setFont(font)

        # Apply comprehensive text edit optimizations
        optimize_text_edit(self.results_text)
        raw_layout.addWidget(self.results_text)

        self.main_tab_widget.addTab(raw_widget, "Raw Results")

    def create_metric_card(self, title, value, color, parent_layout):
        """Create a metric card for the dashboard"""
        card = QWidget()
        card.setFixedSize(200, 100)
        card.setStyleSheet(f"""
            QWidget {{
                background-color: #161B22;
                border: 1px solid #30363D;
                border-radius: 8px;
                border-left: 4px solid {color};
            }}
        """)

        card_layout = QVBoxLayout(card)
        card_layout.setContentsMargins(16, 12, 16, 12)
        card_layout.setSpacing(8)

        title_label = ModernLabel(title, "caption")
        title_label.setStyleSheet("color: #8B949E; font-weight: 500;")
        card_layout.addWidget(title_label)

        value_label = ModernLabel(value, "headline_medium")
        value_label.setStyleSheet(f"color: {color}; font-weight: 700; font-size: 24px;")
        card_layout.addWidget(value_label)

        card_layout.addStretch()
        parent_layout.addWidget(card)

    def create_risk_card(self, title, value, color, parent_layout):
        """Create a risk assessment card"""
        card = QWidget()
        card.setFixedSize(250, 120)
        card.setStyleSheet(f"""
            QWidget {{
                background-color: #161B22;
                border: 1px solid #30363D;
                border-radius: 8px;
                border-left: 4px solid {color};
            }}
        """)

        card_layout = QVBoxLayout(card)
        card_layout.setContentsMargins(16, 12, 16, 12)
        card_layout.setSpacing(8)

        title_label = ModernLabel(title, "body")
        title_label.setStyleSheet("color: #E6EDF3; font-weight: 600;")
        card_layout.addWidget(title_label)

        value_label = ModernLabel(value, "headline_large")
        value_label.setStyleSheet(f"color: {color}; font-weight: 700; font-size: 28px;")
        card_layout.addWidget(value_label)

        card_layout.addStretch()
        parent_layout.addWidget(card)

    def setup_selection_details_section(self):
        """Setup Selection Details section in right panel"""
        details_card = ModernCard("Selection Details", get_search_icon(20))
        details_layout = details_card.content_layout

        # Placeholder for selection details
        self.selection_details_content = ModernLabel("Select a function or node to view details", "body")
        self.selection_details_content.setStyleSheet("color: #8B949E; text-align: center; padding: 20px;")
        self.selection_details_content.setAlignment(Qt.AlignmentFlag.AlignCenter)
        details_layout.addWidget(self.selection_details_content)

        self.right_content_layout.addWidget(details_card)

    def setup_progress_section(self):
        """Setup Analysis Progress section in right panel"""
        progress_card = ModernCard("Analysis Progress", get_play_icon(20))
        progress_layout = progress_card.content_layout

        # Progress visualization
        self.progress_visualization = QWidget()
        self.progress_visualization.setFixedHeight(120)
        self.progress_visualization.setStyleSheet("""
            QWidget {
                background-color: #0D1117;
                border-radius: 8px;
                padding: 16px;
            }
        """)

        progress_viz_layout = QVBoxLayout(self.progress_visualization)
        progress_viz_layout.setContentsMargins(16, 16, 16, 16)

        # Progress ring (simplified as progress bar for now)
        self.analysis_progress_bar = ModernProgressBar()
        self.analysis_progress_bar.setRange(0, 100)
        self.analysis_progress_bar.setValue(0)
        progress_viz_layout.addWidget(self.analysis_progress_bar)

        # Current stage
        self.current_stage_label = ModernLabel("Ready", "caption")
        self.current_stage_label.setStyleSheet("color: #8B949E; text-align: center;")
        self.current_stage_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        progress_viz_layout.addWidget(self.current_stage_label)

        # Estimated time
        self.estimated_time_label = ModernLabel("", "caption")
        self.estimated_time_label.setStyleSheet("color: #6E7681; text-align: center;")
        self.estimated_time_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        progress_viz_layout.addWidget(self.estimated_time_label)

        progress_layout.addWidget(self.progress_visualization)

        # Progress stages
        self.setup_progress_stages(progress_layout)

        self.right_content_layout.addWidget(progress_card)

        # Aliases for compatibility with batch analysis code
        self.progress_bar = self.analysis_progress_bar
        self.progress_status_label = self.current_stage_label

    def setup_progress_stages(self, parent_layout):
        """Setup progress stages visualization"""
        stages_widget = QWidget()
        stages_layout = QVBoxLayout(stages_widget)
        stages_layout.setContentsMargins(0, 0, 0, 0)
        stages_layout.setSpacing(8)

        self.progress_stages = []
        stages_data = [
            ("Initializing", "#58A6FF", "⚙️"),
            ("Exporting Baseline", "#3FB950", "📤"),
            ("Analyzing Target", "#D29922", "🔍"),
            ("Comparing", "#A371F7", "⚖️"),
            ("Generating Report", "#1F6FEB", "📊")
        ]

        for stage_name, color, icon in stages_data:
            stage_item = QWidget()
            stage_item.setFixedHeight(32)
            stage_layout = QHBoxLayout(stage_item)
            stage_layout.setContentsMargins(8, 4, 8, 4)

            # Stage icon
            stage_icon = ModernLabel(icon, "body")
            stage_layout.addWidget(stage_icon)

            # Stage name
            stage_label = ModernLabel(stage_name, "caption")
            stage_label.setStyleSheet("color: #8B949E;")
            stage_layout.addWidget(stage_label)

            stage_layout.addStretch()

            # Status indicator
            status_indicator = QLabel()
            status_indicator.setFixedSize(12, 12)
            status_indicator.setStyleSheet(f"""
                QLabel {{
                    background-color: #30363D;
                    border-radius: 6px;
                }}
            """)
            stage_layout.addWidget(status_indicator)

            stages_layout.addWidget(stage_item)
            self.progress_stages.append((stage_item, status_indicator, color))

        parent_layout.addWidget(stages_widget)

    def setup_quick_actions_section(self):
        """Setup Quick Actions section in right panel"""
        actions_card = ModernCard("Quick Actions", get_settings_icon(20))
        actions_layout = actions_card.content_layout

        # Action buttons
        actions_list = [
            ("Analyze Logic Flows", get_play_icon(16), self.start_analysis, True),
            ("Cancel Analysis", get_clear_icon(16), self.cancel_analysis, False),
            ("Save Results", get_save_icon(16), self.save_results, False),
            ("Save as Baseline", get_save_icon(16), self.save_baseline, False),
            ("Export Graph", get_save_icon(16), lambda: self.export_results("graph"), False),
            ("Load Baseline", get_load_icon(16), self.load_baseline, True),
            ("Batch Analysis", get_chart_icon(16), self.show_batch_analysis, True),
        ]

        for action_text, icon, callback, enabled in actions_list:
            action_btn = ModernButton(action_text, icon, button_type="outline")
            action_btn.clicked.connect(callback)
            action_btn.setEnabled(enabled)
            actions_layout.addWidget(action_btn)

            # Store references for later enabling/disabling
            if action_text == "Analyze Logic Flows":
                self.analyze_btn = action_btn
            elif action_text == "Cancel Analysis":
                self.cancel_btn = action_btn
            elif action_text == "Save Results":
                self.save_btn = action_btn
            elif action_text == "Save as Baseline":
                self.save_baseline_btn = action_btn
            elif action_text == "Load Baseline":
                self.load_baseline_btn = action_btn

        self.right_content_layout.addWidget(actions_card)

    # New methods for the updated UI
    def toggle_theme(self):
        """Toggle between light and dark themes"""
        from ..utils.qt_helper import apply_theme

        self.dark_mode = not self.dark_mode

        # Apply new theme
        app = QApplication.instance()
        apply_theme(app, dark_mode=self.dark_mode)

        # Update theme toggle button icon
        if self.dark_mode:
            self.theme_toggle_btn.setIcon(get_sun_icon(20))
            self.theme_toggle_btn.setToolTip("Switch to light theme")
        else:
            self.theme_toggle_btn.setIcon(get_moon_icon(20))
            self.theme_toggle_btn.setToolTip("Switch to dark theme")

        # Force redraw of all widgets
        self.update()
        for widget in self.findChildren(QWidget):
            widget.update()

        self.status_message.setText(f"Switched to {'dark' if self.dark_mode else 'light'} theme")

    def show_settings_menu(self):
        """Show settings dropdown menu"""
        menu = QMenu(self)
        menu.setStyleSheet("""
            QMenu {
                background-color: #161B22;
                border: 1px solid #30363D;
                color: #E6EDF3;
            }
            QMenu::item {
                padding: 8px 16px;
            }
            QMenu::item:selected {
                background-color: #1F6FEB;
                color: white;
            }
        """)

        # Add menu items
        preferences_action = menu.addAction("Preferences")
        keyboard_shortcuts_action = menu.addAction("Keyboard Shortcuts")
        about_action = menu.addAction("About")

        # Show menu
        selected_action = menu.exec(self.settings_btn.mapToGlobal(
            QPoint(0, self.settings_btn.height())
        ))

        if selected_action == preferences_action:
            QMessageBox.information(self, "Preferences", "Preferences dialog will be implemented")
        elif selected_action == keyboard_shortcuts_action:
            QMessageBox.information(self, "Keyboard Shortcuts", "Keyboard shortcuts help will be implemented")
        elif selected_action == about_action:
            QMessageBox.information(self, "About", "Logic Flow Analysis Tool v3.0\nAdvanced binary analysis for Windows kernel drivers")

    def toggle_sidebar(self):
        """Toggle sidebar visibility"""
        current_width = self.main_splitter.sizes()[0]
        if current_width > 50:  # Sidebar is visible
            self.main_splitter.setSizes([0, self.main_splitter.sizes()[1] + current_width, self.main_splitter.sizes()[2]])
            self.sidebar_collapse_btn.setIcon(get_clear_icon(16))  # Change to expand icon
        else:  # Sidebar is collapsed
            self.main_splitter.setSizes([280, max(1, self.main_splitter.sizes()[1] - 280), self.main_splitter.sizes()[2]])
            self.sidebar_collapse_btn.setIcon(get_clear_icon(16))  # Keep collapse icon

    def toggle_right_panel(self):
        """Toggle right panel visibility"""
        current_width = self.main_splitter.sizes()[2]
        if current_width > 50:  # Panel is visible
            self.main_splitter.setSizes([self.main_splitter.sizes()[0], self.main_splitter.sizes()[1] + current_width, 0])
        else:  # Panel is collapsed
            self.main_splitter.setSizes([self.main_splitter.sizes()[0], max(1, self.main_splitter.sizes()[1] - 320), 320])

    def on_driver_card_clicked(self, card, driver):
        """Handle driver card click"""
        if driver == "Driver A":
            self.select_driver_a()
        elif driver == "Driver B":
            self.select_driver_b()

    def on_driver_card_drag_enter(self, event, driver):
        """Handle drag enter on driver card"""
        if event.mimeData().hasUrls():
            event.accept()
        else:
            event.ignore()

    def on_driver_card_drop(self, event, driver):
        """Handle file drop on driver card with loading animation"""
        if event.mimeData().hasUrls():
            file_path = event.mimeData().urls()[0].toLocalFile()
            if os.path.isfile(file_path) and file_path.lower().endswith('.sys'):
                # Show loading state
                card = self.driver_a_card if driver == "Driver A" else self.driver_b_card
                self.show_card_loading_state(card, True)

                # Process file with slight delay to show loading animation
                QTimer.singleShot(500, lambda: self.process_dropped_file(file_path, driver))
            event.accept()
        else:
            event.ignore()

    def process_dropped_file(self, file_path, driver):
        """Process dropped file after loading animation"""
        card = self.driver_a_card if driver == "Driver A" else self.driver_b_card

        try:
            if driver == "Driver A":
                self.driver_a_path = file_path
                self.update_driver_a_card(file_path)
            elif driver == "Driver B":
                self.driver_b_path = file_path
                self.update_driver_b_card(file_path)

            self.update_analysis_button_state()
            self.status_message.setText(f"Loaded {os.path.basename(file_path)} as {driver}")

        except Exception as e:
            card.file_name_label.setText("Error loading file")
            card.file_details_label.setText(str(e))
            card.status_indicator.setStyleSheet("""
                QWidget {
                    background-color: #F85149;
                    border-radius: 6px;
                    border: 2px solid #1C2128;
                }
            """)
            self.status_message.setText(f"Error loading {os.path.basename(file_path)}")

        finally:
            self.show_card_loading_state(card, False)

    def show_card_loading_state(self, card, loading):
        """Show or hide loading state on driver card"""
        card.loading_progress.setVisible(loading)
        if loading:
            card.action_hint.setText("Loading file...")
            card.action_hint.setStyleSheet("color: #58A6FF; font-style: italic;")
            # Animate progress bar
            self.animate_progress_bar(card.loading_progress)
        else:
            card.action_hint.setStyleSheet("color: #6E7681; font-style: italic;")

    def animate_progress_bar(self, progress_bar):
        """Animate progress bar to show loading"""
        progress_bar.setRange(0, 0)  # Indeterminate progress
        QTimer.singleShot(2000, lambda: progress_bar.setRange(0, 100))  # Stop after 2 seconds

    def on_graph_node_selected(self, node_id):
        """Handle graph node selection"""
        self.status_message.setText(f"Selected node: {node_id}")
        # Update selection details panel
        if hasattr(self, 'selection_details_content'):
            self.selection_details_content.setText(f"Selected: {node_id}\n\nNode details will appear here.")
            self.selection_details_content.setStyleSheet("color: #E6EDF3; text-align: left; padding: 20px;")

    def on_graph_node_double_clicked(self, node_id):
        """Handle graph node double-click"""
        self.status_message.setText(f"Double-clicked node: {node_id}")
        # Could open detailed view or center on node

    def toggle_graph_overlay(self):
        """Toggle between graph overlay modes"""
        # Placeholder for overlay functionality
        QMessageBox.information(self, "Graph Overlay", "Overlay mode toggle - will show diff visualization")

    def load_sample_graph(self):
        """Load a sample graph for demonstration"""
        # Sample graph data
        sample_data = {
            "nodes": [
                {"id": "entry", "label": "Entry Point", "type": "entry", "position": (0, 0)},
                {"id": "init", "label": "Initialize", "type": "normal", "position": (0, 100)},
                {"id": "check", "label": "Validate Input", "type": "decision", "position": (0, 200)},
                {"id": "process", "label": "Process Data", "type": "normal", "position": (-100, 300)},
                {"id": "error", "label": "Handle Error", "type": "normal", "position": (100, 300)},
                {"id": "exit", "label": "Exit", "type": "exit", "position": (0, 400)}
            ],
            "edges": [
                {"source": "entry", "target": "init"},
                {"source": "init", "target": "check"},
                {"source": "check", "target": "process"},
                {"source": "check", "target": "error"},
                {"source": "process", "target": "exit"},
                {"source": "error", "target": "exit"}
            ]
        }

        if hasattr(self, 'graph_view'):
            self.graph_view.load_graph_data(sample_data)
            self.main_tab_widget.setCurrentIndex(1)  # Switch to graph tab
            self.status_message.setText("Loaded sample graph for demonstration")

    def select_driver_a(self):
        """Select Driver A file"""
        file_path, _ = QFileDialog.getOpenFileName(
            self, "Select Reference Driver A",
            "", "Windows Drivers (*.sys);;All files (*.*)"
        )
        if file_path:
            self.driver_a_path = file_path
            self.update_driver_a_card(file_path)
            self.update_analysis_button_state()

    def select_driver_b(self):
        """Select Driver B file"""
        file_path, _ = QFileDialog.getOpenFileName(
            self, "Select Target Driver B",
            "", "Windows Drivers (*.sys);;All files (*.*)"
        )
        if file_path:
            self.driver_b_path = file_path
            self.update_driver_b_card(file_path)
            self.update_analysis_button_state()

    def update_driver_a_card(self, file_path):
        """Update Driver A card with file information"""
        self.update_driver_card(self.driver_a_card, file_path, "Driver A")

    def update_driver_b_card(self, file_path):
        """Update Driver B card with file information"""
        self.update_driver_card(self.driver_b_card, file_path, "Driver B")

    def update_driver_card(self, card, file_path, driver_name):
        """Update driver card with file information and visual feedback"""
        try:
            file_name = os.path.basename(file_path)
            file_size = os.path.getsize(file_path)
            file_size_mb = file_size / (1024 * 1024)

            # Update card appearance
            card.file_name_label.setText(file_name)
            card.file_details_label.setText(f"Size: {file_size_mb:.1f} MB")
            card.status_indicator.setStyleSheet("""
                QWidget {
                    background-color: #3FB950;
                    border-radius: 6px;
                    border: 2px solid #1C2128;
                }
            """)
            card.action_hint.setText("File loaded successfully ✓")
            card.action_hint.setStyleSheet("color: #3FB950; font-style: normal; font-weight: 500;")
            card.file_info_widget.setVisible(True)

            # Enable fetch functions button for Driver A
            if driver_name == "Driver A":
                self.fetch_functions_btn.setEnabled(True)

        except Exception as e:
            card.file_name_label.setText("Error loading file")
            card.file_details_label.setText(str(e))
            card.status_indicator.setStyleSheet("""
                QWidget {
                    background-color: #F85149;
                    border-radius: 6px;
                    border: 2px solid #1C2128;
                }
            """)

    def on_global_search_changed(self, text):
        """Handle global search text changes for live search"""
        if len(text) >= 3:  # Only search when 3+ characters
            self.perform_global_search()

    def perform_global_search(self):
        """Perform global search across all content"""
        search_text = self.global_search.text().strip()
        if not search_text:
            return

        # Search in results text
        if self.results_text.toPlainText():
            cursor = self.results_text.textCursor()
            document = self.results_text.document()

            # Find the text
            found = document.find(search_text, cursor)
            if found:
                self.results_text.setTextCursor(found)
                self.results_text.ensureCursorVisible()
                # Switch to Raw Results tab
                self.main_tab_widget.setCurrentIndex(4)  # Raw Results tab
                self.status_message.setText(f"Found '{search_text}' in results")
            else:
                self.status_message.setText(f"'{search_text}' not found")

        # TODO: Extend search to other tabs and components

    def export_results(self, format_type):
        """Export results in specified format"""
        if not self.current_results:
            QMessageBox.information(self, "Info", "No results to export")
            return

        if format_type == "json":
            self.save_results()  # Use existing save functionality
        elif format_type == "csv":
            # Implement CSV export
            QMessageBox.information(self, "Export CSV", "CSV export will be implemented")
        elif format_type == "graph":
            # Implement graph export
            QMessageBox.information(self, "Export Graph", "Graph export will be implemented")

    def setup_center_content(self, splitter):
        """Setup center content area with dynamic tabs"""
        center_widget = QWidget()
        center_layout = QVBoxLayout(center_widget)
        center_layout.setContentsMargins(0, 0, 0, 0)
        center_layout.setSpacing(0)

        # Tab widget for main content
        self.main_tab_widget = QTabWidget()
        self.main_tab_widget.setObjectName("mainTabs")
        self.main_tab_widget.setStyleSheet("""
            QTabWidget#mainTabs::pane {
                border: 1px solid #30363D;
                background-color: #0D1117;
                border-radius: 0;
            }
            QTabBar::tab {
                background-color: #161B22;
                color: #8B949E;
                border: 1px solid #30363D;
                border-bottom: none;
                padding: 12px 20px;
                margin-right: 2px;
                border-top-left-radius: 8px;
                border-top-right-radius: 8px;
                font-size: 13px;
                font-weight: 500;
            }
            QTabBar::tab:selected {
                background-color: #0D1117;
                color: #E6EDF3;
                border-bottom: 2px solid #1F6FEB;
                font-weight: 600;
            }
            QTabBar::tab:hover {
                background-color: #1C2128;
                color: #E6EDF3;
            }
        """)

        # Analysis Dashboard tab
        self.setup_analysis_dashboard_tab()

        # Graph Comparison tab
        self.setup_graph_comparison_tab()

        # Function Matches tab
        self.setup_function_matches_tab()

        # Security Insights tab
        self.setup_security_insights_tab()
        
        # EDR Simulator tab
        self.setup_edr_tab()

        # Raw Results tab
        self.setup_raw_results_tab()

        center_layout.addWidget(self.main_tab_widget)
        splitter.addWidget(center_widget)

    def setup_right_panel(self, splitter):
        """Setup collapsible right panel"""
        right_panel_widget = QWidget()
        right_panel_widget.setFixedWidth(320)
        right_panel_widget.setObjectName("rightPanel")
        right_panel_widget.setStyleSheet("""
            QWidget#rightPanel {
                background-color: #161B22;
                border-left: 1px solid #30363D;
            }
        """)

        right_layout = QVBoxLayout(right_panel_widget)
        right_layout.setContentsMargins(0, 0, 0, 0)
        right_layout.setSpacing(0)

        # Right panel header
        right_header = QWidget()
        right_header.setFixedHeight(48)
        right_header.setStyleSheet("background-color: #1C2128; border-bottom: 1px solid #30363D;")
        header_layout = QHBoxLayout(right_header)
        header_layout.setContentsMargins(16, 0, 16, 0)

        right_title = ModernLabel("Context", "subtitle")
        header_layout.addWidget(right_title)
        header_layout.addStretch()

        # Collapse button
        self.right_panel_collapse_btn = ModernButton("", get_clear_icon(16), button_type="outline")
        self.right_panel_collapse_btn.setFixedSize(32, 32)
        self.right_panel_collapse_btn.setToolTip("Collapse panel")
        self.right_panel_collapse_btn.clicked.connect(self.toggle_right_panel)
        header_layout.addWidget(self.right_panel_collapse_btn)

        right_layout.addWidget(right_header)

        # Context-sensitive content area
        self.right_content_area = QWidget()
        self.right_content_layout = QVBoxLayout(self.right_content_area)
        self.right_content_layout.setContentsMargins(16, 16, 16, 16)
        self.right_content_layout.setSpacing(16)

        # Selection Details section
        self.setup_selection_details_section()

        # Analysis Progress section
        self.setup_progress_section()

        # Quick Actions section
        self.setup_quick_actions_section()

        right_layout.addWidget(self.right_content_area)
        splitter.addWidget(right_panel_widget)

    def setup_bottom_status_bar(self, parent_layout):
        """Setup bottom status bar"""
        status_container = QWidget()
        status_container.setFixedHeight(32)
        status_container.setObjectName("bottomStatusBar")
        status_container.setStyleSheet("""
            QWidget#bottomStatusBar {
                background-color: #161B22;
                border-top: 1px solid #30363D;
                padding: 0 16px;
            }
        """)

        status_layout = QHBoxLayout(status_container)
        status_layout.setContentsMargins(0, 0, 0, 0)
        status_layout.setSpacing(16)

        # Status message
        self.status_message = ModernLabel("Ready", "caption")
        status_layout.addWidget(self.status_message)

        status_layout.addStretch()

        # Statistics summary
        self.stats_summary = ModernLabel("", "caption")
        self.stats_summary.setStyleSheet("color: #8B949E;")
        status_layout.addWidget(self.stats_summary)

        # Version info
        version_label = ModernLabel("v3.0", "caption")
        version_label.setStyleSheet("color: #6E7681;")
        status_layout.addWidget(version_label)

        parent_layout.addWidget(status_container)

    def load_function_comparison_data(self, results):
        """Load function comparison data from analysis results"""
        comparison_data = None

        # Extract comparison results
        if "comparison_results" in results:
            comparison_data = results["comparison_results"]
        elif "comparisons" in results:
            # Convert old format to new format if needed
            comparison_data = []
            for addr, comp_data in results["comparisons"].items():
                comparison_data.append({
                    "candidate_address": addr,
                    "candidate_name": comp_data.get("name", f"function_{addr}"),
                    "score": comp_data.get("similarity_score", 0),
                    "comparison": comp_data
                })

        if comparison_data and hasattr(self, 'function_comparison_table'):
            self.function_comparison_table.load_comparison_data(comparison_data)
            # Switch to functions tab if we have data
            if comparison_data:
                self.main_tab_widget.setCurrentIndex(2)  # Functions tab

    def on_function_selected(self, function_data, dialog=None):
        """Handle function selection from table"""
        func_name = function_data.get("candidate_name", "Unknown")
        score = function_data.get("score", 0)
        address = function_data.get("candidate_address") or function_data.get("address", "0x00000000")

        # Update selection details panel
        # Format address (can be int or string)
        if isinstance(address, int):
            addr_str = f"0x{address:08X}"
        else:
            addr_str = str(address)
        
        details_text = f"""
<b>Function:</b> {func_name}<br>
<b>Address:</b> {addr_str}<br>
<b>Similarity Score:</b> {score:.1f}<br>
<b>Risk Level:</b> {self.calculate_risk_level_from_score(score)}<br><br>
<i>Double-click for detailed analysis</i>
        """

        if hasattr(self, 'selection_details_content'):
            self.selection_details_content.setText(details_text)
            self.selection_details_content.setStyleSheet("color: #E6EDF3; text-align: left; padding: 20px;")

        # Update status
        self.status_message.setText(f"Selected function: {func_name} (Score: {score:.1f})")

    def calculate_risk_level_from_score(self, score):
        """Calculate risk level from similarity score"""
        if score > 8.5:
            return "Critical"
        elif score > 7.0:
            return "High"
        elif score > 5.0:
            return "Medium"
        else:
            return "Low"

    def setup_connections(self):
        """Setup signal connections"""
        pass  # Connections are set up in individual methods

    def on_driver_a_selected(self, file_path: str):
        """Handle driver A selection"""
        self.driver_a_path = file_path
        self.update_analysis_button_state()

    def on_driver_b_selected(self, file_path: str):
        """Handle driver B selection"""
        self.driver_b_path = file_path
        self.update_analysis_button_state()

    def on_ida_selected(self, file_path: str):
        """Handle IDA path selection"""
        self.ida_path = file_path
        self.config_manager.set_ida_path(file_path)
        self.update_analysis_button_state()

    def on_timeout_changed(self, minutes: int):
        """Handle timeout value change"""
        timeout_seconds = minutes * 60
        self.config_manager.set_ida_timeout(timeout_seconds)

    def search_in_results(self):
        """Show search dialog for results text"""
        if not self.results_text.toPlainText():
            QMessageBox.information(self, "Info", "No results to search")
            return

        search_text, ok = QInputDialog.getText(
            self, "Search in Results",
            "Enter text to search:",
            text=self.last_search_text if hasattr(self, 'last_search_text') else ""
        )

        if ok and search_text:
            self.last_search_text = search_text
            self.perform_search(search_text)

    def perform_search(self, search_text: str):
        """Perform search in results text"""
        cursor = self.results_text.textCursor()
        document = self.results_text.document()

        # Find the text
        found = document.find(search_text, cursor)

        if found:
            self.results_text.setTextCursor(found)
            self.results_text.ensureCursorVisible()
        else:
            # Wrap around to beginning
            cursor.setPosition(0)
            found = document.find(search_text, cursor)
            if found:
                self.results_text.setTextCursor(found)
                self.results_text.ensureCursorVisible()
            else:
                QMessageBox.information(self, "Search", f"Text '{search_text}' not found")

    def keyPressEvent(self, event):
        """Handle global key presses"""
        # Ctrl+K - Focus global search
        if event.key() == Qt.Key.Key_K and event.modifiers() == Qt.KeyboardModifier.ControlModifier:
            self.global_search.setFocus()
            self.global_search.selectAll()
            event.accept()
        # Ctrl+F - Search in results
        elif event.key() == Qt.Key.Key_F and event.modifiers() == Qt.KeyboardModifier.ControlModifier:
            self.search_in_results()
            event.accept()
        # Ctrl+Enter - Start analysis
        elif event.key() == Qt.Key.Key_Enter and event.modifiers() == Qt.KeyboardModifier.ControlModifier:
            if self.analyze_btn.isEnabled():
                self.start_analysis()
            event.accept()
        # Ctrl+S - Save results
        elif event.key() == Qt.Key.Key_S and event.modifiers() == Qt.KeyboardModifier.ControlModifier:
            if self.save_btn.isEnabled():
                self.save_results()
            event.accept()
        # F11 - Toggle fullscreen
        elif event.key() == Qt.Key.Key_F11:
            if self.isFullScreen():
                self.showNormal()
            else:
                self.showFullScreen()
            event.accept()
        else:
            super().keyPressEvent(event)

    def update_analysis_button_state(self):
        """Update analysis button enabled state"""
        can_analyze = bool(self.driver_a_path and self.driver_b_path and self.ida_path)
        self.analyze_btn.setEnabled(can_analyze)

        # Enable fetch functions button if we have driver A and IDA
        can_fetch_functions = bool(self.driver_a_path and self.ida_path)
        self.fetch_functions_btn.setEnabled(can_fetch_functions)

    def add_to_recent_analyses(self):
        """Add current driver pair to recent analyses"""
        if self.driver_a_path and self.driver_b_path:
            from PyQt6.QtCore import QSettings
            settings = QSettings("LogicFlowAnalysis", "RecentAnalyses")

            # Get existing recent analyses
            recent_str = settings.value("recent_pairs", "")
            recent_pairs = [pair for pair in recent_str.split("|||") if pair] if recent_str else []

            # Create new pair string
            new_pair = f"{self.driver_a_path}|{self.driver_b_path}"

            # Remove if already exists (to avoid duplicates)
            if new_pair in recent_pairs:
                recent_pairs.remove(new_pair)

            # Add to front
            recent_pairs.insert(0, new_pair)

            # Keep only last 5
            recent_pairs = recent_pairs[:5]

            # Save back
            settings.setValue("recent_pairs", "|||".join(recent_pairs))

    def collect_debug_context(self):
        """Collect debug context from UI"""
        context = {}

        exception_type = self.exception_edit.text().strip()
        if exception_type:
            context["exception_type"] = exception_type

        irql_level = self.irql_edit.text().strip()
        if irql_level:
            try:
                context["irql_level"] = int(irql_level)
            except ValueError:
                context["irql_level"] = irql_level

        status_code = self.status_edit.text().strip()
        if status_code:
            context["status_code"] = status_code

        crash_address = self.crash_addr_edit.text().strip()
        if crash_address:
            try:
                if crash_address.startswith('0x'):
                    context["crash_address"] = int(crash_address, 16)
                else:
                    context["crash_address"] = int(crash_address, 16)
            except ValueError:
                context["crash_address"] = crash_address

        call_stack = self.callstack_edit.text().strip()
        if call_stack:
            context["call_stack"] = [addr.strip() for addr in call_stack.split(',') if addr.strip()]

        notes = self.notes_edit.toPlainText().strip()
        if notes:
            context["notes"] = notes

        if context:
            context["captured_at"] = datetime.now().isoformat()

        return context if context else None

    def start_analysis(self):
        """Start logic flow analysis"""
        if not self.validate_inputs():
            return

        # Collect debug context and anchor function
        self.debug_context = self.collect_debug_context()
        anchor_function = self.anchor_function_combo.currentText().strip()

        # Clear previous results
        self.results_text.clear()
        self.analysis_progress_bar.setValue(0)
        self.current_stage_label.setText("Starting analysis...")
        self.status_message.setText("🚀 Starting analysis...")

        # Disable UI during analysis
        self.analyze_btn.setEnabled(False)
        if hasattr(self, 'save_btn'):
            self.save_btn.setEnabled(False)

        # Start analysis worker
        self.analysis_worker = AnalysisWorker(
            self.driver_a_path,
            self.driver_b_path,
            self.ida_path,
            anchor_function,
            self.debug_context
        )

        self.analysis_worker.progress_updated.connect(self.on_progress_updated)
        self.analysis_worker.analysis_finished.connect(self.on_analysis_finished)
        self.analysis_worker.error_occurred.connect(self.on_analysis_error)

        self.analysis_worker.start()

        # Enable cancel button during analysis
        if hasattr(self, 'cancel_btn'):
            self.cancel_btn.setEnabled(True)

    def fetch_functions_from_driver_a(self):
        """Fetch function list from Driver A using lightweight IDA analysis"""
        if not self.driver_a_path or not self.ida_path:
            QMessageBox.warning(self, "Error", "Please select both Driver A and IDA Pro path first")
            return

        # Disable button and show progress
        self.fetch_functions_btn.setEnabled(False)
        self.status_message.setText("🔍 Initializing function fetch...")

        # Create worker using new pattern
        worker = Worker(self._do_fetch_functions_logic)
        worker.signals.result.connect(self.on_function_fetch_finished)
        worker.signals.error.connect(self.on_function_fetch_error)
        worker.signals.finished.connect(self.on_function_fetch_complete)

        # Start the worker
        self.threadpool.start(worker)

    def _do_fetch_functions_logic(self, progress_callback):
        """Background logic for fetching functions using IDAClient."""
        from ..core.analyzer import IDAClient

        # Get script path
        from ..core.analyzer import IDAAnalysisRunner
        runner = IDAAnalysisRunner(self.ida_path)
        script_path = runner.script_path

        # Create IDA client and fetch functions
        client = IDAClient(self.ida_path, self.driver_a_path, script_path)
        try:
            # Start server and connect
            client.start_server()

            # Send list_functions command
            response = client.send_command('list_functions')

            if 'error' in response:
                raise RuntimeError(f"IDA error: {response['error']}")

            functions_data = response.get('data', [])
            if not functions_data:
                raise RuntimeError("No functions found in the driver")

            # Convert to format expected by UI
            functions_list = []
            for func_data in functions_data:
                addr = func_data.get("address", "unknown")
                name = func_data.get("name", "unknown")
                functions_list.append(f"{addr} - {name}")

            return functions_list

        finally:
            client.close()

    def on_function_fetch_complete(self):
        """Handle completion of function fetch (success or failure)."""
        # Re-enable the button
        self.fetch_functions_btn.setEnabled(True)

    def on_function_fetch_progress(self, message: str):
        """Handle function fetch progress updates"""
        self.status_message.setText(message)

    def on_function_fetch_finished(self, functions_list: list):
        """Handle successful function fetch completion"""
        try:
            # Update the anchor function dropdown
            self.anchor_function_combo.clear()
            self.anchor_function_combo.addItems(functions_list)

            self.status_message.setText(f"✅ Successfully loaded {len(functions_list)} functions from Driver A")

            # Log success
            self.log_message(f"Loaded {len(functions_list)} functions from Driver A")

        except Exception as e:
            self.on_function_fetch_error(f"Error updating UI: {str(e)}")

    def on_function_fetch_error(self, error_info):
        """Handle function fetch errors"""
        # Handle both string errors (from old code) and tuple errors (from Worker)
        if isinstance(error_info, tuple):
            exctype, value, traceback_str = error_info
            error_message = str(value)
        else:
            error_message = str(error_info)

        # Re-enable the button
        self.fetch_functions_btn.setEnabled(True)
        self.status_message.setText("❌ Function fetch failed")

        # Show error dialog
        QMessageBox.critical(self, "Function Fetch Error", error_message)

        # Log error
        self.log_message(f"Function fetch error: {error_message}")

        # Clear any partial results
        self.anchor_function_combo.clear()

    def populate_anchor_function_combo(self, functions):
        """Populate the anchor function combo box with fetched functions"""
        # Clear existing items except the default ones
        current_text = self.anchor_function_combo.currentText()
        self.anchor_function_combo.clear()

        # Add default examples back
        default_items = ["", "IoctlHandler", "DispatchDeviceControl", "DispatchRead", "DispatchWrite", "DriverEntry"]
        for item in default_items:
            self.anchor_function_combo.addItem(item)

        # Add separator
        self.anchor_function_combo.insertSeparator(len(default_items))

        # Add fetched functions (limit to 100 for performance)
        function_names = []
        for func in functions[:100]:
            display_text = f"{func['name']} ({func['address']})"
            self.anchor_function_combo.addItem(display_text, func)  # Store function data
            function_names.append(func['name'])

        # Add completer for auto-completion
        completer = QCompleter(function_names)
        completer.setCaseSensitivity(Qt.CaseSensitivity.CaseInsensitive)
        completer.setCompletionMode(QCompleter.CompletionMode.PopupCompletion)
        completer.setFilterMode(Qt.MatchFlag.MatchContains)
        self.anchor_function_combo.setCompleter(completer)

        # Restore previous selection if it was a fetched function
        if current_text and current_text not in default_items:
            # Try to find it in the fetched functions
            for func in functions[:100]:
                if func['name'] == current_text:
                    display_text = f"{func['name']} ({func['address']})"
                    self.anchor_function_combo.setCurrentText(display_text)
                    break
            else:
                # If not found, add it back
                self.anchor_function_combo.setCurrentText(current_text)

    def show_function_selection_dialog(self, functions):
        """Show dialog to select function from the fetched list"""
        from PyQt6.QtWidgets import QDialog, QVBoxLayout, QListWidget, QListWidgetItem, QPushButton, QHBoxLayout

        dialog = QDialog(self)
        dialog.setWindowTitle("Select Anchor Function")
        dialog.setModal(True)
        dialog.resize(500, 400)

        layout = QVBoxLayout(dialog)

        # Instructions
        instruction_label = ModernLabel(f"Found {len(functions)} functions in Driver A. Select the anchor function to analyze:", "body")
        layout.addWidget(instruction_label)

        # Function list
        list_widget = QListWidget()
        for func in functions[:1000]:  # Limit for performance
            item = QListWidgetItem(f"{func['address']} - {func['name']}")
            item.setData(1, func)  # Store function data
            list_widget.addItem(item)
        layout.addWidget(list_widget)

        # Buttons
        button_layout = QHBoxLayout()

        select_btn = QPushButton("Select")
        select_btn.clicked.connect(lambda: self.on_function_selected_from_dialog(list_widget.currentItem(), dialog))

        cancel_btn = QPushButton("Cancel")
        cancel_btn.clicked.connect(dialog.reject)

        button_layout.addStretch()
        button_layout.addWidget(cancel_btn)
        button_layout.addWidget(select_btn)

        layout.addLayout(button_layout)

        dialog.exec()

    def on_function_selected_from_dialog(self, item, dialog):
        """Handle function selection from dialog"""
        if item:
            func_data = item.data(1)
            if func_data:
                # Set the selected function in the anchor input
                func_name = func_data['name']
                func_address = func_data['address']
                self.anchor_function_combo.setCurrentText(func_name)
                self.log_message(f"Selected anchor function: {func_name} ({func_address})")

        dialog.accept()

    def cancel_analysis(self):
        """Cancel the current analysis"""
        if self.analysis_worker and self.analysis_worker.isRunning():
            self.progress_status_label.setText("Cancelling analysis...")
            self.status_label.setText("🛑 Cancelling analysis...")

            # Request termination of the worker thread
            self.analysis_worker.requestInterruption()

            # Try to terminate IDA processes
            self._terminate_ida_processes()

            # Disable buttons
            self.analyze_btn.setEnabled(False)
            self.cancel_btn.setEnabled(False)

    def _terminate_ida_processes(self):
        """Terminate IDA Pro processes spawned by this application only"""
        try:
            import psutil
            import os

            current_pid = os.getpid()
            terminated_count = 0

            for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
                try:
                    proc_name = proc.info['name']
                    if not proc_name:
                        continue

                    proc_name_lower = proc_name.lower()
                    is_ida_process = 'ida' in proc_name_lower or 'idat' in proc_name_lower

                    # Only terminate IDA processes (not all of them)
                    if is_ida_process and proc.info['pid'] != current_pid:
                        cmdline = ' '.join(proc.info['cmdline'] or [])
                        cmdline_lower = cmdline.lower()

                        # Check if this IDA process is related to our analysis
                        should_terminate = False

                        # Check for our driver paths
                        if self.driver_a_path and self.driver_a_path.lower() in cmdline_lower:
                            should_terminate = True
                        if self.driver_b_path and self.driver_b_path.lower() in cmdline_lower:
                            should_terminate = True

                        # Check for our temp directory marker
                        if 'ida_analysis_' in cmdline_lower:
                            should_terminate = True

                        # Check if it's a direct child process of ours (most reliable)
                        try:
                            if proc.parent() and proc.parent().pid == current_pid:
                                should_terminate = True
                        except:
                            pass

                        if should_terminate:
                            try:
                                logger.info(f"Terminating IDA process: PID {proc.info['pid']}, Command: {proc_name}")
                                proc.terminate()

                                # Wait for graceful termination
                                try:
                                    proc.wait(timeout=3)
                                except psutil.TimeoutExpired:
                                    logger.warning(f"Force killing IDA process: {proc.info['pid']}")
                                    proc.kill()

                                terminated_count += 1

                            except psutil.NoSuchProcess:
                                pass  # Already terminated
                            except Exception as e:
                                logger.error(f"Error terminating process {proc.info['pid']}: {e}")

                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue

            if terminated_count > 0:
                logger.info(f"Successfully terminated {terminated_count} IDA processes")
                self.log_message(f"✅ Terminated {terminated_count} running IDA processes")

        except ImportError:
            logger.warning("psutil not available, cannot terminate IDA processes safely")
            self.log_message("⚠️  Cannot terminate IDA processes (psutil not installed)")
        except Exception as e:
            logger.error(f"Error terminating IDA processes: {e}")
            self.log_message(f"⚠️  Error terminating IDA processes: {str(e)}")

    def validate_inputs(self):
        """Validate user inputs"""
        # Normalize paths for cross-platform compatibility
        driver_a_path = os.path.normpath(self.driver_a_path) if self.driver_a_path else None
        driver_b_path = os.path.normpath(self.driver_b_path) if self.driver_b_path else None
        ida_path = os.path.normpath(self.ida_path) if self.ida_path else None

        if not driver_a_path or not os.path.exists(driver_a_path):
            QMessageBox.warning(self, "Error", "Please select a valid reference driver A")
            return False

        if not driver_b_path or not os.path.exists(driver_b_path):
            QMessageBox.warning(self, "Error", "Please select a valid target driver B")
            return False

        if not ida_path or not os.path.exists(ida_path):
            QMessageBox.warning(self, "Error", "Please select a valid IDA Pro executable")
            return False

        return True

    # ========================================================================
    # GRAPH VIEW CONTROLS
    # ========================================================================
    
    def on_view_mode_changed(self, index: int):
        """Handle view mode dropdown change"""
        if not hasattr(self, 'graph_view') or not hasattr(self, 'current_results'):
            return
        
        if not self.current_results or "graph" not in self.current_results:
            return
        
        mode = self.view_mode_combo.currentText()
        graph_data = self.current_results["graph"]
        
        if mode == "Side-by-Side":
            # Reload with side-by-side layout
            self.graph_view.load_graph_data(graph_data)
            self.log_message("📊 View: Side-by-Side")
        elif mode == "Overlay":
            # Stack all nodes together with unified layout
            self.graph_view.clear_graph()
            for node_data in graph_data.get("nodes", []):
                node_id = node_data.get("id", "")
                label = node_data.get("label", node_id)
                node_type = node_data.get("type", "normal")
                self.graph_view.add_node(node_id, label, node_type, (0, 0))
            
            for edge_data in graph_data.get("edges", []):
                self.graph_view.add_edge(
                    edge_data.get("source", ""),
                    edge_data.get("target", ""),
                    edge_data.get("label", ""),
                    edge_data.get("type", "direct")
                )
            
            self.graph_view.auto_layout()
            self.graph_view.fitInView(self.graph_view.scene.sceneRect(), Qt.AspectRatioMode.KeepAspectRatio)
            self.log_message("📊 View: Overlay (all nodes merged)")
        elif mode == "Unified Diff":
            # Show only changed/different nodes
            self.graph_view.clear_graph()
            
            # basic mapping from analysis
            matches = self.current_results.get("matches", [])
            matched_pairs = set()
            for m in matches:
                # Store tuple of (addr_a, addr_b) or names
                # Try to match loosely based on address or name found in node ID
                pass

            # Identifying A vs B based on driver names
            import os
            driver_a_name = os.path.basename(self.driver_a_path) if self.driver_a_path else ""
            driver_b_name = os.path.basename(self.driver_b_path) if self.driver_b_path else ""
            
            # Simple heuristic for now: 
            # If node from A and not in matches -> Removed (Red)
            # If node from B and not in matches -> Added (Green)
            # If in matches -> Unchanged (Gray)
            
            # Build match sets for lookup
            matched_a_addrs = set()
            matched_b_addrs = set()
            for m in matches:
                # Handle int or hex string addresses
                addr_a = m.get("address")
                addr_b = m.get("candidate_address")
                matched_a_addrs.add(str(addr_a))
                matched_a_addrs.add(f"0x{int(addr_a):X}" if isinstance(addr_a, int) else str(addr_a))
                
                matched_b_addrs.add(str(addr_b))
                matched_b_addrs.add(f"0x{int(addr_b):X}" if isinstance(addr_b, int) else str(addr_b))

            nodes_to_show = []
            
            for node_data in graph_data.get("nodes", []):
                node_id = node_data.get("id", "")
                label = node_data.get("label", node_id)
                origin = node_data.get("file", "") or node_data.get("module", "")
                
                node_type = "normal"
                
                # Determine status
                is_a = driver_a_name and driver_a_name in origin
                is_b = driver_b_name and driver_b_name in origin
                
                # Check if ID (often address) is in matched sets
                # Extract address from ID if possible, or use ID itself
                # Assuming ID is unique, often function name or address
                
                # Fallback: Check if "status" is pre-calc
                if "status" in node_data:
                    status = node_data["status"]
                    if status == "baseline": node_type = "removed"
                    elif status == "current": node_type = "added"
                    elif status == "modified": node_type = "modified"
                    else: node_type = "unchanged"
                else:
                    # Heuristic inference
                    if is_a:
                        # If ID or label implies it's matched, use unchanged
                        # This is weak, but better than nothing
                        node_type = "removed" # Default for A
                    elif is_b:
                        node_type = "added" # Default for B
                    
                self.graph_view.add_node(node_id, label, node_type, (0, 0))
            
            for edge_data in graph_data.get("edges", []):
                self.graph_view.add_edge(
                    edge_data.get("source", ""),
                    edge_data.get("target", ""),
                    edge_data.get("label", ""),
                    edge_data.get("type", "direct")
                )
            
            self.graph_view.auto_layout()
            self.graph_view.fitInView(self.graph_view.scene.sceneRect(), Qt.AspectRatioMode.KeepAspectRatio)
            self.log_message(f"📊 View: Unified Diff ({len(graph_data.get('nodes', []))} nodes processed)")

    def toggle_graph_overlay(self):
        """Toggle between side-by-side and overlay view modes"""
        if not hasattr(self, 'graph_view') or not hasattr(self, 'current_results'):
            return
            
        # Toggle internal mode flag
        if not hasattr(self, '_graph_overlay_mode'):
            self._graph_overlay_mode = False
        
        self._graph_overlay_mode = not self._graph_overlay_mode
        
        # Reload graph with new layout
        if self.current_results and "graph" in self.current_results:
            graph_data = self.current_results["graph"]
            
            if self._graph_overlay_mode:
                # Overlay mode: stack graphs on top of each other
                self.graph_view.clear_graph()
                for node_data in graph_data.get("nodes", []):
                    node_id = node_data.get("id", "")
                    label = node_data.get("label", node_id)
                    node_type = node_data.get("type", "normal")
                    self.graph_view.add_node(node_id, label, node_type, (0, 0))
                
                for edge_data in graph_data.get("edges", []):
                    self.graph_view.add_edge(
                        edge_data.get("source", ""),
                        edge_data.get("target", ""),
                        edge_data.get("label", ""),
                        edge_data.get("type", "direct")
                    )
                
                # Use single unified layout
                self.graph_view.auto_layout()
                self.graph_view.fitInView(self.graph_view.scene.sceneRect(), Qt.AspectRatioMode.KeepAspectRatio)
                self.log_message("📊 Switched to Overlay view")
            else:
                # Side-by-side mode
                self.graph_view.load_graph_data(graph_data)
                self.log_message("📊 Switched to Side-by-Side view")

    def on_graph_node_selected(self, node_id: str):
        """Handle graph node selection"""
        # Parse the node ID to extract function info
        # Format: "A_0x140001000" or "B_0x140001000"
        if node_id.startswith("A_"):
            graph_label = "Driver A (Baseline)"
            address = node_id[2:]  # Remove "A_" prefix
        elif node_id.startswith("B_"):
            graph_label = "Driver B (Target)"
            address = node_id[2:]
        else:
            graph_label = "Unknown"
            address = node_id
        
        self.status_message.setText(f"Selected: {address} from {graph_label}")

    def on_graph_node_double_clicked(self, node_id: str):
        """Handle graph node double-click - show details"""
        # Find the function in matches
        if not hasattr(self, 'current_results') or not self.current_results:
            return
        
        matches = self.current_results.get("matches", [])
        
        # Parse address from node_id
        if node_id.startswith(("A_", "B_")):
            address = node_id[2:]
        else:
            address = node_id
        
        # Find matching function
        for match in matches:
            if match.get("address", "") == address:
                # Show details in a message or panel
                details = f"Function: {match.get('function_name', 'Unknown')}\n"
                details += f"Address: {address}\n"
                details += f"Role: {match.get('role', 'unknown')}\n"
                details += f"Risk: {match.get('risk', 'low')}"
                
                QMessageBox.information(self, "Function Details", details)
                return
        
        # If not found in matches, just show the address
        QMessageBox.information(self, "Node Selected", f"Address: {address}")

    def on_progress_updated(self, progress_or_stage, message):
        """Handle progress updates - supports both (int, str) and (str, str) formats"""
        if isinstance(progress_or_stage, int):
            # Numeric progress format from AnalysisWorker (0-100)
            self.analysis_progress_bar.setRange(0, 100)
            self.analysis_progress_bar.setValue(progress_or_stage)
            self.current_stage_label.setText(message)
        else:
            # String stage format (legacy)
            if progress_or_stage == "starting":
                self.analysis_progress_bar.setRange(0, 0)  # Indeterminate mode
                self.current_stage_label.setText("Initializing...")
            elif progress_or_stage == "finished":
                self.analysis_progress_bar.setRange(0, 100)  # Normal mode
                self.analysis_progress_bar.setValue(100)
                self.current_stage_label.setText("Analysis Complete")
        self.status_message.setText(message)

    def on_analysis_finished(self, report):
        """Handle analysis completion with new report structure"""
        self.current_results = report
        
        # Display summary text
        summary_text = self.format_analysis_summary(report)
        self.results_text.setText(summary_text)

        # Load graph data
        if "graph" in report:
            self.load_graph_from_report(report["graph"])

        # Load function comparison data
        if "matches" in report:
            self.load_function_comparison_data(report["matches"])

        # Load security insights
        if "security_insights" in report:
            self.load_security_insights(report["security_insights"])
        
        # Pass data to PoC Generator
        if hasattr(self, 'poc_result_widget'):
            # Set binary path (prefer baseline driver A)
            if hasattr(self, 'driver_a_path') and self.driver_a_path:
                self.poc_result_widget.set_binary_path(self.driver_a_path)
            # Set graph for symbolic execution - use graph_a (baseline)
            if "graph_a" in report:
                self.poc_result_widget.set_graph(report.get("graph_a"))
            elif "graph" in report:
                self.poc_result_widget.set_graph(report.get("graph"))
            
        # Update Dashboard
        self.update_dashboard_metrics(report)

    def update_dashboard_metrics(self, report):
        """Update dashboard metric cards with analysis results"""
        if not hasattr(self, 'metric_labels'):
            return
            
        # 1. Functions Analyzed
        graph = report.get("graph", {})
        nodes = graph.get("nodes", [])
        if self.metric_labels.get("functions"):
            self.metric_labels["functions"].setText(str(len(nodes)))
        
        # 2. Similarities Found
        matches = report.get("matches", [])
        if self.metric_labels.get("similarities"):
            self.metric_labels["similarities"].setText(str(len(matches)))
        
        # 3. Risk Candidates
        security = report.get("security_insights", [])
        risk_count = len([s for s in security if isinstance(s, dict) and s.get("risk_score", 0) > 50])
        if self.metric_labels.get("risks"):
            self.metric_labels["risks"].setText(str(risk_count))
        
        # 4. Analysis Time
        duration = report.get("metadata", {}).get("analysis_duration", "N/A")
        if self.metric_labels.get("time"):
            if isinstance(duration, (int, float)):
                 self.metric_labels["time"].setText(f"{duration:.2f}s")
            else:
                 self.metric_labels["time"].setText(str(duration))

        # 5. Update Similarity Chart
        if hasattr(self, 'similarity_chart'):
            matches = report.get("matches", [])
            total_nodes_a = report.get("summary", {}).get("total_nodes_a", 0)
            
            match_c = 0
            partial_c = 0
            
            for m in matches:
                sim = m.get('similarity', 0.0)
                if sim >= 0.85:
                    match_c += 1
                else: 
                    partial_c += 1
            
            # "No Match" are functions in Baseline that weren't matched
            no_match_c = max(0, total_nodes_a - (match_c + partial_c))
            
            self.similarity_chart.set_data({
                "Match": match_c,
                "Partial": partial_c,
                "No Match": no_match_c
            })

        # 6. Update Metadata Widget
        if hasattr(self, 'metadata_widget'):
            summary = report.get("summary", {})
            import os
            meta_a = {
                "file_size": f"{summary.get('size_a', 0) / 1024:.1f} KB" if summary.get('size_a') else "N/A",
                "arch": summary.get("arch_a", "x64"),
                "entry_point": hex(summary.get("entry_a", 0)) if summary.get("entry_a") else "N/A",
                "func_count": summary.get("total_nodes_a", 0),
                "edge_count": summary.get("total_edges_a", 0)
            }
            meta_b = {
                "file_size": f"{summary.get('size_b', 0) / 1024:.1f} KB" if summary.get('size_b') else "N/A",
                "arch": summary.get("arch_b", "x64"),
                "entry_point": hex(summary.get("entry_b", 0)) if summary.get("entry_b") else "N/A",
                "func_count": summary.get("total_nodes_b", 0),
                "edge_count": summary.get("total_edges_b", 0)
            }
            self.metadata_widget.set_metadata(meta_a, meta_b)

        # Add to recent analyses
        self.add_to_recent_analyses()

        # Update UI state
        self.analyze_btn.setEnabled(True)
        self.cancel_btn.setEnabled(False)
        self.save_btn.setEnabled(True)
        
        # Determine overall status from insights if available
        status_msg = "✅ Analysis completed successfully"
        if "security_insights" in report:
            risk_level = report["security_insights"].get("overall_risk", "LOW")
            status_msg = f"✅ Analysis complete - Risk Level: {risk_level}"
            
        self.status_message.setText(status_msg)
        self.progress_status_label.setText("Done")

    def format_analysis_summary(self, report):
        """Format analysis report as text for the raw results view"""
        summary = report.get("summary", {})
        text = f"ANALYSIS REPORT\n"
        text += f"===============\n"
        text += f"Timestamp: {summary.get('timestamp', 'N/A')}\n"
        text += f"Overall Similarity: {summary.get('overall_similarity', 0):.2f}\n"
        text += f"Nodes in Baseline: {summary.get('total_nodes_a', 0)}\n"
        text += f"Nodes in Target: {summary.get('total_nodes_b', 0)}\n\n"
        
        if "security_insights" in report:
            insights = report["security_insights"]
            text += f"SECURITY INSIGHTS\n"
            text += f"-----------------\n"
            text += f"Risk Level: {insights.get('overall_risk', 'UNKNOWN')}\n"
            # Add more details as needed
            
        return text

    def load_graph_from_report(self, graph_data):
        """Load graph data from analysis report"""
        if graph_data and hasattr(self, 'graph_view'):
            # The report format matches what the widget expects (nodes list, edges list)
            self.graph_view.load_graph_data(graph_data)
            self.main_tab_widget.setCurrentIndex(1)  # Switch to graph tab

    def load_function_comparison_data(self, matches):
        """Load function comparison data from analysis report"""
        if matches and hasattr(self, 'function_comparison_table'):
            self.function_comparison_table.load_comparison_data(matches)
            if matches:
                # Update stats summary
                 self.stats_summary.setText(f"Found {len(matches)} function matches")


    def load_security_insights(self, insights):
        """Load security insights data"""
        if hasattr(self, 'security_insights_widget'):
            self.security_insights_widget.update_insights(insights)
            # Optional: Automatic tab switch or notification



    def show_recent_analyses(self):
        """Show menu with recent analysis pairs"""
        from PyQt6.QtCore import QSettings
        settings = QSettings("LogicFlowAnalysis", "RecentAnalyses")

        recent_str = settings.value("recent_pairs", "")
        if not recent_str:
            QMessageBox.information(self, "Recent Analyses", "No recent analyses found")
            return

        recent_pairs = [pair for pair in recent_str.split("|||") if pair]

        if not recent_pairs:
            QMessageBox.information(self, "Recent Analyses", "No recent analyses found")
            return

        # Create menu
        menu = QMenu(self)

        for pair_str in recent_pairs:
            try:
                driver_a, driver_b = pair_str.split("|", 1)
                driver_a_name = driver_a.split("\\")[-1].split("/")[-1]
                driver_b_name = driver_b.split("\\")[-1].split("/")[-1]

                action_text = f"{driver_a_name} vs {driver_b_name}"
                action = menu.addAction(action_text)
                action.setData((driver_a, driver_b))
            except ValueError:
                continue

        # Show menu at cursor position
        if menu.actions():
            selected_action = menu.exec(QCursor.pos())

            if selected_action:
                driver_a, driver_b = selected_action.data()
                self.driver_a_path = driver_a
                self.driver_b_path = driver_b
                self.update_driver_a_card(driver_a)
                self.update_driver_b_card(driver_b)
                self.update_analysis_button_state()

    def on_analysis_error(self, error_msg):
        """Handle analysis errors"""
        logger.error(f"Analysis failed: {error_msg}")
        
        # Re-enable UI
        self.analyze_btn.setEnabled(True)
        if hasattr(self, 'save_btn'):
            self.save_btn.setEnabled(False)
        if hasattr(self, 'cancel_btn'):
            self.cancel_btn.setEnabled(False)
        
        # Update UI with error
        self.current_stage_label.setText("Analysis Failed")
        self.status_message.setText(f"❌ Error: {error_msg}")
        
        # Show error dialog
        QMessageBox.critical(self, "Analysis Error", f"Analysis failed:\n\n{error_msg}")

    def display_results(self, results, report):
        """Display analysis results"""
        self.results_text.clear()

        if "error" in results:
            self.log_message(f"Analysis Error: {results['error']}")
            return

        self.log_message("=== LOGIC FLOW ANALYSIS RESULTS ===")
        self.log_message(f"Anchor Function: {hex(results.get('anchor_function', 0))}")

        # Display debug context if available
        debug_context = results.get("debug_context", {})
        if debug_context:
            self.log_message("Debug Context:")
            for key, value in debug_context.items():
                if key != "captured_at":
                    self.log_message(f"  {key}: {value}")
            self.log_message("")

        # Display analysis summary
        summary = results.get('analysis_summary', {})
        if summary.get('key_findings'):
            self.log_message("Key Findings:")
            for finding in summary['key_findings']:
                self.log_message(f"  • {finding}")
            self.log_message("")

        if summary.get('manual_review_points'):
            self.log_message("Manual Review Points:")
            for point in summary['manual_review_points']:
                self.log_message(f"  • {point}")
            self.log_message("")

        # Display scoring statistics if available
        scoring_stats = summary.get('scoring_stats', {})
        if scoring_stats:
            self.log_message("Scoring Statistics:")
            self.log_message(f"  Highest Score: {scoring_stats.get('highest_score', 'N/A')}")
            self.log_message(f"  Average Score: {scoring_stats.get('average_score', 'N/A'):.1f}")
            self.log_message(f"  Score Range: {scoring_stats.get('score_range', 'N/A')}")
            candidates_high = scoring_stats.get('candidates_with_high_scores', 0)
            if candidates_high > 0:
                self.log_message(f"  High-Confidence Candidates: {candidates_high}")
            self.log_message("")

        # Handle new comparison format
        comparison_results = results.get("comparison_results", [])
        if comparison_results:
            self.log_message(f"Analyzed {len(comparison_results)} candidate functions")

            for i, comp_result in enumerate(comparison_results, 1):
                candidate_addr = comp_result.get("candidate_address", "unknown")
                candidate_name = comp_result.get("candidate_name", "unknown")
                score = comp_result.get("score", 0)

                self.log_message(f"\nCandidate {i}: {candidate_name} at {candidate_addr} (Score: {score})")

                # Display scoring details
                scoring_details = comp_result.get("scoring_details", {})
                if scoring_details.get("semantic_role_match"):
                    self.log_message(f"  🎯 Role Match: +{scoring_details['semantic_role_match']} points")
                if scoring_details.get("failfast_alignment") == 4:
                    self.log_message("  🛡️ FailFast: Perfect alignment")
                if scoring_details.get("complete_alignment") == 3:
                    self.log_message("  📋 Completion: Perfect alignment")

                # Display comparison data
                comparison = comp_result.get("comparison", {})
                struct_sim = comparison.get("structural_similarity", {})
                node_diff = struct_sim.get("node_count_diff", 0)
                if node_diff != 0:
                    self.log_message(f"  📊 Structure: {node_diff} node difference")

                hints = comparison.get("manual_analysis_hints", [])
                if hints:
                    self.log_message("  💡 Analysis hints:")
                    for hint in hints[:2]:
                        self.log_message(f"     • {hint}")
        else:
            # Fallback for old format
            comparisons = results.get("comparisons", {})
            self.log_message(f"Analyzed {len(comparisons)} candidate functions")

            for i, (candidate_addr, comparison) in enumerate(comparisons.items(), 1):
                self.log_message(f"\nCandidate {i}: {hex(candidate_addr)}")

                struct = comparison.get("structural_similarity", {})
                self.log_message(f"  📊 Node count diff: {struct.get('node_count_similarity', 'N/A')}")

                hints = comparison.get("manual_analysis_hints", [])
                if hints:
                    self.log_message("  💡 Analysis hints:")
                    for hint in hints[:2]:
                        self.log_message(f"     • {hint}")

        # Display Security Insights (new feature)
        self._display_security_insights(results)

    def _display_security_insights(self, results):
        """Display security insights for research and PoC development"""
        security_insights = results.get("security_insights", {})
        if not security_insights:
            return

        self.log_message("\n" + "="*60)
        self.log_message("🔒 SECURITY RESEARCH INSIGHTS")
        self.log_message("="*60)

        # Overall risk assessment
        risk_assessment = security_insights.get("risk_assessment", {})
        overall_risk = risk_assessment.get("overall_risk", "UNKNOWN")
        self.log_message(f"🎯 Overall Risk Level: {overall_risk}")
        self.log_message(f"   Critical Functions: {risk_assessment.get('critical_functions', 0)}")
        self.log_message(f"   Exposed Attack Surface: {risk_assessment.get('exposed_attack_surface', 0)}")
        self.log_message("")

        # High Priority Targets
        high_priority_targets = security_insights.get("high_priority_targets", [])
        if high_priority_targets:
            self.log_message("🎯 HIGH PRIORITY TARGETS (IOCTL Reachable + Security Changes):")
            for target in high_priority_targets[:5]:  # Limit to top 5
                self.log_message(f"   🚨 {target['name']} (0x{target['address']:08X})")
                self.log_message(f"      Risk: {target['risk_level']} | Change: {target['change_type']}")
                ioctl_codes = target.get('ioctl_codes', [])
                if ioctl_codes:
                    self.log_message(f"      IOCTL: {', '.join(ioctl_codes)}")
                self.log_message(f"      Exploit Potential: {target.get('exploit_potential', 'Unknown')}")
            self.log_message("")

        # Vulnerability Candidates
        vuln_candidates = security_insights.get("vulnerability_candidates", [])
        if vuln_candidates:
            self.log_message("💀 VULNERABILITY CANDIDATES:")
            for candidate in vuln_candidates[:3]:  # Limit to top 3
                self.log_message(f"   • {candidate['description']}")
                self.log_message(f"     Vector: {candidate.get('exploit_vector', 'Unknown')}")
            self.log_message("")

        # Security Improvements
        security_improvements = security_insights.get("security_improvements", [])
        if security_improvements:
            self.log_message("🛡️ SECURITY IMPROVEMENTS:")
            for improvement in security_improvements[:3]:  # Limit to top 3
                self.log_message(f"   ✓ {improvement['description']}")
            self.log_message("")

        # Display PoC Development Support (enhanced features)
        poc_development = results.get("poc_development", {})
        if poc_development:
            self._display_poc_development_info(poc_development)

        # Generate WinDbg script if there are high priority targets
        if high_priority_targets:
            self._generate_windbg_script_option(results)

    def _generate_windbg_script_option(self, results):
        """Offer to generate WinDbg script for dynamic analysis"""
        from PyQt6.QtWidgets import QMessageBox
        from ..core.poc_helper import PoCHelper

        reply = QMessageBox.question(
            self, 'Generate WinDbg Script',
            'High-priority security targets detected. Generate WinDbg script for dynamic analysis?',
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        )

        if reply == QMessageBox.StandardButton.Yes:
            try:
                poc_helper = PoCHelper()
                script_path = poc_helper.generate_windbg_script(
                    results,
                    "security_analysis_windbg.js"
                )

                if script_path:
                    self.log_message(f"✅ WinDbg script generated: {script_path}")
                    self.log_message("   Use: .scriptload <path_to_script>")
                else:
                    self.log_message("❌ Failed to generate WinDbg script")

            except Exception as e:
                self.log_message(f"❌ Error generating WinDbg script: {e}")

    def _display_poc_development_info(self, poc_development):
        """Display PoC development support information"""
        self.log_message("\n" + "="*60)
        self.log_message("🛠️  PoC DEVELOPMENT SUPPORT")
        self.log_message("="*60)

        # WinDbg Script
        script_path = poc_development.get("windbg_script_path")
        if script_path:
            self.log_message("📜 WinDbg Script Generated:")
            self.log_message(f"   Path: {script_path}")
            self.log_message("   Usage: .scriptload <path_to_script>")
            self.log_message("   Features: Automated breakpoints, data flow tracing, exploit analysis")
            self.log_message("")

        # High Priority Targets for PoC
        high_priority_targets = poc_development.get("high_priority_targets", [])
        if high_priority_targets:
            self.log_message("🎯 CRITICAL TARGETS FOR PoC DEVELOPMENT:")
            for i, target in enumerate(high_priority_targets[:3], 1):  # Top 3
                self.log_message(f"   {i}. {target['function_name']} (0x{target['address']:08X})")
                if target.get('ioctl_codes'):
                    self.log_message(f"      IOCTL Codes: {', '.join(target['ioctl_codes'])}")
                self.log_message(f"      Exploit Potential: {target.get('exploit_potential', 'Unknown')}")
                self.log_message(f"      Description: {target.get('description', '')}")
                self.log_message("")

        # Attack Vector Analysis
        attack_vectors = poc_development.get("attack_vector_analysis", {})
        if attack_vectors:
            self.log_message("⚔️  ATTACK VECTOR ANALYSIS:")

            # IOCTL-based attacks
            ioctl_attacks = attack_vectors.get("ioctl_based_attacks", [])
            if ioctl_attacks:
                self.log_message("   🔌 IOCTL-Based Attack Vectors:")
                for attack in ioctl_attacks[:2]:  # Top 2
                    self.log_message(f"      • {attack['type']}: {attack['description']}")
                    self.log_message(f"        Complexity: {attack['exploit_complexity']}")

            # Memory corruption opportunities
            mem_corruption = attack_vectors.get("memory_corruption_opportunities", [])
            if mem_corruption:
                self.log_message("   💥 Memory Corruption Opportunities:")
                for vuln in mem_corruption:
                    self.log_message(f"      • {vuln['function']}: Exposure increased by {vuln['exposure_increase']}")
                    self.log_message(f"        Complexity: {vuln['exploit_complexity']}")

            # Privilege escalation paths
            priv_esc = attack_vectors.get("privilege_escalation_paths", [])
            if priv_esc:
                self.log_message("   👑 Privilege Escalation Paths:")
                for path in priv_esc:
                    self.log_message(f"      • {path['type']}: {path['description']}")
                    self.log_message(f"        Complexity: {path['exploit_complexity']}")

            self.log_message("")

        # Exploit Templates
        exploit_templates = poc_development.get("exploit_templates", [])
        if exploit_templates:
            self.log_message("📝 EXPLOIT TEMPLATES GENERATED:")
            for template in exploit_templates:
                self.log_message(f"   Language: {template.get('language', 'Unknown')}")
                self.log_message(f"   Description: {template.get('description', '')}")
                self.log_message("   Template saved with analysis results")
            self.log_message("")

        # Error handling
        if "error" in poc_development:
            self.log_message(f"⚠️  PoC Development Error: {poc_development['error']}")
            self.log_message("")

    def log_message(self, message):
        """Log message to results text area"""
        timestamp = datetime.now().strftime('%H:%M:%S')
        formatted_message = f"{timestamp} - {message}"

        # Process message immediately
        self.results_text.append(formatted_message + '\n')

        # Smart auto-scroll
        if self.results_text.isVisible():
            scrollbar = self.results_text.verticalScrollBar()
            if scrollbar:
                scrollbar.setValue(scrollbar.maximum())

    def save_results(self):
        """Save analysis results in multiple formats"""
        if not self.current_results:
            QMessageBox.information(self, "Info", "No results to save")
            return

        # Get save directory
        save_dir = QFileDialog.getExistingDirectory(self, "Select Save Directory")
        if not save_dir:
            return

        try:
            # Import the save function
            from ..core.diff_reflecting import save_comparison_results

            # Prepare complete results for saving
            complete_results = {
                "timestamp": datetime.now().isoformat(),
                "driver_a": self.driver_a_path,
                "driver_b": self.driver_b_path,
                "analysis_type": "logic_flow_analysis",
                "debug_context": self.debug_context,
                "results": self.current_results['results'],
                "analysis_report": self.current_results['report'],
                "analysis_metadata": {
                    "tool_version": "3.0",
                    "logic_graph_modeling": True,
                    "semantic_flow_analysis": True,
                    "crash_traceability": True,
                    "manual_analysis_support": True,
                    "no_automated_verdicts": True
                }
            }

            # Save in multiple formats
            saved_files = save_comparison_results(complete_results, save_dir)

            # Show success message
            success_msg = "Analysis results saved successfully:\n\n"
            for format_name, file_path in saved_files.items():
                success_msg += f"{format_name.upper()}: {file_path}\n"

            QMessageBox.information(
                self, "Success", success_msg
            )

        except Exception as e:
            QMessageBox.critical(
                self, "Error",
                f"Failed to save results: {str(e)}"
            )

    def save_baseline(self):
        """Save current analysis as baseline signature"""
        if not self.current_results or 'graph_a' not in self.current_results.get('results', {}):
            QMessageBox.information(self, "Info", "No analysis results to save as baseline")
            return

        # Get baseline name from user
        from PyQt6.QtWidgets import QInputDialog
        driver_name = os.path.basename(self.driver_a_path or "unknown_driver")
        default_name = f"Baseline_{driver_name}"

        name, ok = QInputDialog.getText(
            self, "Save Baseline",
            "Enter baseline name:",
            text=default_name
        )

        if not ok or not name.strip():
            return

        try:
            # Extract graph from results
            graph_data = self.current_results['results']['graph_a']
            if isinstance(graph_data, dict):
                from ..core.logic_graph import LogicGraph
                graph = LogicGraph.from_dict(graph_data)
            else:
                graph = graph_data

            # Save baseline
            filepath = self.baseline_manager.save_baseline(
                name=name.strip(),
                driver_path=self.driver_a_path,
                graph=graph,
                metadata={
                    "analysis_timestamp": self.current_results.get('timestamp'),
                    "tool_version": "3.0"
                }
            )

            QMessageBox.information(
                self, "Success",
                f"Baseline signature saved successfully:\n\nName: {name}\nFile: {filepath}"
            )

        except Exception as e:
            QMessageBox.critical(
                self, "Error",
                f"Failed to save baseline: {str(e)}"
            )

    def load_baseline(self):
        """Load a baseline signature"""
        baselines = self.baseline_manager.list_baselines()

        if not baselines:
            QMessageBox.information(self, "Info", "No baseline signatures available")
            return

        # Create menu with available baselines
        from PyQt6.QtWidgets import QMenu
        menu = QMenu(self)

        for baseline in baselines:
            action_text = f"{baseline['name']} - {baseline['driver_path']}"
            action = menu.addAction(action_text)
            action.setData(baseline['signature_id'])

        # Show menu
        selected_action = menu.exec(self.load_baseline_btn.mapToGlobal(
            self.load_baseline_btn.rect().bottomLeft()
        ))

        if selected_action:
            signature_id = selected_action.data()

            try:
                signature = self.baseline_manager.load_baseline(signature_id)
                if signature:
                    # Set driver A path and show success
                    self.driver_a_path = signature.driver_path
                    self.update_driver_a_card(signature.driver_path)
                    self.update_analysis_button_state()

                    QMessageBox.information(
                        self, "Success",
                        f"Baseline loaded successfully:\n\nName: {signature.name}\nDriver: {signature.driver_path}"
                    )
                else:
                    QMessageBox.warning(self, "Error", "Failed to load baseline signature")

            except Exception as e:
                QMessageBox.critical(
                    self, "Error",
                    f"Failed to load baseline: {str(e)}"
                )

    def show_batch_analysis(self):
        """Show batch analysis dialog"""
        dialog = BatchAnalysisDialog(self.baseline_manager, self)
        dialog.analysis_requested.connect(self.run_batch_analysis)
        dialog.exec()

    def run_batch_analysis(self, target_files, output_dir, baseline_name):
        """Run batch analysis on multiple target files"""
        from ..core.batch_analyzer import BatchAnalyzer
        from datetime import datetime

        try:
            self.log_message(f"\n{'='*60}")
            self.log_message("🔄 STARTING BATCH ANALYSIS")
            self.log_message(f"{'='*60}")
            self.log_message(f"Baseline: {baseline_name}")
            self.log_message(f"Target files: {len(target_files)}")
            self.log_message(f"Output directory: {output_dir}")
            self.log_message("")

            # Create batch analyzer
            batch_analyzer = BatchAnalyzer(self.baseline_manager, self.config_manager)

            # Start batch analysis
            self.progress_bar.setValue(0)
            self.progress_status_label.setText("Starting batch analysis...")
            self.status_label.setText("🔄 Running batch analysis...")

            # Run in background thread
            self.batch_worker = BatchAnalysisWorker(
                batch_analyzer, target_files, output_dir, baseline_name
            )
            self.batch_worker.progress_updated.connect(self.update_batch_progress)
            self.batch_worker.batch_finished.connect(self.on_batch_finished)
            self.batch_worker.error_occurred.connect(self.on_batch_error)
            self.batch_worker.start()

        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to start batch analysis: {str(e)}")

    def update_batch_progress(self, current, total, driver_name, status):
        """Update batch analysis progress"""
        percentage = int((current / total) * 100) if total > 0 else 0
        self.progress_bar.setValue(percentage)
        self.progress_status_label.setText(f"Analyzing {driver_name}: {status}")
        self.status_label.setText(f"🔄 Batch analysis: {current}/{total} completed")

    def on_batch_finished(self, results_summary):
        """Handle batch analysis completion"""
        self.progress_bar.setValue(100)
        self.progress_status_label.setText("Batch analysis completed")
        self.status_label.setText("✅ Batch analysis completed successfully")

        # Display summary
        self.log_message(f"\n{'='*60}")
        self.log_message("✅ BATCH ANALYSIS COMPLETED")
        self.log_message(f"{'='*60}")
        self.log_message(f"Total comparisons: {results_summary['total_comparisons']}")
        self.log_message(f"Successful: {results_summary['successful']}")
        self.log_message(f"Failed: {results_summary['failed']}")
        self.log_message(f"Output directory: {results_summary['output_dir']}")

        if results_summary['high_similarity_drivers']:
            self.log_message(f"\n🔍 High similarity drivers (>8.0 score):")
            for driver_info in results_summary['high_similarity_drivers'][:5]:
                self.log_message(f"  • {driver_info['name']}: {driver_info['score']:.1f}")

        QMessageBox.information(
            self, "Batch Analysis Complete",
            f"Batch analysis completed successfully!\n\n"
            f"Results saved to: {results_summary['output_dir']}\n"
            f"Successful comparisons: {results_summary['successful']}\n"
            f"Failed comparisons: {results_summary['failed']}"
        )

    def on_batch_error(self, error_msg):
        """Handle batch analysis error"""
        self.status_label.setText("❌ Batch analysis failed")
        QMessageBox.critical(self, "Batch Analysis Error", error_msg)

    def clear_debug_context(self):
        """Clear all debug context fields"""
        self.exception_edit.clear()
        self.irql_edit.clear()
        self.status_edit.clear()
        self.crash_addr_edit.clear()
        self.callstack_edit.clear()
        self.notes_edit.clear()
        self.log_message("Debug context cleared")

    def load_debug_context(self):
        """Load debug context from file"""
        file_path, _ = QFileDialog.getOpenFileName(
            self, "Load Debug Context", "", "JSON files (*.json);;All files (*.*)"
        )

        if file_path:
            try:
                with open(file_path, 'r') as f:
                    context = json.load(f)

                # Populate UI fields
                self.exception_edit.setText(context.get("exception_type", ""))
                self.irql_edit.setText(str(context.get("irql_level", "")))
                self.status_edit.setText(context.get("status_code", ""))
                self.crash_addr_edit.setText(context.get("crash_address", ""))
                self.callstack_edit.setText(", ".join(context.get("call_stack", [])))
                self.notes_edit.setPlainText(context.get("notes", ""))

                self.log_message(f"Debug context loaded from {file_path}")

            except Exception as e:
                QMessageBox.critical(
                    self, "Error",
                    f"Failed to load debug context: {str(e)}"
                )

    def show_color_picker(self):
        """Show the color picker dialog for edge customization."""
        # Get current colors from graph view if available
        current_colors = None
        if hasattr(self, 'graph_view') and hasattr(self.graph_view, 'edge_colors'):
            current_colors = self.graph_view.edge_colors
        
        dialog = ColorPickerDialog(current_colors, self)
        dialog.colors_changed.connect(self.on_colors_changed)
        dialog.exec()
    
    def on_colors_changed(self, new_colors):
        """Apply new edge colors to the graph visualization."""
        if hasattr(self, 'graph_view'):
            self.graph_view.edge_colors = new_colors
            # Refresh graph to apply changes
            if hasattr(self, 'current_results') and self.current_results and "graph" in self.current_results:
                self.graph_view.load_graph_data(self.current_results["graph"])
        self.log_message(f"🎨 Applied new edge colors: {new_colors}")
