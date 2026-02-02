"""
Qt Optimization and Helper Utilities
Provides utilities for optimizing PyQt6 performance and modern theming.
"""

import os
import traceback
import sys
from PyQt6.QtWidgets import QApplication, QWidget, QScrollArea, QTextEdit, QToolTip
from PyQt6.QtCore import QTimer, Qt, QRunnable, pyqtSlot, QObject, pyqtSignal
from PyQt6.QtGui import QFont, QPalette, QColor


def create_font(family="Segoe UI", size=9, weight=None):
    """Create optimized font"""
    font = QFont(family, size)
    if weight:
        font.setWeight(weight)
    # Optimize font rendering
    font.setStyleHint(QFont.StyleHint.System, QFont.StyleStrategy.PreferAntialias)
    return font


def setup_qt_environment():
    """Setup optimized Qt environment before QApplication creation"""
    os.environ.setdefault('QT_QPA_PLATFORM', 'windows:darkmode=1')
    os.environ.setdefault('QT_AUTO_SCREEN_SCALE_FACTOR', '1')
    os.environ.setdefault('QT_LOGGING_RULES', 'qt.qpa.plugin=false')


def get_theme_colors(dark_mode=True):
    """Get color palette for the specified theme"""
    if dark_mode:
        return {
            'bg_primary': '#0D1117',
            'bg_secondary': '#161B22',
            'bg_tertiary': '#1C2128',
            'bg_elevated': '#21262D',
            'surface_default': '#161B22',
            'surface_hover': '#1C2128',
            'surface_active': '#21262D',
            'surface_border': '#30363D',
            'text_primary': '#E6EDF3',
            'text_secondary': '#8B949E',
            'text_tertiary': '#6E7681',
            'text_link': '#58A6FF',
            'text_success': '#3FB950',
            'text_warning': '#D29922',
            'text_error': '#F85149',
            'text_info': '#58A6FF',
            'accent_primary': '#1F6FEB',
            'accent_primary_hover': '#388BFD',
            'accent_secondary': '#238636',
            'accent_tertiary': '#DA3633',
            'graph_nodes_entry': '#3FB950',
            'graph_nodes_exit': '#F85149',
            'graph_nodes_decision': '#D29922',
            'graph_nodes_call': '#58A6FF',
            'graph_nodes_normal': '#8B949E',
            'graph_nodes_highlight': '#A371F7'
        }
    else:  # Light theme
        return {
            'bg_primary': '#FFFFFF',
            'bg_secondary': '#F6F8FA',
            'bg_tertiary': '#EFF1F3',
            'bg_elevated': '#FFFFFF',
            'surface_default': '#FFFFFF',
            'surface_hover': '#F6F8FA',
            'surface_active': '#EFF1F3',
            'surface_border': '#D0D7DE',
            'text_primary': '#1F2328',
            'text_secondary': '#656D76',
            'text_tertiary': '#8C959F',
            'text_link': '#0969DA',
            'text_success': '#1A7F37',
            'text_warning': '#9A6700',
            'text_error': '#CF222E',
            'text_info': '#0969DA',
            'accent_primary': '#0969DA',
            'accent_primary_hover': '#0550AE',
            'accent_secondary': '#1A7F37',
            'accent_tertiary': '#CF222E',
            'graph_nodes_entry': '#1A7F37',
            'graph_nodes_exit': '#CF222E',
            'graph_nodes_decision': '#9A6700',
            'graph_nodes_call': '#0969DA',
            'graph_nodes_normal': '#656D76',
            'graph_nodes_highlight': '#8250DF'
        }

def apply_modern_dark_theme(app: QApplication):
    """Apply a modern VS Code-inspired dark theme based on the design system"""
    apply_theme(app, dark_mode=True)

def apply_theme(app: QApplication, dark_mode=True):
    """Apply theme (dark or light) based on the design system"""
    app.setStyle("Fusion")

    # Get color palette for the specified theme
    colors = get_theme_colors(dark_mode)

    # Set up palette for better system integration and defaults
    palette = QPalette()
    palette.setColor(QPalette.ColorRole.Window, QColor(colors['bg_primary']))
    palette.setColor(QPalette.ColorRole.WindowText, QColor(colors['text_primary']))
    palette.setColor(QPalette.ColorRole.Base, QColor(colors['bg_secondary']))
    palette.setColor(QPalette.ColorRole.AlternateBase, QColor(colors['bg_tertiary']))
    palette.setColor(QPalette.ColorRole.ToolTipBase, QColor(colors['bg_secondary']))
    palette.setColor(QPalette.ColorRole.ToolTipText, QColor(colors['text_primary']))
    palette.setColor(QPalette.ColorRole.Text, QColor(colors['text_primary']))
    palette.setColor(QPalette.ColorRole.Button, QColor(colors['surface_default']))
    palette.setColor(QPalette.ColorRole.ButtonText, QColor(colors['text_primary']))
    palette.setColor(QPalette.ColorRole.BrightText, Qt.GlobalColor.red)
    palette.setColor(QPalette.ColorRole.Link, QColor(colors['text_link']))
    palette.setColor(QPalette.ColorRole.Highlight, QColor(colors['accent_primary']))
    palette.setColor(QPalette.ColorRole.HighlightedText, QColor('white'))
    app.setPalette(palette)

    # Global Font
    # Using 'Segoe UI' for Windows, as specified in the design system primary font family
    font_family_primary = "'Segoe UI', 'Noto Sans', Helvetica, Arial, sans-serif"
    font_family_monospace = "'Cascadia Code', 'JetBrains Mono', 'Fira Code', 'Consolas', monospace"
    font_size_body = "13px"
    font_size_caption = "12px"
    font_size_title = "16px"
    font_weight_semibold = "600"
    font_weight_bold = "700"
    font_weight_regular = "400"

    # Set global font for the application
    app_font = QFont("Segoe UI", 10) # Base font size can be adjusted
    app_font.setStyleHint(QFont.StyleHint.System, QFont.StyleStrategy.PreferAntialias)
    app.setFont(app_font)

    # Comprehensive QSS Stylesheet based on Design System
    app.setStyleSheet(f"""
        /* Global Settings */
        * {{
            font-family: {font_family_primary};
            font-size: {font_size_body};
            color: {colors['text_primary']};
        }}

        QMainWindow, QDialog {{
            background-color: {colors['bg_primary']};
        }}

        QWidget {{
            background-color: transparent;
        }}

        QToolTip {{
            background-color: {colors['surface_default']};
            color: {colors['text_primary']};
            border: 1px solid {colors['surface_border']};
            font-size: {font_size_caption};
            border-radius: 4px;
            padding: 4px 8px;
        }}

        /* --- Cards & Containers (using surface_default for background) --- */
        QFrame#modernCard {{
            background-color: {colors['surface_default']};
            border: 1px solid {colors['surface_border']};
            border-radius: 8px; /* medium border radius */
        }}
        
        QFrame#modernCard QLabel#cardTitle {{
            font-size: {font_size_title};
            font-weight: {font_weight_bold};
            color: {colors['text_primary']};
        }}
        
        QFrame#modernCard QLabel#subtitle {{
            font-size: {font_size_body};
            color: {colors['text_secondary']};
        }}

        /* --- Buttons --- */
        QPushButton {{
            background-color: {colors['surface_default']};
            border: 1px solid {colors['surface_border']};
            border-radius: 4px; /* small border radius */
            padding: 6px 16px;
            font-weight: {font_weight_semibold};
            font-size: {font_size_body};
            min-height: 32px; /* Standard button height */
            color: {colors['text_primary']};
        }}
        QPushButton:hover {{
            background-color: {colors['surface_hover']};
            border-color: {colors['text_secondary']};
        }}
        QPushButton:pressed {{
            background-color: {colors['surface_active']};
            border-color: {colors['accent_primary']};
        }}
        QPushButton:disabled {{
            background-color: {colors['bg_tertiary']};
            color: {colors['text_tertiary']};
            border: 1px solid {colors['surface_border']};
        }}

        /* Button Variants */
        QPushButton#modernButton_primary {{
            background-color: {colors['accent_primary']};
            color: white;
            border: none;
        }}
        QPushButton#modernButton_primary:hover {{
            background-color: {colors['accent_primary_hover']};
        }}
        
        QPushButton#modernButton_secondary {{
            background-color: {colors['accent_secondary']};
            color: white;
            border: none;
        }}
        QPushButton#modernButton_secondary:hover {{
            background-color: #2BA042; /* Slightly darker green */
        }}
        
        QPushButton#modernButton_outline {{
            background-color: transparent;
            border: 1px solid {colors['surface_border']};
            color: {colors['text_primary']};
        }}
        QPushButton#modernButton_outline:hover {{
            background-color: {colors['surface_hover']};
            border-color: {colors['text_secondary']};
        }}

        QPushButton#modernButton_danger {{
            background-color: {colors['accent_tertiary']};
            color: white;
            border: none;
        }}
        QPushButton#modernButton_danger:hover {{
            background-color: #C82D2A; /* Slightly darker red */
        }}

        /* --- Inputs --- */
        QLineEdit, QTextEdit, QPlainTextEdit, QSpinBox {{
            background-color: {colors['bg_secondary']};
            border: 1px solid {colors['surface_border']};
            border-radius: 4px; /* small border radius */
            padding: 6px 8px;
            color: {colors['text_primary']};
            selection-background-color: {colors['accent_primary']};
        }}

        /* --- Combobox Specifics --- */
        QComboBox {{
            background-color: #0D1117;
            border: 1px solid #30363D;
            border-radius: 6px;
            padding: 5px 12px;
            color: #C9D1D9;
            min-height: 32px;
        }}

        QComboBox:hover {{
            border: 1px solid #8B949E;
            background-color: #161B22;
        }}

        QComboBox:focus {{
            border: 1px solid #58A6FF;
            background-color: #0D1117;
        }}

        QComboBox::drop-down {{
            subcontrol-origin: padding;
            subcontrol-position: top right;
            width: 24px;
            border-left-width: 0px;
            border-top-right-radius: 6px;
            border-bottom-right-radius: 6px;
        }}

        QComboBox::down-arrow {{
            image: none;
            border-left: 2px solid transparent;
            border-right: 2px solid transparent;
            border-top: 5px solid #8B949E;
            margin-right: 8px;
        }}

        QComboBox QAbstractItemView {{
            background-color: #161B22;
            border: 1px solid #30363D;
            border-radius: 6px;
            color: #C9D1D9;
            selection-background-color: #1F6FEB;
            selection-color: #FFFFFF;
            outline: 0;
            padding: 4px;
        }}
            selection-color: white;
            min-height: 28px; /* Consistent input height */
        }}
        QLineEdit:focus, QTextEdit:focus, QPlainTextEdit:focus, QSpinBox:focus, QComboBox:focus {{
            border: 1px solid {colors['accent_primary']};
            background-color: {colors['bg_tertiary']};
        }}
        QLineEdit:read-only {{
            background-color: {colors['bg_tertiary']};
            color: {colors['text_tertiary']};
            border: 1px dashed {colors['surface_border']};
        }}

        /* --- Group Box --- */
        QGroupBox {{
            border: 1px solid {colors['surface_border']};
            border-radius: 8px; /* medium border radius */
            margin-top: 24px;
            padding-top: 10px;
            font-weight: {font_weight_semibold};
            font-size: {font_size_title};
            color: {colors['text_primary']};
            background-color: {colors['bg_secondary']};
        }}
        QGroupBox::title {{
            subcontrol-origin: margin;
            subcontrol-position: top left;
            left: 10px;
            padding: 0 5px;
            background-color: {colors['bg_primary']}; /* Match Window BG */
            color: {colors['text_secondary']};
            font-size: {font_size_body};
            font-weight: {font_weight_semibold};
        }}

        /* --- Lists, Trees & Tables --- */
        QTreeWidget, QListWidget, QTableWidget {{
            background-color: {colors['bg_secondary']};
            border: 1px solid {colors['surface_border']};
            border-radius: 4px; /* small border radius */
            outline: none;
            color: {colors['text_primary']};
        }}
        QTreeWidget::item, QListWidget::item, QTableWidget::item {{
            padding: 4px;
            color: {colors['text_primary']};
        }}
        QTreeWidget::item:selected, QListWidget::item:selected, QTableWidget::item:selected {{
            background-color: {colors['surface_active']};
            color: white;
            border-left: 2px solid {colors['accent_primary']};
        }}
        QTreeWidget::item:hover, QListWidget::item:hover, QTableWidget::item:hover {{
            background-color: {colors['surface_hover']};
        }}
        QHeaderView::section {{
            background-color: {colors['bg_tertiary']};
            padding: 8px;
            border: none;
            border-bottom: 1px solid {colors['surface_border']};
            color: {colors['text_secondary']};
            font-weight: {font_weight_semibold};
            font-size: {font_size_caption};
        }}

        /* --- Scrollbars --- */
        QScrollBar:vertical {{
            border: none;
            background: {colors['bg_primary']};
            width: 12px;
            margin: 0px;
        }}
        QScrollBar::handle:vertical {{
            background: {colors['surface_border']};
            min-height: 20px;
            border-radius: 6px;
            margin: 2px;
        }}
        QScrollBar::handle:vertical:hover {{
            background: {colors['text_tertiary']};
        }}
        QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {{
            height: 0px;
        }}
        QScrollBar:horizontal {{
            border: none;
            background: {colors['bg_primary']};
            height: 12px;
            margin: 0px;
        }}
        QScrollBar::handle:horizontal {{
            background: {colors['surface_border']};
            min-width: 20px;
            border-radius: 6px;
            margin: 2px;
        }}
        QScrollBar::handle:horizontal:hover {{
            background: {colors['text_tertiary']};
        }}

        /* --- Status Bar --- */
        QStatusBar {{
            background-color: {colors['accent_primary']}; /* Use primary accent for status bar */
            color: white;
            border-top: 1px solid {colors['surface_border']};
            font-size: {font_size_caption};
        }}
        QStatusBar QLabel {{
            color: white;
            padding: 0 4px;
        }}
        
        /* --- Tabs --- */
        QTabWidget::pane {{
            border: 1px solid {colors['surface_border']};
            background-color: {colors['bg_secondary']};
            border-radius: 4px;
        }}

        QTabBar::tab {{
            background-color: {colors['bg_tertiary']};
            color: {colors['text_secondary']};
            border: 1px solid {colors['surface_border']};
            border-bottom: none;
            padding: 8px 16px;
            margin-right: 2px;
            border-top-left-radius: 4px;
            border-top-right-radius: 4px;
            font-weight: {font_weight_regular};
        }}

        QTabBar::tab:selected {{
            background-color: {colors['bg_secondary']};
            color: {colors['text_primary']};
            border-bottom: 2px solid {colors['accent_primary']};
            font-weight: {font_weight_semibold};
        }}

        QTabBar::tab:hover {{
            background-color: {colors['surface_hover']};
        }}

        /* --- Menus --- */
        QMenuBar {{
            background-color: {colors['bg_primary']};
            color: {colors['text_primary']};
            border-bottom: 1px solid {colors['surface_border']};
            padding: 4px;
        }}

        QMenuBar::item {{
            background-color: transparent;
            padding: 6px 12px;
            border-radius: 4px;
            color: {colors['text_primary']};
        }}

        QMenuBar::item:selected {{
            background-color: {colors['surface_hover']};
        }}

        QMenu {{
            background-color: {colors['bg_secondary']};
            border: 1px solid {colors['surface_border']};
            border-radius: 4px;
            padding: 4px;
        }}

        QMenu::item {{
            padding: 6px 20px;
            border-radius: 4px;
            color: {colors['text_primary']};
        }}

        QMenu::item:selected {{
            background-color: {colors['surface_active']};
            color: white;
        }}

        QMenu::separator {{
            height: 1px;
            background-color: {colors['surface_border']};
            margin: 4px 0;
        }}

        /* --- Progress Bar --- */
        QProgressBar {{
            border: 1px solid {colors['surface_border']};
            border-radius: 4px;
            text-align: center;
            background-color: {colors['bg_secondary']};
            color: {colors['text_primary']};
            font-size: {font_size_caption};
        }}

        QProgressBar::chunk {{
            background-color: {colors['text_success']};
            border-radius: 3px;
        }}

        /* --- Dialogs --- */
        QDialog {{
            background-color: {colors['bg_primary']};
            color: {colors['text_primary']};
            border-radius: 8px; /* medium border radius */
        }}

        /* --- ToolBar --- */
        QToolBar {{
            background-color: {colors['bg_primary']};
            border-bottom: 1px solid {colors['surface_border']};
            spacing: 4px;
            padding: 4px;
        }}

        QToolButton {{
            background-color: transparent;
            border: none;
            border-radius: 4px;
            padding: 6px;
            color: {colors['text_primary']};
        }}

        QToolButton:hover {{
            background-color: {colors['surface_hover']};
        }}

        QToolButton:pressed {{
            background-color: {colors['surface_active']};
        }}

        /* --- Splitters --- */
        QSplitter::handle {{
            background-color: {colors['surface_border']};
        }}

        QSplitter::handle:hover {{
            background-color: {colors['text_tertiary']};
        }}

        QSplitter::handle:horizontal {{
            width: 2px;
        }}

        QSplitter::handle:vertical {{
            height: 2px;
        }}

        /* --- Message Boxes --- */
        QMessageBox {{
            background-color: {colors['bg_primary']};
            color: {colors['text_primary']};
        }}

        QMessageBox QLabel {{
            color: {colors['text_primary']};
        }}

        QMessageBox QPushButton {{
            min-width: 80px;
        }}
    """
    )


def setup_application_attributes(app: QApplication):
    """Setup optimized application attributes and apply theme"""
    optimize_application(app)
    apply_modern_dark_theme(app)


def optimize_application(app: QApplication):
    """Apply performance optimizations to QApplication"""
    # Set high DPI scaling attributes (PyQt6 6.0+ only)
    if hasattr(Qt.ApplicationAttribute, 'AA_EnableHighDpiScaling'):
        app.setAttribute(Qt.ApplicationAttribute.AA_EnableHighDpiScaling, True)
    if hasattr(Qt.ApplicationAttribute, 'AA_UseHighDpiPixmaps'):
        app.setAttribute(Qt.ApplicationAttribute.AA_UseHighDpiPixmaps, True)

    # Optimize for Windows 11
    if hasattr(Qt.ApplicationAttribute, 'AA_DontCreateNativeWidgetSiblings'):
        app.setAttribute(Qt.ApplicationAttribute.AA_DontCreateNativeWidgetSiblings, True)

    # Set desktop aware settings
    if hasattr(Qt.ApplicationAttribute, 'AA_PluginApplication'):
        app.setAttribute(Qt.ApplicationAttribute.AA_PluginApplication, False)


def optimize_widget(widget: QWidget):
    """Apply performance optimizations to individual widgets"""
    # Enable optimized painting
    widget.setAttribute(Qt.WidgetAttribute.WA_OpaquePaintEvent, False)

    # Optimize focus policy
    widget.setFocusPolicy(Qt.FocusPolicy.StrongFocus)

    # Enable mouse tracking for better interaction
    widget.setMouseTracking(True)


def optimize_scroll_area(scroll_area: QScrollArea):
    """Optimize QScrollArea for better performance"""
    # Enable viewport optimization
    viewport = scroll_area.viewport()
    if viewport:
        viewport.setAttribute(Qt.WidgetAttribute.WA_OpaquePaintEvent, True)

    # Set scroll optimization
    scroll_area.setWidgetResizable(True)
    scroll_area.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAsNeeded)
    scroll_area.setVerticalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAsNeeded)


def optimize_text_edit(text_edit: QTextEdit):
    """Optimize QTextEdit for better performance"""
    # Optimize viewport
    viewport = text_edit.viewport()
    if viewport:
        viewport.setAttribute(Qt.WidgetAttribute.WA_OpaquePaintEvent, False)

    # Set update mode for better performance
    text_edit.setAutoFormatting(QTextEdit.AutoFormattingFlag.AutoNone)
    text_edit.setTabStopDistance(40)  # Standard tab width


def create_performance_timer():
    """Create a performance monitoring timer"""
    return QTimer()


def batch_widget_updates(widget: QWidget):
    """Batch widget updates for better performance"""
    widget.setUpdatesEnabled(False)
    try:
        yield widget
    finally:
        widget.setUpdatesEnabled(True)
        widget.update()


def deferred_update(widget: QWidget, delay_ms: int = 50):
    """Defer widget update to prevent excessive repaints"""
    def update():
        widget.update()

    QTimer.singleShot(delay_ms, update)


class WorkerSignals(QObject):
    """Signals for Worker class."""
    finished = pyqtSignal()
    error = pyqtSignal(tuple)
    result = pyqtSignal(object)
    progress = pyqtSignal(int)


class Worker(QRunnable):
    """
    Generic worker class for running functions in background threads using QThreadPool.

    Usage:
        worker = Worker(my_function, arg1, arg2, kwarg1=value)
        worker.signals.result.connect(my_result_handler)
        worker.signals.error.connect(my_error_handler)
        worker.signals.finished.connect(my_finished_handler)

        threadpool = QThreadPool()
        threadpool.start(worker)
    """

    def __init__(self, fn, *args, **kwargs):
        """
        Initialize worker.

        Args:
            fn: Function to run in background
            *args: Positional arguments for function
            **kwargs: Keyword arguments for function
                     May include 'progress_callback' which will be passed to fn
        """
        super(Worker, self).__init__()
        self.fn = fn
        self.args = args
        self.kwargs = kwargs
        self.signals = WorkerSignals()

        # Add progress callback to kwargs if function expects it
        self.kwargs['progress_callback'] = self.signals.progress

    @pyqtSlot()
    def run(self):
        """Run the function in background thread."""
        try:
            result = self.fn(*self.args, **self.kwargs)
        except:
            traceback.print_exc()
            exctype, value = sys.exc_info()[:2]
            self.signals.error.emit((exctype, value, traceback.format_exc()))
        else:
            self.signals.result.emit(result)
        finally:
            self.signals.finished.emit()
