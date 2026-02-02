"""
Log Viewer Widgets for Logic Flow Analysis Tool.

Provides:
1. SystemLogWidget - Captures Python logging output
2. IDALogViewer - Tails ida_debug_{pid}.txt in real-time
"""

import os
import logging
import tempfile
from typing import Optional
from pathlib import Path

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QTextEdit, 
    QPushButton, QLabel, QComboBox, QLineEdit
)
from PyQt6.QtCore import QTimer, pyqtSignal, QThread, pyqtSlot, QObject
from PyQt6.QtGui import QTextCursor, QColor, QTextCharFormat


class LogSignalEmitter(QObject):
    """Helper to emit log records from logging handler (thread-safe)."""
    record_ready = pyqtSignal(object)

class QTextEditLogHandler(logging.Handler):
    """
    Custom logging handler that sends records to the GUI via signals.
    """
    
    def __init__(self, emitter):
        super().__init__()
        self.emitter = emitter
        self.setFormatter(logging.Formatter(
            '%(asctime)s [%(levelname)s] %(name)s: %(message)s',
            datefmt='%H:%M:%S'
        ))
    
    def emit(self, record):
        try:
            msg = self.format(record)
            record.formatted_message = msg
            self.emitter.record_ready.emit(record)
        except Exception:
            pass

class SystemLogWidget(QWidget):
    """
    Widget that captures and displays Python logging output with filtering.
    """
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self._records = []  # Store all records
        self._current_level = logging.INFO
        
        self._setup_ui()
        self._setup_logging()
        
        # Format colors
        self._colors = {
            logging.DEBUG: QColor('#888888'),    # Grey
            logging.INFO: QColor('#22c55e'),     # Green
            logging.WARNING: QColor('#f97316'),  # Orange
            logging.ERROR: QColor('#ef4444'),    # Red
            logging.CRITICAL: QColor('#dc2626'), # Dark Red
        }
    
    def _setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        
        # Toolbar
        toolbar = QHBoxLayout()
        
        self.level_combo = QComboBox()
        self.level_combo.addItems(['DEBUG', 'INFO', 'WARNING', 'ERROR'])
        self.level_combo.setCurrentText('INFO')
        self.level_combo.currentTextChanged.connect(self._on_level_changed)
        toolbar.addWidget(QLabel('Level:'))
        toolbar.addWidget(self.level_combo)
        
        self.filter_input = QLineEdit()
        self.filter_input.setPlaceholderText("Filter text...")
        self.filter_input.textChanged.connect(self._refresh_display)
        toolbar.addWidget(self.filter_input)
        
        toolbar.addStretch()
        
        clear_btn = QPushButton('Clear')
        clear_btn.clicked.connect(self._clear_log)
        toolbar.addWidget(clear_btn)
        
        layout.addLayout(toolbar)
        
        # Log display
        self.log_display = QTextEdit()
        self.log_display.setReadOnly(True)
        self.log_display.setLineWrapMode(QTextEdit.LineWrapMode.NoWrap)
        self.log_display.setStyleSheet("""
            QTextEdit {
                background-color: #1e1e2e;
                color: #cdd6f4;
                font-family: 'Consolas', 'Monaco', monospace;
                font-size: 11px;
                border: 1px solid #45475a;
                border-radius: 4px;
            }
        """)
        layout.addWidget(self.log_display)
    
    def _setup_logging(self):
        """Attach log handler to root logger."""
        # Emitter to bridge threads
        self.log_emitter = LogSignalEmitter()
        self.log_emitter.record_ready.connect(self._handle_log_record)
        
        self.log_handler = QTextEditLogHandler(self.log_emitter)
        self.log_handler.setLevel(logging.DEBUG) # Capture everything
        
        # Add to root logger
        root_logger = logging.getLogger()
        root_logger.setLevel(logging.DEBUG) # Ensure root captures everything
        root_logger.addHandler(self.log_handler)
        
        # Also add to logic_flow loggers specifically
        for logger_name in ['logic_flow', 'logic_flow.core', 'logic_flow.gui']:
            logger = logging.getLogger(logger_name)
            logger.setLevel(logging.DEBUG)
            logger.addHandler(self.log_handler)
    
    def _on_level_changed(self, level_str: str):
        self._current_level = getattr(logging, level_str, logging.INFO)
        self._refresh_display()
    
    def _refresh_display(self):
        """Refilter and redraw all logs."""
        self.log_display.clear()
        filter_text = self.filter_input.text().lower()
        
        # Re-add records matching filter
        cursor = self.log_display.textCursor()
        cursor.beginEditBlock()
        
        for record in self._records:
            if record.levelno >= self._current_level:
                msg = getattr(record, 'formatted_message', str(record.msg))
                if filter_text and filter_text not in msg.lower():
                    continue
                self._append_record_to_view(record, cursor)
                
        cursor.endEditBlock()
        self.log_display.setTextCursor(cursor)
        self.log_display.ensureCursorVisible()

    @pyqtSlot(object)
    def _handle_log_record(self, record):
        """Handle new log record from signal."""
        self._records.append(record)
        
        # Check against current filters
        if record.levelno < self._current_level:
            return
            
        filter_text = self.filter_input.text().lower()
        msg = getattr(record, 'formatted_message', str(record.msg))
        
        if filter_text and filter_text not in msg.lower():
            return

        cursor = self.log_display.textCursor()
        self._append_record_to_view(record, cursor)
        self.log_display.setTextCursor(cursor) # Auto-scroll
    
    def _append_record_to_view(self, record, cursor=None):
        if cursor is None:
            cursor = self.log_display.textCursor()
            
        color = self._colors.get(record.levelno, QColor('#cdd6f4'))
        fmt = QTextCharFormat()
        fmt.setForeground(color)
        
        cursor.movePosition(QTextCursor.MoveOperation.End)
        # Use stored formatted message
        msg = getattr(record, 'formatted_message', str(record.msg))
        cursor.insertText(msg + '\n', fmt)

    def _clear_log(self):
        self._records.clear()
        self.log_display.clear()
    
    def log(self, message: str, level: int = logging.INFO):
        """Programmatically log a message via the logging system."""
        logging.log(level, message)


class IDALogViewer(QWidget):
    """
    Widget that tails ida_debug_{pid}.txt files in real-time.
    
    Provides live log viewing for IDA analysis processes.
    """
    
    logUpdated = pyqtSignal(str)  # Emits new log content
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self._current_pid: Optional[int] = None
        self._current_file: Optional[Path] = None
        self._last_position: int = 0
        self._timer: Optional[QTimer] = None
        
        self._setup_ui()
    
    def _setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        
        # Toolbar
        toolbar = QHBoxLayout()
        
        toolbar.addWidget(QLabel('IDA Process:'))
        
        self.pid_combo = QComboBox()
        self.pid_combo.setMinimumWidth(150)
        self.pid_combo.currentTextChanged.connect(self._on_pid_changed)
        toolbar.addWidget(self.pid_combo)
        
        refresh_btn = QPushButton('Refresh')
        refresh_btn.clicked.connect(self.refresh_pid_list)
        toolbar.addWidget(refresh_btn)
        
        self.filter_input = QLineEdit()
        self.filter_input.setPlaceholderText("Filter text...")
        self.filter_input.textChanged.connect(self._refresh_display)
        toolbar.addWidget(self.filter_input)

        toolbar.addStretch()
        
        self.status_label = QLabel('Not monitoring')
        self.status_label.setStyleSheet('color: #888888;')
        toolbar.addWidget(self.status_label)
        
        clear_btn = QPushButton('Clear')
        clear_btn.clicked.connect(self._clear_log)
        toolbar.addWidget(clear_btn)
        
        layout.addLayout(toolbar)
        
        # Log display
        self.log_display = QTextEdit()
        self.log_display.setReadOnly(True)
        self.log_display.setLineWrapMode(QTextEdit.LineWrapMode.NoWrap)
        self.log_display.setStyleSheet("""
            QTextEdit {
                background-color: #1a1a2e;
                color: #00ff88;
                font-family: 'Consolas', 'Monaco', monospace;
                font-size: 11px;
                border: 1px solid #45475a;
                border-radius: 4px;
            }
        """)
        layout.addWidget(self.log_display)
        
        self._full_log_lines = [] # Store lines for filtering
        
        # Setup timer for tailing
        self._timer = QTimer(self)
        self._timer.timeout.connect(self._tail_log)
    
    def refresh_pid_list(self):
        """Scan temp directory for ida_debug_*.txt files."""
        import glob
        
        temp_dir = tempfile.gettempdir()
        pattern = os.path.join(temp_dir, "ida_debug_*.txt")
        
        self.pid_combo.clear()
        self.pid_combo.addItem('-- Select PID --')
        
        for log_file in glob.glob(pattern):
            basename = os.path.basename(log_file)
            pid_str = basename.replace("ida_debug_", "").replace(".txt", "")
            try:
                pid = int(pid_str)
                # Check if file has content
                if os.path.getsize(log_file) > 0:
                    self.pid_combo.addItem(f"PID {pid}", pid)
            except (ValueError, OSError):
                pass
    
    def _on_pid_changed(self, text: str):
        """Handle PID selection change."""
        if text.startswith('PID'):
            pid = self.pid_combo.currentData()
            self.start_monitoring(pid)
        else:
            self.stop_monitoring()
    
    def start_monitoring(self, pid: int):
        """Start monitoring a specific IDA log file."""
        self._current_pid = pid
        self._current_file = Path(tempfile.gettempdir()) / f"ida_debug_{pid}.txt"
        self._last_position = 0
        self._full_log_lines = []
        
        if self._current_file.exists():
            # Load existing content
            try:
                with open(self._current_file, 'r', encoding='utf-8', errors='replace') as f:
                    content = f.read()
                    self._full_log_lines = content.splitlines()
                    self._last_position = len(content)
                    self._refresh_display()
            except Exception as e:
                self.log_display.setPlainText(f"Error reading log: {e}")
        
        self._timer.start(500)  # Poll every 500ms
        self.status_label.setText(f'Monitoring PID {pid}')
        self.status_label.setStyleSheet('color: #22c55e;')
    
    def stop_monitoring(self):
        """Stop monitoring."""
        self._timer.stop()
        self._current_pid = None
        self._current_file = None
        self.status_label.setText('Not monitoring')
        self.status_label.setStyleSheet('color: #888888;')
    
    def _refresh_display(self):
        """Redraw filtered display."""
        filter_text = self.filter_input.text().lower()
        self.log_display.clear()
        
        lines_to_show = []
        for line in self._full_log_lines:
            if not filter_text or filter_text in line.lower():
                lines_to_show.append(line)
        
        self.log_display.setPlainText("\n".join(lines_to_show))
        
        # Scroll to bottom
        cursor = self.log_display.textCursor()
        cursor.movePosition(QTextCursor.MoveOperation.End)
        self.log_display.setTextCursor(cursor)

    def _tail_log(self):
        """Read new content from log file."""
        if not self._current_file or not self._current_file.exists():
            return
        
        try:
            with open(self._current_file, 'r', encoding='utf-8', errors='replace') as f:
                f.seek(self._last_position)
                new_content = f.read()
                
                if new_content:
                    self._last_position = f.tell()
                    new_lines = new_content.splitlines()
                    self._full_log_lines.extend(new_lines)
                    
                    # Update display efficiently
                    filter_text = self.filter_input.text().lower()
                    cursor = self.log_display.textCursor()
                    cursor.movePosition(QTextCursor.MoveOperation.End)
                    
                    for line in new_lines:
                        if not filter_text or filter_text in line.lower():
                            cursor.insertText(line + '\n')
                    
                    self.log_display.setTextCursor(cursor)
                    self.log_display.ensureCursorVisible()
                    
                    self.logUpdated.emit(new_content)
        except Exception:
            pass
    
    def _clear_log(self):
        self.log_display.clear()
        self._full_log_lines = []
        self._last_position = 0


class UnifiedLogWidget(QWidget):
    """
    Unified Log Viewer - Shows ALL logs from all sources in one view.
    Combines: System (Python logging) + IDA Debug logs.
    """
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self._records = []  # List of (timestamp, source, level, message)
        self._current_level = logging.DEBUG  # Show all by default
        
        self._setup_ui()
        self._setup_logging()
        
        # Colors for sources and levels
        self._source_colors = {
            'SYS': QColor('#89b4fa'),    # Blue for System
            'IDA': QColor('#a6e3a1'),    # Green for IDA
        }
        self._level_colors = {
            logging.DEBUG: QColor('#6c7086'),
            logging.INFO: QColor('#cdd6f4'),
            logging.WARNING: QColor('#f9e2af'),
            logging.ERROR: QColor('#f38ba8'),
            logging.CRITICAL: QColor('#eba0ac'),
        }
        
        # IDA log tailing
        self._ida_log_path = None
        self._ida_last_pos = 0
        self._ida_timer = QTimer(self)
        self._ida_timer.timeout.connect(self._tail_ida_log)
        self._ida_timer.start(500)
    
    def _setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        
        # Toolbar
        toolbar = QHBoxLayout()
        
        toolbar.addWidget(QLabel('Level:'))
        self.level_combo = QComboBox()
        self.level_combo.addItems(['ALL', 'DEBUG', 'INFO', 'WARNING', 'ERROR'])
        self.level_combo.setCurrentText('ALL')
        self.level_combo.currentTextChanged.connect(self._on_level_changed)
        toolbar.addWidget(self.level_combo)
        
        toolbar.addWidget(QLabel('Source:'))
        self.source_combo = QComboBox()
        self.source_combo.addItems(['ALL', 'SYS', 'IDA'])
        self.source_combo.currentTextChanged.connect(self._refresh_display)
        toolbar.addWidget(self.source_combo)
        
        self.filter_input = QLineEdit()
        self.filter_input.setPlaceholderText("Filter text...")
        self.filter_input.textChanged.connect(self._refresh_display)
        toolbar.addWidget(self.filter_input)
        
        toolbar.addStretch()
        
        # Show All button - quick reset filters
        show_all_btn = QPushButton('📋 All')
        show_all_btn.setStyleSheet("""
            QPushButton {
                background-color: #238636;
                color: white;
                border: none;
                padding: 6px 12px;
                border-radius: 4px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #2ea043;
            }
        """)
        show_all_btn.clicked.connect(self._show_all)
        toolbar.addWidget(show_all_btn)
        
        clear_btn = QPushButton('Clear')
        clear_btn.clicked.connect(self._clear_log)
        toolbar.addWidget(clear_btn)
        
        layout.addLayout(toolbar)
        
        # Log display
        self.log_display = QTextEdit()
        self.log_display.setReadOnly(True)
        self.log_display.setLineWrapMode(QTextEdit.LineWrapMode.NoWrap)
        self.log_display.setStyleSheet("""
            QTextEdit {
                background-color: #11111b;
                color: #cdd6f4;
                font-family: 'Consolas', 'Monaco', monospace;
                font-size: 11px;
                border: 1px solid #313244;
                border-radius: 4px;
            }
        """)
        layout.addWidget(self.log_display)
    
    def _setup_logging(self):
        """Attach to root logger."""
        self.log_emitter = LogSignalEmitter()
        self.log_emitter.record_ready.connect(self._handle_sys_record)
        
        self.log_handler = QTextEditLogHandler(self.log_emitter)
        self.log_handler.setLevel(logging.DEBUG)
        
        root_logger = logging.getLogger()
        root_logger.addHandler(self.log_handler)
    
    def _on_level_changed(self, level_str: str):
        if level_str == 'ALL':
            self._current_level = logging.DEBUG
        else:
            self._current_level = getattr(logging, level_str, logging.DEBUG)
        self._refresh_display()
    
    @pyqtSlot(object)
    def _handle_sys_record(self, record):
        """Handle system log record."""
        import time
        self._records.append({
            'timestamp': time.time(),
            'source': 'SYS',
            'level': record.levelno,
            'message': getattr(record, 'formatted_message', str(record.msg))
        })
        self._maybe_append_to_view(self._records[-1])
    
    def _tail_ida_log(self):
        """Tail IDA debug log file."""
        if not self._ida_log_path:
            # Try to find any ida_debug file
            import glob
            temp_dir = tempfile.gettempdir()
            files = glob.glob(os.path.join(temp_dir, 'ida_debug_*.txt'))
            if files:
                # Use most recently modified
                self._ida_log_path = max(files, key=os.path.getmtime)
        
        if self._ida_log_path and os.path.exists(self._ida_log_path):
            try:
                import time
                with open(self._ida_log_path, 'r', encoding='utf-8', errors='replace') as f:
                    f.seek(self._ida_last_pos)
                    new_content = f.read()
                    
                    if new_content:
                        self._ida_last_pos = f.tell()
                        for line in new_content.splitlines():
                            if line.strip():
                                self._records.append({
                                    'timestamp': time.time(),
                                    'source': 'IDA',
                                    'level': logging.INFO,
                                    'message': line
                                })
                                self._maybe_append_to_view(self._records[-1])
            except Exception:
                pass
    
    def _maybe_append_to_view(self, record: dict):
        """Append single record if it matches filters."""
        if record['level'] < self._current_level:
            return
        
        source_filter = self.source_combo.currentText()
        if source_filter != 'ALL' and record['source'] != source_filter:
            return
        
        filter_text = self.filter_input.text().lower()
        if filter_text and filter_text not in record['message'].lower():
            return
        
        self._append_record_to_view(record)
    
    def _append_record_to_view(self, record: dict):
        """Append formatted record to display."""
        cursor = self.log_display.textCursor()
        cursor.movePosition(QTextCursor.MoveOperation.End)
        
        # Format: [SRC] message
        src = record['source']
        src_color = self._source_colors.get(src, QColor('#888888'))
        level_color = self._level_colors.get(record['level'], QColor('#cdd6f4'))
        
        # Source tag
        fmt = QTextCharFormat()
        fmt.setForeground(src_color)
        fmt.setFontWeight(700)
        cursor.insertText(f"[{src}] ", fmt)
        
        # Message
        fmt.setForeground(level_color)
        fmt.setFontWeight(400)
        cursor.insertText(record['message'] + '\n', fmt)
        
        self.log_display.setTextCursor(cursor)
        self.log_display.ensureCursorVisible()
    
    def _refresh_display(self):
        """Refilter and redraw all logs."""
        self.log_display.clear()
        
        for record in self._records:
            self._maybe_append_to_view(record)
    
    def _clear_log(self):
        self._records.clear()
        self.log_display.clear()
    
    def _show_all(self):
        """Reset all filters to show all logs."""
        self.level_combo.setCurrentText('ALL')
        self.source_combo.setCurrentText('ALL')
        self.filter_input.clear()
        self._refresh_display()
    
    def set_ida_log_path(self, path: str):
        """Set specific IDA log file to tail."""
        self._ida_log_path = path
        self._ida_last_pos = 0

