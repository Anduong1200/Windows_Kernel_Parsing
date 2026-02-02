"""
PoC Result Widget for displaying Symbolic Execution results.

Shows:
- Hex dump of generated input bytes
- IOCTL code
- Constraints summary
- Save PoC file functionality
"""

import os
from typing import Optional
from pathlib import Path

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QTextEdit, QGroupBox, QFileDialog, QMessageBox, QProgressDialog
)
from PyQt6.QtCore import pyqtSignal, Qt, QThread
from PyQt6.QtGui import QFont


class PoCGenerationWorker(QThread):
    """Worker thread for symbolic execution."""
    
    finished = pyqtSignal(object)  # SymbolicResult
    progress = pyqtSignal(str)
    
    def __init__(self, binary_path: str, graph, target_addr: int, max_time: int = 60):
        super().__init__()
        self.binary_path = binary_path
        self.graph = graph
        self.target_addr = target_addr
        self.max_time = max_time
    
    def run(self):
        from ..core.symbolic_execution import generate_poc_for_target, is_available
        
        if not is_available():
            from ..core.symbolic_execution import SymbolicResult
            self.finished.emit(SymbolicResult(
                success=False,
                target_reached=False,
                error="angr not installed. Install with: pip install angr"
            ))
            return
        
        self.progress.emit("Loading binary...")
        
        result = generate_poc_for_target(
            self.binary_path,
            self.graph,
            self.target_addr,
            self.max_time
        )
        
        self.finished.emit(result)


class PoCResultWidget(QWidget):
    """
    Widget for displaying and saving PoC generation results.
    """
    
    pocGenerated = pyqtSignal(bytes)  # Emits the generated input bytes
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self._current_result = None
        self._binary_path = None
        self._setup_ui()
    
    def _setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(10, 10, 10, 10)
        
        # Header
        header = QLabel("Proof-of-Concept Generator")
        header.setStyleSheet("font-size: 16px; font-weight: bold; color: #cdd6f4;")
        layout.addWidget(header)
        
        # Status
        self.status_label = QLabel("No PoC generated")
        self.status_label.setStyleSheet("color: #888888;")
        layout.addWidget(self.status_label)
        
        # Input Section - Target Address and Binary
        input_group = QGroupBox("Generation Parameters")
        input_group.setStyleSheet("""
            QGroupBox {
                border: 1px solid #30363D;
                border-radius: 6px;
                margin-top: 10px;
                padding-top: 10px;
                background-color: #161B22;
            }
            QGroupBox::title {
                color: #58A6FF;
            }
        """)
        input_layout = QVBoxLayout(input_group)
        
        # Binary Path Display
        binary_row = QHBoxLayout()
        binary_label = QLabel("Binary:")
        binary_label.setStyleSheet("color: #8B949E;")
        binary_label.setFixedWidth(80)
        self.binary_display = QLabel("(Not Set)")
        self.binary_display.setStyleSheet("color: #C9D1D9;")
        binary_row.addWidget(binary_label)
        binary_row.addWidget(self.binary_display)
        binary_row.addStretch()
        input_layout.addLayout(binary_row)
        
        # Target Address Input
        target_row = QHBoxLayout()
        target_label = QLabel("Target Addr:")
        target_label.setStyleSheet("color: #8B949E;")
        target_label.setFixedWidth(80)
        
        from PyQt6.QtWidgets import QLineEdit
        self.target_input = QLineEdit()
        self.target_input.setPlaceholderText("0x140001234")
        self.target_input.setStyleSheet("""
            QLineEdit {
                background-color: #0D1117;
                border: 1px solid #30363D;
                border-radius: 4px;
                padding: 6px;
                color: #C9D1D9;
            }
        """)
        self.target_input.setFixedWidth(150)
        target_row.addWidget(target_label)
        target_row.addWidget(self.target_input)
        target_row.addStretch()
        input_layout.addLayout(target_row)
        
        layout.addWidget(input_group)
        
        # IOCTL Code Group
        ioctl_group = QGroupBox("IOCTL Information")
        ioctl_group.setStyleSheet("""
            QGroupBox {
                border: 1px solid #45475a;
                border-radius: 6px;
                margin-top: 10px;
                padding-top: 10px;
            }
            QGroupBox::title {
                color: #89b4fa;
            }
        """)
        ioctl_layout = QVBoxLayout(ioctl_group)
        
        self.ioctl_label = QLabel("IOCTL Code: --")
        self.ioctl_label.setFont(QFont("Consolas", 12))
        self.ioctl_label.setStyleSheet("color: #f9e2af;")
        ioctl_layout.addWidget(self.ioctl_label)
        
        self.path_label = QLabel("Path length: --")
        self.path_label.setStyleSheet("color: #94e2d5;")
        ioctl_layout.addWidget(self.path_label)
        
        layout.addWidget(ioctl_group)
        
        # Input Buffer Hex Dump
        buffer_group = QGroupBox("Input Buffer (Hex Dump)")
        buffer_group.setStyleSheet("""
            QGroupBox {
                border: 1px solid #45475a;
                border-radius: 6px;
                margin-top: 10px;
                padding-top: 10px;
            }
            QGroupBox::title {
                color: #89b4fa;
            }
        """)
        buffer_layout = QVBoxLayout(buffer_group)
        
        self.hex_display = QTextEdit()
        self.hex_display.setReadOnly(True)
        self.hex_display.setFont(QFont("Consolas", 10))
        self.hex_display.setStyleSheet("""
            QTextEdit {
                background-color: #1e1e2e;
                color: #cdd6f4;
                border: 1px solid #313244;
                border-radius: 4px;
            }
        """)
        self.hex_display.setMinimumHeight(200)
        buffer_layout.addWidget(self.hex_display)
        
        layout.addWidget(buffer_group)
        
        # Constraints Summary
        constraints_group = QGroupBox("Path Constraints (Summary)")
        constraints_group.setStyleSheet("""
            QGroupBox {
                border: 1px solid #45475a;
                border-radius: 6px;
                margin-top: 10px;
                padding-top: 10px;
            }
            QGroupBox::title {
                color: #89b4fa;
            }
        """)
        constraints_layout = QVBoxLayout(constraints_group)
        
        self.constraints_display = QTextEdit()
        self.constraints_display.setReadOnly(True)
        self.constraints_display.setFont(QFont("Consolas", 9))
        self.constraints_display.setStyleSheet("""
            QTextEdit {
                background-color: #1e1e2e;
                color: #a6adc8;
                border: 1px solid #313244;
                border-radius: 4px;
            }
        """)
        self.constraints_display.setMaximumHeight(100)
        constraints_layout.addWidget(self.constraints_display)
        
        layout.addWidget(constraints_group)
        
        # Buttons
        btn_layout = QHBoxLayout()
        
        self.save_btn = QPushButton("Save PoC File")
        self.save_btn.clicked.connect(self._save_poc_file)
        self.save_btn.setEnabled(False)
        self.save_btn.setStyleSheet("""
            QPushButton {
                background-color: #89b4fa;
                color: #1e1e2e;
                border: none;
                padding: 8px 16px;
                border-radius: 6px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #b4befe;
            }
            QPushButton:disabled {
                background-color: #45475a;
                color: #6c7086;
            }
        """)
        btn_layout.addWidget(self.save_btn)
        
        self.copy_btn = QPushButton("Copy Hex")
        self.copy_btn.clicked.connect(self._copy_hex)
        self.copy_btn.setEnabled(False)
        btn_layout.addWidget(self.copy_btn)
        
        btn_layout.addStretch()
        
        self.generate_btn = QPushButton("Generate PoC")
        self.generate_btn.clicked.connect(self._request_generate)
        self.generate_btn.setStyleSheet("""
            QPushButton {
                background-color: #a6e3a1;
                color: #1e1e2e;
                border: none;
                padding: 8px 16px;
                border-radius: 6px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #94e2d5;
            }
        """)
        btn_layout.addWidget(self.generate_btn)
        
        layout.addLayout(btn_layout)
    
    def set_binary_path(self, path: str):
        """Set the binary path for PoC generation."""
        self._binary_path = path
    
    def set_result(self, result):
        """
        Display symbolic execution result.
        
        Args:
            result: SymbolicResult from symbolic_execution module
        """
        self._current_result = result
        
        if not result.success:
            self.status_label.setText(f"❌ Generation failed: {result.error}")
            self.status_label.setStyleSheet("color: #f38ba8;")
            self._clear_display()
            return
        
        if not result.target_reached:
            self.status_label.setText(f"⚠ No path found: {result.error or 'Target unreachable'}")
            self.status_label.setStyleSheet("color: #f9e2af;")
            self._clear_display()
            return
        
        # Success!
        self.status_label.setText("✅ PoC Generated Successfully!")
        self.status_label.setStyleSheet("color: #a6e3a1;")
        
        # IOCTL Code
        if result.ioctl_code is not None:
            self.ioctl_label.setText(f"IOCTL Code: {hex(result.ioctl_code)}")
        else:
            self.ioctl_label.setText("IOCTL Code: (any)")
        
        self.path_label.setText(f"Path length: {result.path_length} basic blocks")
        
        # Hex dump
        if result.input_bytes:
            self.hex_display.setPlainText(self._format_hex_dump(result.input_bytes))
            self.save_btn.setEnabled(True)
            self.copy_btn.setEnabled(True)
        else:
            self.hex_display.setPlainText("(No input buffer required)")
        
        # Constraints
        if result.constraints:
            self.constraints_display.setPlainText('\n'.join(result.constraints))
        else:
            self.constraints_display.setPlainText("(No constraints captured)")
    
    def _clear_display(self):
        """Clear all display fields."""
        self.ioctl_label.setText("IOCTL Code: --")
        self.path_label.setText("Path length: --")
        self.hex_display.clear()
        self.constraints_display.clear()
        self.save_btn.setEnabled(False)
        self.copy_btn.setEnabled(False)
    
    def _format_hex_dump(self, data: bytes, bytes_per_line: int = 16) -> str:
        """Format bytes as hex dump with ASCII."""
        lines = []
        
        for offset in range(0, len(data), bytes_per_line):
            chunk = data[offset:offset + bytes_per_line]
            
            # Hex part
            hex_part = ' '.join(f'{b:02X}' for b in chunk)
            hex_part = hex_part.ljust(bytes_per_line * 3 - 1)
            
            # ASCII part
            ascii_part = ''.join(
                chr(b) if 32 <= b < 127 else '.'
                for b in chunk
            )
            
            lines.append(f"{offset:08X}  {hex_part}  |{ascii_part}|")
        
        return '\n'.join(lines)
    
    def _save_poc_file(self):
        """Save the PoC input to a file."""
        if not self._current_result or not self._current_result.input_bytes:
            return
        
        filename, _ = QFileDialog.getSaveFileName(
            self,
            "Save PoC File",
            "poc_input.bin",
            "Binary Files (*.bin);;All Files (*)"
        )
        
        if filename:
            try:
                with open(filename, 'wb') as f:
                    f.write(self._current_result.input_bytes)
                
                QMessageBox.information(
                    self,
                    "Saved",
                    f"PoC saved to: {filename}"
                )
            except Exception as e:
                QMessageBox.warning(
                    self,
                    "Error",
                    f"Failed to save file: {e}"
                )
    
    def _copy_hex(self):
        """Copy hex dump to clipboard."""
        from PyQt6.QtWidgets import QApplication
        
        if self._current_result and self._current_result.input_bytes:
            hex_str = self._current_result.input_bytes.hex()
            QApplication.clipboard().setText(hex_str)
    
    def set_binary_path(self, path: str):
        """Set the binary path for PoC generation."""
        self._binary_path = path
        if hasattr(self, 'binary_display'):
            import os
            self.binary_display.setText(os.path.basename(path) if path else "(Not Set)")
    
    def set_graph(self, graph):
        """Set the analysis graph for PoC generation."""
        self._graph = graph
    
    def _request_generate(self):
        """Request PoC generation from user input."""
        # Parse target address from input
        target_text = self.target_input.text().strip()
        if not target_text:
            QMessageBox.warning(self, "Input Required", "Please enter a target address (e.g., 0x140001234)")
            return
        
        try:
            if target_text.lower().startswith("0x"):
                target_addr = int(target_text, 16)
            else:
                target_addr = int(target_text)
        except ValueError:
            QMessageBox.warning(self, "Invalid Address", "Target address must be a valid hex (0x...) or decimal number.")
            return
        
        # Check for graph
        if not hasattr(self, '_graph') or not self._graph:
            QMessageBox.warning(self, "No Graph", "Please run analysis first to generate a graph.")
            return
        
        self.generate_for_target(self._graph, target_addr)
    
    def generate_for_target(self, graph, target_addr: int, binary_path: str = None):
        """
        Start PoC generation for a target address.
        
        Args:
            graph: LogicGraph from analysis
            target_addr: Target address to reach
            binary_path: Optional binary path override
        """
        binary = binary_path or self._binary_path
        if not binary:
            QMessageBox.warning(self, "Error", "Binary path not set")
            return
        
        # Show progress dialog
        self.progress = QProgressDialog("Generating PoC...", "Cancel", 0, 0, self)
        self.progress.setWindowModality(Qt.WindowModality.WindowModal)
        self.progress.show()
        
        # Start worker
        self.worker = PoCGenerationWorker(binary, graph, target_addr)
        self.worker.finished.connect(self._on_generation_complete)
        self.worker.progress.connect(lambda msg: self.progress.setLabelText(msg))
        self.worker.start()
    
    def _on_generation_complete(self, result):
        """Handle generation completion."""
        self.progress.close()
        self.set_result(result)
        
        if result.success and result.target_reached and result.input_bytes:
            self.pocGenerated.emit(result.input_bytes)
