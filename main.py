#!/usr/bin/env python3
"""
Main entry point for Windows Kernel Driver Logic Flow Analysis Tool

This is the primary entry point for running the GUI application.
"""

import sys
import os

# Add the logic_flow package to Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from logic_flow.utils.qt_helper import setup_qt_environment, setup_application_attributes
from logic_flow.utils.logging_utils import setup_logging
from logic_flow.gui.main_window import LogicFlowAnalysisGUI

from PyQt6.QtWidgets import QApplication
from PyQt6.QtCore import Qt


def main():
    """Main entry point - optimized for graphics and Windows 11 compatibility"""
    try:
        # Setup logging first
        setup_logging()

        # Setup optimized Qt environment BEFORE creating QApplication
        setup_qt_environment()

        # Create QApplication with optimized settings
        app = QApplication(sys.argv if len(sys.argv) > 1 else [])

        # Set application properties
        app.setApplicationName("Logic Flow Analysis Tool")
        app.setApplicationVersion("3.0.0")
        app.setOrganizationName("Security Research Tools")

        # Setup optimized application attributes
        setup_application_attributes(app)

        # Create and setup main window
        window = LogicFlowAnalysisGUI()

        # Show window with smooth startup
        window.show()
        window.raise_()  # Bring to front
        window.activateWindow()  # Activate window

        # Force initial paint for better perceived performance
        app.processEvents()

        # Start event loop with proper error handling
        return app.exec()

    except Exception as e:
        import logging
        logger = logging.getLogger(__name__)
        logger.error(f"Application error: {str(e)}")

        # Print error to console since QMessageBox requires QApplication
        print(f"Fatal Error: Application failed to start: {str(e)}")
        print("This might be due to PyQt6 version compatibility issues.")
        print("Try: pip install --upgrade PyQt6")

        import traceback
        traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())