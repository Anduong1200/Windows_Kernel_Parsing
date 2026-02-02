#!/usr/bin/env python3
"""
Simple launcher for the Logic Flow Analysis GUI.
Run this to start the application.
"""

import sys
import os

def main():
    """Launch the GUI application"""
    try:
        # Add current directory to Python path
        current_dir = os.path.dirname(os.path.abspath(__file__))
        if current_dir not in sys.path:
            sys.path.insert(0, current_dir)

        print("Starting Logic Flow Analysis Tool...")

        # Import and run the main GUI
        from logic_flow.utils.qt_helper import setup_qt_environment
        from logic_flow.utils.logging_utils import setup_logging
        from logic_flow.gui.main_window import LogicFlowAnalysisGUI

        from PyQt6.QtWidgets import QApplication

        # Setup logging
        setup_logging()

        # Setup Qt environment
        setup_qt_environment()

        # Create application
        app = QApplication(sys.argv)

        # Create main window
        window = LogicFlowAnalysisGUI()

        # Show window
        window.show()

        # Start event loop
        return app.exec()

    except ImportError as e:
        print(f"Import error: {e}")
        print("Please ensure all dependencies are installed:")
        print("pip install PyQt6 psutil")
        return 1

    except Exception as e:
        print(f"Error starting application: {e}")
        import traceback
        traceback.print_exc()
        return 1

if __name__ == "__main__":
    sys.exit(main())