#!/usr/bin/env python3
"""
Startup script with enhanced error handling for PyQt6 issues.
"""

import sys
import os
import traceback

# Add current dir to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Write startup log
log_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'startup.md')

def log(msg):
    with open(log_file, 'a', encoding='utf-8') as f:
        f.write(msg + '\n')

log('# Startup Log')
log('')
log('## System Info')
log(f'- Python: {sys.version}')
log(f'- Platform: {sys.platform}')
log('')

try:
    log('## Step 1: Import PyQt6 base')
    import PyQt6
    log(f'- PyQt6 path: {PyQt6.__file__}')
    log('- Status: OK')
except Exception as e:
    log(f'- FAILED: {e}')
    log(f'```\n{traceback.format_exc()}\n```')
    sys.exit(1)

try:
    log('')
    log('## Step 2: Import QtCore')
    from PyQt6.QtCore import Qt, QTimer
    log('- Status: OK')
except Exception as e:
    log(f'- FAILED: {e}')
    log(f'```\n{traceback.format_exc()}\n```')
    sys.exit(1)

try:
    log('')
    log('## Step 3: Import QtWidgets')
    from PyQt6.QtWidgets import QApplication, QMainWindow, QLabel
    log('- Status: OK')
except Exception as e:
    log(f'- FAILED: {e}')
    log(f'```\n{traceback.format_exc()}\n```')
    sys.exit(1)

try:
    log('')
    log('## Step 4: Create QApplication')
    app = QApplication(sys.argv)
    log('- Status: OK')
except Exception as e:
    log(f'- FAILED: {e}')
    log(f'```\n{traceback.format_exc()}\n```')
    sys.exit(1)

try:
    log('')
    log('## Step 5: Import logic_flow')
    from logic_flow.gui.main_window import LogicFlowAnalysisGUI
    log('- Status: OK')
except Exception as e:
    log(f'- FAILED: {e}')
    log(f'```\n{traceback.format_exc()}\n```')
    sys.exit(1)

try:
    log('')
    log('## Step 6: Create Main Window')
    window = LogicFlowAnalysisGUI()
    log('- Status: OK')
except Exception as e:
    log(f'- FAILED: {e}')
    log(f'```\n{traceback.format_exc()}\n```')
    sys.exit(1)

try:
    log('')
    log('## Step 7: Show Window')
    window.show()
    log('- Status: OK')
    log('')
    log('## Application Started Successfully!')
except Exception as e:
    log(f'- FAILED: {e}')
    log(f'```\n{traceback.format_exc()}\n```')
    sys.exit(1)

# Run event loop
sys.exit(app.exec())
