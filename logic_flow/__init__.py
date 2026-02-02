"""
Windows Kernel Driver Logic Flow Analysis Tool

A modern PyQt6 GUI application for analyzing error handling and resource management
logic flows in Windows kernel drivers using IDA Pro.

Author: Security Research Tools
Version: 3.0.0
"""

__version__ = "3.0.0"
__author__ = "Security Research Tools"
__description__ = "Windows Kernel Driver Logic Flow Analysis Tool"

from .core import LogicGraph, FunctionNode, FunctionRole
from .utils.config import ConfigManager

__all__ = [
    "LogicGraph",
    "FunctionNode",
    "FunctionRole",
    "ConfigManager",
    "__version__",
    "__author__",
    "__description__"
]
