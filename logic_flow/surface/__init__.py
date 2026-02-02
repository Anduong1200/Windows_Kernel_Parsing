"""
Attack Surface Extraction Module.

Responsible for mapping the driver's interface:
- Dispatch Routines (IRP Major Functions)
- IOCTLs (Control Codes, Buffers, Handlers)
- Device Objects & Symbolic Links
"""

from .extractor import InterfaceExtractor, generate_driver_model

__all__ = ["InterfaceExtractor", "generate_driver_model"]
