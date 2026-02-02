"""
Crash Triage and Deduplication Module.

Responsible for:
- Parsing crash logs (text/json)
- Computing crash signatures (Stack Hash, Offset Hash)
- Clustering unique crashes
"""
from .dedup import CrashDedup, CrashReport

__all__ = ["CrashDedup", "CrashReport"]
