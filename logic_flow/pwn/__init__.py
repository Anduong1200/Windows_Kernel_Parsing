"""
Pwn Suite - Offensive Security Modules.

Contains:
- exploit_generator: Automated Exploit Generation (AEG)
- taint_engine: Source-to-Sink Data Flow Analysis
- double_fetch: Race Condition Detection
- pwn_orchestrator: Full TaintEngine → SymExec → Exploit pipeline
"""

from .exploit_generator import ExploitGenerator
from .taint_engine import TaintEngine
from .double_fetch import DoubleFetchDetector
from .pwn_orchestrator import PwnOrchestrator, run_automated_pwn

__all__ = ['ExploitGenerator', 'TaintEngine', 'DoubleFetchDetector', 'PwnOrchestrator', 'run_automated_pwn']

