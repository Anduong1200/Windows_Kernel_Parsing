"""
Disassembler Provider Abstraction Layer.

Provides a unified interface for multiple disassembler backends:
- IDA Pro (primary)
- Ghidra (headless analyzer)
- Radare2 (future)

This allows the analysis logic to be tool-agnostic.
"""

import logging
from abc import ABC, abstractmethod
from typing import List, Dict, Tuple, Optional, Any
from dataclasses import dataclass
from enum import Enum, auto

logger = logging.getLogger(__name__)


class DisassemblerType(Enum):
    """Supported disassembler backends."""
    IDA = auto()
    GHIDRA = auto()
    RADARE2 = auto()
    MOCK = auto()  # For testing


@dataclass
class FunctionInfo:
    """Platform-neutral function information."""
    address: int
    name: str
    size: int
    start_ea: int
    end_ea: int
    is_thunk: bool = False
    is_library: bool = False


@dataclass
class InstructionInfo:
    """Platform-neutral instruction information."""
    address: int
    mnemonic: str
    operands: List[str]
    bytes: bytes
    size: int


@dataclass  
class XrefInfo:
    """Cross-reference information."""
    from_addr: int
    to_addr: int
    xref_type: str  # 'call', 'jump', 'data'


class DisassemblerProvider(ABC):
    """
    Abstract base class for disassembler providers.
    
    All backend-specific code should implement this interface.
    """
    
    @property
    @abstractmethod
    def name(self) -> str:
        """Return the name of this provider (e.g., 'IDA', 'Ghidra')."""
        pass
    
    @property
    @abstractmethod
    def version(self) -> str:
        """Return the version of the disassembler."""
        pass
    
    @abstractmethod
    def is_available(self) -> bool:
        """Check if this provider is available in the current environment."""
        pass
    
    # =========================================================================
    # Function Operations
    # =========================================================================
    
    @abstractmethod
    def get_function(self, address: int) -> Optional[FunctionInfo]:
        """Get function containing the given address."""
        pass
    
    @abstractmethod
    def get_function_by_name(self, name: str) -> Optional[FunctionInfo]:
        """Get function by name."""
        pass
    
    @abstractmethod
    def get_all_functions(self) -> List[FunctionInfo]:
        """Get all functions in the binary."""
        pass
    
    @abstractmethod
    def get_function_name(self, address: int) -> Optional[str]:
        """Get name of function at address."""
        pass
    
    @abstractmethod
    def get_function_bytes(self, address: int) -> Optional[bytes]:
        """Get raw bytes of function."""
        pass
    
    # =========================================================================
    # Instruction Operations
    # =========================================================================
    
    @abstractmethod
    def get_instruction(self, address: int) -> Optional[InstructionInfo]:
        """Get instruction at address."""
        pass
    
    @abstractmethod
    def get_function_instructions(self, func_address: int) -> List[InstructionInfo]:
        """Get all instructions in a function."""
        pass
    
    @abstractmethod
    def get_mnemonic(self, address: int) -> Optional[str]:
        """Get instruction mnemonic at address."""
        pass
    
    # =========================================================================
    # Cross-Reference Operations
    # =========================================================================
    
    @abstractmethod
    def get_xrefs_to(self, address: int) -> List[XrefInfo]:
        """Get all cross-references TO this address."""
        pass
    
    @abstractmethod
    def get_xrefs_from(self, address: int) -> List[XrefInfo]:
        """Get all cross-references FROM this address."""
        pass
    
    @abstractmethod
    def get_callers(self, func_address: int) -> List[int]:
        """Get all functions that call this function."""
        pass
    
    @abstractmethod
    def get_callees(self, func_address: int) -> List[int]:
        """Get all functions called by this function."""
        pass
    
    # =========================================================================
    # Data Operations
    # =========================================================================
    
    @abstractmethod
    def get_string(self, address: int) -> Optional[str]:
        """Get string at address if it exists."""
        pass
    
    @abstractmethod
    def get_bytes(self, address: int, size: int) -> bytes:
        """Get raw bytes from address."""
        pass
    
    # =========================================================================
    # Navigation
    # =========================================================================
    
    @abstractmethod
    def jump_to(self, address: int) -> bool:
        """Jump to address in the disassembler UI (if supported)."""
        pass


# =============================================================================
# GHIDRA HEADLESS PROVIDER
# =============================================================================

class GhidraHeadlessProvider(DisassemblerProvider):
    """
    Ghidra Headless Analyzer provider.
    
    Uses Ghidra's analyzeHeadless script to analyze binaries without GUI.
    Results are cached for subsequent queries.
    
    Usage:
        provider = GhidraHeadlessProvider(ghidra_path="/path/to/ghidra")
        provider.analyze("/path/to/binary.sys")
        funcs = provider.get_all_functions()
    """
    
    def __init__(self, ghidra_path: str = None, project_path: str = None):
        """
        Initialize Ghidra provider.
        
        Args:
            ghidra_path: Path to Ghidra installation directory
            project_path: Path for Ghidra project files (temp if not specified)
        """
        self.ghidra_path = ghidra_path or self._find_ghidra()
        self.project_path = project_path
        self._current_binary = None
        self._function_cache: Dict[int, FunctionInfo] = {}
        self._instruction_cache: Dict[int, InstructionInfo] = {}
        
    def _find_ghidra(self) -> Optional[str]:
        """Try to find Ghidra installation."""
        import os
        
        # Check environment variable
        ghidra_home = os.environ.get('GHIDRA_INSTALL_DIR')
        if ghidra_home and os.path.isdir(ghidra_home):
            return ghidra_home
        
        # Check common paths
        common_paths = [
            r"C:\ghidra",
            r"C:\Program Files\ghidra",
            "/opt/ghidra",
            "/usr/local/ghidra",
            os.path.expanduser("~/ghidra")
        ]
        
        for path in common_paths:
            if os.path.isdir(path):
                return path
        
        return None
    
    @property
    def name(self) -> str:
        return "Ghidra"
    
    @property
    def version(self) -> str:
        # Would parse from Ghidra installation
        return "10.x"
    
    def is_available(self) -> bool:
        """Check if Ghidra headless is available."""
        if not self.ghidra_path:
            return False
        
        import os
        headless_script = os.path.join(
            self.ghidra_path, "support", "analyzeHeadless.bat"
        )
        if os.name != 'nt':
            headless_script = os.path.join(
                self.ghidra_path, "support", "analyzeHeadless"
            )
        
        return os.path.exists(headless_script)
    
    def analyze(self, binary_path: str, script_path: str = None) -> bool:
        """
        Run Ghidra headless analysis on a binary.
        
        Args:
            binary_path: Path to binary to analyze
            script_path: Optional path to post-analysis script
            
        Returns:
            True if analysis succeeded
        """
        import subprocess
        import tempfile
        import os
        
        if not self.is_available():
            logger.error("Ghidra headless not available")
            return False
        
        self._current_binary = binary_path
        
        # Create temp project directory
        if not self.project_path:
            self.project_path = tempfile.mkdtemp(prefix="ghidra_")
        
        # Build command
        headless = os.path.join(self.ghidra_path, "support", "analyzeHeadless")
        if os.name == 'nt':
            headless += ".bat"
        
        cmd = [
            headless,
            self.project_path,
            "TempProject",
            "-import", binary_path,
            "-overwrite",
            "-analysisTimeoutPerFile", "300"
        ]
        
        if script_path:
            cmd.extend(["-postScript", script_path])
        
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=600
            )
            
            if result.returncode != 0:
                logger.error(f"Ghidra analysis failed: {result.stderr}")
                return False
            
            # Parse output to build caches
            self._parse_analysis_output(result.stdout)
            return True
            
        except subprocess.TimeoutExpired:
            logger.error("Ghidra analysis timed out")
            return False
        except Exception as e:
            logger.error(f"Ghidra analysis error: {e}")
            return False
    
    def _parse_analysis_output(self, output: str):
        """Parse Ghidra output to populate caches."""
        # This would parse the output from a post-analysis script
        # that exports function information in a structured format
        pass
    
    # Implement abstract methods with cache lookups
    def get_function(self, address: int) -> Optional[FunctionInfo]:
        return self._function_cache.get(address)
    
    def get_function_by_name(self, name: str) -> Optional[FunctionInfo]:
        for func in self._function_cache.values():
            if func.name == name:
                return func
        return None
    
    def get_all_functions(self) -> List[FunctionInfo]:
        return list(self._function_cache.values())
    
    def get_function_name(self, address: int) -> Optional[str]:
        func = self.get_function(address)
        return func.name if func else None
    
    def get_function_bytes(self, address: int) -> Optional[bytes]:
        # Would need to access Ghidra's byte provider
        return None
    
    def get_instruction(self, address: int) -> Optional[InstructionInfo]:
        return self._instruction_cache.get(address)
    
    def get_function_instructions(self, func_address: int) -> List[InstructionInfo]:
        func = self.get_function(func_address)
        if not func:
            return []
        
        return [
            insn for addr, insn in self._instruction_cache.items()
            if func.start_ea <= addr < func.end_ea
        ]
    
    def get_mnemonic(self, address: int) -> Optional[str]:
        insn = self.get_instruction(address)
        return insn.mnemonic if insn else None
    
    def get_xrefs_to(self, address: int) -> List[XrefInfo]:
        return []  # Would query Ghidra's reference manager
    
    def get_xrefs_from(self, address: int) -> List[XrefInfo]:
        return []
    
    def get_callers(self, func_address: int) -> List[int]:
        return []
    
    def get_callees(self, func_address: int) -> List[int]:
        return []
    
    def get_string(self, address: int) -> Optional[str]:
        return None
    
    def get_bytes(self, address: int, size: int) -> bytes:
        return b''
    
    def jump_to(self, address: int) -> bool:
        # Headless mode doesn't support UI navigation
        return False


# =============================================================================
# PROVIDER FACTORY
# =============================================================================

_active_provider: Optional[DisassemblerProvider] = None


def get_provider() -> Optional[DisassemblerProvider]:
    """Get the currently active disassembler provider."""
    global _active_provider
    return _active_provider


def set_provider(provider: DisassemblerProvider):
    """Set the active disassembler provider."""
    global _active_provider
    _active_provider = provider
    logger.info(f"Disassembler provider set to: {provider.name}")


def create_provider(provider_type: DisassemblerType, **kwargs) -> DisassemblerProvider:
    """
    Create a disassembler provider of the specified type.
    
    Args:
        provider_type: Type of provider to create
        **kwargs: Provider-specific arguments
        
    Returns:
        Configured DisassemblerProvider instance
    """
    if provider_type == DisassemblerType.IDA:
        # Import IDA provider from existing module
        from .ida_provider import create_ida_provider
        return create_ida_provider()
    
    elif provider_type == DisassemblerType.GHIDRA:
        return GhidraHeadlessProvider(**kwargs)
    
    elif provider_type == DisassemblerType.MOCK:
        from .ida_provider import MockIDAProvider
        return MockIDAProvider()
    
    else:
        raise ValueError(f"Unsupported provider type: {provider_type}")


def auto_detect_provider() -> Optional[DisassemblerProvider]:
    """
    Automatically detect the available disassembler and create a provider.
    
    Returns:
        Best available provider, or None if none found
    """
    # Try IDA first (highest priority)
    try:
        import idaapi
        from .ida_provider import create_ida_provider
        provider = create_ida_provider()
        logger.info("Auto-detected IDA Pro environment")
        return provider
    except ImportError:
        pass
    
    # Try Ghidra
    ghidra = GhidraHeadlessProvider()
    if ghidra.is_available():
        logger.info("Auto-detected Ghidra installation")
        return ghidra
    
    logger.warning("No disassembler detected, using mock provider")
    from .ida_provider import MockIDAProvider
    return MockIDAProvider()
