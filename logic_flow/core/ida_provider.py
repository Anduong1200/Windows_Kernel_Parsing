"""
IDA Provider Abstraction Layer

This module provides an abstraction layer for IDA Pro APIs to enable:
- Clean separation between real IDA and mock implementations
- Easier testing and development without IDA Pro
- Consistent API regardless of IDA version
"""

from abc import ABC, abstractmethod
from typing import Iterator, Optional, Any, List
from dataclasses import dataclass


@dataclass
class IDAFunction:
    """Mock representation of IDA function object"""
    start_ea: int
    end_ea: int
    flags: int = 0

    def __post_init__(self):
        # Set some reasonable defaults for mock functions
        if self.end_ea <= self.start_ea:
            self.end_ea = self.start_ea + 0x100  # Default 256 bytes


@dataclass
class XRef:
    """Mock representation of IDA cross-reference"""
    frm: int  # From address
    to: int   # To address
    type: int = 0


class IDAProvider(ABC):
    """Abstract base class for IDA Pro API providers"""

    # Constants
    BADADDR = 0xFFFFFFFFFFFFFFFF  # Mock BADADDR, adjust for actual IDA if needed

    @abstractmethod
    def get_func(self, ea: int) -> Optional[IDAFunction]:
        """Get function information at address"""
        pass

    @abstractmethod
    def get_func_qty(self) -> int:
        """Get total number of functions"""
        pass

    @abstractmethod
    def get_next_func(self, ea: int) -> int:
        """Get next function address after given address"""
        pass

    @abstractmethod
    def Functions(self) -> Iterator[int]:
        """Iterator over all function addresses"""
        pass

    @abstractmethod
    def get_ea_name(self, ea: int) -> str:
        """Get name at address"""
        pass

    @abstractmethod
    def XrefsTo(self, ea: int, flags: int = 0) -> Iterator[XRef]:
        """Get cross-references to address"""
        pass

    @abstractmethod
    def is_call_insn(self, ea: int) -> bool:
        """Check if instruction at address is a call"""
        pass

    @abstractmethod
    def get_code_refs_from(self, ea: int) -> Iterator[int]:
        """Get code references from address (calls/jumps)"""
        pass

    @abstractmethod
    def next_head(self, ea: int, maxea: int) -> int:
        """Get next instruction head"""
        pass


class RealIDAProvider(IDAProvider):
    """Real IDA Pro API implementation"""

    def __init__(self):
        # IDA modules should already be available when this is called
        # (checked in create_ida_provider)
        import ida_funcs
        import ida_name
        import ida_xref
        import ida_idaapi
        import ida_bytes
        import ida_ua
        self.ida_funcs = ida_funcs
        self.ida_name = ida_name
        self.ida_xref = ida_xref
        self.ida_idaapi = ida_idaapi
    @abstractmethod
    def get_mnemonic(self, ea: int) -> str:
        """Get instruction mnemonic at address"""
        pass

    @abstractmethod
    def get_string(self, ea: int) -> Optional[str]:
        """Get string content at address"""
        pass

    @abstractmethod
    def get_operand_text(self, ea: int, n: int) -> str:
        """Get operand text"""
        pass


class RealIDAProvider(IDAProvider):
    """Real IDA Pro API implementation"""

    def __init__(self):
        # IDA modules should already be available when this is called
        # (checked in create_ida_provider)
        import ida_funcs
        import ida_name
        import ida_xref
        import ida_idaapi
        import ida_bytes
        import ida_ua
        import ida_nalt
        self.ida_funcs = ida_funcs
        self.ida_name = ida_name
        self.ida_xref = ida_xref
        self.ida_idaapi = ida_idaapi
        self.ida_bytes = ida_bytes
        self.ida_ua = ida_ua
        self.ida_nalt = ida_nalt
        self.BADADDR = ida_idaapi.BADADDR

    def get_func(self, ea: int) -> Optional[IDAFunction]:
        """Get function information using real IDA API"""
        func = self.ida_funcs.get_func(ea)
        if func is None:
            return None
        return IDAFunction(
            start_ea=func.start_ea,
            end_ea=func.end_ea,
            flags=func.flags
        )

    def get_func_qty(self) -> int:
        """Get total number of functions"""
        return self.ida_funcs.get_func_qty()

    def get_next_func(self, ea: int) -> int:
        """Get next function address"""
        return self.ida_funcs.get_next_func(ea)

    def Functions(self) -> Iterator[int]:
        """Iterator over all function addresses"""
        return self.ida_funcs.Functions()

    def get_ea_name(self, ea: int) -> str:
        """Get name at address"""
        return self.ida_name.get_ea_name(ea)

    def XrefsTo(self, ea: int, flags: int = 0) -> Iterator[XRef]:
        """Get cross-references to address"""
        for xref in self.ida_xref.XrefsTo(ea, flags):
            yield XRef(
                frm=xref.frm,
                to=xref.to,
                type=xref.type
            )

    def is_call_insn(self, ea: int) -> bool:
        # IDA 9.x compatibility check could go here if needed
        # Assuming ida_idaapi.is_call_insn exists or using ida_ua
        try:
            return self.ida_idaapi.is_call_insn(ea)
        except AttributeError:
             # Fallback for newer IDA versions where is_call_insn might be moved
             insn = self.ida_ua.insn_t()
             if self.ida_ua.decode_insn(insn, ea):
                 return self.ida_ua.is_call_insn(insn)
             return False

    def get_code_refs_from(self, ea: int) -> Iterator[int]:
        # Iterate code refs from EA (skipping ordinary flow if typical usage)
        # Using 0 (flow=False) as default for calls
        for ref in self.ida_xref.CodeRefsFrom(ea, 0):
             yield ref

    def next_head(self, ea: int, maxea: int) -> int:
        return self.ida_bytes.next_head(ea, maxea)

    def get_mnemonic(self, ea: int) -> str:
        return self.ida_ua.ua_mnem(ea) or ""

    def get_string(self, ea: int) -> Optional[str]:
        content = self.ida_bytes.get_strlit_contents(ea, -1, self.ida_nalt.STRTYPE_C)
        if content:
            return content.decode('utf-8', errors='ignore')
        return None

    def get_operand_text(self, ea: int, n: int) -> str:
        return self.ida_ua.ua_outop(ea, n) or "" # This actually returns op_t in new IDA?
        # ua_outop returns boolean success, but prints to buffer? No.
        # In python: ida_ua.ua_outop(ea, n) usually returns op_t object.
        # But we want TEXT representation like "#5".
        # We can use print_operand(ea, n).
        # But wait, self.ida_ua.print_operand(ea, n).
        # Let's try that.
        return self.ida_ua.print_operand(ea, n)


class MockIDAProvider(IDAProvider):
    """Mock IDA Pro API implementation for testing and standalone usage"""

    def __init__(self):
        # Mock data storage
        self._functions = {}  # ea -> IDAFunction
        self._names = {}      # ea -> name
        self._xrefs = {}      # ea -> list of XRef
        self._calls = {}      # ea -> list of callees (for code refs)

        # Initialize with some mock data
        self._init_mock_data()

    def _init_mock_data(self):
        """Initialize mock data for testing"""
        # Mock functions
        mock_funcs = [
            (0x1000, 0x1100, "NtCreateFile"),
            (0x2000, 0x2100, "NtReadFile"),
            (0x3000, 0x3200, "ErrorHandler"),
            (0x4000, 0x4100, "CleanupHandler"),
            (0x5000, 0x5100, "ValidateInput"),
        ]

        for start_ea, end_ea, name in mock_funcs:
            func = IDAFunction(start_ea, end_ea)
            self._functions[start_ea] = func
            self._names[start_ea] = name

        # Mock cross-references (simplified)
        self._xrefs[0x3000] = [XRef(0x1000, 0x3000)]  # NtCreateFile -> ErrorHandler
        self._xrefs[0x4000] = [XRef(0x2000, 0x4000)]  # NtReadFile -> CleanupHandler
        
        # Mock calls (for get_code_refs_from)
        # 0x1050 inside NtCreateFile calls 0x3000
        self._calls[0x1050] = [0x3000]

    def get_func(self, ea: int) -> Optional[IDAFunction]:
        """Get mock function information"""
        return self._functions.get(ea)

    def get_func_qty(self) -> int:
        """Get total number of mock functions"""
        return len(self._functions)

    def get_next_func(self, ea: int) -> int:
        """Get next function address in mock data"""
        func_eas = sorted(self._functions.keys())
        for i, func_ea in enumerate(func_eas):
            if func_ea > ea:
                return func_ea
        return self.BADADDR

    def Functions(self) -> Iterator[int]:
        """Iterator over mock function addresses"""
        yield from sorted(self._functions.keys())

    def get_ea_name(self, ea: int) -> str:
        """Get mock name at address"""
        return self._names.get(ea, f"sub_{ea:08X}")

    def XrefsTo(self, ea: int, flags: int = 0) -> Iterator[XRef]:
        """Get mock cross-references to address"""
        yield from self._xrefs.get(ea, [])

    def is_call_insn(self, ea: int) -> bool:
        # Mock check: assume address in _calls dict is a call instruction
        return ea in self._calls

    def get_code_refs_from(self, ea: int) -> Iterator[int]:
        yield from self._calls.get(ea, [])

    def next_head(self, ea: int, maxea: int) -> int:
        # Simple mock: strict 4-byte alignment iteration
        next_ea = ea + 4
        if next_ea >= maxea:
            return self.BADADDR
        return next_ea

    def get_mnemonic(self, ea: int) -> str:
        return "nop" # Mock mnemonic

    def get_string(self, ea: int) -> Optional[str]:
        return None

    def get_operand_text(self, ea: int, n: int) -> str:
        return ""

def create_ida_provider() -> IDAProvider:
    """Factory function to create appropriate IDA provider"""
    # Check if IDA modules are available before trying to import them
    try:
        import ida_funcs
        import ida_name
        import ida_idaapi
        # If we get here, IDA is available
        return RealIDAProvider()
    except ImportError:
        # IDA not available, use mock implementation
        return MockIDAProvider()
