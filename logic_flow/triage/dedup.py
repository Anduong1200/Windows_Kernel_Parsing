"""
Crash Deduplication Logic.

Clusters crashes based on heuristics:
1. Faulting Module + Offset
2. Exception Code
3. Stack Trace Hash (Top N frames)
"""
import hashlib
import json
import re
from typing import List, Dict, Any, Optional
from dataclasses import dataclass, asdict
from pathlib import Path

@dataclass
class CrashInput:
    filename: str
    content: str

@dataclass
class CrashSignature:
    faulting_module: str
    faulting_offset: int
    exception_code: str
    stack_hash: str
    
    def to_string(self) -> str:
        """Unique string representation for hashing."""
        return f"{self.exception_code}|{self.faulting_module}|{self.faulting_offset:x}|{self.stack_hash}"

@dataclass
class CrashReport:
    unique_crashes: int
    total_crashes: int
    clusters: Dict[str, List[str]] # Sig -> List[Filenames]
    details: Dict[str, Any] # Sig -> {Info}

class CrashDedup:
    """
    Main deduplication engine.
    """
    def __init__(self):
        self.signature_map: Dict[str, List[str]] = {} # Signature -> [Filenames]
        self.details_map: Dict[str, Any] = {} # Signature -> Common Info

    def process_directory(self, input_dir: str) -> CrashReport:
        """Process all crash logs in a directory."""
        p = Path(input_dir)
        total = 0
        
        for file in p.glob("*.*"): # Helper: consume txt, log, json
            if file.is_file():
                try:
                    content = file.read_text(errors='replace')
                    self.process_crash(file.name, content)
                    total += 1
                except Exception as e:
                    print(f"Failed to read {file}: {e}")
                    
        return CrashReport(
            unique_crashes=len(self.signature_map),
            total_crashes=total,
            clusters=self.signature_map,
            details=self.details_map
        )

    def process_crash(self, filename: str, content: str):
        """Parse and deduplicate a single crash."""
        sig = self._extract_signature(content)
        sig_str = sig.to_string()
        
        if sig_str not in self.signature_map:
            self.signature_map[sig_str] = []
            self.details_map[sig_str] = asdict(sig)
            
        self.signature_map[sig_str].append(filename)

    def _extract_signature(self, content: str) -> CrashSignature:
        """
        Heuristic parser to extract crash info.
        Supports generic WinDbg/text logs or JSON structured logs.
        """
        # 1. Try JSON
        try:
            data = json.loads(content)
            if isinstance(data, dict):
                return CrashSignature(
                    faulting_module=data.get('module', 'unknown'),
                    faulting_offset=int(str(data.get('offset', '0')), 16),
                    exception_code=data.get('exception', 'unknown'),
                    stack_hash=data.get('stack_hash', '0')
                )
        except:
            pass
            
        # 2. Try Regex (Text Log)
        # Look for "Access violation - code c0000005"
        # Look for "Image: MyDriver.sys + 0x1234"
        
        exception = "unknown"
        module = "unknown"
        offset = 0
        stack = []
        
        # Simple regex heuristics (customizable)
        # Ex: "ExceptionCode: c0000005"
        m_exc = re.search(r"ExceptionCode:\s*([0-9a-fA-F]+)", content)
        if m_exc:
            exception = m_exc.group(1)
            
        # Ex: "Fault address: MyDriver+0x1234"
        m_addr = re.search(r"Fault address:\s*([a-zA-Z0-9_.]+)\+0x([0-9a-fA-F]+)", content)
        if m_addr:
            module = m_addr.group(1)
            offset = int(m_addr.group(2), 16)
            
        # Stack hash: crude approach (hash lines starting with #)
        for line in content.splitlines():
            line = line.strip()
            if line.startswith("#") or line.lower().startswith("frame"):
                stack.append(line)
        
        stack_hash = hashlib.md5("".join(stack[:5]).encode()).hexdigest() if stack else "0"
        
        return CrashSignature(
            faulting_module=module,
            faulting_offset=offset,
            exception_code=exception,
            stack_hash=stack_hash
        )
