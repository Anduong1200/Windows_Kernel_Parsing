"""
Security Model — Guard/sink/source taxonomy for Windows kernel drivers.

This module classifies imported API calls and instruction patterns into
security-relevant categories used by the security-aware diff engine.

No heavy dependencies (IDA/angr/PyQt). Pure data classification.
"""

from __future__ import annotations
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, FrozenSet, List, Set


# ---------------------------------------------------------------------------
# Security role taxonomy
# ---------------------------------------------------------------------------
class SecurityRole(str, Enum):
    """Classification of a function's security role."""
    GUARD = "guard"                # Input validation / bounds check
    SINK = "sink"                  # Dangerous operation target
    SOURCE = "source"              # Data origin / user input entry
    ALLOC = "alloc"                # Memory allocation
    FREE = "free"                  # Memory deallocation
    COPY = "copy"                  # Memory copy (potential overflow)
    LOCK = "lock"                  # Synchronization primitive
    DISPATCH = "dispatch"          # IRP dispatch handler
    COMPLETION = "completion"      # I/O completion
    NEUTRAL = "neutral"            # No specific security role


class RiskLevel(str, Enum):
    """Risk level for a security finding."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


# ---------------------------------------------------------------------------
# Guard APIs — functions that validate/check inputs
# ---------------------------------------------------------------------------
GUARD_APIS: FrozenSet[str] = frozenset({
    # Probe / Validate
    "ProbeForRead",
    "ProbeForWrite",
    # Buffer checks
    "RtlULongLongAdd",
    "RtlULongAdd",
    "RtlSizeTAdd",
    "RtlSizeTMult",
    # Safe string operations
    "RtlStringCbCopyW",
    "RtlStringCbCopyA",
    "RtlStringCchCopyW",
    "RtlStringCchCopyA",
    "RtlStringCbCatW",
    "RtlStringCbLengthW",
    "RtlStringCchLengthW",
    # IRQL checks
    "KeGetCurrentIrql",
    "KeLowerIrql",
    "KeRaiseIrql",
    "KeRaiseIrqlToDpcLevel",
    # Access checks
    "SeAccessCheck",
    "SeSinglePrivilegeCheck",
    "IoCheckShareAccess",
    "ObReferenceObjectByHandle",
    # Exception handling
    "ExRaiseAccessViolation",
    "ExRaiseDatatypeMisalignment",
    "ExRaiseStatus",
    # MDL checks
    "MmGetSystemAddressForMdlSafe",
    "IoAllocateMdl",
    "MmProbeAndLockPages",
    # Try/except (__try pattern markers)
    "_SEH_prolog",
    "_SEH_epilog",
    "__C_specific_handler",
})


# ---------------------------------------------------------------------------
# Sink APIs — dangerous operations
# ---------------------------------------------------------------------------
SINK_APIS: FrozenSet[str] = frozenset({
    # Memory copy (buffer overflow targets)
    "RtlCopyMemory",
    "RtlMoveMemory",
    "RtlFillMemory",
    "RtlZeroMemory",
    "memcpy",
    "memmove",
    "memset",
    "strncpy",
    "wcsncpy",
    "strcpy",
    "wcscpy",
    # Unchecked operations
    "RtlCopyBytes",
    "RtlCopyUnicodeString",
    # Registry (persistence targets)
    "ZwSetValueKey",
    "ZwCreateKey",
    "ZwOpenKey",
    # Process / Thread (privilege escalation)
    "ZwOpenProcess",
    "ZwOpenThread",
    "PsLookupProcessByProcessId",
    "PsLookupThreadByThreadId",
    # Physical memory
    "MmMapIoSpace",
    "MmMapLockedPages",
    "MmMapLockedPagesSpecifyCache",
    "ZwMapViewOfSection",
    # Device I/O
    "ZwDeviceIoControlFile",
    "ZwFsControlFile",
    # File system
    "ZwCreateFile",
    "ZwWriteFile",
    "ZwReadFile",
})


# ---------------------------------------------------------------------------
# Source APIs — user-controlled data entry points
# ---------------------------------------------------------------------------
SOURCE_APIS: FrozenSet[str] = frozenset({
    "WdfRequestRetrieveInputBuffer",
    "WdfRequestRetrieveOutputBuffer",
    "WdfRequestRetrieveInputMemory",
    "WdfRequestRetrieveOutputMemory",
    "WdfRequestRetrieveInputWdmMdl",
    "MmGetSystemAddressForMdlSafe",
    # IRP buffer access patterns are detected by instruction analysis
})


# ---------------------------------------------------------------------------
# Allocation APIs
# ---------------------------------------------------------------------------
ALLOC_APIS: FrozenSet[str] = frozenset({
    "ExAllocatePool",
    "ExAllocatePoolWithTag",
    "ExAllocatePool2",
    "ExAllocatePool3",
    "ExAllocatePoolWithQuota",
    "ExAllocatePoolWithQuotaTag",
    "MmAllocateNonCachedMemory",
    "MmAllocateContiguousMemory",
    "IoAllocateIrp",
    "IoAllocateWorkItem",
    "IoAllocateErrorLogEntry",
})


FREE_APIS: FrozenSet[str] = frozenset({
    "ExFreePool",
    "ExFreePoolWithTag",
    "MmFreeNonCachedMemory",
    "MmFreeContiguousMemory",
    "IoFreeIrp",
    "IoFreeWorkItem",
})


COMPLETION_APIS: FrozenSet[str] = frozenset({
    "IoCompleteRequest",
    "WdfRequestComplete",
    "WdfRequestCompleteWithInformation",
    "IoSetCompletionRoutine",
    "IoSetCompletionRoutineEx",
})


LOCK_APIS: FrozenSet[str] = frozenset({
    "ExAcquireFastMutex",
    "ExReleaseFastMutex",
    "ExAcquireResourceExclusiveLite",
    "ExAcquireResourceSharedLite",
    "ExReleaseResourceLite",
    "KeAcquireSpinLock",
    "KeReleaseSpinLock",
    "KeAcquireSpinLockAtDpcLevel",
    "KeReleaseSpinLockFromDpcLevel",
    "ExInterlockedInsertHeadList",
    "ExInterlockedRemoveHeadList",
    "KeWaitForSingleObject",
    "KeWaitForMultipleObjects",
})


# ---------------------------------------------------------------------------
# Aggregate role classification
# ---------------------------------------------------------------------------
def classify_api(name: str) -> SecurityRole:
    """Classify an API name by its security role."""
    # Strip leading underscore variants
    clean = name.lstrip("_")

    if clean in GUARD_APIS:
        return SecurityRole.GUARD
    if clean in SINK_APIS:
        return SecurityRole.SINK
    if clean in SOURCE_APIS:
        return SecurityRole.SOURCE
    if clean in ALLOC_APIS:
        return SecurityRole.ALLOC
    if clean in FREE_APIS:
        return SecurityRole.FREE
    if clean in COMPLETION_APIS:
        return SecurityRole.COMPLETION
    if clean in LOCK_APIS:
        return SecurityRole.LOCK
    return SecurityRole.NEUTRAL


# ---------------------------------------------------------------------------
# Function-level security annotation
# ---------------------------------------------------------------------------
@dataclass
class FunctionSecurityProfile:
    """Security annotation for a single function."""
    ea: int
    name: str
    called_guards: List[str] = field(default_factory=list)
    called_sinks: List[str] = field(default_factory=list)
    called_sources: List[str] = field(default_factory=list)
    called_allocs: List[str] = field(default_factory=list)
    called_frees: List[str] = field(default_factory=list)
    called_completions: List[str] = field(default_factory=list)
    is_dispatch_handler: bool = False
    is_ioctl_handler: bool = False
    ioctl_codes: List[int] = field(default_factory=list)
    has_seh: bool = False

    @property
    def has_guards(self) -> bool:
        return len(self.called_guards) > 0

    @property
    def has_sinks(self) -> bool:
        return len(self.called_sinks) > 0

    @property
    def has_unguarded_sinks(self) -> bool:
        """Sink present but no guard — potential vulnerability."""
        return self.has_sinks and not self.has_guards

    @property
    def risk_summary(self) -> str:
        parts = []
        if self.has_unguarded_sinks:
            parts.append(f"UNGUARDED_SINK({','.join(self.called_sinks)})")
        if self.is_ioctl_handler:
            parts.append(f"IOCTL({','.join(hex(c) for c in self.ioctl_codes)})")
        if self.has_guards:
            parts.append(f"GUARDED({','.join(self.called_guards[:3])})")
        return " | ".join(parts) if parts else "clean"


def build_security_profile(
    ea: int,
    name: str,
    callees: List[str],
    dispatch_handler_eas: Set[int],
    ioctl_handler_map: Dict[int, List[int]],
) -> FunctionSecurityProfile:
    """
    Build security profile for a function from its callee list.

    Args:
        ea: Function address
        name: Function name
        callees: List of callee function names
        dispatch_handler_eas: Set of EAs that are IRP dispatch handlers
        ioctl_handler_map: Map of handler_ea → [ioctl_codes]
    """
    profile = FunctionSecurityProfile(ea=ea, name=name)
    profile.is_dispatch_handler = ea in dispatch_handler_eas
    profile.is_ioctl_handler = ea in ioctl_handler_map
    profile.ioctl_codes = ioctl_handler_map.get(ea, [])

    for callee in callees:
        role = classify_api(callee)
        if role == SecurityRole.GUARD:
            profile.called_guards.append(callee)
        elif role == SecurityRole.SINK:
            profile.called_sinks.append(callee)
        elif role == SecurityRole.SOURCE:
            profile.called_sources.append(callee)
        elif role == SecurityRole.ALLOC:
            profile.called_allocs.append(callee)
        elif role == SecurityRole.FREE:
            profile.called_frees.append(callee)
        elif role == SecurityRole.COMPLETION:
            profile.called_completions.append(callee)

        # SEH detection
        if callee in ("_SEH_prolog", "_SEH_epilog", "__C_specific_handler"):
            profile.has_seh = True

    return profile
