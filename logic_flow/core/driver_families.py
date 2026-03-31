"""
Driver Family Classification — Domain-aware grouping for similarity search.

Classifies drivers into families (NDIS, WDF, filesystem, USB, etc.) using
multi-signal heuristics:
  1. Import signatures  — presence of subsystem-specific APIs
  2. String patterns    — device/registry path conventions
  3. Dispatch table     — IRP_MJ handler count and shape
  4. Pool tags          — known subsystem pool tags

Works entirely on the schema v2 data contract.
"""

from __future__ import annotations
import logging
import re
from enum import Enum
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set

from .protocol_v2 import DriverAnalysisExportV2

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Driver family taxonomy
# ---------------------------------------------------------------------------
class DriverFamily(str, Enum):
    """Known driver subsystem families."""
    NDIS = "ndis"
    WDF_KMDF = "wdf_kmdf"
    WDF_UMDF = "wdf_umdf"
    FILESYSTEM = "filesystem"
    MINIFILTER = "minifilter"
    STORAGE = "storage"
    USB = "usb"
    HID = "hid"
    DISPLAY = "display"
    AUDIO = "audio"
    SERIAL = "serial"
    NETWORK_FILTER = "network_filter"
    VENDOR_IOCTL = "vendor_ioctl"
    GENERIC_WDM = "generic_wdm"
    UNKNOWN = "unknown"


# ---------------------------------------------------------------------------
# Import-based classification rules
# ---------------------------------------------------------------------------
# Each entry: (set of API name substrings → family, confidence weight)
_IMPORT_RULES: List[tuple[List[str], DriverFamily, float]] = [
    # NDIS — network miniport / protocol / filter
    (["NdisMRegisterMiniportDriver", "NdisRegisterProtocolDriver"],
     DriverFamily.NDIS, 1.0),
    (["NdisMSetMiniportAttributes", "NdisMIndicateReceiveNetBufferLists"],
     DriverFamily.NDIS, 0.9),
    (["NdisAllocateNetBufferList", "NdisFSendNetBufferLists"],
     DriverFamily.NDIS, 0.8),

    # KMDF
    (["WdfDriverCreate", "WdfDeviceCreate"],
     DriverFamily.WDF_KMDF, 1.0),
    (["WdfIoQueueCreate", "WdfRequestComplete"],
     DriverFamily.WDF_KMDF, 0.9),

    # Filesystem / minifilter
    (["FltRegisterFilter", "FltStartFiltering"],
     DriverFamily.MINIFILTER, 1.0),
    (["FltAllocateCallbackData", "FltGetRequestorProcessId"],
     DriverFamily.MINIFILTER, 0.9),
    (["IoRegisterFileSystem", "FsRtlRegisterFileSystemFilterCallbacks"],
     DriverFamily.FILESYSTEM, 0.9),
    (["CcInitializeCacheMap", "FsRtlCheckLockForReadAccess"],
     DriverFamily.FILESYSTEM, 0.8),

    # Storage
    (["StorPortInitialize", "StorPortGetDeviceBase"],
     DriverFamily.STORAGE, 1.0),
    (["IoStartPacket", "IoSetHardErrorOrVerifyDevice"],
     DriverFamily.STORAGE, 0.6),

    # USB
    (["WdfUsbTargetDeviceCreate", "USBD_CreateConfigurationRequestEx"],
     DriverFamily.USB, 1.0),
    (["UsbBuildInterruptOrBulkTransferRequest"],
     DriverFamily.USB, 0.9),

    # HID
    (["HidRegisterMinidriver", "HidP_GetCaps"],
     DriverFamily.HID, 1.0),

    # Display
    (["DxgkInitialize", "DxgkDdiStartDevice"],
     DriverFamily.DISPLAY, 1.0),

    # Audio
    (["PcRegisterSubdevice", "PcAddAdapterDevice"],
     DriverFamily.AUDIO, 1.0),
    (["KsCreateFilterFactory"],
     DriverFamily.AUDIO, 0.8),

    # Serial
    (["SerCxInitialize", "SerCx2InitializeDevice"],
     DriverFamily.SERIAL, 1.0),

    # WFP / network filter
    (["FwpmEngineOpen", "FwpsCalloutRegister"],
     DriverFamily.NETWORK_FILTER, 1.0),
    (["FwpmFilterAdd", "FwpmCalloutAdd"],
     DriverFamily.NETWORK_FILTER, 0.9),
]


# ---------------------------------------------------------------------------
# String-pattern rules
# ---------------------------------------------------------------------------
_STRING_PATTERNS: List[tuple[str, DriverFamily, float]] = [
    (r"\\Device\\Tcp", DriverFamily.NDIS, 0.6),
    (r"\\Device\\Nsi", DriverFamily.NDIS, 0.6),
    (r"\\FileSystem\\", DriverFamily.FILESYSTEM, 0.7),
    (r"\\FileSystem\\Filters\\", DriverFamily.MINIFILTER, 0.8),
    (r"USBSTOR", DriverFamily.USB, 0.5),
    (r"HID\\", DriverFamily.HID, 0.5),
    (r"\\DosDevices\\COM", DriverFamily.SERIAL, 0.5),
]


# ---------------------------------------------------------------------------
# Pool tag rules
# ---------------------------------------------------------------------------
_POOL_TAG_RULES: Dict[str, DriverFamily] = {
    "NDIS": DriverFamily.NDIS,
    "Ndis": DriverFamily.NDIS,
    "ndis": DriverFamily.NDIS,
    "FMfn": DriverFamily.MINIFILTER,
    "FMfl": DriverFamily.MINIFILTER,
    "Fsrt": DriverFamily.FILESYSTEM,
    "Stor": DriverFamily.STORAGE,
    "Usb": DriverFamily.USB,
    "UsbH": DriverFamily.USB,
    "HidP": DriverFamily.HID,
}


# ---------------------------------------------------------------------------
# Classification result
# ---------------------------------------------------------------------------
@dataclass
class ClassificationResult:
    """Result of driver family classification."""
    family: DriverFamily
    confidence: float  # 0.0 – 1.0
    signals: List[str] = field(default_factory=list)
    secondary_families: List[DriverFamily] = field(default_factory=list)

    def __str__(self) -> str:
        sigs = ", ".join(self.signals[:3])
        return f"{self.family.value} (confidence={self.confidence:.0%}, signals=[{sigs}])"


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------
def classify_driver(export: DriverAnalysisExportV2) -> ClassificationResult:
    """
    Auto-classify a driver export into a family using multi-signal heuristics.

    Returns ClassificationResult with the best-match family and confidence.
    """
    scores: Dict[DriverFamily, float] = {}
    signals: Dict[DriverFamily, List[str]] = {}

    # Collect import names (both from imports list and function names)
    import_names: Set[str] = set()
    for imp in export.imports:
        import_names.add(imp.name)
    for fi in export.functions.values():
        if fi.is_import:
            import_names.add(fi.name)

    # 1. Import-based classification
    for api_patterns, family, weight in _IMPORT_RULES:
        for pattern in api_patterns:
            # Check for exact match or substring match
            for imp_name in import_names:
                if pattern in imp_name:
                    scores[family] = scores.get(family, 0.0) + weight
                    signals.setdefault(family, []).append(f"import:{pattern}")
                    break

    # 2. String-based classification
    for s in export.strings:
        for pattern, family, weight in _STRING_PATTERNS:
            if re.search(pattern, s.value, re.IGNORECASE):
                scores[family] = scores.get(family, 0.0) + weight
                signals.setdefault(family, []).append(f"string:{pattern}")

    # 3. Pool tag classification
    for tag in export.driver_interface.detected_pools:
        for tag_pattern, family in _POOL_TAG_RULES.items():
            if tag_pattern in tag:
                scores[family] = scores.get(family, 0.0) + 0.5
                signals.setdefault(family, []).append(f"pool:{tag}")

    # 4. Dispatch table shape
    dispatch_count = len(export.driver_interface.dispatch_table)
    if dispatch_count >= 10:
        # Filesystem drivers typically register many IRP_MJ handlers
        scores[DriverFamily.FILESYSTEM] = scores.get(DriverFamily.FILESYSTEM, 0.0) + 0.4
        signals.setdefault(DriverFamily.FILESYSTEM, []).append(
            f"dispatch_count:{dispatch_count}"
        )
    elif dispatch_count == 0 and len(export.driver_interface.ioctls) > 0:
        # IOCTL-only driver
        scores[DriverFamily.VENDOR_IOCTL] = scores.get(DriverFamily.VENDOR_IOCTL, 0.0) + 0.3
        signals.setdefault(DriverFamily.VENDOR_IOCTL, []).append("ioctl_only")

    # 5. Fallback: check for basic WDM markers
    wdm_apis = {"IoCreateDevice", "IoDeleteDevice", "IoCompleteRequest"}
    if import_names & wdm_apis and not scores:
        scores[DriverFamily.GENERIC_WDM] = 0.3
        signals[DriverFamily.GENERIC_WDM] = ["import:IoCreateDevice"]

    # ── Pick winner ────────────────────────────────────────────────────
    if not scores:
        return ClassificationResult(
            family=DriverFamily.UNKNOWN,
            confidence=0.0,
            signals=["no_matching_signals"],
        )

    # Normalize scores to 0–1 range
    max_score = max(scores.values())
    sorted_families = sorted(scores.items(), key=lambda x: x[1], reverse=True)

    best_family = sorted_families[0][0]
    # Confidence = normalized best score capped at 1.0
    confidence = min(max_score / 3.0, 1.0)  # 3.0 = strong multi-signal

    secondary = [f for f, _ in sorted_families[1:3] if scores[f] > max_score * 0.5]

    return ClassificationResult(
        family=best_family,
        confidence=confidence,
        signals=signals.get(best_family, []),
        secondary_families=secondary,
    )


def classify_by_filename(filename: str) -> Optional[DriverFamily]:
    """
    Quick heuristic classification from filename alone.
    Returns None if inconclusive.
    """
    name_lower = filename.lower()

    patterns = {
        "ndis": DriverFamily.NDIS,
        "miniport": DriverFamily.NDIS,
        "flt": DriverFamily.MINIFILTER,
        "filter": DriverFamily.NETWORK_FILTER,
        "usb": DriverFamily.USB,
        "hid": DriverFamily.HID,
        "stor": DriverFamily.STORAGE,
        "disk": DriverFamily.STORAGE,
        "serial": DriverFamily.SERIAL,
        "display": DriverFamily.DISPLAY,
        "audio": DriverFamily.AUDIO,
    }

    for pattern, family in patterns.items():
        if pattern in name_lower:
            return family

    return None


def get_family_description(family: DriverFamily) -> str:
    """Return a human-readable description of a driver family."""
    descriptions = {
        DriverFamily.NDIS: "Network (NDIS miniport/protocol/filter)",
        DriverFamily.WDF_KMDF: "Kernel-Mode Driver Framework (KMDF)",
        DriverFamily.WDF_UMDF: "User-Mode Driver Framework (UMDF)",
        DriverFamily.FILESYSTEM: "Legacy Filesystem Driver",
        DriverFamily.MINIFILTER: "Filesystem Minifilter",
        DriverFamily.STORAGE: "Storage / Disk Stack",
        DriverFamily.USB: "USB Class/Function Driver",
        DriverFamily.HID: "Human Interface Device (HID)",
        DriverFamily.DISPLAY: "Display Miniport",
        DriverFamily.AUDIO: "Audio (PortCls / AVStream)",
        DriverFamily.SERIAL: "Serial / COM Port",
        DriverFamily.NETWORK_FILTER: "Network Filter (WFP / NDIS LWF)",
        DriverFamily.VENDOR_IOCTL: "Vendor-Specific IOCTL Driver",
        DriverFamily.GENERIC_WDM: "Generic WDM Driver",
        DriverFamily.UNKNOWN: "Unknown / Unclassified",
    }
    return descriptions.get(family, "Unknown")
