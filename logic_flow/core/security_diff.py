"""
Security Diff Engine — Driver-semantic patch diffing.

Produces a structured SecurityDiffReport that highlights:
- Guard additions / removals (ProbeForRead, SEH, bounds checks)
- Sink exposure changes (memcpy, ZwOpen*, MmMapIoSpace)
- IOCTL interface mutations (added/removed/changed codes)
- Dispatch table changes (handler swaps)
- Fuzzing-ready output (which IOCTLs to target first)

Works entirely on the schema v2 data contract. No IDA/angr dependency.
"""

from __future__ import annotations
import logging
from dataclasses import dataclass, field
from typing import Dict, List, Optional

from .protocol_v2 import (
    DriverAnalysisExportV2,
)
from .security_model import (
    RiskLevel, FunctionSecurityProfile,
    build_security_profile,
)
from .diff_report import DiffReport

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Security findings
# ---------------------------------------------------------------------------
@dataclass
class SecurityFinding:
    """A single security-relevant change."""
    category: str       # "guard_removed" | "guard_added" | "sink_added" | ...
    risk: RiskLevel
    title: str
    detail: str
    old_ea: Optional[int] = None
    new_ea: Optional[int] = None
    func_name: str = ""
    related_apis: List[str] = field(default_factory=list)


@dataclass
class IOCTLDelta:
    """Change in IOCTL interface."""
    code: int
    method: str
    change: str          # "added" | "removed" | "handler_changed" | "size_changed"
    old_handler: Optional[str] = None
    new_handler: Optional[str] = None
    old_input_size: Optional[int] = None
    new_input_size: Optional[int] = None
    risk: RiskLevel = RiskLevel.MEDIUM


@dataclass
class DispatchDelta:
    """Change in IRP dispatch table."""
    major_function: int
    change: str          # "handler_changed" | "added" | "removed"
    old_handler: Optional[str] = None
    new_handler: Optional[str] = None
    risk: RiskLevel = RiskLevel.HIGH


@dataclass
class FuzzTarget:
    """Recommended fuzzing target."""
    ioctl_code: int
    method: str
    handler_name: str
    handler_ea: int
    reason: str
    priority: int        # 1 = highest
    input_size: Optional[int] = None


@dataclass
class SecurityDiffReport:
    """Complete security-aware diff output."""
    findings: List[SecurityFinding] = field(default_factory=list)
    ioctl_deltas: List[IOCTLDelta] = field(default_factory=list)
    dispatch_deltas: List[DispatchDelta] = field(default_factory=list)
    fuzz_targets: List[FuzzTarget] = field(default_factory=list)
    old_profiles: Dict[int, FunctionSecurityProfile] = field(default_factory=dict)
    new_profiles: Dict[int, FunctionSecurityProfile] = field(default_factory=dict)
    stats: Dict[str, int] = field(default_factory=dict)

    @property
    def critical_count(self) -> int:
        return sum(1 for f in self.findings if f.risk == RiskLevel.CRITICAL)

    @property
    def high_count(self) -> int:
        return sum(1 for f in self.findings if f.risk == RiskLevel.HIGH)

    def summary_text(self) -> str:
        lines = [
            f"Security Findings: {len(self.findings)} "
            f"(CRIT:{self.critical_count} HIGH:{self.high_count})",
            f"IOCTL Changes:     {len(self.ioctl_deltas)}",
            f"Dispatch Changes:  {len(self.dispatch_deltas)}",
            f"Fuzz Targets:      {len(self.fuzz_targets)}",
        ]
        return "\n".join(lines)


# ---------------------------------------------------------------------------
# Security Diff Engine
# ---------------------------------------------------------------------------
class SecurityDiffEngine:
    """
    Compares two exports from a security-aware perspective.

    Builds FunctionSecurityProfiles for both versions, then diffs:
    - Guard/sink changes per matched function
    - IOCTL interface mutations
    - Dispatch table handler changes
    - Generates prioritized fuzz targets
    """

    def __init__(self, diff_report: Optional[DiffReport] = None):
        self.diff_report = diff_report

    def run(
        self,
        old_export: DriverAnalysisExportV2,
        new_export: DriverAnalysisExportV2,
        diff_report: Optional[DiffReport] = None,
    ) -> SecurityDiffReport:
        """Execute the full security diff."""
        report = SecurityDiffReport()
        diff = diff_report or self.diff_report

        # 1. Build call graph index for both versions
        old_callees = self._build_callee_index(old_export)
        new_callees = self._build_callee_index(new_export)

        # 2. Build dispatch/IOCTL lookup
        old_dispatch_eas = {
            e.handler_ea for e in old_export.driver_interface.dispatch_table
        }
        new_dispatch_eas = {
            e.handler_ea for e in new_export.driver_interface.dispatch_table
        }
        old_ioctl_map = self._build_ioctl_handler_map(old_export)
        new_ioctl_map = self._build_ioctl_handler_map(new_export)

        # 3. Build security profiles
        for ea_str, fi in old_export.functions.items():
            if fi.is_import:
                continue
            callees = old_callees.get(fi.ea, [])
            profile = build_security_profile(
                fi.ea, fi.name, callees, old_dispatch_eas, old_ioctl_map,
            )
            report.old_profiles[fi.ea] = profile

        for ea_str, fi in new_export.functions.items():
            if fi.is_import:
                continue
            callees = new_callees.get(fi.ea, [])
            profile = build_security_profile(
                fi.ea, fi.name, callees, new_dispatch_eas, new_ioctl_map,
            )
            report.new_profiles[fi.ea] = profile

        # 4. Compare matched functions for guard/sink changes
        if diff:
            self._diff_matched_functions(diff, report)

        # 5. IOCTL interface diff
        self._diff_ioctls(old_export, new_export, report)

        # 6. Dispatch table diff
        self._diff_dispatch_table(old_export, new_export, report)

        # 7. Generate fuzz targets
        self._generate_fuzz_targets(new_export, report)

        # 8. Stats
        report.stats = {
            "total_findings": len(report.findings),
            "critical": report.critical_count,
            "high": report.high_count,
            "ioctl_changes": len(report.ioctl_deltas),
            "dispatch_changes": len(report.dispatch_deltas),
            "fuzz_targets": len(report.fuzz_targets),
            "old_funcs_profiled": len(report.old_profiles),
            "new_funcs_profiled": len(report.new_profiles),
        }

        logger.info(f"Security diff: {report.summary_text()}")
        return report

    # ----- Internal helpers -----

    def _build_callee_index(
        self, export: DriverAnalysisExportV2
    ) -> Dict[int, List[str]]:
        """Map function EA → list of callee names."""
        index: Dict[int, List[str]] = {}
        for cs in export.call_graph:
            if cs.target_name:
                index.setdefault(cs.caller_ea, []).append(cs.target_name)
        return index

    def _build_ioctl_handler_map(
        self, export: DriverAnalysisExportV2
    ) -> Dict[int, List[int]]:
        """Map handler_ea → [ioctl_codes]."""
        m: Dict[int, List[int]] = {}
        for ioctl in export.driver_interface.ioctls:
            m.setdefault(ioctl.handler_ea, []).append(ioctl.code)
        return m

    def _diff_matched_functions(
        self, diff: DiffReport, report: SecurityDiffReport
    ) -> None:
        """Compare security profiles of matched function pairs."""
        for match in diff.matched:
            old_prof = report.old_profiles.get(match.old_ea)
            new_prof = report.new_profiles.get(match.new_ea)
            if not old_prof or not new_prof:
                continue

            func_name = match.name_old or match.name_new

            # --- Guard removals (HIGH risk) ---
            old_guards = set(old_prof.called_guards)
            new_guards = set(new_prof.called_guards)
            removed_guards = old_guards - new_guards
            added_guards = new_guards - old_guards

            if removed_guards:
                report.findings.append(SecurityFinding(
                    category="guard_removed",
                    risk=RiskLevel.HIGH,
                    title=f"Guard removed from {func_name}",
                    detail=f"Removed: {', '.join(sorted(removed_guards))}",
                    old_ea=match.old_ea,
                    new_ea=match.new_ea,
                    func_name=func_name,
                    related_apis=sorted(removed_guards),
                ))

            if added_guards:
                report.findings.append(SecurityFinding(
                    category="guard_added",
                    risk=RiskLevel.INFO,
                    title=f"Guard added to {func_name}",
                    detail=f"Added: {', '.join(sorted(added_guards))}",
                    old_ea=match.old_ea,
                    new_ea=match.new_ea,
                    func_name=func_name,
                    related_apis=sorted(added_guards),
                ))

            # --- Sink additions (MEDIUM-HIGH risk) ---
            old_sinks = set(old_prof.called_sinks)
            new_sinks = set(new_prof.called_sinks)
            added_sinks = new_sinks - old_sinks
            removed_sinks = old_sinks - new_sinks

            if added_sinks and not new_prof.has_guards:
                report.findings.append(SecurityFinding(
                    category="unguarded_sink_added",
                    risk=RiskLevel.CRITICAL,
                    title=f"Unguarded sink added to {func_name}",
                    detail=f"New sink(s) {', '.join(sorted(added_sinks))} "
                           f"with NO guard calls detected",
                    old_ea=match.old_ea,
                    new_ea=match.new_ea,
                    func_name=func_name,
                    related_apis=sorted(added_sinks),
                ))
            elif added_sinks:
                report.findings.append(SecurityFinding(
                    category="sink_added",
                    risk=RiskLevel.MEDIUM,
                    title=f"Sink added to {func_name}",
                    detail=f"Added: {', '.join(sorted(added_sinks))} "
                           f"(guards present: {', '.join(sorted(new_guards))})",
                    old_ea=match.old_ea,
                    new_ea=match.new_ea,
                    func_name=func_name,
                    related_apis=sorted(added_sinks),
                ))

            if removed_sinks:
                report.findings.append(SecurityFinding(
                    category="sink_removed",
                    risk=RiskLevel.LOW,
                    title=f"Sink removed from {func_name}",
                    detail=f"Removed: {', '.join(sorted(removed_sinks))}",
                    old_ea=match.old_ea,
                    new_ea=match.new_ea,
                    func_name=func_name,
                    related_apis=sorted(removed_sinks),
                ))

            # --- Previously unguarded sink now guarded (patch indicator) ---
            if old_prof.has_unguarded_sinks and not new_prof.has_unguarded_sinks:
                report.findings.append(SecurityFinding(
                    category="silent_patch",
                    risk=RiskLevel.HIGH,
                    title=f"Silent patch detected: {func_name}",
                    detail=f"Old had unguarded sink(s) {', '.join(old_prof.called_sinks)}, "
                           f"new version added guards {', '.join(sorted(added_guards))}",
                    old_ea=match.old_ea,
                    new_ea=match.new_ea,
                    func_name=func_name,
                    related_apis=sorted(added_guards | old_sinks),
                ))

    def _diff_ioctls(
        self,
        old_export: DriverAnalysisExportV2,
        new_export: DriverAnalysisExportV2,
        report: SecurityDiffReport,
    ) -> None:
        """Compare IOCTL interfaces between versions."""
        old_codes = {i.code: i for i in old_export.driver_interface.ioctls}
        new_codes = {i.code: i for i in new_export.driver_interface.ioctls}

        # Added IOCTLs (new attack surface)
        for code in sorted(set(new_codes) - set(old_codes)):
            nc = new_codes[code]
            report.ioctl_deltas.append(IOCTLDelta(
                code=code,
                method=nc.method,
                change="added",
                new_handler=str(nc.handler_ea),
                new_input_size=nc.input_size,
                risk=RiskLevel.HIGH,
            ))

        # Removed IOCTLs
        for code in sorted(set(old_codes) - set(new_codes)):
            oc = old_codes[code]
            report.ioctl_deltas.append(IOCTLDelta(
                code=code,
                method=oc.method,
                change="removed",
                old_handler=str(oc.handler_ea),
                old_input_size=oc.input_size,
                risk=RiskLevel.LOW,
            ))

        # Changed IOCTLs (same code, different handler/size)
        for code in sorted(set(old_codes) & set(new_codes)):
            oc = old_codes[code]
            nc = new_codes[code]

            if oc.handler_ea != nc.handler_ea:
                report.ioctl_deltas.append(IOCTLDelta(
                    code=code,
                    method=nc.method,
                    change="handler_changed",
                    old_handler=str(oc.handler_ea),
                    new_handler=str(nc.handler_ea),
                    risk=RiskLevel.MEDIUM,
                ))

            if oc.input_size != nc.input_size:
                report.ioctl_deltas.append(IOCTLDelta(
                    code=code,
                    method=nc.method,
                    change="size_changed",
                    old_input_size=oc.input_size,
                    new_input_size=nc.input_size,
                    risk=RiskLevel.MEDIUM,
                ))

    def _diff_dispatch_table(
        self,
        old_export: DriverAnalysisExportV2,
        new_export: DriverAnalysisExportV2,
        report: SecurityDiffReport,
    ) -> None:
        """Compare IRP dispatch tables."""
        old_dispatch = {
            d.major_function: d
            for d in old_export.driver_interface.dispatch_table
        }
        new_dispatch = {
            d.major_function: d
            for d in new_export.driver_interface.dispatch_table
        }

        for mf in sorted(set(old_dispatch) | set(new_dispatch)):
            old_d = old_dispatch.get(mf)
            new_d = new_dispatch.get(mf)

            if old_d and not new_d:
                report.dispatch_deltas.append(DispatchDelta(
                    major_function=mf,
                    change="removed",
                    old_handler=old_d.handler_name,
                    risk=RiskLevel.MEDIUM,
                ))
            elif not old_d and new_d:
                report.dispatch_deltas.append(DispatchDelta(
                    major_function=mf,
                    change="added",
                    new_handler=new_d.handler_name,
                    risk=RiskLevel.HIGH,
                ))
            elif old_d and new_d:
                if old_d.handler_ea != new_d.handler_ea:
                    report.dispatch_deltas.append(DispatchDelta(
                        major_function=mf,
                        change="handler_changed",
                        old_handler=old_d.handler_name,
                        new_handler=new_d.handler_name,
                        risk=RiskLevel.HIGH,
                    ))

    def _generate_fuzz_targets(
        self,
        new_export: DriverAnalysisExportV2,
        report: SecurityDiffReport,
    ) -> None:
        """
        Generate prioritized fuzz targets from new version's IOCTLs.

        Priority rules:
        - P1: IOCTL with METHOD_NEITHER (most dangerous)
        - P2: IOCTL whose handler has unguarded sinks
        - P3: Newly added IOCTLs
        - P4: IOCTLs with large input buffers
        - P5: All other IOCTLs
        """
        added_codes = {d.code for d in report.ioctl_deltas if d.change == "added"}

        for ioctl in new_export.driver_interface.ioctls:
            handler_name = ""
            for fi in new_export.functions.values():
                if fi.ea == ioctl.handler_ea:
                    handler_name = fi.name
                    break

            # Determine priority
            priority = 5  # default
            reasons = []

            if ioctl.method == "NEITHER" or ioctl.method == "METHOD_NEITHER":
                priority = min(priority, 1)
                reasons.append("METHOD_NEITHER (no kernel buffering)")

            handler_profile = report.new_profiles.get(ioctl.handler_ea)
            if handler_profile and handler_profile.has_unguarded_sinks:
                priority = min(priority, 2)
                reasons.append(
                    f"unguarded sinks: {','.join(handler_profile.called_sinks)}"
                )

            if ioctl.code in added_codes:
                priority = min(priority, 3)
                reasons.append("newly added IOCTL")

            if ioctl.input_size and ioctl.input_size >= 256:
                priority = min(priority, 4)
                reasons.append(f"large input buffer ({ioctl.input_size} bytes)")

            if not reasons:
                reasons.append("standard IOCTL")

            report.fuzz_targets.append(FuzzTarget(
                ioctl_code=ioctl.code,
                method=ioctl.method,
                handler_name=handler_name,
                handler_ea=ioctl.handler_ea,
                reason=" | ".join(reasons),
                priority=priority,
                input_size=ioctl.input_size,
            ))

        # Sort by priority (ascending = highest priority first)
        report.fuzz_targets.sort(key=lambda t: t.priority)
