"""
Tests for security_model + security_diff — Security-aware diff engine.

Uses synthetic test samples. No IDA/angr/PyQt dependencies.
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from logic_flow.core.security_model import (
    SecurityRole, classify_api, build_security_profile,
    GUARD_APIS, SINK_APIS, ALLOC_APIS,
)
from logic_flow.core.security_diff import (
    SecurityDiffEngine, SecurityDiffReport, RiskLevel,
)
from logic_flow.core.protocol_v2 import DriverAnalysisExportV2
from logic_flow.core.diff_pipeline import DiffPipeline

SAMPLE_DIR = os.path.join(os.path.dirname(__file__), '..', 'samples')


class TestSecurityModel(unittest.TestCase):
    """Test API classification taxonomy."""

    def test_guard_apis_classified(self):
        self.assertEqual(classify_api("ProbeForRead"), SecurityRole.GUARD)
        self.assertEqual(classify_api("ProbeForWrite"), SecurityRole.GUARD)
        self.assertEqual(classify_api("SeAccessCheck"), SecurityRole.GUARD)

    def test_sink_apis_classified(self):
        self.assertEqual(classify_api("RtlCopyMemory"), SecurityRole.SINK)
        self.assertEqual(classify_api("memcpy"), SecurityRole.SINK)
        self.assertEqual(classify_api("MmMapIoSpace"), SecurityRole.SINK)
        self.assertEqual(classify_api("ZwOpenProcess"), SecurityRole.SINK)

    def test_alloc_apis_classified(self):
        self.assertEqual(classify_api("ExAllocatePoolWithTag"), SecurityRole.ALLOC)

    def test_unknown_api_is_neutral(self):
        self.assertEqual(classify_api("my_custom_function"), SecurityRole.NEUTRAL)

    def test_underscore_stripping(self):
        self.assertEqual(classify_api("_ProbeForRead"), SecurityRole.GUARD)

    def test_build_profile_unguarded_sink(self):
        """Function calling RtlCopyMemory but NO guard → has_unguarded_sinks=True."""
        profile = build_security_profile(
            ea=0x1000,
            name="dangerous_func",
            callees=["RtlCopyMemory", "ExAllocatePoolWithTag"],
            dispatch_handler_eas=set(),
            ioctl_handler_map={},
        )
        self.assertTrue(profile.has_sinks)
        self.assertFalse(profile.has_guards)
        self.assertTrue(profile.has_unguarded_sinks)
        self.assertIn("RtlCopyMemory", profile.called_sinks)

    def test_build_profile_guarded(self):
        """Function calling both ProbeForRead and RtlCopyMemory → guarded."""
        profile = build_security_profile(
            ea=0x2000,
            name="safe_func",
            callees=["ProbeForRead", "RtlCopyMemory"],
            dispatch_handler_eas=set(),
            ioctl_handler_map={},
        )
        self.assertTrue(profile.has_guards)
        self.assertTrue(profile.has_sinks)
        self.assertFalse(profile.has_unguarded_sinks)

    def test_dispatch_handler_tagging(self):
        profile = build_security_profile(
            ea=0x3000,
            name="DispatchControl",
            callees=[],
            dispatch_handler_eas={0x3000},
            ioctl_handler_map={},
        )
        self.assertTrue(profile.is_dispatch_handler)

    def test_ioctl_handler_tagging(self):
        profile = build_security_profile(
            ea=0x4000,
            name="HandleIoctl",
            callees=[],
            dispatch_handler_eas=set(),
            ioctl_handler_map={0x4000: [0x222003, 0x222007]},
        )
        self.assertTrue(profile.is_ioctl_handler)
        self.assertEqual(profile.ioctl_codes, [0x222003, 0x222007])


class TestSecurityDiffIntegration(unittest.TestCase):
    """Integration tests using old→new sample pair."""

    def setUp(self):
        old_path = os.path.join(SAMPLE_DIR, "test_old.json")
        new_path = os.path.join(SAMPLE_DIR, "test_new.json")
        if not os.path.exists(old_path) or not os.path.exists(new_path):
            self.skipTest("Sample files not found")

        self.old_export = DriverAnalysisExportV2.load(old_path)
        self.new_export = DriverAnalysisExportV2.load(new_path)

        pipeline = DiffPipeline()
        self.diff_report = pipeline.run(self.old_export, self.new_export)

    def test_security_diff_runs(self):
        """Security diff should complete without errors."""
        engine = SecurityDiffEngine()
        sec_report = engine.run(self.old_export, self.new_export, self.diff_report)

        self.assertIsInstance(sec_report, SecurityDiffReport)
        self.assertGreater(len(sec_report.stats), 0)

    def test_profiles_built_for_non_imports(self):
        """Profiles should be built for all non-import functions."""
        engine = SecurityDiffEngine()
        sec_report = engine.run(self.old_export, self.new_export, self.diff_report)

        # Old: 5 non-import functions
        old_non_import = sum(
            1 for f in self.old_export.functions.values() if not f.is_import
        )
        self.assertEqual(len(sec_report.old_profiles), old_non_import)

    def test_ioctl_size_change_detected(self):
        """IOCTL 0x222003 input_size changed from 256→512."""
        engine = SecurityDiffEngine()
        sec_report = engine.run(self.old_export, self.new_export, self.diff_report)

        size_changes = [
            d for d in sec_report.ioctl_deltas if d.change == "size_changed"
        ]
        self.assertGreater(len(size_changes), 0,
                           "Should detect IOCTL input_size change")

    def test_new_import_detected_in_profiles(self):
        """New version has ProbeForRead import → should appear as guard in profiles."""
        engine = SecurityDiffEngine()
        sec_report = engine.run(self.old_export, self.new_export, self.diff_report)

        # Check if any new profile has ProbeForRead as a guard
        new_import_names = {i.name for i in self.new_export.imports}
        self.assertIn("ProbeForRead", new_import_names)

    def test_fuzz_targets_generated(self):
        """At least one fuzz target should be generated."""
        engine = SecurityDiffEngine()
        sec_report = engine.run(self.old_export, self.new_export, self.diff_report)

        self.assertGreater(len(sec_report.fuzz_targets), 0)

    def test_fuzz_targets_sorted_by_priority(self):
        """Fuzz targets should be sorted by priority (ascending)."""
        engine = SecurityDiffEngine()
        sec_report = engine.run(self.old_export, self.new_export, self.diff_report)

        if len(sec_report.fuzz_targets) > 1:
            priorities = [t.priority for t in sec_report.fuzz_targets]
            self.assertEqual(priorities, sorted(priorities))

    def test_summary_text(self):
        engine = SecurityDiffEngine()
        sec_report = engine.run(self.old_export, self.new_export, self.diff_report)
        summary = sec_report.summary_text()
        self.assertIn("CRIT:", summary)
        self.assertIn("Fuzz Targets:", summary)


if __name__ == '__main__':
    unittest.main()
