"""
Tests for DiffPipeline — Two-stage funnel matching.

Uses synthetic test samples (no IDA/angr/PyQt dependencies).
"""

import os
import sys
import unittest

# Ensure we can import from project root
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from logic_flow.core.protocol_v2 import DriverAnalysisExportV2
from logic_flow.core.diff_pipeline import DiffPipeline
from logic_flow.core.diff_report import DiffReport, FunctionMatch

SAMPLE_DIR = os.path.join(os.path.dirname(__file__), '..', 'samples')


class TestDiffPipelineUnit(unittest.TestCase):
    """Unit tests for DiffPipeline components."""

    def test_diff_report_summary(self):
        report = DiffReport(
            matched=[
                FunctionMatch(old_ea=1, new_ea=1, score=1.0,
                              match_type="exact_name", name_old="f", name_new="f")
            ],
            unmatched_old=[2, 3],
            unmatched_new=[4],
        )
        self.assertAlmostEqual(report.match_rate, 1 / 3)
        self.assertIn("1", report.summary())

    def test_diff_report_empty(self):
        report = DiffReport()
        self.assertEqual(report.match_rate, 0.0)

    def test_pipeline_identical_exports(self):
        """Diffing identical exports should match everything."""
        path = os.path.join(SAMPLE_DIR, "test_old.json")
        if not os.path.exists(path):
            self.skipTest("Sample file not found")

        export = DriverAnalysisExportV2.load(path)
        pipeline = DiffPipeline()
        report = pipeline.run(export, export)

        # All non-import functions should match
        non_import_count = sum(
            1 for f in export.functions.values() if not f.is_import
        )
        matched_non_import = sum(
            1 for m in report.matched
            if not export.functions.get(str(m.old_ea), None)
            or not export.functions[str(m.old_ea)].is_import
        )
        self.assertGreater(len(report.matched), 0)
        self.assertEqual(len(report.unmatched_old), 0)
        self.assertEqual(len(report.unmatched_new), 0)

    def test_pipeline_deterministic(self):
        """Same inputs should always produce identical output."""
        path = os.path.join(SAMPLE_DIR, "test_old.json")
        if not os.path.exists(path):
            self.skipTest("Sample file not found")

        export = DriverAnalysisExportV2.load(path)
        pipeline = DiffPipeline()

        report1 = pipeline.run(export, export)
        report2 = pipeline.run(export, export)

        self.assertEqual(len(report1.matched), len(report2.matched))
        self.assertEqual(len(report1.unmatched_old), len(report2.unmatched_old))


class TestDiffPipelineIntegration(unittest.TestCase):
    """Integration tests using old → new sample pair."""

    def setUp(self):
        old_path = os.path.join(SAMPLE_DIR, "test_old.json")
        new_path = os.path.join(SAMPLE_DIR, "test_new.json")
        if not os.path.exists(old_path) or not os.path.exists(new_path):
            self.skipTest("Sample files not found")

        self.old_export = DriverAnalysisExportV2.load(old_path)
        self.new_export = DriverAnalysisExportV2.load(new_path)
        self.pipeline = DiffPipeline()

    def test_matched_by_name(self):
        """Common functions should be matched by exact name."""
        report = self.pipeline.run(self.old_export, self.new_export)

        matched_names = {m.name_old for m in report.matched}
        # DriverEntry, DispatchDeviceControl, HandleIoctl, ValidateInputBuffer
        self.assertIn("DriverEntry", matched_names)
        self.assertIn("DispatchDeviceControl", matched_names)

    def test_new_function_is_unmatched(self):
        """CheckBufferBounds (new only) should be in unmatched_new."""
        report = self.pipeline.run(self.old_export, self.new_export)

        new_func_names = {
            self.new_export.functions[str(ea)].name
            for ea in report.unmatched_new
            if str(ea) in self.new_export.functions
        }
        self.assertIn("CheckBufferBounds", new_func_names)

    def test_old_only_function_is_unmatched(self):
        """sub_140002000 (old only) should be in unmatched_old."""
        report = self.pipeline.run(self.old_export, self.new_export)

        old_func_names = {
            self.old_export.functions[str(ea)].name
            for ea in report.unmatched_old
            if str(ea) in self.old_export.functions
        }
        self.assertIn("sub_140002000", old_func_names)

    def test_report_has_timing_stats(self):
        report = self.pipeline.run(self.old_export, self.new_export)
        self.assertIn("stage0_time", report.stats)
        self.assertIn("total_time", report.stats)
        self.assertIn("old_func_count", report.stats)

    def test_identical_function_scores_one(self):
        """DriverEntry with identical instructions should score 1.0."""
        report = self.pipeline.run(self.old_export, self.new_export)

        driver_entry = [m for m in report.matched if m.name_old == "DriverEntry"]
        self.assertEqual(len(driver_entry), 1)
        self.assertEqual(driver_entry[0].score, 1.0)


if __name__ == '__main__':
    unittest.main()
