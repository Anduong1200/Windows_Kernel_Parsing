"""
Tests for protocol_v2 — Schema v2 data contract.

No IDA/angr/PyQt dependencies required.
"""

import json
import os
import sys
import tempfile
import unittest

# Ensure we can import from project root
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from logic_flow.core.protocol_v2 import (
    SCHEMA_VERSION,
    CallSite,
    DriverAnalysisExportV2,
    ExportMetadata,
    FunctionInfo,
    ImportEntry,
    Instruction,
    StringEntry,
    validate_export,
)

SAMPLE_DIR = os.path.join(os.path.dirname(__file__), '..', 'samples')


class TestProtocolV2Schema(unittest.TestCase):
    """Validate schema v2 dataclass behavior."""

    def test_schema_version_constant(self):
        self.assertEqual(SCHEMA_VERSION, "2.0")

    def test_empty_export_roundtrip(self):
        """Empty export serializes and deserializes correctly."""
        export = DriverAnalysisExportV2()
        d = export.to_dict()
        self.assertEqual(d["metadata"]["schema_version"], "2.0")
        self.assertEqual(d["functions"], {})

        restored = DriverAnalysisExportV2.from_dict(d)
        self.assertEqual(restored.metadata.schema_version, "2.0")

    def test_function_info_roundtrip(self):
        fi = FunctionInfo(
            ea=0x140001000,
            name="DriverEntry",
            start_ea=0x140001000,
            end_ea=0x140001100,
            size=256,
            is_export=True,
        )
        export = DriverAnalysisExportV2()
        export.functions["5368713216"] = fi

        d = export.to_dict()
        restored = DriverAnalysisExportV2.from_dict(d)
        f = restored.functions["5368713216"]
        self.assertEqual(f.name, "DriverEntry")
        self.assertEqual(f.size, 256)
        self.assertTrue(f.is_export)

    def test_callsite_has_callsite_ea(self):
        cs = CallSite(
            caller_ea=0x1000,
            callee_ea=0x2000,
            callsite_ea=0x1050,
            type="direct",
            target_name="IoCreateDevice",
        )
        self.assertEqual(cs.callsite_ea, 0x1050)

    def test_string_entry(self):
        s = StringEntry(
            ea=0x3000,
            value="\\Device\\MyDriver",
            encoding="utf-16",
            xref_funcs=[0x1000, 0x1100],
        )
        self.assertEqual(len(s.xref_funcs), 2)

    def test_import_entry(self):
        i = ImportEntry(ea=0x4000, name="IoCreateDevice", module="ntoskrnl.exe")
        self.assertEqual(i.module, "ntoskrnl.exe")
        self.assertIsNone(i.ordinal)


class TestProtocolV2Validation(unittest.TestCase):
    """Validate schema validation logic."""

    def test_valid_export(self):
        data = {
            "metadata": {
                "schema_version": "2.0",
                "binary_sha256": "aabb" * 16,
            },
            "functions": {},
            "call_graph": [],
        }
        errors = validate_export(data)
        self.assertEqual(errors, [])

    def test_missing_metadata(self):
        errors = validate_export({})
        self.assertIn("Missing 'metadata' field", errors)

    def test_wrong_schema_version(self):
        data = {
            "metadata": {
                "schema_version": "1.0",
                "binary_sha256": "aabb" * 16,
            },
            "functions": {},
            "call_graph": [],
        }
        errors = validate_export(data)
        self.assertTrue(any("schema_version" in e for e in errors))

    def test_missing_sha256(self):
        data = {
            "metadata": {
                "schema_version": "2.0",
            },
            "functions": {},
            "call_graph": [],
        }
        errors = validate_export(data)
        self.assertTrue(any("binary_sha256" in e for e in errors))


class TestProtocolV2FileIO(unittest.TestCase):
    """Test file save/load operations."""

    def test_save_and_load(self):
        export = DriverAnalysisExportV2()
        export.metadata.binary_sha256 = "test_hash"
        export.functions["1000"] = FunctionInfo(
            ea=1000, name="test_func", start_ea=1000,
            end_ea=1100, size=100,
        )

        with tempfile.NamedTemporaryFile(
            mode='w', suffix='.json', delete=False
        ) as f:
            path = f.name

        try:
            export.save(path)
            loaded = DriverAnalysisExportV2.load(path)
            self.assertEqual(loaded.metadata.binary_sha256, "test_hash")
            self.assertEqual(len(loaded.functions), 1)
            self.assertEqual(loaded.functions["1000"].name, "test_func")
        finally:
            os.unlink(path)

    def test_load_sample_old(self):
        """Load the synthetic test_old.json sample."""
        path = os.path.join(SAMPLE_DIR, "test_old.json")
        if not os.path.exists(path):
            self.skipTest("Sample file not found")

        export = DriverAnalysisExportV2.load(path)
        self.assertEqual(export.metadata.schema_version, "2.0")
        self.assertGreater(len(export.functions), 0)
        self.assertGreater(len(export.call_graph), 0)
        self.assertGreater(len(export.strings), 0)
        self.assertGreater(len(export.imports), 0)

    def test_load_sample_new(self):
        """Load the synthetic test_new.json sample."""
        path = os.path.join(SAMPLE_DIR, "test_new.json")
        if not os.path.exists(path):
            self.skipTest("Sample file not found")

        export = DriverAnalysisExportV2.load(path)
        # New version has the extra function
        func_names = [f.name for f in export.functions.values()]
        self.assertIn("CheckBufferBounds", func_names)
        # New version has ProbeForRead import
        import_names = [i.name for i in export.imports]
        self.assertIn("ProbeForRead", import_names)


if __name__ == '__main__':
    unittest.main()
