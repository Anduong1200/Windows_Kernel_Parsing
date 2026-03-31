"""
Tests for IndexStore — SQLite-backed persistent sketch storage.
"""

import os
import tempfile
import pytest
from pathlib import Path

# Module under test
from logic_flow.core.index_store import IndexStore, BinaryRecord, FunctionSketch
from logic_flow.core.protocol_v2 import DriverAnalysisExportV2

SAMPLES_DIR = Path(__file__).parent.parent / "samples"


@pytest.fixture
def tmp_db(tmp_path):
    """Create a temporary database path."""
    return str(tmp_path / "test_index.db")


@pytest.fixture
def store(tmp_db):
    """Create and return an IndexStore."""
    s = IndexStore(tmp_db)
    yield s
    s.close()


@pytest.fixture
def old_export():
    return DriverAnalysisExportV2.load(str(SAMPLES_DIR / "test_old.json"))


@pytest.fixture
def ndis_v1():
    return DriverAnalysisExportV2.load(str(SAMPLES_DIR / "ndis_miniport_v1.json"))


@pytest.fixture
def ndis_v2():
    return DriverAnalysisExportV2.load(str(SAMPLES_DIR / "ndis_miniport_v2.json"))


class TestIndexStoreBasic:
    """Basic CRUD operations."""

    def test_create_open(self, tmp_db):
        """Schema is created on first open."""
        store = IndexStore(tmp_db)
        assert store.get_binary_count() == 0
        store.close()

        # Re-open existing DB
        store2 = IndexStore(tmp_db)
        assert store2.get_binary_count() == 0
        store2.close()

    def test_index_binary(self, store, old_export):
        """Index a binary and verify record."""
        record = store.index_binary(old_export, family="vendor_ioctl")

        assert record.filename == "test_old_driver.sys"
        assert record.driver_family == "vendor_ioctl"
        assert record.func_count > 0
        assert store.get_binary_count() == 1

    def test_lookup_binary(self, store, old_export):
        """Lookup an indexed binary by SHA256."""
        store.index_binary(old_export, family="vendor_ioctl")
        sha = old_export.metadata.binary_sha256

        found = store.lookup_binary(sha)
        assert found is not None
        assert found.filename == "test_old_driver.sys"

        # Non-existent
        assert store.lookup_binary("deadbeef" * 8) is None

    def test_idempotent_index(self, store, old_export):
        """Re-indexing the same binary updates rather than duplicating."""
        store.index_binary(old_export, family="vendor_ioctl")
        store.index_binary(old_export, family="generic_wdm")

        assert store.get_binary_count() == 1
        sha = old_export.metadata.binary_sha256
        record = store.lookup_binary(sha)
        assert record.driver_family == "generic_wdm"

    def test_delete_binary(self, store, old_export):
        """Delete a binary and its sketches."""
        store.index_binary(old_export, family="vendor_ioctl")
        sha = old_export.metadata.binary_sha256

        assert store.get_binary_count() == 1
        assert store.delete_binary(sha) is True
        assert store.get_binary_count() == 0
        assert store.lookup_binary(sha) is None

        # Delete non-existent returns False
        assert store.delete_binary("deadbeef" * 8) is False

    def test_list_binaries(self, store, old_export, ndis_v1):
        """List binaries, optionally filtered by family."""
        store.index_binary(old_export, family="vendor_ioctl")
        store.index_binary(ndis_v1, family="ndis")

        all_bins = store.list_binaries()
        assert len(all_bins) == 2

        ndis_only = store.list_binaries(family="ndis")
        assert len(ndis_only) == 1
        assert ndis_only[0].driver_family == "ndis"


class TestIndexStoreSearch:
    """Search and query operations."""

    def test_get_function_sketches(self, store, old_export):
        """Retrieve sketches for a binary."""
        store.index_binary(old_export, family="vendor_ioctl")
        sha = old_export.metadata.binary_sha256

        sketches = store.get_function_sketches(sha)
        # Should exclude imports by default
        non_import_count = sum(
            1 for fi in old_export.functions.values() if not fi.is_import
        )
        assert len(sketches) == non_import_count

        # Including imports
        all_sketches = store.get_function_sketches(sha, include_imports=True)
        assert len(all_sketches) == len(old_export.functions)

    def test_search_by_name(self, store, old_export):
        """Search functions by name pattern."""
        store.index_binary(old_export, family="vendor_ioctl")

        results = store.search_by_name("DriverEntry")
        assert any(sk.func_name == "DriverEntry" for sk in results)

        results = store.search_by_name("nonexistent_func")
        assert len(results) == 0

    def test_search_by_opcode_hash(self, store, ndis_v1, ndis_v2):
        """Search by exact opcode hash."""
        store.index_binary(ndis_v1, family="ndis")
        store.index_binary(ndis_v2, family="ndis")

        # Get a hash from v1
        sha1 = ndis_v1.metadata.binary_sha256
        sketches = store.get_function_sketches(sha1)
        hashed = [s for s in sketches if s.opcode_hash]
        assert len(hashed) > 0

        # Search for that hash (excluding source binary)
        results = store.search_by_opcode_hash(
            hashed[0].opcode_hash,
            exclude_sha256=sha1,
        )
        # v2 has similar functions, may find matches
        # Just verify the search doesn't crash
        assert isinstance(results, list)

    def test_search_similar_functions(self, store, ndis_v1, ndis_v2):
        """Search for similar functions by hash prefix."""
        store.index_binary(ndis_v1, family="ndis")
        store.index_binary(ndis_v2, family="ndis")

        sha1 = ndis_v1.metadata.binary_sha256
        sketches = store.get_function_sketches(sha1)
        hashed = [s for s in sketches if s.opcode_hash]

        if hashed:
            results = store.search_similar_functions(
                hashed[0].opcode_hash,
                exclude_sha256=sha1,
            )
            assert isinstance(results, list)
            for sketch, score in results:
                assert 0 <= score <= 100

    def test_family_stats(self, store, old_export, ndis_v1, ndis_v2):
        """Get family distribution stats."""
        store.index_binary(old_export, family="vendor_ioctl")
        store.index_binary(ndis_v1, family="ndis")
        store.index_binary(ndis_v2, family="ndis")

        stats = store.get_family_stats()
        assert stats["ndis"] == 2
        assert stats["vendor_ioctl"] == 1

    def test_total_sketch_count(self, store, old_export):
        """Count total function sketches."""
        assert store.get_total_sketch_count() == 0
        store.index_binary(old_export, family="vendor_ioctl")
        assert store.get_total_sketch_count() > 0


class TestAutoClassification:
    """Test auto-classification during indexing."""

    def test_ndis_auto_classify(self, store, ndis_v1):
        """NDIS driver should be auto-classified."""
        record = store.index_binary(ndis_v1)  # no family override
        assert record.driver_family == "ndis"

    def test_family_override(self, store, ndis_v1):
        """Override auto-classification."""
        record = store.index_binary(ndis_v1, family="custom_family")
        assert record.driver_family == "custom_family"
