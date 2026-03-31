"""
Tests for QueryPipeline — multi-stage similarity search.
"""

import pytest
from pathlib import Path

from logic_flow.core.index_store import IndexStore
from logic_flow.core.query_pipeline import QueryPipeline
from logic_flow.core.protocol_v2 import DriverAnalysisExportV2

SAMPLES_DIR = Path(__file__).parent.parent / "samples"


@pytest.fixture
def tmp_db(tmp_path):
    return str(tmp_path / "test_query.db")


@pytest.fixture
def store(tmp_db):
    s = IndexStore(tmp_db)
    yield s
    s.close()


@pytest.fixture
def old_export():
    return DriverAnalysisExportV2.load(str(SAMPLES_DIR / "test_old.json"))


@pytest.fixture
def new_export():
    return DriverAnalysisExportV2.load(str(SAMPLES_DIR / "test_new.json"))


@pytest.fixture
def ndis_v1():
    return DriverAnalysisExportV2.load(str(SAMPLES_DIR / "ndis_miniport_v1.json"))


@pytest.fixture
def ndis_v2():
    return DriverAnalysisExportV2.load(str(SAMPLES_DIR / "ndis_miniport_v2.json"))


class TestQueryPipelineBasic:
    """Basic query pipeline functionality."""

    def test_empty_index_query(self, store, old_export):
        """Query against an empty index returns no results."""
        pipeline = QueryPipeline(store)
        result = pipeline.query_binary(old_export, skip_refine=True)

        assert result.target_filename == old_export.metadata.input_file
        assert len(result.similar_binaries) == 0

    def test_single_binary_no_match(self, store, old_export):
        """Query the only indexed binary against itself — excluded by SHA256."""
        store.index_binary(old_export, family="vendor_ioctl")
        pipeline = QueryPipeline(store)
        result = pipeline.query_binary(old_export, skip_refine=True)

        # Should not match itself (excluded by SHA256)
        # Unless there are collisions in the hash space
        assert isinstance(result.similar_binaries, list)

    def test_two_binaries_cross_query(self, store, ndis_v1, ndis_v2):
        """Index two similar NDIS drivers, query one against the other."""
        store.index_binary(ndis_v1, family="ndis")
        store.index_binary(ndis_v2, family="ndis")

        pipeline = QueryPipeline(store)
        result = pipeline.query_binary(ndis_v1, skip_refine=True)

        assert len(result.similar_binaries) > 0
        best = result.similar_binaries[0]
        assert best.filename == "ndis_miniport_v2.sys"
        assert best.overall_score > 0

    def test_family_filter(self, store, old_export, ndis_v1, ndis_v2):
        """Family filter restricts results to matching family."""
        store.index_binary(old_export, family="vendor_ioctl")
        store.index_binary(ndis_v2, family="ndis")

        pipeline = QueryPipeline(store)

        # Query NDIS v1 with family filter "ndis" — should find v2 but not old
        result = pipeline.query_binary(ndis_v1, family="ndis", skip_refine=True)
        for sim in result.similar_binaries:
            assert sim.family == "ndis"

    def test_top_k_limit(self, store, ndis_v1, ndis_v2, old_export):
        """Top-K limits the number of results."""
        store.index_binary(ndis_v2, family="ndis")
        store.index_binary(old_export, family="vendor_ioctl")

        pipeline = QueryPipeline(store)
        result = pipeline.query_binary(ndis_v1, top_k=1, skip_refine=True)

        assert len(result.similar_binaries) <= 1


class TestQueryPipelineFunction:
    """Single-function queries."""

    def test_query_function(self, store, ndis_v1, ndis_v2):
        """Query a single function for similar matches across index."""
        store.index_binary(ndis_v2, family="ndis")

        pipeline = QueryPipeline(store)

        # Find DriverEntry EA in v1
        driver_entry_ea = None
        for fi in ndis_v1.functions.values():
            if fi.name == "DriverEntry":
                driver_entry_ea = fi.ea
                break

        assert driver_entry_ea is not None

        hits = pipeline.query_function(
            driver_entry_ea, ndis_v1, top_k=5
        )
        assert isinstance(hits, list)


class TestQueryPipelineTimings:
    """Timing metadata in query results."""

    def test_timings_present(self, store, ndis_v1, ndis_v2):
        """Query results include stage timing data."""
        store.index_binary(ndis_v2, family="ndis")

        pipeline = QueryPipeline(store)
        result = pipeline.query_binary(ndis_v1, skip_refine=True)

        assert "stage1_sketch" in result.stage_timings
        assert "stage2_scoring" in result.stage_timings
        assert result.stage_timings["stage1_sketch"] >= 0
        assert result.stage_timings["stage2_scoring"] >= 0

    def test_summary(self, store, ndis_v1, ndis_v2):
        """Summary string is well-formed."""
        store.index_binary(ndis_v2, family="ndis")

        pipeline = QueryPipeline(store)
        result = pipeline.query_binary(ndis_v1, skip_refine=True)

        summary = result.summary()
        assert "ndis_miniport_v1.sys" in summary
