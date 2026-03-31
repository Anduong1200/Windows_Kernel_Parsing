"""
Tests for Benchmark Framework — ground truth, precision/recall, comparison.
"""

import pytest
from pathlib import Path

from logic_flow.core.protocol_v2 import DriverAnalysisExportV2
from logic_flow.core.ground_truth import GroundTruth, MatchPair, generate_ground_truth
from logic_flow.core.benchmark import (
    BinDiffBenchmark,
    format_comparison_report,
)
from logic_flow.core.driver_families import (
    DriverFamily,
    classify_driver,
    classify_by_filename,
    get_family_description,
)

SAMPLES_DIR = Path(__file__).parent.parent / "samples"


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


# ── Ground Truth Tests ─────────────────────────────────────────────────

class TestGroundTruth:
    """Ground truth generation and serialization."""

    def test_generate_from_name_match(self, old_export, new_export):
        """Generate ground truth from name-matched functions."""
        gt = generate_ground_truth(old_export, new_export)

        assert gt.source == "auto_name_match"
        assert len(gt.pairs) > 0
        assert gt.binary_old == old_export.metadata.input_file
        assert gt.binary_new == new_export.metadata.input_file

    def test_ground_truth_pair_set(self, old_export, new_export):
        """pair_set property returns correct set of tuples."""
        gt = generate_ground_truth(old_export, new_export)
        pair_set = gt.pair_set

        assert isinstance(pair_set, set)
        assert len(pair_set) == len(gt.pairs)

        for p in gt.pairs:
            assert (p.old_ea, p.new_ea) in pair_set

    def test_save_load_roundtrip(self, old_export, new_export, tmp_path):
        """Ground truth can be saved and loaded without loss."""
        gt = generate_ground_truth(old_export, new_export)
        path = str(tmp_path / "gt.json")
        gt.save(path)

        gt2 = GroundTruth.load(path)
        assert len(gt2.pairs) == len(gt.pairs)
        assert gt2.source == gt.source
        assert gt2.binary_old == gt.binary_old

    def test_ndis_ground_truth(self, ndis_v1, ndis_v2):
        """NDIS v1 vs v2 generates meaningful ground truth."""
        gt = generate_ground_truth(ndis_v1, ndis_v2)
        # Should match: DriverEntry, MiniportInitializeEx, etc.
        names = {p.func_name for p in gt.pairs}
        assert "DriverEntry" in names
        assert "MiniportInitializeEx" in names

    def test_min_func_size_filter(self, old_export, new_export):
        """Small functions are excluded by min_func_size."""
        gt_loose = generate_ground_truth(old_export, new_export, min_func_size=0)
        gt_strict = generate_ground_truth(old_export, new_export, min_func_size=500)
        assert len(gt_loose.pairs) >= len(gt_strict.pairs)


# ── Benchmark Tests ────────────────────────────────────────────────────

class TestBenchmark:
    """Benchmark precision/recall/F1 computation."""

    def test_perfect_match(self):
        """Tool that finds exactly the ground truth → P=R=F1=1.0."""
        gt = GroundTruth(pairs=[
            MatchPair(old_ea=100, new_ea=200, func_name="foo"),
            MatchPair(old_ea=300, new_ea=400, func_name="bar"),
        ])

        bench = BinDiffBenchmark(gt)
        result = bench._evaluate("test", [(100, 200), (300, 400)])

        assert result.precision == pytest.approx(1.0)
        assert result.recall == pytest.approx(1.0)
        assert result.f1_score == pytest.approx(1.0)
        assert result.true_positives == 2
        assert result.false_positives == 0
        assert result.false_negatives == 0

    def test_partial_recall(self):
        """Tool that misses one match."""
        gt = GroundTruth(pairs=[
            MatchPair(old_ea=100, new_ea=200, func_name="foo"),
            MatchPair(old_ea=300, new_ea=400, func_name="bar"),
        ])

        bench = BinDiffBenchmark(gt)
        result = bench._evaluate("test", [(100, 200)])  # misses bar

        assert result.precision == pytest.approx(1.0)
        assert result.recall == pytest.approx(0.5)
        assert result.true_positives == 1
        assert result.false_negatives == 1

    def test_false_positives(self):
        """Tool that reports extra (wrong) matches."""
        gt = GroundTruth(pairs=[
            MatchPair(old_ea=100, new_ea=200, func_name="foo"),
        ])

        bench = BinDiffBenchmark(gt)
        result = bench._evaluate("test", [(100, 200), (999, 888)])

        assert result.precision == pytest.approx(0.5)
        assert result.recall == pytest.approx(1.0)
        assert result.false_positives == 1

    def test_empty_gt(self):
        """Empty ground truth with tool matches → precision=0."""
        gt = GroundTruth(pairs=[])
        bench = BinDiffBenchmark(gt)
        result = bench._evaluate("test", [(100, 200)])

        assert result.precision == pytest.approx(0.0)
        assert result.recall == pytest.approx(0.0)

    def test_fastdiff_benchmark(self, old_export, new_export):
        """Run FastDiff benchmark on sample data."""
        gt = generate_ground_truth(old_export, new_export)
        bench = BinDiffBenchmark(gt)
        result = bench.run_fastdiff(old_export, new_export)

        assert result.tool_name == "FastDiff"
        assert result.wall_clock_secs > 0
        assert result.match_count > 0

    def test_synthetic_bindiff(self, old_export, new_export):
        """Create synthetic BinDiff result and compare."""
        gt = generate_ground_truth(old_export, new_export)
        bench = BinDiffBenchmark(gt)

        bd_result = bench.create_synthetic_bindiff_result(
            noise_ratio=0.1, miss_ratio=0.1
        )
        assert bd_result.tool_name == "BinDiff (synthetic)"
        assert bd_result.match_count > 0

    def test_comparison_report(self, old_export, new_export):
        """Generate and format a comparison report."""
        gt = generate_ground_truth(old_export, new_export)
        bench = BinDiffBenchmark(gt)

        fd_result = bench.run_fastdiff(old_export, new_export)
        bd_result = bench.create_synthetic_bindiff_result()

        report = bench.compare(fd_result, bd_result)
        assert report.ground_truth_size > 0
        assert isinstance(report.agreed, list)

        # Format
        text = format_comparison_report(report)
        assert "FastDiff" in text
        assert "BinDiff" in text
        assert "Precision" in text


# ── Driver Family Tests ────────────────────────────────────────────────

class TestDriverFamilies:
    """Driver family classification tests."""

    def test_ndis_classification(self, ndis_v1):
        """NDIS miniport is classified correctly."""
        result = classify_driver(ndis_v1)
        assert result.family == DriverFamily.NDIS
        assert result.confidence > 0.3
        assert len(result.signals) > 0

    def test_vendor_ioctl_classification(self, old_export):
        """Driver with IOCTL and IoCreateDevice is vendor_ioctl or generic_wdm."""
        result = classify_driver(old_export)
        # The test driver has IoCreateDevice import and IOCTLs
        assert result.family in (
            DriverFamily.VENDOR_IOCTL,
            DriverFamily.GENERIC_WDM,
            DriverFamily.UNKNOWN,
        )

    def test_filename_classification(self):
        """Filename-based quick classification."""
        assert classify_by_filename("ndis_miniport.sys") == DriverFamily.NDIS
        assert classify_by_filename("usbhub3.sys") == DriverFamily.USB
        assert classify_by_filename("ntfs.sys") is None  # no direct match
        assert classify_by_filename("storport.sys") == DriverFamily.STORAGE

    def test_family_descriptions(self):
        """All families have descriptions."""
        for family in DriverFamily:
            desc = get_family_description(family)
            assert isinstance(desc, str)
            assert len(desc) > 0

    def test_classification_str(self, ndis_v1):
        """ClassificationResult has readable __str__."""
        result = classify_driver(ndis_v1)
        s = str(result)
        assert "ndis" in s
        assert "confidence" in s
