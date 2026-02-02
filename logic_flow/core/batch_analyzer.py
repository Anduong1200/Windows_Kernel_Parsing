"""
Batch Analyzer for Logic Flow Analysis

Handles batch comparison of multiple drivers against a baseline signature.
"""

import os
import logging
from typing import List, Dict, Callable, Any, Optional
from datetime import datetime

from .baseline_manager import BaselineManager
from .analyzer import IDAAnalysisRunner
from .diff_reflecting import compare_logic_flows, save_comparison_results
from ..utils.config import ConfigManager

logger = logging.getLogger(__name__)


class BatchAnalyzer:
    """
    Handles batch analysis of multiple drivers against a baseline.

    Provides efficient batch processing with progress tracking and
    comprehensive result aggregation.
    """

    def __init__(self, baseline_manager: BaselineManager, config_manager: ConfigManager):
        self.baseline_manager = baseline_manager
        self.config_manager = config_manager
        self.ida_path = config_manager.get_ida_path()

    def run_batch_analysis(self, target_files: List[str], output_dir: str,
                          baseline_name: str, progress_callback: Optional[Callable] = None) -> Dict[str, Any]:
        """
        Run batch analysis comparing multiple target files against a baseline.

        Args:
            target_files: List of paths to target driver files
            output_dir: Directory to save results
            baseline_name: Name of the baseline signature to use
            progress_callback: Optional callback for progress updates (current, total, driver_name, status)

        Returns:
            Summary of batch analysis results
        """
        if not self.ida_path:
            raise ValueError("IDA Pro path not configured")

        # Find baseline signature
        baselines = self.baseline_manager.list_baselines()
        baseline_info = None

        for baseline in baselines:
            if baseline['name'] == baseline_name:
                baseline_info = baseline
                break

        if not baseline_info:
            raise ValueError(f"Baseline '{baseline_name}' not found")

        # Load baseline signature
        baseline_signature = self.baseline_manager.load_baseline(baseline_info['signature_id'])
        if not baseline_signature:
            raise ValueError(f"Failed to load baseline '{baseline_name}'")

        logger.info(f"Starting batch analysis with baseline: {baseline_name}")
        logger.info(f"Target files: {len(target_files)}")

        # Create output subdirectory for this batch
        batch_timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        batch_output_dir = os.path.join(output_dir, f"batch_analysis_{batch_timestamp}")
        os.makedirs(batch_output_dir, exist_ok=True)

        # Initialize results tracking
        results_summary = {
            "baseline_name": baseline_name,
            "baseline_path": baseline_signature.driver_path,
            "total_comparisons": len(target_files),
            "successful": 0,
            "failed": 0,
            "output_dir": batch_output_dir,
            "comparisons": [],
            "high_similarity_drivers": [],
            "start_time": datetime.now().isoformat()
        }

        # Process each target file
        for i, target_file in enumerate(target_files, 1):
            driver_name = os.path.basename(target_file)

            try:
                if progress_callback:
                    progress_callback(i-1, len(target_files), driver_name, "Starting analysis")

                # Run analysis
                comparison_result = self._analyze_single_target(
                    baseline_signature, target_file, progress_callback, i, len(target_files)
                )

                # Save results
                if progress_callback:
                    progress_callback(i-1, len(target_files), driver_name, "Saving results")

                driver_output_dir = os.path.join(batch_output_dir, f"comparison_{i:03d}_{driver_name}")
                os.makedirs(driver_output_dir, exist_ok=True)

                saved_files = save_comparison_results(comparison_result, driver_output_dir)

                # Extract key metrics
                logic_eq = comparison_result.get("logic_equivalence", {})
                overall_score = logic_eq.get("overall_similarity_score", 0)

                comparison_summary = {
                    "target_file": target_file,
                    "driver_name": driver_name,
                    "overall_score": overall_score,
                    "output_dir": driver_output_dir,
                    "saved_files": list(saved_files.keys()),
                    "status": "success",
                    "comparison_time": datetime.now().isoformat()
                }

                # Check for high similarity
                if overall_score >= 8.0:
                    results_summary["high_similarity_drivers"].append({
                        "name": driver_name,
                        "path": target_file,
                        "score": overall_score
                    })

                results_summary["comparisons"].append(comparison_summary)
                results_summary["successful"] += 1

                if progress_callback:
                    progress_callback(i, len(target_files), driver_name, f"Completed (Score: {overall_score:.1f})")

                logger.info(f"Completed analysis of {driver_name}: Score {overall_score:.1f}")

            except Exception as e:
                logger.error(f"Failed to analyze {driver_name}: {e}")

                comparison_summary = {
                    "target_file": target_file,
                    "driver_name": driver_name,
                    "status": "failed",
                    "error": str(e),
                    "comparison_time": datetime.now().isoformat()
                }

                results_summary["comparisons"].append(comparison_summary)
                results_summary["failed"] += 1

                if progress_callback:
                    progress_callback(i, len(target_files), driver_name, f"Failed: {str(e)[:50]}...")

        # Sort high similarity drivers by score
        results_summary["high_similarity_drivers"].sort(key=lambda x: x["score"], reverse=True)

        # Save batch summary
        results_summary["end_time"] = datetime.now().isoformat()
        self._save_batch_summary(results_summary, batch_output_dir)

        logger.info(f"Batch analysis completed: {results_summary['successful']} successful, {results_summary['failed']} failed")

        return results_summary

    def _analyze_single_target(self, baseline_signature, target_file: str,
                              progress_callback: Optional[Callable], current: int, total: int) -> Dict[str, Any]:
        """
        Analyze a single target file against the baseline.

        Args:
            baseline_signature: Baseline signature to compare against
            target_file: Path to target driver file
            progress_callback: Progress callback function
            current: Current file index (1-based)
            total: Total number of files

        Returns:
            Comparison result dictionary
        """
        driver_name = os.path.basename(target_file)

        if progress_callback:
            progress_callback(current-1, total, driver_name, "Initializing IDA")

        # Create IDA analyzer
        ida_runner = IDAAnalysisRunner(self.ida_path)

        if progress_callback:
            progress_callback(current-1, total, driver_name, "Analyzing target driver")

        # Analyze target driver
        target_analysis = ida_runner.run_analysis(target_file, {
            "operation": "logic_flow_export",
            "debug_context": {}
        })

        if "error" in target_analysis:
            raise RuntimeError(f"Target analysis failed: {target_analysis['error']}")

        # Extract target graph
        target_graph_data = target_analysis.get("logic_graph", {})
        if not target_graph_data or "nodes" not in target_graph_data:
            raise RuntimeError("No logic graph found in target analysis")

        from .logic_graph import LogicGraph
        target_graph = LogicGraph.from_dict(target_graph_data)

        if progress_callback:
            progress_callback(current-1, total, driver_name, "Comparing with baseline")

        # Compare graphs
        comparison_result = compare_logic_flows(
            baseline_signature.graph,
            target_graph,
            baseline_debug_context={},
            target_debug_context={}
        )

        # Add metadata
        comparison_result.update({
            "batch_analysis": True,
            "baseline_name": baseline_signature.name,
            "baseline_driver": baseline_signature.driver_path,
            "target_driver": target_file,
            "timestamp": datetime.now().isoformat()
        })

        return comparison_result

    def _save_batch_summary(self, results_summary: Dict[str, Any], output_dir: str):
        """
        Save batch analysis summary to file.

        Args:
            results_summary: Summary dictionary
            output_dir: Output directory
        """
        import json

        summary_file = os.path.join(output_dir, "batch_analysis_summary.json")
        with open(summary_file, 'w', encoding='utf-8') as f:
            json.dump(results_summary, f, indent=2, default=str)

        # Create HTML summary
        html_summary = self._generate_batch_html_summary(results_summary)
        html_file = os.path.join(output_dir, "batch_analysis_summary.html")
        with open(html_file, 'w', encoding='utf-8') as f:
            f.write(html_summary)

    def _generate_batch_html_summary(self, results_summary: Dict[str, Any]) -> str:
        """
        Generate HTML summary for batch analysis.

        Args:
            results_summary: Results summary dictionary

        Returns:
            HTML content string
        """
        html_content = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Batch Analysis Summary</title>
    <style>
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            margin: 0;
            padding: 20px;
            background-color: #f5f5f5;
            color: #333;
        }}
        .container {{
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            padding: 30px;
            border-radius: 10px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }}
        .header {{
            text-align: center;
            border-bottom: 3px solid #007acc;
            padding-bottom: 20px;
            margin-bottom: 30px;
        }}
        .header h1 {{
            color: #007acc;
            margin: 0;
            font-size: 2.5em;
        }}
        .summary-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin: 30px 0;
        }}
        .summary-card {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 20px;
            border-radius: 10px;
            text-align: center;
        }}
        .summary-card h3 {{
            margin: 0;
            font-size: 2em;
        }}
        .summary-card p {{
            margin: 10px 0 0 0;
            opacity: 0.9;
        }}
        .results-table {{
            width: 100%;
            border-collapse: collapse;
            margin: 20px 0;
            background: white;
        }}
        .results-table th, .results-table td {{
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid #ddd;
        }}
        .results-table th {{
            background-color: #f8f9fa;
            font-weight: 600;
            color: #007acc;
        }}
        .score-high {{ color: #28a745; font-weight: bold; }}
        .score-medium {{ color: #ffc107; font-weight: bold; }}
        .score-low {{ color: #dc3545; font-weight: bold; }}
        .status-success {{ color: #28a745; }}
        .status-failed {{ color: #dc3545; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔄 Batch Analysis Summary</h1>
            <div style="color: #666; font-size: 1.1em; margin-top: 10px;">
                Baseline: <strong>{results_summary['baseline_name']}</strong><br>
                Generated on {results_summary['start_time'][:19].replace('T', ' ')}
            </div>
        </div>

        <div class="summary-grid">
            <div class="summary-card">
                <h3>{results_summary['total_comparisons']}</h3>
                <p>Total Comparisons</p>
            </div>
            <div class="summary-card">
                <h3>{results_summary['successful']}</h3>
                <p>Successful</p>
            </div>
            <div class="summary-card">
                <h3>{results_summary['failed']}</h3>
                <p>Failed</p>
            </div>
            <div class="summary-card">
                <h3>{len(results_summary['high_similarity_drivers'])}</h3>
                <p>High Similarity (>8.0)</p>
            </div>
        </div>

        <h2>📊 Comparison Results</h2>
        <table class="results-table">
            <tr>
                <th>Driver</th>
                <th>Similarity Score</th>
                <th>Status</th>
                <th>Output Directory</th>
            </tr>
"""

        for comp in results_summary["comparisons"]:
            status_class = "status-success" if comp["status"] == "success" else "status-failed"
            score_class = ""
            score_display = "N/A"

            if comp["status"] == "success":
                score = comp.get("overall_score", 0)
                score_display = f"{score:.1f}"
                if score >= 8.0:
                    score_class = "score-high"
                elif score >= 5.0:
                    score_class = "score-medium"
                else:
                    score_class = "score-low"

            html_content += f"""
            <tr>
                <td>{comp['driver_name']}</td>
                <td class="{score_class}">{score_display}</td>
                <td class="{status_class}">{comp['status']}</td>
                <td>{os.path.basename(comp.get('output_dir', 'N/A'))}</td>
            </tr>
"""

        html_content += """
        </table>

        <h2>🏆 Top Similar Drivers</h2>
"""

        if results_summary["high_similarity_drivers"]:
            html_content += """
        <table class="results-table">
            <tr>
                <th>Driver</th>
                <th>Similarity Score</th>
            </tr>
"""
            for driver in results_summary["high_similarity_drivers"][:10]:  # Top 10
                html_content += f"""
            <tr>
                <td>{driver['name']}</td>
                <td class="score-high">{driver['score']:.1f}</td>
            </tr>
"""
            html_content += "</table>"
        else:
            html_content += "<p>No drivers with high similarity (>8.0) found.</p>"

        html_content += f"""
        <div style="margin-top: 40px; padding-top: 20px; border-top: 1px solid #e0e0e0; color: #666; text-align: center;">
            <p>Batch analysis completed at {results_summary['end_time'][:19].replace('T', ' ')}</p>
            <p>Results saved to: {results_summary['output_dir']}</p>
        </div>
    </div>
</body>
</html>
"""

        return html_content
