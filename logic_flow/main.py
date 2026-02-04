
import argparse
import json
import sys
import os
from pathlib import Path

# Add project root to path if needed, though installed as package it handles itself.
# relative imports work if run as module.

from .surface.extractor import generate_driver_model
from .fuzzing.harness_generator import HarnessGenerator
from .fuzzing.corpus_generator import CorpusGenerator
from .core.logic_graph import LogicGraph
from .report.html_generator import HTMLReportGenerator

def main():
    parser = argparse.ArgumentParser(description="Logic Flow Analysis CLI")
    subparsers = parser.add_subparsers(dest="command", help="Command to execute")

    # Command: extract-interface
    parser_extract = subparsers.add_parser("extract-interface", help="Extract Driver Interface from Analysis Export")
    parser_extract.add_argument("input_json", help="Path to IDA export JSON")
    parser_extract.add_argument("-o", "--output", help="Output Interface JSON", default="interface.json")

    # Command: gen-harness
    parser_harness = subparsers.add_parser("gen-harness", help="Generate Fuzzing Harness")
    parser_harness.add_argument("interface_json", help="Path to Interface JSON")
    parser_harness.add_argument("--out", help="Output Directory", default="harness")
    parser_harness.add_argument("--ioctl", type=str, help="Specific IOCTL code (hex) to target", default=None)

    # Command: analyze (Placeholder for full pipeline)
    parser_analyze = subparsers.add_parser("analyze", help="Run full analysis (Requires IDA)")
    parser_analyze.add_argument("driver_path", help="Path to .sys file")
    
    # Command: triage
    parser_triage = subparsers.add_parser("triage", help="Deduplicate Crash Logs")
    parser_triage.add_argument("crash_dir", help="Directory containing crash logs")
    parser_triage.add_argument("--out", help="Output Report JSON", default="triage_report.json")
    
    # Command: gen-report
    parser_report = subparsers.add_parser("gen-report", help="Generate HTML Report")
    parser_report.add_argument("--interface", help="Path to interface.json", default="interface.json")
    parser_report.add_argument("--triage", help="Path to triage_report.json", default=None)
    parser_report.add_argument("-o", "--output", help="Output HTML file", default="report.html")
    
    args = parser.parse_args()

    if args.command == "extract-interface":
        cmd_extract_interface(args)
    elif args.command == "gen-harness":
        cmd_gen_harness(args)
    elif args.command == "triage":
        cmd_triage(args)
    elif args.command == "gen-report":
        cmd_gen_report(args)
    elif args.command == "analyze":
        print("Analysis pipeline requires IDA Pro setup. Use 'logic-flow-gui' or run scripts directly.")
    else:
        parser.print_help()

def cmd_triage(args):
    """Run crash triage."""
    from .triage.dedup import CrashDedup, asdict
    
    print(f"Triaging crashes in: {args.crash_dir}")
    deduper = CrashDedup()
    report = deduper.process_directory(args.crash_dir)
    
    print(f"Found {report.total_crashes} total crashes.")
    print(f"Identified {report.unique_crashes} unique clusters.")
    
    # Convert to dict for JSON serialization
    report_dict = asdict(report)
    
    with open(args.out, 'w') as f:
        json.dump(report_dict, f, indent=2)
    print(f"Report saved to {args.out}")


def cmd_extract_interface(args):
    print(f"Loading export: {args.input_json}")
    try:
        with open(args.input_json, 'r') as f:
            raw_data = json.load(f)
        
        # We need a LogicGraph to use InterfaceExtractor properly
        # Reconstruct graph locally (headless)
        from .core.engine import CoreAnalysisEngine
        # Mock engine or use it? LogicGraph reconstruction is in Engine.
        # But Engine needs raw_data structure.
        
        # Simplified reconstruction for interface extraction:
        # We might not need full graph if we trust the export's heuristic data,
        # but InterfaceExtractor uses 'graph.nodes[ea].role'.
        
        print("Reconstructing graph for context...")
        # Since we don't have the engine initialized with all config, 
        # let's just do a minimal graph load.
        # Actually CoreAnalysisEngine._reconstruct_graph is good.
        engine = CoreAnalysisEngine()
        # Find anchor in data?
        # metadata = raw_data.get('metadata', {})
        # anchor = metadata.get('anchor_function') # If we saved it?
        # Provide default anchor if needed or just process all nodes.
        
        # Hack: The engine.process_analysis expects raw_data and does everything.
        # But we want just the graph and then extract interface.
        # The engine NOW returns the graph with metadata['driver_interface'] attached!
        # So we can just use engine.
        
        graph = engine.process_analysis(raw_data)
        
        interface_model = graph.metadata.get('driver_interface')
        if not interface_model:
            # If engine didn't produce it (maybe old export?), try manual extract
            # But we just added it to engine. So if inputs are valid, it works.
            print("Warning: Engine did not produce driver_interface. Attempting fallback...")
            interface_model = generate_driver_model(graph, raw_data)

        print(f"Extraction complete. Found {len(interface_model['dispatch_table'])} dispatch entries, {len(interface_model['ioctls'])} IOCTLs.")
        
        with open(args.output, 'w') as f:
            json.dump(interface_model, f, indent=2)
        print(f"Saved to {args.output}")

    except Exception as e:
        print(f"Error extracting interface: {e}")
        import traceback
        traceback.print_exc()

def cmd_gen_harness(args):
    print(f"Loading interface: {args.interface_json}")
    try:
        with open(args.interface_json, 'r') as f:
            interface = json.load(f)
        
        out_dir = Path(args.out)
        out_dir.mkdir(parents=True, exist_ok=True)
        
        devices = interface.get('devices', [])
        device_name = devices[0]['name'] if devices else "\\\\.\\UnknownDevice"
        if devices:
            # Prefer symbolic link if available as it's accessible from user mode
            if devices[0].get('symlink'):
                 device_name = devices[0]['symlink'] # e.g. \DosDevices\MyDriver
                 # Fix symlink for CreateFile: \DosDevices\X -> \\.\X
                 if device_name.startswith("\\DosDevices\\"):
                     device_name = "\\\\.\\" + device_name[12:]
        
        ioctls = interface.get('ioctls', [])
        
        # If specific IOCTL requested
        if args.ioctl:
            target_code = int(args.ioctl, 16)
            ioctls = [i for i in ioctls if i['code'] == target_code]
            
        if not ioctls:
            print("No IOCTLs found to fuzz options.")
            return

        print(f"Generating harnesses for {len(ioctls)} IOCTLs...")
        
        for ioctl in ioctls:
            code = ioctl['code']
            h_source = HarnessGenerator.generate_cpp_harness(device_name, code)
            fname = f"harness_{code:x}.cpp"
            with open(out_dir / fname, 'w') as f:
                f.write(h_source)
            print(f" - Generated {fname}")
            
            # Generate corpus
            input_size = ioctl.get('input_size', 0)
            corpus_gen = CorpusGenerator(str(out_dir / f"corpus_{code:x}"))
            corpus_gen.generate_seeds_for_ioctl(code, input_size)
            
        print(f"Done. Output in {out_dir}")

    except Exception as e:
        print(f"Error generating harness: {e}")

def cmd_gen_report(args):
    """Generate HTML report from analysis data."""
    print(f"Generating report...")
    try:
        generator = HTMLReportGenerator()
        
        # Load interface data
        if Path(args.interface).exists():
            generator.load_interface(args.interface)
            print(f"  Loaded interface from {args.interface}")
        else:
            print(f"  Warning: Interface file not found: {args.interface}")
        
        # Load triage data if provided
        if args.triage and Path(args.triage).exists():
            generator.load_triage(args.triage)
            print(f"  Loaded triage from {args.triage}")
        
        # Generate report
        output_path = generator.generate(args.output)
        print(f"Report saved to: {output_path}")
        
    except Exception as e:
        print(f"Error generating report: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    main()
