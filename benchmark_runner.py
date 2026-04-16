#!/usr/bin/env python3
"""
Benchmark runner for CKKS DAG test programs.
Runs each test multiple times and computes average timing statistics.
"""

import subprocess
import re
import sys
from pathlib import Path
from collections import defaultdict
from typing import Dict, List, Tuple


class BenchmarkCollector:
    """Collects and aggregates timing data from benchmark runs."""
    
    def __init__(self):
        self.data = defaultdict(lambda: defaultdict(list))
    
    def add_run(self, program_name: str, timing_data: Dict[str, float]):
        """Add timing data from a single run."""
        for key, value in timing_data.items():
            self.data[program_name][key].append(value)
    
    def get_averages(self, program_name: str) -> Dict[str, float]:
        """Get average values for a program."""
        averages = {}
        if program_name in self.data:
            for key, values in self.data[program_name].items():
                if values:
                    averages[key] = sum(values) / len(values)
        return averages
    
    def get_all_programs(self) -> List[str]:
        """Get list of all programs."""
        return list(self.data.keys())


def parse_timing_output(output: str) -> Dict[str, float]:
    """
    Parse timing data from program output.
    Extracts all lines with 'TIME:' pattern.
    """
    timings = {}
    
    # Match lines like "CKKS setup TIME: 123.45 ms"
    # or "  branch_add TIME: 456.78 ms"
    pattern = r'([A-Za-z0-9_\s\-/\.]+?)\s+TIME:\s+([\d\.]+)\s+ms'
    
    for match in re.finditer(pattern, output):
        key = match.group(1).strip()
        value = float(match.group(2))
        timings[key] = value
    
    return timings


def run_benchmark(program_path: str, num_runs: int = 30) -> Tuple[str, List[Dict[str, float]]]:
    """
    Run a benchmark program multiple times and collect timing data.
    
    Returns:
        Tuple of (program_name, list of timing dictionaries)
    """
    program_name = Path(program_path).name
    results = []
    
    print(f"\n{'='*70}")
    print(f"Running {program_name} ({num_runs} iterations)...")
    print(f"{'='*70}")
    
    for i in range(num_runs):
        try:
            result = subprocess.run(
                [program_path],
                capture_output=True,
                text=True,
                timeout=300  # 5 minute timeout per run
            )
            
            if result.returncode != 0:
                print(f"  Run {i+1}/{num_runs}: FAILED (exit code {result.returncode})")
                continue
            
            timings = parse_timing_output(result.stdout)
            if timings:
                results.append(timings)
                print(f"  Run {i+1}/{num_runs}: OK ({len(timings)} timing points)")
            else:
                print(f"  Run {i+1}/{num_runs}: FAILED (no timing data found)")
                
        except subprocess.TimeoutExpired:
            print(f"  Run {i+1}/{num_runs}: TIMEOUT")
        except Exception as e:
            print(f"  Run {i+1}/{num_runs}: ERROR ({e})")
    
    print(f"\nCompleted {len(results)}/{num_runs} successful runs")
    return program_name, results


def print_results(collector: BenchmarkCollector):
    """Print aggregated benchmark results."""
    print(f"\n\n{'='*70}")
    print("BENCHMARK RESULTS - AVERAGE TIMINGS")
    print(f"{'='*70}\n")
    
    for program_name in collector.get_all_programs():
        averages = collector.get_averages(program_name)
        
        print(f"\n{program_name}")
        print("-" * 70)
        
        if not averages:
            print("  No data collected")
            continue
        
        # Group and sort for readability
        timing_items = sorted(averages.items())
        
        # System setup timings
        setup_keys = [k for k in timing_items if 'setup' in k[0].lower() or 'generation' in k[0].lower()]
        if setup_keys:
            print("\n  Setup & Key Generation:")
            for key, value in setup_keys:
                print(f"    {key:.<50} {value:>10.2f} ms")
        
        # Encode/Encrypt/Evaluation timings
        encode_keys = [k for k in timing_items if 'encode' in k[0].lower()]
        if encode_keys:
            print("\n  Encoding:")
            for key, value in encode_keys:
                print(f"    {key:.<50} {value:>10.2f} ms")
        
        encrypt_keys = [k for k in timing_items if 'encrypt' in k[0].lower()]
        if encrypt_keys:
            print("\n  Encryption:")
            for key, value in encrypt_keys:
                print(f"    {key:.<50} {value:>10.2f} ms")
        
        eval_keys = [k for k in timing_items if 'evaluation' in k[0].lower()]
        if eval_keys:
            print("\n  Evaluation:")
            for key, value in eval_keys:
                print(f"    {key:.<50} {value:>10.2f} ms")
        
        # Group timing details (branch_add, branch_quad, etc.)
        group_keys = [k for k in timing_items if 'group timing' in k[0].lower() or any(
            group in k[0].lower() for group in ['branch_add', 'branch_quad', 'branch_cross', 'merge_tail', 'fanout']
        )]
        if group_keys:
            print("\n  Operation Group Timings:")
            for key, value in group_keys:
                print(f"    {key:.<50} {value:>10.2f} ms")
        
        # Other timings
        other_keys = [k for k in timing_items if k not in [x[0] for x in setup_keys + encode_keys + encrypt_keys + eval_keys + group_keys]]
        if other_keys:
            print("\n  Other Timings:")
            for key, value in other_keys:
                print(f"    {key:.<50} {value:>10.2f} ms")


def main():
    """Main entry point."""
    build_dir = Path("/home/guoshuai/github/poseidon/build/bin")
    
    programs = [
        build_dir / "test_ckks_dag_single_thread",
        build_dir / "test_ckks_dag_manual_parallel",
        build_dir / "test_ckks_dag_omp_hierarchical",
    ]
    
    # Check if programs exist
    missing = [p for p in programs if not p.exists()]
    if missing:
        print("Error: The following programs were not found:")
        for p in missing:
            print(f"  {p}")
        print("\nPlease build the project first.")
        sys.exit(1)
    
    num_runs = 30
    collector = BenchmarkCollector()
    
    print(f"\nBenchmark Configuration:")
    print(f"  Build directory: {build_dir}")
    print(f"  Number of runs per program: {num_runs}")
    print(f"  Total programs: {len(programs)}")
    
    # Run each program
    for program in programs:
        program_name, results = run_benchmark(str(program), num_runs)
        if results:
            for timing_data in results:
                collector.add_run(program_name, timing_data)
    
    # Print results
    print_results(collector)
    
    print(f"\n{'='*70}\n")


if __name__ == "__main__":
    main()
