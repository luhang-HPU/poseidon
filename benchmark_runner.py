#!/usr/bin/env python3
"""
Benchmark runner for CKKS DAG test programs.

It preserves fine-grained DAG operation names such as:
    [branch_add] add_a_b TIME: 1.37 ms

and also prints averaged total time for each benchmark program.
"""

from __future__ import annotations

import re
import subprocess
import sys
from collections import defaultdict
from pathlib import Path
from typing import DefaultDict, Dict, List, Tuple


GROUP_TOTAL_KEYS = {
    "fanout",
    "branch_add",
    "branch_quad",
    "branch_cross",
    "merge_tail",
}

TOP_LEVEL_ORDER = [
    "CKKS setup",
    "CKKS key generation",
    "CKKS runtime object setup",
    "Message preparation",
    "Plaintext reference",
    "CKKS encode",
    "CKKS encrypt",
    "CKKS DAG single-thread evaluation",
    "CKKS decrypt/decode",
    "Manual-parallel encode",
    "Manual-parallel encrypt",
    "Manual-parallel thread-pool setup",
    "CKKS DAG manual-parallel evaluation",
    "Manual-parallel decrypt/decode",
    "OMP hierarchical encode",
    "OMP hierarchical encrypt",
    "CKKS DAG OMP hierarchical evaluation",
    "OMP hierarchical decrypt/decode",
]


class BenchmarkCollector:
    """Collects and aggregates timing data from benchmark runs."""

    def __init__(self):
        self.data: DefaultDict[str, DefaultDict[str, List[float]]] = defaultdict(
            lambda: defaultdict(list)
        )

    def add_run(self, program_name: str, timing_data: Dict[str, float]) -> None:
        for key, value in timing_data.items():
            self.data[program_name][key].append(value)

    def get_averages(self, program_name: str) -> Dict[str, float]:
        averages: Dict[str, float] = {}
        if program_name in self.data:
            for key, values in self.data[program_name].items():
                if values:
                    averages[key] = sum(values) / len(values)
        return averages

    def get_all_programs(self) -> List[str]:
        return list(self.data.keys())


def parse_timing_output(output: str) -> Dict[str, float]:
    """
    Parse timing data from program output line by line.

    Examples:
        CKKS setup TIME: 123.45 ms
        [branch_add] add_a_b TIME: 1.37099 ms
    """
    timings: Dict[str, float] = {}
    pattern = re.compile(r"^\s*([^\n]+?)\s+TIME:\s+([0-9]+(?:\.[0-9]+)?)\s+ms\s*$")

    for line in output.splitlines():
        match = pattern.match(line)
        if not match:
            continue

        key = match.group(1).strip()
        value = float(match.group(2))
        timings[key] = value

    return timings


def run_benchmark(program_path: str, num_runs: int = 30) -> Tuple[str, List[Dict[str, float]]]:
    program_name = Path(program_path).name
    results: List[Dict[str, float]] = []

    print(f"\n{'=' * 70}")
    print(f"Running {program_name} ({num_runs} iterations)...")
    print(f"{'=' * 70}")

    for i in range(num_runs):
        try:
            result = subprocess.run(
                [program_path],
                capture_output=True,
                text=True,
                timeout=300,
            )

            if result.returncode != 0:
                print(f"  Run {i + 1}/{num_runs}: FAILED (exit code {result.returncode})")
                continue

            timings = parse_timing_output(result.stdout)
            if timings:
                results.append(timings)
                print(f"  Run {i + 1}/{num_runs}: OK ({len(timings)} timing points)")
            else:
                print(f"  Run {i + 1}/{num_runs}: FAILED (no timing data found)")

        except subprocess.TimeoutExpired:
            print(f"  Run {i + 1}/{num_runs}: TIMEOUT")
        except Exception as exc:
            print(f"  Run {i + 1}/{num_runs}: ERROR ({exc})")

    print(f"\nCompleted {len(results)}/{num_runs} successful runs")
    return program_name, results


def classify_metrics(averages: Dict[str, float]) -> Tuple[List[Tuple[str, float]], List[Tuple[str, float]], List[Tuple[str, float]], float]:
    top_level: List[Tuple[str, float]] = []
    group_totals: List[Tuple[str, float]] = []
    operations: List[Tuple[str, float]] = []

    for key, value in averages.items():
        if key.startswith("[") and "]" in key:
            operations.append((key, value))
        elif key in GROUP_TOTAL_KEYS:
            group_totals.append((key, value))
        else:
            top_level.append((key, value))

    top_level.sort(key=lambda item: (TOP_LEVEL_ORDER.index(item[0]) if item[0] in TOP_LEVEL_ORDER else len(TOP_LEVEL_ORDER), item[0]))
    group_totals.sort(key=lambda item: item[0])
    operations.sort(key=lambda item: item[0])

    total_time = sum(value for _, value in top_level)
    return top_level, group_totals, operations, total_time


def print_metric_rows(rows: List[Tuple[str, float]]) -> None:
    for key, value in rows:
        print(f"    {key:.<60} {value:>10.2f} ms")


def print_results(collector: BenchmarkCollector) -> None:
    print(f"\n\n{'=' * 70}")
    print("BENCHMARK RESULTS - AVERAGE TIMINGS")
    print(f"{'=' * 70}\n")

    for program_name in collector.get_all_programs():
        averages = collector.get_averages(program_name)

        print(f"\n{program_name}")
        print("-" * 70)

        if not averages:
            print("  No data collected")
            continue

        top_level, group_totals, operations, total_time = classify_metrics(averages)

        print("\n  Program Total:")
        print(f"    {'TOTAL'.ljust(60, '.')} {total_time:>10.2f} ms")

        if top_level:
            print("\n  Program-Level Timings:")
            print_metric_rows(top_level)

        if group_totals:
            print("\n  DAG Group Totals:")
            print_metric_rows(group_totals)

        if operations:
            print("\n  DAG Operation Timings:")
            print_metric_rows(operations)


def main() -> None:
    build_dir = Path("/home/guoshuai/github/poseidon/build/bin")

    programs = [
        build_dir / "test_ckks_dag_single_thread",
        build_dir / "test_ckks_dag_manual_parallel",
        build_dir / "test_ckks_dag_omp_hierarchical",
    ]

    missing = [p for p in programs if not p.exists()]
    if missing:
        print("Error: The following programs were not found:")
        for path in missing:
            print(f"  {path}")
        print("\nPlease build the project first.")
        sys.exit(1)

    num_runs = 30
    collector = BenchmarkCollector()

    print("\nBenchmark Configuration:")
    print(f"  Build directory: {build_dir}")
    print(f"  Number of runs per program: {num_runs}")
    print(f"  Total programs: {len(programs)}")

    for program in programs:
        program_name, results = run_benchmark(str(program), num_runs)
        if results:
            for timing_data in results:
                collector.add_run(program_name, timing_data)

    print_results(collector)
    print(f"\n{'=' * 70}\n")


if __name__ == "__main__":
    main()
