#!/usr/bin/env python3
"""
Benchmark runner for CKKS DAG test programs.

It preserves fine-grained DAG operation names such as:
    [branch_add] add_a_b TIME: 1.37 ms
    [branch_add] add_a_b CORES: 3,7

and also prints explicit full-pipeline/example-total timing and core participation.
"""

from __future__ import annotations

import re
import subprocess
import sys
from collections import defaultdict
from pathlib import Path
from typing import DefaultDict, Dict, List, Set, Tuple


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
    "CKKS full pipeline (setup -> decrypt/decode)",
    "Manual-parallel encode",
    "Manual-parallel encrypt",
    "Manual-parallel thread-pool setup",
    "CKKS DAG manual-parallel evaluation",
    "Manual-parallel decrypt/decode",
    "Manual-parallel full pipeline (shared setup included)",
    "OMP hierarchical encode",
    "OMP hierarchical encrypt",
    "CKKS DAG OMP hierarchical evaluation",
    "OMP hierarchical decrypt/decode",
    "OMP hierarchical full pipeline (shared setup included)",
    "Example total (including reference build)",
]

EXPLICIT_TOTAL_TIME_KEYS = [
    "Example total (including reference build)",
    "CKKS full pipeline (setup -> decrypt/decode)",
    "Manual-parallel full pipeline (shared setup included)",
    "OMP hierarchical full pipeline (shared setup included)",
]

ATOMIC_STAGE_TIME_KEYS = {
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
}


ParsedRun = Tuple[Dict[str, float], Dict[str, Set[int]]]


class BenchmarkCollector:
    """Collects and aggregates timing and core data from benchmark runs."""

    def __init__(self) -> None:
        self.time_data: DefaultDict[str, DefaultDict[str, List[float]]] = defaultdict(
            lambda: defaultdict(list)
        )
        self.core_data: DefaultDict[str, DefaultDict[str, Set[int]]] = defaultdict(
            lambda: defaultdict(set)
        )

    def add_run(self, program_name: str, times: Dict[str, float], cores: Dict[str, Set[int]]) -> None:
        for key, value in times.items():
            self.time_data[program_name][key].append(value)
        for key, cpu_set in cores.items():
            self.core_data[program_name][key].update(cpu_set)

    def get_averages(self, program_name: str) -> Dict[str, float]:
        averages: Dict[str, float] = {}
        if program_name in self.time_data:
            for key, values in self.time_data[program_name].items():
                if values:
                    averages[key] = sum(values) / len(values)
        return averages

    def get_core_unions(self, program_name: str) -> Dict[str, Set[int]]:
        unions: Dict[str, Set[int]] = {}
        if program_name in self.core_data:
            for key, values in self.core_data[program_name].items():
                unions[key] = set(values)
        return unions

    def get_all_programs(self) -> List[str]:
        return sorted(set(self.time_data.keys()) | set(self.core_data.keys()))


def parse_core_list(value: str) -> Set[int]:
    value = value.strip()
    if not value or value == "(unavailable)":
        return set()

    cores: Set[int] = set()
    for token in value.split(","):
        token = token.strip()
        if not token:
            continue
        try:
            cores.add(int(token))
        except ValueError:
            continue
    return cores


def parse_benchmark_output(output: str) -> ParsedRun:
    times: Dict[str, float] = {}
    cores: Dict[str, Set[int]] = {}
    time_pattern = re.compile(
        r"^\s*(.+?)\s+TIME(?:\s+\(([^)]+)\))?:\s+([0-9]+(?:\.[0-9]+)?)\s+ms(?:\s+\|\s+cores\s+([^|]+?))?(?:\s+\|.*)?\s*$"
    )
    core_pattern = re.compile(r"^\s*([^\n]+?)\s+CORES:\s+(.+?)\s*$")

    for line in output.splitlines():
        time_match = time_pattern.match(line)
        if time_match:
            key = time_match.group(1).strip()
            qualifier = time_match.group(2)
            if qualifier:
                key = f"{key} ({qualifier.strip()})"

            times[key] = float(time_match.group(3))
            inline_cores = time_match.group(4)
            if inline_cores:
                cores[key] = parse_core_list(inline_cores)
            continue

        core_match = core_pattern.match(line)
        if core_match:
            key = core_match.group(1).strip()
            cores[key] = parse_core_list(core_match.group(2))

    return times, cores


def run_benchmark(program_path: str, num_runs: int = 30) -> Tuple[str, List[ParsedRun]]:
    program_name = Path(program_path).name
    results: List[ParsedRun] = []

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

            times, cores = parse_benchmark_output(result.stdout)
            if times:
                results.append((times, cores))
                print(
                    f"  Run {i + 1}/{num_runs}: OK "
                    f"({len(times)} timing points, {len(cores)} core entries)"
                )
            else:
                print(f"  Run {i + 1}/{num_runs}: FAILED (no timing data found)")

        except subprocess.TimeoutExpired:
            print(f"  Run {i + 1}/{num_runs}: TIMEOUT")
        except Exception as exc:
            print(f"  Run {i + 1}/{num_runs}: ERROR ({exc})")

    print(f"\nCompleted {len(results)}/{num_runs} successful runs")
    return program_name, results


def format_cores(cores: Set[int]) -> str:
    if not cores:
        return "(unavailable)"
    return ",".join(str(cpu) for cpu in sorted(cores))


def sort_key(name: str) -> Tuple[int, str]:
    return (
        TOP_LEVEL_ORDER.index(name) if name in TOP_LEVEL_ORDER else len(TOP_LEVEL_ORDER),
        name,
    )


def classify_metrics(
    averages: Dict[str, float], core_unions: Dict[str, Set[int]]
) -> Tuple[
    List[Tuple[str, float]],
    List[Tuple[str, float]],
    List[Tuple[str, float]],
    Tuple[str, float] | None,
    Set[int],
]:
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

    top_level.sort(key=lambda item: sort_key(item[0]))
    group_totals.sort(key=lambda item: item[0])
    operations.sort(key=lambda item: item[0])

    explicit_total: Tuple[str, float] | None = None
    for key in EXPLICIT_TOTAL_TIME_KEYS:
        if key in averages:
            explicit_total = (key, averages[key])
            break

    if explicit_total is not None:
        total_cores = core_unions.get(explicit_total[0], set())
    else:
        total_cores: Set[int] = set()
        for key in ATOMIC_STAGE_TIME_KEYS:
            total_cores.update(core_unions.get(key, set()))

    return top_level, group_totals, operations, explicit_total, total_cores


def print_metric_rows(rows: List[Tuple[str, float]], core_unions: Dict[str, Set[int]]) -> None:
    for key, value in rows:
        print(
            f"    {key:.<60} {value:>10.2f} ms"
            f" | cores: {format_cores(core_unions.get(key, set()))}"
        )


def print_results(collector: BenchmarkCollector) -> None:
    print(f"\n\n{'=' * 70}")
    print("BENCHMARK RESULTS - AVERAGE TIMINGS")
    print(f"{'=' * 70}\n")

    for program_name in collector.get_all_programs():
        averages = collector.get_averages(program_name)
        core_unions = collector.get_core_unions(program_name)

        print(f"\n{program_name}")
        print("-" * 70)

        if not averages:
            print("  No data collected")
            continue

        top_level, group_totals, operations, explicit_total, total_cores = classify_metrics(
            averages, core_unions
        )

        print("\n  Program Total:")
        if explicit_total is not None:
            total_name, total_value = explicit_total
            print(
                f"    {total_name:.<60} {total_value:>10.2f} ms"
                f" | cores: {format_cores(total_cores)}"
            )
        else:
            fallback_total = sum(
                value for key, value in top_level if key in ATOMIC_STAGE_TIME_KEYS
            )
            print(
                f"    {'TOTAL (derived from atomic stages)'.ljust(60, '.')} "
                f"{fallback_total:>10.2f} ms | cores: {format_cores(total_cores)}"
            )

        if top_level:
            print("\n  Program-Level Timings:")
            print_metric_rows(top_level, core_unions)

        if group_totals:
            print("\n  DAG Group Totals:")
            print_metric_rows(group_totals, core_unions)

        if operations:
            print("\n  DAG Operation Timings:")
            print_metric_rows(operations, core_unions)


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

    num_runs = 10
    collector = BenchmarkCollector()

    print("\nBenchmark Configuration:")
    print(f"  Build directory: {build_dir}")
    print(f"  Number of runs per program: {num_runs}")
    print(f"  Total programs: {len(programs)}")

    for program in programs:
        program_name, results = run_benchmark(str(program), num_runs)
        for times, cores in results:
            collector.add_run(program_name, times, cores)

    print_results(collector)
    print(f"\n{'=' * 70}\n")


if __name__ == "__main__":
    main()
