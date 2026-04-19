#!/usr/bin/env python3
"""
Run the 24/48-branch CKKS DAG examples repeatedly and report average timings.

Default programs:
  - test_ckks_dag_single_thread_24_parallel
  - test_ckks_dag_manual_parallel_24
  - test_ckks_dag_single_thread_48_parallel
  - test_ckks_dag_manual_parallel_48
"""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
from collections import defaultdict
from pathlib import Path
from typing import DefaultDict, Dict, Iterable, List, Sequence, Tuple


DEFAULT_RUNS = 10
DEFAULT_TIMEOUT_SECONDS = 900
DEFAULT_BUILD_DIR = Path("build")
DEFAULT_OUTPUT = Path("ckks_dag_24_48_benchmark_summary.txt")

PROGRAMS: Sequence[Tuple[str, str, str]] = (
    (
        "24_ops_single_thread",
        "test_ckks_dag_single_thread_24_parallel",
        "test_ckks_dag_single_thread_24_parallel",
    ),
    (
        "24_ops_manual_parallel",
        "test_ckks_dag_manual_parallel_24",
        "test_ckks_dag_manual_parallel_24",
    ),
    (
        "48_ops_single_thread",
        "test_ckks_dag_single_thread_48_parallel",
        "test_ckks_dag_single_thread_48_parallel",
    ),
    (
        "48_ops_manual_parallel",
        "test_ckks_dag_manual_parallel_48",
        "test_ckks_dag_manual_parallel_48",
    ),
)

TOP_LEVEL_ORDER = [
    "CKKS setup",
    "CKKS key generation",
    "CKKS runtime object setup",
    "Message preparation",
    "CKKS encode",
    "CKKS encrypt",
    "Manual-parallel thread-pool setup",
    "CKKS DAG single-thread 24-branch evaluation",
    "CKKS DAG manual-parallel 24-branch evaluation",
    "CKKS DAG single-thread 48-branch evaluation",
    "CKKS DAG manual-parallel 48-branch evaluation",
    "CKKS decrypt/decode",
    "Plaintext reference",
    "CKKS full pipeline (setup -> decrypt/decode)",
    "Example total (including reference build)",
]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Benchmark 24/48-operation CKKS DAG single-thread and manual-parallel examples."
    )
    parser.add_argument(
        "--runs",
        type=int,
        default=DEFAULT_RUNS,
        help=f"Number of successful runs per program. Default: {DEFAULT_RUNS}.",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=DEFAULT_TIMEOUT_SECONDS,
        help=f"Timeout in seconds for each single program run. Default: {DEFAULT_TIMEOUT_SECONDS}.",
    )
    parser.add_argument(
        "--build-dir",
        type=Path,
        default=DEFAULT_BUILD_DIR,
        help=f"CMake build directory. Default: {DEFAULT_BUILD_DIR}.",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=DEFAULT_OUTPUT,
        help=f"Summary output file. Default: {DEFAULT_OUTPUT}.",
    )
    parser.add_argument(
        "--no-build",
        action="store_true",
        help="Do not build the four targets before running.",
    )
    parser.add_argument(
        "--only",
        choices=[label for label, _, _ in PROGRAMS],
        nargs="+",
        help="Run only selected benchmark labels.",
    )
    return parser.parse_args()


def average(values: Iterable[float]) -> float:
    values = list(values)
    if not values:
        return 0.0
    return sum(values) / len(values)


def metric_sort_key(name: str) -> Tuple[int, str]:
    if name in TOP_LEVEL_ORDER:
        return TOP_LEVEL_ORDER.index(name), name
    if name.endswith("TOTAL_TIME"):
        return len(TOP_LEVEL_ORDER), name
    if name.startswith("branch_"):
        return len(TOP_LEVEL_ORDER) + 1, name
    if name.startswith("["):
        return len(TOP_LEVEL_ORDER) + 2, name
    return len(TOP_LEVEL_ORDER) + 3, name


def parse_timing_output(output: str) -> Dict[str, float]:
    timings: Dict[str, float] = {}
    time_pattern = re.compile(
        r"^\s*(?P<name>.+?)\s+(?P<kind>TIME|TOTAL_TIME):\s+"
        r"(?P<value>[0-9]+(?:\.[0-9]+)?)\s+ms(?:\s+\|.*)?\s*$"
    )

    for line in output.splitlines():
        match = time_pattern.match(line)
        if not match:
            continue

        name = match.group("name").strip()
        kind = match.group("kind")
        if kind == "TOTAL_TIME":
            name = f"{name} TOTAL_TIME"
        timings[name] = float(match.group("value"))

    return timings


def build_targets(build_dir: Path, targets: Sequence[str]) -> None:
    print("Building benchmark targets...")
    subprocess.run(["cmake", "-S", ".", "-B", str(build_dir)], check=True)
    for target in targets:
        print(f"  building {target}")
        subprocess.run(
            ["cmake", "--build", str(build_dir), "--target", target, "-j2"],
            check=True,
        )


def run_once(binary: Path, timeout: int) -> Dict[str, float]:
    result = subprocess.run(
        [str(binary)],
        capture_output=True,
        text=True,
        timeout=timeout,
    )

    if result.returncode != 0:
        raise RuntimeError(
            f"program exited with code {result.returncode}\n"
            f"stdout:\n{result.stdout}\n"
            f"stderr:\n{result.stderr}"
        )

    timings = parse_timing_output(result.stdout)
    if not timings:
        raise RuntimeError("no timing data found in program output")
    return timings


def run_program(label: str, binary: Path, runs: int, timeout: int) -> List[Dict[str, float]]:
    results: List[Dict[str, float]] = []

    print("\n" + "=" * 90)
    print(f"Running {label}: {binary.name} ({runs} successful runs requested)")
    print("=" * 90)

    attempts = 0
    max_attempts = runs
    while len(results) < runs and attempts < max_attempts:
        attempts += 1
        print(f"  Run {len(results) + 1}/{runs} ... ", end="", flush=True)
        try:
            timings = run_once(binary, timeout)
        except subprocess.TimeoutExpired:
            print("TIMEOUT")
            continue
        except Exception as exc:
            print(f"FAILED ({exc})")
            continue

        results.append(timings)
        evaluation_keys = [key for key in timings if "evaluation" in key]
        if evaluation_keys:
            key = sorted(evaluation_keys)[0]
            print(f"OK ({key}: {timings[key]:.3f} ms)")
        else:
            print(f"OK ({len(timings)} timing items)")

    if len(results) < runs:
        print(f"  Warning: collected {len(results)}/{runs} successful runs")
    return results


def summarize_runs(runs: List[Dict[str, float]]) -> Dict[str, float]:
    grouped: DefaultDict[str, List[float]] = defaultdict(list)
    for run in runs:
        for metric, value in run.items():
            grouped[metric].append(value)
    return {metric: average(values) for metric, values in grouped.items()}


def format_summary(all_summaries: Dict[str, Dict[str, float]], run_counts: Dict[str, int]) -> str:
    lines: List[str] = []
    lines.append("=" * 100)
    lines.append("CKKS DAG 24/48 BENCHMARK AVERAGES")
    lines.append("=" * 100)
    lines.append("")

    for label in all_summaries:
        summary = all_summaries[label]
        lines.append(f"{label}  (successful runs: {run_counts[label]})")
        lines.append("-" * 100)
        for metric, value in sorted(summary.items(), key=lambda item: metric_sort_key(item[0])):
            lines.append(f"{metric:.<78} {value:>14.6f} ms")
        lines.append("")

    lines.append("=" * 100)
    return "\n".join(lines)


def main() -> int:
    args = parse_args()
    if args.runs <= 0 or args.timeout <= 0:
        print("Error: --runs and --timeout must be > 0.", file=sys.stderr)
        return 1

    selected = [
        item for item in PROGRAMS if args.only is None or item[0] in set(args.only)
    ]
    if not selected:
        print("Error: no benchmark programs selected.", file=sys.stderr)
        return 1

    build_dir = args.build_dir.resolve()
    if not args.no_build:
        try:
            build_targets(build_dir, [target for _, target, _ in selected])
        except subprocess.CalledProcessError as exc:
            print(f"Error: build failed with exit code {exc.returncode}.", file=sys.stderr)
            return exc.returncode

    bin_dir = build_dir / "bin"
    binaries = [(label, bin_dir / binary_name) for label, _, binary_name in selected]
    missing = [binary for _, binary in binaries if not binary.exists()]
    if missing:
        print("Error: missing benchmark binaries:", file=sys.stderr)
        for binary in missing:
            print(f"  {binary}", file=sys.stderr)
        print("Build first or run without --no-build.", file=sys.stderr)
        return 1

    all_summaries: Dict[str, Dict[str, float]] = {}
    run_counts: Dict[str, int] = {}
    for label, binary in binaries:
        runs = run_program(label, binary, args.runs, args.timeout)
        if not runs:
            print(f"  No successful runs for {label}; skipping summary")
            continue
        all_summaries[label] = summarize_runs(runs)
        run_counts[label] = len(runs)

    if not all_summaries:
        print("Error: no successful benchmark data collected.", file=sys.stderr)
        return 1

    summary_text = format_summary(all_summaries, run_counts)
    print("\n" + summary_text)

    args.output.write_text(summary_text + "\n", encoding="utf-8")
    print(f"\nSummary written to: {args.output.resolve()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
