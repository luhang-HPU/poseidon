#!/usr/bin/env python3
"""
Benchmark runner for examples/ckks/test_ckks_benchmarks.

It runs the CKKS benchmark binary with thread counts 1, 4, 8, 16, and 48
under degree 32768, collects all `TIME: ... ms` metrics, and prints averaged
results for each thread configuration.
"""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
from collections import defaultdict
from pathlib import Path
from typing import DefaultDict, Dict, Iterable, List


DEFAULT_THREADS = [1, 4, 8, 16, 48]
DEFAULT_DEGREE = 32768
DEFAULT_RUNS = 5
DEFAULT_ITERATIONS = 10
DEFAULT_TIMEOUT_SECONDS = 1800


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run CKKS benchmarks across multiple thread counts."
    )
    parser.add_argument(
        "--binary",
        type=Path,
        default=Path("/home/guoshuai/github/poseidon/build/bin/test_ckks_benchmarks"),
        help="Path to the CKKS benchmark binary.",
    )
    parser.add_argument(
        "--degree",
        type=int,
        default=DEFAULT_DEGREE,
        help="Polynomial degree passed to the benchmark binary.",
    )
    parser.add_argument(
        "--threads",
        type=int,
        nargs="+",
        default=DEFAULT_THREADS,
        help="Thread counts to test.",
    )
    parser.add_argument(
        "--runs",
        type=int,
        default=DEFAULT_RUNS,
        help="Number of repeated runs per thread count.",
    )
    parser.add_argument(
        "--iterations",
        type=int,
        default=DEFAULT_ITERATIONS,
        help="Iterations passed to the benchmark binary.",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=DEFAULT_TIMEOUT_SECONDS,
        help="Timeout in seconds for each benchmark process.",
    )
    return parser.parse_args()


def parse_timing_output(output: str) -> Dict[str, float]:
    pattern = r"^([A-Za-z0-9_ /.\-]+?)\s+TIME:\s+([\d\.]+)\s+ms$"
    timings: Dict[str, float] = {}

    for match in re.finditer(pattern, output, flags=re.MULTILINE):
        name = match.group(1).strip()
        value = float(match.group(2))
        timings[name] = value

    return timings


def average(values: Iterable[float]) -> float:
    values = list(values)
    if not values:
        return 0.0
    return sum(values) / len(values)


def run_once(binary: Path, degree: int, threads: int, iterations: int, timeout: int) -> Dict[str, float]:
    result = subprocess.run(
        [
            str(binary),
            "--degree",
            str(degree),
            "--threads",
            str(threads),
            "--iterations",
            str(iterations),
        ],
        capture_output=True,
        text=True,
        timeout=timeout,
    )

    if result.returncode != 0:
        raise RuntimeError(
            f"benchmark exited with code {result.returncode}\n"
            f"stdout:\n{result.stdout}\n"
            f"stderr:\n{result.stderr}"
        )

    timings = parse_timing_output(result.stdout)
    if not timings:
        raise RuntimeError("no timing data found in benchmark output")

    return timings


def summarize_by_thread(
    all_results: Dict[int, List[Dict[str, float]]]
) -> Dict[int, Dict[str, float]]:
    summary: Dict[int, Dict[str, float]] = {}

    for thread_count, runs in all_results.items():
        metric_values: DefaultDict[str, List[float]] = defaultdict(list)
        for run in runs:
            for metric, value in run.items():
                metric_values[metric].append(value)

        summary[thread_count] = {
            metric: average(values) for metric, values in sorted(metric_values.items())
        }

    return summary


def print_summary(summary: Dict[int, Dict[str, float]]) -> None:
    print("\n" + "=" * 90)
    print("CKKS BENCHMARK SUMMARY")
    print("=" * 90)

    for thread_count in sorted(summary):
        print(f"\nThreads = {thread_count}")
        print("-" * 90)
        for metric, value in summary[thread_count].items():
            print(f"{metric:.<70} {value:>12.6f} ms")


def main() -> int:
    args = parse_args()
    binary = args.binary.resolve()

    if not binary.exists():
        print(f"Error: benchmark binary not found: {binary}", file=sys.stderr)
        print("Please build the project first.", file=sys.stderr)
        return 1

    if args.degree <= 0 or args.runs <= 0 or args.iterations <= 0 or args.timeout <= 0:
        print("Error: degree, runs, iterations, and timeout must all be > 0.", file=sys.stderr)
        return 1

    if any(thread <= 0 for thread in args.threads):
        print("Error: thread counts must all be > 0.", file=sys.stderr)
        return 1

    print("Benchmark Configuration:")
    print(f"  Binary      : {binary}")
    print(f"  Degree      : {args.degree}")
    print(f"  Threads     : {args.threads}")
    print(f"  Runs        : {args.runs}")
    print(f"  Iterations  : {args.iterations}")
    print(f"  Timeout     : {args.timeout}s")

    all_results: Dict[int, List[Dict[str, float]]] = {}

    for thread_count in args.threads:
        print("\n" + "=" * 90)
        print(f"Running degree={args.degree}, threads={thread_count}")
        print("=" * 90)

        thread_runs: List[Dict[str, float]] = []
        for run_index in range(1, args.runs + 1):
            print(f"  Run {run_index}/{args.runs} ... ", end="", flush=True)
            try:
                timings = run_once(
                    binary=binary,
                    degree=args.degree,
                    threads=thread_count,
                    iterations=args.iterations,
                    timeout=args.timeout,
                )
            except subprocess.TimeoutExpired:
                print("TIMEOUT")
                continue
            except Exception as exc:
                print(f"FAILED ({exc})")
                continue

            thread_runs.append(timings)
            print(f"OK ({len(timings)} metrics)")

        if not thread_runs:
            print(f"  No successful runs for threads={thread_count}")
            continue

        all_results[thread_count] = thread_runs

    if not all_results:
        print("Error: no successful benchmark data collected.", file=sys.stderr)
        return 1

    summary = summarize_by_thread(all_results)
    print_summary(summary)
    print("\n" + "=" * 90)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
