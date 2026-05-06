#!/usr/bin/env python3
"""
Run the four CKKS DAG example binaries repeatedly and summarize timings.

Targets:
  - 24-branch single-thread
  - 24-branch manual-parallel
  - 48-branch single-thread
  - 48-branch manual-parallel

The script lets you configure:
  - outer DAG worker count via POSEIDON_DAG_WORKERS
  - inner OpenMP thread count via OMP_NUM_THREADS
  - separate manual-parallel settings for 24-branch and 48-branch runs
"""

from __future__ import annotations

import argparse
import csv
import math
import os
import re
import statistics
import subprocess
import sys
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Sequence


REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_BUILD_DIR = REPO_ROOT / "build"
DEFAULT_RUNS = 5
DEFAULT_TIMEOUT_SECONDS = 1800

TIME_PATTERN = re.compile(
    r"^\s*(?P<name>.+?)\s+TIME:\s+(?P<value>[0-9]+(?:\.[0-9]+)?)\s+ms(?:\s+\|.*)?\s*$",
    re.MULTILINE,
)


@dataclass(frozen=True)
class TargetSpec:
    key: str
    binary_name: str
    branch_count: int
    mode: str

    @property
    def evaluation_label(self) -> str:
        return f"CKKS DAG {self.mode} {self.branch_count}-branch evaluation"


TARGETS: Sequence[TargetSpec] = (
    TargetSpec("24_single", "test_ckks_dag_single_thread_24_parallel", 24, "single-thread"),
    TargetSpec("24_manual", "test_ckks_dag_manual_parallel_24", 24, "manual-parallel"),
    TargetSpec("48_single", "test_ckks_dag_single_thread_48_parallel", 48, "single-thread"),
    TargetSpec("48_manual", "test_ckks_dag_manual_parallel_48", 48, "manual-parallel"),
)


@dataclass
class RunResult:
    run_index: int
    target_key: str
    binary_name: str
    branch_count: int
    mode: str
    outer_workers: int
    inner_threads: Optional[int]
    evaluation_ms: float
    full_pipeline_ms: Optional[float]
    example_total_ms: Optional[float]


def default_output_dir() -> Path:
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    return REPO_ROOT / "output" / f"ckks_dag_four_way_{timestamp}"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run the four CKKS DAG tasks repeatedly and summarize average timings."
    )
    parser.add_argument(
        "--runs",
        type=int,
        default=DEFAULT_RUNS,
        help=f"Successful runs per target. Default: {DEFAULT_RUNS}.",
    )
    parser.add_argument(
        "--outer-workers",
        type=int,
        default=None,
        help="Fallback outer DAG worker count for manual-parallel binaries. Default: branch count (24 or 48).",
    )
    parser.add_argument(
        "--inner-threads",
        type=int,
        default=None,
        help="Fallback OMP_NUM_THREADS value to export for all runs. Default: leave unset.",
    )
    parser.add_argument(
        "--outer-workers-24",
        type=int,
        default=None,
        help="Outer DAG worker count for 24_manual. Overrides --outer-workers for that target.",
    )
    parser.add_argument(
        "--outer-workers-48",
        type=int,
        default=None,
        help="Outer DAG worker count for 48_manual. Overrides --outer-workers for that target.",
    )
    parser.add_argument(
        "--inner-threads-24",
        type=int,
        default=None,
        help="OMP_NUM_THREADS for 24_manual. Overrides --inner-threads for that target.",
    )
    parser.add_argument(
        "--inner-threads-48",
        type=int,
        default=None,
        help="OMP_NUM_THREADS for 48_manual. Overrides --inner-threads for that target.",
    )
    parser.add_argument(
        "--build-dir",
        type=Path,
        default=DEFAULT_BUILD_DIR,
        help=f"CMake build directory. Default: {DEFAULT_BUILD_DIR}.",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=None,
        help="Directory for CSV outputs. Default: output/ckks_dag_four_way_<timestamp>.",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=DEFAULT_TIMEOUT_SECONDS,
        help=f"Timeout in seconds for each binary run. Default: {DEFAULT_TIMEOUT_SECONDS}.",
    )
    parser.add_argument(
        "--no-build",
        action="store_true",
        help="Do not build the four binaries before running.",
    )
    parser.add_argument(
        "--targets",
        choices=[target.key for target in TARGETS],
        nargs="+",
        help="Optional subset of targets to run.",
    )
    return parser.parse_args()


def build_targets(build_dir: Path, targets: Sequence[TargetSpec]) -> None:
    print("Configuring CMake...")
    subprocess.run(
        ["cmake", "-S", str(REPO_ROOT), "-B", str(build_dir)],
        check=True,
        cwd=REPO_ROOT,
    )

    for target in targets:
        print(f"Building {target.binary_name}...")
        subprocess.run(
            ["cmake", "--build", str(build_dir), "--target", target.binary_name, "-j2"],
            check=True,
            cwd=REPO_ROOT,
        )


def parse_time_metrics(output: str) -> Dict[str, float]:
    metrics: Dict[str, float] = {}
    for match in TIME_PATTERN.finditer(output):
        metrics[match.group("name").strip()] = float(match.group("value"))
    return metrics


def resolve_outer_workers(target: TargetSpec, args: argparse.Namespace) -> int:
    if target.mode != "manual-parallel":
        return 1
    configured: Optional[int]
    if target.key == "24_manual" and args.outer_workers_24 is not None:
        configured = args.outer_workers_24
    elif target.key == "48_manual" and args.outer_workers_48 is not None:
        configured = args.outer_workers_48
    else:
        configured = args.outer_workers
    if configured is None:
        return target.branch_count
    return max(1, configured)


def resolve_inner_threads(target: TargetSpec, args: argparse.Namespace) -> Optional[int]:
    if target.key == "24_manual" and args.inner_threads_24 is not None:
        return args.inner_threads_24
    if target.key == "48_manual" and args.inner_threads_48 is not None:
        return args.inner_threads_48
    return args.inner_threads


def run_once(
    binary: Path,
    target: TargetSpec,
    outer_workers: int,
    inner_threads: Optional[int],
    timeout: int,
) -> RunResult:
    env = os.environ.copy()
    env["POSEIDON_DAG_WORKERS"] = str(outer_workers)
    if inner_threads is None:
        env.pop("OMP_NUM_THREADS", None)
    else:
        env["OMP_NUM_THREADS"] = str(inner_threads)

    result = subprocess.run(
        [str(binary)],
        capture_output=True,
        text=True,
        timeout=timeout,
        env=env,
        cwd=REPO_ROOT,
    )
    if result.returncode != 0:
        raise RuntimeError(
            f"{binary.name} exited with code {result.returncode}\n"
            f"stdout:\n{result.stdout}\n"
            f"stderr:\n{result.stderr}"
        )

    metrics = parse_time_metrics(result.stdout)
    evaluation_ms = metrics.get(target.evaluation_label)
    if evaluation_ms is None:
        raise RuntimeError(
            f"Did not find evaluation timing '{target.evaluation_label}' in output."
        )

    return RunResult(
        run_index=0,
        target_key=target.key,
        binary_name=binary.name,
        branch_count=target.branch_count,
        mode=target.mode,
        outer_workers=outer_workers,
        inner_threads=inner_threads,
        evaluation_ms=evaluation_ms,
        full_pipeline_ms=metrics.get("CKKS full pipeline (setup -> decrypt/decode)"),
        example_total_ms=metrics.get("Example total (including reference build)"),
    )


def mean(values: Iterable[float]) -> float:
    seq = list(values)
    if not seq:
        return math.nan
    return sum(seq) / len(seq)


def stddev(values: Iterable[float]) -> float:
    seq = list(values)
    if len(seq) < 2:
        return 0.0
    return statistics.stdev(seq)


def write_raw_csv(path: Path, rows: Sequence[RunResult]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as fh:
        writer = csv.writer(fh)
        writer.writerow(
            [
                "run_index",
                "target_key",
                "binary_name",
                "branch_count",
                "mode",
                "outer_workers",
                "inner_threads",
                "evaluation_ms",
                "full_pipeline_ms",
                "example_total_ms",
            ]
        )
        for row in rows:
            writer.writerow(
                [
                    row.run_index,
                    row.target_key,
                    row.binary_name,
                    row.branch_count,
                    row.mode,
                    row.outer_workers,
                    "" if row.inner_threads is None else row.inner_threads,
                    f"{row.evaluation_ms:.6f}",
                    "" if row.full_pipeline_ms is None else f"{row.full_pipeline_ms:.6f}",
                    "" if row.example_total_ms is None else f"{row.example_total_ms:.6f}",
                ]
            )


def write_summary_csv(path: Path, rows: Sequence[RunResult]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as fh:
        writer = csv.writer(fh)
        writer.writerow(
            [
                "target_key",
                "binary_name",
                "branch_count",
                "mode",
                "runs",
                "outer_workers",
                "inner_threads",
                "evaluation_mean_ms",
                "evaluation_min_ms",
                "evaluation_max_ms",
                "evaluation_stddev_ms",
                "full_pipeline_mean_ms",
                "example_total_mean_ms",
            ]
        )
        for target in TARGETS:
            group = [row for row in rows if row.target_key == target.key]
            if not group:
                continue
            eval_values = [row.evaluation_ms for row in group]
            full_values = [row.full_pipeline_ms for row in group if row.full_pipeline_ms is not None]
            total_values = [row.example_total_ms for row in group if row.example_total_ms is not None]
            writer.writerow(
                [
                    target.key,
                    group[0].binary_name,
                    target.branch_count,
                    target.mode,
                    len(group),
                    group[0].outer_workers,
                    "" if group[0].inner_threads is None else group[0].inner_threads,
                    f"{mean(eval_values):.6f}",
                    f"{min(eval_values):.6f}",
                    f"{max(eval_values):.6f}",
                    f"{stddev(eval_values):.6f}",
                    "" if not full_values else f"{mean(full_values):.6f}",
                    "" if not total_values else f"{mean(total_values):.6f}",
                ]
            )


def print_summary(rows: Sequence[RunResult]) -> None:
    print("\n" + "=" * 96)
    print("CKKS DAG FOUR-WAY SUMMARY")
    print("=" * 96)
    header = (
        f"{'target':<14}"
        f"{'outer':>8}"
        f"{'inner':>8}"
        f"{'runs':>6}"
        f"{'eval_avg_ms':>16}"
        f"{'eval_std_ms':>14}"
        f"{'full_avg_ms':>14}"
    )
    print(header)
    print("-" * len(header))

    for target in TARGETS:
        group = [row for row in rows if row.target_key == target.key]
        if not group:
            continue
        eval_values = [row.evaluation_ms for row in group]
        full_values = [row.full_pipeline_ms for row in group if row.full_pipeline_ms is not None]
        inner = "unset" if group[0].inner_threads is None else str(group[0].inner_threads)
        full_avg = mean(full_values) if full_values else math.nan
        print(
            f"{target.key:<14}"
            f"{group[0].outer_workers:>8}"
            f"{inner:>8}"
            f"{len(group):>6}"
            f"{mean(eval_values):>16.6f}"
            f"{stddev(eval_values):>14.6f}"
            f"{full_avg:>14.6f}"
        )


def main() -> int:
    args = parse_args()
    if args.runs <= 0 or args.timeout <= 0:
        print("Error: --runs and --timeout must be > 0.", file=sys.stderr)
        return 1
    if args.outer_workers is not None and args.outer_workers <= 0:
        print("Error: --outer-workers must be > 0.", file=sys.stderr)
        return 1
    if args.inner_threads is not None and args.inner_threads <= 0:
        print("Error: --inner-threads must be > 0.", file=sys.stderr)
        return 1
    if args.outer_workers_24 is not None and args.outer_workers_24 <= 0:
        print("Error: --outer-workers-24 must be > 0.", file=sys.stderr)
        return 1
    if args.outer_workers_48 is not None and args.outer_workers_48 <= 0:
        print("Error: --outer-workers-48 must be > 0.", file=sys.stderr)
        return 1
    if args.inner_threads_24 is not None and args.inner_threads_24 <= 0:
        print("Error: --inner-threads-24 must be > 0.", file=sys.stderr)
        return 1
    if args.inner_threads_48 is not None and args.inner_threads_48 <= 0:
        print("Error: --inner-threads-48 must be > 0.", file=sys.stderr)
        return 1

    selected_targets = [
        target for target in TARGETS if args.targets is None or target.key in set(args.targets)
    ]
    if not selected_targets:
        print("Error: no targets selected.", file=sys.stderr)
        return 1

    build_dir = args.build_dir.resolve()
    if not args.no_build:
        try:
            build_targets(build_dir, selected_targets)
        except subprocess.CalledProcessError as exc:
            print(f"Error: build failed with exit code {exc.returncode}.", file=sys.stderr)
            return exc.returncode

    bin_dir = build_dir / "bin"
    binaries = {target.key: bin_dir / target.binary_name for target in selected_targets}
    missing = [binary for binary in binaries.values() if not binary.exists()]
    if missing:
        print("Error: missing binaries:", file=sys.stderr)
        for binary in missing:
            print(f"  {binary}", file=sys.stderr)
        print("Build first or run without --no-build.", file=sys.stderr)
        return 1

    all_rows: List[RunResult] = []
    for target in selected_targets:
        binary = binaries[target.key]
        outer_workers = resolve_outer_workers(target, args)
        inner_threads = resolve_inner_threads(target, args)
        print("\n" + "=" * 96)
        print(
            f"Running {target.key}: binary={binary.name}, runs={args.runs}, "
            f"outer_workers={outer_workers}, inner_threads={inner_threads if inner_threads is not None else 'unset'}"
        )
        print("=" * 96)

        successes = 0
        attempts = 0
        while successes < args.runs and attempts < args.runs:
            attempts += 1
            print(f"  Run {successes + 1}/{args.runs} ... ", end="", flush=True)
            try:
                row = run_once(
                    binary=binary,
                    target=target,
                    outer_workers=outer_workers,
                    inner_threads=inner_threads,
                    timeout=args.timeout,
                )
            except subprocess.TimeoutExpired:
                print("TIMEOUT")
                continue
            except Exception as exc:
                print(f"FAILED ({exc})")
                continue

            successes += 1
            row.run_index = successes
            all_rows.append(row)
            print(f"OK (evaluation={row.evaluation_ms:.6f} ms)")

        if successes < args.runs:
            print(f"Warning: only collected {successes}/{args.runs} successful runs for {target.key}")

    if not all_rows:
        print("Error: no successful runs collected.", file=sys.stderr)
        return 1

    output_dir = (args.output_dir or default_output_dir()).resolve()
    raw_csv = output_dir / "raw_runs.csv"
    summary_csv = output_dir / "summary.csv"
    write_raw_csv(raw_csv, all_rows)
    write_summary_csv(summary_csv, all_rows)
    print_summary(all_rows)
    print(f"\nRaw CSV written to: {raw_csv}")
    print(f"Summary CSV written to: {summary_csv}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
