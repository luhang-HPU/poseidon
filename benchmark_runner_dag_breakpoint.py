#!/usr/bin/env python3
"""
Find the worker-count breakpoint for Poseidon CKKS DAG 24/48 branch examples.

The script is machine-portable: it detects CPU topology, generates a worker
sweep, runs single-thread baselines, then runs manual-parallel binaries with
POSEIDON_DAG_WORKERS set for each point.
"""

from __future__ import annotations

import argparse
import csv
import os
import platform
import re
import socket
import subprocess
import sys
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path
from statistics import mean
from typing import DefaultDict, Dict, Iterable, List, Optional, Sequence, Tuple


DEFAULT_RUNS = 5
DEFAULT_TIMEOUT_SECONDS = 900
DEFAULT_BUILD_DIR = Path("build")
DEFAULT_RAW_CSV = Path("ckks_dag_breakpoint_raw.csv")
DEFAULT_SUMMARY_CSV = Path("ckks_dag_breakpoint_summary.csv")
DEFAULT_REPORT = Path("ckks_dag_breakpoint_report.txt")

MANUAL_TARGETS = {
    24: "test_ckks_dag_manual_parallel_24",
    48: "test_ckks_dag_manual_parallel_48",
}

SINGLE_TARGETS = {
    24: "test_ckks_dag_single_thread_24_parallel",
    48: "test_ckks_dag_single_thread_48_parallel",
}


@dataclass(frozen=True)
class CpuInfo:
    machine_id: str
    hostname: str
    logical_cpus: int
    physical_cores: int
    sockets: int
    threads_per_core: int
    model_name: str


@dataclass
class RunMetrics:
    eval_ms: float
    avg_branch_ms: float
    max_branch_ms: float
    branch_work_sum_ms: float
    merge_tail_ms: float


@dataclass
class SummaryRow:
    machine_id: str
    logical_cpus: int
    physical_cores: int
    sockets: int
    threads_per_core: int
    core_budget: int
    branch_count: int
    workers: int
    omp_threads: str
    core_demand: int
    core_utilization: float
    oversubscribed: bool
    runs: int
    eval_avg_ms: float
    eval_min_ms: float
    eval_max_ms: float
    speedup_vs_single_thread: float
    avg_branch_time_ms: float
    max_branch_time_ms: float
    branch_work_sum_ms: float
    merge_tail_avg_ms: float


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Sweep Poseidon DAG worker counts and report breakpoint metrics."
    )
    parser.add_argument(
        "--runs",
        type=int,
        default=DEFAULT_RUNS,
        help=f"Successful runs per configuration. Default: {DEFAULT_RUNS}.",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=DEFAULT_TIMEOUT_SECONDS,
        help=f"Timeout seconds per single binary run. Default: {DEFAULT_TIMEOUT_SECONDS}.",
    )
    parser.add_argument(
        "--branch-counts",
        type=int,
        choices=sorted(MANUAL_TARGETS),
        nargs="+",
        default=sorted(MANUAL_TARGETS),
        help="Branch counts to test. Default: 24 48.",
    )
    parser.add_argument(
        "--omp-threads",
        "--rns-threads",
        dest="omp_threads",
        nargs="+",
        default=["1"],
        help="Inner RNS/OpenMP thread values to test, or 'auto'. Default: 1.",
    )
    parser.add_argument(
        "--workers",
        type=int,
        nargs="+",
        help="Explicit worker counts to test instead of auto-generated sweep.",
    )
    parser.add_argument(
        "--quick",
        action="store_true",
        help="Use a smaller worker sweep for fast validation.",
    )
    parser.add_argument(
        "--core-budget",
        choices=["physical", "logical"],
        default="physical",
        help="Core budget used for workers*inner_threads recommendations. Default: physical.",
    )
    parser.add_argument(
        "--core-budget-value",
        type=int,
        help="Explicit core budget. Overrides --core-budget.",
    )
    parser.add_argument(
        "--fit-core-budget",
        action="store_true",
        help="Skip manual-parallel configs where workers*inner_threads exceeds the core budget.",
    )
    parser.add_argument(
        "--build-dir",
        type=Path,
        default=DEFAULT_BUILD_DIR,
        help=f"CMake build directory. Default: {DEFAULT_BUILD_DIR}.",
    )
    parser.add_argument(
        "--no-build",
        action="store_true",
        help="Do not configure/build benchmark targets before running.",
    )
    parser.add_argument(
        "--raw-csv",
        type=Path,
        default=DEFAULT_RAW_CSV,
        help=f"Raw CSV output. Default: {DEFAULT_RAW_CSV}.",
    )
    parser.add_argument(
        "--summary-csv",
        type=Path,
        default=DEFAULT_SUMMARY_CSV,
        help=f"Summary CSV output. Default: {DEFAULT_SUMMARY_CSV}.",
    )
    parser.add_argument(
        "--report",
        type=Path,
        default=DEFAULT_REPORT,
        help=f"Text report output. Default: {DEFAULT_REPORT}.",
    )
    return parser.parse_args()


def positive_int(value: object, fallback: int) -> int:
    try:
        parsed = int(str(value).strip())
    except Exception:
        return fallback
    return parsed if parsed > 0 else fallback


def parse_lscpu() -> Dict[str, str]:
    try:
        result = subprocess.run(
            ["lscpu"],
            capture_output=True,
            text=True,
            check=True,
            timeout=10,
        )
    except Exception:
        return {}

    data: Dict[str, str] = {}
    for line in result.stdout.splitlines():
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        data[key.strip()] = value.strip()
    return data


def detect_cpu_info() -> CpuInfo:
    hostname = socket.gethostname()
    lscpu = parse_lscpu()
    logical = positive_int(lscpu.get("CPU(s)"), os.cpu_count() or 1)
    sockets = positive_int(lscpu.get("Socket(s)"), 1)
    cores_per_socket = positive_int(lscpu.get("Core(s) per socket"), 0)
    threads_per_core = positive_int(lscpu.get("Thread(s) per core"), 1)

    if cores_per_socket > 0:
        physical = cores_per_socket * sockets
    else:
        physical = max(1, logical // max(1, threads_per_core))

    model_name = lscpu.get("Model name", platform.processor() or "unknown")
    compact_model = re.sub(r"\s+", "_", model_name.strip())[:48]
    machine_id = f"{hostname}_{compact_model}_{physical}c{logical}t"
    return CpuInfo(
        machine_id=machine_id,
        hostname=hostname,
        logical_cpus=logical,
        physical_cores=physical,
        sockets=sockets,
        threads_per_core=threads_per_core,
        model_name=model_name,
    )


def clamp_worker(value: int, branch_count: int) -> int:
    return max(1, min(branch_count, value))


def round_positive(value: float) -> int:
    return max(1, int(round(value)))


def auto_worker_points(branch_count: int, cpu: CpuInfo, quick: bool) -> List[int]:
    if quick:
        candidates = {
            1,
            2,
            4,
            round_positive(cpu.physical_cores / 2),
            cpu.physical_cores,
            branch_count,
        }
    else:
        candidates = {
            1,
            2,
            3,
            4,
            6,
            8,
            12,
            16,
            round_positive(cpu.physical_cores / 4),
            round_positive(cpu.physical_cores / 2),
            cpu.physical_cores,
            round_positive(cpu.physical_cores * 1.5),
            cpu.logical_cpus,
            branch_count,
        }

    return sorted({clamp_worker(value, branch_count) for value in candidates})


def omp_thread_values(raw_values: Sequence[str], cpu: CpuInfo) -> List[str]:
    values: List[str] = []
    for raw in raw_values:
        if raw == "auto":
            candidates = [
                1,
                2,
                3,
                4,
                6,
                8,
                12,
                15,
                max(1, cpu.physical_cores // 2),
                cpu.physical_cores,
            ]
            values.extend(str(value) for value in candidates)
        else:
            parsed = positive_int(raw, 0)
            if parsed <= 0:
                raise ValueError(f"invalid --omp-threads value: {raw}")
            values.append(str(parsed))
    return sorted(set(values), key=lambda item: int(item))


def resolve_core_budget(args: argparse.Namespace, cpu: CpuInfo) -> int:
    if args.core_budget_value is not None:
        if args.core_budget_value <= 0:
            raise ValueError("--core-budget-value must be > 0")
        return args.core_budget_value
    if args.core_budget == "logical":
        return cpu.logical_cpus
    return cpu.physical_cores


def build_targets(build_dir: Path, targets: Sequence[str]) -> None:
    print("Configuring CMake...")
    subprocess.run(["cmake", "-S", ".", "-B", str(build_dir)], check=True)
    for target in targets:
        print(f"Building {target}...")
        subprocess.run(
            ["cmake", "--build", str(build_dir), "--target", target, "-j2"],
            check=True,
        )


def parse_metrics(output: str, branch_count: int, mode: str) -> RunMetrics:
    eval_pattern = re.compile(
        rf"^\s*CKKS DAG {re.escape(mode)} {branch_count}-branch evaluation TIME:\s+"
        r"(?P<value>[0-9]+(?:\.[0-9]+)?)\s+ms\s*$"
    )
    branch_pattern = re.compile(
        r"^\s*branch_\d+\s+TIME:\s+(?P<value>[0-9]+(?:\.[0-9]+)?)\s+ms\s*$"
    )
    merge_pattern = re.compile(
        r"^\s*merge_tail\s+TIME:\s+(?P<value>[0-9]+(?:\.[0-9]+)?)\s+ms\s*$"
    )

    eval_ms: Optional[float] = None
    branch_times: List[float] = []
    merge_tail_ms = 0.0

    for line in output.splitlines():
        eval_match = eval_pattern.match(line)
        if eval_match:
            eval_ms = float(eval_match.group("value"))
            continue

        branch_match = branch_pattern.match(line)
        if branch_match:
            branch_times.append(float(branch_match.group("value")))
            continue

        merge_match = merge_pattern.match(line)
        if merge_match:
            merge_tail_ms = float(merge_match.group("value"))

    if eval_ms is None:
        raise RuntimeError("evaluation timing was not found in output")
    if len(branch_times) != branch_count:
        raise RuntimeError(
            f"expected {branch_count} branch timings, found {len(branch_times)}"
        )

    return RunMetrics(
        eval_ms=eval_ms,
        avg_branch_ms=mean(branch_times),
        max_branch_ms=max(branch_times),
        branch_work_sum_ms=sum(branch_times),
        merge_tail_ms=merge_tail_ms,
    )


def run_binary(
    binary: Path,
    branch_count: int,
    mode: str,
    omp_threads: str,
    timeout: int,
    workers: Optional[int] = None,
) -> RunMetrics:
    env = os.environ.copy()
    env["OMP_NUM_THREADS"] = omp_threads
    env.setdefault("OMP_DYNAMIC", "FALSE")
    if workers is not None:
        env["POSEIDON_DAG_WORKERS"] = str(workers)
    else:
        env.pop("POSEIDON_DAG_WORKERS", None)

    result = subprocess.run(
        [str(binary)],
        capture_output=True,
        text=True,
        timeout=timeout,
        env=env,
    )
    if result.returncode != 0:
        raise RuntimeError(
            f"{binary.name} exited with {result.returncode}\n"
            f"stdout:\n{result.stdout}\n"
            f"stderr:\n{result.stderr}"
        )
    return parse_metrics(result.stdout, branch_count, mode)


def collect_successful_runs(
    binary: Path,
    branch_count: int,
    mode: str,
    omp_threads: str,
    timeout: int,
    requested_runs: int,
    workers: Optional[int] = None,
) -> List[RunMetrics]:
    runs: List[RunMetrics] = []
    label_workers = workers if workers is not None else 1
    for attempt in range(1, requested_runs + 1):
        print(
            f"  {mode} branch={branch_count} workers={label_workers} "
            f"omp={omp_threads} run {attempt}/{requested_runs} ... ",
            end="",
            flush=True,
        )
        try:
            metrics = run_binary(
                binary=binary,
                branch_count=branch_count,
                mode=mode,
                omp_threads=omp_threads,
                timeout=timeout,
                workers=workers,
            )
        except subprocess.TimeoutExpired:
            print("TIMEOUT")
            continue
        except Exception as exc:
            print(f"FAILED ({exc})")
            continue
        runs.append(metrics)
        print(f"OK eval={metrics.eval_ms:.3f} ms")
    return runs


def average_metrics(runs: List[RunMetrics]) -> RunMetrics:
    return RunMetrics(
        eval_ms=mean(run.eval_ms for run in runs),
        avg_branch_ms=mean(run.avg_branch_ms for run in runs),
        max_branch_ms=mean(run.max_branch_ms for run in runs),
        branch_work_sum_ms=mean(run.branch_work_sum_ms for run in runs),
        merge_tail_ms=mean(run.merge_tail_ms for run in runs),
    )


def write_raw_csv(path: Path, rows: List[Dict[str, object]]) -> None:
    fieldnames = [
        "machine_id",
        "logical_cpus",
        "physical_cores",
        "sockets",
        "threads_per_core",
        "core_budget",
        "branch_count",
        "workers",
        "omp_threads",
        "core_demand",
        "core_utilization",
        "oversubscribed",
        "mode",
        "run_index",
        "eval_ms",
        "avg_branch_time_ms",
        "max_branch_time_ms",
        "branch_work_sum_ms",
        "merge_tail_ms",
    ]
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def write_summary_csv(path: Path, rows: List[SummaryRow]) -> None:
    fieldnames = list(SummaryRow.__dataclass_fields__.keys())
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows:
            writer.writerow(row.__dict__)


def find_breakpoints(rows: List[SummaryRow]) -> Dict[Tuple[int, str], Dict[str, Optional[SummaryRow]]]:
    grouped: DefaultDict[Tuple[int, str], List[SummaryRow]] = defaultdict(list)
    for row in rows:
        grouped[(row.branch_count, row.omp_threads)].append(row)

    result: Dict[Tuple[int, str], Dict[str, Optional[SummaryRow]]] = {}
    for key, group_rows in grouped.items():
        ordered = sorted(group_rows, key=lambda row: row.workers)
        best = min(ordered, key=lambda row: row.eval_avg_ms)
        threshold = best.eval_avg_ms * 1.05
        saturation = next(row for row in ordered if row.eval_avg_ms <= threshold)
        regression = next(
            (row for row in ordered if row.workers > best.workers and row.eval_avg_ms > threshold),
            None,
        )
        result[key] = {
            "best": best,
            "saturation": saturation,
            "regression": regression,
        }
    return result


def group_rows_by_branch(rows: List[SummaryRow]) -> Dict[int, List[SummaryRow]]:
    grouped: DefaultDict[int, List[SummaryRow]] = defaultdict(list)
    for row in rows:
        grouped[row.branch_count].append(row)
    return dict(grouped)


def best_high_utilization_row(rows: List[SummaryRow], min_utilization: float = 0.80) -> Optional[SummaryRow]:
    candidates = [
        row
        for row in rows
        if not row.oversubscribed and row.core_utilization >= min_utilization
    ]
    if candidates:
        return min(candidates, key=lambda row: row.eval_avg_ms)

    under_budget = [row for row in rows if not row.oversubscribed]
    if not under_budget:
        return None
    return max(under_budget, key=lambda row: (row.core_utilization, -row.eval_avg_ms))


def format_ms(value: float) -> str:
    return f"{value:.3f} ms"


def write_report(path: Path, cpu: CpuInfo, rows: List[SummaryRow], core_budget: int) -> None:
    breakpoints = find_breakpoints(rows)
    branch_groups = group_rows_by_branch(rows)
    lines: List[str] = []
    lines.append("POSEIDON CKKS DAG OUTER+INNER THREAD BREAKPOINT REPORT")
    lines.append("=" * 80)
    lines.append(f"machine_id: {cpu.machine_id}")
    lines.append(f"hostname: {cpu.hostname}")
    lines.append(f"model: {cpu.model_name}")
    lines.append(
        f"cpu: physical={cpu.physical_cores}, logical={cpu.logical_cpus}, "
        f"sockets={cpu.sockets}, threads_per_core={cpu.threads_per_core}"
    )
    lines.append(f"core_budget: {core_budget}")
    lines.append("core_demand model: outer_workers * inner_RNS/OpenMP_threads")
    lines.append("")

    for branch_count, branch_rows in sorted(branch_groups.items()):
        global_best = min(branch_rows, key=lambda row: row.eval_avg_ms)
        under_budget_rows = [row for row in branch_rows if not row.oversubscribed]
        best_under_budget = (
            min(under_budget_rows, key=lambda row: row.eval_avg_ms)
            if under_budget_rows
            else None
        )
        best_high_util = best_high_utilization_row(branch_rows)

        lines.append(f"GLOBAL RECOMMENDATION branch_count={branch_count}")
        lines.append("-" * 80)
        lines.append(
            "fastest_tested="
            f"workers={global_best.workers}, inner={global_best.omp_threads}, "
            f"demand={global_best.core_demand}/{core_budget}, "
            f"oversubscribed={global_best.oversubscribed}, "
            f"eval={format_ms(global_best.eval_avg_ms)}"
        )
        if best_under_budget is not None:
            lines.append(
                "fastest_within_budget="
                f"workers={best_under_budget.workers}, inner={best_under_budget.omp_threads}, "
                f"demand={best_under_budget.core_demand}/{core_budget}, "
                f"util={best_under_budget.core_utilization:.3f}, "
                f"eval={format_ms(best_under_budget.eval_avg_ms)}"
            )
        if best_high_util is not None:
            lines.append(
                "recommended_full_core_config="
                f"workers={best_high_util.workers}, inner={best_high_util.omp_threads}, "
                f"demand={best_high_util.core_demand}/{core_budget}, "
                f"util={best_high_util.core_utilization:.3f}, "
                f"eval={format_ms(best_high_util.eval_avg_ms)}"
            )
        lines.append("")

    for (branch_count, omp_threads), points in sorted(breakpoints.items()):
        best = points["best"]
        saturation = points["saturation"]
        regression = points["regression"]
        assert best is not None
        assert saturation is not None

        lines.append(f"DETAIL branch_count={branch_count}, inner_RNS/OpenMP_threads={omp_threads}")
        lines.append("-" * 80)
        lines.append(
            "recommended_workers="
            f"{saturation.workers} "
            f"(saturation, eval {format_ms(saturation.eval_avg_ms)}, "
            f"speedup {saturation.speedup_vs_single_thread:.3f}x)"
        )
        lines.append(
            f"best_workers={best.workers} "
            f"(eval {format_ms(best.eval_avg_ms)}, "
            f"speedup {best.speedup_vs_single_thread:.3f}x)"
        )
        if regression is None:
            lines.append("regression_start_workers=(none in tested range)")
        else:
            lines.append(
                f"regression_start_workers={regression.workers} "
                f"(eval {format_ms(regression.eval_avg_ms)})"
            )
        lines.append("")
        lines.append(
            "workers | demand | oversub | eval_avg_ms | speedup | avg_branch_ms | "
            "max_branch_ms | merge_tail_ms"
        )
        for row in sorted(
            [row for row in rows if row.branch_count == branch_count and row.omp_threads == omp_threads],
            key=lambda item: item.workers,
        ):
            lines.append(
                f"{row.workers:>7} | {row.core_demand:>6} | "
                f"{str(row.oversubscribed):>7} | "
                f"{row.eval_avg_ms:>11.3f} | "
                f"{row.speedup_vs_single_thread:>7.3f} | "
                f"{row.avg_branch_time_ms:>13.3f} | "
                f"{row.max_branch_time_ms:>13.3f} | "
                f"{row.merge_tail_avg_ms:>13.3f}"
            )
        lines.append("")

    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def raw_row(
    cpu: CpuInfo,
    core_budget: int,
    branch_count: int,
    workers: int,
    omp_threads: str,
    mode: str,
    run_index: int,
    metrics: RunMetrics,
) -> Dict[str, object]:
    core_demand = workers * int(omp_threads)
    core_utilization = core_demand / core_budget
    return {
        "machine_id": cpu.machine_id,
        "logical_cpus": cpu.logical_cpus,
        "physical_cores": cpu.physical_cores,
        "sockets": cpu.sockets,
        "threads_per_core": cpu.threads_per_core,
        "core_budget": core_budget,
        "branch_count": branch_count,
        "workers": workers,
        "omp_threads": omp_threads,
        "core_demand": core_demand,
        "core_utilization": f"{core_utilization:.6f}",
        "oversubscribed": core_demand > core_budget,
        "mode": mode,
        "run_index": run_index,
        "eval_ms": f"{metrics.eval_ms:.6f}",
        "avg_branch_time_ms": f"{metrics.avg_branch_ms:.6f}",
        "max_branch_time_ms": f"{metrics.max_branch_ms:.6f}",
        "branch_work_sum_ms": f"{metrics.branch_work_sum_ms:.6f}",
        "merge_tail_ms": f"{metrics.merge_tail_ms:.6f}",
    }


def main() -> int:
    args = parse_args()
    if args.runs <= 0 or args.timeout <= 0:
        print("Error: --runs and --timeout must be > 0.", file=sys.stderr)
        return 1

    cpu = detect_cpu_info()
    try:
        omp_values = omp_thread_values(args.omp_threads, cpu)
        core_budget = resolve_core_budget(args, cpu)
    except ValueError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1

    print(
        f"Detected CPU: physical={cpu.physical_cores}, logical={cpu.logical_cpus}, "
        f"sockets={cpu.sockets}, threads/core={cpu.threads_per_core}"
    )
    print(f"Core budget for recommendations: {core_budget}")

    build_dir = args.build_dir.resolve()
    targets = []
    for branch_count in args.branch_counts:
        targets.extend([SINGLE_TARGETS[branch_count], MANUAL_TARGETS[branch_count]])

    if not args.no_build:
        try:
            build_targets(build_dir, sorted(set(targets)))
        except subprocess.CalledProcessError as exc:
            print(f"Error: build failed with exit code {exc.returncode}.", file=sys.stderr)
            return exc.returncode

    bin_dir = build_dir / "bin"
    for target in targets:
        binary = bin_dir / target
        if not binary.exists():
            print(f"Error: missing benchmark binary: {binary}", file=sys.stderr)
            return 1

    raw_rows: List[Dict[str, object]] = []
    summary_rows: List[SummaryRow] = []

    for branch_count in args.branch_counts:
        if args.workers:
            worker_points = sorted(
                {clamp_worker(worker, branch_count) for worker in args.workers}
            )
        else:
            worker_points = auto_worker_points(branch_count, cpu, args.quick)

        print(f"\nBranch {branch_count} worker sweep: {worker_points}")

        for omp_threads in omp_values:
            single_binary = bin_dir / SINGLE_TARGETS[branch_count]
            manual_binary = bin_dir / MANUAL_TARGETS[branch_count]

            print(f"\nSingle-thread baseline: branch={branch_count}, omp={omp_threads}")
            baseline_runs = collect_successful_runs(
                binary=single_binary,
                branch_count=branch_count,
                mode="single-thread",
                omp_threads=omp_threads,
                timeout=args.timeout,
                requested_runs=args.runs,
                workers=None,
            )
            if not baseline_runs:
                print(
                    f"Warning: no baseline data for branch={branch_count}, omp={omp_threads}; skipping",
                    file=sys.stderr,
                )
                continue

            for index, metrics in enumerate(baseline_runs, start=1):
                raw_rows.append(
                    raw_row(
                        cpu=cpu,
                        core_budget=core_budget,
                        branch_count=branch_count,
                        workers=1,
                        omp_threads=omp_threads,
                        mode="single-thread",
                        run_index=index,
                        metrics=metrics,
                    )
                )

            baseline = average_metrics(baseline_runs)

            for workers in worker_points:
                core_demand = workers * int(omp_threads)
                if args.fit_core_budget and core_demand > core_budget:
                    print(
                        f"\nSkipping branch={branch_count}, workers={workers}, "
                        f"omp={omp_threads}: demand {core_demand} > budget {core_budget}"
                    )
                    continue

                print(
                    f"\nManual-parallel: branch={branch_count}, workers={workers}, "
                    f"omp={omp_threads}, demand={core_demand}/{core_budget}"
                )
                runs = collect_successful_runs(
                    binary=manual_binary,
                    branch_count=branch_count,
                    mode="manual-parallel",
                    omp_threads=omp_threads,
                    timeout=args.timeout,
                    requested_runs=args.runs,
                    workers=workers,
                )
                if not runs:
                    print(
                        f"Warning: no data for branch={branch_count}, workers={workers}, omp={omp_threads}",
                        file=sys.stderr,
                    )
                    continue

                for index, metrics in enumerate(runs, start=1):
                    raw_rows.append(
                        raw_row(
                            cpu=cpu,
                            core_budget=core_budget,
                            branch_count=branch_count,
                            workers=workers,
                            omp_threads=omp_threads,
                            mode="manual-parallel",
                            run_index=index,
                            metrics=metrics,
                        )
                    )

                avg = average_metrics(runs)
                core_utilization = core_demand / core_budget
                summary_rows.append(
                    SummaryRow(
                        machine_id=cpu.machine_id,
                        logical_cpus=cpu.logical_cpus,
                        physical_cores=cpu.physical_cores,
                        sockets=cpu.sockets,
                        threads_per_core=cpu.threads_per_core,
                        core_budget=core_budget,
                        branch_count=branch_count,
                        workers=workers,
                        omp_threads=omp_threads,
                        core_demand=core_demand,
                        core_utilization=core_utilization,
                        oversubscribed=core_demand > core_budget,
                        runs=len(runs),
                        eval_avg_ms=avg.eval_ms,
                        eval_min_ms=min(run.eval_ms for run in runs),
                        eval_max_ms=max(run.eval_ms for run in runs),
                        speedup_vs_single_thread=baseline.eval_ms / avg.eval_ms,
                        avg_branch_time_ms=avg.avg_branch_ms,
                        max_branch_time_ms=avg.max_branch_ms,
                        branch_work_sum_ms=avg.branch_work_sum_ms,
                        merge_tail_avg_ms=avg.merge_tail_ms,
                    )
                )

    if not summary_rows:
        print("Error: no benchmark summary data collected.", file=sys.stderr)
        return 1

    write_raw_csv(args.raw_csv, raw_rows)
    write_summary_csv(args.summary_csv, summary_rows)
    write_report(args.report, cpu, summary_rows, core_budget)

    print(f"\nRaw data written to: {args.raw_csv.resolve()}")
    print(f"Summary written to: {args.summary_csv.resolve()}")
    print(f"Report written to: {args.report.resolve()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
