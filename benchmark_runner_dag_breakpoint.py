#!/usr/bin/env python3
"""
Sweep Poseidon CKKS DAG outer workers and inner RNS/OpenMP threads.

The script is machine-portable: it detects CPU topology, probes the benchmark
binary for the RNS width, runs a 2D search over `(workers, omp_threads)`, then
emits raw CSV, summary CSV, best-point CSV, text reports, and line charts.
"""

from __future__ import annotations

import argparse
import csv
import math
import os
import platform
import re
import socket
import subprocess
import sys
from collections import defaultdict
from dataclasses import asdict, dataclass
from pathlib import Path
from statistics import mean, median, stdev
from typing import DefaultDict, Dict, Iterable, List, Optional, Sequence, Tuple

try:
    from PIL import Image, ImageDraw, ImageFont
except ImportError:  # pragma: no cover - optional dependency in some envs
    Image = None
    ImageDraw = None
    ImageFont = None


DEFAULT_RUNS = 5
DEFAULT_TIMEOUT_SECONDS = 900
DEFAULT_BUILD_DIR = Path("build")
DEFAULT_OUTPUT_DIR = Path(".")
DEFAULT_PLOT_FORMAT = "png"
DEFAULT_OBJECTIVE = "latency"

MANUAL_TARGETS = {
    24: "test_ckks_dag_manual_parallel_24",
    48: "test_ckks_dag_manual_parallel_48",
}

SINGLE_TARGETS = {
    24: "test_ckks_dag_single_thread_24_parallel",
    48: "test_ckks_dag_single_thread_48_parallel",
}

TIME_PATTERN = re.compile(
    r"^\s*(?P<name>.+?)\s+(?P<kind>TIME|TOTAL_TIME):\s+"
    r"(?P<value>[0-9]+(?:\.[0-9]+)?)\s+ms(?:\s+\|.*)?\s*$"
)
BRANCH_COUNT_PATTERN = re.compile(r"^\s*CKKS DAG independent branch count:\s+(?P<value>\d+)\s*$")
RNS_WIDTH_PATTERN = re.compile(r"^\s*CKKS coeff_modulus_size \(RNS width\):\s+(?P<value>\d+)\s*$")
OMP_REQUEST_PATTERN = re.compile(r"^\s*Requested OMP_NUM_THREADS:\s+(?P<value>\d+|unset)\s*$")
EFFECTIVE_WORKERS_PATTERN = re.compile(r"^\s*Effective DAG workers:\s+(?P<value>\d+)\s*$")
MANUAL_WORKERS_PATTERN = re.compile(r"^\s*Manual thread-pool workers:\s+(?P<value>\d+)\s*$")
BRANCH_TIME_PATTERN = re.compile(r"^\s*branch_\d+\s+TIME:\s+(?P<value>[0-9]+(?:\.[0-9]+)?)\s+ms\s*$")
MERGE_TIME_PATTERN = re.compile(r"^\s*merge_tail\s+TIME:\s+(?P<value>[0-9]+(?:\.[0-9]+)?)\s+ms\s*$")


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


@dataclass(frozen=True)
class BinaryMetadata:
    branch_count: int
    rns_width: int
    requested_omp_threads: Optional[int]
    effective_workers: int


@dataclass(frozen=True)
class MetricStats:
    mean: float
    median: float
    min: float
    max: float
    stddev: float


@dataclass
class ConfigRuns:
    branch_count: int
    rns_width: int
    workers: int
    omp_threads: int
    baseline_runs: List[RunMetrics]
    manual_runs: List[RunMetrics]


@dataclass
class SummaryRow:
    machine_id: str
    logical_cpus: int
    physical_cores: int
    sockets: int
    threads_per_core: int
    budget_mode: str
    core_budget: int
    branch_count: int
    rns_width: int
    workers: int
    omp_threads: int
    requested_omp_threads: int
    effective_workers: int
    core_demand: int
    core_utilization: float
    oversubscribed: bool
    runs: int
    eval_mean_ms: float
    eval_median_ms: float
    eval_stddev_ms: float
    eval_min_ms: float
    eval_max_ms: float
    baseline_eval_median_ms: float
    speedup_vs_single_thread_mean: float
    speedup_vs_single_thread_median: float
    avg_branch_time_mean_ms: float
    max_branch_time_mean_ms: float
    branch_work_sum_mean_ms: float
    merge_tail_mean_ms: float


@dataclass
class BestPointRow:
    machine_id: str
    budget_mode: str
    branch_count: int
    recommendation_class: str
    workers: int
    inner_threads: int
    core_budget: int
    core_demand: int
    core_utilization: float
    oversubscribed: bool
    eval_median_ms: float
    eval_mean_ms: float
    eval_stddev_ms: float
    speedup_vs_single_thread_median: float
    rns_width: int


@dataclass(frozen=True)
class OutputBundle:
    raw_csv: Path
    summary_csv: Path
    report_txt: Path
    best_points_csv: Path
    plot_dir: Path


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Search CKKS DAG worker/inner-thread sweet spots and generate reports."
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
        default=["auto"],
        help="Inner RNS/OpenMP thread values to test, or 'auto'. Default: auto.",
    )
    parser.add_argument(
        "--workers",
        type=int,
        nargs="+",
        help="Explicit worker counts to test instead of the default sweep.",
    )
    parser.add_argument(
        "--quick",
        action="store_true",
        help="Use a sparse worker sweep for fast validation.",
    )
    parser.add_argument(
        "--objective",
        choices=["latency", "dual"],
        default=DEFAULT_OBJECTIVE,
        help="Recommendation objective. Default: latency.",
    )
    parser.add_argument(
        "--budget-mode",
        choices=["physical", "logical", "both"],
        default=None,
        help="Budget view to materialize. Default: both.",
    )
    parser.add_argument(
        "--core-budget",
        choices=["physical", "logical"],
        default=None,
        help=argparse.SUPPRESS,
    )
    parser.add_argument(
        "--core-budget-value",
        type=int,
        help="Explicit core budget value. Overrides detected physical/logical budgets.",
    )
    parser.add_argument(
        "--allow-oversubscribe",
        action="store_true",
        help="Include configs whose demand exceeds the selected maximum budget.",
    )
    parser.add_argument(
        "--fit-core-budget",
        action="store_true",
        help="Deprecated inverse of --allow-oversubscribe.",
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
        "--output-dir",
        type=Path,
        default=DEFAULT_OUTPUT_DIR,
        help="Directory for all generated outputs. Default: current directory.",
    )
    parser.add_argument(
        "--raw-csv",
        type=Path,
        help="Override raw CSV path when generating a single budget mode.",
    )
    parser.add_argument(
        "--summary-csv",
        type=Path,
        help="Override summary CSV path when generating a single budget mode.",
    )
    parser.add_argument(
        "--report",
        type=Path,
        help="Override report path when generating a single budget mode.",
    )
    parser.add_argument(
        "--best-points-csv",
        type=Path,
        help="Override best-points CSV path when generating a single budget mode.",
    )
    parser.add_argument(
        "--plot-dir",
        type=Path,
        help="Override plot directory when generating a single budget mode.",
    )
    parser.add_argument(
        "--plot-format",
        choices=["png", "none"],
        default=DEFAULT_PLOT_FORMAT,
        help=f"Plot format. Default: {DEFAULT_PLOT_FORMAT}.",
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


def resolve_budget_modes(args: argparse.Namespace) -> List[str]:
    if args.budget_mode is not None:
        if args.budget_mode == "both":
            return ["physical", "logical"]
        return [args.budget_mode]
    if args.core_budget is not None:
        return [args.core_budget]
    return ["physical", "logical"]


def resolve_core_budget(mode: str, args: argparse.Namespace, cpu: CpuInfo) -> int:
    if args.core_budget_value is not None:
        if args.core_budget_value <= 0:
            raise ValueError("--core-budget-value must be > 0")
        return args.core_budget_value
    if mode == "logical":
        return cpu.logical_cpus
    return cpu.physical_cores


def resolve_output_bundles(args: argparse.Namespace, budget_modes: Sequence[str]) -> Dict[str, OutputBundle]:
    if len(budget_modes) > 1 and any(
        value is not None
        for value in (
            args.raw_csv,
            args.summary_csv,
            args.report,
            args.best_points_csv,
            args.plot_dir,
        )
    ):
        raise ValueError(
            "Custom --raw-csv/--summary-csv/--report/--best-points-csv/--plot-dir "
            "can only be used with a single --budget-mode."
        )

    output_dir = args.output_dir.resolve()
    bundles: Dict[str, OutputBundle] = {}
    for budget_mode in budget_modes:
        if len(budget_modes) == 1:
            raw_csv = (args.raw_csv or output_dir / f"{budget_mode}_raw.csv").resolve()
            summary_csv = (args.summary_csv or output_dir / f"{budget_mode}_summary.csv").resolve()
            report_txt = (args.report or output_dir / f"{budget_mode}_report.txt").resolve()
            best_points_csv = (
                args.best_points_csv or output_dir / f"{budget_mode}_best_points.csv"
            ).resolve()
            plot_dir = (args.plot_dir or output_dir / "plots").resolve()
        else:
            raw_csv = (output_dir / f"{budget_mode}_raw.csv").resolve()
            summary_csv = (output_dir / f"{budget_mode}_summary.csv").resolve()
            report_txt = (output_dir / f"{budget_mode}_report.txt").resolve()
            best_points_csv = (output_dir / f"{budget_mode}_best_points.csv").resolve()
            plot_dir = (output_dir / "plots").resolve()

        bundles[budget_mode] = OutputBundle(
            raw_csv=raw_csv,
            summary_csv=summary_csv,
            report_txt=report_txt,
            best_points_csv=best_points_csv,
            plot_dir=plot_dir,
        )
    return bundles


def ensure_parent(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)


def clamp_worker(value: int, branch_count: int) -> int:
    return max(1, min(branch_count, value))


def round_positive(value: float) -> int:
    return max(1, int(round(value)))


def auto_worker_points(branch_count: int, cpu: CpuInfo, quick: bool) -> List[int]:
    if quick:
        candidates = {
            1,
            2,
            3,
            4,
            6,
            8,
            round_positive(branch_count / 2),
            branch_count,
            round_positive(cpu.physical_cores / 2),
        }
        return sorted({clamp_worker(value, branch_count) for value in candidates})
    return list(range(1, branch_count + 1))


def resolve_omp_values(raw_values: Sequence[str], rns_width: int) -> List[int]:
    values: List[int] = []
    for raw in raw_values:
        if raw == "auto":
            values.extend(range(1, rns_width + 1))
            continue
        parsed = positive_int(raw, 0)
        if parsed <= 0:
            raise ValueError(f"invalid --omp-threads value: {raw}")
        values.append(parsed)
    return sorted(set(values))


def build_targets(build_dir: Path, targets: Sequence[str]) -> None:
    print("Configuring CMake...")
    subprocess.run(["cmake", "-S", ".", "-B", str(build_dir)], check=True)
    for target in sorted(set(targets)):
        print(f"Building {target}...")
        subprocess.run(
            ["cmake", "--build", str(build_dir), "--target", target, "-j2"],
            check=True,
        )


def parse_run_output(
    output: str,
    branch_count: int,
    mode: str,
    expected_workers: int,
) -> Tuple[RunMetrics, BinaryMetadata]:
    eval_pattern = re.compile(
        rf"^\s*CKKS DAG {re.escape(mode)} {branch_count}-branch evaluation TIME:\s+"
        r"(?P<value>[0-9]+(?:\.[0-9]+)?)\s+ms\s*$"
    )

    eval_ms: Optional[float] = None
    actual_branch_count: Optional[int] = None
    rns_width: Optional[int] = None
    requested_omp_threads: Optional[int] = None
    actual_workers: Optional[int] = None
    branch_times: List[float] = []
    merge_tail_ms = 0.0

    for line in output.splitlines():
        match = BRANCH_COUNT_PATTERN.match(line)
        if match:
            actual_branch_count = int(match.group("value"))
            continue

        match = RNS_WIDTH_PATTERN.match(line)
        if match:
            rns_width = int(match.group("value"))
            continue

        match = OMP_REQUEST_PATTERN.match(line)
        if match:
            value = match.group("value")
            requested_omp_threads = None if value == "unset" else int(value)
            continue

        match = EFFECTIVE_WORKERS_PATTERN.match(line)
        if match:
            actual_workers = int(match.group("value"))
            continue

        match = MANUAL_WORKERS_PATTERN.match(line)
        if match and actual_workers is None:
            actual_workers = int(match.group("value"))
            continue

        match = eval_pattern.match(line)
        if match:
            eval_ms = float(match.group("value"))
            continue

        match = BRANCH_TIME_PATTERN.match(line)
        if match:
            branch_times.append(float(match.group("value")))
            continue

        match = MERGE_TIME_PATTERN.match(line)
        if match:
            merge_tail_ms = float(match.group("value"))

    if eval_ms is None:
        raise RuntimeError("evaluation timing was not found in output")
    if actual_branch_count is not None and actual_branch_count != branch_count:
        raise RuntimeError(
            f"branch count mismatch: expected {branch_count}, output reported {actual_branch_count}"
        )
    if actual_workers is None:
        actual_workers = expected_workers
    if actual_workers != expected_workers:
        raise RuntimeError(
            f"effective worker mismatch: expected {expected_workers}, output used {actual_workers}"
        )
    if len(branch_times) != branch_count:
        raise RuntimeError(f"expected {branch_count} branch timings, found {len(branch_times)}")
    if rns_width is None:
        raise RuntimeError("RNS width metadata was not found in output")

    return (
        RunMetrics(
            eval_ms=eval_ms,
            avg_branch_ms=mean(branch_times),
            max_branch_ms=max(branch_times),
            branch_work_sum_ms=sum(branch_times),
            merge_tail_ms=merge_tail_ms,
        ),
        BinaryMetadata(
            branch_count=branch_count,
            rns_width=rns_width,
            requested_omp_threads=requested_omp_threads,
            effective_workers=actual_workers,
        ),
    )


def run_binary(
    binary: Path,
    branch_count: int,
    mode: str,
    omp_threads: int,
    timeout: int,
    workers: Optional[int],
) -> Tuple[RunMetrics, BinaryMetadata]:
    env = os.environ.copy()
    env["OMP_NUM_THREADS"] = str(omp_threads)
    env.setdefault("OMP_DYNAMIC", "FALSE")
    if workers is not None:
        env["POSEIDON_DAG_WORKERS"] = str(workers)
        expected_workers = workers
    else:
        env.pop("POSEIDON_DAG_WORKERS", None)
        expected_workers = 1

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

    metrics, metadata = parse_run_output(
        result.stdout,
        branch_count=branch_count,
        mode=mode,
        expected_workers=expected_workers,
    )
    if metadata.requested_omp_threads is not None and metadata.requested_omp_threads != omp_threads:
        raise RuntimeError(
            f"OMP thread mismatch: requested {omp_threads}, output reported {metadata.requested_omp_threads}"
        )
    return metrics, metadata


def collect_successful_runs(
    binary: Path,
    branch_count: int,
    mode: str,
    omp_threads: int,
    timeout: int,
    requested_runs: int,
    workers: Optional[int],
) -> Tuple[List[RunMetrics], Optional[BinaryMetadata]]:
    runs: List[RunMetrics] = []
    metadata: Optional[BinaryMetadata] = None
    label_workers = workers if workers is not None else 1

    for attempt in range(1, requested_runs + 1):
        print(
            f"  {mode} branch={branch_count} workers={label_workers} "
            f"omp={omp_threads} run {attempt}/{requested_runs} ... ",
            end="",
            flush=True,
        )
        try:
            metrics, current_metadata = run_binary(
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

        if metadata is None:
            metadata = current_metadata
        elif metadata.rns_width != current_metadata.rns_width:
            raise RuntimeError(
                f"inconsistent RNS width across runs: {metadata.rns_width} vs {current_metadata.rns_width}"
            )

        runs.append(metrics)
        print(f"OK eval={metrics.eval_ms:.3f} ms")

    return runs, metadata


def probe_binary_metadata(binary: Path, branch_count: int, timeout: int) -> BinaryMetadata:
    print(f"Probing metadata for branch={branch_count} using {binary.name} ...")
    _, metadata = run_binary(
        binary=binary,
        branch_count=branch_count,
        mode="single-thread",
        omp_threads=1,
        timeout=timeout,
        workers=None,
    )
    return metadata


def compute_metric_stats(values: Iterable[float]) -> MetricStats:
    items = list(values)
    if not items:
        raise ValueError("cannot compute stats for empty values")
    return MetricStats(
        mean=mean(items),
        median=median(items),
        min=min(items),
        max=max(items),
        stddev=stdev(items) if len(items) > 1 else 0.0,
    )


def core_budget_limit(
    budget_modes: Sequence[str],
    budgets: Dict[str, int],
    allow_oversubscribe: bool,
    fit_core_budget: bool,
) -> Optional[int]:
    if allow_oversubscribe:
        return None
    if fit_core_budget:
        return min(budgets[mode] for mode in budget_modes)
    return max(budgets[mode] for mode in budget_modes)


def raw_row(
    cpu: CpuInfo,
    budget_mode: str,
    core_budget: int,
    branch_count: int,
    rns_width: int,
    mode: str,
    requested_workers: int,
    effective_workers: int,
    omp_threads: int,
    run_index: int,
    metrics: RunMetrics,
) -> Dict[str, object]:
    core_demand = effective_workers * omp_threads
    core_utilization = core_demand / core_budget
    return {
        "machine_id": cpu.machine_id,
        "logical_cpus": cpu.logical_cpus,
        "physical_cores": cpu.physical_cores,
        "sockets": cpu.sockets,
        "threads_per_core": cpu.threads_per_core,
        "budget_mode": budget_mode,
        "core_budget": core_budget,
        "branch_count": branch_count,
        "rns_width": rns_width,
        "mode": mode,
        "requested_workers": requested_workers,
        "effective_workers": effective_workers,
        "omp_threads": omp_threads,
        "requested_omp_threads": omp_threads,
        "core_demand": core_demand,
        "core_utilization": f"{core_utilization:.6f}",
        "oversubscribed": core_demand > core_budget,
        "run_index": run_index,
        "eval_ms": f"{metrics.eval_ms:.6f}",
        "avg_branch_time_ms": f"{metrics.avg_branch_ms:.6f}",
        "max_branch_time_ms": f"{metrics.max_branch_ms:.6f}",
        "branch_work_sum_ms": f"{metrics.branch_work_sum_ms:.6f}",
        "merge_tail_ms": f"{metrics.merge_tail_ms:.6f}",
    }


def build_summary_rows(
    cpu: CpuInfo,
    budget_mode: str,
    core_budget: int,
    configs: Sequence[ConfigRuns],
) -> List[SummaryRow]:
    rows: List[SummaryRow] = []
    for config in configs:
        eval_stats = compute_metric_stats(run.eval_ms for run in config.manual_runs)
        baseline_eval_stats = compute_metric_stats(run.eval_ms for run in config.baseline_runs)
        avg_branch_mean = mean(run.avg_branch_ms for run in config.manual_runs)
        max_branch_mean = mean(run.max_branch_ms for run in config.manual_runs)
        branch_work_sum_mean = mean(run.branch_work_sum_ms for run in config.manual_runs)
        merge_tail_mean = mean(run.merge_tail_ms for run in config.manual_runs)
        core_demand = config.workers * config.omp_threads
        core_utilization = core_demand / core_budget
        rows.append(
            SummaryRow(
                machine_id=cpu.machine_id,
                logical_cpus=cpu.logical_cpus,
                physical_cores=cpu.physical_cores,
                sockets=cpu.sockets,
                threads_per_core=cpu.threads_per_core,
                budget_mode=budget_mode,
                core_budget=core_budget,
                branch_count=config.branch_count,
                rns_width=config.rns_width,
                workers=config.workers,
                omp_threads=config.omp_threads,
                requested_omp_threads=config.omp_threads,
                effective_workers=config.workers,
                core_demand=core_demand,
                core_utilization=core_utilization,
                oversubscribed=core_demand > core_budget,
                runs=len(config.manual_runs),
                eval_mean_ms=eval_stats.mean,
                eval_median_ms=eval_stats.median,
                eval_stddev_ms=eval_stats.stddev,
                eval_min_ms=eval_stats.min,
                eval_max_ms=eval_stats.max,
                baseline_eval_median_ms=baseline_eval_stats.median,
                speedup_vs_single_thread_mean=baseline_eval_stats.mean / eval_stats.mean,
                speedup_vs_single_thread_median=baseline_eval_stats.median / eval_stats.median,
                avg_branch_time_mean_ms=avg_branch_mean,
                max_branch_time_mean_ms=max_branch_mean,
                branch_work_sum_mean_ms=branch_work_sum_mean,
                merge_tail_mean_ms=merge_tail_mean,
            )
        )
    return rows


def find_breakpoints(rows: Sequence[SummaryRow]) -> Dict[Tuple[int, int], Dict[str, Optional[SummaryRow]]]:
    grouped: DefaultDict[Tuple[int, int], List[SummaryRow]] = defaultdict(list)
    for row in rows:
        grouped[(row.branch_count, row.omp_threads)].append(row)

    result: Dict[Tuple[int, int], Dict[str, Optional[SummaryRow]]] = {}
    for key, group_rows in grouped.items():
        ordered = sorted(group_rows, key=lambda row: row.workers)
        best = min(ordered, key=lambda row: row.eval_median_ms)
        threshold = best.eval_median_ms * 1.05
        saturation = next(row for row in ordered if row.eval_median_ms <= threshold)
        regression = next(
            (
                row
                for row in ordered
                if row.workers > best.workers and row.eval_median_ms > threshold
            ),
            None,
        )
        result[key] = {
            "best": best,
            "saturation": saturation,
            "regression": regression,
        }
    return result


def build_best_point_rows(rows: Sequence[SummaryRow]) -> List[BestPointRow]:
    grouped: DefaultDict[int, List[SummaryRow]] = defaultdict(list)
    for row in rows:
        grouped[row.branch_count].append(row)

    results: List[BestPointRow] = []
    for branch_count, branch_rows in sorted(grouped.items()):
        absolute_best = min(branch_rows, key=lambda row: row.eval_median_ms)
        within_budget = [row for row in branch_rows if not row.oversubscribed]
        budget_best = min(within_budget, key=lambda row: row.eval_median_ms) if within_budget else None

        results.append(best_point_row_from_summary(absolute_best, "absolute_best"))
        if budget_best is not None:
            results.append(
                best_point_row_from_summary(
                    budget_best, f"best_within_{absolute_best.budget_mode}_budget"
                )
            )
    return results


def best_point_row_from_summary(row: SummaryRow, recommendation_class: str) -> BestPointRow:
    return BestPointRow(
        machine_id=row.machine_id,
        budget_mode=row.budget_mode,
        branch_count=row.branch_count,
        recommendation_class=recommendation_class,
        workers=row.workers,
        inner_threads=row.omp_threads,
        core_budget=row.core_budget,
        core_demand=row.core_demand,
        core_utilization=row.core_utilization,
        oversubscribed=row.oversubscribed,
        eval_median_ms=row.eval_median_ms,
        eval_mean_ms=row.eval_mean_ms,
        eval_stddev_ms=row.eval_stddev_ms,
        speedup_vs_single_thread_median=row.speedup_vs_single_thread_median,
        rns_width=row.rns_width,
    )


def write_raw_csv(path: Path, rows: Sequence[Dict[str, object]]) -> None:
    ensure_parent(path)
    fieldnames = [
        "machine_id",
        "logical_cpus",
        "physical_cores",
        "sockets",
        "threads_per_core",
        "budget_mode",
        "core_budget",
        "branch_count",
        "rns_width",
        "mode",
        "requested_workers",
        "effective_workers",
        "omp_threads",
        "requested_omp_threads",
        "core_demand",
        "core_utilization",
        "oversubscribed",
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


def write_summary_csv(path: Path, rows: Sequence[SummaryRow]) -> None:
    ensure_parent(path)
    fieldnames = list(SummaryRow.__dataclass_fields__.keys())
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows:
            writer.writerow(asdict(row))


def write_best_points_csv(path: Path, rows: Sequence[BestPointRow]) -> None:
    ensure_parent(path)
    fieldnames = list(BestPointRow.__dataclass_fields__.keys())
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows:
            writer.writerow(asdict(row))


def format_ms(value: float) -> str:
    return f"{value:.3f} ms"


def write_report(
    path: Path,
    cpu: CpuInfo,
    budget_mode: str,
    core_budget: int,
    rows: Sequence[SummaryRow],
    best_points: Sequence[BestPointRow],
    objective: str,
) -> None:
    ensure_parent(path)
    breakpoints = find_breakpoints(rows)
    grouped_by_branch: DefaultDict[int, List[SummaryRow]] = defaultdict(list)
    for row in rows:
        grouped_by_branch[row.branch_count].append(row)

    lines: List[str] = []
    lines.append("POSEIDON CKKS DAG OUTER+INNER THREAD SEARCH REPORT")
    lines.append("=" * 80)
    lines.append(f"machine_id: {cpu.machine_id}")
    lines.append(f"hostname: {cpu.hostname}")
    lines.append(f"model: {cpu.model_name}")
    lines.append(
        f"cpu: physical={cpu.physical_cores}, logical={cpu.logical_cpus}, "
        f"sockets={cpu.sockets}, threads_per_core={cpu.threads_per_core}"
    )
    lines.append(f"budget_mode: {budget_mode}")
    lines.append(f"core_budget: {core_budget}")
    lines.append(f"objective: {objective}")
    lines.append("core_demand model: outer_workers * inner_RNS/OpenMP_threads")
    lines.append("")

    for branch_count, branch_rows in sorted(grouped_by_branch.items()):
        absolute_best = min(branch_rows, key=lambda row: row.eval_median_ms)
        within_budget = [row for row in branch_rows if not row.oversubscribed]
        budget_best = min(within_budget, key=lambda row: row.eval_median_ms) if within_budget else None

        lines.append(f"GLOBAL RECOMMENDATION branch_count={branch_count}")
        lines.append("-" * 80)
        lines.append(
            "absolute_best="
            f"workers={absolute_best.workers}, inner={absolute_best.omp_threads}, "
            f"demand={absolute_best.core_demand}/{core_budget}, "
            f"oversubscribed={absolute_best.oversubscribed}, "
            f"eval_median={format_ms(absolute_best.eval_median_ms)}, "
            f"eval_stddev={format_ms(absolute_best.eval_stddev_ms)}"
        )
        if budget_best is not None:
            lines.append(
                "best_within_budget="
                f"workers={budget_best.workers}, inner={budget_best.omp_threads}, "
                f"demand={budget_best.core_demand}/{core_budget}, "
                f"util={budget_best.core_utilization:.3f}, "
                f"eval_median={format_ms(budget_best.eval_median_ms)}, "
                f"eval_stddev={format_ms(budget_best.eval_stddev_ms)}"
            )
        lines.append("")

    lines.append("BEST POINTS")
    lines.append("-" * 80)
    for item in best_points:
        lines.append(
            f"branch={item.branch_count} | class={item.recommendation_class} | "
            f"workers={item.workers} | inner={item.inner_threads} | "
            f"demand={item.core_demand}/{item.core_budget} | "
            f"eval_median={format_ms(item.eval_median_ms)} | "
            f"speedup={item.speedup_vs_single_thread_median:.3f}x"
        )
    lines.append("")

    for (branch_count, omp_threads), points in sorted(breakpoints.items()):
        best = points["best"]
        saturation = points["saturation"]
        regression = points["regression"]
        assert best is not None
        assert saturation is not None
        detail_rows = sorted(
            (
                row
                for row in rows
                if row.branch_count == branch_count and row.omp_threads == omp_threads
            ),
            key=lambda row: row.workers,
        )

        lines.append(f"DETAIL branch_count={branch_count}, inner_RNS/OpenMP_threads={omp_threads}")
        lines.append("-" * 80)
        lines.append(
            f"recommended_workers={saturation.workers} "
            f"(eval_median {format_ms(saturation.eval_median_ms)}, "
            f"speedup {saturation.speedup_vs_single_thread_median:.3f}x)"
        )
        lines.append(
            f"best_workers={best.workers} "
            f"(eval_median {format_ms(best.eval_median_ms)}, "
            f"speedup {best.speedup_vs_single_thread_median:.3f}x)"
        )
        if regression is None:
            lines.append("regression_start_workers=(none in tested range)")
        else:
            lines.append(
                f"regression_start_workers={regression.workers} "
                f"(eval_median {format_ms(regression.eval_median_ms)})"
            )
        lines.append("")
        lines.append(
            "workers | demand | oversub | eval_median_ms | eval_mean_ms | stddev_ms | "
            "speedup_median | merge_tail_mean_ms"
        )
        for row in detail_rows:
            lines.append(
                f"{row.workers:>7} | {row.core_demand:>6} | {str(row.oversubscribed):>7} | "
                f"{row.eval_median_ms:>14.3f} | {row.eval_mean_ms:>12.3f} | "
                f"{row.eval_stddev_ms:>9.3f} | {row.speedup_vs_single_thread_median:>14.3f} | "
                f"{row.merge_tail_mean_ms:>18.3f}"
            )
        lines.append("")

    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def get_font(size: int):
    if ImageFont is None:
        return None
    try:
        return ImageFont.truetype("DejaVuSans.ttf", size)
    except Exception:
        return ImageFont.load_default()


def draw_text(draw, position, text, fill, font):
    draw.text(position, text, fill=fill, font=font)


def measure_text(draw, text, font) -> Tuple[int, int]:
    bbox = draw.textbbox((0, 0), text, font=font)
    return bbox[2] - bbox[0], bbox[3] - bbox[1]


def draw_marker(draw, x: int, y: int, color: Tuple[int, int, int], oversubscribed: bool) -> None:
    if oversubscribed:
        draw.rectangle((x - 4, y - 4, x + 4, y + 4), outline=color, fill=(255, 255, 255), width=2)
    else:
        draw.ellipse((x - 4, y - 4, x + 4, y + 4), outline=color, fill=color, width=1)


def draw_highlight_marker(draw, x: int, y: int, color: Tuple[int, int, int], label: str) -> None:
    draw.ellipse((x - 8, y - 8, x + 8, y + 8), outline=color, fill=(255, 255, 255), width=3)
    draw.line((x - 10, y, x + 10, y), fill=color, width=2)
    draw.line((x, y - 10, x, y + 10), fill=color, width=2)
    draw_text(draw, (x + 10, y - 18), label, color, get_font(18))


def palette_color(index: int) -> Tuple[int, int, int]:
    palette = [
        (31, 119, 180),
        (255, 127, 14),
        (44, 160, 44),
        (214, 39, 40),
        (148, 103, 189),
        (140, 86, 75),
        (227, 119, 194),
        (127, 127, 127),
        (188, 189, 34),
        (23, 190, 207),
    ]
    return palette[index % len(palette)]


def nice_ticks(min_value: float, max_value: float, count: int = 6) -> List[float]:
    if math.isclose(min_value, max_value):
        return [min_value]
    span = max_value - min_value
    rough_step = span / max(1, count - 1)
    magnitude = 10 ** math.floor(math.log10(max(rough_step, 1e-9)))
    normalized = rough_step / magnitude
    if normalized <= 1:
        step = 1 * magnitude
    elif normalized <= 2:
        step = 2 * magnitude
    elif normalized <= 5:
        step = 5 * magnitude
    else:
        step = 10 * magnitude
    start = math.floor(min_value / step) * step
    end = math.ceil(max_value / step) * step
    ticks: List[float] = []
    value = start
    while value <= end + step * 0.5:
        ticks.append(value)
        value += step
    return ticks


def point_lookup(rows: Sequence[SummaryRow]) -> Dict[Tuple[int, int], SummaryRow]:
    return {(row.workers, row.omp_threads): row for row in rows}


def render_line_chart_png(
    path: Path,
    rows: Sequence[SummaryRow],
    branch_count: int,
    budget_mode: str,
    view: str,
) -> None:
    if Image is None or ImageDraw is None:
        raise RuntimeError("Pillow is required for --plot-format png")

    width = 1800
    height = 1080
    margin_left = 110
    margin_top = 80
    margin_bottom = 90
    margin_right = 480
    plot_left = margin_left
    plot_top = margin_top
    plot_right = width - margin_right
    plot_bottom = height - margin_bottom
    plot_width = plot_right - plot_left
    plot_height = plot_bottom - plot_top

    title_font = get_font(28)
    body_font = get_font(18)
    small_font = get_font(16)

    image = Image.new("RGB", (width, height), (255, 255, 255))
    draw = ImageDraw.Draw(image)

    branch_rows = [row for row in rows if row.branch_count == branch_count]
    if not branch_rows:
        return

    if view == "workers_vs_eval":
        series_key_fn = lambda row: row.omp_threads
        x_value_fn = lambda row: row.workers
        x_label = "Outer workers"
        series_label = lambda key: f"inner={key}"
    else:
        series_key_fn = lambda row: row.workers
        x_value_fn = lambda row: row.omp_threads
        x_label = "Inner RNS/OpenMP threads"
        series_label = lambda key: f"workers={key}"

    grouped: DefaultDict[int, List[SummaryRow]] = defaultdict(list)
    for row in branch_rows:
        grouped[series_key_fn(row)].append(row)
    ordered_series = sorted(grouped.items(), key=lambda item: item[0])

    x_values = sorted({x_value_fn(row) for row in branch_rows})
    y_values = [row.eval_median_ms for row in branch_rows]
    y_min = min(y_values)
    y_max = max(y_values)
    if math.isclose(y_min, y_max):
        y_min = max(0.0, y_min - 1.0)
        y_max = y_max + 1.0
    padding = (y_max - y_min) * 0.08
    y_min = max(0.0, y_min - padding)
    y_max = y_max + padding

    absolute_best = min(branch_rows, key=lambda row: row.eval_median_ms)
    budget_rows = [row for row in branch_rows if not row.oversubscribed]
    budget_best = min(budget_rows, key=lambda row: row.eval_median_ms) if budget_rows else None

    def x_to_px(value: int) -> int:
        if len(x_values) == 1:
            return plot_left + plot_width // 2
        index = x_values.index(value)
        return plot_left + round(index * plot_width / (len(x_values) - 1))

    def y_to_px(value: float) -> int:
        if math.isclose(y_min, y_max):
            return plot_bottom
        ratio = (value - y_min) / (y_max - y_min)
        return plot_bottom - round(ratio * plot_height)

    for tick in nice_ticks(y_min, y_max):
        y = y_to_px(tick)
        draw.line((plot_left, y, plot_right, y), fill=(225, 225, 225), width=1)
        draw_text(draw, (20, y - 10), f"{tick:.0f}", (90, 90, 90), body_font)

    for value in x_values:
        x = x_to_px(value)
        draw.line((x, plot_top, x, plot_bottom), fill=(240, 240, 240), width=1)
        label = str(value)
        text_w, _ = measure_text(draw, label, body_font)
        draw_text(draw, (x - text_w // 2, plot_bottom + 12), label, (90, 90, 90), body_font)

    draw.line((plot_left, plot_top, plot_left, plot_bottom), fill=(0, 0, 0), width=2)
    draw.line((plot_left, plot_bottom, plot_right, plot_bottom), fill=(0, 0, 0), width=2)

    for index, (series_key, series_rows) in enumerate(ordered_series):
        color = palette_color(index)
        ordered_points = sorted(series_rows, key=x_value_fn)
        points = [(x_to_px(x_value_fn(row)), y_to_px(row.eval_median_ms)) for row in ordered_points]
        if len(points) >= 2:
            draw.line(points, fill=color, width=3)
        for row, (x, y) in zip(ordered_points, points):
            draw_marker(draw, x, y, color, row.oversubscribed)

    draw_highlight_marker(
        draw,
        x_to_px(x_value_fn(absolute_best)),
        y_to_px(absolute_best.eval_median_ms),
        (220, 20, 60),
        "absolute best",
    )
    if budget_best is not None:
        draw_highlight_marker(
            draw,
            x_to_px(x_value_fn(budget_best)),
            y_to_px(budget_best.eval_median_ms),
            (30, 90, 200),
            "budget best",
        )

    title = (
        f"{budget_mode.capitalize()} budget | branch={branch_count} | "
        f"{'workers' if view == 'workers_vs_eval' else 'inner threads'} vs eval median"
    )
    draw_text(draw, (plot_left, 20), title, (0, 0, 0), title_font)
    draw_text(draw, (plot_left, height - 45), x_label, (0, 0, 0), body_font)
    draw_text(draw, (20, 40), "Eval median (ms)", (0, 0, 0), body_font)

    summary_x = plot_right + 30
    summary_y = plot_top
    draw_text(draw, (summary_x, summary_y), "Highlights", (0, 0, 0), title_font)
    summary_y += 44
    draw_text(
        draw,
        (summary_x, summary_y),
        (
            f"Absolute best\n"
            f"  workers={absolute_best.workers}, inner={absolute_best.omp_threads}\n"
            f"  demand={absolute_best.core_demand}/{absolute_best.core_budget}\n"
            f"  eval={absolute_best.eval_median_ms:.3f} ms"
        ),
        (220, 20, 60),
        body_font,
    )
    summary_y += 110
    if budget_best is not None:
        draw_text(
            draw,
            (summary_x, summary_y),
            (
                f"Budget best\n"
                f"  workers={budget_best.workers}, inner={budget_best.omp_threads}\n"
                f"  demand={budget_best.core_demand}/{budget_best.core_budget}\n"
                f"  eval={budget_best.eval_median_ms:.3f} ms"
            ),
            (30, 90, 200),
            body_font,
        )
        summary_y += 110

    draw_text(
        draw,
        (summary_x, summary_y),
        "Marker: hollow square = oversubscribed",
        (80, 80, 80),
        body_font,
    )
    summary_y += 50
    draw_text(draw, (summary_x, summary_y), "Legend", (0, 0, 0), title_font)
    summary_y += 40

    max_per_col = 18
    for index, (series_key, _) in enumerate(ordered_series):
        col = index // max_per_col
        row = index % max_per_col
        x = summary_x + col * 150
        y = summary_y + row * 28
        color = palette_color(index)
        draw.line((x, y + 9, x + 25, y + 9), fill=color, width=3)
        draw.ellipse((x + 8, y + 4, x + 16, y + 12), outline=color, fill=color, width=1)
        draw_text(draw, (x + 34, y), series_label(series_key), (0, 0, 0), small_font)

    ensure_parent(path)
    image.save(path)


def generate_plots(
    plot_dir: Path,
    plot_format: str,
    budget_mode: str,
    rows: Sequence[SummaryRow],
) -> List[Path]:
    generated: List[Path] = []
    if plot_format == "none":
        return generated

    plot_dir.mkdir(parents=True, exist_ok=True)
    branch_counts = sorted({row.branch_count for row in rows})
    for branch_count in branch_counts:
        for view in ("workers_vs_eval", "inner_vs_eval"):
            filename = f"{budget_mode}_branch{branch_count}_{view}.{plot_format}"
            plot_path = plot_dir / filename
            render_line_chart_png(plot_path, rows, branch_count, budget_mode, view)
            generated.append(plot_path)
    return generated


def main() -> int:
    args = parse_args()
    if args.runs <= 0 or args.timeout <= 0:
        print("Error: --runs and --timeout must be > 0.", file=sys.stderr)
        return 1
    if args.plot_format == "png" and Image is None:
        print("Error: Pillow is required for --plot-format png.", file=sys.stderr)
        return 1

    cpu = detect_cpu_info()
    try:
        budget_modes = resolve_budget_modes(args)
        bundles = resolve_output_bundles(args, budget_modes)
        budgets = {mode: resolve_core_budget(mode, args, cpu) for mode in budget_modes}
    except ValueError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1

    print(
        f"Detected CPU: physical={cpu.physical_cores}, logical={cpu.logical_cpus}, "
        f"sockets={cpu.sockets}, threads/core={cpu.threads_per_core}"
    )
    print("Budget outputs:")
    for mode in budget_modes:
        print(f"  {mode}: {budgets[mode]}")

    build_dir = args.build_dir.resolve()
    targets: List[str] = []
    for branch_count in args.branch_counts:
        targets.extend([SINGLE_TARGETS[branch_count], MANUAL_TARGETS[branch_count]])

    if not args.no_build:
        try:
            build_targets(build_dir, targets)
        except subprocess.CalledProcessError as exc:
            print(f"Error: build failed with exit code {exc.returncode}.", file=sys.stderr)
            return exc.returncode

    bin_dir = build_dir / "bin"
    for target in sorted(set(targets)):
        binary = bin_dir / target
        if not binary.exists():
            print(f"Error: missing benchmark binary: {binary}", file=sys.stderr)
            return 1

    budget_limit = core_budget_limit(
        budget_modes=budget_modes,
        budgets=budgets,
        allow_oversubscribe=args.allow_oversubscribe,
        fit_core_budget=args.fit_core_budget,
    )

    all_configs: List[ConfigRuns] = []
    raw_rows_by_budget: Dict[str, List[Dict[str, object]]] = {mode: [] for mode in budget_modes}

    for branch_count in args.branch_counts:
        if args.workers:
            worker_points = sorted({clamp_worker(worker, branch_count) for worker in args.workers})
        else:
            worker_points = auto_worker_points(branch_count, cpu, args.quick)

        single_binary = bin_dir / SINGLE_TARGETS[branch_count]
        manual_binary = bin_dir / MANUAL_TARGETS[branch_count]

        metadata_probe = probe_binary_metadata(single_binary, branch_count, args.timeout)
        omp_values = resolve_omp_values(args.omp_threads, metadata_probe.rns_width)

        print(f"\nBranch {branch_count} worker sweep: {worker_points}")
        print(f"Branch {branch_count} inner-thread sweep: {omp_values}")
        print(f"Branch {branch_count} detected RNS width: {metadata_probe.rns_width}")

        for omp_threads in omp_values:
            print(f"\nSingle-thread baseline: branch={branch_count}, omp={omp_threads}")
            baseline_runs, baseline_metadata = collect_successful_runs(
                binary=single_binary,
                branch_count=branch_count,
                mode="single-thread",
                omp_threads=omp_threads,
                timeout=args.timeout,
                requested_runs=args.runs,
                workers=None,
            )
            if not baseline_runs or baseline_metadata is None:
                print(
                    f"Warning: no baseline data for branch={branch_count}, omp={omp_threads}; skipping",
                    file=sys.stderr,
                )
                continue

            rns_width = baseline_metadata.rns_width
            for budget_mode in budget_modes:
                for index, metrics in enumerate(baseline_runs, start=1):
                    raw_rows_by_budget[budget_mode].append(
                        raw_row(
                            cpu=cpu,
                            budget_mode=budget_mode,
                            core_budget=budgets[budget_mode],
                            branch_count=branch_count,
                            rns_width=rns_width,
                            mode="single-thread",
                            requested_workers=1,
                            effective_workers=1,
                            omp_threads=omp_threads,
                            run_index=index,
                            metrics=metrics,
                        )
                    )

            for workers in worker_points:
                core_demand = workers * omp_threads
                if budget_limit is not None and core_demand > budget_limit:
                    print(
                        f"\nSkipping branch={branch_count}, workers={workers}, "
                        f"omp={omp_threads}: demand {core_demand} > limit {budget_limit}"
                    )
                    continue

                print(
                    f"\nManual-parallel: branch={branch_count}, workers={workers}, "
                    f"omp={omp_threads}, demand={core_demand}"
                )
                manual_runs, manual_metadata = collect_successful_runs(
                    binary=manual_binary,
                    branch_count=branch_count,
                    mode="manual-parallel",
                    omp_threads=omp_threads,
                    timeout=args.timeout,
                    requested_runs=args.runs,
                    workers=workers,
                )
                if not manual_runs or manual_metadata is None:
                    print(
                        f"Warning: no data for branch={branch_count}, workers={workers}, omp={omp_threads}",
                        file=sys.stderr,
                    )
                    continue

                all_configs.append(
                    ConfigRuns(
                        branch_count=branch_count,
                        rns_width=manual_metadata.rns_width,
                        workers=workers,
                        omp_threads=omp_threads,
                        baseline_runs=baseline_runs,
                        manual_runs=manual_runs,
                    )
                )

                for budget_mode in budget_modes:
                    for index, metrics in enumerate(manual_runs, start=1):
                        raw_rows_by_budget[budget_mode].append(
                            raw_row(
                                cpu=cpu,
                                budget_mode=budget_mode,
                                core_budget=budgets[budget_mode],
                                branch_count=branch_count,
                                rns_width=manual_metadata.rns_width,
                                mode="manual-parallel",
                                requested_workers=workers,
                                effective_workers=workers,
                                omp_threads=omp_threads,
                                run_index=index,
                                metrics=metrics,
                            )
                        )

    if not all_configs:
        print("Error: no benchmark summary data collected.", file=sys.stderr)
        return 1

    for budget_mode in budget_modes:
        summary_rows = build_summary_rows(cpu, budget_mode, budgets[budget_mode], all_configs)
        best_points = build_best_point_rows(summary_rows)
        bundle = bundles[budget_mode]

        write_raw_csv(bundle.raw_csv, raw_rows_by_budget[budget_mode])
        write_summary_csv(bundle.summary_csv, summary_rows)
        write_best_points_csv(bundle.best_points_csv, best_points)
        write_report(
            bundle.report_txt,
            cpu=cpu,
            budget_mode=budget_mode,
            core_budget=budgets[budget_mode],
            rows=summary_rows,
            best_points=best_points,
            objective=args.objective,
        )
        generated_plots = generate_plots(
            plot_dir=bundle.plot_dir,
            plot_format=args.plot_format,
            budget_mode=budget_mode,
            rows=summary_rows,
        )

        print(f"\n[{budget_mode}] Raw data written to: {bundle.raw_csv}")
        print(f"[{budget_mode}] Summary written to: {bundle.summary_csv}")
        print(f"[{budget_mode}] Best points written to: {bundle.best_points_csv}")
        print(f"[{budget_mode}] Report written to: {bundle.report_txt}")
        if generated_plots:
            print(f"[{budget_mode}] Generated plots:")
            for plot in generated_plots:
                print(f"  {plot}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
