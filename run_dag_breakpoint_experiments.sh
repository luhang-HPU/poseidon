#!/usr/bin/env bash
set -euo pipefail

RUNS="${RUNS:-5}"
BRANCH_COUNTS="${BRANCH_COUNTS:-24 48}"
RNS_THREADS="${RNS_THREADS:-auto}"
BUILD_DIR="${BUILD_DIR:-build}"
OUT_DIR="${OUT_DIR:-dag_breakpoint_results_$(date +%Y%m%d_%H%M%S)}"
SKIP_BUILD="${SKIP_BUILD:-0}"
QUICK="${QUICK:-0}"
ALLOW_OVERSUBSCRIBE="${ALLOW_OVERSUBSCRIBE:-0}"

usage() {
  cat <<'EOF'
Usage:
  ./run_dag_breakpoint_experiments.sh [options]

Options:
  --runs N                 Runs per configuration. Default: env RUNS or 5.
  --branch-counts "24 48"  Branch counts to benchmark. Default: env BRANCH_COUNTS or "24 48".
  --rns-threads "auto"     Inner RNS/OpenMP thread sweep. Default: env RNS_THREADS or auto.
  --out-dir DIR            Output directory. Default: dag_breakpoint_results_<timestamp>.
  --build-dir DIR          CMake build dir. Default: env BUILD_DIR or build.
  --skip-build             Do not configure/build before running.
  --quick                  Use smaller worker sweep for validation.
  --allow-oversubscribe    Also run configs where outer_workers * inner_threads exceeds the core budget.
  -h, --help               Show this help.

Examples:
  ./run_dag_breakpoint_experiments.sh
  ./run_dag_breakpoint_experiments.sh --runs 3 --quick
  ./run_dag_breakpoint_experiments.sh --runs 5 --branch-counts "24 48"
  ./run_dag_breakpoint_experiments.sh --runs 3 --allow-oversubscribe

Outputs:
  <out-dir>/physical_report.txt
  <out-dir>/logical_report.txt
  <out-dir>/physical_best_points.csv
  <out-dir>/logical_best_points.csv
  <out-dir>/physical_summary.csv
  <out-dir>/logical_summary.csv
  <out-dir>/physical_raw.csv
  <out-dir>/logical_raw.csv
  <out-dir>/plots/*.png
  <out-dir>/run.log
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --runs)
      RUNS="$2"
      shift 2
      ;;
    --branch-counts)
      BRANCH_COUNTS="$2"
      shift 2
      ;;
    --rns-threads|--omp-threads)
      RNS_THREADS="$2"
      shift 2
      ;;
    --out-dir)
      OUT_DIR="$2"
      shift 2
      ;;
    --build-dir)
      BUILD_DIR="$2"
      shift 2
      ;;
    --skip-build|--no-build)
      SKIP_BUILD=1
      shift
      ;;
    --quick)
      QUICK=1
      shift
      ;;
    --allow-oversubscribe)
      ALLOW_OVERSUBSCRIBE=1
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown option: $1" >&2
      usage >&2
      exit 1
      ;;
  esac
done

mkdir -p "$OUT_DIR"
LOG_FILE="$OUT_DIR/run.log"

run_logged() {
  echo
  echo "+ $*"
  "$@"
}

{
  echo "DAG breakpoint experiment"
  echo "Started at: $(date)"
  echo "Host: $(hostname)"
  echo "Runs: $RUNS"
  echo "Branch counts: $BRANCH_COUNTS"
  echo "RNS/OpenMP threads: $RNS_THREADS"
  echo "Allow oversubscribe: $ALLOW_OVERSUBSCRIBE"
  echo "Build dir: $BUILD_DIR"
  echo "Output dir: $OUT_DIR"
  echo

  if command -v lscpu >/dev/null 2>&1; then
    lscpu
    echo
  fi

  if [[ "$SKIP_BUILD" != "1" ]]; then
    run_logged cmake -S . -B "$BUILD_DIR"
    run_logged cmake --build "$BUILD_DIR" --target test_ckks_dag_single_thread_24_parallel -j2
    run_logged cmake --build "$BUILD_DIR" --target test_ckks_dag_manual_parallel_24 -j2
    run_logged cmake --build "$BUILD_DIR" --target test_ckks_dag_single_thread_48_parallel -j2
    run_logged cmake --build "$BUILD_DIR" --target test_ckks_dag_manual_parallel_48 -j2
    NO_BUILD_FLAG=(--no-build)
  else
    NO_BUILD_FLAG=(--no-build)
  fi

  QUICK_FLAG=()
  if [[ "$QUICK" == "1" ]]; then
    QUICK_FLAG=(--quick)
  fi

  OVERSUB_FLAG=()
  if [[ "$ALLOW_OVERSUBSCRIBE" == "1" ]]; then
    OVERSUB_FLAG=(--allow-oversubscribe)
  fi

  COMMON_ARGS=(
    --runs "$RUNS"
    --branch-counts $BRANCH_COUNTS
    --rns-threads $RNS_THREADS
    --build-dir "$BUILD_DIR"
    "${NO_BUILD_FLAG[@]}"
    "${QUICK_FLAG[@]}"
    "${OVERSUB_FLAG[@]}"
  )

  run_logged python3 ./benchmark_runner_dag_breakpoint.py \
    "${COMMON_ARGS[@]}" \
    --budget-mode both \
    --output-dir "$OUT_DIR" \
    --plot-format png

  echo
  echo "Finished at: $(date)"
  echo "Reports:"
  echo "  $OUT_DIR/physical_report.txt"
  echo "  $OUT_DIR/logical_report.txt"
  echo "Best points:"
  echo "  $OUT_DIR/physical_best_points.csv"
  echo "  $OUT_DIR/logical_best_points.csv"
  echo "Plots:"
  echo "  $OUT_DIR/plots/"
} 2>&1 | tee "$LOG_FILE"
