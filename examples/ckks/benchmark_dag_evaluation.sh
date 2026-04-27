#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
BUILD_DIR="${BUILD_DIR:-$ROOT_DIR/build}"
BIN_DIR="${BIN_DIR:-$BUILD_DIR/bin}"
REPEATS="${REPEATS:-5}"
WORKERS_LIST="${WORKERS_LIST:-4 8 12 16 24 32 48}"
TASKS_LIST="${TASKS_LIST:-24 48}"
WARMUP="${WARMUP:-1}"

usage() {
    cat <<'EOF'
Usage:
  benchmark_dag_evaluation.sh [repeats]

Environment variables:
  BUILD_DIR      Build directory. Default: <repo>/build
  BIN_DIR        Binary directory. Default: <BUILD_DIR>/bin
  REPEATS        Repetitions per configuration. Default: 5
  WARMUP         Warmup runs per configuration. Default: 1
  WORKERS_LIST   Space-separated outer DAG worker counts. Default: "4 8 12 16 24 32 48"
  TASKS_LIST     Space-separated DAG task counts. Default: "24 48"

Examples:
  REPEATS=8 WORKERS_LIST="4 8 16 24" ./examples/ckks/benchmark_dag_evaluation.sh
  TASKS_LIST="24" REPEATS=10 ./examples/ckks/benchmark_dag_evaluation.sh
EOF
}

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
    usage
    exit 0
fi

if [[ $# -ge 1 ]]; then
    REPEATS="$1"
fi

if ! [[ "$REPEATS" =~ ^[0-9]+$ ]] || [[ "$REPEATS" -le 0 ]]; then
    echo "REPEATS must be a positive integer, got: $REPEATS" >&2
    exit 1
fi

if ! [[ "$WARMUP" =~ ^[0-9]+$ ]]; then
    echo "WARMUP must be a non-negative integer, got: $WARMUP" >&2
    exit 1
fi

declare -A TASK_TO_BIN=(
    ["24"]="$BIN_DIR/test_ckks_dag_manual_parallel_24"
    ["48"]="$BIN_DIR/test_ckks_dag_manual_parallel_48"
)

extract_eval_ms() {
    local log_file="$1"
    awk '
        /CKKS DAG .* evaluation TIME:/ {
            for (i = 1; i <= NF; ++i) {
                if ($i == "TIME:") {
                    print $(i + 1)
                    exit
                }
            }
        }
    ' "$log_file"
}

run_case() {
    local task_count="$1"
    local workers="$2"
    local run_index="$3"
    local bin_path="$4"
    local log_file
    local eval_ms

    log_file="$(mktemp)"
    POSEIDON_DAG_WORKERS="$workers" "$bin_path" >"$log_file" 2>&1
    eval_ms="$(extract_eval_ms "$log_file")"

    if [[ -z "$eval_ms" ]]; then
        echo "Failed to parse evaluation time for task_count=$task_count workers=$workers run=$run_index" >&2
        echo "Last 40 log lines:" >&2
        tail -n 40 "$log_file" >&2
        rm -f "$log_file"
        exit 1
    fi

    printf "%s\n" "$eval_ms"
    rm -f "$log_file"
}

echo "Benchmark root: $ROOT_DIR"
echo "Build dir: $BUILD_DIR"
echo "Bin dir: $BIN_DIR"
echo "Repeats: $REPEATS"
echo "Warmup: $WARMUP"
echo "Task counts: $TASKS_LIST"
echo "Worker counts: $WORKERS_LIST"
echo

printf "%-8s %-8s %-8s %-14s %-14s %-14s\n" "tasks" "workers" "runs" "avg_eval_ms" "min_eval_ms" "max_eval_ms"

for task_count in $TASKS_LIST; do
    if [[ -z "${TASK_TO_BIN[$task_count]:-}" ]]; then
        echo "Unsupported task_count: $task_count" >&2
        exit 1
    fi

    bin_path="${TASK_TO_BIN[$task_count]}"
    if [[ ! -x "$bin_path" ]]; then
        echo "Binary not found or not executable: $bin_path" >&2
        echo "Build it first with:" >&2
        echo "  cmake --build \"$BUILD_DIR\" --target test_ckks_dag_manual_parallel_${task_count}" >&2
        exit 1
    fi

    for workers in $WORKERS_LIST; do
        if ! [[ "$workers" =~ ^[0-9]+$ ]] || [[ "$workers" -le 0 ]]; then
            echo "Invalid worker count: $workers" >&2
            exit 1
        fi

        if [[ "$WARMUP" -gt 0 ]]; then
            for ((w = 1; w <= WARMUP; ++w)); do
                run_case "$task_count" "$workers" "warmup-$w" "$bin_path" >/dev/null
            done
        fi

        run_values=""
        for ((run = 1; run <= REPEATS; ++run)); do
            eval_ms="$(run_case "$task_count" "$workers" "$run" "$bin_path")"
            if [[ -z "$run_values" ]]; then
                run_values="$eval_ms"
            else
                run_values="$run_values $eval_ms"
            fi
            printf "run tasks=%s workers=%s iter=%d eval_ms=%s\n" "$task_count" "$workers" "$run" "$eval_ms" >&2
        done

        summary="$(
            awk -v values="$run_values" '
                BEGIN {
                    n = split(values, arr, " ")
                    sum = 0
                    min = -1
                    max = -1
                    for (i = 1; i <= n; ++i) {
                        val = arr[i] + 0
                        sum += val
                        if (min < 0 || val < min) min = val
                        if (max < 0 || val > max) max = val
                    }
                    avg = sum / n
                    printf "%.6f %.6f %.6f", avg, min, max
                }
            '
        )"

        avg_eval_ms="$(awk '{print $1}' <<<"$summary")"
        min_eval_ms="$(awk '{print $2}' <<<"$summary")"
        max_eval_ms="$(awk '{print $3}' <<<"$summary")"

        printf "%-8s %-8s %-8s %-14s %-14s %-14s\n" \
            "$task_count" "$workers" "$REPEATS" "$avg_eval_ms" "$min_eval_ms" "$max_eval_ms"
    done
done
