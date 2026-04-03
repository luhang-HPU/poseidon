#!/usr/bin/env python3
from __future__ import annotations

import argparse
from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tools.he_dag.analysis import analyze_dag, validate_parallel_groups
from tools.he_dag.parser import extract_he_dag


def main() -> int:
    parser = argparse.ArgumentParser(description="Extract a restricted HE DAG from a C++ function.")
    parser.add_argument("input", help="input C++ file")
    parser.add_argument("--function", required=True, help="target function name")
    parser.add_argument("--out", required=True, help="output dag json file")
    args = parser.parse_args()

    dag = analyze_dag(extract_he_dag(args.input, args.function))
    dag.metadata["layer_validation"] = validate_parallel_groups(dag)

    output_path = Path(args.out)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(dag.to_json() + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

