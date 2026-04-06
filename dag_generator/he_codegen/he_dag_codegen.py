#!/usr/bin/env python3
from __future__ import annotations

import argparse
from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from dag_generator.he_dag.ir import Dag
from dag_generator.he_dag.render import dag_to_cpp


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate a conservative parallel C++ skeleton from HE DAG JSON.")
    parser.add_argument("input", help="dag json file")
    parser.add_argument("--scheduler", choices=["levelized"], default="levelized", help="scheduling strategy")
    parser.add_argument("--namespace", default="poseidon_codegen", help="generated namespace")
    parser.add_argument("--out", required=True, help="output cpp file")
    args = parser.parse_args()

    dag = Dag.from_json(Path(args.input).read_text(encoding="utf-8"))
    output_path = Path(args.out)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(dag_to_cpp(dag, namespace=args.namespace), encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
