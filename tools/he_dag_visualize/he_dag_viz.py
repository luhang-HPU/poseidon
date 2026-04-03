#!/usr/bin/env python3
from __future__ import annotations

import argparse
from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tools.he_dag.ir import Dag
from tools.he_dag.render import dag_summary, dag_to_dot


def main() -> int:
    parser = argparse.ArgumentParser(description="Render HE DAG JSON as DOT or a textual summary.")
    parser.add_argument("input", help="dag json file")
    parser.add_argument("--out", required=True, help="output path")
    parser.add_argument("--grouped", action="store_true", help="cluster nodes by scheduled layer")
    parser.add_argument("--format", choices=["dot", "summary"], default="dot", help="output format")
    args = parser.parse_args()

    dag = Dag.from_json(Path(args.input).read_text(encoding="utf-8"))
    content = dag_to_dot(dag, grouped=args.grouped) if args.format == "dot" else dag_summary(dag)

    output_path = Path(args.out)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(content, encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

