#!/usr/bin/env python3
from __future__ import annotations

import argparse
from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from dag_generator.hedag.pipeline import run_pipeline


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="hedag_pipeline", description="Run the full HE DAG v2 pipeline")
    parser.add_argument("input", help="input C++ file")
    parser.add_argument("--function", required=True, help="target entry function name")
    parser.add_argument("--out-dir", help="artifact output directory override")
    parser.add_argument("--case-name", help="folder name under dag_generator/hedag_output")
    parser.add_argument("--frontend", choices=["auto", "clang"], default="auto", help="frontend mode")
    parser.add_argument("--clang-ast-json", help="optional clang AST dump JSON file")
    parser.add_argument("--skip-dot", action="store_true", help="do not render graph.dot")
    parser.add_argument("--skip-summary", action="store_true", help="do not render summary.json")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    result = run_pipeline(
        repo_root=ROOT,
        input_path=args.input,
        function_name=args.function,
        frontend=args.frontend,
        clang_ast_json=args.clang_ast_json,
        out_dir=args.out_dir,
        case_name=args.case_name,
        render_dot=not args.skip_dot,
        render_summary_file=not args.skip_summary,
    )
    print(f"[hedag_pipeline] output dir -> {result['output_dir']}")
    for name, path in result["files"].items():
        print(f"[hedag_pipeline] {name} -> {path}")
    print("[hedag_pipeline] done")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
