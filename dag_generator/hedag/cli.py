#!/usr/bin/env python3
from __future__ import annotations

import argparse
from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from dag_generator.hedag.frontend import extract_program
from dag_generator.hedag.ir import ExecutionPlan, Graph
from dag_generator.hedag.passes import build_execution_plan, build_graph, build_rewrite_plan
from dag_generator.hedag.render import graph_to_dot, render_summary


def _write_json(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content + "\n", encoding="utf-8")


def _write_text(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="hedag", description="HE DAG v2 tooling")
    subparsers = parser.add_subparsers(dest="command", required=True)

    extract = subparsers.add_parser("extract", help="extract graph.json and diagnostics.json from source")
    extract.add_argument("input", help="input C++ file")
    extract.add_argument("--function", required=True, help="target entry function")
    extract.add_argument("--frontend", choices=["auto", "clang"], default="auto", help="frontend mode")
    extract.add_argument("--clang-ast-json", help="optional clang AST dump JSON to consume instead of invoking clang")
    extract.add_argument("--out-dir", required=True, help="artifact directory")

    analyze = subparsers.add_parser("analyze", help="derive execution_plan.json from graph.json")
    analyze.add_argument("graph", help="graph.json path")
    analyze.add_argument("--out-dir", required=True, help="artifact directory")

    rewrite = subparsers.add_parser("rewrite-plan", help="derive rewrite_plan.json from graph and execution plan")
    rewrite.add_argument("graph", help="graph.json path")
    rewrite.add_argument("execution_plan", help="execution_plan.json path")
    rewrite.add_argument("--out-dir", required=True, help="artifact directory")

    render = subparsers.add_parser("render", help="render DOT or summary from graph and execution plan")
    render.add_argument("graph", help="graph.json path")
    render.add_argument("execution_plan", help="execution_plan.json path")
    render.add_argument("--format", choices=["dot", "summary"], default="dot", help="render format")
    render.add_argument("--out", required=True, help="output file")
    render.add_argument("--rewrite-plan", help="optional rewrite_plan.json path for summary status")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command == "extract":
        program = extract_program(
            args.input,
            args.function,
            frontend=args.frontend,
            clang_ast_json=args.clang_ast_json,
        )
        graph = build_graph(program)
        out_dir = Path(args.out_dir)
        _write_json(out_dir / "graph.json", graph.to_json())
        diagnostics = {"diagnostics": [item.to_dict() for item in graph.diagnostics]}
        _write_json(out_dir / "diagnostics.json", __import__("json").dumps(diagnostics, indent=2, sort_keys=True))
        return 0

    if args.command == "analyze":
        graph = Graph.from_json(Path(args.graph).read_text(encoding="utf-8"))
        execution_plan = build_execution_plan(graph)
        _write_json(Path(args.out_dir) / "execution_plan.json", execution_plan.to_json())
        return 0

    if args.command == "rewrite-plan":
        graph = Graph.from_json(Path(args.graph).read_text(encoding="utf-8"))
        execution_plan = ExecutionPlan.from_json(Path(args.execution_plan).read_text(encoding="utf-8"))
        rewrite_plan = build_rewrite_plan(graph, execution_plan)
        _write_json(Path(args.out_dir) / "rewrite_plan.json", rewrite_plan.to_json())
        return 0

    if args.command == "render":
        graph = Graph.from_json(Path(args.graph).read_text(encoding="utf-8"))
        execution_plan = ExecutionPlan.from_json(Path(args.execution_plan).read_text(encoding="utf-8"))
        rewrite_status = None
        if args.rewrite_plan:
            from dag_generator.hedag.ir import RewritePlan

            rewrite_status = RewritePlan.from_json(Path(args.rewrite_plan).read_text(encoding="utf-8")).status
        content = graph_to_dot(graph, execution_plan) if args.format == "dot" else render_summary(graph, execution_plan, rewrite_status)
        _write_text(Path(args.out), content if content.endswith("\n") else content + "\n")
        return 0

    parser.error(f"unknown command {args.command}")
    return 2
