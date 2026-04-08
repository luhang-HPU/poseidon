#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path
import re
import sys
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from dag_generator.hedag.frontend import discover_tracked_functions
from dag_generator.hedag.ir import ExecutionPlan, Graph
from dag_generator.hedag.pipeline import run_pipeline
from dag_generator.hedag.render import EDGE_COLORS, NODE_COLORS, render_dot_file


SOURCE_SUFFIXES = {".cpp", ".cc", ".cxx"}
OVERVIEW_CALL_EDGE_COLOR = "#0f766e"


def _sanitize_case_component(text: str) -> str:
    return re.sub(r"[^A-Za-z0-9_]+", "_", text).strip("_") or "case"


def default_trident_output_root(repo_root: Path) -> Path:
    return repo_root / "dag_generator" / "hedag_output" / "trident"


def _iter_trident_sources(trident_root: Path, sources: list[str] | None = None) -> list[Path]:
    if sources:
        resolved: list[Path] = []
        for item in sources:
            candidate = Path(item)
            if not candidate.is_absolute():
                candidate = (ROOT / candidate).resolve()
            if candidate.is_dir():
                resolved.extend(path for path in candidate.rglob("*") if path.suffix in SOURCE_SUFFIXES)
            elif candidate.suffix in SOURCE_SUFFIXES:
                resolved.append(candidate)
        return sorted(dict.fromkeys(path.resolve() for path in resolved))
    return sorted(path.resolve() for path in trident_root.rglob("*") if path.suffix in SOURCE_SUFFIXES)


def _build_case_output_dir(output_root: Path, trident_root: Path, source_path: Path, function_name: str) -> Path:
    relative_source = source_path.resolve().relative_to(trident_root.resolve())
    parent = relative_source.parent
    source_case = _sanitize_case_component(source_path.stem)
    function_case = _sanitize_case_component(function_name)
    return output_root / parent / f"{source_case}__{function_case}"


def _write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _display_path(path: Path, repo_root: Path) -> str:
    try:
        return str(path.relative_to(repo_root.resolve()))
    except ValueError:
        return str(path)


def _has_main_function(source_path: Path) -> bool:
    return re.search(r"\bmain\s*\(", source_path.read_text(encoding="utf-8", errors="ignore")) is not None


def _resolve_repo_path(path_str: str, repo_root: Path) -> Path:
    path = Path(path_str)
    return path if path.is_absolute() else (repo_root / path).resolve()


def _dot_escape(text: str) -> str:
    return text.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")


def _component_name(source_file: str) -> str:
    parts = Path(source_file).parts
    if len(parts) >= 2 and parts[0] == "Trident":
        return parts[1]
    return parts[0] if parts else "trident"


def _case_key(case: dict[str, Any]) -> str:
    return _sanitize_case_component(f"{case['source_file']}__{case['entry_function']}")


def _load_case_artifacts(case: dict[str, Any], repo_root: Path) -> tuple[Graph, ExecutionPlan]:
    output_dir = _resolve_repo_path(case["output_dir"], repo_root)
    graph = Graph.from_json((output_dir / "graph.json").read_text(encoding="utf-8"))
    execution = ExecutionPlan.from_json((output_dir / "execution_plan.json").read_text(encoding="utf-8"))
    return graph, execution


def _entry_offset(graph: Graph) -> int:
    entry_span = graph.metadata.get("entry_span", {})
    start = entry_span.get("start", {})
    return int(start.get("offset", 0))


def _call_body(case: dict[str, Any], graph: Graph, repo_root: Path, source_cache: dict[str, str]) -> str:
    source_file = case["source_file"]
    if source_file not in source_cache:
        source_cache[source_file] = _resolve_repo_path(source_file, repo_root).read_text(encoding="utf-8", errors="ignore")
    source = source_cache[source_file]
    entry_span = graph.metadata.get("entry_span", {})
    start = entry_span.get("start", {}).get("offset")
    end = entry_span.get("end", {}).get("offset")
    if isinstance(start, int) and isinstance(end, int) and end >= start:
        return source[start : end + 1]
    return source


def _overview_op_label(op_id: str, op, execution: ExecutionPlan) -> str:
    layer = execution.op_schedule.get(op_id, {}).get("layer")
    parts = [op.op_kind, f"line {op.source_span.start.line}"]
    if layer is not None:
        parts.append(f"L{layer}")
    return "\\n".join(parts)


def _build_overview_dot(
    *,
    cases: list[dict[str, Any]],
    component: str,
    repo_root: Path,
) -> tuple[str, dict[str, Any]]:
    prepared: list[dict[str, Any]] = []
    for case in cases:
        if "error" in case:
            continue
        graph, execution = _load_case_artifacts(case, repo_root)
        prepared.append(
            {
                "case": case,
                "case_key": _case_key(case),
                "execution": execution,
                "graph": graph,
                "header_id": f"{_case_key(case)}__entry",
                "node_prefix": f"{_case_key(case)}__",
            }
        )
    prepared.sort(key=lambda item: (0 if item["case"]["entry_function"] == "main" else 1, item["case"]["source_file"], _entry_offset(item["graph"]), item["case"]["entry_function"]))

    source_cache: dict[str, str] = {}
    call_edges: list[dict[str, str]] = []
    seen_edges: set[tuple[str, str]] = set()
    for caller in prepared:
        body = _call_body(caller["case"], caller["graph"], repo_root, source_cache)
        for callee in prepared:
            if caller["case_key"] == callee["case_key"]:
                continue
            pattern = re.compile(rf"(?<![A-Za-z0-9_:~])(?:->|\.)?\s*{re.escape(callee['case']['entry_function'])}\s*\(")
            if pattern.search(body):
                edge_key = (caller["case_key"], callee["case_key"])
                if edge_key in seen_edges:
                    continue
                seen_edges.add(edge_key)
                call_edges.append(
                    {
                        "callee": callee["case"]["entry_function"],
                        "dst": callee["header_id"],
                        "src": caller["header_id"],
                    }
                )

    lines = [
        "digraph hedag_trident_overview {",
        '  rankdir=LR;',
        '  compound=true;',
        '  graph [fontname="Helvetica", pad="0.3"];',
        '  node [shape=box, style="rounded,filled", fontname="Helvetica"];',
        '  edge [fontname="Helvetica"];',
        f'  overview_root [shape=folder, fillcolor="#bfdbfe", color="#2563eb", label="{_dot_escape(component + " Overview")}"];',
    ]

    overview_cases: list[dict[str, Any]] = []
    for item in prepared:
        case = item["case"]
        graph = item["graph"]
        execution = item["execution"]
        cluster_color = "#93c5fd" if case["entry_function"] == "main" else "#d1d5db"
        header_color = "#dbeafe" if case["entry_function"] == "main" else "#f8fafc"
        header_label = "\\n".join(
            [
                case["entry_function"],
                Path(case["source_file"]).name,
                f"ops {case.get('op_count', 0)}",
                f"diag {case.get('diagnostic_count', 0)}",
                case.get("rewrite_status", "unknown"),
            ]
        )
        lines.append(f"  subgraph cluster_{item['case_key']} {{")
        lines.append(f'    label="{_dot_escape(case["source_file"])}";')
        lines.append(f'    color="{cluster_color}";')
        lines.append('    style="rounded";')
        lines.append(
            f'    {item["header_id"]} [shape=component, fillcolor="{header_color}", color="#475569", label="{_dot_escape(header_label)}"];'
        )

        layer_zero_nodes: list[str] = []
        op_map = {op.op_id: op for op in graph.ops}
        for layer_index, layer in enumerate(execution.layers):
            if layer_index == 0:
                layer_zero_nodes = [f'{item["node_prefix"]}{op_id}' for op_id in layer]
            lines.append(f"    subgraph cluster_{item['case_key']}_layer_{layer_index} {{")
            lines.append(f'      label="layer {layer_index}";')
            lines.append('      color="#e5e7eb";')
            for op_id in layer:
                op = op_map[op_id]
                color = NODE_COLORS.get(op.op_kind, "#dbeafe" if op.attrs.get("barrier") else "#e5e7eb")
                node_id = f'{item["node_prefix"]}{op_id}'
                lines.append(
                    f'      {node_id} [fillcolor="{color}", label="{_dot_escape(_overview_op_label(op_id, op, execution))}"];'
                )
            lines.append("    }")

        if not graph.ops:
            empty_id = f'{item["node_prefix"]}empty'
            layer_zero_nodes = [empty_id]
            lines.append(f'    {empty_id} [fillcolor="#f1f5f9", label="no tracked ops"];')

        for node_id in layer_zero_nodes:
            lines.append(f'    {item["header_id"]} -> {node_id} [style="dotted", color="#94a3b8", arrowhead="none"];')
        lines.append("  }")

        for edge in graph.edges:
            if edge.src in op_map and edge.dst in op_map:
                src = f'{item["node_prefix"]}{edge.src}'
                dst = f'{item["node_prefix"]}{edge.dst}'
                color = EDGE_COLORS.get(edge.kind, "#94a3b8")
                lines.append(f'  {src} -> {dst} [color="{color}", penwidth="1.2"];')

        lines.append(f'  overview_root -> {item["header_id"]} [color="#94a3b8", style="dashed"];')
        overview_cases.append(
            {
                "diagnostic_count": case.get("diagnostic_count", 0),
                "entry_function": case["entry_function"],
                "op_count": case.get("op_count", 0),
                "output_dir": case["output_dir"],
                "rewrite_status": case.get("rewrite_status", "unknown"),
                "source_file": case["source_file"],
            }
        )

    for edge in call_edges:
        lines.append(
            f'  {edge["src"]} -> {edge["dst"]} [color="{OVERVIEW_CALL_EDGE_COLOR}", penwidth="2", style="dashed", label="{_dot_escape(edge["callee"])}"];'
        )

    lines.append("}")
    payload = {
        "call_edges": call_edges,
        "case_count": len(overview_cases),
        "cases": overview_cases,
        "component": component,
        "schema_version": 1,
    }
    return "\n".join(lines) + "\n", payload


def _render_component_overviews(
    *,
    repo_root: Path,
    output_root: Path,
    cases: list[dict[str, Any]],
    render_dot: bool,
    render_images: bool,
) -> list[dict[str, Any]]:
    by_component: dict[str, list[dict[str, Any]]] = {}
    for case in cases:
        if "error" in case:
            continue
        component = _component_name(case["source_file"])
        by_component.setdefault(component, []).append(case)

    overviews: list[dict[str, Any]] = []
    for component, component_cases in sorted(by_component.items()):
        component_output_dir = output_root / component
        component_output_dir.mkdir(parents=True, exist_ok=True)
        dot_text, payload = _build_overview_dot(cases=component_cases, component=component, repo_root=repo_root)
        overview_json_path = component_output_dir / "overview.json"
        _write_json(overview_json_path, payload)

        files = {"json": _display_path(overview_json_path, repo_root)}
        if render_dot:
            dot_path = component_output_dir / "overview.dot"
            dot_path.write_text(dot_text, encoding="utf-8")
            files["dot"] = _display_path(dot_path, repo_root)
            if render_images:
                svg_path = component_output_dir / "overview.svg"
                png_path = component_output_dir / "overview.png"
                if render_dot_file(dot_path, svg_path, "svg"):
                    files["svg"] = _display_path(svg_path, repo_root)
                if render_dot_file(dot_path, png_path, "png"):
                    files["png"] = _display_path(png_path, repo_root)
        overviews.append({"component": component, "files": files, "case_count": payload["case_count"]})

    return overviews


def run_trident_pipeline(
    *,
    repo_root: Path,
    trident_root: str | Path = "Trident",
    output_root: str | Path | None = None,
    sources: list[str] | None = None,
    frontend: str = "auto",
    clang_ast_json: str | None = None,
    render_dot: bool = True,
    render_summary_file: bool = True,
    render_images: bool = True,
) -> dict[str, Any]:
    resolved_trident_root = (repo_root / trident_root).resolve() if not Path(trident_root).is_absolute() else Path(trident_root).resolve()
    resolved_output_root = (
        Path(output_root).resolve()
        if output_root
        else default_trident_output_root(repo_root).resolve()
    )
    resolved_output_root.mkdir(parents=True, exist_ok=True)

    cases: list[dict[str, Any]] = []
    skipped: list[dict[str, Any]] = []

    for source_path in _iter_trident_sources(resolved_trident_root, sources):
        relative_source = source_path.relative_to(repo_root.resolve())
        functions = discover_tracked_functions(str(source_path))
        if not functions and _has_main_function(source_path):
            functions = ["main"]
        if not functions:
            skipped.append(
                {
                    "reason": "no tracked HE functions discovered",
                    "source_file": str(relative_source),
                }
            )
            continue

        for function_name in functions:
            case_output_dir = _build_case_output_dir(resolved_output_root, resolved_trident_root, source_path, function_name)
            try:
                result = run_pipeline(
                    repo_root=repo_root,
                    input_path=str(source_path),
                    function_name=function_name,
                    frontend=frontend,
                    clang_ast_json=clang_ast_json,
                    out_dir=str(case_output_dir),
                    render_dot=render_dot,
                    render_summary_file=render_summary_file,
                    render_images=render_images,
                )
                cases.append(
                    {
                        "diagnostic_count": len(result["graph"].diagnostics),
                        "entry_function": function_name,
                        "max_parallel_width": result["execution_plan"].max_parallel_width,
                        "op_count": len(result["graph"].ops),
                        "output_dir": _display_path(case_output_dir, repo_root),
                        "rewrite_status": result["rewrite_plan"].status,
                        "source_file": str(relative_source),
                    }
                )
            except Exception as exc:
                cases.append(
                    {
                        "entry_function": function_name,
                        "error": f"{type(exc).__name__}: {exc}",
                        "output_dir": _display_path(case_output_dir, repo_root),
                        "source_file": str(relative_source),
                    }
                )

    payload = {
        "cases": cases,
        "output_root": _display_path(resolved_output_root, repo_root),
        "overviews": _render_component_overviews(
            repo_root=repo_root,
            output_root=resolved_output_root,
            cases=cases,
            render_dot=render_dot,
            render_images=render_images,
        ),
        "schema_version": 1,
        "skipped": skipped,
        "trident_root": _display_path(resolved_trident_root, repo_root),
    }
    _write_json(resolved_output_root / "index.json", payload)
    return payload


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="hedag_trident", description="Generate HE DAG artifacts for Trident sources")
    parser.add_argument("sources", nargs="*", help="optional Trident source files or directories")
    parser.add_argument("--trident-root", default="Trident", help="Trident source root")
    parser.add_argument("--output-root", help="artifact output root (default: dag_generator/hedag_output/trident)")
    parser.add_argument("--frontend", choices=["auto", "clang"], default="auto", help="frontend mode")
    parser.add_argument("--clang-ast-json", help="optional shared clang AST dump JSON file")
    parser.add_argument("--skip-dot", action="store_true", help="do not render graph.dot")
    parser.add_argument("--skip-summary", action="store_true", help="do not render summary.json")
    parser.add_argument("--skip-images", action="store_true", help="do not render graph.svg or graph.png")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    payload = run_trident_pipeline(
        repo_root=ROOT,
        trident_root=args.trident_root,
        output_root=args.output_root,
        sources=args.sources or None,
        frontend=args.frontend,
        clang_ast_json=args.clang_ast_json,
        render_dot=not args.skip_dot,
        render_summary_file=not args.skip_summary,
        render_images=not args.skip_images,
    )
    print(f"[hedag_trident] output root -> {payload['output_root']}")
    print(f"[hedag_trident] generated cases -> {len(payload['cases'])}")
    print(f"[hedag_trident] skipped sources -> {len(payload['skipped'])}")
    print("[hedag_trident] index -> dag_generator/hedag_output/trident/index.json")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
