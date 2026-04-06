from __future__ import annotations

from pathlib import Path
import json
from typing import Any

from .frontend import extract_program
from .ir import ExecutionPlan, Graph
from .passes import build_execution_plan, build_graph, build_rewrite_plan
from .render import graph_to_dot, render_dot_file, render_summary


PREFIXES = (
    "test_ckks_",
    "test_bfv_",
    "test_bgv_",
    "test_",
)


def normalize_case_stem(stem: str) -> str:
    normalized = stem
    changed = True
    while changed:
        changed = False
        for prefix in PREFIXES:
            if normalized.startswith(prefix):
                normalized = normalized[len(prefix) :]
                changed = True
                break
    return normalized


def default_case_name(input_path: str, function_name: str) -> str:
    stem = Path(input_path).stem
    normalized = normalize_case_stem(stem)
    if function_name in {"main", stem, normalized}:
        return normalized
    return f"{normalized}_{function_name}"


def default_output_dir(repo_root: Path, input_path: str, function_name: str, case_name: str | None = None) -> Path:
    resolved_case = case_name or default_case_name(input_path, function_name)
    return repo_root / "dag_generator" / "hedag_output" / resolved_case


def _write_json(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content + "\n", encoding="utf-8")


def _write_text(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content if content.endswith("\n") else content + "\n", encoding="utf-8")


def run_pipeline(
    *,
    repo_root: Path,
    input_path: str,
    function_name: str,
    frontend: str = "auto",
    clang_ast_json: str | None = None,
    out_dir: str | None = None,
    case_name: str | None = None,
    render_dot: bool = True,
    render_summary_file: bool = True,
    render_images: bool = True,
) -> dict[str, Any]:
    output_dir = Path(out_dir) if out_dir else default_output_dir(repo_root, input_path, function_name, case_name)
    output_dir.mkdir(parents=True, exist_ok=True)

    program = extract_program(
        input_path,
        function_name,
        frontend=frontend,
        clang_ast_json=clang_ast_json,
    )
    graph = build_graph(program)
    execution_plan = build_execution_plan(graph)
    rewrite_plan = build_rewrite_plan(graph, execution_plan)

    graph_path = output_dir / "graph.json"
    execution_path = output_dir / "execution_plan.json"
    rewrite_path = output_dir / "rewrite_plan.json"
    diagnostics_path = output_dir / "diagnostics.json"
    summary_path = output_dir / "summary.json"
    dot_path = output_dir / "graph.dot"
    svg_path = output_dir / "graph.svg"
    png_path = output_dir / "graph.png"

    _write_json(graph_path, graph.to_json())
    _write_json(execution_path, execution_plan.to_json())
    _write_json(rewrite_path, rewrite_plan.to_json())
    diagnostics_payload = {"diagnostics": [item.to_dict() for item in graph.diagnostics]}
    _write_json(diagnostics_path, json.dumps(diagnostics_payload, indent=2, sort_keys=True))

    if render_summary_file:
        _write_text(summary_path, render_summary(graph, execution_plan, rewrite_plan.status))
    if render_dot:
        _write_text(dot_path, graph_to_dot(graph, execution_plan))
        if render_images:
            try:
                if render_dot_file(dot_path, svg_path, "svg"):
                    files_svg = str(svg_path)
                else:
                    files_svg = None
                if render_dot_file(dot_path, png_path, "png"):
                    files_png = str(png_path)
                else:
                    files_png = None
            except Exception:
                files_svg = None
                files_png = None
        else:
            files_svg = None
            files_png = None
    else:
        files_svg = None
        files_png = None

    files = {
        "graph": str(graph_path),
        "execution_plan": str(execution_path),
        "rewrite_plan": str(rewrite_path),
        "diagnostics": str(diagnostics_path),
    }
    if render_summary_file:
        files["summary"] = str(summary_path)
    if render_dot:
        files["dot"] = str(dot_path)
    if files_svg:
        files["svg"] = files_svg
    if files_png:
        files["png"] = files_png

    return {
        "output_dir": str(output_dir),
        "case_name": output_dir.name,
        "files": files,
        "graph": graph,
        "execution_plan": execution_plan,
        "rewrite_plan": rewrite_plan,
    }


def load_pipeline_artifacts(output_dir: str | Path) -> dict[str, Any]:
    output = Path(output_dir)
    graph = Graph.from_json((output / "graph.json").read_text(encoding="utf-8"))
    execution_plan = ExecutionPlan.from_json((output / "execution_plan.json").read_text(encoding="utf-8"))
    rewrite = json.loads((output / "rewrite_plan.json").read_text(encoding="utf-8"))
    summary = None
    if (output / "summary.json").exists():
        summary = json.loads((output / "summary.json").read_text(encoding="utf-8"))
    diagnostics = json.loads((output / "diagnostics.json").read_text(encoding="utf-8"))
    return {
        "graph": graph,
        "execution_plan": execution_plan,
        "rewrite_plan": rewrite,
        "summary": summary,
        "diagnostics": diagnostics,
    }
