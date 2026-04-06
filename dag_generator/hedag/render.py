from __future__ import annotations

import json
from pathlib import Path
import shutil
import subprocess

from .ir import ExecutionPlan, Graph


EDGE_COLORS = {
    "data": "#1f2937",
    "read_after_write": "#2563eb",
    "write_after_read": "#dc2626",
    "write_after_write": "#f97316",
    "resource_use": "#7c3aed",
    "call_order": "#0f766e",
}

NODE_COLORS = {
    "assign": "#17becf",
    "return": "#64748b",
    "bootstrap": "#7f7f7f",
    "evaluate_poly_vector": "#e377c2",
    "multiply_relin": "#d62728",
    "multiply_relin_dynamic": "#d62728",
    "rotate": "#9467bd",
    "rescale": "#8c564b",
    "rescale_dynamic": "#8c564b",
}


def graph_to_dot(graph: Graph, execution_plan: ExecutionPlan | None = None) -> str:
    op_map = {op.op_id: op for op in graph.ops}
    lines = [
        "digraph hedag_v2 {",
        '  rankdir=LR;',
        '  node [shape=box, style="rounded,filled", fontname="Helvetica"];',
        '  edge [fontname="Helvetica"];',
    ]
    if execution_plan:
        for index, layer in enumerate(execution_plan.layers):
            lines.append(f"  subgraph cluster_layer_{index} {{")
            lines.append(f'    label="layer {index}";')
            lines.append('    color="#d1d5db";')
            for op_id in layer:
                op = op_map[op_id]
                color = NODE_COLORS.get(op.op_kind, "#dbeafe" if op.attrs.get("barrier") else "#e5e7eb")
                lines.append(f'    {op_id} [label="{_op_label(op, execution_plan)}", fillcolor="{color}"];')
            lines.append("  }")
    else:
        for op in graph.ops:
            color = NODE_COLORS.get(op.op_kind, "#dbeafe" if op.attrs.get("barrier") else "#e5e7eb")
            lines.append(f'  {op.op_id} [label="{_op_label(op, execution_plan)}", fillcolor="{color}"];')

    for edge in graph.edges:
        if edge.src in op_map and edge.dst in op_map:
            color = EDGE_COLORS.get(edge.kind, "#9ca3af")
            label = edge.reason or edge.kind
            lines.append(f'  {edge.src} -> {edge.dst} [color="{color}", label="{label}"];')

    lines.append("}")
    return "\n".join(lines) + "\n"


def render_summary(graph: Graph, execution_plan: ExecutionPlan, rewrite_status: str | None = None) -> str:
    summary = {
        "schema_version": graph.schema_version,
        "source_file": graph.source_file,
        "entry_function": graph.entry_function,
        "frontend": graph.frontend,
        "ops": len(graph.ops),
        "values": len(graph.values),
        "edges": len(graph.edges),
        "diagnostics": [diagnostic.to_dict() for diagnostic in graph.diagnostics],
        "critical_path_cost": execution_plan.critical_path_cost,
        "max_parallel_width": execution_plan.max_parallel_width,
        "layers": [f"layer {index}: {', '.join(layer)}" for index, layer in enumerate(execution_plan.layers)],
    }
    if rewrite_status is not None:
        summary["rewrite_status"] = rewrite_status
    return json.dumps(summary, indent=2, ensure_ascii=False, sort_keys=True)


def render_dot_file(dot_path: str | Path, output_path: str | Path, fmt: str) -> bool:
    dot_bin = shutil.which("dot")
    if not dot_bin:
        return False
    dot_path = Path(dot_path)
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    subprocess.run(
        [dot_bin, f"-T{fmt}", str(dot_path), "-o", str(output_path)],
        check=True,
        capture_output=True,
        text=True,
    )
    return True


def _op_label(op, execution_plan: ExecutionPlan | None) -> str:
    parts = [op.op_id, op.op_kind, f"line {op.source_span.start.line}"]
    if execution_plan and op.op_id in execution_plan.op_schedule:
        schedule = execution_plan.op_schedule[op.op_id]
        parts.append(f"layer {schedule.get('layer', 0)}")
        parts.append(f"cost {schedule.get('cost', 1)}")
    if op.outputs:
        parts.append("out " + ", ".join(op.outputs))
    if op.inputs:
        parts.append("in " + ", ".join(op.inputs))
    return "\\n".join(parts)
