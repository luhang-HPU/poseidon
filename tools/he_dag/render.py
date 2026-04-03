from __future__ import annotations

from collections import defaultdict
import json

from .ir import Dag


COLORS = {
    "encode": "#1f77b4",
    "encrypt": "#1f77b4",
    "decrypt": "#1f77b4",
    "add": "#2ca02c",
    "sub": "#2ca02c",
    "add_plain": "#2ca02c",
    "sub_plain": "#2ca02c",
    "multiply": "#d62728",
    "multiply_plain": "#ff7f0e",
    "multiply_relin": "#d62728",
    "rotate": "#9467bd",
    "conjugate": "#9467bd",
    "rescale": "#8c564b",
    "rescale_dynamic": "#8c564b",
    "relinearize": "#8c564b",
    "drop_modulus": "#8c564b",
    "drop_modulus_to_next": "#8c564b",
    "evaluate_poly_vector": "#e377c2",
    "bootstrap": "#7f7f7f",
    "assign": "#17becf",
}

EDGE_COLORS = {
    "data": "#222222",
    "resource": "#1f77b4",
    "order": "#ff7f0e",
    "anti": "#d62728",
}


def dag_to_dot(dag: Dag, grouped: bool = False) -> str:
    lines = [
        "digraph he_dag {",
        '  rankdir=LR;',
        '  graph [fontname="Helvetica"];',
        '  node [shape=box, style="rounded,filled", fontname="Helvetica"];',
        '  edge [fontname="Helvetica"];',
    ]
    if grouped:
        for index, group in enumerate(dag.parallel_groups):
            lines.append(f"  subgraph cluster_layer_{index} {{")
            lines.append(f'    label="layer {index}";')
            lines.append('    color="#cccccc";')
            for op_id in group:
                op = next(item for item in dag.ops if item.id == op_id)
                lines.append(f'    {op.id} [label="{_node_label(op)}", fillcolor="{COLORS.get(op.kind, "#dddddd")}"];')
            lines.append("  }")
        rendered = {op_id for group in dag.parallel_groups for op_id in group}
        for op in dag.ops:
            if op.id not in rendered:
                lines.append(f'  {op.id} [label="{_node_label(op)}", fillcolor="{COLORS.get(op.kind, "#dddddd")}"];')
    else:
        for op in dag.ops:
            lines.append(f'  {op.id} [label="{_node_label(op)}", fillcolor="{COLORS.get(op.kind, "#dddddd")}"];')

    for edge in dag.edges:
        if edge.src.startswith("op") and edge.dst.startswith("op"):
            color = EDGE_COLORS.get(edge.kind, "#999999")
            label = edge.reason or edge.kind
            lines.append(f'  {edge.src} -> {edge.dst} [color="{color}", label="{label}"];')
    lines.append("}")
    return "\n".join(lines) + "\n"


def dag_summary(dag: Dag) -> str:
    layers = [f"layer {index}: {', '.join(group)}" for index, group in enumerate(dag.parallel_groups)]
    summary = {
        "source_file": dag.source_file,
        "function": dag.function,
        "critical_path_cost": dag.metadata.get("critical_path_cost", 0),
        "max_parallel_width": dag.metadata.get("max_parallel_width", 0),
        "ops": len(dag.ops),
        "edges": len(dag.edges),
        "layers": layers,
        "unsupported": dag.unsupported,
    }
    return json.dumps(summary, indent=2, ensure_ascii=False)


def dag_to_cpp(dag: Dag, namespace: str = "poseidon_codegen") -> str:
    layers: dict[int, list[str]] = defaultdict(list)
    op_index = {op.id: op for op in dag.ops}
    for op in dag.ops:
        layer = op.layer if op.layer is not None else 0
        layers[layer].append(op.id)

    lines = [
        '#include "poseidon/util/thread_pool.h"',
        "#include <cstddef>",
        "#include <thread>",
        "",
        f"namespace {namespace} {{",
        "",
        f"// Generated from {dag.source_file}:{dag.function}.",
        f"// This prototype emits a conservative schedule skeleton for the extracted HE calls.",
        "template <typename SetupFn>",
        f"void run_{dag.function}_parallel(SetupFn &&emit_serial_statement,",
        "                           std::size_t he_dag_threads = std::thread::hardware_concurrency())",
        "{",
        "    poseidon::ThreadPool pool(he_dag_threads == 0 ? 1 : he_dag_threads);",
        "",
    ]

    for layer in sorted(layers):
        group = [op_index[op_id] for op_id in layers[layer]]
        lines.append(f"    // layer {layer}")
        if len(group) == 1:
            op = group[0]
            lines.append(f'    emit_serial_statement(R"stmt({op.source_text};)stmt");')
        else:
            for op in group:
                lines.append("    pool.enqueue([&]() {")
                lines.append(f'        emit_serial_statement(R"stmt({op.source_text};)stmt");')
                lines.append("    });")
            lines.append("    pool.wait_all();")
        lines.append("")

    lines.extend(["}", "", f"}}  // namespace {namespace}", ""])
    return "\n".join(lines)


def _node_label(op) -> str:
    parts = [
        op.id,
        op.kind,
        f"line {op.source_line}",
        f"cost {op.cost}",
    ]
    if op.outputs:
        parts.append("out " + ", ".join(op.outputs))
    if op.inputs:
        parts.append("in " + ", ".join(op.inputs))
    return "\\n".join(parts)

