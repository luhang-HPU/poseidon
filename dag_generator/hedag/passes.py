from __future__ import annotations

from collections import defaultdict, deque
from typing import Any

from .frontend import NormalizedProgram
from .ir import DepEdge, ExecutionPlan, Graph, OpNode, RewritePlan, SymbolRef, ValueNode


def build_graph(program: NormalizedProgram) -> Graph:
    values: list[ValueNode] = []
    ops: list[OpNode] = []
    value_index: dict[str, ValueNode] = {}
    current_version: dict[str, int] = {}

    def ensure_value(symbol: SymbolRef, value_kind: str, version: int, origin_scope: str, producer: str | None, span) -> str:
        value_id = f"{symbol.key()}@{version}"
        if value_id not in value_index:
            value_index[value_id] = ValueNode(
                value_id=value_id,
                symbol=symbol,
                ssa_index=version,
                value_kind=value_kind,
                source_span=span,
                origin_scope=origin_scope,
                producer_op_id=producer,
                annotations={},
            )
            values.append(value_index[value_id])
        return value_id

    symbol_kinds = {key: declared.value_kind for key, declared in program.declared_symbols.items()}
    symbol_scopes = {key: declared.origin_scope for key, declared in program.declared_symbols.items()}
    symbol_spans = {key: declared.source_span for key, declared in program.declared_symbols.items()}

    for key, declared in program.declared_symbols.items():
        current_version.setdefault(key, 0)
        ensure_value(declared.symbol, declared.value_kind, 0, declared.origin_scope, None, declared.source_span)

    for op_index, normalized in enumerate(program.operations):
        op_id = f"op{op_index}"
        input_ids: list[str] = []
        output_ids: list[str] = []
        resource_ids: list[str] = []

        for symbol in normalized.input_symbols:
            kind = symbol_kinds.get(symbol.key(), "external")
            span = symbol_spans.get(symbol.key(), normalized.source_span)
            scope = symbol_scopes.get(symbol.key(), program.entry_function)
            input_ids.append(ensure_value(symbol, kind, current_version.get(symbol.key(), 0), scope, None, span))

        for symbol in normalized.resource_symbols:
            kind = symbol_kinds.get(symbol.key(), "resource")
            span = symbol_spans.get(symbol.key(), normalized.source_span)
            scope = symbol_scopes.get(symbol.key(), program.entry_function)
            resource_ids.append(ensure_value(symbol, kind, current_version.get(symbol.key(), 0), scope, None, span))

        for symbol in normalized.output_symbols:
            kind = symbol_kinds.get(symbol.key(), "external")
            span = normalized.source_span
            scope = symbol_scopes.get(symbol.key(), program.entry_function)
            next_version = current_version.get(symbol.key(), 0) + 1
            current_version[symbol.key()] = next_version
            symbol_spans[symbol.key()] = span
            output_ids.append(ensure_value(symbol, kind, next_version, scope, op_id, span))

        ops.append(
            OpNode(
                op_id=op_id,
                op_kind=normalized.op_kind,
                api_name=normalized.api_name,
                inputs=input_ids,
                outputs=output_ids,
                resources=resource_ids,
                attrs=dict(normalized.attrs),
                effects=[dict(effect) for effect in normalized.effects],
                stmt_id=normalized.stmt_id,
                source_span=normalized.source_span,
                origin_callstack=[dict(frame) for frame in normalized.origin_callstack],
            )
        )

    graph = Graph(
        schema_version=2,
        source_file=program.source_file,
        entry_function=program.entry_function,
        frontend=program.frontend,
        values=values,
        ops=ops,
        edges=[],
        diagnostics=list(program.diagnostics),
        metadata=dict(program.metadata),
    )
    add_dependency_edges(graph)
    return graph


def add_dependency_edges(graph: Graph) -> Graph:
    value_map = {value.value_id: value for value in graph.values}
    producer_map = {output: op.op_id for op in graph.ops for output in op.outputs}
    existing: set[tuple[str, str, str, str | None]] = set()
    edges: list[DepEdge] = []

    last_writer: dict[str, str] = {}
    readers_since_last_write: dict[str, set[str]] = defaultdict(set)

    def add_edge(src: str, dst: str, kind: str, value_id: str | None, reason: str | None) -> None:
        key = (src, dst, kind, value_id)
        if src == dst or key in existing:
            return
        existing.add(key)
        edges.append(DepEdge(src=src, dst=dst, kind=kind, value_id=value_id, reason=reason))

    for op in graph.ops:
        read_symbols: list[str] = []
        for value_id in op.inputs:
            producer = producer_map.get(value_id)
            symbol_key = value_map[value_id].symbol.key()
            read_symbols.append(symbol_key)
            if producer:
                add_edge(producer, op.op_id, "data", value_id, symbol_key)
            if symbol_key in last_writer:
                add_edge(last_writer[symbol_key], op.op_id, "read_after_write", value_id, symbol_key)
            readers_since_last_write[symbol_key].add(op.op_id)
        for value_id in op.resources:
            producer = producer_map.get(value_id)
            symbol_key = value_map[value_id].symbol.key()
            if producer:
                add_edge(producer, op.op_id, "resource_use", value_id, symbol_key)
        for value_id in op.outputs:
            symbol_key = value_map[value_id].symbol.key()
            if symbol_key in last_writer:
                add_edge(last_writer[symbol_key], op.op_id, "write_after_write", value_id, symbol_key)
            for reader in sorted(readers_since_last_write[symbol_key]):
                add_edge(reader, op.op_id, "write_after_read", value_id, symbol_key)
            last_writer[symbol_key] = op.op_id
            readers_since_last_write[symbol_key] = {op.op_id} if symbol_key in read_symbols else set()
        if op.origin_callstack:
            parent_stmt = op.origin_callstack[-1]["stmt_id"]
            for prev in reversed(graph.ops[: int(op.op_id[2:])]):
                if prev.origin_callstack and prev.origin_callstack[-1]["stmt_id"] == parent_stmt:
                    add_edge(prev.op_id, op.op_id, "call_order", None, parent_stmt)
                    break

    graph.edges = edges
    return graph


def build_execution_plan(graph: Graph) -> ExecutionPlan:
    op_index = {op.op_id: op for op in graph.ops}
    indegree = {op.op_id: 0 for op in graph.ops}
    successors: dict[str, list[str]] = defaultdict(list)
    predecessors: dict[str, list[str]] = defaultdict(list)

    for edge in graph.edges:
        if edge.src in indegree and edge.dst in indegree:
            indegree[edge.dst] += 1
            successors[edge.src].append(edge.dst)
            predecessors[edge.dst].append(edge.src)

    queue = deque(
        sorted(
            [op_id for op_id, degree in indegree.items() if degree == 0],
            key=lambda item: op_index[item].source_span.start.offset,
        )
    )
    topo: list[str] = []
    depth: dict[str, int] = {}
    while queue:
        current = queue.popleft()
        topo.append(current)
        if predecessors[current]:
            depth[current] = max(depth[parent] + 1 for parent in predecessors[current])
        else:
            depth[current] = 0
        for nxt in successors[current]:
            indegree[nxt] -= 1
            if indegree[nxt] == 0:
                queue.append(nxt)

    if len(topo) != len(graph.ops):
        raise ValueError("cycle detected in semantic graph")

    earliest_finish: dict[str, int] = {}
    latest_start: dict[str, int] = {}
    latest_finish: dict[str, int] = {}
    op_schedule: dict[str, dict[str, Any]] = {}
    for op_id in topo:
        op = op_index[op_id]
        cost = int(op.attrs.get("cost", 1))
        es = max((earliest_finish[parent] for parent in predecessors[op_id]), default=0)
        ef = es + cost
        earliest_finish[op_id] = ef
        op_schedule[op_id] = {
            "earliest_start": es,
            "earliest_finish": ef,
            "cost": cost,
            "source_line": op.source_span.start.line,
            "barrier": bool(op.attrs.get("barrier", False)),
        }

    makespan = max(earliest_finish.values(), default=0)
    for op_id in reversed(topo):
        cost = int(op_index[op_id].attrs.get("cost", 1))
        lf = min((latest_start[child] for child in successors[op_id]), default=makespan)
        ls = lf - cost
        latest_start[op_id] = ls
        latest_finish[op_id] = lf
        op_schedule[op_id]["latest_start"] = ls
        op_schedule[op_id]["latest_finish"] = lf
        op_schedule[op_id]["slack"] = ls - op_schedule[op_id]["earliest_start"]
        op_schedule[op_id]["critical"] = op_schedule[op_id]["slack"] == 0

    grouped: dict[int, list[str]] = defaultdict(list)
    for op_id in topo:
        grouped[depth[op_id]].append(op_id)
    layers: list[list[str]] = []
    barriers: list[str] = []
    for _, group in sorted(grouped.items()):
        barrier_group = [op_id for op_id in group if op_index[op_id].attrs.get("barrier", False)]
        normal_group = [op_id for op_id in group if not op_index[op_id].attrs.get("barrier", False)]
        if normal_group:
            layers.append(normal_group)
        for barrier in barrier_group:
            layers.append([barrier])
            barriers.append(barrier)

    for layer_index, layer in enumerate(layers):
        for op_id in layer:
            op_schedule[op_id]["layer"] = layer_index

    return ExecutionPlan(
        schema_version=2,
        source_file=graph.source_file,
        entry_function=graph.entry_function,
        layers=layers,
        topological_order=topo,
        critical_path_cost=makespan,
        max_parallel_width=max((len(layer) for layer in layers), default=0),
        barriers=barriers,
        op_schedule=op_schedule,
        metadata={"frontend": graph.frontend},
    )


def build_rewrite_plan(graph: Graph, execution_plan: ExecutionPlan) -> RewritePlan:
    blocking = [diagnostic.to_dict() for diagnostic in graph.diagnostics if diagnostic.blocking]
    status = "blocked" if blocking else "ready"
    op_map = {op.op_id: op for op in graph.ops}
    regions: list[dict[str, Any]] = []
    parallel_blocks: list[dict[str, Any]] = []
    for index, layer in enumerate(execution_plan.layers):
        region = {
            "region_id": f"region{index}",
            "kind": "parallel" if len(layer) > 1 else "serial",
            "op_ids": list(layer),
            "stmt_ids": [op_map[op_id].stmt_id for op_id in layer],
            "source_spans": [
                {
                    "file": op_map[op_id].source_span.file,
                    "start": {
                        "line": op_map[op_id].source_span.start.line,
                        "column": op_map[op_id].source_span.start.column,
                        "offset": op_map[op_id].source_span.start.offset,
                    },
                    "end": {
                        "line": op_map[op_id].source_span.end.line,
                        "column": op_map[op_id].source_span.end.column,
                        "offset": op_map[op_id].source_span.end.offset,
                    },
                }
                for op_id in layer
            ],
        }
        regions.append(region)
        if len(layer) > 1:
            parallel_blocks.append(
                {
                    "region_id": region["region_id"],
                    "op_ids": list(layer),
                    "anchor_stmt_ids": region["stmt_ids"],
                }
            )

    temporary_keys: set[str] = set()
    value_versions: defaultdict[str, set[int]] = defaultdict(set)
    for value in graph.values:
        value_versions[value.symbol.key()].add(value.ssa_index)
    for symbol_key, versions in value_versions.items():
        if len(versions) > 1:
            temporary_keys.add(symbol_key)
    for op in graph.ops:
        for effect in op.effects:
            if effect.get("kind") == "in_place_write":
                symbol = effect.get("symbol", {}).get("text")
                if symbol:
                    temporary_keys.add(symbol)

    required_temporaries = [{"symbol": key} for key in sorted(temporary_keys)]
    anchor = graph.metadata.get("entry_span", {})
    return RewritePlan(
        schema_version=2,
        source_file=graph.source_file,
        entry_function=graph.entry_function,
        status=status,
        regions=regions,
        operation_order=list(execution_plan.topological_order),
        parallel_blocks=parallel_blocks,
        required_temporaries=required_temporaries,
        barriers=list(execution_plan.barriers),
        source_edits_anchor=anchor,
        blocking_diagnostics=blocking,
        metadata={"frontend": graph.frontend},
    )
