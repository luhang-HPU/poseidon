from __future__ import annotations

from collections import defaultdict, deque

from .ir import Dag, Edge


def analyze_dag(dag: Dag) -> Dag:
    op_index = {op.id: op for op in dag.ops}
    indegree = {op.id: 0 for op in dag.ops}
    successors: dict[str, list[str]] = defaultdict(list)
    predecessors: dict[str, list[str]] = defaultdict(list)

    for edge in dag.edges:
        if edge.src in indegree and edge.dst in indegree:
            indegree[edge.dst] += 1
            successors[edge.src].append(edge.dst)
            predecessors[edge.dst].append(edge.src)

    queue = deque(sorted((op_id for op_id, degree in indegree.items() if degree == 0), key=lambda item: op_index[item].source_line))
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

    if len(topo) != len(dag.ops):
        raise ValueError("cycle detected in extracted DAG")

    earliest_finish: dict[str, int] = {}
    for op_id in topo:
        op = op_index[op_id]
        earliest_start = 0
        if predecessors[op_id]:
            earliest_start = max(earliest_finish[parent] for parent in predecessors[op_id])
        earliest_finish[op_id] = earliest_start + op.cost
        op.earliest_start = earliest_start
        op.earliest_finish = earliest_finish[op_id]

    makespan = max((op.earliest_finish or 0 for op in dag.ops), default=0)
    latest_start: dict[str, int] = {}
    latest_finish: dict[str, int] = {}
    for op_id in reversed(topo):
        op = op_index[op_id]
        if successors[op_id]:
            lf = min(latest_start[child] for child in successors[op_id])
        else:
            lf = makespan
        ls = lf - op.cost
        latest_start[op_id] = ls
        latest_finish[op_id] = lf
        op.latest_start = ls
        op.latest_finish = lf
        op.slack = ls - (op.earliest_start or 0)
        op.critical = op.slack == 0

    grouped: dict[int, list[str]] = defaultdict(list)
    for op_id in topo:
        grouped[depth[op_id]].append(op_id)

    layers: list[list[str]] = []
    for _, group in sorted(grouped.items()):
        barrier = [op_id for op_id in group if op_index[op_id].barrier]
        normal = [op_id for op_id in group if not op_index[op_id].barrier]
        if normal:
            layers.append(normal)
        for op_id in barrier:
            layers.append([op_id])

    for layer_index, group in enumerate(layers):
        for op_id in group:
            op_index[op_id].layer = layer_index

    dag.parallel_groups = layers
    dag.metadata["critical_path_cost"] = makespan
    dag.metadata["max_parallel_width"] = max((len(group) for group in layers), default=0)
    dag.metadata["topological_order"] = topo
    return dag


def validate_parallel_groups(dag: Dag) -> list[str]:
    op_layer = {op.id: op.layer for op in dag.ops}
    issues: list[str] = []
    for edge in dag.edges:
        if edge.src in op_layer and edge.dst in op_layer:
            if op_layer[edge.src] is not None and op_layer[edge.dst] is not None and op_layer[edge.src] >= op_layer[edge.dst]:
                issues.append(f"{edge.src} -> {edge.dst} violates layer ordering")
    return issues

