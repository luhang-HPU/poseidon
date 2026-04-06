from __future__ import annotations

from dataclasses import asdict, dataclass, field
import json
from typing import Any


@dataclass
class SourcePosition:
    line: int
    column: int
    offset: int

    @staticmethod
    def from_dict(data: dict[str, Any]) -> "SourcePosition":
        return SourcePosition(
            line=data["line"],
            column=data["column"],
            offset=data["offset"],
        )


@dataclass
class SourceSpan:
    file: str
    start: SourcePosition
    end: SourcePosition

    @staticmethod
    def from_dict(data: dict[str, Any]) -> "SourceSpan":
        return SourceSpan(
            file=data["file"],
            start=SourcePosition.from_dict(data["start"]),
            end=SourcePosition.from_dict(data["end"]),
        )


@dataclass
class SymbolRef:
    kind: str
    text: str
    base: str | None = None
    index: str | None = None

    def key(self) -> str:
        return self.text

    @staticmethod
    def from_dict(data: dict[str, Any]) -> "SymbolRef":
        return SymbolRef(
            kind=data["kind"],
            text=data["text"],
            base=data.get("base"),
            index=data.get("index"),
        )


@dataclass
class Diagnostic:
    severity: str
    blocking: bool
    reason: str
    stmt_id: str | None
    source_span: SourceSpan
    suggested_fallback: str | None = None
    details: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "severity": self.severity,
            "blocking": self.blocking,
            "reason": self.reason,
            "stmt_id": self.stmt_id,
            "source_span": asdict(self.source_span),
            "suggested_fallback": self.suggested_fallback,
            "details": self.details,
        }

    @staticmethod
    def from_dict(data: dict[str, Any]) -> "Diagnostic":
        return Diagnostic(
            severity=data["severity"],
            blocking=data["blocking"],
            reason=data["reason"],
            stmt_id=data.get("stmt_id"),
            source_span=SourceSpan.from_dict(data["source_span"]),
            suggested_fallback=data.get("suggested_fallback"),
            details=data.get("details", {}),
        )


@dataclass
class ValueNode:
    value_id: str
    symbol: SymbolRef
    ssa_index: int
    value_kind: str
    source_span: SourceSpan
    origin_scope: str
    producer_op_id: str | None = None
    annotations: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "value_id": self.value_id,
            "symbol": asdict(self.symbol),
            "ssa_index": self.ssa_index,
            "value_kind": self.value_kind,
            "source_span": asdict(self.source_span),
            "origin_scope": self.origin_scope,
            "producer_op_id": self.producer_op_id,
            "annotations": self.annotations,
        }

    @staticmethod
    def from_dict(data: dict[str, Any]) -> "ValueNode":
        return ValueNode(
            value_id=data["value_id"],
            symbol=SymbolRef.from_dict(data["symbol"]),
            ssa_index=data["ssa_index"],
            value_kind=data["value_kind"],
            source_span=SourceSpan.from_dict(data["source_span"]),
            origin_scope=data["origin_scope"],
            producer_op_id=data.get("producer_op_id"),
            annotations=data.get("annotations", {}),
        )


@dataclass
class OpNode:
    op_id: str
    op_kind: str
    api_name: str
    inputs: list[str]
    outputs: list[str]
    resources: list[str]
    attrs: dict[str, Any]
    effects: list[dict[str, Any]]
    stmt_id: str
    source_span: SourceSpan
    origin_callstack: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "op_id": self.op_id,
            "op_kind": self.op_kind,
            "api_name": self.api_name,
            "inputs": self.inputs,
            "outputs": self.outputs,
            "resources": self.resources,
            "attrs": self.attrs,
            "effects": self.effects,
            "stmt_id": self.stmt_id,
            "source_span": asdict(self.source_span),
            "origin_callstack": self.origin_callstack,
        }

    @staticmethod
    def from_dict(data: dict[str, Any]) -> "OpNode":
        return OpNode(
            op_id=data["op_id"],
            op_kind=data["op_kind"],
            api_name=data["api_name"],
            inputs=data.get("inputs", []),
            outputs=data.get("outputs", []),
            resources=data.get("resources", []),
            attrs=data.get("attrs", {}),
            effects=data.get("effects", []),
            stmt_id=data["stmt_id"],
            source_span=SourceSpan.from_dict(data["source_span"]),
            origin_callstack=data.get("origin_callstack", []),
        )


@dataclass
class DepEdge:
    src: str
    dst: str
    kind: str
    value_id: str | None = None
    reason: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @staticmethod
    def from_dict(data: dict[str, Any]) -> "DepEdge":
        return DepEdge(
            src=data["src"],
            dst=data["dst"],
            kind=data["kind"],
            value_id=data.get("value_id"),
            reason=data.get("reason"),
        )


@dataclass
class Graph:
    schema_version: int
    source_file: str
    entry_function: str
    frontend: str
    values: list[ValueNode]
    ops: list[OpNode]
    edges: list[DepEdge]
    diagnostics: list[Diagnostic]
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "source_file": self.source_file,
            "entry_function": self.entry_function,
            "frontend": self.frontend,
            "values": [value.to_dict() for value in self.values],
            "ops": [op.to_dict() for op in self.ops],
            "edges": [edge.to_dict() for edge in self.edges],
            "diagnostics": [diagnostic.to_dict() for diagnostic in self.diagnostics],
            "metadata": self.metadata,
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2, sort_keys=True)

    @staticmethod
    def from_dict(data: dict[str, Any]) -> "Graph":
        return Graph(
            schema_version=data["schema_version"],
            source_file=data["source_file"],
            entry_function=data["entry_function"],
            frontend=data["frontend"],
            values=[ValueNode.from_dict(item) for item in data.get("values", [])],
            ops=[OpNode.from_dict(item) for item in data.get("ops", [])],
            edges=[DepEdge.from_dict(item) for item in data.get("edges", [])],
            diagnostics=[Diagnostic.from_dict(item) for item in data.get("diagnostics", [])],
            metadata=data.get("metadata", {}),
        )

    @staticmethod
    def from_json(text: str) -> "Graph":
        return Graph.from_dict(json.loads(text))


@dataclass
class ExecutionPlan:
    schema_version: int
    source_file: str
    entry_function: str
    layers: list[list[str]]
    topological_order: list[str]
    critical_path_cost: int
    max_parallel_width: int
    barriers: list[str]
    op_schedule: dict[str, dict[str, Any]]
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2, sort_keys=True)

    @staticmethod
    def from_dict(data: dict[str, Any]) -> "ExecutionPlan":
        return ExecutionPlan(
            schema_version=data["schema_version"],
            source_file=data["source_file"],
            entry_function=data["entry_function"],
            layers=data.get("layers", []),
            topological_order=data.get("topological_order", []),
            critical_path_cost=data.get("critical_path_cost", 0),
            max_parallel_width=data.get("max_parallel_width", 0),
            barriers=data.get("barriers", []),
            op_schedule=data.get("op_schedule", {}),
            metadata=data.get("metadata", {}),
        )

    @staticmethod
    def from_json(text: str) -> "ExecutionPlan":
        return ExecutionPlan.from_dict(json.loads(text))


@dataclass
class RewritePlan:
    schema_version: int
    source_file: str
    entry_function: str
    status: str
    regions: list[dict[str, Any]]
    operation_order: list[str]
    parallel_blocks: list[dict[str, Any]]
    required_temporaries: list[dict[str, Any]]
    barriers: list[str]
    source_edits_anchor: dict[str, Any]
    blocking_diagnostics: list[dict[str, Any]]
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2, sort_keys=True)

    @staticmethod
    def from_dict(data: dict[str, Any]) -> "RewritePlan":
        return RewritePlan(
            schema_version=data["schema_version"],
            source_file=data["source_file"],
            entry_function=data["entry_function"],
            status=data["status"],
            regions=data.get("regions", []),
            operation_order=data.get("operation_order", []),
            parallel_blocks=data.get("parallel_blocks", []),
            required_temporaries=data.get("required_temporaries", []),
            barriers=data.get("barriers", []),
            source_edits_anchor=data.get("source_edits_anchor", {}),
            blocking_diagnostics=data.get("blocking_diagnostics", []),
            metadata=data.get("metadata", {}),
        )

    @staticmethod
    def from_json(text: str) -> "RewritePlan":
        return RewritePlan.from_dict(json.loads(text))
