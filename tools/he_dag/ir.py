from __future__ import annotations

from dataclasses import asdict, dataclass, field
import json
from typing import Any


@dataclass
class Value:
    id: str
    name: str
    kind: str
    version: int = 0
    source_line: int | None = None
    producer: str | None = None
    is_ephemeral: bool = False
    annotations: dict[str, Any] = field(default_factory=dict)


@dataclass
class Op:
    id: str
    kind: str
    method: str
    receiver: str | None
    inputs: list[str]
    outputs: list[str]
    resources: list[str]
    constants: list[str]
    source_line: int
    source_text: str
    cost: int
    level: int | None = None
    scale: str | None = None
    barrier: bool = False
    layer: int | None = None
    earliest_start: int | None = None
    earliest_finish: int | None = None
    latest_start: int | None = None
    latest_finish: int | None = None
    slack: int | None = None
    critical: bool = False
    annotations: dict[str, Any] = field(default_factory=dict)


@dataclass
class Edge:
    src: str
    dst: str
    kind: str
    value: str | None = None
    reason: str | None = None


@dataclass
class Dag:
    source_file: str
    function: str
    source_hash: str
    values: list[Value]
    ops: list[Op]
    edges: list[Edge]
    parallel_groups: list[list[str]] = field(default_factory=list)
    unsupported: list[dict[str, Any]] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "source_file": self.source_file,
            "function": self.function,
            "source_hash": self.source_hash,
            "values": [asdict(value) for value in self.values],
            "ops": [asdict(op) for op in self.ops],
            "edges": [asdict(edge) for edge in self.edges],
            "parallel_groups": self.parallel_groups,
            "unsupported": self.unsupported,
            "metadata": self.metadata,
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2, sort_keys=True)

    @staticmethod
    def from_dict(data: dict[str, Any]) -> "Dag":
        return Dag(
            source_file=data["source_file"],
            function=data["function"],
            source_hash=data.get("source_hash", ""),
            values=[Value(**value) for value in data.get("values", [])],
            ops=[Op(**op) for op in data.get("ops", [])],
            edges=[Edge(**edge) for edge in data.get("edges", [])],
            parallel_groups=data.get("parallel_groups", []),
            unsupported=data.get("unsupported", []),
            metadata=data.get("metadata", {}),
        )

    @staticmethod
    def from_json(text: str) -> "Dag":
        return Dag.from_dict(json.loads(text))

