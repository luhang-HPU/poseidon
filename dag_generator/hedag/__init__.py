"""HE DAG v2 package."""

from .cli import main
from .frontend import discover_tracked_functions, extract_program
from .ir import Diagnostic, ExecutionPlan, Graph, RewritePlan
from .passes import build_execution_plan, build_graph, build_rewrite_plan
from .pipeline import default_case_name, default_output_dir, run_pipeline

__all__ = [
    "Diagnostic",
    "ExecutionPlan",
    "Graph",
    "RewritePlan",
    "build_execution_plan",
    "build_graph",
    "build_rewrite_plan",
    "default_case_name",
    "default_output_dir",
    "discover_tracked_functions",
    "extract_program",
    "main",
    "run_pipeline",
]
