from __future__ import annotations

import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

from dag_generator.hedag.frontend import extract_program
from dag_generator.hedag.pipeline import default_case_name, default_output_dir, run_pipeline
from dag_generator.hedag.passes import build_execution_plan, build_graph, build_rewrite_plan
from dag_generator.hedag.render import render_summary


REPO_ROOT = Path(__file__).resolve().parents[1]
SAMPLE = REPO_ROOT / "dag_generator" / "hedag" / "samples" / "knn_ckks_demo.cpp"
BOOTSTRAP = REPO_ROOT / "examples" / "ckks" / "test_ckks_bootstrap.cpp"
HELPER_SAMPLE = REPO_ROOT / "tests" / "fixtures" / "hedag_helper.cpp"
INPLACE_SAMPLE = REPO_ROOT / "tests" / "fixtures" / "hedag_inplace.cpp"
INDEXED_SAMPLE = REPO_ROOT / "tests" / "fixtures" / "hedag_indexed.cpp"
CONTROL_FLOW_SAMPLE = REPO_ROOT / "tests" / "fixtures" / "hedag_control_flow.cpp"
KNN_AST_FIXTURE = REPO_ROOT / "tests" / "fixtures" / "hedag_knn_ast.json"


class HEDagToolingTests(unittest.TestCase):
    def test_pipeline_helpers_choose_default_output_dir(self) -> None:
        case_name = default_case_name(str(SAMPLE), "knn_ckks_demo")
        output_dir = default_output_dir(REPO_ROOT, str(SAMPLE), "knn_ckks_demo")

        self.assertEqual(case_name, "knn_ckks_demo")
        self.assertEqual(output_dir, REPO_ROOT / "dag_generator" / "hedag_output" / "knn_ckks_demo")

    def test_extracts_sample_knn_graph_v2(self) -> None:
        program = extract_program(str(SAMPLE), "knn_ckks_demo")
        graph = build_graph(program)
        plan = build_execution_plan(graph)
        rewrite_plan = build_rewrite_plan(graph, plan)

        self.assertEqual(graph.frontend, "textual_fallback")
        self.assertEqual(len(graph.ops), 7)
        self.assertEqual(plan.layers, [["op0", "op1"], ["op2", "op3"], ["op4"], ["op5"], ["op6"]])
        self.assertEqual(plan.critical_path_cost, 12)
        self.assertEqual(rewrite_plan.status, "ready")
        self.assertEqual(graph.diagnostics, [])

    def test_extracts_with_clang_ast_fixture(self) -> None:
        program = extract_program(str(SAMPLE), "knn_ckks_demo", frontend="clang", clang_ast_json=str(KNN_AST_FIXTURE))
        graph = build_graph(program)
        plan = build_execution_plan(graph)

        self.assertEqual(program.frontend, "clang_ast_json")
        self.assertEqual(program.metadata["frontend_mode"], "clang_ast_json")
        self.assertEqual(program.metadata["clang_ast"]["mode"], "json_fixture")
        self.assertEqual(len(graph.ops), 7)
        self.assertEqual(plan.critical_path_cost, 12)

    def test_extracts_bootstrap_resources(self) -> None:
        program = extract_program(str(BOOTSTRAP), "main")
        graph = build_graph(program)
        bootstrap_ops = [op for op in graph.ops if op.op_kind == "bootstrap"]

        self.assertEqual(len(bootstrap_ops), 1)
        bootstrap_op = bootstrap_ops[0]
        resource_names = {value_id.split("@", 1)[0] for value_id in bootstrap_op.resources}
        self.assertIn("relin_keys", resource_names)
        self.assertIn("rot_keys", resource_names)
        self.assertIn("ckks_encoder", resource_names)

    def test_inlines_same_file_helper_calls(self) -> None:
        program = extract_program(str(HELPER_SAMPLE), "helper_demo")
        graph = build_graph(program)

        self.assertEqual([op.op_kind for op in graph.ops], ["sub", "multiply_relin", "assign"])
        self.assertTrue(graph.ops[0].origin_callstack)
        self.assertIn("helper_demo", graph.ops[0].origin_callstack[0]["function"])

    def test_models_in_place_hazards(self) -> None:
        graph = build_graph(extract_program(str(INPLACE_SAMPLE), "inplace_demo"))
        edge_kinds = {edge.kind for edge in graph.edges}

        self.assertIn("write_after_write", edge_kinds)
        self.assertIn("read_after_write", edge_kinds)
        self.assertIn("write_after_read", edge_kinds)

    def test_keeps_indexed_symbol_identity(self) -> None:
        graph = build_graph(extract_program(str(INDEXED_SAMPLE), "indexed_demo"))
        indexed = [value for value in graph.values if value.symbol.kind == "indexed"]

        self.assertTrue(indexed)
        self.assertTrue(any(value.symbol.base == "data" and value.symbol.index == "0" for value in indexed))
        self.assertTrue(any(value.symbol.base == "query" and value.symbol.index == "1" for value in indexed))

    def test_reports_blocking_control_flow_diagnostics(self) -> None:
        program = extract_program(str(CONTROL_FLOW_SAMPLE), "control_flow_demo")
        reasons = {diagnostic.reason for diagnostic in program.diagnostics}

        self.assertTrue(program.diagnostics)
        self.assertIn("unsupported control flow: if", reasons)
        self.assertIn("unsupported dynamic loop boundary", reasons)

    def test_cli_roundtrip_writes_v2_artifacts(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            out_dir = Path(tmpdir)
            subprocess.run(
                ["python3", "-m", "dag_generator.hedag", "extract", str(SAMPLE), "--function", "knn_ckks_demo", "--out-dir", str(out_dir)],
                check=True,
                cwd=REPO_ROOT,
            )
            subprocess.run(
                ["python3", "-m", "dag_generator.hedag", "analyze", str(out_dir / "graph.json"), "--out-dir", str(out_dir)],
                check=True,
                cwd=REPO_ROOT,
            )
            subprocess.run(
                [
                    "python3",
                    "-m",
                    "dag_generator.hedag",
                    "rewrite-plan",
                    str(out_dir / "graph.json"),
                    str(out_dir / "execution_plan.json"),
                    "--out-dir",
                    str(out_dir),
                ],
                check=True,
                cwd=REPO_ROOT,
            )
            subprocess.run(
                [
                    "python3",
                    "-m",
                    "dag_generator.hedag",
                    "render",
                    str(out_dir / "graph.json"),
                    str(out_dir / "execution_plan.json"),
                    "--format",
                    "summary",
                    "--rewrite-plan",
                    str(out_dir / "rewrite_plan.json"),
                    "--out",
                    str(out_dir / "summary.json"),
                ],
                check=True,
                cwd=REPO_ROOT,
            )

            graph = json.loads((out_dir / "graph.json").read_text(encoding="utf-8"))
            execution = json.loads((out_dir / "execution_plan.json").read_text(encoding="utf-8"))
            rewrite = json.loads((out_dir / "rewrite_plan.json").read_text(encoding="utf-8"))
            summary = json.loads((out_dir / "summary.json").read_text(encoding="utf-8"))

            self.assertEqual(graph["schema_version"], 2)
            self.assertEqual(execution["critical_path_cost"], 12)
            self.assertEqual(rewrite["status"], "ready")
            self.assertEqual(summary["rewrite_status"], "ready")

    def test_pipeline_script_runs_end_to_end(self) -> None:
        out_dir = REPO_ROOT / "dag_generator" / "hedag_output" / "unittest_pipeline_case"
        if out_dir.exists():
            shutil.rmtree(out_dir)
        try:
            subprocess.run(
                [
                    str(REPO_ROOT / "hedag_pipeline"),
                    str(SAMPLE),
                    "--function",
                    "knn_ckks_demo",
                    "--case-name",
                    "unittest_pipeline_case",
                ],
                check=True,
                cwd=REPO_ROOT,
            )
            self.assertTrue((out_dir / "graph.json").exists())
            self.assertTrue((out_dir / "execution_plan.json").exists())
            self.assertTrue((out_dir / "rewrite_plan.json").exists())
            self.assertTrue((out_dir / "summary.json").exists())
            self.assertTrue((out_dir / "graph.dot").exists())
        finally:
            if out_dir.exists():
                shutil.rmtree(out_dir)

    def test_run_pipeline_python_api(self) -> None:
        out_dir = REPO_ROOT / "dag_generator" / "hedag_output" / "unittest_python_api_case"
        if out_dir.exists():
            shutil.rmtree(out_dir)
        try:
            result = run_pipeline(
                repo_root=REPO_ROOT,
                input_path=str(SAMPLE),
                function_name="knn_ckks_demo",
                case_name="unittest_python_api_case",
            )
            self.assertEqual(Path(result["output_dir"]), out_dir)
            self.assertTrue((out_dir / "graph.json").exists())
            self.assertTrue((out_dir / "summary.json").exists())
        finally:
            if out_dir.exists():
                shutil.rmtree(out_dir)

    def test_cli_extract_accepts_clang_ast_fixture(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            out_dir = Path(tmpdir)
            subprocess.run(
                [
                    "python3",
                    "-m",
                    "dag_generator.hedag",
                    "extract",
                    str(SAMPLE),
                    "--function",
                    "knn_ckks_demo",
                    "--frontend",
                    "clang",
                    "--clang-ast-json",
                    str(KNN_AST_FIXTURE),
                    "--out-dir",
                    str(out_dir),
                ],
                check=True,
                cwd=REPO_ROOT,
            )
            graph = json.loads((out_dir / "graph.json").read_text(encoding="utf-8"))
            self.assertEqual(graph["frontend"], "clang_ast_json")

    def test_render_summary_matches_execution_plan(self) -> None:
        graph = build_graph(extract_program(str(SAMPLE), "knn_ckks_demo"))
        execution = build_execution_plan(graph)
        rewrite = build_rewrite_plan(graph, execution)
        summary = json.loads(render_summary(graph, execution, rewrite.status))

        self.assertEqual(summary["critical_path_cost"], 12)
        self.assertEqual(summary["rewrite_status"], "ready")


if __name__ == "__main__":
    unittest.main()
