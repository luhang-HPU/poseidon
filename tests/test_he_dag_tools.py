from __future__ import annotations

from pathlib import Path
import unittest

from tools.he_dag.analysis import analyze_dag, validate_parallel_groups
from tools.he_dag.parser import extract_he_dag
from tools.he_dag.render import dag_to_cpp


REPO_ROOT = Path(__file__).resolve().parents[1]
SAMPLE = REPO_ROOT / "tools" / "he_dag" / "samples" / "knn_ckks_demo.cpp"
CKKS_BASIC = REPO_ROOT / "examples" / "ckks" / "test_ckks_basic.cpp"


class HEDagToolingTests(unittest.TestCase):
    def test_extracts_sample_knn_graph(self) -> None:
        dag = analyze_dag(extract_he_dag(str(SAMPLE), "knn_ckks_demo"))

        self.assertEqual(len(dag.ops), 7)
        self.assertEqual(dag.parallel_groups, [["op0", "op1"], ["op2", "op3"], ["op4"], ["op5"], ["op6"]])
        self.assertEqual(dag.metadata["critical_path_cost"], 12)
        self.assertEqual(validate_parallel_groups(dag), [])

    def test_extracts_existing_ckks_example(self) -> None:
        dag = analyze_dag(extract_he_dag(str(CKKS_BASIC), "main"))

        self.assertGreaterEqual(len(dag.ops), 20)
        self.assertEqual(dag.unsupported, [])
        self.assertGreaterEqual(dag.metadata["max_parallel_width"], 2)

    def test_codegen_includes_thread_pool_schedule(self) -> None:
        dag = analyze_dag(extract_he_dag(str(SAMPLE), "knn_ckks_demo"))
        generated = dag_to_cpp(dag)

        self.assertIn('poseidon::ThreadPool pool', generated)
        self.assertIn('pool.wait_all();', generated)
        self.assertIn('ckks_eva.multiply(diff0, diff0, sq0);', generated)


if __name__ == "__main__":
    unittest.main()
