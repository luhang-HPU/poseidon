# HE DAG Tooling Prototype

This repository now includes a first-pass prototype for extracting and analyzing a restricted
homomorphic-encryption application DAG from C++ source.

## Scope

The current prototype is intentionally conservative.

- It targets a restricted C++ subset centered on explicit HE API calls such as
  `encode`, `encrypt`, `add`, `sub`, `multiply`, `rotate`, `rescale_dynamic`,
  `relinearize`, `evaluate_poly_vector`, and `bootstrap`.
- It assumes the main HE workflow lives in a single function.
- It tracks explicit result variables and treats in-place writes as ordered hazards.
- It can expand very simple static `for (int i = 0; i < N; i++)` loops when `N` is a literal or a
  previously declared integer constant.
- It does not attempt whole-program alias analysis or general-purpose C++ compilation.

The front-end is implemented as a repo-local Python prototype so the end-to-end flow is runnable
without depending on Clang development libraries. The IR and CLI boundaries are kept narrow so a
future Clang LibTooling extractor can replace the parser without changing visualization and
scheduling layers.

## CLI entrypoints

- `python3 tools/he_dag_extract/he_dag_extract.py input.cpp --function knn_ckks_demo --out dag.json`
- `python3 tools/he_dag_visualize/he_dag_viz.py dag.json --out dag.dot`
- `python3 tools/he_dag_visualize/he_dag_viz.py dag.json --grouped --out dag_grouped.dot`
- `python3 tools/he_dag_visualize/he_dag_viz.py dag.json --format summary --out dag_summary.json`
- `python3 tools/he_codegen/he_dag_codegen.py dag.json --scheduler levelized --out knn_parallel_gen.cpp`

## IR shape

The generated JSON includes:

- `values`: tracked HE values and transient literals
- `ops`: extracted operations with source location, cost, barrier flag, and schedule metadata
- `edges`: `data`, `resource`, `order`, and `anti` dependencies
- `parallel_groups`: levelized scheduling result
- `metadata`: supported methods, critical-path estimate, and validation info

## Outputs

Visualization currently emits:

- raw DOT DAG
- grouped DOT DAG, clustered by scheduled layer
- a JSON summary with critical-path and layer information

Code generation currently emits a conservative C++ schedule skeleton:

- each DAG layer is preserved
- multi-op layers become thread-pool tasks
- barrier operations are isolated into their own layers
- the generated code uses `poseidon::ThreadPool`

This skeleton is designed to make the parallel schedule explicit and reviewable. It is a safe
starting point for a future source-to-source rewrite pass that reconstructs full compilable
functions.
