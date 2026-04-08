# HE DAG Tooling v2

This repository now includes a v2 HE DAG pipeline under `dag_generator/hedag/`. The v2 design is
source-to-source-rewrite oriented and separates extraction, graph construction, scheduling, and
rewrite planning into explicit stages.

## Scope

The v2 pipeline targets a restricted HE-oriented C++ subset with the following priorities:

- canonical semantic graph first, scheduling second
- precise source spans on all tracked operations
- same-file helper extraction with preserved callsite provenance
- explicit in-place write semantics and hazard edges
- separate `graph.json`, `execution_plan.json`, `rewrite_plan.json`, and `diagnostics.json`

Supported v1 scope for v2:

- explicit HE API calls such as `encode`, `encrypt`, `add`, `sub`, `multiply`, `rotate`,
  `rescale_dynamic`, `evaluate_poly_vector`, and `bootstrap`
- plain assignments and returns
- same-file helper calls with semantic inlining
- simple static `for` loops with literal or previously declared integer bounds
- indexed symbols such as `vec[i]`

Unsupported constructs currently emit structured diagnostics instead of being silently skipped:

- `if` / `else`, `while`, `switch`
- dynamic loop bounds
- complex aliasing
- cross-file helper extraction

## Frontend

The canonical frontend contract is a Clang AST frontend. The current implementation probes for a
local Clang toolchain and falls back to a repo-local textual frontend when Clang is unavailable in
the runtime environment. The produced semantic artifacts are the same shape in either mode, and the
selected frontend is recorded in graph metadata.

When Clang is available, the extractor reuses `build/compile_commands.json` when possible to derive
include paths and compile flags. For environments without a local Clang toolchain, the extractor can
also consume a pre-dumped AST JSON file via `--clang-ast-json`.

## CLI

The canonical CLI is `hedag` with four subcommands:

- `python3 -m dag_generator.hedag extract input.cpp --function knn_ckks_demo --out-dir /tmp/hedag`
- `python3 -m dag_generator.hedag extract input.cpp --function knn_ckks_demo --frontend clang --clang-ast-json /tmp/ast.json --out-dir /tmp/hedag`
- `python3 -m dag_generator.hedag analyze /tmp/hedag/graph.json --out-dir /tmp/hedag`
- `python3 -m dag_generator.hedag rewrite-plan /tmp/hedag/graph.json /tmp/hedag/execution_plan.json --out-dir /tmp/hedag`
- `python3 -m dag_generator.hedag render /tmp/hedag/graph.json /tmp/hedag/execution_plan.json --format summary --rewrite-plan /tmp/hedag/rewrite_plan.json --out /tmp/hedag/summary.json`

The repository root also includes a `hedag` launcher script that forwards to the same Python CLI.
If you want the whole pipeline in one command, use the root script:

- `./hedag_pipeline input.cpp --function knn_ckks_demo`
- `./hedag_pipeline input.cpp --function knn_ckks_demo --case-name my_case`
- `./hedag_pipeline input.cpp --function knn_ckks_demo --frontend clang --clang-ast-json /tmp/ast.json`
- `./hedag_trident`
- `./hedag_trident Trident/heartstudy/heartstudy.cpp`

By default, `hedag_pipeline` writes into:

- `dag_generator/hedag_output/<case-name>/`

The default case name is derived from the input file stem, with common example prefixes such as
`test_ckks_` stripped. If the function is not `main`, the function name is appended to avoid
collisions. Generic stems such as `main.cpp` fall back to the parent directory name so sibling
targets such as `Trident/pir_bfv/main.cpp` and `Trident/pir_bgv/main.cpp` no longer overwrite each
other. You can still override the location entirely with `--out-dir`.

For bulk Trident generation, `hedag_trident` scans `Trident/**/*.cpp`, discovers same-file
functions that directly contain tracked HE API calls or call helpers that do, and writes artifacts
into:

- `dag_generator/hedag_output/trident/<relative-source-dir>/<file-stem>__<function>/`

The batch command also writes an index file to:

- `dag_generator/hedag_output/trident/index.json`

## Web UI

For a browser-based workflow, the repository also includes a FastAPI backend plus a small frontend
page:

- install optional dependencies with `pip install -r requirements-hedag-web.txt`
- start the server with `./hedag_web`
- or run `./hedag_web --host 0.0.0.0 --port 8000`
- or run `python3 -m dag_generator.hedag.webapp --host 127.0.0.1 --port 8000`

Once the server is running, open:

- `http://127.0.0.1:8000/`

The web UI lets you:

- choose a sample or type a C++ source path
- pick the target function and frontend mode
- launch the full extract -> analyze -> rewrite-plan -> render pipeline
- inspect generated artifacts under `dag_generator/hedag_output/<case-name>/`

The backend exposes JSON APIs as well:

- `GET /api/options`
- `POST /api/run`
- `GET /api/output/{case_name}`
- `GET /api/file/{case_name}/{file_name}`

## Artifact Shape

`graph.json` contains:

- `values`: canonical SSA-like value nodes with structured symbols and source spans
- `ops`: semantic operation nodes with call provenance and rewrite-relevant effects
- `edges`: dependency edges such as `data`, `read_after_write`, `write_after_read`,
  `write_after_write`, `resource_use`, and `call_order`
- `diagnostics`: structured blocking and non-blocking diagnostics

`execution_plan.json` contains:

- topological order
- barrier-aware layers
- per-op timing/scheduling metadata
- critical path and max parallel width

`rewrite_plan.json` contains:

- rewrite regions
- operation order
- parallel blocks
- required temporaries
- barrier list
- source edit anchor

`diagnostics.json` contains the standalone serialized diagnostics list extracted from `graph.json`.

## Module Layout

The v2 implementation is split by responsibility:

- `dag_generator/hedag/frontend.py`: frontend extraction and normalized semantic statements
- `dag_generator/hedag/ir.py`: canonical graph, execution-plan, and rewrite-plan types
- `dag_generator/hedag/passes.py`: graph construction, dependency analysis, scheduling, and rewrite planning
- `dag_generator/hedag/render.py`: DOT and summary rendering
- `dag_generator/hedag/cli.py`: CLI orchestration

The v2 CLI and JSON formats above are the authoritative path forward.
