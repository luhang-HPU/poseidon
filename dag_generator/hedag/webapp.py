from __future__ import annotations

import argparse
from pathlib import Path
import json
from typing import Any

from .pipeline import default_case_name, run_pipeline


try:
    from fastapi import FastAPI, HTTPException
    from fastapi.middleware.cors import CORSMiddleware
    from fastapi.responses import FileResponse, HTMLResponse
    from fastapi.staticfiles import StaticFiles
    import uvicorn
except ModuleNotFoundError:  # pragma: no cover - optional dependency path
    FastAPI = None  # type: ignore[assignment]
    HTTPException = RuntimeError  # type: ignore[assignment]
    CORSMiddleware = None  # type: ignore[assignment]
    FileResponse = None  # type: ignore[assignment]
    HTMLResponse = None  # type: ignore[assignment]
    StaticFiles = None  # type: ignore[assignment]
    uvicorn = None  # type: ignore[assignment]


ROOT = Path(__file__).resolve().parents[2]
STATIC_DIR = Path(__file__).resolve().parent / "web" / "static"


def _require_fastapi() -> None:
    if FastAPI is None or uvicorn is None:
        raise RuntimeError(
            "FastAPI web UI requires optional dependencies. Install them with "
            "`pip install -r requirements-hedag-web.txt`."
        )


def _discover_cpp_candidates() -> list[str]:
    roots = [
        ROOT / "dag_generator" / "hedag" / "samples",
        ROOT / "examples",
        ROOT / "tests" / "fixtures",
    ]
    candidates: list[str] = []
    for root in roots:
        if not root.exists():
            continue
        for suffix in ("*.cpp", "*.cc", "*.cxx"):
            for path in root.rglob(suffix):
                if path.is_file():
                    candidates.append(str(path.relative_to(ROOT)))
    return sorted(dict.fromkeys(candidates))


def _build_payload(result: dict[str, Any]) -> dict[str, Any]:
    graph = result["graph"]
    execution_plan = result["execution_plan"]
    rewrite_plan = result["rewrite_plan"]
    summary_path = result["files"].get("summary")
    summary = None
    if summary_path:
        summary = json.loads(Path(summary_path).read_text(encoding="utf-8"))
    preview_url = None
    files = result["files"]
    for key, suffix in (("svg", "graph.svg"), ("png", "graph.png")):
        file_path = files.get(key)
        if file_path:
            preview_url = f"/api/file/{result['case_name']}/{suffix}"
            break
    return {
        "output_dir": result["output_dir"],
        "case_name": result["case_name"],
        "files": files,
        "summary": summary,
        "rewrite_status": rewrite_plan.status,
        "diagnostic_count": len(graph.diagnostics),
        "layer_count": len(execution_plan.layers),
        "ops": len(graph.ops),
        "preview_url": preview_url,
    }


def create_app() -> "FastAPI":
    _require_fastapi()
    app = FastAPI(title="HE DAG UI", version="2")
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_methods=["*"],
        allow_headers=["*"],
    )

    @app.get("/api/health")
    def health() -> dict[str, Any]:
        return {"ok": True}

    @app.get("/api/options")
    def options() -> dict[str, Any]:
        samples = _discover_cpp_candidates()
        return {
            "samples": samples,
            "default_frontend": "auto",
            "default_sample": samples[0] if samples else "",
        }

    @app.post("/api/run")
    def run(request: dict[str, Any]) -> dict[str, Any]:
        input_path = request.get("input")
        function_name = request.get("function")
        if not input_path or not function_name:
            raise HTTPException(status_code=400, detail="input and function are required")
        resolved_input = ROOT / input_path if not Path(input_path).is_absolute() else Path(input_path)
        if not resolved_input.exists():
            raise HTTPException(status_code=404, detail=f"input file not found: {input_path}")

        case_name = request.get("case_name") or default_case_name(str(resolved_input), function_name)
        try:
            result = run_pipeline(
                repo_root=ROOT,
                input_path=str(resolved_input),
                function_name=function_name,
                frontend=request.get("frontend", "auto"),
                clang_ast_json=request.get("clang_ast_json"),
                out_dir=request.get("out_dir"),
                case_name=case_name,
                render_dot=not bool(request.get("skip_dot", False)),
                render_summary_file=not bool(request.get("skip_summary", False)),
            )
        except Exception as exc:
            raise HTTPException(status_code=500, detail=str(exc)) from exc
        return _build_payload(result)

    @app.get("/api/output/{case_name}")
    def output(case_name: str) -> dict[str, Any]:
        output_dir = ROOT / "dag_generator" / "hedag_output" / case_name
        if not output_dir.exists():
            raise HTTPException(status_code=404, detail=f"case not found: {case_name}")
        files = {
            "graph": output_dir / "graph.json",
            "execution_plan": output_dir / "execution_plan.json",
            "rewrite_plan": output_dir / "rewrite_plan.json",
            "diagnostics": output_dir / "diagnostics.json",
            "summary": output_dir / "summary.json",
            "dot": output_dir / "graph.dot",
            "svg": output_dir / "graph.svg",
            "png": output_dir / "graph.png",
        }
        return {
            "case_name": case_name,
            "output_dir": str(output_dir),
            "files": {name: str(path.relative_to(ROOT)) for name, path in files.items() if path.exists()},
        }

    @app.get("/api/file/{case_name}/{file_name}")
    def get_file(case_name: str, file_name: str):  # type: ignore[override]
        allowed = {
            "graph.json",
            "execution_plan.json",
            "rewrite_plan.json",
            "diagnostics.json",
            "summary.json",
            "graph.dot",
            "graph.svg",
            "graph.png",
        }
        if file_name not in allowed:
            raise HTTPException(status_code=404, detail="unsupported file")
        file_path = ROOT / "dag_generator" / "hedag_output" / case_name / file_name
        if not file_path.exists():
            raise HTTPException(status_code=404, detail="file not found")
        if file_name.endswith(".json"):
            media_type = "application/json"
        elif file_name.endswith(".svg"):
            media_type = "image/svg+xml"
        elif file_name.endswith(".png"):
            media_type = "image/png"
        else:
            media_type = "text/plain"
        return FileResponse(file_path, media_type=media_type, filename=file_name)

    @app.get("/", response_class=HTMLResponse)
    def index() -> str:
        return (STATIC_DIR / "index.html").read_text(encoding="utf-8")

    app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")
    return app


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="hedag_web", description="Run the HE DAG FastAPI web UI")
    parser.add_argument("--host", default="127.0.0.1", help="bind host")
    parser.add_argument("--port", type=int, default=8000, help="bind port")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    _require_fastapi()
    app = create_app()
    uvicorn.run(app, host=args.host, port=args.port)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
