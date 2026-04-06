from __future__ import annotations

from dataclasses import dataclass, field
import json
from pathlib import Path
import hashlib
import re
import shutil
import subprocess
import shlex
from typing import Any

from .ir import Diagnostic, SourcePosition, SourceSpan, SymbolRef


HE_TYPES = {
    "Ciphertext": "ciphertext",
    "Plaintext": "plaintext",
    "RelinKeys": "relin_keys",
    "GaloisKeys": "galois_keys",
    "PublicKey": "public_key",
    "SecretKey": "secret_key",
    "Encryptor": "encryptor",
    "Decryptor": "decryptor",
    "CKKSEncoder": "encoder",
    "BatchEncoder": "encoder",
    "KeyGenerator": "key_generator",
    "EvaluatorCkksBase": "evaluator",
    "EvaluatorBase": "evaluator",
    "PoseidonContext": "context",
    "PolynomialVector": "polynomial_vector",
    "EvalModPoly": "eval_mod_poly",
}

CONTAINER_VALUE_KINDS = {
    "std::vector<Ciphertext>": "ciphertext_vector",
    "vector<Ciphertext>": "ciphertext_vector",
    "std::vector<Plaintext>": "plaintext_vector",
    "vector<Plaintext>": "plaintext_vector",
    "std::vector<std::complex<double>>": "complex_vector",
    "vector<std::complex<double>>": "complex_vector",
    "std::vector<complex<double>>": "complex_vector",
    "vector<complex<double>>": "complex_vector",
}

INDEXED_KIND_MAP = {
    "ciphertext_vector": "ciphertext",
    "plaintext_vector": "plaintext",
    "complex_vector": "complex_vector_element",
}


@dataclass(frozen=True)
class ApiSpec:
    op_kind: str
    output_positions: list[int]
    resource_positions: list[int] = field(default_factory=list)
    constant_positions: list[int] = field(default_factory=list)
    cost: int = 1
    barrier: bool = False


API_SPECS = {
    "encode": ApiSpec("encode", [-1], cost=1),
    "decode": ApiSpec("decode", [-1], cost=1),
    "encrypt": ApiSpec("encrypt", [-1], cost=4),
    "decrypt": ApiSpec("decrypt", [-1], cost=4),
    "add": ApiSpec("add", [-1], cost=1),
    "sub": ApiSpec("sub", [-1], cost=1),
    "sub_dynamic": ApiSpec("sub_dynamic", [2], resource_positions=[3], cost=1),
    "add_plain": ApiSpec("add_plain", [-1], cost=1),
    "sub_plain": ApiSpec("sub_plain", [-1], cost=1),
    "multiply": ApiSpec("multiply", [-1], cost=5),
    "multiply_plain": ApiSpec("multiply_plain", [-1], cost=3),
    "multiply_relin": ApiSpec("multiply_relin", [2], resource_positions=[3], cost=6, barrier=True),
    "multiply_relin_dynamic": ApiSpec("multiply_relin_dynamic", [2], resource_positions=[3], cost=6, barrier=True),
    "multiply_const": ApiSpec("multiply_const", [3], resource_positions=[4], constant_positions=[1, 2], cost=3),
    "add_const": ApiSpec("add_const", [2], resource_positions=[3], constant_positions=[1], cost=1),
    "rotate": ApiSpec("rotate", [1], resource_positions=[3], constant_positions=[2], cost=4),
    "conjugate": ApiSpec("conjugate", [2], resource_positions=[1], cost=4),
    "rescale": ApiSpec("rescale", [-1], cost=4, barrier=True),
    "rescale_dynamic": ApiSpec("rescale_dynamic", [1], constant_positions=[2], cost=4, barrier=True),
    "relinearize": ApiSpec("relinearize", [1], resource_positions=[2], cost=4, barrier=True),
    "drop_modulus": ApiSpec("drop_modulus", [1], constant_positions=[2], cost=4, barrier=True),
    "drop_modulus_to_next": ApiSpec("drop_modulus_to_next", [1], cost=4, barrier=True),
    "ntt_fwd": ApiSpec("ntt_fwd", [-1], cost=3),
    "ntt_inv": ApiSpec("ntt_inv", [-1], cost=3),
    "evaluate_poly_vector": ApiSpec("evaluate_poly_vector", [1], resource_positions=[2, 4, 5], constant_positions=[3], cost=8, barrier=True),
    "bootstrap": ApiSpec("bootstrap", [1], resource_positions=[2, 3, 4, 5], cost=10, barrier=True),
    "read": ApiSpec("read", [], cost=1),
    "create_public_key": ApiSpec("create_public_key", [-1], cost=2),
    "create_relin_keys": ApiSpec("create_relin_keys", [-1], cost=2),
    "create_galois_keys": ApiSpec("create_galois_keys", [-1], cost=2),
}


DECL_RE = re.compile(
    r"^(?:const\s+)?(?P<type>.+?)\s+(?P<vars>[A-Za-z_].*)$"
)
AUTO_DECL_RE = re.compile(r"^(?:const\s+)?auto\s+(?P<name>[A-Za-z_]\w*)\s*=\s*(?P<rhs>.+)$")
ASSIGN_RE = re.compile(r"^(?P<lhs>[A-Za-z_]\w*(?:\s*\[[^\]]+\])?)\s*=\s*(?P<rhs>[A-Za-z_]\w*(?:\s*\[[^\]]+\])?)$")
ASSIGN_CALL_RE = re.compile(r"^(?P<lhs>[A-Za-z_]\w*(?:\s*\[[^\]]+\])?)\s*=\s*(?P<rhs>.+)$")
CONST_INT_RE = re.compile(
    r"^(?:const\s+)?(?:int|size_t|std::size_t|uint32_t|long|auto)\s+"
    r"(?P<name>[A-Za-z_]\w*)\s*=\s*(?P<value>\d+)\s*$"
)
CALL_RE = re.compile(
    r"(?P<receiver>[^();]+?)\s*(?P<access>->|\.)\s*(?P<method>[A-Za-z_]\w*)\s*\((?P<args>.*)\)$"
)
FUNC_CALL_RE = re.compile(r"^(?P<name>[A-Za-z_]\w*)\s*\((?P<args>.*)\)$")
INDEX_EXPR_RE = re.compile(r"^(?P<base>[A-Za-z_]\w*)\s*\[(?P<index>.+)\]$")
RETURN_RE = re.compile(r"^return\s+(?P<expr>.+)$")
DECL_ASSIGN_RE = re.compile(r"^(?P<type>.+?)\s+(?P<name>[A-Za-z_]\w*)\s*=\s*(?P<rhs>.+)$")
FOR_HEADER_RE = re.compile(
    r"for\s*\(\s*(?:int|size_t|std::size_t|auto)\s+"
    r"(?P<var>[A-Za-z_]\w*)\s*=\s*(?P<start>[A-Za-z_]\w*|\d+)\s*;\s*"
    r"(?P=var)\s*<\s*(?P<end>[A-Za-z_]\w*|\d+)\s*;\s*"
    r"(?:(?P=var)\s*\+\+|\+\+\s*(?P=var))\s*\)\s*\{",
    re.S,
)


@dataclass
class DeclaredSymbol:
    symbol: SymbolRef
    value_kind: str
    source_span: SourceSpan
    origin_scope: str


@dataclass
class NormalizedOperation:
    stmt_id: str
    source_span: SourceSpan
    source_text: str
    op_kind: str
    api_name: str
    input_symbols: list[SymbolRef]
    output_symbols: list[SymbolRef]
    resource_symbols: list[SymbolRef]
    attrs: dict[str, Any]
    effects: list[dict[str, Any]]
    origin_callstack: list[dict[str, Any]] = field(default_factory=list)


@dataclass
class NormalizedProgram:
    source_file: str
    entry_function: str
    frontend: str
    declared_symbols: dict[str, DeclaredSymbol]
    operations: list[NormalizedOperation]
    diagnostics: list[Diagnostic]
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class ExtractedStatement:
    raw: str
    start_offset: int
    end_offset: int
    line: int
    expanded_from_loop: bool = False
    loop_context: dict[str, int] | None = None
    category: str = "statement"
    diagnostic_reason: str | None = None


@dataclass
class FunctionDefinition:
    name: str
    params_text: str
    body: str
    body_start_line: int
    body_start_offset: int
    full_span: SourceSpan


def _strip_comments_and_directives(source: str) -> str:
    source = re.sub(r"//.*", "", source)
    source = re.sub(r"/\*.*?\*/", lambda m: "\n" * m.group(0).count("\n"), source, flags=re.S)
    return re.sub(r"^[ \t]*#.*$", "", source, flags=re.M)


def _line_col(source: str, offset: int) -> tuple[int, int]:
    line = source.count("\n", 0, offset) + 1
    last_break = source.rfind("\n", 0, offset)
    column = offset + 1 if last_break == -1 else offset - last_break
    return line, column


def _make_span(source: str, path: str, start_offset: int, end_offset: int) -> SourceSpan:
    start_line, start_col = _line_col(source, start_offset)
    end_line, end_col = _line_col(source, end_offset)
    return SourceSpan(
        file=path,
        start=SourcePosition(line=start_line, column=start_col, offset=start_offset),
        end=SourcePosition(line=end_line, column=end_col, offset=end_offset),
    )


def _split_arguments(args: str) -> list[str]:
    result: list[str] = []
    current: list[str] = []
    depth = 0
    angle_depth = 0
    bracket_depth = 0
    for char in args:
        if char == "," and depth == 0 and angle_depth == 0 and bracket_depth == 0:
            token = "".join(current).strip()
            if token:
                result.append(token)
            current = []
            continue
        current.append(char)
        if char == "(":
            depth += 1
        elif char == ")":
            depth = max(depth - 1, 0)
        elif char == "<":
            angle_depth += 1
        elif char == ">":
            angle_depth = max(angle_depth - 1, 0)
        elif char == "[":
            bracket_depth += 1
        elif char == "]":
            bracket_depth = max(bracket_depth - 1, 0)
    token = "".join(current).strip()
    if token:
        result.append(token)
    return result


def _find_matching_brace(text: str, open_index: int) -> int:
    depth = 0
    for index in range(open_index, len(text)):
        char = text[index]
        if char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                return index
    raise ValueError("unbalanced braces")


def _find_matching_paren(text: str, open_index: int) -> int:
    depth = 0
    for index in range(open_index, len(text)):
        char = text[index]
        if char == "(":
            depth += 1
        elif char == ")":
            depth -= 1
            if depth == 0:
                return index
    raise ValueError("unbalanced parentheses")


def _normalize_text(text: str) -> str:
    return " ".join(text.strip().split())


def _normalize_symbol_ref(text: str) -> SymbolRef:
    normalized = _normalize_text(text)
    indexed = INDEX_EXPR_RE.match(normalized)
    if not indexed:
        return SymbolRef(kind="symbol", text=normalized)
    base = indexed.group("base")
    index = _normalize_text(indexed.group("index"))
    return SymbolRef(kind="indexed", text=f"{base}[{index}]", base=base, index=index)


def _infer_kind_from_type(type_text: str) -> str | None:
    normalized = " ".join(type_text.replace("&", " ").replace("*", " ").split())
    for container_type, kind in CONTAINER_VALUE_KINDS.items():
        if container_type in normalized:
            return kind
    for he_type, kind in HE_TYPES.items():
        if re.search(rf"\b{re.escape(he_type)}\b", normalized):
            return kind
    if "shared_ptr<EvaluatorCkksBase>" in normalized or "shared_ptr<EvaluatorBase>" in normalized:
        return "evaluator"
    if "PoseidonContext" in normalized:
        return "context"
    return None


def _infer_symbol_kind(symbol: SymbolRef, symbol_kinds: dict[str, str]) -> str:
    if symbol.key() in symbol_kinds:
        return symbol_kinds[symbol.key()]
    if symbol.kind == "indexed" and symbol.base:
        base_kind = symbol_kinds.get(symbol.base)
        if base_kind in INDEXED_KIND_MAP:
            return INDEXED_KIND_MAP[base_kind]
    return "external"


def _find_clang() -> str | None:
    for candidate in ("clang++", "clang++-18", "clang++-17", "clang++-16"):
        found = shutil.which(candidate)
        if found:
            return found
    return None


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[2]


def _load_compile_commands() -> list[dict[str, Any]]:
    root = _repo_root()
    for candidate in (root / "build" / "compile_commands.json", root / "compile_commands.json"):
        if candidate.exists():
            return json.loads(candidate.read_text(encoding="utf-8"))
    return []


def _lookup_compile_command(source_path: str) -> dict[str, Any] | None:
    resolved = str(Path(source_path).resolve())
    for item in _load_compile_commands():
        if Path(item.get("file", "")).resolve().as_posix() == Path(resolved).as_posix():
            return item
    return None


def _command_to_arguments(command: dict[str, Any]) -> list[str]:
    if "arguments" in command and command["arguments"]:
        return list(command["arguments"])
    if "command" in command and command["command"]:
        return shlex.split(command["command"])
    return []


def _default_clang_arguments(source_path: str, compiler: str) -> list[str]:
    root = _repo_root()
    return [
        compiler,
        "-std=gnu++20",
        f"-I{root / 'build'}",
        f"-I{root / 'src'}",
        str(Path(source_path).resolve()),
    ]


def _prepare_clang_ast_command(source_path: str) -> tuple[list[str], str]:
    compiler = _find_clang()
    if not compiler:
        raise RuntimeError("clang toolchain not available")
    command = _lookup_compile_command(source_path)
    arguments = _command_to_arguments(command) if command else _default_clang_arguments(source_path, compiler)
    if not arguments:
        arguments = _default_clang_arguments(source_path, compiler)
    arguments[0] = compiler

    cleaned: list[str] = [arguments[0]]
    skip_next = False
    for index, arg in enumerate(arguments[1:], start=1):
        if skip_next:
            skip_next = False
            continue
        if arg in {"-c", "-Winvalid-pch"}:
            continue
        if arg == "-o" and index + 1 < len(arguments):
            skip_next = True
            continue
        if arg.startswith("-o") and arg != "-Winvalid-pch":
            continue
        cleaned.append(arg)

    source_resolved = str(Path(source_path).resolve())
    if source_resolved not in cleaned:
        cleaned.append(source_resolved)

    cleaned.extend(["-fsyntax-only", "-Xclang", "-ast-dump=json"])
    directory = command.get("directory") if command else str(_repo_root())
    return cleaned, directory


def _extract_function_definitions(source: str, path: str, function_name: str) -> list[FunctionDefinition]:
    pattern = re.compile(rf"\b{re.escape(function_name)}\s*\((?P<params>[^;]*?)\)\s*\{{", re.S)
    definitions: list[FunctionDefinition] = []
    for match in pattern.finditer(source):
        open_index = source.find("{", match.start())
        close_index = _find_matching_brace(source, open_index)
        body_start = open_index + 1
        definitions.append(
            FunctionDefinition(
                name=function_name,
                params_text=match.group("params"),
                body=source[body_start:close_index],
                body_start_line=_line_col(source, body_start)[0],
                body_start_offset=body_start,
                full_span=_make_span(source, path, match.start(), close_index),
            )
        )
    return definitions


def _choose_definition(definitions: list[FunctionDefinition], arg_count: int | None = None) -> FunctionDefinition | None:
    if not definitions:
        return None
    if arg_count is None:
        return definitions[0]
    exact: list[FunctionDefinition] = []
    for definition in definitions:
        params = _split_arguments(_normalize_text(definition.params_text))
        if len(params) == arg_count:
            exact.append(definition)
    if len(exact) == 1:
        return exact[0]
    return definitions[0] if len(definitions) == 1 else None


def _parse_parameters(params_text: str, source: str, path: str, function_name: str, base_offset: int) -> list[DeclaredSymbol]:
    params: list[DeclaredSymbol] = []
    normalized = _normalize_text(params_text)
    if not normalized or normalized == "void":
        return params
    cursor = 0
    for raw_param in _split_arguments(params_text):
        token = raw_param.strip()
        if not token:
            continue
        match = re.search(r"(?P<name>[A-Za-z_]\w*)\s*$", token)
        if not match:
            cursor += len(raw_param) + 1
            continue
        name = match.group("name")
        kind = _infer_kind_from_type(token[: match.start("name")].strip())
        if kind:
            start = base_offset + params_text.find(token, cursor)
            end = start + len(token)
            span = _make_span(source, path, start, end)
            params.append(
                DeclaredSymbol(
                    symbol=_normalize_symbol_ref(name),
                    value_kind=kind,
                    source_span=span,
                    origin_scope=function_name,
                )
            )
        cursor = params_text.find(token, cursor) + len(token)
    return params


def _inline_lambda_enqueues(body: str) -> str:
    index = 0
    parts: list[str] = []
    while True:
        match = re.search(r"\benqueue\s*\(", body[index:])
        if not match:
            parts.append(body[index:])
            break
        enqueue_start = index + match.start()
        stmt_start = body.rfind("\n", 0, enqueue_start) + 1
        open_paren = body.find("(", enqueue_start)
        lambda_open = body.find("{", open_paren)
        if lambda_open == -1:
            parts.append(body[index:])
            break
        try:
            lambda_close = _find_matching_brace(body, lambda_open)
            call_close = _find_matching_paren(body, open_paren)
        except ValueError:
            parts.append(body[index:])
            break
        semicolon = body.find(";", call_close)
        if semicolon == -1:
            parts.append(body[index:])
            break
        parts.append(body[index:stmt_start])
        parts.append(body[lambda_open + 1 : lambda_close])
        index = semicolon + 1
    return "".join(parts)


def _extract_statements(
    source: str,
    path: str,
    body: str,
    body_start_offset: int,
    const_env: dict[str, int],
) -> list[ExtractedStatement]:
    body = _inline_lambda_enqueues(body)
    statements: list[ExtractedStatement] = []
    index = 0
    while index < len(body):
        while index < len(body) and body[index].isspace():
            index += 1
        if index >= len(body):
            break
        absolute_index = body_start_offset + index
        for_match = FOR_HEADER_RE.match(body, index)
        if for_match:
            start_token = for_match.group("start")
            end_token = for_match.group("end")
            start = int(start_token) if start_token.isdigit() else const_env.get(start_token)
            end = int(end_token) if end_token.isdigit() else const_env.get(end_token)
            open_brace = body.find("{", for_match.start())
            close_brace = _find_matching_brace(body, open_brace)
            if start is not None and end is not None:
                nested = _extract_statements(
                    source,
                    path,
                    body[open_brace + 1 : close_brace],
                    body_start_offset + open_brace + 1,
                    const_env,
                )
                for value in range(start, end):
                    loop_var = for_match.group("var")
                    loop_context = {loop_var: value}
                    for nested_stmt in nested:
                        raw = re.sub(rf"\b{re.escape(loop_var)}\b", str(value), nested_stmt.raw)
                        statements.append(
                            ExtractedStatement(
                                raw=raw,
                                start_offset=nested_stmt.start_offset,
                                end_offset=nested_stmt.end_offset,
                                line=nested_stmt.line,
                                expanded_from_loop=True,
                                loop_context=loop_context,
                                category=nested_stmt.category,
                                diagnostic_reason=nested_stmt.diagnostic_reason,
                            )
                        )
            else:
                block_start = body_start_offset + for_match.start()
                block_end = body_start_offset + close_brace
                span_line = _line_col(source, block_start)[0]
                statements.append(
                    ExtractedStatement(
                        raw=body[for_match.start() : close_brace + 1].strip(),
                        start_offset=block_start,
                        end_offset=block_end,
                        line=span_line,
                        category="unsupported",
                        diagnostic_reason="unsupported dynamic loop boundary",
                    )
                )
            index = close_brace + 1
            continue
        for keyword in ("if", "while", "switch"):
            if body.startswith(keyword, index) and (index + len(keyword) == len(body) or not body[index + len(keyword)].isalnum()):
                open_paren = body.find("(", index)
                close_paren = _find_matching_paren(body, open_paren)
                cursor = close_paren + 1
                while cursor < len(body) and body[cursor].isspace():
                    cursor += 1
                if cursor < len(body) and body[cursor] == "{":
                    close_brace = _find_matching_brace(body, cursor)
                    end_index = close_brace + 1
                else:
                    semicolon = body.find(";", cursor)
                    end_index = len(body) if semicolon == -1 else semicolon + 1
                stmt_start = body_start_offset + index
                stmt_end = body_start_offset + end_index - 1
                statements.append(
                    ExtractedStatement(
                        raw=body[index:end_index].strip(),
                        start_offset=stmt_start,
                        end_offset=stmt_end,
                        line=_line_col(source, stmt_start)[0],
                        category="unsupported",
                        diagnostic_reason=f"unsupported control flow: {keyword}",
                    )
                )
                index = end_index
                break
        else:
            if body[index] == "{":
                close_brace = _find_matching_brace(body, index)
                nested = _extract_statements(source, path, body[index + 1 : close_brace], body_start_offset + index + 1, const_env)
                statements.extend(nested)
                index = close_brace + 1
                continue
            semicolon = body.find(";", index)
            if semicolon == -1:
                break
            raw = body[index:semicolon].strip()
            if raw:
                statements.append(
                    ExtractedStatement(
                        raw=raw,
                        start_offset=absolute_index,
                        end_offset=body_start_offset + semicolon,
                        line=_line_col(source, absolute_index)[0],
                    )
                )
            index = semicolon + 1
            continue
        continue
    return statements


def _parse_declaration(stmt: str) -> tuple[str, list[str]] | None:
    normalized = _normalize_text(stmt)
    if "(" in normalized and normalized.endswith(")"):
        return None
    match = DECL_RE.match(normalized)
    if not match:
        return None
    type_text = match.group("type").strip()
    kind = _infer_kind_from_type(type_text)
    if not kind:
        return None
    names: list[str] = []
    for token in _split_arguments(match.group("vars")):
        part = token.strip()
        if "=" in part:
            part = part.split("=", 1)[0].strip()
        if "(" in part:
            part = part.split("(", 1)[0].strip()
        part = part.replace("&", "").replace("*", "").strip()
        if part:
            names.append(part)
    return kind, names


def _parse_call(stmt: str) -> dict[str, Any] | None:
    normalized = _normalize_text(stmt)
    match = CALL_RE.search(normalized)
    if not match:
        return None
    return {
        "receiver": _normalize_text(match.group("receiver")),
        "method": match.group("method"),
        "args": _split_arguments(match.group("args")),
        "full_text": normalized,
    }


def _parse_function_call(stmt: str) -> dict[str, Any] | None:
    normalized = _normalize_text(stmt)
    match = FUNC_CALL_RE.match(normalized)
    if not match:
        return None
    return {
        "name": match.group("name"),
        "args": _split_arguments(match.group("args")),
        "full_text": normalized,
    }


def _clone_symbol(symbol: SymbolRef, alias_map: dict[str, SymbolRef]) -> SymbolRef:
    if symbol.key() in alias_map:
        return alias_map[symbol.key()]
    if symbol.kind == "indexed" and symbol.base and symbol.base in alias_map:
        base_alias = alias_map[symbol.base]
        return SymbolRef(
            kind="indexed",
            text=f"{base_alias.text}[{symbol.index}]",
            base=base_alias.text,
            index=symbol.index,
        )
    return symbol


def _stmt_id(function_name: str, start_offset: int, loop_context: dict[str, int] | None = None) -> str:
    if not loop_context:
        return f"{function_name}@{start_offset}"
    suffix = "_".join(f"{key}_{value}" for key, value in sorted(loop_context.items()))
    return f"{function_name}@{start_offset}@{suffix}"


def _span_to_dict(span: SourceSpan) -> dict[str, Any]:
    return {
        "file": span.file,
        "start": {"line": span.start.line, "column": span.start.column, "offset": span.start.offset},
        "end": {"line": span.end.line, "column": span.end.column, "offset": span.end.offset},
    }


def _build_diagnostic(reason: str, stmt_id: str | None, span: SourceSpan, blocking: bool = True, details: dict[str, Any] | None = None) -> Diagnostic:
    return Diagnostic(
        severity="error" if blocking else "warning",
        blocking=blocking,
        reason=reason,
        stmt_id=stmt_id,
        source_span=span,
        suggested_fallback="skip rewrite for this region",
        details=details or {},
    )


def _iter_ast_nodes(node: dict[str, Any]) -> list[dict[str, Any]]:
    result = [node]
    for child in node.get("inner", []):
        if isinstance(child, dict):
            result.extend(_iter_ast_nodes(child))
    return result


def _node_file(node: dict[str, Any]) -> str | None:
    for key in ("range", "loc"):
        payload = node.get(key, {})
        begin = payload.get("begin", payload)
        file_name = begin.get("file")
        if file_name:
            return file_name
        included = begin.get("includedFrom", {})
        file_name = included.get("file")
        if file_name:
            return file_name
    return None


def _offset_to_position(source: str, offset: int) -> SourcePosition:
    line, column = _line_col(source, offset)
    return SourcePosition(line=line, column=column, offset=offset)


def _span_from_ast_node(node: dict[str, Any], source: str, source_path: str) -> SourceSpan:
    range_data = node.get("range") or {}
    begin = range_data.get("begin", {})
    end = range_data.get("end", {})
    start_offset = begin.get("offset")
    end_offset = end.get("offset")
    token_len = end.get("tokLen", 1)
    if start_offset is None or end_offset is None:
        loc = node.get("loc", {})
        start_offset = loc.get("offset", 0)
        end_offset = start_offset
    return SourceSpan(
        file=source_path,
        start=_offset_to_position(source, start_offset),
        end=_offset_to_position(source, end_offset + max(token_len - 1, 0)),
    )


def _match_definition_to_span(source: str, source_path: str, function_name: str, span: SourceSpan) -> FunctionDefinition | None:
    definitions = _extract_function_definitions(source, source_path, function_name)
    for definition in definitions:
        if definition.full_span.start.offset == span.start.offset:
            return definition
    for definition in definitions:
        if definition.full_span.start.line == span.start.line:
            return definition
    return _choose_definition(definitions)


def _load_clang_ast(source_path: str, clang_ast_json: str | None = None) -> tuple[dict[str, Any], dict[str, Any]]:
    if clang_ast_json:
        ast_path = Path(clang_ast_json)
        payload = json.loads(ast_path.read_text(encoding="utf-8"))
        return payload, {"mode": "json_fixture", "path": str(ast_path)}

    command, directory = _prepare_clang_ast_command(source_path)
    completed = subprocess.run(
        command,
        cwd=directory,
        check=True,
        capture_output=True,
        text=True,
    )
    return json.loads(completed.stdout), {
        "mode": "clang_subprocess",
        "command": command,
        "directory": directory,
    }


def _find_clang_function_node(ast_root: dict[str, Any], source_path: str, function_name: str) -> dict[str, Any] | None:
    resolved = str(Path(source_path).resolve())
    candidates: list[dict[str, Any]] = []
    for node in _iter_ast_nodes(ast_root):
        if node.get("kind") != "FunctionDecl":
            continue
        if node.get("name") != function_name:
            continue
        node_file = _node_file(node)
        if node_file and Path(node_file).resolve().as_posix() != Path(resolved).as_posix():
            continue
        if any(child.get("kind") == "CompoundStmt" for child in node.get("inner", []) if isinstance(child, dict)):
            candidates.append(node)
    return candidates[0] if candidates else None


def _extract_with_clang_ast(source_path: str, function_name: str, clang_ast_json: str | None = None) -> NormalizedProgram:
    source = _strip_comments_and_directives(Path(source_path).read_text(encoding="utf-8"))
    ast_root, ast_metadata = _load_clang_ast(source_path, clang_ast_json=clang_ast_json)
    function_node = _find_clang_function_node(ast_root, source_path, function_name)
    if not function_node:
        raise RuntimeError(f"function '{function_name}' not found in clang AST")

    span = _span_from_ast_node(function_node, source, source_path)
    definition = _match_definition_to_span(source, source_path, function_name, span)
    if not definition:
        raise RuntimeError(f"failed to match clang AST function '{function_name}' back to source definition")

    program = _extract_with_text_fallback_inner(source, source_path, definition, [])
    program.frontend = "clang_ast_json"
    program.metadata["frontend_mode"] = "clang_ast_json"
    program.metadata["clang_ast"] = ast_metadata
    program.metadata["entry_span"] = _span_to_dict(span)
    return program


def extract_program(
    source_path: str,
    function_name: str,
    frontend: str = "auto",
    clang_ast_json: str | None = None,
) -> NormalizedProgram:
    path = str(Path(source_path))
    if frontend in {"clang", "auto"}:
        try:
            return _extract_with_clang_ast(path, function_name, clang_ast_json=clang_ast_json)
        except RuntimeError:
            if frontend == "clang":
                raise
    return _extract_with_text_fallback(path, function_name)


def _extract_with_text_fallback(source_path: str, function_name: str) -> NormalizedProgram:
    source = _strip_comments_and_directives(Path(source_path).read_text(encoding="utf-8"))
    definitions = _extract_function_definitions(source, source_path, function_name)
    definition = _choose_definition(definitions)
    if not definition:
        raise ValueError(f"function '{function_name}' not found in {source_path}")
    return _extract_with_text_fallback_inner(source, source_path, definition, [])


def _extract_with_text_fallback_inner(
    source: str,
    source_path: str,
    definition: FunctionDefinition,
    stack: list[str],
) -> NormalizedProgram:
    function_name = definition.name

    diagnostics: list[Diagnostic] = []
    declared_symbols: dict[str, DeclaredSymbol] = {}
    operations: list[NormalizedOperation] = []
    const_env: dict[str, int] = {}
    symbol_kinds: dict[str, str] = {}

    for declared in _parse_parameters(
        definition.params_text,
        source,
        source_path,
        function_name,
        definition.full_span.start.offset,
    ):
        declared_symbols[declared.symbol.key()] = declared
        symbol_kinds[declared.symbol.key()] = declared.value_kind

    statements = _extract_statements(source, source_path, definition.body, definition.body_start_offset, const_env)
    for statement in statements:
        const_match = CONST_INT_RE.match(_normalize_text(statement.raw))
        if const_match:
            const_env[const_match.group("name")] = int(const_match.group("value"))

    stack: list[str] = []

    def register_symbol(symbol: SymbolRef, value_kind: str, span: SourceSpan, origin_scope: str) -> None:
        if symbol.key() in declared_symbols:
            return
        declared_symbols[symbol.key()] = DeclaredSymbol(symbol=symbol, value_kind=value_kind, source_span=span, origin_scope=origin_scope)
        symbol_kinds[symbol.key()] = value_kind

    def inline_local_function(
        callee_name: str,
        args: list[str],
        assign_target: SymbolRef | None,
        call_stmt_id: str,
        call_span: SourceSpan,
        call_text: str,
        parent_stack: list[dict[str, Any]],
    ) -> bool:
        if callee_name in stack:
            diagnostics.append(_build_diagnostic("recursive helper extraction is not supported", call_stmt_id, call_span))
            return True
        candidates = _extract_function_definitions(source, source_path, callee_name)
        callee_definition = _choose_definition(candidates, arg_count=len(args))
        if not callee_definition:
            return False
        stack.append(callee_name)
        helper = _extract_with_text_fallback_inner(source, source_path, callee_definition, stack)
        stack.pop()
        diagnostics.extend(helper.diagnostics)

        helper_params = _parse_parameters(
            callee_definition.params_text,
            source,
            source_path,
            callee_name,
            callee_definition.full_span.start.offset,
        )
        alias_map: dict[str, SymbolRef] = {}
        for declared, arg_text in zip(helper_params, args):
            actual = _normalize_symbol_ref(arg_text)
            alias_map[declared.symbol.key()] = actual
            actual_kind = _infer_symbol_kind(actual, symbol_kinds)
            if actual_kind == "external":
                register_symbol(actual, declared.value_kind, call_span, function_name)
            elif actual.key() not in symbol_kinds:
                register_symbol(actual, actual_kind, call_span, function_name)

        helper_prefix = call_stmt_id.replace("@", "_")
        for key, declared in helper.declared_symbols.items():
            if key in alias_map or key == "__return__":
                continue
            renamed = SymbolRef(kind=declared.symbol.kind, text=f"{callee_name}__{helper_prefix}__{declared.symbol.text}", base=declared.symbol.base, index=declared.symbol.index)
            alias_map[key] = renamed
            register_symbol(renamed, declared.value_kind, declared.source_span, f"{function_name}::{callee_name}")

        helper_frame = {
            "function": function_name,
            "stmt_id": call_stmt_id,
            "source_span": _span_to_dict(call_span),
            "source_text": call_text,
        }
        for op in helper.operations:
            mapped_inputs = [_clone_symbol(symbol, alias_map) for symbol in op.input_symbols]
            mapped_outputs = [_clone_symbol(symbol, alias_map) for symbol in op.output_symbols]
            mapped_resources = [_clone_symbol(symbol, alias_map) for symbol in op.resource_symbols]
            callstack = list(parent_stack) + [helper_frame] + list(op.origin_callstack)
            if op.op_kind == "return":
                if assign_target and mapped_inputs:
                    target_kind = _infer_symbol_kind(assign_target, symbol_kinds)
                    if target_kind == "external":
                        target_kind = _infer_symbol_kind(mapped_inputs[0], symbol_kinds)
                        register_symbol(assign_target, target_kind, call_span, function_name)
                    operations.append(
                        NormalizedOperation(
                            stmt_id=f"{call_stmt_id}::return",
                            source_span=call_span,
                            source_text=call_text,
                            op_kind="assign",
                            api_name="assign",
                            input_symbols=[mapped_inputs[0]],
                            output_symbols=[assign_target],
                            resource_symbols=[],
                            attrs={"cost": 1, "barrier": False, "source_text": call_text},
                            effects=_make_effects([mapped_inputs[0]], [assign_target]),
                            origin_callstack=callstack,
                        )
                    )
                continue
            operations.append(
                NormalizedOperation(
                    stmt_id=f"{call_stmt_id}::{op.stmt_id}",
                    source_span=op.source_span,
                    source_text=op.source_text,
                    op_kind=op.op_kind,
                    api_name=op.api_name,
                    input_symbols=mapped_inputs,
                    output_symbols=mapped_outputs,
                    resource_symbols=mapped_resources,
                    attrs=dict(op.attrs),
                    effects=[dict(item) for item in op.effects],
                    origin_callstack=callstack,
                )
            )
        return True

    for statement in statements:
        span = _make_span(source, source_path, statement.start_offset, statement.end_offset)
        stmt_id = _stmt_id(function_name, statement.start_offset, statement.loop_context)
        if statement.category == "unsupported":
            diagnostics.append(
                _build_diagnostic(
                    statement.diagnostic_reason or "unsupported construct",
                    stmt_id,
                    span,
                    details={"source_text": statement.raw},
                )
            )
            continue

        decl_assignment = DECL_ASSIGN_RE.match(_normalize_text(statement.raw))
        if decl_assignment:
            type_text = decl_assignment.group("type").strip()
            name = decl_assignment.group("name").strip()
            rhs = decl_assignment.group("rhs").strip()
            kind = _infer_kind_from_type(type_text)
            target = _normalize_symbol_ref(name)
            if kind:
                register_symbol(target, kind, span, function_name)
            func_call = _parse_function_call(rhs)
            if func_call and inline_local_function(func_call["name"], func_call["args"], target, stmt_id, span, statement.raw, []):
                continue

        declaration = _parse_declaration(statement.raw)
        if declaration:
            value_kind, names = declaration
            for name in names:
                register_symbol(_normalize_symbol_ref(name), value_kind, span, function_name)
            continue

        auto_decl = AUTO_DECL_RE.match(_normalize_text(statement.raw))
        if auto_decl:
            name = auto_decl.group("name")
            rhs = auto_decl.group("rhs").strip()
            target = _normalize_symbol_ref(name)
            func_call = _parse_function_call(rhs)
            if func_call and inline_local_function(func_call["name"], func_call["args"], target, stmt_id, span, statement.raw, []):
                inferred = _infer_symbol_kind(target, symbol_kinds)
                if inferred == "external":
                    register_symbol(target, "external", span, function_name)
                continue
            rhs_symbol = _normalize_symbol_ref(rhs)
            rhs_kind = _infer_symbol_kind(rhs_symbol, symbol_kinds)
            if rhs_kind != "external":
                register_symbol(target, rhs_kind, span, function_name)
                operations.append(
                    NormalizedOperation(
                        stmt_id=stmt_id,
                        source_span=span,
                        source_text=statement.raw,
                        op_kind="assign",
                        api_name="assign",
                        input_symbols=[rhs_symbol],
                        output_symbols=[target],
                        resource_symbols=[],
                        attrs={"cost": 1, "barrier": False, "source_text": statement.raw},
                        effects=_make_effects([rhs_symbol], [target]),
                    )
                )
            continue

        assign_call = ASSIGN_CALL_RE.match(_normalize_text(statement.raw))
        if assign_call:
            lhs = _normalize_symbol_ref(assign_call.group("lhs"))
            rhs = assign_call.group("rhs").strip()
            func_call = _parse_function_call(rhs)
            if func_call and inline_local_function(func_call["name"], func_call["args"], lhs, stmt_id, span, statement.raw, []):
                continue

        plain_assign = ASSIGN_RE.match(_normalize_text(statement.raw))
        if plain_assign:
            lhs = _normalize_symbol_ref(plain_assign.group("lhs"))
            rhs = _normalize_symbol_ref(plain_assign.group("rhs"))
            lhs_kind = _infer_symbol_kind(lhs, symbol_kinds)
            rhs_kind = _infer_symbol_kind(rhs, symbol_kinds)
            if lhs_kind == "external" and rhs_kind != "external":
                register_symbol(lhs, rhs_kind, span, function_name)
            if lhs.key() in symbol_kinds:
                operations.append(
                    NormalizedOperation(
                        stmt_id=stmt_id,
                        source_span=span,
                        source_text=statement.raw,
                        op_kind="assign",
                        api_name="assign",
                        input_symbols=[rhs],
                        output_symbols=[lhs],
                        resource_symbols=[],
                        attrs={"cost": 1, "barrier": False, "source_text": statement.raw},
                        effects=_make_effects([rhs], [lhs]),
                    )
                )
                continue

        member_call = _parse_call(statement.raw)
        if member_call:
            spec = API_SPECS.get(member_call["method"])
            if not spec:
                continue
            input_symbols: list[SymbolRef] = []
            output_symbols: list[SymbolRef] = []
            resource_symbols: list[SymbolRef] = []
            constants: list[str] = []
            output_positions = [(pos if pos >= 0 else len(member_call["args"]) + pos) for pos in spec.output_positions]
            for index, arg in enumerate(member_call["args"]):
                arg_text = _normalize_text(arg)
                symbol = _normalize_symbol_ref(arg_text)
                inferred_kind = _infer_symbol_kind(symbol, symbol_kinds)
                if index in output_positions:
                    output_symbols.append(symbol)
                    if inferred_kind == "external":
                        fallback_kind = _infer_symbol_kind(_normalize_symbol_ref(member_call["receiver"]), symbol_kinds)
                        register_symbol(symbol, fallback_kind if fallback_kind != "external" else "external", span, function_name)
                    continue
                if index in spec.resource_positions:
                    resource_symbols.append(symbol)
                    continue
                if index in spec.constant_positions or inferred_kind == "external":
                    constants.append(arg_text)
                    continue
                input_symbols.append(symbol)
            if spec.output_positions and not output_symbols and member_call["method"] != "read":
                diagnostics.append(_build_diagnostic("supported API call without tracked output", stmt_id, span, details={"source_text": statement.raw}))
                continue
            effects = _make_effects(input_symbols, output_symbols)
            attrs = {
                "cost": spec.cost,
                "barrier": spec.barrier,
                "constants": constants,
                "receiver": member_call["receiver"],
                "source_text": member_call["full_text"],
                "loop_context": statement.loop_context or {},
                "expanded_from_loop": statement.expanded_from_loop,
            }
            operations.append(
                NormalizedOperation(
                    stmt_id=stmt_id,
                    source_span=span,
                    source_text=member_call["full_text"],
                    op_kind=spec.op_kind,
                    api_name=member_call["method"],
                    input_symbols=input_symbols,
                    output_symbols=output_symbols,
                    resource_symbols=resource_symbols,
                    attrs=attrs,
                    effects=effects,
                )
            )
            continue

        helper_call = _parse_function_call(statement.raw)
        if helper_call and inline_local_function(helper_call["name"], helper_call["args"], None, stmt_id, span, statement.raw, []):
            continue

        return_match = RETURN_RE.match(_normalize_text(statement.raw))
        if return_match:
            expr_symbol = _normalize_symbol_ref(return_match.group("expr"))
            operations.append(
                NormalizedOperation(
                    stmt_id=stmt_id,
                    source_span=span,
                    source_text=statement.raw,
                    op_kind="return",
                    api_name="return",
                    input_symbols=[expr_symbol],
                    output_symbols=[SymbolRef(kind="symbol", text="__return__")],
                    resource_symbols=[],
                    attrs={"cost": 1, "barrier": False, "source_text": statement.raw},
                    effects=[],
                )
            )

    metadata = {
        "frontend_mode": "textual_fallback",
        "source_hash": hashlib.sha256(source.encode("utf-8")).hexdigest(),
        "entry_span": _span_to_dict(definition.full_span),
    }
    return NormalizedProgram(
        source_file=source_path,
        entry_function=function_name,
        frontend="textual_fallback",
        declared_symbols=declared_symbols,
        operations=operations,
        diagnostics=diagnostics,
        metadata=metadata,
    )


def _make_effects(inputs: list[SymbolRef], outputs: list[SymbolRef]) -> list[dict[str, Any]]:
    input_keys = {symbol.key() for symbol in inputs}
    effects: list[dict[str, Any]] = []
    for symbol in outputs:
        effect_kind = "write"
        if symbol.key() in input_keys:
            effect_kind = "in_place_write"
        effects.append(
            {
                "kind": effect_kind,
                "symbol": {
                    "kind": symbol.kind,
                    "text": symbol.text,
                    "base": symbol.base,
                    "index": symbol.index,
                },
            }
        )
    return effects
