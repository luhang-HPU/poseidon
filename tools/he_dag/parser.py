from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import hashlib
import re
from typing import Any

from .ir import Dag, Edge, Op, Value


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
}

CONTAINER_VALUE_KINDS = {
    "std::vector<Ciphertext>": "ciphertext_vector",
    "vector<Ciphertext>": "ciphertext_vector",
    "std::vector<Plaintext>": "plaintext_vector",
    "vector<Plaintext>": "plaintext_vector",
    "std::vector<std::complex<double>>": "complex_vector",
    "vector<std::complex<double>>": "complex_vector",
}

INDEXED_KIND_MAP = {
    "ciphertext_vector": "ciphertext",
    "plaintext_vector": "plaintext",
    "complex_vector": "complex_vector_element",
}

HE_METHODS = {
    "encode": {"kind": "encode", "output_positions": [-1], "cost": 1},
    "encrypt": {"kind": "encrypt", "output_positions": [-1], "cost": 4},
    "decrypt": {"kind": "decrypt", "output_positions": [-1], "cost": 4},
    "add": {"kind": "add", "output_positions": [-1], "cost": 1},
    "sub": {"kind": "sub", "output_positions": [-1], "cost": 1},
    "add_plain": {"kind": "add_plain", "output_positions": [-1], "cost": 1},
    "sub_plain": {"kind": "sub_plain", "output_positions": [-1], "cost": 1},
    "multiply": {"kind": "multiply", "output_positions": [-1], "cost": 5},
    "multiply_plain": {"kind": "multiply_plain", "output_positions": [-1], "cost": 3},
    "multiply_relin": {
        "kind": "multiply_relin",
        "output_positions": [2],
        "resource_positions": [3],
        "cost": 6,
        "barrier": True,
    },
    "multiply_relin_dynamic": {
        "kind": "multiply_relin_dynamic",
        "output_positions": [2],
        "resource_positions": [3],
        "cost": 6,
        "barrier": True,
    },
    "multiply_const": {
        "kind": "multiply_const",
        "output_positions": [3],
        "resource_positions": [4],
        "cost": 3,
    },
    "add_const": {
        "kind": "add_const",
        "output_positions": [2],
        "resource_positions": [3],
        "cost": 1,
    },
    "rotate": {
        "kind": "rotate",
        "output_positions": [1],
        "resource_positions": [3],
        "constant_positions": [2],
        "cost": 4,
    },
    "conjugate": {
        "kind": "conjugate",
        "output_positions": [2],
        "resource_positions": [1],
        "cost": 4,
    },
    "rescale": {"kind": "rescale", "output_positions": [-1], "cost": 4, "barrier": True},
    "rescale_dynamic": {
        "kind": "rescale_dynamic",
        "output_positions": [1],
        "constant_positions": [2],
        "cost": 4,
        "barrier": True,
    },
    "relinearize": {
        "kind": "relinearize",
        "output_positions": [1],
        "resource_positions": [2],
        "cost": 4,
        "barrier": True,
    },
    "drop_modulus": {
        "kind": "drop_modulus",
        "output_positions": [1],
        "constant_positions": [2],
        "cost": 4,
        "barrier": True,
    },
    "drop_modulus_to_next": {
        "kind": "drop_modulus_to_next",
        "output_positions": [1],
        "cost": 4,
        "barrier": True,
    },
    "ntt_fwd": {"kind": "ntt_fwd", "output_positions": [-1], "cost": 3},
    "ntt_inv": {"kind": "ntt_inv", "output_positions": [-1], "cost": 3},
    "evaluate_poly_vector": {
        "kind": "evaluate_poly_vector",
        "output_positions": [1],
        "resource_positions": [2, 4, 5],
        "constant_positions": [3],
        "cost": 8,
        "barrier": True,
    },
    "bootstrap": {
        "kind": "bootstrap",
        "output_positions": [1],
        "resource_positions": [2, 3, 4, 5],
        "cost": 10,
        "barrier": True,
    },
    "read": {"kind": "read", "output_positions": [], "cost": 1},
    "create_public_key": {"kind": "create_public_key", "output_positions": [-1], "cost": 2},
    "create_relin_keys": {"kind": "create_relin_keys", "output_positions": [-1], "cost": 2},
    "create_galois_keys": {"kind": "create_galois_keys", "output_positions": [-1], "cost": 2},
}


DECL_RE = re.compile(
    r"^(?:const\s+)?(?:(?:poseidon|std)::)*"
    r"(?P<type>Ciphertext|Plaintext|RelinKeys|GaloisKeys|PublicKey|SecretKey|"
    r"Encryptor|Decryptor|CKKSEncoder|BatchEncoder|KeyGenerator|EvaluatorCkksBase|EvaluatorBase)"
    r"\s+(?P<vars>.+)$"
)
AUTO_DECL_RE = re.compile(r"^(?:const\s+)?auto\s+(?P<name>[A-Za-z_]\w*)\s*=\s*(?P<rhs>.+)$")
ASSIGN_RE = re.compile(r"^(?P<lhs>[A-Za-z_]\w*)\s*=\s*(?P<rhs>[A-Za-z_]\w*)$")
ASSIGN_CALL_RE = re.compile(r"^(?P<lhs>[A-Za-z_]\w*)\s*=\s*(?P<rhs>.+)$")
CONST_INT_RE = re.compile(
    r"^(?:const\s+)?(?:int|size_t|std::size_t|uint32_t|long|auto)\s+"
    r"(?P<name>[A-Za-z_]\w*)\s*=\s*(?P<value>\d+)\s*$"
)
CALL_RE = re.compile(
    r"(?P<receiver>[^();]+?)\s*(?P<access>->|\.)\s*(?P<method>[A-Za-z_]\w*)\s*"
    r"\((?P<args>.*)\)$"
)
FUNC_CALL_RE = re.compile(r"^(?P<name>[A-Za-z_]\w*)\s*\((?P<args>.*)\)$")
INDEX_EXPR_RE = re.compile(r"^(?P<base>[A-Za-z_]\w*)\s*\[(?P<index>.+)\]$")
RETURN_RE = re.compile(r"^return\s+(?P<expr>.+)$")
DECL_ASSIGN_RE = re.compile(r"^(?P<type>.+?)\s+(?P<name>[A-Za-z_]\w*)\s*=\s*(?P<rhs>.+)$")
FOR_HEADER_RE = re.compile(
    r"for\s*\(\s*(?:int|size_t|std::size_t|auto)\s+"
    r"(?P<var>[A-Za-z_]\w*)\s*=\s*(?P<start>[A-Za-z_]\w*|\d+)\s*;\s*"
    r"(?P=var)\s*<\s*(?P<end>[A-Za-z_]\w*|\d+)\s*;\s*"
    r"(?P=var)\s*\+\+\s*\)\s*\{",
    re.S,
)


@dataclass
class ExtractedStatement:
    line: int
    raw: str
    expanded_from_loop: bool = False
    loop_context: dict[str, int] | None = None


def _strip_comments(source: str) -> str:
    source = re.sub(r"//.*", "", source)
    return re.sub(r"/\*.*?\*/", "", source, flags=re.S)


def _split_arguments(args: str) -> list[str]:
    result: list[str] = []
    current: list[str] = []
    depth = 0
    angle_depth = 0
    for char in args:
        if char == "," and depth == 0 and angle_depth == 0:
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
    raise ValueError("unbalanced braces while parsing function")


def _line_number(source: str, offset: int) -> int:
    return source.count("\n", 0, offset) + 1


def _extract_function_body(source: str, function_name: str) -> tuple[str, int]:
    pattern = re.compile(rf"\b{re.escape(function_name)}\s*\((?P<params>[^;]*?)\)\s*\{{", re.S)
    match = pattern.search(source)
    if not match:
        raise ValueError(f"function '{function_name}' not found")
    open_index = source.find("{", match.start())
    close_index = _find_matching_brace(source, open_index)
    return source[open_index + 1 : close_index], _line_number(source, open_index + 1)


def _extract_function_definition(source: str, function_name: str) -> tuple[str, str, int]:
    pattern = re.compile(rf"\b{re.escape(function_name)}\s*\((?P<params>[^;]*?)\)\s*\{{", re.S)
    match = pattern.search(source)
    if not match:
        raise ValueError(f"function '{function_name}' not found")
    open_index = source.find("{", match.start())
    close_index = _find_matching_brace(source, open_index)
    return match.group("params"), source[open_index + 1 : close_index], _line_number(source, open_index + 1)


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


def _extract_statements(body: str, body_start_line: int, const_env: dict[str, int]) -> list[ExtractedStatement]:
    body = _inline_lambda_enqueues(body)
    statements: list[ExtractedStatement] = []
    index = 0
    while index < len(body):
        while index < len(body) and body[index].isspace():
            index += 1
        if index >= len(body):
            break
        for_match = FOR_HEADER_RE.match(body, index)
        if for_match:
            loop_var = for_match.group("var")
            start_token = for_match.group("start")
            start = int(start_token) if start_token.isdigit() else const_env.get(start_token)
            end_token = for_match.group("end")
            end = int(end_token) if end_token.isdigit() else const_env.get(end_token)
            open_brace = body.find("{", for_match.start())
            close_brace = _find_matching_brace(body, open_brace)
            if start is not None and end is not None:
                nested = _extract_statements(body[open_brace + 1 : close_brace], body_start_line + body.count("\n", 0, open_brace + 1), const_env)
                for value in range(start, end):
                    loop_context = {loop_var: value}
                    for nested_stmt in nested:
                        raw = re.sub(rf"\b{re.escape(loop_var)}\b", str(value), nested_stmt.raw)
                        statements.append(
                            ExtractedStatement(
                                line=nested_stmt.line,
                                raw=raw,
                                expanded_from_loop=True,
                                loop_context=loop_context,
                            )
                        )
            else:
                nested = _extract_statements(body[open_brace + 1 : close_brace], body_start_line + body.count("\n", 0, open_brace + 1), const_env)
                for nested_stmt in nested:
                    statements.append(nested_stmt)
            index = close_brace + 1
            continue
        semicolon = body.find(";", index)
        if semicolon == -1:
            break
        raw = body[index:semicolon].strip()
        line = body_start_line + body.count("\n", 0, index)
        if raw:
            statements.append(ExtractedStatement(line=line, raw=raw))
        index = semicolon + 1
    return statements


def _parse_declaration(stmt: str) -> tuple[str, list[str]] | None:
    normalized = " ".join(stmt.split())
    match = DECL_RE.match(normalized)
    if not match:
        return None
    decl_type = match.group("type").split("::")[-1]
    vars_part = match.group("vars")
    names = []
    for token in _split_arguments(vars_part):
        token = token.strip()
        if "=" in token:
            token = token.split("=", 1)[0].strip()
        if "(" in token:
            token = token.split("(", 1)[0].strip()
        token = token.replace("&", "").replace("*", "").strip()
        if token:
            names.append(token)
    return decl_type, names


def _parse_call(stmt: str) -> dict[str, Any] | None:
    normalized = " ".join(stmt.split())
    match = CALL_RE.search(normalized)
    if not match:
        return None
    return {
        "full_text": match.group(0).strip().lstrip("{").strip(),
        "receiver": match.group("receiver").strip().lstrip("{").strip(),
        "method": match.group("method").strip(),
        "args": _split_arguments(match.group("args").strip()),
    }


def _parse_function_call(stmt: str) -> dict[str, Any] | None:
    normalized = " ".join(stmt.split())
    match = FUNC_CALL_RE.match(normalized)
    if not match:
        return None
    return {
        "name": match.group("name").strip(),
        "args": _split_arguments(match.group("args").strip()),
        "full_text": normalized.strip(),
    }


def _parse_auto_declaration(stmt: str) -> tuple[str, str] | None:
    normalized = " ".join(stmt.split())
    match = AUTO_DECL_RE.match(normalized)
    if not match:
        return None
    return match.group("name"), match.group("rhs").strip()


def _infer_auto_kind(rhs: str) -> str | None:
    if "create_ckks_evaluator" in rhs:
        return "evaluator"
    if "create_bfv_evaluator" in rhs or "create_bgv_evaluator" in rhs:
        return "evaluator"
    if "create_poseidon_context" in rhs:
        return "context"
    return None


def _parse_decl_assignment(stmt: str) -> tuple[str, str, str] | None:
    normalized = " ".join(stmt.split())
    match = DECL_ASSIGN_RE.match(normalized)
    if not match:
        return None
    return match.group("type").strip(), match.group("name").strip(), match.group("rhs").strip()


def _normalize_value_ref(name: str) -> str:
    indexed_match = INDEX_EXPR_RE.match(" ".join(name.split()))
    if not indexed_match:
        return name.strip()
    base = indexed_match.group("base")
    index = " ".join(indexed_match.group("index").split())
    return f"{base}[{index}]"


def _infer_param_kind(type_text: str) -> str | None:
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


def _parse_parameters(params_text: str) -> list[tuple[str, str | None]]:
    params: list[tuple[str, str | None]] = []
    normalized_params = " ".join(params_text.split())
    if not normalized_params or normalized_params == "void":
        return params
    for param in _split_arguments(normalized_params):
        token = param.strip()
        if not token:
            continue
        match = re.search(r"(?P<name>[A-Za-z_]\w*)\s*$", token)
        if not match:
            continue
        name = match.group("name")
        type_text = token[: match.start("name")].strip()
        kind = _infer_param_kind(type_text)
        params.append((name, kind))
    return params


def _substitute_text(text: str, replacements: dict[str, str]) -> str:
    result = text
    for old, new in sorted(replacements.items(), key=lambda item: len(item[0]), reverse=True):
        result = re.sub(rf"\b{re.escape(old)}\b", new, result)
    return result


def _find_return_expr(body: str) -> str | None:
    for statement in reversed(_extract_statements(body, 1, {})):
        match = RETURN_RE.match(" ".join(statement.raw.split()))
        if match:
            return _normalize_value_ref(match.group("expr").strip())
    return None


def _infer_value_kind(name: str, variables: dict[str, str]) -> str:
    name = _normalize_value_ref(name)
    if name in variables:
        return variables[name]
    indexed_match = INDEX_EXPR_RE.match(name)
    if indexed_match:
        base_kind = variables.get(indexed_match.group("base"))
        if base_kind in INDEXED_KIND_MAP:
            return INDEXED_KIND_MAP[base_kind]
    if name.startswith("\"") or name.replace(".", "", 1).isdigit():
        return "literal"
    return "external"


def _add_value(
    values: list[Value],
    value_index: dict[str, Value],
    name: str,
    kind: str,
    version: int,
    source_line: int,
    producer: str | None,
    is_ephemeral: bool = False,
    annotations: dict[str, Any] | None = None,
) -> str:
    value_id = f"{name}@{version}"
    if value_id not in value_index:
        value = Value(
            id=value_id,
            name=name,
            kind=kind,
            version=version,
            source_line=source_line,
            producer=producer,
            is_ephemeral=is_ephemeral,
            annotations=annotations or {},
        )
        value_index[value_id] = value
        values.append(value)
    return value_id


def extract_he_dag(source_path: str, function_name: str, _stack: set[str] | None = None) -> Dag:
    _stack = set() if _stack is None else set(_stack)
    if function_name in _stack:
        raise ValueError(f"recursive extraction is not supported for '{function_name}'")
    _stack.add(function_name)
    source = _strip_comments(Path(source_path).read_text(encoding="utf-8"))
    params_text, body, body_start_line = _extract_function_definition(source, function_name)
    const_env: dict[str, int] = {}

    initial_statements = _extract_statements(body, body_start_line, const_env)
    for statement in initial_statements:
        const_match = CONST_INT_RE.match(statement.raw)
        if const_match:
            const_env[const_match.group("name")] = int(const_match.group("value"))
    statements = _extract_statements(body, body_start_line, const_env)

    values: list[Value] = []
    value_index: dict[str, Value] = {}
    ops: list[Op] = []
    edges: list[Edge] = []
    variables: dict[str, str] = {}
    current_version: dict[str, int] = {}
    last_write: dict[str, str] = {}
    unsupported: list[dict[str, Any]] = []

    for name, kind in _parse_parameters(params_text):
        if kind:
            variables[name] = kind
            current_version.setdefault(name, 0)
            _add_value(values, value_index, name, kind, 0, body_start_line, producer=None)

    def append_recorded_op(
        *,
        kind: str,
        method: str,
        receiver: str | None,
        input_names: list[str],
        output_names: list[str],
        resource_names: list[str],
        constant_names: list[str],
        source_line: int,
        source_text: str,
        cost: int,
        barrier: bool = False,
        annotations: dict[str, Any] | None = None,
    ) -> None:
        op_id = f"op{len(ops)}"
        input_ids: list[str] = []
        output_ids: list[str] = []
        resource_ids: list[str] = []
        constant_ids: list[str] = []
        read_names: list[str] = []
        write_names: list[str] = []

        for arg in input_names:
            arg = _normalize_value_ref(arg)
            kind_name = _infer_value_kind(arg, variables)
            if kind_name != "external" and arg not in variables:
                variables[arg] = kind_name
            value_id = _add_value(
                values,
                value_index,
                arg,
                kind_name,
                current_version.get(arg, 0),
                source_line,
                producer=last_write.get(arg),
                is_ephemeral=kind_name in {"literal", "external"},
                annotations={"expression": arg} if kind_name in {"literal", "external"} else {},
            )
            input_ids.append(value_id)
            if kind_name != "external":
                read_names.append(arg)

        for arg in resource_names:
            arg = _normalize_value_ref(arg)
            kind_name = _infer_value_kind(arg, variables)
            if kind_name != "external" and arg not in variables:
                variables[arg] = kind_name
            value_id = _add_value(
                values,
                value_index,
                arg,
                kind_name,
                current_version.get(arg, 0),
                source_line,
                producer=last_write.get(arg),
            )
            resource_ids.append(value_id)

        for arg in constant_names:
            arg = _normalize_value_ref(arg)
            kind_name = _infer_value_kind(arg, variables)
            value_id = _add_value(
                values,
                value_index,
                arg,
                kind_name,
                current_version.get(arg, 0),
                source_line,
                producer=last_write.get(arg),
                is_ephemeral=kind_name in {"literal", "external"},
                annotations={"expression": arg} if kind_name in {"literal", "external"} else {},
            )
            constant_ids.append(value_id)

        for arg in output_names:
            arg = _normalize_value_ref(arg)
            kind_name = _infer_value_kind(arg, variables)
            if kind_name != "external" and arg not in variables:
                variables[arg] = kind_name
            current_version[arg] = current_version.get(arg, 0) + 1
            value_id = _add_value(
                values,
                value_index,
                arg,
                variables.get(arg, kind_name),
                current_version[arg],
                source_line,
                producer=op_id,
            )
            output_ids.append(value_id)
            write_names.append(arg)

        op = Op(
            id=op_id,
            kind=kind,
            method=method,
            receiver=receiver,
            inputs=input_ids,
            outputs=output_ids,
            resources=resource_ids,
            constants=constant_ids,
            source_line=source_line,
            source_text=source_text,
            cost=cost,
            barrier=barrier,
            annotations=annotations or {"reads": read_names, "writes": write_names},
        )
        ops.append(op)

        for name, value_id in zip(read_names, input_ids):
            producer = last_write.get(name)
            if producer:
                edges.append(Edge(src=producer, dst=op_id, kind="data", value=value_id, reason=name))
        for arg, value_id in zip(resource_names, resource_ids):
            arg = _normalize_value_ref(arg)
            producer = last_write.get(arg)
            if producer:
                edges.append(Edge(src=producer, dst=op_id, kind="resource", value=value_id, reason=arg))
        for written_name, value_id in zip(write_names, output_ids):
            previous = last_write.get(written_name)
            if previous:
                edge_kind = "anti" if written_name in read_names else "order"
                edges.append(Edge(src=previous, dst=op_id, kind=edge_kind, value=value_id, reason=f"overwrite {written_name}"))
            last_write[written_name] = op_id

    def inline_local_function(
        callee_name: str,
        args: list[str],
        source_line: int,
        source_text: str,
        assign_target: str | None,
    ) -> bool:
        try:
            callee_params, callee_body, _ = _extract_function_definition(source, callee_name)
        except ValueError:
            return False
        helper = extract_he_dag(source_path, callee_name, _stack=_stack)
        helper_params = [name for name, _ in _parse_parameters(callee_params)]
        helper_param_kinds = {name: kind for name, kind in _parse_parameters(callee_params)}
        alias_map: dict[str, str] = {}
        for param_name, arg in zip(helper_params, args):
            alias_map[param_name] = _normalize_value_ref(arg)
            kind = helper_param_kinds.get(param_name)
            if kind and alias_map[param_name] not in variables:
                variables[alias_map[param_name]] = kind
                current_version.setdefault(alias_map[param_name], 0)
                _add_value(values, value_index, alias_map[param_name], kind, 0, source_line, producer=None)
        for value in helper.values:
            if value.name in alias_map:
                continue
            if value.name.startswith("__return__"):
                continue
            if value.name not in helper_params and value.kind not in {"literal", "external"}:
                alias_map[value.name] = f"{callee_name}__{len(ops)}__{value.name}"
        return_expr = _find_return_expr(callee_body)
        if assign_target and return_expr:
            alias_map[return_expr] = _normalize_value_ref(assign_target)

        helper_values = {value.id: value for value in helper.values}
        for helper_op in helper.ops:
            if helper_op.kind == "return":
                continue
            mapped_inputs = [_substitute_text(helper_values[value_id].name, alias_map) for value_id in helper_op.inputs]
            mapped_outputs = [_substitute_text(helper_values[value_id].name, alias_map) for value_id in helper_op.outputs]
            mapped_resources = [_substitute_text(helper_values[value_id].name, alias_map) for value_id in helper_op.resources]
            mapped_constants = [_substitute_text(helper_values[value_id].name, alias_map) for value_id in helper_op.constants]
            mapped_text = _substitute_text(helper_op.source_text, alias_map)
            append_recorded_op(
                kind=helper_op.kind,
                method=helper_op.method,
                receiver=_substitute_text(helper_op.receiver, alias_map) if helper_op.receiver else None,
                input_names=mapped_inputs,
                output_names=mapped_outputs,
                resource_names=mapped_resources,
                constant_names=mapped_constants,
                source_line=source_line,
                source_text=mapped_text,
                cost=helper_op.cost,
                barrier=helper_op.barrier,
                annotations={
                    "inlined_from": callee_name,
                    "callsite": source_text,
                    "reads": mapped_inputs,
                    "writes": mapped_outputs,
                },
            )
        return True

    for statement in statements:
        decl_assignment = _parse_decl_assignment(statement.raw)
        if decl_assignment:
            type_text, name, rhs = decl_assignment
            func_call = _parse_function_call(rhs)
            inferred_kind = _infer_param_kind(type_text)
            if inferred_kind:
                variables.setdefault(name, inferred_kind)
                current_version.setdefault(name, 0)
                _add_value(values, value_index, name, inferred_kind, 0, statement.line, producer=None)
            if func_call and inline_local_function(func_call["name"], func_call["args"], statement.line, statement.raw, name):
                continue

        declaration = _parse_declaration(statement.raw)
        if declaration:
            decl_type, names = declaration
            value_kind = HE_TYPES[decl_type]
            for name in names:
                variables[name] = value_kind
                current_version.setdefault(name, 0)
                _add_value(values, value_index, name, value_kind, 0, statement.line, producer=None)
            continue

        auto_declaration = _parse_auto_declaration(statement.raw)
        if auto_declaration:
            name, rhs = auto_declaration
            inferred_kind = _infer_auto_kind(rhs)
            if inferred_kind:
                variables[name] = inferred_kind
                current_version.setdefault(name, 0)
                _add_value(values, value_index, name, inferred_kind, 0, statement.line, producer=None)
            else:
                normalized_rhs = _normalize_value_ref(rhs)
                rhs_kind = _infer_value_kind(normalized_rhs, variables)
                if rhs_kind != "external":
                    variables[name] = rhs_kind
                    current_version.setdefault(name, 0)
                    _add_value(values, value_index, name, rhs_kind, 0, statement.line, producer=None)
                    if normalized_rhs in variables:
                        op_id = f"op{len(ops)}"
                        input_id = _add_value(
                            values,
                            value_index,
                            normalized_rhs,
                            rhs_kind,
                            current_version.get(normalized_rhs, 0),
                            statement.line,
                            producer=last_write.get(normalized_rhs),
                        )
                        current_version[name] = current_version.get(name, 0) + 1
                        output_id = _add_value(
                            values,
                            value_index,
                            name,
                            rhs_kind,
                            current_version[name],
                            statement.line,
                            producer=op_id,
                        )
                        ops.append(
                            Op(
                                id=op_id,
                                kind="assign",
                                method="assign",
                                receiver=None,
                                inputs=[input_id],
                                outputs=[output_id],
                                resources=[],
                                constants=[],
                                source_line=statement.line,
                                source_text=f"{name} = {normalized_rhs}",
                                cost=1,
                            )
                        )
                        if last_write.get(normalized_rhs):
                            edges.append(
                                Edge(
                                    src=last_write[normalized_rhs],
                                    dst=op_id,
                                    kind="data",
                                    value=input_id,
                                    reason=normalized_rhs,
                                )
                            )
                        last_write[name] = op_id
                else:
                    func_call = _parse_function_call(rhs)
                    if func_call and inline_local_function(func_call["name"], func_call["args"], statement.line, statement.raw, name):
                        variables.setdefault(name, rhs_kind)
            continue

        assignment_match = ASSIGN_RE.match(statement.raw)
        if assignment_match and assignment_match.group("lhs") in variables:
            lhs = assignment_match.group("lhs")
            rhs = assignment_match.group("rhs")
            op_id = f"op{len(ops)}"
            in_version = current_version.get(rhs, 0)
            input_id = _add_value(
                values,
                value_index,
                rhs,
                _infer_value_kind(rhs, variables),
                in_version,
                statement.line,
                producer=last_write.get(rhs),
            )
            current_version[lhs] = current_version.get(lhs, 0) + 1
            output_id = _add_value(
                values,
                value_index,
                lhs,
                variables[lhs],
                current_version[lhs],
                statement.line,
                producer=op_id,
            )
            op = Op(
                id=op_id,
                kind="assign",
                method="assign",
                receiver=None,
                inputs=[input_id],
                outputs=[output_id],
                resources=[],
                constants=[],
                source_line=statement.line,
                source_text=statement.raw,
                cost=1,
            )
            ops.append(op)
            if last_write.get(rhs):
                edges.append(Edge(src=last_write[rhs], dst=op_id, kind="data", value=input_id, reason=rhs))
            if last_write.get(lhs):
                edges.append(Edge(src=last_write[lhs], dst=op_id, kind="order", value=output_id, reason=f"overwrite {lhs}"))
            last_write[lhs] = op_id
            continue

        assign_call_match = ASSIGN_CALL_RE.match(" ".join(statement.raw.split()))
        if assign_call_match and assign_call_match.group("lhs") in variables:
            lhs = assign_call_match.group("lhs")
            rhs = assign_call_match.group("rhs").strip()
            func_call = _parse_function_call(rhs)
            if func_call and inline_local_function(func_call["name"], func_call["args"], statement.line, statement.raw, lhs):
                continue

        call = _parse_call(statement.raw)
        if not call:
            plain_call = _parse_function_call(statement.raw)
            if plain_call and inline_local_function(plain_call["name"], plain_call["args"], statement.line, statement.raw, None):
                continue
            return_match = RETURN_RE.match(" ".join(statement.raw.split()))
            if return_match:
                expr = _normalize_value_ref(return_match.group("expr").strip())
                expr_kind = _infer_value_kind(expr, variables)
                if expr_kind not in {"external", "literal"}:
                    append_recorded_op(
                        kind="return",
                        method="return",
                        receiver=None,
                        input_names=[expr],
                        output_names=["__return__"],
                        resource_names=[],
                        constant_names=[],
                        source_line=statement.line,
                        source_text=f"return {expr}",
                        cost=1,
                    )
                continue
            continue
        method_spec = HE_METHODS.get(call["method"])
        if not method_spec:
            continue

        args = call["args"]
        output_positions = []
        for position in method_spec.get("output_positions", []):
            output_positions.append(position if position >= 0 else len(args) + position)
        resource_positions = set(method_spec.get("resource_positions", []))
        constant_positions = set(method_spec.get("constant_positions", []))

        input_names: list[str] = []
        output_names: list[str] = []
        resource_names: list[str] = []
        constant_names: list[str] = []

        for index, arg in enumerate(args):
            arg = _normalize_value_ref(arg.strip())
            inferred_arg_kind = _infer_value_kind(arg, variables)
            if index in output_positions and inferred_arg_kind != "external":
                output_names.append(arg)
                continue
            if index in resource_positions:
                resource_names.append(arg)
            elif index in constant_positions or inferred_arg_kind in {"literal", "external"}:
                constant_names.append(arg)
            else:
                input_names.append(arg)

        if not output_names and call["method"] not in {"read"}:
            unsupported.append({"line": statement.line, "statement": statement.raw, "reason": "supported method without tracked output variable"})
            continue
        append_recorded_op(
            kind=method_spec["kind"],
            method=call["method"],
            receiver=call["receiver"],
            input_names=input_names,
            output_names=output_names,
            resource_names=resource_names,
            constant_names=constant_names,
            source_line=statement.line,
            source_text=call.get("full_text", statement.raw),
            cost=method_spec["cost"],
            barrier=method_spec.get("barrier", False),
            annotations={
                "reads": input_names,
                "writes": output_names,
                "expanded_from_loop": statement.expanded_from_loop,
                "loop_context": statement.loop_context or {},
            },
        )

    metadata = {
        "ir_version": 1,
        "supported_methods": sorted(HE_METHODS.keys()),
        "value_kinds": sorted(set(HE_TYPES.values()) | {"external", "literal"}),
    }

    return Dag(
        source_file=source_path,
        function=function_name,
        source_hash=hashlib.sha256(source.encode("utf-8")).hexdigest(),
        values=values,
        ops=ops,
        edges=edges,
        unsupported=unsupported,
        metadata=metadata,
    )
