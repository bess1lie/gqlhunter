from __future__ import annotations

import json
from typing import Any

from gqlhunter.schema.parser import ArgType, Field, SchemaType

PLACEHOLDER_BY_SCALAR = {
    "String": '"value"',
    "Int": "0",
    "Float": "0.0",
    "Boolean": "true",
    "ID": '"ID"',
}


def build_query(field: Field, types_by_name: dict[str, SchemaType], max_depth: int = 3) -> str:
    selection = _build_selection(field.return_type, types_by_name, depth=0, max_depth=max_depth)
    args = _build_args(field.args)
    return f"query {{\n  {field.name}{args} {selection}\n}}"


def build_mutation(field: Field, types_by_name: dict[str, SchemaType], max_depth: int = 3) -> str:
    selection = _build_selection(field.return_type, types_by_name, depth=0, max_depth=max_depth)
    args = _build_args(field.args)
    body = f"mutation {{\n  {field.name}{args} {selection}\n}}"
    return f"# DO NOT AUTO-RUN — manual verification required\n{body}"


def build_as_json(
    query_text: str,
    operation_type: str,
    operation_name: str,
) -> str:
    payload: dict[str, Any] = {
        "query": query_text,
        "operation": f"{operation_type}.{operation_name}",
    }
    if operation_type == "mutation":
        payload["warning"] = "DO NOT AUTO-RUN — manual verification required"
    return json.dumps(payload, indent=2)


def _build_args(args: list[Field]) -> str:
    if not args:
        return ""
    parts: list[str] = []
    for a in args:
        val = _placeholder(a.type)
        parts.append(f"{a.name}: {val}")
    return f"({', '.join(parts)})"


def _placeholder(t: ArgType) -> str:
    unwrapped = _unwrap_type(t)
    if unwrapped in PLACEHOLDER_BY_SCALAR:
        return PLACEHOLDER_BY_SCALAR[unwrapped]
    return '"PLACEHOLDER"'


def _unwrap_type(t: ArgType) -> str:
    if t.name and t.name in PLACEHOLDER_BY_SCALAR:
        return t.name
    if t.name:
        return t.name
    if t.of_type:
        raw = t.of_type.strip("![]")
        return raw if raw else "String"
    return "String"


def _base_type_name(t: ArgType | None) -> str | None:
    if t is None:
        return None
    if t.name:
        return t.name
    if t.of_type:
        raw = t.of_type.strip("![]")
        return raw if raw else None
    return None


def _build_selection(
    return_type: ArgType | None,
    types_by_name: dict[str, SchemaType],
    depth: int,
    max_depth: int = 3,
) -> str:
    if depth >= max_depth:
        return ""

    type_name = _base_type_name(return_type)
    if type_name is None:
        return ""

    st = types_by_name.get(type_name)
    if st is None or st.kind != "OBJECT" or not st.fields:
        return ""

    lines: list[str] = []
    indent = "  " * (depth + 1)

    for f in st.fields:
        f_type_name = _base_type_name(f.return_type)
        f_st = types_by_name.get(f_type_name) if f_type_name else None

        if f_st and f_st.kind == "OBJECT" and f_st.fields:
            nested = _build_selection(f.return_type, types_by_name, depth + 1, max_depth)
            if nested:
                lines.append(f"{indent}{f.name} {nested}")
            else:
                lines.append(f"{indent}{f.name}")
        else:
            lines.append(f"{indent}{f.name}")

    if not lines:
        return ""

    body = "\n".join(lines)
    outer_indent = "  " * depth
    return f"{{\n{body}\n{outer_indent}}}"
