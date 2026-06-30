from __future__ import annotations

import json
import random
from dataclasses import dataclass, field
from typing import Any

from gqlhunter.generator.query_builder import build_as_json, build_mutation, build_query
from gqlhunter.schema.parser import ArgType, Field, FieldArg, SchemaType


@dataclass
class Variant:
    variant_type: str
    operation_type: str
    operation_name: str
    query: str
    description: str


def _field_from_op(op: dict) -> Field:
    args = []
    if op.get("args_json"):
        raw = json.loads(op["args_json"])
        for a in raw:
            args.append(FieldArg(
                name=a["name"],
                type=ArgType(kind="SCALAR", name=a["type"], of_type=a["type"]),
            ))
    return Field(
        name=op["name"],
        description=op.get("description"),
        args=args,
        return_type=ArgType(kind="OBJECT", name=op["return_type"] or "String", of_type=op.get("return_type")),
    )


def _alias_variant(field: Field, types_by_name: dict[str, SchemaType], max_depth: int = 3) -> str:
    base = build_query(field, types_by_name, max_depth)
    lines = base.split("\n")
    if len(lines) >= 2:
        inner = lines[1].strip()
        aliases = "\n".join(
            f"  a{i}: {inner.lstrip()}" for i in range(1, 4)
        )
        return f"{{\n{aliases}\n}}"
    return base


def _arg_removal_variants(field: Field, types_by_name: dict[str, SchemaType], max_depth: int = 3) -> list[str]:
    if not field.args:
        return []
    queries = []
    for i in range(len(field.args)):
        reduced = [a for j, a in enumerate(field.args) if j != i]
        modified = Field(
            name=field.name,
            description=field.description,
            args=reduced,
            return_type=field.return_type,
        )
        queries.append(build_query(modified, types_by_name, max_depth))
    return queries


def _depth_variants(field: Field, types_by_name: dict[str, SchemaType], depths: list[int]) -> list[str]:
    return [build_query(field, types_by_name, d) for d in depths]


def generate_variants(
    operations: list[dict[str, Any]],
    types_by_name: dict[str, SchemaType],
    strategy: str = "single",
    max_depth: int = 3,
) -> list[Variant]:
    variants: list[Variant] = []

    for op in operations:
        op_type = op.get("type", "query")
        op_name = op.get("name", "unknown")
        field = _field_from_op(op)

        if strategy == "single":
            q = _alias_variant(field, types_by_name, max_depth)
            variants.append(Variant(
                variant_type="alias",
                operation_type=op_type,
                operation_name=op_name,
                query=q,
                description="Aliased 3x",
            ))
            if op_type == "mutation":
                qm = build_mutation(field, types_by_name, max_depth)
                variants.append(Variant(
                    variant_type="standard",
                    operation_type=op_type,
                    operation_name=op_name,
                    query=qm,
                    description="Standard mutation (manual verify)",
                ))

        elif strategy == "combinations":
            alias_q = _alias_variant(field, types_by_name, max_depth)
            variants.append(Variant("alias", op_type, op_name, alias_q, "Aliased 3x"))

            for q in _arg_removal_variants(field, types_by_name, max_depth):
                variants.append(Variant("arg_removal", op_type, op_name, q, "Removed one arg"))

            for d, dq in zip([1, 3, 5], _depth_variants(field, types_by_name, [1, 3, 5])):
                variants.append(Variant("depth", op_type, op_name, dq, f"Depth={d}"))

            if op_type == "mutation":
                qm = build_mutation(field, types_by_name, max_depth)
                variants.append(Variant("standard", op_type, op_name, qm, "Standard mutation"))

        elif strategy == "random":
            pool: list[tuple[str, str, str]] = []
            pool.append(("alias", _alias_variant(field, types_by_name, max_depth), "Aliased 3x"))
            for q in _arg_removal_variants(field, types_by_name, max_depth):
                pool.append(("arg_removal", q, "Removed one arg"))

            if op_type == "mutation":
                qm = build_mutation(field, types_by_name, max_depth)
                pool.append(("standard", qm, "Standard mutation"))

            if pool:
                selected = random.sample(pool, min(2, len(pool)))
                for vt, q, desc in selected:
                    variants.append(Variant(vt, op_type, op_name, q, desc))

    return variants


def variants_to_json(variants: list[Variant], indent: int = 2) -> str:
    data = [
        {
            "variant_type": v.variant_type,
            "operation_type": v.operation_type,
            "operation_name": v.operation_name,
            "query": v.query,
            "description": v.description,
        }
        for v in variants
    ]
    return json.dumps(data, indent=indent)
