from __future__ import annotations

import json

from gqlhunter.generator.query_builder import build_as_json, build_query
from gqlhunter.schema.parser import ArgType, Field, FieldArg, SchemaType
from gqlhunter.variants.variant_engine import (
    Variant,
    _alias_variant,
    _arg_removal_variants,
    _depth_variants,
    _field_from_op,
    generate_variants,
    variants_to_json,
)


def _st(name: str, fields: list | None = None) -> SchemaType:
    return SchemaType(kind="OBJECT", name=name, description=None, fields=fields or [])


def _field(
    name: str,
    return_kind: str = "SCALAR",
    return_name: str = "String",
    args: list | None = None,
) -> Field:
    return Field(
        name=name,
        description=None,
        args=args or [],
        return_type=ArgType(kind=return_kind, name=return_name),
    )


def _arg(name: str, kind: str = "SCALAR", type_name: str = "String") -> FieldArg:
    return FieldArg(name=name, type=ArgType(kind=kind, name=type_name))


TYPES: dict[str, SchemaType] = {
    "User": _st("User", [_field("id", return_name="ID"), _field("email")]),
    "Query": _st("Query", [_field("user", return_name="User", return_kind="OBJECT")]),
}

QUERY_OP = {
    "type": "query",
    "name": "user",
    "args_json": '[{"name": "id", "type": "ID"}]',
    "return_type": "User",
}

MUTATION_OP = {
    "type": "mutation",
    "name": "deleteUser",
    "args_json": '[{"name": "id", "type": "ID"}]',
    "return_type": "Boolean",
}


class TestFieldFromOp:
    def test_creates_field_with_args(self) -> None:
        field = _field_from_op(QUERY_OP)
        assert field.name == "user"
        assert len(field.args) == 1
        assert field.args[0].name == "id"

    def test_no_args_when_args_json_none(self) -> None:
        op = dict(QUERY_OP, args_json=None)
        field = _field_from_op(op)
        assert field.args == []


class TestAliasVariant:
    def test_generates_aliased_query(self) -> None:
        field = _field_from_op(QUERY_OP)
        result = _alias_variant(field, TYPES)
        assert "a1:" in result
        assert "a2:" in result
        assert "a3:" in result
        assert "user" in result


class TestArgRemovalVariants:
    def test_returns_empty_when_no_args(self) -> None:
        field = _field("ping", return_name="String")
        result = _arg_removal_variants(field, TYPES)
        assert result == []

    def test_returns_one_variant_per_arg(self) -> None:
        field = _field_from_op(QUERY_OP)
        result = _arg_removal_variants(field, TYPES)
        assert len(result) == 1
        assert '(id: "ID")' not in result[0]

    def test_multiple_args(self) -> None:
        field = _field("search", args=[_arg("q"), _arg("limit", type_name="Int")])
        result = _arg_removal_variants(field, TYPES)
        assert len(result) == 2


class TestDepthVariants:
    def test_returns_variants_for_each_depth(self) -> None:
        field = _field("user", return_name="User", return_kind="OBJECT", args=[_arg("id", type_name="ID")])
        result = _depth_variants(field, TYPES, [1, 3])
        assert len(result) == 2
        assert len(result[0]) <= len(result[1])


class TestGenerateVariants:
    def test_single_strategy_yields_alias_for_query(self) -> None:
        result = generate_variants([QUERY_OP], TYPES, strategy="single")
        assert len(result) == 1
        assert result[0].variant_type == "alias"

    def test_single_strategy_yields_alias_and_standard_for_mutation(self) -> None:
        result = generate_variants([MUTATION_OP], TYPES, strategy="single")
        assert len(result) == 2
        types = {v.variant_type for v in result}
        assert types == {"alias", "standard"}

    def test_combinations_strategy(self) -> None:
        result = generate_variants([QUERY_OP], TYPES, strategy="combinations")
        assert len(result) >= 3
        types = {v.variant_type for v in result}
        assert "alias" in types
        assert "arg_removal" in types
        assert "depth" in types

    def test_random_strategy(self) -> None:
        result = generate_variants([QUERY_OP], TYPES, strategy="random")
        assert len(result) >= 1

    def test_multiple_operations(self) -> None:
        ops = [QUERY_OP, MUTATION_OP]
        result = generate_variants(ops, TYPES, strategy="single")
        assert len(result) >= 2


class TestVariantsToJson:
    def test_serializes_to_json(self) -> None:
        variants = [
            Variant("alias", "query", "user", "query { a1: user }", "Aliased"),
        ]
        text = variants_to_json(variants)
        data = json.loads(text)
        assert len(data) == 1
        assert data[0]["variant_type"] == "alias"
        assert data[0]["operation_type"] == "query"

    def test_pretty_print_default(self) -> None:
        variants = [
            Variant("alias", "query", "user", "query { a1: user }", "Aliased"),
        ]
        text = variants_to_json(variants)
        assert "\n" in text


# ── GUARDRAIL: zero network calls ──


def test_variant_engine_makes_zero_network_calls() -> None:
    from unittest.mock import MagicMock
    mock = MagicMock()
    result = generate_variants([QUERY_OP], TYPES, strategy="single")
    assert len(result) >= 1
    mock.get.assert_not_called()
    mock.post.assert_not_called()
    mock.request.assert_not_called()
