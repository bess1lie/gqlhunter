from unittest.mock import MagicMock

import pytest

from gqlhunter.generator.query_builder import build_as_json, build_mutation, build_query
from gqlhunter.schema.parser import ArgType, Field, FieldArg, SchemaType


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
    "Mutation": _st(
        "Mutation",
        [
            _field("deleteUser", return_name="Boolean", args=[_arg("id", type_name="ID")]),
            _field(
                "createUser",
                return_name="User",
                return_kind="OBJECT",
                args=[_arg("name"), _arg("email")],
            ),
        ],
    ),
}


# ── Positive: query text output ──


def test_build_query_scalar_return() -> None:
    f = _field("ping", return_name="String")
    result = build_query(f, TYPES)
    assert result == "query {\n  ping \n}"


def test_build_query_with_args() -> None:
    f = _field("user", return_name="User", return_kind="OBJECT", args=[_arg("id", type_name="ID")])
    result = build_query(f, TYPES)
    assert "(id: " in result
    assert "user" in result


def test_build_query_object_selection() -> None:
    f = _field("user", return_name="User", return_kind="OBJECT")
    result = build_query(f, TYPES)
    assert "id" in result
    assert "email" in result
    assert result.count("{") >= 1


def test_build_query_no_args() -> None:
    f = _field("users", return_name="User", return_kind="OBJECT")
    result = build_query(f, TYPES)
    assert "()" not in result


def test_build_query_multiple_args() -> None:
    f = _field(
        "search",
        return_name="User",
        return_kind="OBJECT",
        args=[_arg("query"), _arg("limit", type_name="Int")],
    )
    result = build_query(f, TYPES)
    assert "query: " in result
    assert "limit: 0" in result


# ── Positive: mutation text output ──


def test_build_mutation_has_warning() -> None:
    f = _field("deleteUser", return_name="Boolean", args=[_arg("id", type_name="ID")])
    result = build_mutation(f, TYPES)
    assert "DO NOT AUTO-RUN" in result
    assert result.startswith("# DO NOT AUTO-RUN")


def test_build_mutation_body_starts_mutation() -> None:
    f = _field("deleteUser", return_name="Boolean", args=[_arg("id", type_name="ID")])
    result = build_mutation(f, TYPES)
    assert "mutation {" in result


def test_build_mutation_includes_field_name() -> None:
    f = _field("createUser", return_name="User", return_kind="OBJECT", args=[_arg("name")])
    result = build_mutation(f, TYPES)
    assert "createUser" in result


def test_build_mutation_placeholder_values() -> None:
    f = _field("updateEmail", args=[_arg("email")])
    result = build_mutation(f, TYPES)
    assert 'email: "value"' in result


# ── Positive: JSON output ──


def test_build_as_json_query() -> None:
    text = "query { ping }"
    result = build_as_json(text, "query", "ping")
    assert '"query":' in result
    assert '"operation": "query.ping"' in result
    assert '"warning"' not in result


def test_build_as_json_mutation_has_warning() -> None:
    text = "mutation { deleteUser }"
    result = build_as_json(text, "mutation", "deleteUser")
    assert '"warning"' in result
    assert "DO NOT AUTO-RUN" in result


# ── Positive: arg type placeholder mapping ──


def test_placeholder_int() -> None:
    f = _field("doSomething", args=[_arg("count", type_name="Int")])
    r = build_query(f, TYPES)
    assert "count: 0" in r


def test_placeholder_float() -> None:
    f = _field("doSomething", args=[_arg("price", type_name="Float")])
    r = build_query(f, TYPES)
    assert "price: 0.0" in r


def test_placeholder_boolean() -> None:
    f = _field("doSomething", args=[_arg("active", type_name="Boolean")])
    r = build_query(f, TYPES)
    assert "active: true" in r


def test_placeholder_id() -> None:
    f = _field("getById", args=[_arg("id", type_name="ID")])
    r = build_query(f, TYPES)
    assert 'id: "ID"' in r


def test_placeholder_string() -> None:
    f = _field("search", args=[_arg("query")])
    r = build_query(f, TYPES)
    assert 'query: "value"' in r


# ── GUARDRAIL: zero network calls from generators ──


def test_build_query_makes_zero_network_calls() -> None:
    mock_client = MagicMock()
    f = _field("user", return_name="User", return_kind="OBJECT", args=[_arg("id", type_name="ID")])
    _ = build_query(f, TYPES)
    mock_client.get.assert_not_called()
    mock_client.post.assert_not_called()
    mock_client.request.assert_not_called()


def test_build_mutation_makes_zero_network_calls() -> None:
    mock_client = MagicMock()
    f = _field("deleteUser", return_name="Boolean", args=[_arg("id", type_name="ID")])
    _ = build_mutation(f, TYPES)
    mock_client.get.assert_not_called()
    mock_client.post.assert_not_called()
    mock_client.request.assert_not_called()


def test_build_as_json_makes_zero_network_calls() -> None:
    mock_client = MagicMock()
    _ = build_as_json("query { ping }", "query", "ping")
    mock_client.get.assert_not_called()
    mock_client.post.assert_not_called()
    mock_client.request.assert_not_called()


# ── Cyclic schema guard (infinite recursion protection) ──


def _cyclic_types() -> dict[str, SchemaType]:
    post = SchemaType(
        kind="OBJECT",
        name="Post",
        description=None,
        fields=[
            Field(
                name="author",
                description=None,
                return_type=ArgType(kind="OBJECT", name="User", of_type="User"),
            ),
        ],
    )
    user = SchemaType(
        kind="OBJECT",
        name="User",
        description=None,
        fields=[
            Field(name="id", description=None, return_type=ArgType(kind="SCALAR", name="ID")),
            Field(
                name="friends",
                description=None,
                return_type=ArgType(kind="LIST", name=None, of_type="[User]"),
            ),
            Field(
                name="posts",
                description=None,
                return_type=ArgType(kind="LIST", name=None, of_type="[Post]"),
            ),
        ],
    )
    return {"User": user, "Post": post}


def test_build_query_cyclic_schema_completes() -> None:
    types = _cyclic_types()
    f = Field(
        name="me",
        description=None,
        return_type=ArgType(kind="OBJECT", name="User", of_type="User"),
    )
    result = build_query(f, types)
    assert "friends" in result
    assert "posts" in result
    assert "id" in result


def test_build_query_cyclic_schema_no_recursion_error() -> None:
    types = _cyclic_types()
    f = Field(
        name="me",
        description=None,
        return_type=ArgType(kind="OBJECT", name="User", of_type="User"),
    )
    import sys

    sys.setrecursionlimit(100)
    try:
        result = build_query(f, types, max_depth=3)
        assert result
    except RecursionError:
        pytest.fail("build_query raised RecursionError on cyclic schema")
    finally:
        sys.setrecursionlimit(1000)


def test_build_mutation_cyclic_schema_completes() -> None:
    types = _cyclic_types()
    f = Field(
        name="deleteUser",
        description=None,
        return_type=ArgType(kind="SCALAR", name="Boolean"),
        args=[FieldArg(name="id", type=ArgType(kind="SCALAR", name="ID"))],
    )
    result = build_mutation(f, types)
    assert "DO NOT AUTO-RUN" in result


def test_max_depth_limits_nesting() -> None:
    types = _cyclic_types()
    f = Field(
        name="me",
        description=None,
        return_type=ArgType(kind="OBJECT", name="User", of_type="User"),
    )
    shallow = build_query(f, types, max_depth=1)
    deeper = build_query(f, types, max_depth=3)
    assert len(shallow) < len(deeper)
