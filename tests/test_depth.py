from __future__ import annotations

from gqlhunter.introspection.introspection import _build_introspection_query


class TestBuildIntrospectionQuery:
    def test_default_depth_4(self) -> None:
        query = _build_introspection_query(max_depth=4)
        assert "fragment TypeRef" in query
        assert query.count("ofType") == 4

    def test_depth_2(self) -> None:
        query = _build_introspection_query(max_depth=2)
        assert query.count("ofType") == 2

    def test_depth_6(self) -> None:
        query = _build_introspection_query(max_depth=6)
        assert query.count("ofType") == 6

    def test_no_introspection_test(self) -> None:
        query = _build_introspection_query(max_depth=0)
        assert "ofType" not in query

    def test_generates_valid_graphql_fragment(self) -> None:
        query = _build_introspection_query(max_depth=3)
        assert "kind" in query
        assert "name" in query
        assert query.strip().endswith("}")
