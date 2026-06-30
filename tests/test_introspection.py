from unittest.mock import AsyncMock

import httpx
import pytest

from gqlhunter.core.http_client import HttpClient
from gqlhunter.introspection.introspection import (
    IntrospectionStatus,
    run_introspection,
)

GOOD_SCHEMA = {
    "data": {
        "__schema": {
            "queryType": {"name": "Query"},
            "mutationType": {"name": "Mutation"},
            "types": [{"kind": "OBJECT", "name": "Query", "fields": []}],
        }
    }
}


def _mock_post(status: int = 200, body: dict | None = None) -> AsyncMock:
    return AsyncMock(return_value=httpx.Response(status, json=body or GOOD_SCHEMA))


@pytest.mark.anyio
async def test_enabled() -> None:
    async with HttpClient(timeout=5.0) as client:
        client._client.request = _mock_post(200, GOOD_SCHEMA)
        result = await run_introspection("https://example.com/graphql", client)
        assert result.status == IntrospectionStatus.ENABLED
        assert result.data is not None


@pytest.mark.anyio
async def test_disabled_with_errors() -> None:
    body = {"errors": [{"message": "query not allowed"}]}
    async with HttpClient(timeout=5.0) as client:
        client._client.request = _mock_post(200, body)
        result = await run_introspection("https://example.com/graphql", client)
        assert result.status == IntrospectionStatus.DISABLED


@pytest.mark.anyio
async def test_filtered() -> None:
    body = {"errors": [{"message": "Filtered introspection"}]}
    async with HttpClient(timeout=5.0) as client:
        client._client.request = _mock_post(200, body)
        result = await run_introspection("https://example.com/graphql", client)
        assert result.status == IntrospectionStatus.FILTERED


@pytest.mark.anyio
async def test_requires_auth_401() -> None:
    async with HttpClient(timeout=5.0) as client:
        client._client.request = _mock_post(401)
        result = await run_introspection("https://example.com/graphql", client)
        assert result.status == IntrospectionStatus.REQUIRES_AUTH
        assert result.status_code == 401


@pytest.mark.anyio
async def test_requires_auth_403() -> None:
    async with HttpClient(timeout=5.0) as client:
        client._client.request = _mock_post(403)
        result = await run_introspection("https://example.com/graphql", client)
        assert result.status == IntrospectionStatus.REQUIRES_AUTH


@pytest.mark.anyio
async def test_blocked_non_200() -> None:
    async with HttpClient(timeout=5.0) as client:
        client._client.request = _mock_post(500)
        result = await run_introspection("https://example.com/graphql", client)
        assert result.status == IntrospectionStatus.BLOCKED


@pytest.mark.anyio
async def test_not_graphql() -> None:
    async with HttpClient(timeout=5.0) as client:
        client._client.request = _mock_post(200, {"not": "json"})
        result = await run_introspection("https://example.com/graphql", client)
        assert result.status == IntrospectionStatus.NOT_GRAPHQL


@pytest.mark.anyio
async def test_not_graphql_when_no_schema() -> None:
    body = {"data": {"__schema": None}}
    async with HttpClient(timeout=5.0) as client:
        client._client.request = _mock_post(200, body)
        result = await run_introspection("https://example.com/graphql", client)
        assert result.status == IntrospectionStatus.NOT_GRAPHQL


@pytest.mark.anyio
async def test_connection_error_returns_blocked() -> None:
    async with HttpClient(timeout=5.0) as client:
        client._client.request = AsyncMock(
            side_effect=httpx.ConnectError("Connection refused")
        )
        result = await run_introspection("https://example.com/graphql", client)
        assert result.status == IntrospectionStatus.BLOCKED
