from unittest.mock import AsyncMock

import httpx
import pytest

from gqlhunter.core.http_client import HttpClient
from gqlhunter.core.scope import Scope
from gqlhunter.discovery.endpoint_discovery import discover_endpoints


@pytest.mark.anyio
async def test_discovers_common_paths() -> None:
    scope = Scope(targets=["example.com"])
    responses = [httpx.Response(200, text="hello")] + [httpx.Response(404) for _ in range(17)]

    async with HttpClient(timeout=5.0) as client:
        client._client.request = AsyncMock(side_effect=responses)
        results = await discover_endpoints("https://example.com", scope, client)

    assert any(r.url == "https://example.com/graphql" for r in results)
    assert any(r.url == "https://example.com/api/graphql" for r in results)
    assert sum(1 for r in results if r.status_code == 200) == 1


@pytest.mark.anyio
async def test_no_endpoints_when_target_out_of_scope() -> None:
    scope = Scope(targets=["allowed.com"])
    async with HttpClient(timeout=5.0) as client:
        results = await discover_endpoints("https://evil.com", scope, client)
    assert results == []


@pytest.mark.anyio
async def test_includes_extra_paths() -> None:
    scope = Scope(targets=["example.com"])
    async with HttpClient(timeout=5.0) as client:
        client._client.request = AsyncMock(return_value=httpx.Response(200))
        results = await discover_endpoints(
            "https://example.com", scope, client, extra_paths=["/custom/graphql"]
        )
    assert any(r.url == "https://example.com/custom/graphql" for r in results)


@pytest.mark.anyio
async def test_ignores_connection_errors() -> None:
    scope = Scope(targets=["example.com"])
    async with HttpClient(timeout=5.0) as client:
        client._client.request = AsyncMock(
            side_effect=httpx.ConnectError("Connection refused")
        )
        results = await discover_endpoints("https://example.com", scope, client)
    assert results == []
