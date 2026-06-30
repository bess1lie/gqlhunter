from unittest.mock import AsyncMock

import httpx
import pytest

from gqlhunter.core.http_client import HttpClient


@pytest.mark.anyio
async def test_successful_request() -> None:
    async with HttpClient(timeout=5.0) as client:
        mock_response = httpx.Response(200, text='{"status": "ok"}')
        client._client.request = AsyncMock(return_value=mock_response)
        resp = await client.get("https://example.com/graphql")
        assert resp.status_code == 200
        assert resp.json() == {"status": "ok"}


@pytest.mark.anyio
async def test_retries_on_timeout() -> None:
    async with HttpClient(timeout=5.0, max_retries=2) as client:
        ok_resp = httpx.Response(200, text="ok")
        client._client.request = AsyncMock(
            side_effect=[
                httpx.TimeoutException("timeout"),
                httpx.TimeoutException("timeout"),
                ok_resp,
            ]
        )
        resp = await client.post("https://example.com/graphql", json={"query": "{ __typename }"})
        assert resp.status_code == 200
        assert client._client.request.call_count == 3


@pytest.mark.anyio
async def test_raises_after_all_retries_fail() -> None:
    async with HttpClient(timeout=5.0, max_retries=2) as client:
        client._client.request = AsyncMock(
            side_effect=httpx.TimeoutException("always timeout")
        )
        with pytest.raises(RuntimeError, match="failed after 2 retries"):
            await client.get("https://example.com/graphql")
        assert client._client.request.call_count == 3


@pytest.mark.anyio
async def test_connect_error_retries() -> None:
    async with HttpClient(timeout=5.0, max_retries=1) as client:
        ok_resp = httpx.Response(200)
        client._client.request = AsyncMock(
            side_effect=[httpx.ConnectError("refused"), ok_resp]
        )
        resp = await client.get("https://example.com/graphql")
        assert resp.status_code == 200
        assert client._client.request.call_count == 2


@pytest.mark.anyio
async def test_merges_default_with_extra_headers() -> None:
    async with HttpClient(timeout=5.0, headers={"User-Agent": "gqlhunter/0.1.0"}) as client:
        mock_response = httpx.Response(200)
        client._client.request = AsyncMock(return_value=mock_response)
        await client.get("https://example.com/graphql", headers={"Authorization": "Bearer x"})
        call_kwargs = client._client.request.call_args[1]
        merged = call_kwargs["headers"]
        assert merged["User-Agent"] == "gqlhunter/0.1.0"
        assert merged["Authorization"] == "Bearer x"


@pytest.mark.anyio
async def test_close_sets_client_to_none() -> None:
    async with HttpClient(timeout=5.0) as client:
        assert client._client is not None
    assert client._client is None


@pytest.mark.anyio
async def test_raises_when_used_after_close() -> None:
    client = HttpClient(timeout=5.0)
    await client.__aenter__()
    await client.close()
    with pytest.raises(RuntimeError, match="closed"):
        await client.get("https://example.com/graphql")
