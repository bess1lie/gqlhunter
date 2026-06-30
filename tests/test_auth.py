from unittest.mock import AsyncMock

import httpx
import pytest

from gqlhunter.auth.auth_analyzer import (
    AuthClassification,
    _preview,
    analyze_auth,
)
from gqlhunter.core.http_client import HttpClient


def _mock_request(
    without_status: int = 200,
    with_status: int = 200,
    without_body: str = '{"data": {"__typename": "Query"}}',
    with_body: str = '{"data": {"__typename": "Query"}}',
) -> AsyncMock:
    """Return an AsyncMock that returns configured responses on sequential calls."""
    return AsyncMock(
        side_effect=[
            httpx.Response(without_status, text=without_body),
            httpx.Response(with_status, text=with_body),
        ]
    )


@pytest.mark.anyio
async def test_auth_required() -> None:
    async with HttpClient(timeout=5.0) as client:
        client._client.request = _mock_request(without_status=401, with_status=200)
        result = await analyze_auth("https://api.example.com/graphql", "Bearer token", client)
    assert result.classification == AuthClassification.AUTH_REQUIRED
    assert result.without_token_status == 401
    assert result.with_token_status == 200


@pytest.mark.anyio
async def test_public() -> None:
    async with HttpClient(timeout=5.0) as client:
        client._client.request = _mock_request(
            without_status=200,
            with_status=403,
            without_body='{"data": {"__typename": "Query"}}',
            with_body='{"error": "unauthorized"}',
        )
        result = await analyze_auth("https://api.example.com/graphql", "Bearer token", client)
    assert result.classification == AuthClassification.PUBLIC


@pytest.mark.anyio
async def test_over_permissive() -> None:
    async with HttpClient(timeout=5.0) as client:
        client._client.request = _mock_request(
            without_status=200,
            with_status=200,
            without_body='{"data": {"user": "public"}}',
            with_body='{"data": {"user": "public"}}',
        )
        result = await analyze_auth("https://api.example.com/graphql", "Bearer token", client)
    assert result.classification == AuthClassification.OVER_PERMISSIVE


@pytest.mark.anyio
async def test_blocked() -> None:
    async with HttpClient(timeout=5.0) as client:
        client._client.request = _mock_request(without_status=500, with_status=500)
        result = await analyze_auth("https://api.example.com/graphql", "Bearer token", client)
    assert result.classification == AuthClassification.BLOCKED


@pytest.mark.anyio
async def test_custom_payload() -> None:
    async with HttpClient(timeout=5.0) as client:
        client._client.request = _mock_request()
        payload = {"query": "query { user { id } }"}
        result = await analyze_auth("https://api.example.com/graphql", "Bearer token", client, query_payload=payload)
    assert result.with_token_request_payload == payload
    assert result.without_token_request_payload == payload


@pytest.mark.anyio
async def test_error_on_first_request() -> None:
    async with HttpClient(timeout=5.0) as client:
        client._client.request = AsyncMock(
            side_effect=httpx.ConnectError("Connection refused")
        )
        result = await analyze_auth("https://api.example.com/graphql", "Bearer token", client)
    assert result.classification == AuthClassification.ERROR


# ── GUARDRAIL: identical args, only header differs ──


@pytest.mark.anyio
async def test_guardrail_identical_payload_only_header_differs() -> None:
    calls: list[dict] = []

    async def recording_request(method, url, **kwargs):
        calls.append({"method": method, "url": url, "kwargs": kwargs})
        return httpx.Response(200, text='{"data": {"__typename": "Query"}}')

    async with HttpClient(timeout=5.0) as client:
        client._client.request = recording_request
        result = await analyze_auth("https://api.example.com/graphql", "Bearer test-token", client)

    assert result.classification == AuthClassification.OVER_PERMISSIVE
    assert len(calls) == 2, "expected exactly 2 HTTP calls"

    without_auth, with_auth = calls

    assert without_auth["method"] == "POST"
    assert with_auth["method"] == "POST"
    assert without_auth["url"] == with_auth["url"]
    assert without_auth["kwargs"]["json"] == with_auth["kwargs"]["json"]

    with_headers = with_auth["kwargs"].get("headers", {})
    without_headers = without_auth["kwargs"].get("headers", {})

    non_auth_with = {k: v for k, v in with_headers.items() if k.lower() != "authorization"}
    non_auth_without = {k: v for k, v in without_headers.items() if k.lower() != "authorization"}
    assert non_auth_without == non_auth_with, "non-auth headers must be identical"

    without_auth_val = next((v for k, v in without_headers.items() if k.lower() == "authorization"), None)
    with_auth_val = next((v for k, v in with_headers.items() if k.lower() == "authorization"), None)

    assert without_auth_val is None, "first request must not have Authorization"
    assert with_auth_val == "Bearer test-token", "second request must have the provided token"


# ── _preview truncation guard ──


class TestPreview:
    def test_truncates_at_300_chars(self) -> None:
        long = "x" * 500
        result = _preview(long)
        assert result == "x" * 300
        assert len(result) == 300

    def test_short_text_unchanged(self) -> None:
        result = _preview("hello")
        assert result == "hello"

    def test_none_returns_none(self) -> None:
        assert _preview(None) is None

    def test_empty_string_returns_none(self) -> None:
        assert _preview("") is None

    def test_exactly_300_unchanged(self) -> None:
        text = "a" * 300
        assert _preview(text) == text
