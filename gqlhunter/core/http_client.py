from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from typing import Any

import httpx


@dataclass
class HttpClient:
    timeout: float = 10.0
    max_retries: int = 2
    rate_per_second: float = 10.0
    headers: dict[str, str] = field(default_factory=lambda: {"User-Agent": "gqlhunter/0.1.0"})
    _client: httpx.AsyncClient | None = field(default=None, repr=False)
    _sem: asyncio.Semaphore | None = field(default=None, repr=False)
    _last_request: float = field(default=0.0, repr=False)

    def __post_init__(self) -> None:
        limits = httpx.Limits(max_keepalive_connections=5, max_connections=20)
        self._client = httpx.AsyncClient(
            timeout=httpx.Timeout(self.timeout),
            limits=limits,
            follow_redirects=True,
        )
        self._sem = asyncio.Semaphore(int(self.rate_per_second))

    async def request(
        self,
        method: str,
        url: str,
        **kwargs: Any,
    ) -> httpx.Response:
        if self._client is None:
            raise RuntimeError("HttpClient is closed")

        merged_headers = dict(self.headers)
        extra_headers = kwargs.pop("headers", None)
        if extra_headers:
            merged_headers.update(extra_headers)

        async with self._sem:
            await self._rate_limit()
            last_exc: Exception | None = None

            for attempt in range(1 + self.max_retries):
                try:
                    resp = await self._client.request(method, url, headers=merged_headers, **kwargs)
                    return resp
                except (httpx.TimeoutException, httpx.ConnectError) as exc:
                    last_exc = exc
                    if attempt < self.max_retries:
                        wait = 2 ** attempt
                        await asyncio.sleep(wait)
                    continue

            msg = f"Request to {url} failed after {self.max_retries} retries"
            raise RuntimeError(msg) from last_exc

    async def get(self, url: str, **kwargs: Any) -> httpx.Response:
        return await self.request("GET", url, **kwargs)

    async def post(
        self, url: str, json: dict[str, Any] | None = None, **kwargs: Any
    ) -> httpx.Response:
        return await self.request("POST", url, json=json, **kwargs)

    async def _rate_limit(self) -> None:
        import time

        now = time.monotonic()
        elapsed = now - self._last_request
        min_interval = 1.0 / self.rate_per_second
        if elapsed < min_interval:
            await asyncio.sleep(min_interval - elapsed)
        self._last_request = time.monotonic()

    async def close(self) -> None:
        if self._client:
            await self._client.aclose()
            self._client = None

    async def __aenter__(self) -> HttpClient:
        return self

    async def __aexit__(self, *args: Any) -> None:
        await self.close()
