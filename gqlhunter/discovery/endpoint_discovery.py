from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import urlparse

from gqlhunter.core.http_client import HttpClient
from gqlhunter.core.scope import Scope

COMMON_PATHS = [
    "/graphql",
    "/api/graphql",
    "/gql",
    "/graphql/v1",
    "/graphql-api",
    "/query",
    "/v1/graphql",
    "/v2/graphql",
    "/v3/graphql",
    "/api/v1/graphql",
    "/api/v2/graphql",
    "/api/query",
    "/explorer",
    "/graphiql",
    "/graphql/explorer",
    "/graphql/graphiql",
    "/playground",
    "/graphql/playground",
]


@dataclass
class DiscoveredEndpoint:
    url: str
    status_code: int
    content_type: str | None
    response_preview: str | None


async def discover_endpoints(
    target: str,
    scope: Scope,
    client: HttpClient,
    extra_paths: list[str] | None = None,
) -> list[DiscoveredEndpoint]:
    parsed = urlparse(target)
    base = f"{parsed.scheme}://{parsed.netloc}"

    if not scope.is_in_scope(base):
        return []

    paths = COMMON_PATHS + (extra_paths or [])
    results: list[DiscoveredEndpoint] = []

    for path in paths:
        url = f"{base}{path}"
        if not scope.is_in_scope(url):
            continue

        try:
            resp = await client.get(url)
        except Exception:
            continue

        preview = None
        if resp.text:
            preview = resp.text[:200]

        results.append(
            DiscoveredEndpoint(
                url=url,
                status_code=resp.status_code,
                content_type=resp.headers.get("content-type"),
                response_preview=preview,
            )
        )

    return results
