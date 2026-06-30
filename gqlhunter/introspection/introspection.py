from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any

from gqlhunter.core.http_client import HttpClient

INTROSPECTION_QUERY = """
query IntrospectionQuery {
  __schema {
    queryType { name }
    mutationType { name }
    subscriptionType { name }
    types {
      kind
      name
      description
      fields(includeDeprecated: true) {
        name
        description
        args {
          name
          type {
            ...TypeRef
          }
        }
        type {
          ...TypeRef
        }
        isDeprecated
        deprecationReason
      }
      inputFields {
        name
        type { ...TypeRef }
      }
      interfaces { name }
      enumValues(includeDeprecated: true) { name }
      possibleTypes { name }
    }
    directives {
      name
      locations
    }
  }
}

fragment TypeRef on __Type {
  kind
  name
  ofType {
    kind
    name
    ofType {
      kind
      name
      ofType {
        kind
        name
      }
    }
  }
}
"""


class IntrospectionStatus(Enum):
    ENABLED = "enabled"
    DISABLED = "disabled"
    FILTERED = "filtered"
    REQUIRES_AUTH = "requires_auth"
    BLOCKED = "blocked"
    NOT_GRAPHQL = "not_graphql"


@dataclass
class IntrospectionResult:
    status: IntrospectionStatus
    status_code: int
    data: dict[str, Any] | None = None
    error: str | None = None


def _build_introspection_query(max_depth: int = 4) -> str:
    lines = ["    kind", "    name"]
    for i in range(max_depth):
        indent = "  " * (2 + i)
        lines.append(f"{indent}ofType {{")
        lines.append(f"{indent}  kind")
        lines.append(f"{indent}  name")
    for i in range(max_depth - 1, -1, -1):
        indent = "  " * (2 + i)
        lines.append(f"{indent}}}")

    fragment_body = "\n".join(lines)

    return f"""\
query IntrospectionQuery {{
  __schema {{
    queryType {{ name }}
    mutationType {{ name }}
    subscriptionType {{ name }}
    types {{
      kind
      name
      description
      fields(includeDeprecated: true) {{
        name
        description
        args {{
          name
          type {{
            ...TypeRef
          }}
        }}
        type {{
          ...TypeRef
        }}
        isDeprecated
        deprecationReason
      }}
      inputFields {{
        name
        type {{ ...TypeRef }}
      }}
      interfaces {{ name }}
      enumValues(includeDeprecated: true) {{ name }}
      possibleTypes {{ name }}
    }}
    directives {{
      name
      locations
    }}
  }}
}}

fragment TypeRef on __Type {{
{fragment_body}
}}
"""


async def run_introspection(
    url: str, client: HttpClient, auth_header: str | None = None, max_depth: int = 4
) -> IntrospectionResult:
    headers = {}
    if auth_header:
        headers["Authorization"] = auth_header

    query = _build_introspection_query(max_depth)
    payload = {"query": query}

    try:
        if auth_header:
            resp = await client.post(url, json=payload, headers=headers)
        else:
            resp = await client.post(url, json=payload)
    except Exception as exc:
        return IntrospectionResult(
            status=IntrospectionStatus.BLOCKED,
            status_code=0,
            error=str(exc),
        )

    if resp.status_code in (401, 403):
        return IntrospectionResult(
            status=IntrospectionStatus.REQUIRES_AUTH,
            status_code=resp.status_code,
        )

    if resp.status_code != 200:
        return IntrospectionResult(
            status=IntrospectionStatus.BLOCKED,
            status_code=resp.status_code,
            error=f"HTTP {resp.status_code}",
        )

    try:
        body = resp.json()
    except Exception:
        return IntrospectionResult(
            status=IntrospectionStatus.NOT_GRAPHQL,
            status_code=resp.status_code,
        )

    if "errors" in body:
        error_msg = str(body["errors"])
        low = error_msg.lower()
        if "filtered" in low or "not authorised" in low or "not authorized" in low:
            return IntrospectionResult(
                status=IntrospectionStatus.FILTERED,
                status_code=resp.status_code,
                data=body,
                error=error_msg,
            )
        return IntrospectionResult(
            status=IntrospectionStatus.DISABLED,
            status_code=resp.status_code,
            data=body,
            error=error_msg,
        )

    schema = body.get("data", {}).get("__schema")
    if schema:
        return IntrospectionResult(
            status=IntrospectionStatus.ENABLED,
            status_code=resp.status_code,
            data=schema,
        )

    return IntrospectionResult(
        status=IntrospectionStatus.NOT_GRAPHQL,
        status_code=resp.status_code,
    )
