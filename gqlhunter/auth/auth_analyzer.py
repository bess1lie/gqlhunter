from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any

from gqlhunter.core.http_client import HttpClient


class AuthClassification(Enum):
    PUBLIC = "public"
    AUTH_REQUIRED = "auth_required"
    OVER_PERMISSIVE = "over_permissive"
    BLOCKED = "blocked"
    ERROR = "error"


@dataclass
class AuthResult:
    endpoint: str
    with_token_status: int
    without_token_status: int
    with_token_body_preview: str | None
    without_token_body_preview: str | None
    classification: AuthClassification
    with_token_headers: dict[str, str] | None = None
    without_token_request_payload: dict[str, Any] | None = None
    with_token_request_payload: dict[str, Any] | None = None


async def analyze_auth(
    endpoint: str,
    auth_header: str,
    client: HttpClient,
    query_payload: dict[str, Any] | None = None,
) -> AuthResult:
    if query_payload is None:
        query_payload = {"query": "{ __typename }"}

    try:
        without_resp = await client.post(endpoint, json=query_payload)
    except Exception as exc:
        return AuthResult(
            endpoint=endpoint,
            with_token_status=0,
            without_token_status=0,
            with_token_body_preview=None,
            without_token_body_preview=str(exc),
            classification=AuthClassification.ERROR,
        )

    try:
        with_resp = await client.post(
            endpoint, json=query_payload, headers={"Authorization": auth_header}
        )
    except Exception as exc:
        return AuthResult(
            endpoint=endpoint,
            with_token_status=0,
            without_token_status=without_resp.status_code,
            with_token_body_preview=str(exc),
            without_token_body_preview=_preview(without_resp.text),
            classification=AuthClassification.ERROR,
        )

    w_token_body = _preview(with_resp.text)
    wo_token_body = _preview(without_resp.text)

    if without_resp.status_code == 200:
        if with_resp.status_code == 200:
            if w_token_body == wo_token_body:
                classification = AuthClassification.OVER_PERMISSIVE
            else:
                classification = AuthClassification.PUBLIC
        else:
            classification = AuthClassification.PUBLIC
    elif without_resp.status_code in (401, 403):
        classification = AuthClassification.AUTH_REQUIRED
    else:
        classification = AuthClassification.BLOCKED

    return AuthResult(
        endpoint=endpoint,
        with_token_status=with_resp.status_code,
        without_token_status=without_resp.status_code,
        with_token_body_preview=w_token_body,
        without_token_body_preview=wo_token_body,
        classification=classification,
        with_token_request_payload=query_payload,
        without_token_request_payload=query_payload,
    )


def _preview(text: str | None) -> str | None:
    if not text:
        return None
    return text[:300]
