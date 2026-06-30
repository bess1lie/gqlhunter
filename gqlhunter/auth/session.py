from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path


class SessionError(Exception):
    pass


def save_session(path: str | Path, auth_header: str, endpoint: str | None = None) -> None:
    data = {
        "auth_header": auth_header,
        "created_at": datetime.now(timezone.utc).isoformat(),
    }
    if endpoint:
        data["endpoint"] = endpoint
    Path(path).write_text(json.dumps(data, indent=2))


def load_session(path: str | Path) -> dict:
    try:
        data = json.loads(Path(path).read_text())
    except (FileNotFoundError, json.JSONDecodeError) as exc:
        raise SessionError(f"Invalid session file: {path}") from exc
    if "auth_header" not in data:
        raise SessionError(f"Session file missing 'auth_header': {path}")
    return data


def resolve_auth_header(
    auth_header: str | None,
    session_path: str | None,
) -> str | None:
    if auth_header is not None:
        return auth_header
    if session_path is not None:
        data = load_session(session_path)
        return data["auth_header"]
    return None
