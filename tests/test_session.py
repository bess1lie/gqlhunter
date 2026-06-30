from __future__ import annotations

import json
import tempfile
from pathlib import Path

from gqlhunter.auth.session import (
    SessionError,
    load_session,
    resolve_auth_header,
    save_session,
)


class TestSaveSession:
    def test_creates_json_file(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "session.json"
            save_session(path, "Bearer test-token", endpoint="https://example.com/graphql")
            data = json.loads(path.read_text())
            assert data["auth_header"] == "Bearer test-token"
            assert data["endpoint"] == "https://example.com/graphql"
            assert "created_at" in data

    def test_without_endpoint(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "session.json"
            save_session(path, "Bearer test-token")
            data = json.loads(path.read_text())
            assert data["auth_header"] == "Bearer test-token"
            assert "endpoint" not in data

    def test_overwrites_existing(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "session.json"
            save_session(path, "old-token", endpoint="https://old.example.com/graphql")
            save_session(path, "new-token", endpoint="https://new.example.com/graphql")
            data = json.loads(path.read_text())
            assert data["auth_header"] == "new-token"
            assert data["endpoint"] == "https://new.example.com/graphql"


class TestLoadSession:
    def test_loads_valid_file(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "session.json"
            path.write_text(json.dumps({"auth_header": "Bearer test-token", "created_at": "2026-01-01T00:00:00"}))
            data = load_session(path)
            assert data["auth_header"] == "Bearer test-token"

    def test_missing_file_raises_error(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "nonexistent.json"
            try:
                load_session(path)
                assert False, "expected SessionError"
            except SessionError:
                pass

    def test_missing_auth_header_key_raises_error(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "session.json"
            path.write_text(json.dumps({"created_at": "2026-01-01T00:00:00"}))
            try:
                load_session(path)
                assert False, "expected SessionError"
            except SessionError:
                pass

    def test_invalid_json_raises_error(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "session.json"
            path.write_text("not json")
            try:
                load_session(path)
                assert False, "expected SessionError"
            except SessionError:
                pass


class TestResolveAuthHeader:
    def test_returns_auth_header_when_given(self) -> None:
        result = resolve_auth_header("Bearer foo", None)
        assert result == "Bearer foo"

    def test_loads_from_session_when_no_direct_header(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "session.json"
            path.write_text(json.dumps({"auth_header": "Bearer session-token"}))
            result = resolve_auth_header(None, str(path))
            assert result == "Bearer session-token"

    def test_direct_header_takes_priority_over_session(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "session.json"
            path.write_text(json.dumps({"auth_header": "Bearer session-token"}))
            result = resolve_auth_header("Bearer direct", str(path))
            assert result == "Bearer direct"

    def test_returns_none_when_neither_provided(self) -> None:
        result = resolve_auth_header(None, None)
        assert result is None
