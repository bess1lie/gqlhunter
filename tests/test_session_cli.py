from __future__ import annotations

import json
import tempfile
from pathlib import Path
from unittest.mock import AsyncMock, patch

import httpx
from typer.testing import CliRunner

from gqlhunter.cli import app

RUNNER = CliRunner()


def _scope_yaml(path: Path) -> None:
    path.write_text("targets:\n  - example.com\n")


def _empty_db(path: Path) -> None:
    from gqlhunter.core.db import Database
    db = Database(path)
    db.initialize()
    db.close()


class TestAuthSessionCli:
    def test_save_session_creates_file(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            scope = tmp_path / "scope.yaml"
            db = tmp_path / "test.db"
            session_out = tmp_path / "session.json"
            _scope_yaml(scope)
            _empty_db(db)

            mock_responses = [
                httpx.Response(401, text='{"error": "unauthorized"}'),
                httpx.Response(200, text='{"data": {"__typename": "Query"}}'),
            ]

            with patch("gqlhunter.core.http_client.HttpClient.request", new=AsyncMock(side_effect=mock_responses)):
                result = RUNNER.invoke(app, [
                    "auth", "https://example.com/graphql",
                    "--scope", str(scope),
                    "--auth-header", "Bearer test-token",
                    "--db", str(db),
                    "--save-session", str(session_out),
                ])

            assert result.exit_code == 0, result.output
            assert session_out.exists(), f"files: {list(tmp_path.iterdir())}"
            data = json.loads(session_out.read_text())
            assert data["auth_header"] == "Bearer test-token"
            assert data["endpoint"] == "https://example.com/graphql"

    def test_session_loads_from_file(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            scope = tmp_path / "scope.yaml"
            db = tmp_path / "test.db"
            session_in = tmp_path / "session.json"
            _scope_yaml(scope)
            _empty_db(db)
            session_in.write_text(json.dumps({"auth_header": "Bearer session-token"}))

            mock_responses = [
                httpx.Response(401, text='{"error": "unauthorized"}'),
                httpx.Response(200, text='{"data": {"__typename": "Query"}}'),
            ]

            with patch("gqlhunter.core.http_client.HttpClient.request", new=AsyncMock(side_effect=mock_responses)):
                result = RUNNER.invoke(app, [
                    "auth", "https://example.com/graphql",
                    "--scope", str(scope),
                    "--session", str(session_in),
                    "--db", str(db),
                ])

            assert result.exit_code == 0, result.output

    def test_requires_auth_header_or_session(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            scope = tmp_path / "scope.yaml"
            db = tmp_path / "test.db"
            _scope_yaml(scope)
            _empty_db(db)

            result = RUNNER.invoke(app, [
                "auth", "https://example.com/graphql",
                "--scope", str(scope),
                "--db", str(db),
            ])

            assert result.exit_code != 0

    def test_session_errors_on_invalid_file(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            scope = tmp_path / "scope.yaml"
            db = tmp_path / "test.db"
            session_in = tmp_path / "session.json"
            _scope_yaml(scope)
            _empty_db(db)
            session_in.write_text("not json")

            result = RUNNER.invoke(app, [
                "auth", "https://example.com/graphql",
                "--scope", str(scope),
                "--session", str(session_in),
                "--db", str(db),
            ])

            assert result.exit_code != 0

    def test_save_session_without_session_path_does_not_create_file(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            scope = tmp_path / "scope.yaml"
            db = tmp_path / "test.db"
            _scope_yaml(scope)
            _empty_db(db)

            mock_responses = [
                httpx.Response(401, text='{"error": "unauthorized"}'),
                httpx.Response(200, text='{"data": {"__typename": "Query"}}'),
            ]

            with patch("gqlhunter.core.http_client.HttpClient.request", new=AsyncMock(side_effect=mock_responses)):
                result = RUNNER.invoke(app, [
                    "auth", "https://example.com/graphql",
                    "--scope", str(scope),
                    "--auth-header", "Bearer test-token",
                    "--db", str(db),
                ])

            assert result.exit_code == 0, result.output
            session_files = list(tmp_path.glob("*.json"))
            assert len(session_files) == 0


class TestScanSessionCli:
    def test_scan_with_session_file(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            scope = tmp_path / "scope.yaml"
            session_in = tmp_path / "session.json"
            _scope_yaml(scope)
            session_in.write_text(json.dumps({"auth_header": "Bearer session-token"}))

            mock_response = httpx.Response(200, text='{"data": {"__typename": "Query"}}')

            with patch("gqlhunter.core.http_client.HttpClient.request", new=AsyncMock(return_value=mock_response)):
                result = RUNNER.invoke(app, [
                    "scan", "https://example.com/graphql",
                    "--scope", str(scope),
                    "--session", str(session_in),
                ])

            assert result.exit_code == 0, result.output

    def test_scan_save_session(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            scope = tmp_path / "scope.yaml"
            session_out = tmp_path / "session.json"
            _scope_yaml(scope)

            mock_response = httpx.Response(200, text='{"data": {"__typename": "Query"}}')

            with patch("gqlhunter.core.http_client.HttpClient.request", new=AsyncMock(return_value=mock_response)):
                result = RUNNER.invoke(app, [
                    "scan", "https://example.com/graphql",
                    "--scope", str(scope),
                    "--auth-header", "Bearer scan-token",
                    "--save-session", str(session_out),
                ])

            assert result.exit_code == 0, result.output
            assert session_out.exists()
            data = json.loads(session_out.read_text())
            assert data["auth_header"] == "Bearer scan-token"
