from __future__ import annotations

import json
import tempfile
from pathlib import Path
from unittest.mock import patch

import httpx
import pytest
from typer.testing import CliRunner

from gqlhunter.cli import app
from gqlhunter.notify.sender import (
    render_notification,
    send_slack,
    send_telegram,
    send_webhook,
)

RUNNER = CliRunner()


def _response(status: int, json_data: dict | None = None) -> httpx.Response:
    r = httpx.Response(status, request=httpx.Request("POST", "http://example.com"))
    if json_data is not None:
        r._content = json.dumps(json_data).encode()
        r.headers["content-type"] = "application/json"
    return r


class TestRenderNotification:
    def test_renders_slack_template(self) -> None:
        context = {
            "endpoint": "https://api.example.com/graphql",
            "run_id": 1,
            "date": "2026-01-01",
            "endpoints": [{"url": "https://api.example.com/graphql"}],
            "operations": [{"name": "users"}],
            "schema_types": [{"name": "User"}],
            "auth_results": [],
            "risk_findings": [],
        }
        result = render_notification("slack", context)
        assert "api.example.com" in result
        assert "1 endpoint(s)" in result
        assert "1 operation(s)" in result

    def test_renders_telegram_template(self) -> None:
        context = {
            "endpoint": "https://api.example.com/graphql",
            "run_id": 1,
            "date": "2026-01-01",
            "endpoints": [],
            "operations": [],
            "schema_types": [],
            "auth_results": [],
            "risk_findings": [],
        }
        result = render_notification("telegram", context)
        assert "api.example.com" in result

    def test_renders_webhook_template(self) -> None:
        context = {
            "endpoint": "https://api.example.com/graphql",
            "run_id": 1,
            "date": "2026-01-01",
            "endpoints": [],
            "operations": [],
            "schema_types": [],
            "auth_results": [],
            "risk_findings": [],
        }
        result = render_notification("webhook", context)
        data = json.loads(result)
        assert data["event"] == "gqlhunter_scan"
        assert data["endpoint"] == "https://api.example.com/graphql"

    def test_custom_template_dir(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            tmpl = tmp_path / "custom.jinja"
            tmpl.write_text("custom: {{ endpoint }}")
            context = {"endpoint": "https://example.com/graphql"}
            result = render_notification("custom", context, template_dir=str(tmp_path))
            assert result == "custom: https://example.com/graphql"


class TestSendSlack:
    def test_sends_post_request(self) -> None:
        with patch("httpx.post") as mock_post:
            mock_post.return_value = _response(200)
            send_slack("https://hooks.slack.com/foo", "Hello")
            mock_post.assert_called_once_with(
                "https://hooks.slack.com/foo",
                json={"text": "Hello"},
                timeout=10.0,
            )

    def test_raises_on_error(self) -> None:
        with patch("httpx.post") as mock_post:
            mock_post.return_value = _response(400)
            with pytest.raises(httpx.HTTPStatusError):
                send_slack("https://hooks.slack.com/foo", "Hello")


class TestSendTelegram:
    def test_sends_post_request(self) -> None:
        with patch("httpx.post") as mock_post:
            mock_post.return_value = _response(200, {"ok": True})
            send_telegram("token123", "chat456", "Hello")
            mock_post.assert_called_once_with(
                "https://api.telegram.org/bottoken123/sendMessage",
                json={"chat_id": "chat456", "text": "Hello"},
                timeout=10.0,
            )

    def test_raises_on_api_error(self) -> None:
        with patch("httpx.post") as mock_post:
            mock_post.return_value = _response(200, {"ok": False})
            with pytest.raises(RuntimeError, match="Telegram API error"):
                send_telegram("token", "chat", "Hello")


class TestSendWebhook:
    def test_sends_post_request(self) -> None:
        with patch("httpx.post") as mock_post:
            mock_post.return_value = _response(200)
            send_webhook("https://hook.example.com", {"key": "value"})
            mock_post.assert_called_once_with(
                "https://hook.example.com",
                json={"key": "value"},
                timeout=10.0,
            )


def _seed_db(db_path: Path) -> int:
    from gqlhunter.core.db import Database
    db = Database(db_path)
    db.initialize()
    run_id = db.create_scan_run("https://api.example.com/graphql")
    ep_id = db.upsert_endpoint("https://api.example.com/graphql", "enabled", run_id)
    db.insert_schema_type(ep_id, "User", "OBJECT", "User type", run_id)
    db.insert_operation(ep_id, "query", "users", '[{"name": "id", "type": "ID"}]', "[User]", None, run_id)
    db.finish_scan_run(run_id)
    db.close()
    return run_id


class TestNotifyCli:
    def test_notify_slack(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "test.db"
            _seed_db(db_path)
            with patch("httpx.post") as mock_post:
                mock_post.return_value = _response(200)
                result = RUNNER.invoke(app, [
                    "notify", "slack",
                    "--db", str(db_path),
                    "--webhook-url", "https://hooks.slack.com/foo",
                ])
            assert result.exit_code == 0, result.output

    def test_notify_slack_missing_webhook(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "test.db"
            _seed_db(db_path)
            result = RUNNER.invoke(app, [
                "notify", "slack",
                "--db", str(db_path),
            ])
            assert result.exit_code != 0

    def test_notify_telegram(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "test.db"
            _seed_db(db_path)
            with patch("httpx.post") as mock_post:
                mock_post.return_value = _response(200, {"ok": True})
                result = RUNNER.invoke(app, [
                    "notify", "telegram",
                    "--db", str(db_path),
                    "--telegram-token", "token",
                    "--telegram-chat", "chat",
                ])
            assert result.exit_code == 0, result.output

    def test_notify_telegram_missing_args(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "test.db"
            _seed_db(db_path)
            result = RUNNER.invoke(app, [
                "notify", "telegram",
                "--db", str(db_path),
            ])
            assert result.exit_code != 0

    def test_notify_webhook(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "test.db"
            _seed_db(db_path)
            with patch("httpx.post") as mock_post:
                mock_post.return_value = _response(200)
                result = RUNNER.invoke(app, [
                    "notify", "webhook",
                    "--db", str(db_path),
                    "--webhook-url", "https://hook.example.com",
                ])
            assert result.exit_code == 0, result.output

    def test_notify_invalid_channel(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "test.db"
            _seed_db(db_path)
            result = RUNNER.invoke(app, [
                "notify", "invalid",
                "--db", str(db_path),
            ])
            assert result.exit_code != 0

    def test_notify_custom_template(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "test.db"
            tmpl_dir = Path(tmp) / "templates"
            tmpl_dir.mkdir()
            tmpl_dir.joinpath("slack.jinja").write_text("custom: {{ endpoint }}")
            _seed_db(db_path)
            with patch("httpx.post") as mock_post:
                mock_post.return_value = _response(200)
                result = RUNNER.invoke(app, [
                    "notify", "slack",
                    "--db", str(db_path),
                    "--webhook-url", "https://hooks.slack.com/foo",
                    "--template-dir", str(tmpl_dir),
                ])
            assert result.exit_code == 0, result.output

    def test_notify_no_db_errors(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "empty.db"
            from gqlhunter.core.db import Database
            db = Database(db_path)
            db.initialize()
            db.close()
            result = RUNNER.invoke(app, [
                "notify", "slack",
                "--db", str(db_path),
                "--webhook-url", "https://hooks.slack.com/foo",
            ])
            assert result.exit_code != 0
            assert "No scan runs" in result.output


# ── GUARDRAIL: default templates use autoescape ──


class TestTemplateAutoescape:
    def test_slack_template_escapes_html(self) -> None:
        context = {
            "endpoint": "<script>alert(1)</script>",
            "run_id": 1,
            "date": "2026-01-01",
            "endpoints": [],
            "operations": [],
            "schema_types": [],
            "auth_results": [],
            "risk_findings": [],
        }
        result = render_notification("slack", context)
        assert "<script>" not in result

    def test_telegram_template_escapes_html(self) -> None:
        context = {
            "endpoint": "<script>alert(1)</script>",
            "run_id": 1,
            "date": "2026-01-01",
            "endpoints": [],
            "operations": [],
            "schema_types": [],
            "auth_results": [],
            "risk_findings": [],
        }
        result = render_notification("telegram", context)
        assert "<script>" not in result

    def test_webhook_template_escapes_html_in_strings(self) -> None:
        context = {
            "endpoint": '<script>alert(1)</script>',
            "run_id": 1,
            "date": "2026-01-01",
            "endpoints": [],
            "operations": [],
            "schema_types": [],
            "auth_results": [],
            "risk_findings": [],
        }
        result = render_notification("webhook", context)
        assert "<script>" not in result
