from __future__ import annotations

import json
import tempfile
from pathlib import Path

from gqlhunter.dashboard import DashboardHandler, INDEX_HTML


def _seed_db(db_path: Path) -> int:
    from gqlhunter.core.db import Database
    db = Database(db_path)
    db.initialize()
    run_id = db.create_scan_run("https://api.example.com/graphql")
    ep_id = db.upsert_endpoint("https://api.example.com/graphql", "enabled", run_id)
    db.insert_schema_type(ep_id, "User", "OBJECT", "User type", run_id)
    db.insert_schema_type(ep_id, "Query", "OBJECT", None, run_id)
    db.insert_operation(ep_id, "query", "users", '[{"name": "id", "type": "ID"}]', "[User]", None, run_id)
    db.finish_scan_run(run_id)
    db.close()
    return run_id


class TestDashboardApi:
    def test_get_runs(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "test.db"
            run_id = _seed_db(db_path)
            DashboardHandler.db_path = str(db_path)
            handler = DashboardHandler.__new__(DashboardHandler)
            runs = handler._get_runs()
            assert len(runs) == 1
            assert runs[0]["id"] == run_id
            assert runs[0]["endpoint"] == "https://api.example.com/graphql"
            assert "endpoint_count" in runs[0]
            assert "operation_count" in runs[0]
            assert "risk_count" in runs[0]

    def test_get_run_found(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "test.db"
            run_id = _seed_db(db_path)
            DashboardHandler.db_path = str(db_path)
            handler = DashboardHandler.__new__(DashboardHandler)
            run = handler._get_run(str(run_id))
            assert run is not None
            assert run["id"] == run_id

    def test_get_run_not_found(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "test.db"
            _seed_db(db_path)
            DashboardHandler.db_path = str(db_path)
            handler = DashboardHandler.__new__(DashboardHandler)
            run = handler._get_run("999")
            assert run is None

    def test_get_run_invalid_id(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "test.db"
            _seed_db(db_path)
            DashboardHandler.db_path = str(db_path)
            handler = DashboardHandler.__new__(DashboardHandler)
            run = handler._get_run("invalid")
            assert run is None

    def test_serve_json(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "test.db"
            _seed_db(db_path)
            DashboardHandler.db_path = str(db_path)
            handler = DashboardHandler.__new__(DashboardHandler)
            handler.requestline = "GET /api/runs HTTP/1.1"
            handler.command = "GET"
            handler.path = "/api/runs"
            handler.request_version = "HTTP/1.1"
            handler.client_address = ("127.0.0.1", 0)
            handler.wfile = __import__("io").BytesIO()
            handler._serve_json([{"id": 1, "endpoint": "https://example.com/graphql"}])
            handler.wfile.seek(0)
            raw = handler.wfile.read().decode()
            # HTTP headers until double CRLF, then body
            body = raw.split("\r\n\r\n", 1)[1]
            data = json.loads(body)
            assert len(data) > 0

    def test_index_html_contains_run_table(self) -> None:
        assert "runs" in INDEX_HTML
        assert "/api/runs" in INDEX_HTML
        assert "Run ID" in INDEX_HTML
