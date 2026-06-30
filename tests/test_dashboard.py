from __future__ import annotations

import json
import threading
import time
from http.server import HTTPServer
from pathlib import Path
from urllib.request import urlopen

from gqlhunter.dashboard import DashboardHandler


def _seed_db(db_path: Path) -> None:
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


def _serve_in_thread(server: HTTPServer) -> threading.Thread:
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    time.sleep(0.3)
    return t


class TestDashboardCli:
    def test_dashboard_api_runs(self) -> None:
        db_path = Path("/tmp") / "test_dash_runs.db"
        db_path.unlink(missing_ok=True)
        _seed_db(db_path)

        DashboardHandler.db_path = str(db_path)
        server = HTTPServer(("127.0.0.1", 8091), DashboardHandler)
        _serve_in_thread(server)

        resp = urlopen("http://127.0.0.1:8091/api/runs")
        assert resp.status == 200
        data = json.loads(resp.read().decode())
        assert len(data) == 1
        assert data[0]["endpoint"] == "https://api.example.com/graphql"

        server.shutdown()
        db_path.unlink(missing_ok=True)

    def test_dashboard_index_html(self) -> None:
        db_path = Path("/tmp") / "test_dash_html.db"
        db_path.unlink(missing_ok=True)
        _seed_db(db_path)

        DashboardHandler.db_path = str(db_path)
        server = HTTPServer(("127.0.0.1", 8092), DashboardHandler)
        _serve_in_thread(server)

        resp = urlopen("http://127.0.0.1:8092/")
        assert resp.status == 200
        html = resp.read().decode()
        assert "gqlhunter Dashboard" in html
        assert "Run ID" in html

        server.shutdown()
        db_path.unlink(missing_ok=True)
