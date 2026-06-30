from __future__ import annotations

import json
from http.server import HTTPServer, BaseHTTPRequestHandler
from pathlib import Path
from typing import Any

from gqlhunter.core.db import Database
from gqlhunter.report.render import render_html


class DashboardHandler(BaseHTTPRequestHandler):
    db_path: str = ""

    def do_GET(self) -> None:
        if self.path == "/" or self.path == "/index.html":
            self._serve_dashboard()
        elif self.path == "/api/runs":
            self._serve_json(self._get_runs())
        elif self.path.startswith("/api/run/"):
            run_id = self.path.split("/")[-1]
            self._serve_json(self._get_run(run_id))
        elif self.path.startswith("/report/"):
            run_id = self.path.split("/")[-1]
            self._serve_report(run_id)
        elif self.path == "/favicon.ico":
            self.send_response(404)
            self.end_headers()
        else:
            self.send_response(404)
            self.end_headers()
            self.wfile.write(b"Not found")

    def _get_runs(self) -> list[dict[str, Any]]:
        db = Database(self.db_path)
        db.connect()
        db.initialize()
        conn = db.connect()
        rows = conn.execute(
            "SELECT id, endpoint, started_at, finished_at FROM scan_runs ORDER BY id DESC"
        ).fetchall()
        runs = [dict(r) for r in rows]
        for r in runs:
            ep_count = conn.execute(
                "SELECT COUNT(*) as c FROM endpoints WHERE scan_run_id = ?", (r["id"],)
            ).fetchone()["c"]
            op_count = conn.execute(
                "SELECT COUNT(*) as c FROM operations WHERE scan_run_id = ?", (r["id"],)
            ).fetchone()["c"]
            risk_count = conn.execute(
                "SELECT COUNT(*) as c FROM risk_findings WHERE scan_run_id = ?", (r["id"],)
            ).fetchone()["c"]
            r["endpoint_count"] = ep_count
            r["operation_count"] = op_count
            r["risk_count"] = risk_count
        db.close()
        return runs

    def _get_run(self, run_id: str) -> dict[str, Any] | None:
        db = Database(self.db_path)
        db.connect()
        db.initialize()
        conn = db.connect()
        try:
            rid = int(run_id)
        except ValueError:
            db.close()
            return None
        row = conn.execute("SELECT * FROM scan_runs WHERE id = ?", (rid,)).fetchone()
        db.close()
        return dict(row) if row else None

    def _serve_dashboard(self) -> None:
        html = INDEX_HTML
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(html)))
        self.end_headers()
        self.wfile.write(html.encode())

    def _serve_report(self, run_id: str) -> None:
        db = Database(self.db_path)
        db.connect()
        db.initialize()
        try:
            rid = int(run_id)
        except ValueError:
            self._serve_error("Invalid run ID")
            db.close()
            return
        run = db.get_latest_scan_run()
        if not run or run["id"] != rid:
            row = db.connect().execute(
                "SELECT * FROM scan_runs WHERE id = ?", (rid,)
            ).fetchone()
            run = dict(row) if row else None
        if not run:
            self._serve_error("Scan run not found")
            db.close()
            return
        endpoints = db.get_endpoints(scan_run_id=run["id"])
        operations = db.get_operations(scan_run_id=run["id"])
        conn = db.connect()
        types_rows = conn.execute(
            "SELECT DISTINCT name, kind FROM schema_types WHERE scan_run_id = ?", (run["id"],)
        ).fetchall()
        risk_rows = conn.execute(
            "SELECT severity, category, detail FROM risk_findings WHERE scan_run_id = ?", (run["id"],)
        ).fetchall()
        auth_results = db.get_auth_results(scan_run_id=run["id"])

        schema_summary: dict | None = None
        if operations:
            def _op_dict(o):
                return {"name": o["name"], "return_type": o["return_type"], "args": o["args_json"] or "\u2014"}
            queries = [_op_dict(o) for o in operations if o["type"] == "query"]
            mutations = [_op_dict(o) for o in operations if o["type"] == "mutation"]
            schema_summary = {
                "query_type": "Query",
                "mutation_type": "Mutation" if mutations else None,
                "subscription_type": None,
                "total_types": len(types_rows),
                "queries": queries,
                "mutations": mutations,
            }

        findings = [dict(r) for r in risk_rows]
        date_str = run["started_at"]
        html = render_html(
            run["endpoint"], run["id"], date_str, endpoints,
            schema_summary, findings, auth_results,
        )
        db.close()
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(html)))
        self.end_headers()
        self.wfile.write(html.encode())

    def _serve_json(self, data: Any) -> None:
        text = json.dumps(data, indent=2, default=str)
        self.send_response(200)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(text)))
        self.end_headers()
        self.wfile.write(text.encode())

    def _serve_error(self, msg: str) -> None:
        self.send_response(404)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.end_headers()
        self.wfile.write(msg.encode())

    def log_message(self, format: str, *args: Any) -> None:
        from gqlhunter.cli import console
        console.print(f"  [dim]{args[0]} - {args[1]} {args[2]}[/]")


INDEX_HTML = """\
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>gqlhunter Dashboard</title>
<style>
  body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; margin: 0; padding: 20px; background: #f8f9fa; color: #212529; }
  .container { max-width: 960px; margin: 0 auto; }
  h1 { color: #212529; }
  table { width: 100%; border-collapse: collapse; margin: 16px 0; background: #fff; border-radius: 8px; box-shadow: 0 1px 3px rgba(0,0,0,.1); }
  th, td { padding: 8px 12px; text-align: left; border-bottom: 1px solid #dee2e6; }
  th { background: #e9ecef; font-weight: 600; }
  tr:hover { background: #f1f3f5; }
  a { color: #0d6efd; text-decoration: none; }
  a:hover { text-decoration: underline; }
  .badge { display: inline-block; padding: 2px 8px; border-radius: 4px; color: #fff; font-size: .75em; font-weight: 700; }
  .empty { color: #6c757d; font-style: italic; }
  .footer { margin-top: 32px; padding-top: 16px; border-top: 1px solid #dee2e6; font-size: .75em; color: #6c757d; }
</style>
</head>
<body>
<div class="container">
<h1>gqlhunter Dashboard</h1>
<p>Scan runs overview. Click a run ID to view the full report.</p>
<table>
  <thead><tr><th>Run ID</th><th>Endpoint</th><th>Started</th><th>Finished</th><th>Endpoints</th><th>Ops</th><th>Risks</th></tr></thead>
  <tbody id="runs"></tbody>
</table>
<div class="footer">gqlhunter dashboard</div>
</div>
<script>
fetch('/api/runs').then(function(r) { return r.json(); }).then(function(runs) {
  var tbody = document.getElementById('runs');
  runs.forEach(function(run) {
    var tr = document.createElement('tr');
    tr.innerHTML = '<td><a href="/report/' + run.id + '">#' + run.id + '</a></td>' +
      '<td><code>' + run.endpoint + '</code></td>' +
      '<td>' + run.started_at + '</td>' +
      '<td>' + (run.finished_at || '—') + '</td>' +
      '<td>' + run.endpoint_count + '</td>' +
      '<td>' + run.operation_count + '</td>' +
      '<td>' + (run.risk_count > 0 ? '<span class="badge" style="background:#dc3545">' + run.risk_count + '</span>' : '0') + '</td>';
    tbody.appendChild(tr);
  });
});
</script>
</body>
</html>"""


def create_dashboard_server(db_path: str, host: str = "127.0.0.1", port: int = 8080) -> HTTPServer:
    """Create and return a configured HTTPServer for the dashboard."""
    DashboardHandler.db_path = db_path
    return HTTPServer((host, port), DashboardHandler)


def run_dashboard(db_path: str, host: str = "127.0.0.1", port: int = 8080) -> None:
    from gqlhunter.cli import console
    console.print(f"[bold green]Dashboard started[/] at [cyan]http://{host}:{port}[/]")
    if host == "127.0.0.1":
        console.print("  [dim]Only accessible from localhost. Use --host 0.0.0.0 for network access.[/]")
    server = create_dashboard_server(db_path, host, port)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        console.print("\n[yellow]Shutting down dashboard...[/]")
        server.server_close()
