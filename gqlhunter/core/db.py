from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import Any

SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS scan_runs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    endpoint TEXT NOT NULL,
    started_at TEXT NOT NULL DEFAULT (datetime('now')),
    finished_at TEXT
);

CREATE TABLE IF NOT EXISTS endpoints (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    url TEXT NOT NULL UNIQUE,
    status TEXT NOT NULL DEFAULT 'pending',
    scan_run_id INTEGER REFERENCES scan_runs(id),
    discovered_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS schema_types (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    endpoint_id INTEGER REFERENCES endpoints(id),
    name TEXT NOT NULL,
    kind TEXT NOT NULL,
    description TEXT,
    scan_run_id INTEGER REFERENCES scan_runs(id)
);

CREATE TABLE IF NOT EXISTS operations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    endpoint_id INTEGER REFERENCES endpoints(id),
    type TEXT NOT NULL CHECK(type IN ('query','mutation','subscription')),
    name TEXT NOT NULL,
    args_json TEXT,
    return_type TEXT,
    description TEXT,
    scan_run_id INTEGER REFERENCES scan_runs(id)
);

CREATE TABLE IF NOT EXISTS risk_findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    operation_id INTEGER REFERENCES operations(id),
    operation_type TEXT NOT NULL,
    operation_name TEXT NOT NULL,
    severity TEXT NOT NULL CHECK(severity IN ('critical','high','medium','low','info')),
    category TEXT NOT NULL,
    detail TEXT,
    scan_run_id INTEGER REFERENCES scan_runs(id),
    UNIQUE(scan_run_id, operation_type, operation_name)
);

CREATE INDEX IF NOT EXISTS idx_endpoints_url ON endpoints(url);
CREATE INDEX IF NOT EXISTS idx_operations_type ON operations(type);
CREATE INDEX IF NOT EXISTS idx_risk_findings_severity ON risk_findings(severity);
CREATE TABLE IF NOT EXISTS auth_results (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_run_id INTEGER REFERENCES scan_runs(id),
    endpoint TEXT NOT NULL,
    classification TEXT NOT NULL
        CHECK(classification IN ('public','auth_required','over_permissive','blocked','error')),
    with_token_status INTEGER NOT NULL,
    without_token_status INTEGER NOT NULL,
    with_token_body_preview TEXT,
    without_token_body_preview TEXT,
    tested_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_auth_results_run ON auth_results(scan_run_id);
CREATE INDEX IF NOT EXISTS idx_auth_results_endpoint ON auth_results(endpoint);
"""


class Database:
    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self._conn: sqlite3.Connection | None = None

    def connect(self) -> sqlite3.Connection:
        if self._conn is None:
            self._conn = sqlite3.connect(str(self.path))
            self._conn.row_factory = sqlite3.Row
            self._conn.execute("PRAGMA journal_mode=WAL")
            self._conn.execute("PRAGMA foreign_keys=ON")
        return self._conn

    def initialize(self) -> None:
        conn = self.connect()
        conn.executescript(SCHEMA_SQL)
        conn.commit()

    def create_scan_run(self, endpoint: str) -> int:
        conn = self.connect()
        cur = conn.execute(
            "INSERT INTO scan_runs (endpoint) VALUES (?)", (endpoint,)
        )
        conn.commit()
        return cur.lastrowid

    def finish_scan_run(self, run_id: int) -> None:
        self.connect().execute(
            "UPDATE scan_runs SET finished_at = datetime('now') WHERE id = ?",
            (run_id,),
        )
        self.connect().commit()

    def upsert_endpoint(self, url: str, status: str, scan_run_id: int) -> int:
        conn = self.connect()
        existing = conn.execute(
            "SELECT id FROM endpoints WHERE url = ?", (url,)
        ).fetchone()
        if existing:
            conn.execute(
                "UPDATE endpoints SET status = ?, scan_run_id = ? WHERE id = ?",
                (status, scan_run_id, existing["id"]),
            )
            conn.commit()
            return existing["id"]
        cur = conn.execute(
            "INSERT INTO endpoints (url, status, scan_run_id) VALUES (?, ?, ?)",
            (url, status, scan_run_id),
        )
        conn.commit()
        return cur.lastrowid

    def insert_schema_type(
        self,
        endpoint_id: int,
        name: str,
        kind: str,
        description: str | None,
        scan_run_id: int,
    ) -> int:
        cur = self.connect().execute(
            "INSERT INTO schema_types "
            "(endpoint_id, name, kind, description, scan_run_id) "
            "VALUES (?, ?, ?, ?, ?)",
            (endpoint_id, name, kind, description, scan_run_id),
        )
        self.connect().commit()
        return cur.lastrowid

    def insert_operation(
        self,
        endpoint_id: int,
        op_type: str,
        name: str,
        args_json: str | None,
        return_type: str | None,
        description: str | None,
        scan_run_id: int,
    ) -> int:
        cur = self.connect().execute(
            "INSERT INTO operations "
            "(endpoint_id, type, name, args_json, return_type, description, scan_run_id) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (endpoint_id, op_type, name, args_json, return_type, description, scan_run_id),
        )
        self.connect().commit()
        return cur.lastrowid

    def insert_risk_finding(
        self,
        operation_id: int,
        operation_type: str,
        operation_name: str,
        severity: str,
        category: str,
        detail: str | None,
        scan_run_id: int,
    ) -> int:
        cur = self.connect().execute(
            "INSERT OR IGNORE INTO risk_findings "
            "(operation_id, operation_type, operation_name, severity, category, detail, scan_run_id) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (operation_id, operation_type, operation_name, severity, category, detail, scan_run_id),
        )
        self.connect().commit()
        return cur.lastrowid

    def get_endpoints(self, scan_run_id: int | None = None) -> list[dict[str, Any]]:
        if scan_run_id:
            rows = self.connect().execute(
                "SELECT * FROM endpoints WHERE scan_run_id = ?", (scan_run_id,)
            ).fetchall()
        else:
            rows = self.connect().execute("SELECT * FROM endpoints").fetchall()
        return [dict(r) for r in rows]

    def get_operations(
        self,
        endpoint_id: int | None = None,
        scan_run_id: int | None = None,
    ) -> list[dict[str, Any]]:
        query = "SELECT * FROM operations WHERE 1=1"
        params: list[Any] = []
        if endpoint_id is not None:
            query += " AND endpoint_id = ?"
            params.append(endpoint_id)
        if scan_run_id is not None:
            query += " AND scan_run_id = ?"
            params.append(scan_run_id)
        rows = self.connect().execute(query, params).fetchall()
        return [dict(r) for r in rows]

    def get_scan_runs_for_endpoint(self, endpoint: str) -> list[dict[str, Any]]:
        rows = self.connect().execute(
            "SELECT * FROM scan_runs WHERE endpoint = ? ORDER BY id ASC",
            (endpoint,),
        ).fetchall()
        return [dict(r) for r in rows]

    def insert_auth_result(
        self,
        scan_run_id: int,
        endpoint: str,
        classification: str,
        with_token_status: int,
        without_token_status: int,
        with_token_body_preview: str | None = None,
        without_token_body_preview: str | None = None,
    ) -> int:
        cur = self.connect().execute(
            "INSERT INTO auth_results "
            "(scan_run_id, endpoint, classification, with_token_status, "
            "without_token_status, with_token_body_preview, without_token_body_preview) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (scan_run_id, endpoint, classification, with_token_status,
             without_token_status, with_token_body_preview, without_token_body_preview),
        )
        self.connect().commit()
        return cur.lastrowid

    def get_auth_results(self, scan_run_id: int | None = None) -> list[dict[str, Any]]:
        if scan_run_id:
            rows = self.connect().execute(
                "SELECT * FROM auth_results WHERE scan_run_id = ?", (scan_run_id,)
            ).fetchall()
        else:
            rows = self.connect().execute("SELECT * FROM auth_results").fetchall()
        return [dict(r) for r in rows]

    def get_latest_scan_run(self) -> dict[str, Any] | None:
        row = self.connect().execute(
            "SELECT * FROM scan_runs ORDER BY id DESC LIMIT 1"
        ).fetchone()
        return dict(row) if row else None

    def close(self) -> None:
        if self._conn:
            self._conn.close()
            self._conn = None
