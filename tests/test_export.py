import json
import tempfile
from pathlib import Path

from typer.testing import CliRunner

from gqlhunter.cli import _collect_export_data, app
from gqlhunter.core.db import Database

RUNNER = CliRunner()


def _seed_db(db_path: Path) -> tuple[Database, int]:
    db = Database(db_path)
    db.initialize()
    run_id = db.create_scan_run("https://api.example.com/graphql")
    ep_id = db.upsert_endpoint("https://api.example.com/graphql", "enabled", run_id)
    db.insert_schema_type(ep_id, "User", "OBJECT", "User type", run_id)
    db.insert_schema_type(ep_id, "Query", "OBJECT", None, run_id)
    db.insert_operation(
        ep_id, "query", "users",
        '[{"name": "id", "type": "ID"}]', "[User]", "List users", run_id,
    )
    db.insert_operation(ep_id, "query", "me", None, "User", "Current user", run_id)
    db.insert_operation(
        ep_id, "mutation", "updateUser",
        '[{"name": "id", "type": "ID"}, {"name": "email", "type": "String"}]',
        "Boolean", None, run_id,
    )
    db.finish_scan_run(run_id)
    return db, run_id


def _run_dict(db: Database, run_id: int) -> dict:
    return dict(db.connect().execute(
        "SELECT * FROM scan_runs WHERE id = ?", (run_id,)
    ).fetchone())


class TestCollectExportData:
    def test_contains_all_sections(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "test.db"
            db, run_id = _seed_db(db_path)
            run = _run_dict(db, run_id)
            data = _collect_export_data(db, run)
            assert set(data.keys()) == {"run", "endpoints", "operations", "schema_types", "auth_results", "risk_findings"}
            db.close()

    def test_run_metadata(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "test.db"
            db, run_id = _seed_db(db_path)
            run = _run_dict(db, run_id)
            data = _collect_export_data(db, run)
            assert data["run"]["endpoint"] == "https://api.example.com/graphql"
            assert "started_at" in data["run"]
            db.close()

    def test_endpoints(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "test.db"
            db, run_id = _seed_db(db_path)
            run = _run_dict(db, run_id)
            data = _collect_export_data(db, run)
            assert len(data["endpoints"]) == 1
            assert data["endpoints"][0]["url"] == "https://api.example.com/graphql"
            assert data["endpoints"][0]["status"] == "enabled"
            db.close()

    def test_operations(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "test.db"
            db, run_id = _seed_db(db_path)
            run = _run_dict(db, run_id)
            data = _collect_export_data(db, run)
            ops = data["operations"]
            assert len(ops) == 3
            names = {o["name"] for o in ops}
            assert names == {"users", "me", "updateUser"}
            db.close()

    def test_schema_types(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "test.db"
            db, run_id = _seed_db(db_path)
            run = _run_dict(db, run_id)
            data = _collect_export_data(db, run)
            types = data["schema_types"]
            assert len(types) == 2
            names = {t["name"] for t in types}
            assert names == {"User", "Query"}
            db.close()

    def test_operations_include_args_json_and_return_type(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "test.db"
            db, run_id = _seed_db(db_path)
            run = _run_dict(db, run_id)
            data = _collect_export_data(db, run)
            users_op = next(o for o in data["operations"] if o["name"] == "users")
            assert users_op["args_json"] == '[{"name": "id", "type": "ID"}]'
            assert users_op["return_type"] == "[User]"
            db.close()


class TestExportCommand:
    def test_creates_json_files(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "test.db"
            db, _ = _seed_db(db_path)
            db.close()
            output_dir = Path(tmp) / "out"
            result = RUNNER.invoke(
                app, ["export", "--db", str(db_path), "--output", str(output_dir)]
            )
            assert result.exit_code == 0
            assert output_dir.joinpath("endpoints.json").exists()
            assert output_dir.joinpath("operations.json").exists()
            assert output_dir.joinpath("run.json").exists()
            assert output_dir.joinpath("schema_types.json").exists()
            assert output_dir.joinpath("auth_results.json").exists()
            assert output_dir.joinpath("risk_findings.json").exists()

    def test_exported_json_is_valid(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "test.db"
            db, _ = _seed_db(db_path)
            db.close()
            output_dir = Path(tmp) / "out"
            RUNNER.invoke(
                app, ["export", "--db", str(db_path), "--output", str(output_dir)]
            )
            run = json.loads(output_dir.joinpath("run.json").read_text())
            assert run["endpoint"] == "https://api.example.com/graphql"
            endpoints = json.loads(
                output_dir.joinpath("endpoints.json").read_text()
            )
            assert isinstance(endpoints, list)
            assert endpoints[0]["url"] == "https://api.example.com/graphql"
            ops = json.loads(output_dir.joinpath("operations.json").read_text())
            assert isinstance(ops, list)
            assert len(ops) == 3
            types = json.loads(
                output_dir.joinpath("schema_types.json").read_text()
            )
            assert isinstance(types, list)
            assert len(types) == 2

    def test_operations_sorted_by_type_then_name(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "test.db"
            db, run_id = _seed_db(db_path)
            run = _run_dict(db, run_id)
            data = _collect_export_data(db, run)
            names = [o["name"] for o in data["operations"]]
            # queries before mutations, alphabetical within each
            assert names == ["me", "users", "updateUser"]
            assert data["operations"][0]["type"] == "query"
            assert data["operations"][1]["type"] == "query"
            assert data["operations"][2]["type"] == "mutation"
            db.close()

    def test_severity_filter_keeps_high_removes_low(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "test.db"
            db = Database(db_path)
            db.initialize()
            run_id = db.create_scan_run("https://api.example.com/graphql")
            db.connect().execute(
                "INSERT INTO risk_findings (scan_run_id, operation_type, operation_name, severity, category, detail) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (run_id, "query", "users", "high", "auth_bypass", "High finding"),
            )
            db.connect().execute(
                "INSERT INTO risk_findings (scan_run_id, operation_type, operation_name, severity, category, detail) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (run_id, "query", "posts", "low", "deprecated", "Low finding"),
            )
            db.finish_scan_run(run_id)
            run = _run_dict(db, run_id)
            data = _collect_export_data(db, run, severity_filter="high")
            details = {f["detail"] for f in data["risk_findings"]}
            assert "High finding" in details
            assert "Low finding" not in details
            db.close()

    def test_severity_filter_none_invalid(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "test.db"
            db, run_id = _seed_db(db_path)
            run = _run_dict(db, run_id)
            data = _collect_export_data(db, run, severity_filter="invalid")
            # invalid filter falls through — all findings returned
            assert "risk_findings" in data
            db.close()

    def test_empty_db_errors(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "empty.db"
            db = Database(db_path)
            db.initialize()
            db.close()
            output_dir = Path(tmp) / "out"
            result = RUNNER.invoke(
                app, ["export", "--db", str(db_path), "--output", str(output_dir)]
            )
            assert result.exit_code != 0
            assert "No scan runs found" in result.output

    # ── Guardrail: no auth token in any export file ──

    def test_no_auth_token_in_any_exported_file(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "test.db"
            db, _ = _seed_db(db_path)
            db.close()
            output_dir = Path(tmp) / "out"
            RUNNER.invoke(
                app, ["export", "--db", str(db_path), "--output", str(output_dir)]
            )
            for fname in (
                "run.json", "endpoints.json",
                "operations.json", "schema_types.json",
                "auth_results.json",
            ):
                content = output_dir.joinpath(fname).read_text().lower()
                assert "authorization" not in content, f"{fname} contains 'authorization'"
                assert "bearer" not in content, f"{fname} contains 'bearer'"
                assert "token" not in content, f"{fname} contains 'token'"
