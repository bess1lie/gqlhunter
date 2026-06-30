from __future__ import annotations

import json
import tempfile
from pathlib import Path

from typer.testing import CliRunner

from gqlhunter.cli import app

RUNNER = CliRunner()


def _seed_db(db_path: Path) -> int:
    from gqlhunter.core.db import Database
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
    db.finish_scan_run(run_id)
    db.close()
    return run_id


class TestVariantsCli:
    def test_variants_with_default_strategy(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "test.db"
            _seed_db(db_path)
            result = RUNNER.invoke(app, [
                "variants", "--db", str(db_path),
            ])
            assert result.exit_code == 0, result.output
            data = json.loads(result.output)
            assert len(data) > 0
            assert data[0]["variant_type"] == "alias"

    def test_variants_combinations_strategy(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "test.db"
            _seed_db(db_path)
            result = RUNNER.invoke(app, [
                "variants", "--db", str(db_path), "--strategy", "combinations",
            ])
            assert result.exit_code == 0, result.output
            data = json.loads(result.output)
            types = {d["variant_type"] for d in data}
            assert "alias" in types
            assert "arg_removal" in types
            assert "depth" in types

    def test_variants_random_strategy(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "test.db"
            _seed_db(db_path)
            result = RUNNER.invoke(app, [
                "variants", "--db", str(db_path), "--strategy", "random",
            ])
            assert result.exit_code == 0, result.output
            data = json.loads(result.output)
            assert len(data) > 0

    def test_variants_output_file(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "test.db"
            out_path = Path(tmp) / "variants.json"
            _seed_db(db_path)
            result = RUNNER.invoke(app, [
                "variants", "--db", str(db_path), "--output", str(out_path),
            ])
            assert result.exit_code == 0, result.output
            assert out_path.exists()
            data = json.loads(out_path.read_text())
            assert len(data) > 0

    def test_variants_invalid_strategy(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "test.db"
            _seed_db(db_path)
            result = RUNNER.invoke(app, [
                "variants", "--db", str(db_path), "--strategy", "invalid",
            ])
            assert result.exit_code != 0

    def test_variants_no_db_errors(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "empty.db"
            from gqlhunter.core.db import Database
            db = Database(db_path)
            db.initialize()
            db.close()
            result = RUNNER.invoke(app, [
                "variants", "--db", str(db_path),
            ])
            assert result.exit_code != 0
            assert "No scan runs" in result.output

    def test_variants_specific_run_id(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "test.db"
            run_id = _seed_db(db_path)
            result = RUNNER.invoke(app, [
                "variants", "--db", str(db_path), "--run-id", str(run_id),
            ])
            assert result.exit_code == 0, result.output
            data = json.loads(result.output)
            assert len(data) > 0

    def test_variants_compact_output(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "test.db"
            _seed_db(db_path)
            result = RUNNER.invoke(app, [
                "variants", "--db", str(db_path), "--compact",
            ])
            assert result.exit_code == 0, result.output
            compact = result.output
            result2 = RUNNER.invoke(app, [
                "variants", "--db", str(db_path), "--pretty",
            ])
            pretty = result2.output
            assert len(compact) < len(pretty)

    def test_variants_no_operations_errors(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "test.db"
            from gqlhunter.core.db import Database
            db = Database(db_path)
            db.initialize()
            run_id = db.create_scan_run("https://api.example.com/graphql")
            db.finish_scan_run(run_id)
            db.close()
            result = RUNNER.invoke(app, [
                "variants", "--db", str(db_path),
            ])
            assert result.exit_code != 0
            assert "No operations" in result.output
