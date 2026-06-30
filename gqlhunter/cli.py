from __future__ import annotations

import asyncio
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import typer
from rich.console import Console
from rich.table import Table

from gqlhunter import __version__
from gqlhunter.core.db import Database

app = typer.Typer(
    name="gqlhunter",
    help="GraphQL recon & analysis CLI — schema discovery, risk classification, IDOR candidates",
    no_args_is_help=True,
)
console = Console()


def _version_callback(value: bool) -> None:
    if value:
        console.print(f"gqlhunter v{__version__} — by bess1lie")
        raise typer.Exit()


@app.callback()
def _main(
    version: bool = typer.Option(
        False, "--version", help="Show version and exit", callback=_version_callback
    ),
) -> None:
    pass


@app.command()
def discover(
    target: str = typer.Argument(..., help="Target URL (e.g. https://example.com)"),
    scope: Path = typer.Option(..., "--scope", help="Path to scope.yaml", exists=True),
    rate: float = typer.Option(10.0, "--rate", help="Requests per second"),
    timeout: float = typer.Option(10.0, "--timeout", help="Request timeout in seconds"),
) -> None:
    asyncio.run(_discover(target, scope, rate, timeout))


async def _discover(target: str, scope_path: Path, rate: float, timeout: float) -> None:
    from gqlhunter.core.db import Database
    from gqlhunter.core.http_client import HttpClient
    from gqlhunter.core.scope import Scope
    from gqlhunter.discovery.endpoint_discovery import discover_endpoints
    from gqlhunter.introspection.introspection import IntrospectionStatus, run_introspection
    from gqlhunter.schema.parser import parse as parse_schema

    scope_obj = Scope.from_yaml(str(scope_path))
    db = Database(f"gqlhunter_{datetime.now(UTC).strftime('%Y%m%d_%H%M%S')}.db")
    db.initialize()

    async with HttpClient(timeout=timeout, rate_per_second=rate) as client:
        console.print(f"[bold]Discovering[/] endpoints at [cyan]{target}[/]")
        discovered = await discover_endpoints(target, scope_obj, client)

        if not discovered:
            console.print("[yellow]No endpoints discovered.[/]")
            db.close()
            return

        table = Table(title="Discovered GraphQL Endpoints")
        table.add_column("URL", style="cyan")
        table.add_column("Status", style="green")
        table.add_column("Content-Type")
        for ep in discovered:
            table.add_row(ep.url, str(ep.status_code), ep.content_type or "—")
        console.print(table)

        live = [ep for ep in discovered if 200 <= ep.status_code < 500]

        for ep in live:
            console.print(f"\n[bold]Running introspection[/] on [cyan]{ep.url}[/]")
            result = await run_introspection(ep.url, client)
            run_id = db.create_scan_run(ep.url)
            db.upsert_endpoint(ep.url, result.status.value, run_id)

            console.print(f"  Status: [bold]{result.status.value}[/] (HTTP {result.status_code})")

            if result.status == IntrospectionStatus.ENABLED and result.data:
                parsed = parse_schema(result.data)
                ep_id = db.upsert_endpoint(ep.url, result.status.value, run_id)

                for st in parsed.types:
                    db.insert_schema_type(
                        ep_id, st.name, st.kind, st.description, run_id
                    )

                all_ops = [
                    ("query", parsed.queries),
                    ("mutation", parsed.mutations),
                    ("subscription", parsed.subscriptions),
                ]
                def _make_args_json(field):
                    if not field.args:
                        return None
                    return json.dumps(
                        [{"name": a.name, "type": a.type.name or a.type.kind} for a in field.args]
                    )

                def _ret_type(field):
                    if field.return_type:
                        return field.return_type.name or field.return_type.of_type
                    return None

                for op_type, fields in all_ops:
                    for f in fields:
                        db.insert_operation(
                            ep_id, op_type, f.name, _make_args_json(f),
                            _ret_type(f), f.description, run_id,
                        )

                console.print(
                    f"  [green]Found {len(parsed.types)} types, "
                    f"{len(parsed.queries)} queries, "
                    f"{len(parsed.mutations)} mutations[/]"
                )

            db.finish_scan_run(run_id)
            console.print(f"  [dim]Run ID: {run_id}[/]")

    console.print(f"\n[bold green]Discovery complete.[/] Database saved to: {db.path}")
    db.close()


@app.command()
def scan(
    endpoint: str = typer.Argument(..., help="GraphQL endpoint URL"),
    scope: Path = typer.Option(..., "--scope", help="Path to scope.yaml", exists=True),
    auth_header: str | None = typer.Option(
        None, "--auth-header", help="Authorization header value (e.g. 'Bearer ...')"
    ),
    rate: float = typer.Option(10.0, "--rate", help="Requests per second"),
    timeout: float = typer.Option(10.0, "--timeout", help="Request timeout in seconds"),
) -> None:
    asyncio.run(_scan(endpoint, scope, auth_header, rate, timeout))


async def _scan(
    endpoint: str, scope_path: Path, auth_header: str | None, rate: float, timeout: float,
) -> None:
    from gqlhunter.core.db import Database
    from gqlhunter.core.http_client import HttpClient
    from gqlhunter.core.scope import Scope
    from gqlhunter.introspection.introspection import IntrospectionStatus, run_introspection
    from gqlhunter.schema.parser import parse as parse_schema

    scope_obj = Scope.from_yaml(str(scope_path))
    if not scope_obj.is_in_scope(endpoint):
        console.print("[red]Endpoint is out of scope.[/]")
        raise typer.Exit(code=1)

    db = Database(f"gqlhunter_{datetime.now(UTC).strftime('%Y%m%d_%H%M%S')}.db")
    db.initialize()
    run_id = db.create_scan_run(endpoint)

    async with HttpClient(timeout=timeout, rate_per_second=rate) as client:
        console.print(f"[bold]Scanning[/] [cyan]{endpoint}[/]")
        result = await run_introspection(endpoint, client, auth_header)
        db.upsert_endpoint(endpoint, result.status.value, run_id)

        console.print(f"Introspection: [bold]{result.status.value}[/] (HTTP {result.status_code})")

        if result.status == IntrospectionStatus.ENABLED and result.data:
            parsed = parse_schema(result.data)
            ep_id = db.upsert_endpoint(endpoint, result.status.value, run_id)

            for st in parsed.types:
                db.insert_schema_type(ep_id, st.name, st.kind, st.description, run_id)

            def _make_args_json(field):
                if not field.args:
                    return None
                return json.dumps(
                    [{"name": a.name, "type": a.type.name or a.type.kind} for a in field.args]
                )

            def _ret_type(field):
                return field.return_type.name if field.return_type else None

            for f in parsed.queries:
                db.insert_operation(
                    ep_id, "query", f.name, _make_args_json(f),
                    _ret_type(f), f.description, run_id,
                )

            for f in parsed.mutations:
                db.insert_operation(
                    ep_id, "mutation", f.name, _make_args_json(f),
                    _ret_type(f), f.description, run_id,
                )

            for f in parsed.subscriptions:
                db.insert_operation(
                    ep_id, "subscription", f.name, _make_args_json(f),
                    _ret_type(f), f.description, run_id,
                )

            console.print(
                f"[green]Stored {len(parsed.types)} types, "
                f"{len(parsed.queries)} queries, "
                f"{len(parsed.mutations)} mutations[/]"
            )

    db.finish_scan_run(run_id)
    console.print(f"\n[bold green]Scan complete.[/] Run ID: {run_id}")
    console.print(f"Database saved to: {db.path}")
    db.close()


@app.command()
def report(
    db_path: Path = typer.Option(..., "--db", help="Path to SQLite database", exists=True),
    format: str = typer.Option("markdown", "--format", help="Report format: markdown or html"),
    output: Path | None = typer.Option(None, "--output", "-o", help="Output file (default: stdout)"),
) -> None:
    from gqlhunter.core.db import Database
    from gqlhunter.report.render import render_html, render_markdown

    db = Database(db_path)
    db.connect()
    db.initialize()

    run = db.get_latest_scan_run()
    if not run:
        console.print("[red]No scan runs found in database.[/]")
        raise typer.Exit(code=1)

    endpoints = db.get_endpoints(scan_run_id=run["id"])
    operations = db.get_operations(scan_run_id=run["id"])

    schema_summary: dict | None = None
    if operations:
        def _op_dict(o):
            return {
                "name": o["name"],
                "return_type": o["return_type"],
                "args": o["args_json"] or "—",
            }

        queries = [_op_dict(o) for o in operations if o["type"] == "query"]
        mutations = [_op_dict(o) for o in operations if o["type"] == "mutation"]

        conn = db.connect()
        types_row = conn.execute(
            "SELECT DISTINCT name, kind FROM schema_types WHERE scan_run_id = ?", (run["id"],)
        ).fetchall()

        schema_summary = {
            "query_type": "Query",
            "mutation_type": "Mutation" if mutations else None,
            "subscription_type": None,
            "total_types": len(types_row),
            "queries": queries,
            "mutations": mutations,
        }

    findings: list[dict] = []

    date_str = run["started_at"]

    ctx = (run["endpoint"], run["id"], date_str, endpoints, schema_summary, findings)
    if format == "html":
        result_text = render_html(*ctx)
    else:
        result_text = render_markdown(*ctx)

    if output:
        output.write_text(result_text)
        console.print(f"[green]Report written to {output}[/]")
    else:
        console.print(result_text)

    db.close()


def _collect_export_data(db: Database, run: dict) -> dict:
    endpoints = db.get_endpoints(scan_run_id=run["id"])
    operations = db.get_operations(scan_run_id=run["id"])
    conn = db.connect()
    types_rows = conn.execute(
        "SELECT * FROM schema_types WHERE scan_run_id = ?", (run["id"],)
    ).fetchall()
    return {
        "run": dict(run),
        "endpoints": endpoints,
        "operations": operations,
        "schema_types": [dict(r) for r in types_rows],
    }


@app.command()
def export(
    db_path: Path = typer.Option(..., "--db", help="Path to SQLite database", exists=True),
    output_dir: Path = typer.Option(..., "--output", help="Output directory"),
) -> None:
    from gqlhunter.core.db import Database

    db = Database(db_path)
    db.connect()
    db.initialize()

    output_dir.mkdir(parents=True, exist_ok=True)

    run = db.get_latest_scan_run()
    if not run:
        console.print("[red]No scan runs found.[/]")
        raise typer.Exit(code=1)

    data = _collect_export_data(db, run)
    output_dir.joinpath("endpoints.json").write_text(json.dumps(data["endpoints"], indent=2))
    output_dir.joinpath("operations.json").write_text(json.dumps(data["operations"], indent=2))
    output_dir.joinpath("run.json").write_text(json.dumps(data["run"], indent=2))
    output_dir.joinpath("schema_types.json").write_text(json.dumps(data["schema_types"], indent=2))

    console.print(f"[green]Exported scan data to {output_dir.resolve()}[/]")
    db.close()


def _parse_args_json(raw: str | None) -> Any:
    """Parse args_json for structural comparison. None stays None."""
    if raw is None:
        return None
    try:
        return json.loads(raw)
    except (json.JSONDecodeError, TypeError):
        return raw


def diff_operations(
    old_ops: list[dict],
    new_ops: list[dict],
) -> list[dict]:
    """Compare two sets of operations and return diff entries.

    Each operation dict must have keys: type, name, args_json, return_type.

    Returns list of dicts with keys: change (added/removed/modified),
    type, name, detail.
    """
    old_by_key = {(o["type"], o["name"]): o for o in old_ops}
    new_by_key = {(o["type"], o["name"]): o for o in new_ops}

    old_keys = set(old_by_key.keys())
    new_keys = set(new_by_key.keys())

    results: list[dict] = []

    for key in sorted(new_keys - old_keys):
        results.append({"change": "added", "type": key[0], "name": key[1], "detail": None})

    for key in sorted(old_keys - new_keys):
        results.append({"change": "removed", "type": key[0], "name": key[1], "detail": None})

    for key in sorted(old_keys & new_keys):
        old_op = old_by_key[key]
        new_op = new_by_key[key]

        changes: list[str] = []

        old_args = _parse_args_json(old_op.get("args_json"))
        new_args = _parse_args_json(new_op.get("args_json"))
        if old_args != new_args:
            changes.append("args changed")

        old_ret = old_op.get("return_type")
        new_ret = new_op.get("return_type")
        if old_ret != new_ret:
            changes.append(f"return: {old_ret} \u2192 {new_ret}")

        if changes:
            results.append({
                "change": "modified",
                "type": key[0],
                "name": key[1],
                "detail": "; ".join(changes),
            })

    sort_order = {"added": 0, "modified": 1, "removed": 2}
    results.sort(key=lambda r: (sort_order.get(r["change"], 99), r["type"], r["name"]))
    return results


@app.command()
def diff(
    db_path: Path = typer.Option(..., "--db", help="Path to SQLite database", exists=True),
    endpoint: str | None = typer.Option(
        None, "--endpoint", help="Filter to specific endpoint URL"
    ),
) -> None:
    from gqlhunter.core.db import Database

    db = Database(db_path)
    db.connect()
    db.initialize()

    conn = db.connect()
    if endpoint:
        runs = conn.execute(
            "SELECT * FROM scan_runs WHERE endpoint = ? ORDER BY id DESC LIMIT 2",
            (endpoint,),
        ).fetchall()
    else:
        runs = conn.execute(
            "SELECT * FROM scan_runs ORDER BY id DESC LIMIT 2"
        ).fetchall()

    if len(runs) < 2:
        console.print("[yellow]Need at least 2 scan runs to diff.[/]")
        if endpoint:
            console.print(f"  Filter: --endpoint {endpoint}")
        db.close()
        return

    older, newer = runs[1], runs[0]

    old_ops = conn.execute(
        "SELECT type, name, args_json, return_type FROM operations WHERE scan_run_id = ?",
        (older["id"],),
    ).fetchall()
    new_ops = conn.execute(
        "SELECT type, name, args_json, return_type FROM operations WHERE scan_run_id = ?",
        (newer["id"],),
    ).fetchall()

    changes = diff_operations([dict(r) for r in old_ops], [dict(r) for r in new_ops])

    if not changes:
        console.print("[green]No changes detected between last two scan runs.[/]")
        db.close()
        return

    table = Table(title="Schema Diff")
    table.add_column("Change", style="bold")
    table.add_column("Operation")
    for c in changes:
        label = c["change"]
        op_key = f"{c['type']}.{c['name']}"
        if label == "added":
            table.add_row("[green]+ Added[/]", op_key)
        elif label == "modified":
            detail = f" [dim]({c['detail']})[/]" if c["detail"] else ""
            table.add_row("[yellow]~ Modified[/]", f"{op_key}{detail}")
        elif label == "removed":
            table.add_row("[red]- Removed[/]", op_key)
    console.print(table)

    db.close()
