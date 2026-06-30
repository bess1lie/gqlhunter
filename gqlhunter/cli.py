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
    help="GraphQL recon & analysis CLI \u2014 schema discovery, risk classification, IDOR candidates",
    no_args_is_help=True,
)
console = Console()


def _version_callback(value: bool) -> None:
    if value:
        console.print(f"gqlhunter v{__version__} \u2014 by bess1lie")
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


@app.command()
def auth(
    endpoint: str = typer.Argument(..., help="GraphQL endpoint URL"),
    scope: Path = typer.Option(..., "--scope", help="Path to scope.yaml", exists=True),
    auth_header: str | None = typer.Option(
        None, "--auth-header", help="Authorization header value (e.g. 'Bearer ...')"
    ),
    session: Path | None = typer.Option(
        None, "--session", help="Load auth header from session file"
    ),
    save_session: Path | None = typer.Option(
        None, "--save-session", help="Save auth header to session file"
    ),
    db_path: Path = typer.Option(..., "--db", help="Path to SQLite database", exists=True),
    rate: float = typer.Option(10.0, "--rate", help="Requests per second"),
    timeout: float = typer.Option(10.0, "--timeout", help="Request timeout in seconds"),
    max_depth: int = typer.Option(3, "--max-depth", help="Maximum nesting depth for introspection"),
) -> None:
    """Analyze auth requirements for a GraphQL endpoint.

    Sends the same query with and without the Authorization header to determine
    whether the endpoint is PUBLIC, AUTH_REQUIRED, OVER_PERMISSIVE, BLOCKED,
    or ERROR. Results are stored in the database and can be surfaced in reports.
    """
    asyncio.run(_auth(endpoint, scope, auth_header, session, save_session, db_path, rate, timeout, max_depth))


async def _auth(
    endpoint: str, scope_path: Path, auth_header: str | None,
    session_path: Path | None, save_session_path: Path | None,
    db_path: Path, rate: float, timeout: float, max_depth: int = 3,
) -> None:
    from gqlhunter.auth.auth_analyzer import analyze_auth
    from gqlhunter.auth.session import resolve_auth_header, save_session
    from gqlhunter.core.http_client import HttpClient
    from gqlhunter.core.scope import Scope

    token = resolve_auth_header(auth_header, str(session_path) if session_path else None)
    if not token:
        console.print("[red]Either --auth-header or --session is required.[/]")
        raise typer.Exit(code=1)

    if save_session_path:
        save_session(save_session_path, token, endpoint=endpoint)

    scope_obj = Scope.from_yaml(str(scope_path))
    if not scope_obj.is_in_scope(endpoint):
        console.print("[red]Endpoint is out of scope.[/]")
        raise typer.Exit(code=1)

    db = Database(str(db_path))
    db.connect()
    db.initialize()
    run_id = db.create_scan_run(endpoint)

    async with HttpClient(timeout=timeout, rate_per_second=rate) as client:
        console.print(f"[bold]Analyzing auth[/] for [cyan]{endpoint}[/]")
        result = await analyze_auth(endpoint, token, client)

    preview = result.with_token_body_preview or ""
    db.insert_auth_result(
        scan_run_id=run_id,
        endpoint=endpoint,
        classification=result.classification.value,
        with_token_status=result.with_token_status,
        without_token_status=result.without_token_status,
        with_token_body_preview=preview[:200] if preview else None,
        without_token_body_preview=result.without_token_body_preview[:200] if result.without_token_body_preview else None,
    )
    db.finish_scan_run(run_id)

    table = Table(title="Auth Analysis Result")
    table.add_column("Property", style="bold")
    table.add_column("Value")
    table.add_row("Classification", f"[bold]{result.classification.value}[/]")
    table.add_row("Without Token Status", str(result.without_token_status))
    table.add_row("With Token Status", str(result.with_token_status))
    table.add_row("Run ID", str(run_id))
    console.print(table)
    console.print(f"\n[bold green]Auth analysis complete.[/] Run ID: {run_id}")
    console.print(f"Database saved to: {db_path}")

    db.close()



@app.command()
def scan(
    endpoint: str = typer.Argument(..., help="GraphQL endpoint URL"),
    scope: Path = typer.Option(..., "--scope", help="Path to scope.yaml", exists=True),
    auth_header: str | None = typer.Option(
        None, "--auth-header", help="Authorization header value (e.g. 'Bearer ...')"
    ),
    session: Path | None = typer.Option(
        None, "--session", help="Load auth header from session file"
    ),
    save_session: Path | None = typer.Option(
        None, "--save-session", help="Save auth header to session file"
    ),
    rate: float = typer.Option(10.0, "--rate", help="Requests per second"),
    timeout: float = typer.Option(10.0, "--timeout", help="Request timeout in seconds"),
    max_depth: int = typer.Option(3, "--max-depth", help="Maximum nesting depth for introspection"),
) -> None:
    asyncio.run(_scan(endpoint, scope, auth_header, session, save_session, rate, timeout, max_depth))


async def _scan(
    endpoint: str, scope_path: Path, auth_header: str | None,
    session_path: Path | None, save_session_path: Path | None,
    rate: float, timeout: float, max_depth: int = 3,
) -> None:
    from gqlhunter.auth.session import resolve_auth_header, save_session
    from gqlhunter.core.db import Database
    from gqlhunter.core.http_client import HttpClient
    from gqlhunter.core.scope import Scope
    from gqlhunter.introspection.introspection import IntrospectionStatus, run_introspection
    from gqlhunter.schema.parser import parse as parse_schema

    token = resolve_auth_header(auth_header, str(session_path) if session_path else None)
    if save_session_path and token:
        save_session(save_session_path, token, endpoint=endpoint)

    scope_obj = Scope.from_yaml(str(scope_path))
    if not scope_obj.is_in_scope(endpoint):
        console.print("[red]Endpoint is out of scope.[/]")
        raise typer.Exit(code=1)

    db = Database(f"gqlhunter_{datetime.now(UTC).strftime('%Y%m%d_%H%M%S')}.db")
    db.initialize()
    run_id = db.create_scan_run(endpoint)

    async with HttpClient(timeout=timeout, rate_per_second=rate) as client:
        console.print(f"[bold]Scanning[/] [cyan]{endpoint}[/]")
        result = await run_introspection(endpoint, client, token, max_depth=max_depth)
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
def variants(
    db_path: Path = typer.Option(..., "--db", help="Path to SQLite database", exists=True),
    output: Path | None = typer.Option(None, "--output", "-o", help="Output file (default: stdout)"),
    strategy: str = typer.Option("single", "--strategy", help="Variant strategy: single, combinations, random"),
    max_depth: int = typer.Option(3, "--max-depth", help="Maximum nesting depth for field selection"),
    scan_run_id: int | None = typer.Option(None, "--run-id", help="Scan run ID (default: latest)"),
    pretty: bool = typer.Option(True, "--pretty/--compact", help="Pretty-print JSON output"),
) -> None:
    """Generate query variants from stored operations.

    Reads operations from the database and generates variant queries
    using the specified strategy (single, combinations, or random).
    Useful for testing endpoint behavior with different query structures.
    """
    asyncio.run(_variants(db_path, output, strategy, max_depth, scan_run_id, pretty))


async def _variants(
    db_path: Path, output: Path | None, strategy: str, max_depth: int,
    scan_run_id: int | None, pretty: bool,
) -> None:
    from gqlhunter.core.db import Database
    from gqlhunter.variants.variant_engine import generate_variants, variants_to_json

    valid_strategies = ("single", "combinations", "random")
    if strategy not in valid_strategies:
        console.print(f"[red]Invalid strategy '{strategy}'. Choose from: {', '.join(valid_strategies)}[/]")
        raise typer.Exit(code=1)

    db = Database(db_path)
    db.connect()
    db.initialize()

    run = None
    if scan_run_id is not None:
        conn = db.connect()
        row = conn.execute("SELECT * FROM scan_runs WHERE id = ?", (scan_run_id,)).fetchone()
        if row:
            run = dict(row)
        else:
            console.print(f"[red]Scan run {scan_run_id} not found.[/]")
            db.close()
            raise typer.Exit(code=1)
    else:
        run = db.get_latest_scan_run()

    if not run:
        console.print("[red]No scan runs found in database.[/]")
        db.close()
        raise typer.Exit(code=1)

    operations = db.get_operations(scan_run_id=run["id"])

    if not operations:
        console.print("[yellow]No operations found for this scan run.[/]")
        db.close()
        raise typer.Exit(code=1)

    conn = db.connect()
    types_rows = conn.execute(
        "SELECT * FROM schema_types WHERE scan_run_id = ?", (run["id"],)
    ).fetchall()

    from gqlhunter.schema.parser import SchemaType, ArgType, Field as ParserField
    types_by_name: dict[str, SchemaType] = {}
    for row in types_rows:
        dr = dict(row)
        types_by_name[dr["name"]] = SchemaType(
            kind=dr["kind"],
            name=dr["name"],
            description=dr.get("description"),
            fields=[],
        )

    result = generate_variants(operations, types_by_name, strategy=strategy, max_depth=max_depth)

    text = variants_to_json(result, indent=2 if pretty else None)

    if output:
        output.write_text(text)
        console.print(f"[green]{len(result)} variants written to {output}[/]")
    else:
        typer.echo(text)

    db.close()


@app.command()
def notify(
    channel: str = typer.Argument(..., help="Notification channel: slack, telegram, webhook"),
    db_path: Path = typer.Option(..., "--db", help="Path to SQLite database", exists=True),
    scope: Path | None = typer.Option(None, "--scope", help="Path to scope.yaml (for template_dir)"),
    webhook_url: str | None = typer.Option(None, "--webhook-url", help="Webhook URL (slack/webhook)"),
    telegram_token: str | None = typer.Option(None, "--telegram-token", help="Telegram bot token"),
    telegram_chat: str | None = typer.Option(None, "--telegram-chat", help="Telegram chat ID"),
    template_dir: Path | None = typer.Option(
        None, "--template-dir", help="Custom template directory (default: built-in templates)"
    ),
    scan_run_id: int | None = typer.Option(None, "--run-id", help="Scan run ID (default: latest)"),
) -> None:
    """Send scan report via Slack, Telegram, or webhook.

    Renders a notification using Jinja2 templates and sends it
    through the specified channel. Built-in templates are used
    unless --template-dir or scope.yaml's template_dir is provided.
    Priority: --template-dir > scope.yaml > built-in templates.
    """
    asyncio.run(_notify(channel, db_path, scope, webhook_url, telegram_token, telegram_chat, template_dir, scan_run_id))


async def _notify(
    channel: str, db_path: Path, scope_path: Path | None,
    webhook_url: str | None, telegram_token: str | None, telegram_chat: str | None,
    template_dir: Path | None, scan_run_id: int | None,
) -> None:
    from gqlhunter.core.db import Database
    from gqlhunter.core.scope import Scope
    from gqlhunter.notify.sender import render_notification, send_slack, send_telegram, send_webhook

    if template_dir is None and scope_path is not None:
        try:
            scope_obj = Scope.from_yaml(str(scope_path))
            if scope_obj.template_dir:
                template_dir = Path(scope_obj.template_dir)
        except Exception:
            pass

    valid = ("slack", "telegram", "webhook")
    if channel not in valid:
        console.print(f"[red]Invalid channel '{channel}'. Choose from: {', '.join(valid)}[/]")
        raise typer.Exit(code=1)

    db = Database(db_path)
    db.connect()
    db.initialize()

    run = None
    if scan_run_id is not None:
        conn = db.connect()
        row = conn.execute("SELECT * FROM scan_runs WHERE id = ?", (scan_run_id,)).fetchone()
        if row:
            run = dict(row)
        else:
            console.print(f"[red]Scan run {scan_run_id} not found.[/]")
            db.close()
            raise typer.Exit(code=1)
    else:
        run = db.get_latest_scan_run()

    if not run:
        console.print("[red]No scan runs found in database.[/]")
        db.close()
        raise typer.Exit(code=1)

    endpoints = db.get_endpoints(scan_run_id=run["id"])
    operations = db.get_operations(scan_run_id=run["id"])
    conn = db.connect()
    types_rows = conn.execute(
        "SELECT * FROM schema_types WHERE scan_run_id = ?", (run["id"],)
    ).fetchall()
    auth_results = db.get_auth_results(scan_run_id=run["id"])
    risk_rows = conn.execute(
        "SELECT * FROM risk_findings WHERE scan_run_id = ?", (run["id"],)
    ).fetchall()

    context = {
        "endpoint": run["endpoint"],
        "run_id": run["id"],
        "date": run["started_at"],
        "endpoints": endpoints,
        "operations": operations,
        "schema_types": [dict(r) for r in types_rows],
        "auth_results": auth_results,
        "risk_findings": [dict(r) for r in risk_rows],
    }

    try:
        message = render_notification(channel, context, template_dir=str(template_dir) if template_dir else None)
    except Exception as exc:
        console.print(f"[red]Template rendering failed: {exc}[/]")
        db.close()
        raise typer.Exit(code=1)

    try:
        if channel == "slack":
            if not webhook_url:
                console.print("[red]--webhook-url is required for slack[/]")
                raise typer.Exit(code=1)
            send_slack(webhook_url, message)
        elif channel == "telegram":
            if not telegram_token or not telegram_chat:
                console.print("[red]--telegram-token and --telegram-chat are required for telegram[/]")
                raise typer.Exit(code=1)
            send_telegram(telegram_token, telegram_chat, message)
        elif channel == "webhook":
            if not webhook_url:
                console.print("[red]--webhook-url is required for webhook[/]")
                raise typer.Exit(code=1)
            import json
            payload = json.loads(message)
            send_webhook(webhook_url, payload)
    except Exception as exc:
        console.print(f"[red]Failed to send notification: {exc}[/]")
        db.close()
        raise typer.Exit(code=1)

    console.print(f"[green]Notification sent via {channel}[/]")
    db.close()


@app.command()
def report(
    db_path: Path = typer.Option(..., "--db", help="Path to SQLite database", exists=True),
    format: str = typer.Option("markdown", "--format", help="Report format: markdown or html"),
    output: Path | None = typer.Option(None, "--output", "-o", help="Output file (default: stdout)"),
    severity: str | None = typer.Option(None, "--severity", "-s", help="Minimum severity filter: critical, high, medium, low, info"),
) -> None:
    from gqlhunter.core.db import Database
    from gqlhunter.report.render import render_html, render_markdown, SEVERITY_ORDER

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
                "args": o["args_json"] or "\u2014",
            }

        queries = sorted(
            [_op_dict(o) for o in operations if o["type"] == "query"],
            key=lambda x: x["name"],
        )
        mutations = sorted(
            [_op_dict(o) for o in operations if o["type"] == "mutation"],
            key=lambda x: x["name"],
        )

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

    auth_results = db.get_auth_results(scan_run_id=run["id"])

    conn = db.connect()
    risk_findings = conn.execute(
        "SELECT * FROM risk_findings WHERE scan_run_id = ?", (run["id"],)
    ).fetchall()
    findings: list[dict] = [dict(r) for r in risk_findings]

    date_str = run["started_at"]

    if severity:
        sev_idx = SEVERITY_ORDER.index(severity) if severity in SEVERITY_ORDER else -1
        if sev_idx == -1:
            console.print(f"[red]Invalid severity: {severity}. Choose from {SEVERITY_ORDER}[/]")
            raise typer.Exit(code=1)
        findings = [f for f in findings if SEVERITY_ORDER.index(f.get("severity", "info")) <= sev_idx]

    ctx = (run["endpoint"], run["id"], date_str, endpoints, schema_summary, findings, auth_results)
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


def _collect_export_data(db: Database, run: dict, *, severity_filter: str | None = None) -> dict:
    endpoints = db.get_endpoints(scan_run_id=run["id"])
    operations = sorted(
        db.get_operations(scan_run_id=run["id"]),
        key=lambda o: (0 if o["type"] == "query" else 1, o["name"]),
    )
    auth_results = db.get_auth_results(scan_run_id=run["id"])
    conn = db.connect()
    types_rows = conn.execute(
        "SELECT * FROM schema_types WHERE scan_run_id = ?", (run["id"],)
    ).fetchall()

    risk_rows = conn.execute(
        "SELECT * FROM risk_findings WHERE scan_run_id = ?", (run["id"],)
    ).fetchall()
    risk_findings = [dict(r) for r in risk_rows]

    if severity_filter:
        from gqlhunter.report.render import SEVERITY_ORDER
        sev_idx = SEVERITY_ORDER.index(severity_filter) if severity_filter in SEVERITY_ORDER else -1
        if sev_idx != -1:
            risk_findings = [f for f in risk_findings if SEVERITY_ORDER.index(f.get("severity", "info")) <= sev_idx]

    return {
        "run": dict(run),
        "endpoints": endpoints,
        "operations": operations,
        "schema_types": [dict(r) for r in types_rows],
        "auth_results": auth_results,
        "risk_findings": risk_findings,
    }


@app.command()
def export(
    db_path: Path = typer.Option(..., "--db", help="Path to SQLite database", exists=True),
    output_dir: Path = typer.Option(..., "--output", help="Output directory"),
    sarif: bool = typer.Option(False, "--sarif", help="Generate SARIF 2.1.0 report"),
    severity: str | None = typer.Option(None, "--severity", "-s", help="Minimum severity filter: critical, high, medium, low, info"),
) -> None:
    from gqlhunter.core.db import Database
    from gqlhunter.report.sarif import generate_sarif

    db = Database(db_path)
    db.connect()
    db.initialize()

    output_dir.mkdir(parents=True, exist_ok=True)

    run = db.get_latest_scan_run()
    if not run:
        console.print("[red]No scan runs found.[/]")
        raise typer.Exit(code=1)

    data = _collect_export_data(db, run, severity_filter=severity)
    output_dir.joinpath("endpoints.json").write_text(json.dumps(data["endpoints"], indent=2))
    output_dir.joinpath("operations.json").write_text(json.dumps(data["operations"], indent=2))
    output_dir.joinpath("run.json").write_text(json.dumps(data["run"], indent=2))
    output_dir.joinpath("schema_types.json").write_text(json.dumps(data["schema_types"], indent=2))
    output_dir.joinpath("auth_results.json").write_text(json.dumps(data["auth_results"], indent=2))
    output_dir.joinpath("risk_findings.json").write_text(json.dumps(data["risk_findings"], indent=2))

    if sarif:
        sarif_path = output_dir / "gqlhunter.sarif"
        generate_sarif(
            endpoint=run["endpoint"],
            scan_run_id=run["id"],
            operations=data["operations"],
            risk_findings=data["risk_findings"],
            output=sarif_path,
        )
        console.print(f"[green]SARIF report: {sarif_path}[/]")

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


@app.command()
def batch(
    scope_path: Path = typer.Argument(..., help="Path to scope.yaml", exists=True),
    rate: float = typer.Option(10.0, "--rate", help="Requests per second"),
    timeout: float = typer.Option(10.0, "--timeout", help="Request timeout in seconds"),
    auth_header: str | None = typer.Option(
        None, "--auth-header", help="Authorization header value (e.g. 'Bearer ...')"
    ),
    output_dir: Path | None = typer.Option(
        None, "--output", "-o", help="Output directory for exports"
    ),
    db_path: Path | None = typer.Option(
        None, "--db", help="Path to SQLite database (auto-generated if not set)"
    ),
) -> None:
    """Batch scan multiple GraphQL endpoints from scope.yaml.

    Reads targets from scope.yaml and runs full scan (discovery + introspection
    + analysis) on each endpoint sequentially, respecting rate limits.
    """
    asyncio.run(_batch(scope_path, rate, timeout, auth_header, output_dir, db_path))


async def _batch(
    scope_path: Path, rate: float, timeout: float,
    auth_header: str | None, output_dir: Path | None,
    db_path: Path | None,
) -> None:
    from rich.progress import BarColumn, Progress, SpinnerColumn, TextColumn

    from gqlhunter.analyzer.risk import analyze_operations
    from gqlhunter.core.db import Database
    from gqlhunter.core.http_client import HttpClient
    from gqlhunter.core.scope import Scope
    from gqlhunter.discovery.endpoint_discovery import discover_endpoints
    from gqlhunter.introspection.introspection import IntrospectionStatus, run_introspection
    from gqlhunter.schema.parser import ArgType, Field, FieldArg
    from gqlhunter.schema.parser import parse as parse_schema

    scope_obj = Scope.from_yaml(str(scope_path))

    if not scope_obj.targets:
        console.print("[red]No targets found in scope.yaml. Add endpoints under 'targets:'[/]")
        raise typer.Exit(code=1)

    if db_path is None:
        db_path = Path(f"gqlhunter_batch_{datetime.now(UTC).strftime('%Y%m%d_%H%M%S')}.db")

    db = Database(str(db_path))
    db.initialize()

    console.print(f"[bold]Batch scanning[/] [cyan]{len(scope_obj.targets)}[/] endpoints")
    console.print(f"[dim]Database: {db_path}[/]")

    success_count = 0
    fail_count = 0

    async with HttpClient(timeout=timeout, rate_per_second=rate) as client:
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            console=console,
        ) as progress:
            overall = progress.add_task(
                f"[cyan]Scanning {len(scope_obj.targets)} endpoints...[/]",
                total=len(scope_obj.targets),
            )

            for target_url in scope_obj.targets:
                task_desc = f"[cyan]{target_url[:60]}...[/]" if len(target_url) > 60 else f"[cyan]{target_url}[/]"
                ep_task = progress.add_task(task_desc, total=None)

                try:
                    if not scope_obj.is_in_scope(target_url):
                        progress.update(ep_task, description=f"[yellow]OOS: {target_url[:50]}[/]")
                        progress.advance(overall)
                        continue

                    progress.update(ep_task, description="[yellow]Discovering...[/]")
                    discovered = await discover_endpoints(target_url, scope_obj, client)

                    if not discovered:
                        progress.update(ep_task, description=f"[red]No endpoints: {target_url[:40]}[/]")
                        fail_count += 1
                        progress.advance(overall)
                        continue

                    live = [ep for ep in discovered if 200 <= ep.status_code < 500]

                    if not live:
                        progress.update(ep_task, description=f"[red]No live: {target_url[:40]}[/]")
                        fail_count += 1
                        progress.advance(overall)
                        continue

                    for ep in live:
                        progress.update(ep_task, description=f"[yellow]Introspecting {ep.url[:50]}...[/]")
                        result = await run_introspection(ep.url, client, auth_header)
                        run_id = db.create_scan_run(ep.url)
                        db.upsert_endpoint(ep.url, result.status.value, run_id)

                        if result.status == IntrospectionStatus.ENABLED and result.data:
                            parsed = parse_schema(result.data)
                            ep_id = db.upsert_endpoint(ep.url, result.status.value, run_id)

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

                            for op_type, fields in [
                                ("query", parsed.queries),
                                ("mutation", parsed.mutations),
                                ("subscription", parsed.subscriptions),
                            ]:
                                for f in fields:
                                    db.insert_operation(
                                        ep_id, op_type, f.name, _make_args_json(f),
                                        _ret_type(f), f.description, run_id,
                                    )

                            all_ops = db.get_operations(scan_run_id=run_id)
                            op_id_map = {(op["type"], op["name"]): op["id"] for op in all_ops}

                            queries: list[Field] = []
                            mutations: list[Field] = []
                            subscriptions: list[Field] = []
                            for op in all_ops:
                                args_list = json.loads(op["args_json"]) if op.get("args_json") else []
                                args = [
                                    FieldArg(
                                        name=a["name"],
                                        type=ArgType(kind=a.get("type", ""), name=a.get("type")),
                                    )
                                    for a in args_list
                                ]
                                field = Field(
                                    name=op["name"],
                                    description=op.get("description"),
                                    args=args,
                                    return_type=(
                                        ArgType(kind="", name=op.get("return_type"))
                                        if op.get("return_type")
                                        else None
                                    ),
                                )
                                if op["type"] == "query":
                                    queries.append(field)
                                elif op["type"] == "mutation":
                                    mutations.append(field)
                                elif op["type"] == "subscription":
                                    subscriptions.append(field)

                            risk_results = analyze_operations(queries, mutations, subscriptions or None)
                            for rr in risk_results:
                                op_id = op_id_map.get((rr.operation_type, rr.operation_name), 0)
                                db.insert_risk_finding(
                                    op_id,
                                    rr.operation_type,
                                    rr.operation_name,
                                    rr.severity,
                                    rr.category,
                                    rr.detail,
                                    run_id,
                                )

                        db.finish_scan_run(run_id)

                    progress.update(ep_task, description=f"[green]\u2713 {target_url[:40]}...[/]")
                    success_count += 1

                except Exception as e:
                    progress.update(ep_task, description=f"[red]\u2717 {target_url[:40]}: {str(e)[:30]}[/]")
                    fail_count += 1

                progress.advance(overall)
                progress.remove_task(ep_task)

    console.print("\n[bold]Batch scan complete[/]")
    console.print(f"  [green]Success: {success_count}[/]")
    console.print(f"  [red]Failed: {fail_count}[/]")
    console.print(f"  [dim]Database: {db_path}[/]")

    if output_dir:
        output_dir.mkdir(parents=True, exist_ok=True)
        last_run = db.get_latest_scan_run()
        if last_run:
            data = _collect_export_data(db, last_run)
            output_dir.joinpath("endpoints.json").write_text(json.dumps(data["endpoints"], indent=2))
            output_dir.joinpath("operations.json").write_text(json.dumps(data["operations"], indent=2))
            output_dir.joinpath("run.json").write_text(json.dumps(data["run"], indent=2))
            output_dir.joinpath("schema_types.json").write_text(json.dumps(data["schema_types"], indent=2))
            output_dir.joinpath("auth_results.json").write_text(json.dumps(data["auth_results"], indent=2))
            console.print(f"[green]Exported to {output_dir.resolve()}[/]")

    db.close()


@app.command()
def dashboard(
    db_path: Path = typer.Option(..., "--db", help="Path to SQLite database", exists=True),
    host: str = typer.Option("127.0.0.1", "--host", help="Bind address (default: 127.0.0.1)"),
    port: int = typer.Option(8080, "--port", "-p", help="Listen port"),
) -> None:
    """Start web dashboard for viewing scan results.

    Serves a browser-based dashboard at http://<host>:<port>.
    By default listens on 127.0.0.1 (localhost only). Use --host 0.0.0.0
    to make accessible from other machines on the network.
    """
    from gqlhunter.dashboard import run_dashboard
    run_dashboard(str(db_path), host=host, port=port)
