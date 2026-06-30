```
   _____ ____  _   _ _   _ _____ _   _ _____ ____
  / ____/ ___|| | | | \ | |_   _| \ | |_   _|  _ \
 | |  _\___ \| | | |  \| | | | |  \| | | | | |_) |
 | | |___ __) | |_| | |\  | | | | |\  | | | |  __/
 |_|_____|____/ \___/|_| \_| |_| |_| \_| |_| |_|
```

# ⚡ gqlhunter

[![CI](https://github.com/bess1lie/gqlhunter/actions/workflows/ci.yml/badge.svg)](https://github.com/bess1lie/gqlhunter/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![Tests](https://img.shields.io/badge/tests-195_passed-green)](tests/)
[![Last commit](https://img.shields.io/github/last-commit/bess1lie/gqlhunter)](https://github.com/bess1lie/gqlhunter/commits/main)
[![Languages](https://img.shields.io/github/languages/top/bess1lie/gqlhunter)](https://github.com/bess1lie/gqlhunter)

**GraphQL recon & analysis CLI** — schema discovery, risk classification, IDOR candidate
detection, auth analysis, and diff for authorised bug bounty programmes.

> Sister project to [bounthunt](https://github.com/bess1lie/bounthunt) — automated web recon for bug bounty programmes.

---

## Quick example

```bash
# Discover GraphQL endpoints
gqlhunter discover https://example.com --scope scope.yaml

# Full scan: introspection → schema → risk analysis
gqlhunter scan https://example.com/graphql --scope scope.yaml

# Auth bypass analysis with session persistence
gqlhunter auth https://example.com/graphql --auth-header "Bearer <token>" --save-session session.json

# HTML report with tabbed findings
gqlhunter report --db gqlhunter.db --format html --output report.html

# Launch web dashboard
gqlhunter dashboard --db gqlhunter.db
```

---

## Ethics & Disclaimer

gqlhunter is designed exclusively for **authorised security testing** (bug bounty programmes,
CTFs, your own infrastructure). It **finds and highlights** potential issues but never
automatically executes mutations, never brute-forces credentials, and never sends requests
outside the user-defined scope.

All risk classifications are **heuristic** — based on field names (`delete*`, `admin*`),
not confirmed vulnerabilities. Every report carries the disclaimer:
**"Potential — manual verification required"**.

## Quickstart

```bash
# Install
pip install gqlhunter

# Or via uv
uv tool install gqlhunter

# Or via Docker
docker build -t gqlhunter .
docker run --rm -v .:/app gqlhunter --help
```

### Define scope

Create a `scope.yaml` file:

```yaml
targets:
  - https://example.com
  - https://api.example.com
allowlist:
  - https://example.com/graphql/public
deny:
  - /admin
```

### Discover endpoints

```bash
gqlhunter discover https://example.com --scope scope.yaml
```

Output:

```
╭───────────────── Discovered GraphQL Endpoints ─────────────────╮
│ URL                                        │ Status           │
├────────────────────────────────────────────┼──────────────────┤
│ https://example.com/graphql                │ 200 OK           │
│ https://example.com/api/graphql            │ 404 Not Found    │
│ https://example.com/graphiql               │ 200 OK           │
╰────────────────────────────────────────────┴──────────────────╯
```

### Run a full scan

```bash
gqlhunter scan https://example.com/graphql --scope scope.yaml
gqlhunter scan https://example.com/graphql --max-depth 5  # override default depth
```

### Analyse auth bypass

```bash
gqlhunter auth https://example.com/graphql --auth-header "Bearer <token>"
gqlhunter auth https://example.com/graphql --save-session session.json  # persist
gqlhunter auth https://example.com/graphql --session session.json       # reuse
```

### Generate query variants

```bash
gqlhunter variants https://example.com/graphql --strategy combinations
gqlhunter variants https://example.com/graphql --strategy random --count 20
```

### Send notifications

```bash
gqlhunter notify --db ./gqlhunter.db --slack-webhook https://hooks.slack.com/...
gqlhunter notify --db ./gqlhunter.db --telegram-token ... --telegram-chat ...
gqlhunter notify --db ./gqlhunter.db --webhook-url https://example.com/webhook
```

### Compare scan runs

```bash
gqlhunter diff --db gqlhunter_20260101_120000.db --endpoint https://example.com/graphql
```

### Generate report

```bash
gqlhunter report --db ./gqlhunter.db --format markdown
gqlhunter report --db ./gqlhunter.db --format html --output report.html
gqlhunter report --db ./gqlhunter.db --severity high  # filter by minimum severity
```

### Export JSON

```bash
gqlhunter export --db ./gqlhunter.db --output ./export/
gqlhunter export --db ./gqlhunter.db --output ./export --severity high
```

Produces: `endpoints.json`, `operations.json`, `run.json`, `schema_types.json`, `auth_results.json`, `risk_findings.json`.

### Start dashboard

```bash
gqlhunter dashboard --db ./gqlhunter.db
gqlhunter dashboard --db ./gqlhunter.db --host 0.0.0.0 --port 9090  # network access
```

### Demo

```bash
$ gqlhunter discover https://example.com --scope scope.yaml
╭───────────────── Discovered GraphQL Endpoints ─────────────────╮
│ URL                                        │ Status           │
├────────────────────────────────────────────┼──────────────────┤
│ https://example.com/graphql                │ 200 OK           │
│ https://example.com/api/graphql            │ 404 Not Found    │
│ https://example.com/graphiql               │ 200 OK           │
╰────────────────────────────────────────────┴──────────────────╯

$ gqlhunter scan https://example.com/graphql
╭────────────────────── Scan Summary ──────────────────────╮
│ Schema: 12 types, 8 queries, 3 mutations                │
│ Risk findings: 2 high, 1 medium, 3 low                  │
│ Auth classification: accessible without token (public)   │
╰──────────────────────────────────────────────────────────╯

$ gqlhunter dashboard --db gqlhunter.db
Dashboard started at http://127.0.0.1:8080
```

## Features

| Domain | Feature |
|--------|---------|
| 🔍 **Discovery** | Endpoint discovery (18 common paths + custom) |
| 📐 **Schema** | Introspection query + 6-status classification |
| | Schema parsing & SQLite storage |
| | Cyclic schema guard (`max_depth=3`) |
| | Configurable introspection depth (`--max-depth`) ¹ |
| 🧠 **Analysis** | Risk classification (field-name heuristics) |
| | IDOR candidate detection (argument heuristics) |
| | Read-only query & mutation generator |
| | Query variant engine (single / combinations / random) ¹ |
| 🔑 **Auth** | Auth bypass analysis (with/without token) |
| | Persistent auth sessions (`--session` / `--save-session`) ¹ |
| 🔁 **Diff & Export** | Schema diff across scan runs (Added / Modified / Removed) |
| | JSON export (no tokens leaked, auth results included) |
| | SARIF export ¹ |
| 📊 **Reporting** | Markdown & HTML reports (Jinja2, XSS-guarded) |
| | Tabbed findings by severity ¹ |
| | Severity filtering (`--severity`) ¹ |
| 🖥️ **Dashboard** | Web dashboard (`gqlhunter dashboard`) ¹ |
| 📬 **Notifications** | Template-based (Slack, Telegram, Webhook) ¹ |
| 🐳 **Deployment** | Docker support |

¹ Added in v0.2.0 — all other features were in v0.1.0.

## Design Decisions

### Cyclic schema protection (`max_depth`)

The query builder uses a simple `max_depth` counter (default 3) instead of tracking
visited types to prevent infinite recursion on self-referencing schemas (e.g. `User`
→ `Post` → `User`). This is a deliberate tradeoff: it's simpler and more predictable,
but **any** chain longer than 3 levels — including legitimate non-cyclic deep nesting —
will be truncated. This is acceptable for a recon tool where the goal is lightweight
sampling, not exhaustive traversal.

### Auth analysis: same-payload comparison

The auth analyzer always sends the **identical** query payload with and without
the Authorization header. It never substitutes different `id` or `userId` values.
This avoids the false-positive risk of comparing responses to different queries.
The guardrail test (`test_guardrail_identical_payload_only_header_differs`)
proves that only the Authorization header changes between the two requests.

### Structural args comparison in diff

The `diff` command compares `args_json` structurally (`json.loads`) rather than
by raw string equality. This prevents false-positive `MODIFIED` entries when
the JSON key ordering differs between serialisations.

### XSS protection in HTML reports

HTML reports use `Jinja2.Environment(autoescape=select_autoescape(["html", "xml"]))`.
All user-controlled data from the target schema (type names, field names, descriptions)
is auto-escaped. Confirmed by `test_script_in_operation_name_is_escaped`.

## Project Structure

```
gqlhunter/
├── cli.py                          # Typer CLI (10 commands: discover, auth, scan, variants, notify, report, export, diff, batch, dashboard)
├── auth/
│   ├── auth_analyzer.py            # Auth bypass analysis (with/without token)
│   └── session.py                  # Persistent auth session save/load
├── core/
│   ├── db.py                       # SQLite storage (7 tables: scan_runs, endpoints, schema_types, operations, risk_findings, auth_results, schema_diff)
│   ├── http_client.py              # Async httpx wrapper (retry + rate-limit)
│   └── scope.py                    # Scope with allowlist/deny/wildcards, template_dir support
├── dashboard.py                    # Web dashboard (HTTPServer, /api/runs, /report/:id)
├── discovery/
│   └── endpoint_discovery.py       # 18 common GraphQL paths
├── generator/
│   └── query_builder.py            # Read-only query & mutation text generator
├── introspection/
│   └── introspection.py            # Standard introspection query + configurable depth
├── notify/
│   ├── sender.py                   # Notification dispatch (Slack, Telegram, Webhook)
│   └── templates/                  # Default Jinja2 notification templates
├── report/
│   ├── render.py                   # Markdown + HTML report rendering (Jinja2, tabbed findings)
│   └── sarif.py                    # SARIF 2.1.0 export
├── schema/
│   └── parser.py                   # Introspection JSON → parsed schema
└── variants/
    └── variant_engine.py           # Query variant generation (single / combinations / random)
```

## Development

```bash
git clone https://github.com/bess1lie/gqlhunter
cd gqlhunter

# Create venv
python3.11 -m venv .venv && source .venv/bin/activate

# Install dev deps
pip install -e ".[dev]"

# Run tests
pytest -v

# Lint
ruff check .

# Pre-commit
pre-commit install
```

## Roadmap

### v0.2.0 — Completed

- [x] Auth analysis persisted in SQLite; included in `report` and `export`
- [x] Persistent auth sessions (`--session` / `--save-session`) with cookie store
- [x] Query variant engine (single / combinations / random strategies)
- [x] Template-based notifications (Slack, Telegram, Webhook) with Jinja2 templates
- [x] Configurable introspection depth (`--max-depth`)
- [x] Tabbed HTML report (findings grouped by severity)
- [x] Web dashboard (`gqlhunter dashboard`, HTTPServer-based)
- [x] Report / export sorting and severity filtering (`--severity`)
- [x] 195 tests (up from 118)

### Planned (v0.3.0+)

- [ ] **Batch diff over N runs** — Diff across more than 2 scan runs; detect regressions
      (a previously REMOVED operation re-appears) and trends (args accumulating over time)
- [ ] **WebSocket subscription tester** — Send GraphQL subscription via WebSocket,
      capture real-time events for analysis (no auto-subscribe persistence)
- [ ] **Batch endpoint fuzzing** — Parameterised query generator: given a mutation
      `updateUser(id: ID!, role: String)`, produce N variants with different arg
      combinations (still text-only, never auto-sent)
- [ ] **VS Code extension** — Inline decorations for schema: severity badges next
      to field names, one-click `gqlhunter diff` in editor
- [ ] **OpenAPI / REST → GraphQL bridge detection** — Heuristic-based identification
      of REST endpoints that wrap GraphQL queries (common in migration-phase APIs)

## Author

**bess1lie** — [GitHub](https://github.com/bess1lie)

## License

MIT
