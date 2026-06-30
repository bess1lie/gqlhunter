# Examples

End-to-end workflows for gqlhunter v0.2.0. All commands assume you have
`scope.yaml` ready (see [scope.md](scope.md)) and have installed the package
(see [installation.md](installation.md)).

## 1. First-time workflow

```bash
# discover GraphQL endpoints on a target
gqlhunter discover https://example.com --scope scope.yaml

# introspect a known endpoint and store the schema
gqlhunter scan https://example.com/graphql --scope scope.yaml

# analyze authorization (with vs without token)
gqlhunter auth https://example.com/graphql \
  --scope scope.yaml \
  --db gqlhunter_20260630_120000.db \
  --auth-header "Bearer eyJhbGc..."

# generate a Markdown report
gqlhunter report --db gqlhunter_20260630_120000.db -o report.md

# or HTML
gqlhunter report --db gqlhunter_20260630_120000.db --format html -o report.html
```

## 2. Use a session file for auth

Save the header once, reuse it across commands:

```bash
# save
gqlhunter auth https://example.com/graphql \
  --scope scope.yaml \
  --db gqlhunter_20260630_120000.db \
  --auth-header "Bearer eyJhbGc..." \
  --save-session ./session.json

# reuse
gqlhunter scan https://example.com/graphql \
  --scope scope.yaml \
  --session ./session.json
```

The session file is JSON with `auth_header`, `created_at` and an optional
`endpoint`:

```json
{
  "auth_header": "Bearer eyJhbGc...",
  "created_at": "2026-06-30T12:00:00Z",
  "endpoint": "https://example.com/graphql"
}
```

`--auth-header` always takes precedence over `--session` if both are given.

## 3. Variants generation

After a `scan`, generate query variants for manual testing in your GraphQL
client:

```bash
# default strategy: single
gqlhunter variants --db gqlhunter_20260630_120000.db -o variants.json

# combinations (aliasing + arg removal + depth + standard mutation)
gqlhunter variants --db gqlhunter_20260630_120000.db \
  --strategy combinations -o variants.json

# random sample of 2 from the pool
gqlhunter variants --db gqlhunter_20260630_120000.db \
  --strategy random -o variants.json
```

Each entry in the output JSON has:

```json
{
  "variant_type": "alias|standard|arg_removal|depth",
  "operation_type": "query|mutation|subscription",
  "operation_name": "getUser",
  "query": "{ a: getUser(id: 1) b: getUser(id: 1) c: getUser(id: 1) }",
  "description": "Aliased 3x"
}
```

> Variants are **generated, not sent**. Copy them into your GraphQL client
> (GraphiQL, Postman, Burp Repeater) and send manually.

## 4. Risk findings (via `batch`)

Risk findings (field-name heuristics + IDOR candidates) are only produced by
the `batch` command. `scan` stores the schema but does not classify it.

```bash
gqlhunter batch scope.yaml --db scan.db --output ./export
```

For each target in scope:

1. Discovers GraphQL endpoints.
2. Keeps live ones (status 200–499).
3. Runs introspection and parses the schema.
4. Classifies every operation by field-name prefix:

   | Prefix | Severity |
   |---|---|
   | `delete`, `remove`, `destroy`, `drop`, `truncate`, `purge` | critical |
   | `admin`, `setRole`, `resetPassword`, `disable`, `enable` | high |
   | `update`, `create`, `add`, `edit`, `modify`, `insert`, `upsert`, `set`, `change`, `register`, `upload` | medium |
   | `get`, `list`, `search`, `find`, `query`, `lookup` | info (queries only; info findings for queries are skipped) |

5. Flags IDOR candidates — operations whose arguments include `id`,
   `userId`, `accountId`, `documentId`, `customerId`, `profileId`, `email`,
   `uid`, `guid`, `uuid` (and their snake_case variants).

## 5. Schema diff between two scans

```bash
# first scan
gqlhunter scan https://example.com/graphql --scope scope.yaml
# ... schema changes upstream ...
# second scan
gqlhunter scan https://example.com/graphql --scope scope.yaml

# diff — uses the last two scan runs by default
gqlhunter diff --db gqlhunter_*.db

# filter to one endpoint
gqlhunter diff --db gqlhunter_*.db --endpoint https://example.com/graphql
```

The output is a Rich table with `added`, `modified` and `removed` operations.
For modified operations, the detail shows what changed — e.g.
`args changed` or `return: User → UserDTO`. Argument comparison is
structural (JSON-parsed), so key ordering differences do not count as
changes.

## 6. Export to JSON + SARIF

```bash
gqlhunter export --db gqlhunter_20260630_120000.db \
  --output ./export --sarif
```

Writes to `./export/`:

| File | Contents |
|---|---|
| `endpoints.json` | discovered GraphQL endpoints |
| `operations.json` | queries, mutations, subscriptions |
| `run.json` | scan run metadata |
| `schema_types.json` | schema type objects |
| `auth_results.json` | auth classification rows |
| `risk_findings.json` | risk findings (only if `batch` was run) |
| `gqlhunter.sarif` | SARIF 2.1.0 report (only with `--sarif`) |

The SARIF file maps severity to level:

- `critical`, `high` → `error`
- `medium` → `warning`
- `low`, `info` → `note`

Drop it into GitHub Security tab or any SARIF-aware viewer.

## 7. Severity-filtered report

```bash
# only high and above
gqlhunter report --db gqlhunter_20260630_120000.db --severity high -o report.md
```

Valid severity values (lowest to highest): `info`, `low`, `medium`, `high`,
`critical`. An invalid value exits with code 1.

## 8. Dashboard

```bash
gqlhunter dashboard --db gqlhunter_20260630_120000.db
# serving on http://127.0.0.1:8080
```

Open `http://127.0.0.1:8080` in a browser. You get:

- `/` — index listing all scan runs in the DB.
- `/api/runs` — JSON list of runs.
- `/api/run/<id>` — JSON details of one run.
- `/report/<id>` — full HTML report for a run.

To bind on all interfaces (e.g. inside Docker):

```bash
gqlhunter dashboard --db gqlhunter_*.db --host 0.0.0.0 --port 8080
```

Stop with `Ctrl+C`.

## 9. Notifications after a scan

```bash
# run batch
gqlhunter batch scope.yaml --db scan.db --output ./export

# notify telegram
gqlhunter notify telegram \
  --db scan.db \
  --telegram-token 123456:ABC-DEF... \
  --telegram-chat -1001234567890

# notify slack with a custom template
gqlhunter notify slack \
  --db scan.db \
  --webhook-url https://hooks.slack.com/services/... \
  --template-dir ./my-templates
```

See [notifications.md](notifications.md) for the full template context.

## 10. Complete pipeline diagram

```
scope.yaml
   │
   ▼
gqlhunter batch scope.yaml
   │
   ├── discover     18 common GraphQL paths per target
   ├── introspect   __schema query, max_depth=3
   ├── parse        types / queries / mutations / subscriptions
   └── analyze      field-name severity + IDOR candidate detection
   │
   ▼
gqlhunter_<timestamp>.db (SQLite, 7 tables, WAL mode)
   │
   ├── gqlhunter report   → Markdown / HTML
   ├── gqlhunter export   → JSON + SARIF 2.1.0
   ├── gqlhunter diff     → schema diff (Rich table)
   ├── gqlhunter variants → query variants (JSON)
   ├── gqlhunter notify   → Slack / Telegram / Webhook
   └── gqlhunter dashboard → local HTTP server (:8080)
```

All detection is heuristic — based on field/argument names and response
status codes. No mutations are executed automatically.
