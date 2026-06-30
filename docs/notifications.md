# Notifications

Gqlhunter sends scan summaries to Slack, Telegram and generic webhooks via
the `notify` command. Unlike bountyhunt, **all credentials are passed as CLI
flags** — there are no environment variables to set.

## Channels

| Channel | Required flags | Transport |
|---|---|---|
| `slack` | `--webhook-url` | Slack incoming webhook, `{"text": message}` |
| `telegram` | `--telegram-token`, `--telegram-chat` | Bot API `sendMessage` |
| `webhook` | `--webhook-url` | Generic JSON POST |

## Sending a notification

```bash
# slack
gqlhunter notify slack \
  --db gqlhunter_20260630_120000.db \
  --webhook-url https://hooks.slack.com/services/T.../B.../...

# telegram
gqlhunter notify telegram \
  --db gqlhunter_20260630_120000.db \
  --telegram-token 123456:ABC-DEF... \
  --telegram-chat -1001234567890

# generic webhook
gqlhunter notify webhook \
  --db gqlhunter_20260630_120000.db \
  --webhook-url https://example.com/internal/hook
```

The `notify` command reads the latest scan run (or a specific one with
`--run-id`) and renders a template with the run's summary.

## Template resolution

Templates are looked up in this order:

1. `--template-dir` flag (highest priority).
2. `template_dir` (or `notify.template_dir`) in `scope.yaml`, if `--scope` is
   passed.
3. Built-in templates at `gqlhunter/notify/templates/`.

Each channel renders `{channel}.jinja` from the resolved directory. To
override the default message, drop a file named `slack.jinja`,
`telegram.jinja` or `webhook.jinja` into a directory and point gqlhunter at
it.

## Template context

Every template receives the following context variables:

| Variable | Type | Example |
|---|---|---|
| `endpoint` | str | `https://example.com/graphql` |
| `run_id` | int | `42` |
| `date` | str | `2026-06-30 12:00:00` |
| `endpoints` | list | discovered endpoints |
| `operations` | list | queries/mutations/subscriptions |
| `schema_types` | list | schema type objects |
| `auth_results` | list | auth classification rows |
| `risk_findings` | list | risk findings (severity, category, detail) |

Jinja2 autoescape is enabled, so HTML in findings is escaped.

## Built-in templates

### `slack.jinja` and `telegram.jinja`

Plain-text summary:

```
gqlhunter scan report — {{ endpoint }}
Run ID: {{ run_id }}
Date: {{ date }}

Introspection: {{ endpoints|length }} endpoint(s)
Operations: {{ operations|length }} operation(s)
Schema types: {{ schema_types|length }} type(s)
Auth results: {{ auth_results|length }} endpoint(s)
Risk findings: {{ risk_findings|length }} finding(s)
```

### `webhook.jinja`

JSON payload:

```json
{
  "event": "gqlhunter_scan",
  "endpoint": "{{ endpoint }}",
  "run_id": {{ run_id }},
  "date": "{{ date }}",
  "summary": {
    "endpoints": {{ endpoints|length }},
    "operations": {{ operations|length }},
    "schema_types": {{ schema_types|length }},
    "auth_results": {{ auth_results|length }},
    "risk_findings": {{ risk_findings|length }}
  }
}
```

For the `webhook` channel, the rendered string is parsed as JSON and sent as
a JSON payload. For `slack` and `telegram`, the rendered string is sent as
the message text.

## Custom template example

```bash
mkdir my-templates
cat > my-templates/slack.jinja <<'EOF'
🚨 gqlhunter — {{ endpoint }}
Run {{ run_id }} on {{ date }}
Findings: {{ risk_findings|length }} ({{ auth_results|length }} auth results)
EOF
```

```bash
gqlhunter notify slack \
  --db gqlhunter_*.db \
  --webhook-url https://hooks.slack.com/services/... \
  --template-dir ./my-templates
```

## Delivery semantics

- **Slack**: `httpx.post(webhook_url, json={"text": message}, timeout=10)`,
  raises on non-2xx.
- **Telegram**: POST to `https://api.telegram.org/bot{token}/sendMessage`
  with `chat_id` and `text`. Checks `data["ok"]`, raises `RuntimeError` on
  failure.
- **Webhook**: `httpx.post(url, json=payload, timeout=10)`, raises on
  non-2xx. The rendered template is parsed as JSON before sending.

## What `notify` does NOT do

- It does **not** run a scan. It reads an existing database.
- It does **not** send a diff. There is no `monitor`/baseline flow like
  bountyhunt — gqlhunter sends a snapshot of the latest run.
- It does **not** include raw secret values (gqlhunter does not store
  secrets).

## Triggering notifications after a batch

The `batch` command runs discovery + introspection + risk analysis across
multiple targets but does **not** send notifications itself. Pipe it
manually:

```bash
# 1. batch scan
gqlhunter batch scope.yaml --db scan.db --output ./export

# 2. notify from the resulting DB
gqlhunter notify telegram --db scan.db \
  --telegram-token 123456:ABC-DEF... \
  --telegram-chat -1001234567890
```

## Exit codes

- Missing required flags for a channel → exit 1.
- Unknown channel (not `slack`/`telegram`/`webhook`) → exit 1.
- HTTP failure from the target service → raises (non-zero exit).
