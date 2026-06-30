# Scope

Every network action in gqlhunter is gated by a YAML scope file. A target
whose host is not in scope is refused **before** any request leaves the host.

## File format

Gqlhunter's `Scope.from_yaml` reads three keys:

```yaml
targets:
  - "*.trevorblades.com"
  - "!admin.trevorblades.com"

allowlist:
  - "*.trevorblades.com"

template_dir: ./templates
# or, equivalently:
# notify:
#   template_dir: ./templates
```

| Key | Purpose |
|---|---|
| `targets` | List of host patterns to scan. Entries starting with `!` are **deny** patterns. |
| `allowlist` | Fallback host patterns used by `is_in_scope` / `can_scan` when `targets` is empty. |
| `template_dir` | Optional path to custom Jinja2 templates for the `notify` command. Can also be nested under `notify.template_dir`. |

### Important: `deny:` is not read

The `Scope` class **only reads `targets`, `allowlist` and `template_dir`**. A
top-level `deny:` key in the YAML file is silently ignored. To deny a host,
prefix the entry with `!` inside `targets`:

```yaml
# correct — admin.trevorblades.com is denied
targets:
  - "*.trevorblades.com"
  - "!admin.trevorblades.com"
```

```yaml
# WRONG — deny: is ignored, admin.trevorblades.com would still match *.trevorblades.com
targets:
  - "*.trevorblades.com"
deny:
  - "admin.trevorblades.com"
```

## Matching rules

Matching uses `fnmatch.fnmatch` (shell-style globs), not bountyhunt's
suffix-based matcher.

- `*.example.com` matches `sub.example.com`, `api.example.com`, etc.
- `*.example.com` does **not** match `example.com` itself (fnmatch requires
  the `*.` prefix to match something).
- `can_scan("example.com")` with `targets: ["*.example.com"]` returns False —
  unlike bountyhunt, gqlhunter does not treat the bare apex as a valid scan
  target for wildcards. Add the bare domain explicitly if you want it:

```yaml
targets:
  - "example.com"
  - "*.example.com"
```

## URL-based scope

Gqlhunter checks scope on **URLs**, not bare domains. `is_in_scope(url)`
extracts `urlparse(url).hostname` and delegates to `can_scan(host)`. This
means you pass the full endpoint URL to the scope check:

```python
scope.is_in_scope("https://api.example.com/graphql")  # True
scope.is_in_scope("https://evil.com/graphql")          # False
```

## How `can_scan` decides

1. If `targets` and `allowlist` are both empty → False.
2. Split `targets` into deny patterns (those starting with `!`) and allow
   patterns (the rest).
3. If the host matches any deny pattern → False.
4. If there are allow patterns in `targets` → host must match one, else False.
5. Else if there are patterns in `allowlist` → host must match one, else
   False.
6. Else False.

## Example scopes

### Single public demo API

```yaml
targets:
  - "*.trevorblades.com"
allowlist:
  - "*.trevorblades.com"
```

### Multiple programs with exclusions

```yaml
targets:
  - "api.example.com"
  - "*.example.com"
  - "!status.example.com"
  - "!admin.example.com"
allowlist:
  - "*.example.com"
template_dir: ./my-templates
```

## Using the scope file

Commands that touch the network require `--scope`:

```bash
gqlhunter discover https://example.com --scope scope.yaml
gqlhunter scan https://example.com/graphql --scope scope.yaml
gqlhunter auth https://example.com/graphql --scope scope.yaml --auth-header "Bearer ..."
gqlhunter batch scope.yaml
```

If a target's host is out of scope, the command exits with code 1 and prints
an error — no request is sent.

## Custom notification templates

Set `template_dir` (or `notify.template_dir`) to a directory containing
`slack.jinja`, `telegram.jinja` and/or `webhook.jinja`. See
[notifications.md](notifications.md) for the template context and how to
override at the CLI with `--template-dir`.
