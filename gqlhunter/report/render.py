from __future__ import annotations

from typing import Any

from jinja2 import BaseLoader, Environment, select_autoescape

from gqlhunter import __version__

SEVERITY_COLORS = {
    "critical": "#dc3545",
    "high": "#fd7e14",
    "medium": "#ffc107",
    "low": "#6c757d",
    "info": "#0d6efd",
}

HTML_TEMPLATE = """\
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>gqlhunter — GraphQL Schema Report</title>
<style>
  body {
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
    margin: 0; padding: 20px; background: #f8f9fa; color: #212529;
  }
  .container {
    max-width: 960px; margin: 0 auto; background: #fff; padding: 24px;
    border-radius: 8px; box-shadow: 0 1px 3px rgba(0,0,0,.1);
  }
  h1 { margin-top: 0; color: #212529; }
  h2 { border-bottom: 2px solid #dee2e6; padding-bottom: 8px; margin-top: 32px; }
  table { width: 100%; border-collapse: collapse; margin: 16px 0; }
  th, td { padding: 8px 12px; text-align: left; border-bottom: 1px solid #dee2e6; }
  th { background: #e9ecef; font-weight: 600; }
  code { background: #e9ecef; padding: 2px 6px; border-radius: 4px; font-size: .875em; }
  .meta { color: #6c757d; font-size: .875em; }
  .severity-tag {
    display: inline-block; padding: 2px 8px; border-radius: 4px; color: #fff;
    font-size: .75em; font-weight: 700; text-transform: uppercase;
  }
  .disclaimer {
    background: #fff3cd; border: 1px solid #ffc107; border-radius: 4px;
    padding: 12px 16px; margin-bottom: 24px; font-size: .875em;
  }
  .tabs { display: flex; gap: 4px; margin-bottom: 16px; flex-wrap: wrap; }
  .tab-btn {
    padding: 6px 16px; border: 1px solid #dee2e6; border-radius: 4px 4px 0 0;
    background: #f8f9fa; cursor: pointer; font-size: .875em; font-weight: 600;
    transition: background .15s;
  }
  .tab-btn:hover { background: #e9ecef; }
  .tab-btn.active { background: #fff; border-bottom-color: #fff; }
  .tab-content { display: none; }
  .tab-content.active { display: block; }
  .empty { color: #6c757d; font-style: italic; }
  .footer {
    margin-top: 32px; padding-top: 16px; border-top: 1px solid #dee2e6;
    font-size: .75em; color: #6c757d;
  }
  .findings-count {
    display: inline-block; padding: 0 6px; border-radius: 8px;
    font-size: .75em; font-weight: 700; color: #fff; margin-left: 4px;
  }
</style>
<script>
function showTab(severity) {
  document.querySelectorAll('.tab-content').forEach(function(el) {
    el.classList.remove('active');
  });
  document.querySelectorAll('.tab-btn').forEach(function(el) {
    el.classList.remove('active');
  });
  var content = document.getElementById('findings-' + severity);
  var btn = document.querySelector('[data-severity="' + severity + '"]');
  if (content) content.classList.add('active');
  if (btn) btn.classList.add('active');
}
</script>
</head>
<body>
<div class="container">

<div class="disclaimer">
  <strong>Disclaimer:</strong> All findings below are <strong>heuristic</strong> —
  based on field/argument names. "Potential" means manual verification is required,
  <em>not</em> confirmed vulnerability. This tool performs detection-only analysis;
  mutations are never executed automatically.
</div>

<h1>gqlhunter — GraphQL Schema Report</h1>
<p class="meta">
  <strong>Target:</strong> {{ target }}<br>
  <strong>Scan Run ID:</strong> {{ scan_run_id }}<br>
  <strong>Date:</strong> {{ date }}
</p>

<h2>Discovered Endpoints</h2>
{% if endpoints %}
<table>
  <thead><tr><th>URL</th><th>Status</th></tr></thead>
  <tbody>
  {% for ep in endpoints %}
    <tr><td><code>{{ ep.url }}</code></td><td><code>{{ ep.status }}</code></td></tr>
  {% endfor %}
  </tbody>
</table>
{% else %}
<p class="empty">No endpoints discovered.</p>
{% endif %}

<h2>Schema Overview</h2>
{% if schema %}
  <p>
    <strong>Query Type:</strong> <code>{{ schema.query_type }}</code><br>
    <strong>Mutation Type:</strong> <code>{{ schema.mutation_type or "—" }}</code><br>
    <strong>Subscription Type:</strong> <code>{{ schema.subscription_type or "—" }}</code><br>
    <strong>Total Types:</strong> {{ schema.total_types }}
  </p>

  <h3>Queries ({{ schema.queries | length }})</h3>
  {% if schema.queries %}
  <table>
    <thead><tr><th>Field</th><th>Return Type</th><th>Args</th></tr></thead>
    <tbody>
    {% for q in schema.queries %}
      <tr>
        <td><code>{{ q.name }}</code></td>
        <td><code>{{ q.return_type or "—" }}</code></td>
        <td>{{ q.args | join(", ") }}</td>
      </tr>
    {% endfor %}
    </tbody>
  </table>
  {% else %}
    <p class="empty">No queries.</p>
  {% endif %}

  {% if schema.mutations %}
  <h3>Mutations ({{ schema.mutations | length }})</h3>
  <table>
    <thead><tr><th>Field</th><th>Return Type</th><th>Args</th></tr></thead>
    <tbody>
    {% for m in schema.mutations %}
      <tr>
        <td><code>{{ m.name }}</code></td>
        <td><code>{{ m.return_type or "—" }}</code></td>
        <td>{{ m.args | join(", ") }}</td>
      </tr>
    {% endfor %}
    </tbody>
  </table>
  {% endif %}
{% else %}
  <p class="empty">No schema data available.</p>
{% endif %}

<h2>Risk Findings</h2>
{% if findings_groups %}
<div class="tabs">
  {% for severity, label, color, items in findings_groups %}
  {% if items %}
  <button class="tab-btn {{ 'active' if loop.first else '' }}" data-severity="{{ severity }}" onclick="showTab('{{ severity }}')">
    {{ label }}
    <span class="findings-count" style="background: {{ color }}">{{ items | length }}</span>
  </button>
  {% endif %}
  {% endfor %}
</div>

{% for severity, label, color, items in findings_groups %}
{% if items %}
<div id="findings-{{ severity }}" class="tab-content {{ 'active' if loop.first else '' }}">
  <table>
    <thead><tr><th>Category</th><th>Detail</th></tr></thead>
    <tbody>
    {% for f in items %}
      <tr>
        <td>{{ f.category }}</td>
        <td>{{ f.detail or "—" }}</td>
      </tr>
    {% endfor %}
    </tbody>
  </table>
</div>
{% endif %}
{% endfor %}
{% else %}
  <p class="empty">No heuristic risk findings.</p>
{% endif %}

<h2>Auth Analysis</h2>
{% if auth_results %}
<table>
  <thead><tr><th>Endpoint</th><th>Classification</th><th>Without Token</th><th>With Token</th></tr></thead>
  <tbody>
  {% for a in auth_results %}
    <tr>
      <td><code>{{ a.endpoint }}</code></td>
      <td><span class="severity-tag" style="background: {{ _severity_color('high') if a.classification in ('over_permissive',) else _severity_color('medium') if a.classification == 'public' else _severity_color('low') }}">{{ a.classification }}</span></td>
      <td>{{ a.without_token_status }}</td>
      <td>{{ a.with_token_status }}</td>
    </tr>
  {% endfor %}
  </tbody>
</table>
{% else %}
<p class="empty">No auth analysis results. Run <code>gqlhunter auth</code> first.</p>
{% endif %}

<div class="footer">
  Report generated by <a href="https://github.com/bess1lie/gqlhunter">gqlhunter</a> v{{ version }}
</div>

</div>
</body>
</html>"""

MARKDOWN_TEMPLATE = """\
# gqlhunter — GraphQL Schema Report

> **Disclaimer:** All findings below are **heuristic** — based on field/argument names.
> "Potential" means manual verification is required, *not* confirmed vulnerability.
> This tool performs detection-only analysis; mutations are never executed automatically.

**Target:** {{ target }}
**Scan Run ID:** {{ scan_run_id }}
**Date:** {{ date }}

---

## Discovered Endpoints

{% for ep in endpoints %}
- **{{ ep.url }}** — status: `{{ ep.status }}`
{% else %}
*No endpoints discovered.*
{% endfor %}

---

## Schema Overview

{% if schema %}
- **Query Type:** `{{ schema.query_type }}`
- **Mutation Type:** `{{ schema.mutation_type or "—" }}`
- **Subscription Type:** `{{ schema.subscription_type or "—" }}`
- **Total Types:** {{ schema.total_types }}

### Queries ({{ schema.queries | length }})

| Field | Return Type | Args |
|-------|-------------|------|
{% for q in schema.queries %}| `{{- q.name -}}` | `{{- q.return_type or "—" -}}` | {{ q.args | join(", ") }} |
{% endfor %}

{% if schema.mutations %}
### Mutations ({{ schema.mutations | length }})

| Field | Return Type | Args |
|-------|-------------|------|
{% for m in schema.mutations %}| `{{- m.name -}}` | `{{- m.return_type or "—" -}}` | {{ m.args | join(", ") }} |
{% endfor %}
{% endif %}
{% else %}
*No schema data available.*
{% endif %}

---

## Risk Findings

{% if findings %}
| Severity | Category | Detail |
|----------|----------|--------|
{% for f in findings %}| **{{ f.severity }}** | {{ f.category }} | {{ f.detail }} |
{% endfor %}
{% else %}
*No heuristic risk findings.*
{% endif %}

---

## Auth Analysis

{% if auth_results %}
| Endpoint | Classification | Without Token | With Token |
|----------|---------------|---------------|------------|
{% for a in auth_results %}| `{{- a.endpoint -}}` | **{{ a.classification }}** | {{ a.without_token_status }} | {{ a.with_token_status }} |
{% endfor %}
{% else %}
*No auth analysis results. Run `gqlhunter auth` first.*
{% endif %}

---

*Report generated by [gqlhunter](https://github.com/bess1lie/gqlhunter) v{{ version }}*
"""


def _severity_color(severity: str) -> str:
    return SEVERITY_COLORS.get(severity, "#6c757d")


def _html_env() -> Environment:
    return Environment(
        loader=BaseLoader(),
        autoescape=select_autoescape(["html", "xml"]),
    )


def render_markdown(
    target: str,
    scan_run_id: int,
    date: str,
    endpoints: list[dict[str, Any]],
    schema: dict[str, Any] | None,
    findings: list[dict[str, Any]],
    auth_results: list[dict[str, Any]] | None = None,
) -> str:
    template = Environment(
        loader=BaseLoader(), autoescape=False
    ).from_string(MARKDOWN_TEMPLATE)
    return template.render(
        target=target,
        scan_run_id=scan_run_id,
        date=date,
        endpoints=endpoints,
        schema=schema,
        findings=findings,
        auth_results=auth_results or [],
        version=__version__,
    )


SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]
SEVERITY_LABELS = {
    "critical": "Critical", "high": "High", "medium": "Medium",
    "low": "Low", "info": "Info",
}


def _group_by_severity(findings: list[dict[str, Any]]) -> list[tuple[str, str, str, list[dict[str, Any]]]]:
    groups: dict[str, list[dict[str, Any]]] = {}
    for f in findings:
        sev = f.get("severity", "info")
        groups.setdefault(sev, []).append(f)
    result: list[tuple[str, str, str, list[dict[str, Any]]]] = []
    for sev in SEVERITY_ORDER:
        items = groups.get(sev, [])
        if items:
            result.append((sev, SEVERITY_LABELS.get(sev, sev), _severity_color(sev), items))
    return result


def render_html(
    target: str,
    scan_run_id: int,
    date: str,
    endpoints: list[dict[str, Any]],
    schema: dict[str, Any] | None,
    findings: list[dict[str, Any]],
    auth_results: list[dict[str, Any]] | None = None,
) -> str:
    env = _html_env()
    env.globals["_severity_color"] = _severity_color
    template = env.from_string(HTML_TEMPLATE)
    return template.render(
        target=target,
        scan_run_id=scan_run_id,
        date=date,
        endpoints=endpoints,
        schema=schema,
        findings=findings,
        findings_groups=_group_by_severity(findings),
        auth_results=auth_results or [],
        version=__version__,
    )
