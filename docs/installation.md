# Installation

Gqlhunter v0.2.0 is a pure-Python async CLI for GraphQL recon and analysis.
It has **no external binary dependencies** — all HTTP is done with `httpx`.

## Requirements

| Requirement | Version |
|---|---|
| Python | >= 3.11 |
| pip | any |

Python dependencies (installed automatically by `pip install .`):

- `typer>=0.12.0`
- `rich>=13.7.0`
- `httpx>=0.27.0`
- `httpx-sse>=0.4.0`
- `pyyaml>=6.0`
- `jinja2>=3.1.0`
- `aiosqlite>=0.20.0`
- `markdown>=3.6.0`

No Go tools, no subprocess calls, no native extensions.

## From source

```bash
git clone https://github.com/bess1lie/gqlhunter.git
cd gqlhunter
pip install .
gqlhunter --version
```

For development, install with the dev extras and run the test suite:

```bash
pip install -e ".[dev]"
pytest
ruff check .
```

> Note: as of this writing the `dev` extra referenced by CI is not declared in
> `pyproject.toml`. If `pip install -e ".[dev]"` fails, install the dev tools
> directly: `pip install pytest ruff respx`.

## Verify the install

```bash
gqlhunter --version
# gqlhunter v0.1.0 — by bess1lie

gqlhunter --help
```

> The `--version` string in the installed package reads `0.1.0` from
> `gqlhunter/__init__.py`. The README and docs describe the v0.2.0 feature
> set. This version-label mismatch is a known issue — the code itself is at
> the v0.2.0 feature level.

## Docker alternative

```bash
docker build -t gqlhunter .
docker run --rm -v $(pwd):/app gqlhunter --help
```

The gqlhunter image is a single-stage `python:3.13-slim` build. See
[docker.md](docker.md).

## Uninstall

```bash
pip uninstall gqlhunter
```

This removes the Python package and the `gqlhunter` console script. It does
not remove timestamped SQLite databases (`gqlhunter_*.db`) you created during
scans.
