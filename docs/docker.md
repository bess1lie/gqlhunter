# Docker

Gqlhunter ships with a minimal single-stage Dockerfile. Because gqlhunter is
pure Python (no external Go tools, no subprocess calls), the image is small
and builds in seconds.

## Image layout

| Base image | `python:3.13-slim` |
|---|---|
| Stage | single |
| Working dir | `/app` |
| Entrypoint | `gqlhunter` |
| Default command | `--help` |

The Dockerfile copies `pyproject.toml`, `README.md` and the `gqlhunter/`
package, runs `pip install --no-cache-dir .`, and sets the entrypoint to
`gqlhunter`. A `.dockerignore` excludes caches and the local virtualenv.

## Build

```bash
docker build -t gqlhunter .
```

## Run ad-hoc commands

The entrypoint is `gqlhunter`, so any CLI command can be passed directly:

```bash
# help
docker run --rm gqlhunter --help

# discover endpoints (mount your scope.yaml)
docker run --rm -v $(pwd):/app gqlhunter discover https://example.com --scope /app/scope.yaml

# full scan
docker run --rm -v $(pwd):/app gqlhunter scan https://example.com/graphql --scope /app/scope.yaml

# dashboard on port 8080
docker run --rm -p 8080:8080 -v $(pwd):/app gqlhunter dashboard --db /app/gqlhunter_*.db --host 0.0.0.0
```

## docker-compose

`docker-compose.yml` is minimal:

```yaml
services:
  gqlhunter:
    build: .
    volumes:
      - .:/app
    entrypoint: ["gqlhunter"]
```

It builds the image, mounts the whole repo at `/app`, and sets the entrypoint
to `gqlhunter`. Use `docker compose run` for ad-hoc commands:

```bash
# build the image
docker compose build

# run a scan
docker compose run --rm gqlhunter scan https://example.com/graphql --scope /app/scope.yaml

# generate a report
docker compose run --rm gqlhunter report --db /app/gqlhunter_<timestamp>.db -o /app/report.md

# export to SARIF
docker compose run --rm gqlhunter export --db /app/gqlhunter_<timestamp>.db --output /app/export --sarif
```

## Database location

Gqlhunter writes timestamped databases to the current working directory by
default: `gqlhunter_<YYYYMMDD_HHMMSS>.db`. Inside the container with the
compose volume, that lands in the mounted repo on the host. To use a stable
path, pass `--db`:

```bash
docker run --rm -v $(pwd):/app gqlhunter scan https://example.com/graphql \
  --scope /app/scope.yaml --db /app/scan.db
```

## Notes

- The image uses `python:3.13-slim` while the local dev requirement is
  Python >= 3.11. CI tests against 3.11, 3.12 and 3.13.
- There is no long-running service mode — gqlhunter is a CLI. Use a container
  scheduler (cron, systemd, GitHub Actions) if you want periodic scans.
- The dashboard (`gqlhunter dashboard`) is a blocking stdlib HTTP server. Run
  it with `-p 8080:8080` and `--host 0.0.0.0` if you want it reachable from
  outside the container.
