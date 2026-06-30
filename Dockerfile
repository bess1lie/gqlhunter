FROM python:3.13-slim

WORKDIR /app

COPY pyproject.toml README.md ./
COPY gqlhunter/ gqlhunter/

RUN pip install --no-cache-dir .

ENTRYPOINT ["gqlhunter"]
CMD ["--help"]
