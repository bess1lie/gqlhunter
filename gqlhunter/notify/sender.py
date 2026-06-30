from __future__ import annotations

from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape

TEMPLATE_DIR = Path(__file__).parent / "templates"


def render_notification(
    channel: str,
    context: dict,
    template_dir: str | Path | None = None,
) -> str:
    loader = FileSystemLoader(str(template_dir or TEMPLATE_DIR))
    env = Environment(
        loader=loader,
        autoescape=True,
    )
    template = env.get_template(f"{channel}.jinja")
    return template.render(context)


def send_slack(webhook_url: str, message: str) -> None:
    import httpx
    resp = httpx.post(webhook_url, json={"text": message}, timeout=10.0)
    resp.raise_for_status()


def send_telegram(token: str, chat_id: str, message: str) -> None:
    import httpx
    url = f"https://api.telegram.org/bot{token}/sendMessage"
    resp = httpx.post(url, json={"chat_id": chat_id, "text": message}, timeout=10.0)
    resp.raise_for_status()
    data = resp.json()
    if not data.get("ok"):
        raise RuntimeError(f"Telegram API error: {data}")


def send_webhook(url: str, payload: dict) -> None:
    import httpx
    resp = httpx.post(url, json=payload, timeout=10.0)
    resp.raise_for_status()
