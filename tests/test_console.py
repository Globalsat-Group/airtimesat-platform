"""Console smoke tests.

Requests go straight to the ASGI app, so the tests need no HTTP client library.
"""

import asyncio
import json

from fastapi import FastAPI
from starlette.types import Message, Scope

from airtimesat_platform.common.config import Settings
from airtimesat_platform.console.app import create_app


def _get(app: FastAPI, path: str) -> tuple[int, bytes]:
    """Send one GET request to ``app`` and return the status code and body."""
    scope: Scope = {
        "type": "http",
        "asgi": {"version": "3.0"},
        "http_version": "1.1",
        "method": "GET",
        "scheme": "http",
        "path": path,
        "raw_path": path.encode(),
        "query_string": b"",
        "root_path": "",
        "headers": [(b"host", b"testserver")],
        "client": ("127.0.0.1", 50000),
        "server": ("testserver", 80),
    }
    sent: list[Message] = []

    async def receive() -> Message:
        return {"type": "http.request", "body": b"", "more_body": False}

    async def send(message: Message) -> None:
        sent.append(message)

    asyncio.run(app(scope, receive, send))
    status = next(m["status"] for m in sent if m["type"] == "http.response.start")
    body = b"".join(m.get("body", b"") for m in sent if m["type"] == "http.response.body")
    return status, body


def test_healthz_returns_ok() -> None:
    status, body = _get(create_app(Settings()), "/healthz")
    assert status == 200
    assert json.loads(body) == {"status": "ok"}


def test_api_docs_are_not_exposed() -> None:
    app = create_app(Settings())
    for path in ("/docs", "/redoc", "/openapi.json"):
        status, _ = _get(app, path)
        assert status == 404
