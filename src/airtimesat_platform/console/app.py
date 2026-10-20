"""Console application factory.

Run locally with
``uv run uvicorn --factory airtimesat_platform.console.app:create_app``.
"""

from typing import Literal, TypedDict

from fastapi import FastAPI

from airtimesat_platform.common.config import Settings, get_settings
from airtimesat_platform.common.log import configure_logging


class Health(TypedDict):
    """Body of the health response."""

    status: Literal["ok"]


def create_app(settings: Settings | None = None) -> FastAPI:
    """Build the console app."""
    settings = settings or get_settings()
    configure_logging(settings.log_level, settings.service_name)

    app = FastAPI(
        title="Airtimesat Ops console",
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
    )

    @app.get("/healthz", include_in_schema=False)
    def healthz() -> Health:
        """Report that the process is up. Checks no dependency."""
        return {"status": "ok"}

    return app
