"""Application settings read from environment variables.

Settings never hold secret values. Secrets are fetched at runtime through
``airtimesat_platform.common.secrets``.
"""

from enum import StrEnum
from functools import lru_cache
from typing import Literal

from pydantic_settings import BaseSettings, SettingsConfigDict

ENV_PREFIX = "AIRTIMESAT_"

LogLevel = Literal["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]


class Environment(StrEnum):
    """Where the app runs. Each IWS environment has its own isolated credentials."""

    LOCAL = "local"
    SITEST = "sitest"
    BETA = "beta"
    PRODUCTION = "production"


class Settings(BaseSettings):
    """Process settings. Every field maps to ``AIRTIMESAT_<FIELD>``."""

    model_config = SettingsConfigDict(
        env_prefix=ENV_PREFIX,
        extra="forbid",
        frozen=True,
    )

    environment: Environment = Environment.LOCAL
    service_name: str = "airtimesat-platform"
    log_level: LogLevel = "INFO"


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Return the process settings, read once."""
    return Settings()
