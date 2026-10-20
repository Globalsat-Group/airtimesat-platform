"""Tests for common: config, logging and the secrets interface."""

import json
import logging

import pytest
from pydantic import ValidationError

from airtimesat_platform.common.config import Environment, Settings, get_settings
from airtimesat_platform.common.log import JsonFormatter, configure_logging
from airtimesat_platform.common.secrets import (
    SecretNotAvailableError,
    SecretsProvider,
    SecretValue,
    UnconfiguredSecretsProvider,
)


def test_settings_defaults(monkeypatch: pytest.MonkeyPatch) -> None:
    for var in ("AIRTIMESAT_ENVIRONMENT", "AIRTIMESAT_LOG_LEVEL", "AIRTIMESAT_SERVICE_NAME"):
        monkeypatch.delenv(var, raising=False)
    settings = Settings()
    assert settings.environment is Environment.LOCAL
    assert settings.log_level == "INFO"


def test_settings_read_prefixed_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AIRTIMESAT_ENVIRONMENT", "sitest")
    monkeypatch.setenv("AIRTIMESAT_LOG_LEVEL", "DEBUG")
    settings = Settings()
    assert settings.environment is Environment.SITEST
    assert settings.log_level == "DEBUG"


def test_settings_reject_unknown_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AIRTIMESAT_ENVIRONMENT", "staging")
    with pytest.raises(ValidationError):
        Settings()


def test_get_settings_is_cached() -> None:
    get_settings.cache_clear()
    assert get_settings() is get_settings()
    get_settings.cache_clear()


def test_json_formatter_emits_one_json_object() -> None:
    record = logging.makeLogRecord(
        {"name": "t", "levelno": logging.INFO, "levelname": "INFO", "msg": "hello %s"}
    )
    record.args = ("world",)
    record.request_id = "r-1"
    line = JsonFormatter("svc").format(record)
    payload = json.loads(line)
    assert payload["message"] == "hello world"
    assert payload["service"] == "svc"
    assert payload["level"] == "INFO"
    assert payload["request_id"] == "r-1"
    assert "\n" not in line


def test_configure_logging_replaces_handlers() -> None:
    root = logging.getLogger()
    saved_handlers, saved_level = root.handlers[:], root.level
    try:
        configure_logging("WARNING", "svc")
        configure_logging("WARNING", "svc")
        assert len(root.handlers) == 1
        assert isinstance(root.handlers[0].formatter, JsonFormatter)
        assert root.level == logging.WARNING
    finally:
        root.handlers[:] = saved_handlers
        root.setLevel(saved_level)


def test_secret_value_never_prints_itself() -> None:
    secret = SecretValue("not-a-real-secret")
    assert "not-a-real-secret" not in str(secret)
    assert "not-a-real-secret" not in repr(secret)
    assert "not-a-real-secret" not in f"{secret}"
    assert secret.reveal() == "not-a-real-secret"
    assert secret == SecretValue("not-a-real-secret")
    assert secret != SecretValue("other")


def test_unconfigured_provider_refuses_without_echoing_values() -> None:
    provider: SecretsProvider = UnconfiguredSecretsProvider()
    with pytest.raises(SecretNotAvailableError, match="iws/sitest"):
        provider.get_secret("iws/sitest")
