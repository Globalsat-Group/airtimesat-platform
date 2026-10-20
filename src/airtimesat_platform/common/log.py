"""Structured logging: one JSON object per line on stdout."""

import json
import logging
import sys
from datetime import UTC, datetime
from typing import Any, override

# Attributes every LogRecord has. Anything else was passed through ``extra=`` and is emitted.
_STANDARD_ATTRS = frozenset(vars(logging.makeLogRecord({}))) | {"message", "asctime"}


class JsonFormatter(logging.Formatter):
    """Format a record as a single-line JSON object."""

    def __init__(self, service_name: str) -> None:
        """Tag every record with ``service_name``."""
        super().__init__()
        self._service_name = service_name

    @override
    def format(self, record: logging.LogRecord) -> str:
        """Return the record as JSON; values that are not JSON types are rendered with str()."""
        payload: dict[str, Any] = {
            "ts": datetime.fromtimestamp(record.created, tz=UTC).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "service": self._service_name,
            "message": record.getMessage(),
        }
        for key, value in vars(record).items():
            if key not in _STANDARD_ATTRS and not key.startswith("_"):
                payload[key] = value
        if record.exc_info:
            payload["exc_info"] = self.formatException(record.exc_info)
        return json.dumps(payload, default=str, ensure_ascii=False)


def configure_logging(level: str, service_name: str) -> None:
    """Send all logs to stdout as JSON at ``level``. Safe to call more than once."""
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(JsonFormatter(service_name))
    root = logging.getLogger()
    root.handlers[:] = [handler]
    root.setLevel(level)
