"""Allowlisted logging and safe exception reports for the recorder (design §8.4).

The recorder's terminal output and run log carry an allowlisted field set only: call id,
codes, timings and counts. ``SafeLogFilter`` runs the §8.1 detectors and the known-value
sets on every record; on a hit it drops the record and trips, and the recorder stops the
run. Exceptions are reported as type and code only, with no message, no arguments and no
traceback, because lxml, aiohttp and validation errors can echo input. There is no debug
mode.
"""

import logging
import re
import sys
import threading
from collections.abc import Callable
from types import TracebackType
from typing import Final, TextIO, override

from airtimesat_platform.masker.detect.patterns import find_hits
from airtimesat_platform.masker.detect.scan import (
    CallKnownValues,
    KnownValueIndex,
    cross_call_hit,
    offline_exemption,
)
from airtimesat_platform.masker.errors import MaskingError

# Fields a record may carry besides its message (passed with ``extra=``).
ALLOWED_FIELDS: Final = frozenset(
    {
        "call_id",
        "plan_id",
        "operation",
        "endpoint",
        "code",
        "detector",
        "path",
        "outcome",
        "duration_ms",
        "count",
        "dropped",
        "issued",
        "in_prefix",
        "run_utc",
        "commit",
        "decision",
        "incident",
    }
)
# A message is a code: upper-case words joined by underscores, nothing else.
_CODE: Final = re.compile(r"[A-Z][A-Z0-9_]{0,63}")
_SAFE_STRING: Final = re.compile(r"[A-Za-z0-9_.:/\-\[\]?]{0,128}")
_STANDARD: Final = frozenset(vars(logging.makeLogRecord({}))) | {"message", "asctime"}


def describe_exception(exc: BaseException) -> str:
    """Return ``<type>`` or ``<type> <code>``: never the message or the arguments."""
    name = type(exc).__name__
    if isinstance(exc, MaskingError):
        return f"{name} {exc}"
    return name


class SafeLogFilter(logging.Filter):
    """Drop any record that is not allowlisted or that a detector fires on, and trip."""

    def __init__(
        self,
        call_known: CallKnownValues | None = None,
        index: KnownValueIndex | None = None,
        on_trip: Callable[[str], None] | None = None,
    ) -> None:
        """Check records against the detectors and the given known-value sets.

        ``on_trip`` receives the reason code when a record is dropped; the recorder uses it
        to stop the run.
        """
        super().__init__()
        self._known = call_known
        self._index = index
        self._on_trip = on_trip
        self.tripped: str | None = None

    def _trip(self, reason: str) -> bool:
        self.tripped = reason
        if self._on_trip is not None:
            self._on_trip(reason)
        return False

    def _value_ok(self, value: object) -> bool:
        if isinstance(value, bool | int | float) or value is None:
            return True
        if not isinstance(value, str) or not _SAFE_STRING.fullmatch(value):
            return False
        if find_hits(value, exempt=offline_exemption()):
            return False
        if self._known is not None and self._known.found_in(value):
            return False
        return not (self._index is not None and cross_call_hit(value, self._index))

    @override
    def filter(self, record: logging.LogRecord) -> bool:
        """Return ``True`` only for an allowlisted, clean record."""
        if not isinstance(record.msg, str) or record.args or not _CODE.fullmatch(record.msg):
            return self._trip("LOG_NOT_A_CODE")
        if record.exc_info is not None or record.exc_text or record.stack_info:
            return self._trip("LOG_EXCEPTION_DETAIL")
        for key, value in vars(record).items():
            if key in _STANDARD or key.startswith("_"):
                continue
            if key not in ALLOWED_FIELDS:
                return self._trip("LOG_FIELD_NOT_ALLOWED")
            if not self._value_ok(value):
                return self._trip("LOG_DETECTOR_HIT")
        return True


def safe_excepthook(
    exc_type: type[BaseException],
    exc: BaseException,
    tb: TracebackType | None,
    stream: TextIO | None = None,
) -> None:
    """Report an uncaught exception as type and code only (replaces the traceback printer)."""
    del exc_type, tb
    out = stream if stream is not None else sys.stderr
    out.write(f"UNCAUGHT {describe_exception(exc)}\n")


def _thread_excepthook(args: threading.ExceptHookArgs) -> None:
    """Report an uncaught exception in a thread as type and code only."""
    if args.exc_value is not None:
        safe_excepthook(args.exc_type, args.exc_value, None)


def _unraisable_hook(unraisable: "sys.UnraisableHookArgs") -> None:
    """Report an unraisable exception (in a finalizer, for example) as type and code only."""
    if unraisable.exc_value is not None:
        safe_excepthook(unraisable.exc_type, unraisable.exc_value, None)


def install_excepthook() -> None:
    """Install the safe reporters for uncaught exceptions: main thread, threads, finalizers.

    Python's default printers write the message and the traceback, which can echo input.
    """
    sys.excepthook = safe_excepthook
    threading.excepthook = _thread_excepthook
    sys.unraisablehook = _unraisable_hook
