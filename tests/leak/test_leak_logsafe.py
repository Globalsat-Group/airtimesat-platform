"""Log leak tests: no canary reaches terminal output or a log record (design §8.2, §8.4)."""

import io
import logging
import sys
import threading
from collections.abc import Callable

import pytest

from airtimesat_platform.masker.detect.canary import canary
from airtimesat_platform.masker.detect.scan import CallKnownValues
from airtimesat_platform.masker.engine import MaskingEngine
from airtimesat_platform.masker.errors import MaskingError, RequestRefusedError
from airtimesat_platform.masker.logsafe import (
    SafeLogFilter,
    describe_exception,
    install_excepthook,
    safe_excepthook,
)

Envelope = Callable[..., bytes]
NS = 'xmlns:ns="urn:example:iws"'


def record(msg: object, *args: object, **extra: object) -> logging.LogRecord:
    rec = logging.LogRecord("recorder", logging.INFO, __file__, 1, msg, args or None, None)
    for key, value in extra.items():
        setattr(rec, key, value)
    return rec


def test_clean_code_records_pass() -> None:
    log_filter = SafeLogFilter()
    assert log_filter.filter(record("CALL_OK", call_id="search", duration_ms=12, count=3))
    assert log_filter.tripped is None


@pytest.mark.parametrize(
    ("rec", "reason"),
    [
        (record("call %s ok", canary("IMEI", 1)), "LOG_NOT_A_CODE"),
        (record(f"value {canary('IMEI', 1)}"), "LOG_NOT_A_CODE"),
        (record(["not", "a", "string"]), "LOG_NOT_A_CODE"),
        (record("CALL_OK", body="<xml/>"), "LOG_FIELD_NOT_ALLOWED"),
        (record("CALL_OK", path=canary("IMEI", 1)), "LOG_DETECTOR_HIT"),
        (record("CALL_OK", path=canary("EMAIL", 1)), "LOG_DETECTOR_HIT"),
        (record("CALL_OK", path="has spaces and words"), "LOG_DETECTOR_HIT"),
        (record("CALL_OK", count=object()), "LOG_DETECTOR_HIT"),
    ],
)
def test_unsafe_records_are_dropped_and_trip(rec: logging.LogRecord, reason: str) -> None:
    tripped: list[str] = []
    log_filter = SafeLogFilter(on_trip=tripped.append)
    assert not log_filter.filter(rec)
    assert log_filter.tripped == reason
    assert tripped == [reason]


def test_exception_details_are_dropped() -> None:
    try:
        raise ValueError(canary("IMEI", 2))
    except ValueError:
        rec = logging.LogRecord("r", logging.ERROR, __file__, 1, "FAILED", None, sys.exc_info())
    log_filter = SafeLogFilter()
    assert not log_filter.filter(rec)
    assert log_filter.tripped == "LOG_EXCEPTION_DETAIL"


def test_known_values_trip_the_filter() -> None:
    known = CallKnownValues()
    known.add("canary-login-name", "user-abcdefgh")
    log_filter = SafeLogFilter(call_known=known)
    assert not log_filter.filter(record("CALL_OK", path="canary-login-name"))

    class Index:
        def is_known(self, value: str) -> bool:
            return value == "canary-org"

    log_filter = SafeLogFilter(index=Index())
    assert not log_filter.filter(record("CALL_OK", path="canary-org"))


def test_filter_on_a_logger_stops_the_record(caplog: pytest.LogCaptureFixture) -> None:
    logger = logging.getLogger("test.logsafe")
    log_filter = SafeLogFilter()
    logger.addFilter(log_filter)
    try:
        with caplog.at_level(logging.INFO, logger="test.logsafe"):
            logger.info("RUN_STARTED", extra={"plan_id": "RP-2026-001"})
            logger.info("leaking %s", canary("MSISDN", 1))
    finally:
        logger.removeFilter(log_filter)
    assert [r.getMessage() for r in caplog.records] == ["RUN_STARTED"]
    assert canary("MSISDN", 1) not in caplog.text


def test_describe_exception_never_includes_the_message() -> None:
    assert describe_exception(ValueError(canary("IMEI", 3))) == "ValueError"
    error = RequestRefusedError("NOT_A_SURROGATE", path="request/filterValue", detector="IMEI")
    assert describe_exception(error) == (
        "RequestRefusedError NOT_A_SURROGATE path=request/filterValue detector=IMEI"
    )


def test_safe_excepthook_prints_type_only(monkeypatch: pytest.MonkeyPatch) -> None:
    stream = io.StringIO()
    safe_excepthook(KeyError, KeyError(canary("ICCID", 1)), None, stream)
    assert stream.getvalue() == "UNCAUGHT KeyError\n"
    monkeypatch.setattr(sys, "excepthook", sys.__excepthook__)
    monkeypatch.setattr(threading, "excepthook", threading.__excepthook__)
    monkeypatch.setattr(sys, "unraisablehook", sys.__unraisablehook__)
    install_excepthook()
    assert sys.excepthook is safe_excepthook
    assert threading.excepthook is not threading.__excepthook__
    assert sys.unraisablehook is not sys.__unraisablehook__
    monkeypatch.setattr(sys, "stderr", stream)
    safe_excepthook(ValueError, ValueError("x"), None)
    assert stream.getvalue().endswith("UNCAUGHT ValueError\n")


def test_every_engine_error_path_is_free_of_canaries(
    engine: MaskingEngine, envelope: Envelope
) -> None:
    """Drive error paths with canary data; no canary may appear in what would be logged."""
    values = [canary("IMEI", 9), canary("MSISDN", 9), canary("EMAIL", 9), "Canary Vessel 9"]
    bodies = [
        envelope(
            f"<ns:getSubscriberAccountResponse {NS}>"
            '<account xsi:type="ns:sbdSubscriberAccountImpl">'
            f"<imei>{values[0]}</imei><extra{values[1]}>{values[2]}</extra{values[1]}>"
            "</account></ns:getSubscriberAccountResponse>"
        ),
        envelope(
            f"<ns:getSubscriberAccountResponse {NS}>"
            '<account xsi:type="ns:sbdSubscriberAccountImpl">'
            f"<accountStatus>{values[3]} {values[1]}</accountStatus>"
            "</account></ns:getSubscriberAccountResponse>"
        ),
        f"<html>{values[0]}</html>".encode(),
        f"<broken {values[2]}".encode(),
    ]
    requests = [
        f"<request><filterType>IMEI</filterType><filterValue>{values[0]}</filterValue></request>".encode(),
        f"<request><filterType>X</filterType><comment>{values[2]}</comment></request>".encode(),
    ]
    errors: list[MaskingError] = []
    for body in bodies:
        with pytest.raises(MaskingError) as info:
            engine.mask_response(engine.start_call("getSubscriberAccount"), body)
        errors.append(info.value)
    for body in requests:
        with pytest.raises(MaskingError) as info:
            engine.unmask_request(engine.start_call("accountSearch"), body)
        errors.append(info.value)
    log_filter = SafeLogFilter()
    for error in errors:
        for message in (str(error), repr(error), describe_exception(error)):
            for value in values:
                assert value.casefold() not in message.casefold()
        fields = {"code": error.code, "path": error.path, "detector": error.detector}
        assert log_filter.filter(record("CALL_BLOCKED", **fields)), error.code
