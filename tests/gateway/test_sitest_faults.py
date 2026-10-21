"""Reading IWS replies: SOAP 1.2 check and fault codes only (design §5.8, §8.4)."""

import pytest

from airtimesat_platform.gateway.errors import IwsThrottledError, ResponseError
from airtimesat_platform.gateway.faults import FaultSummary, raise_if_throttled, read_reply

SOAP = "http://www.w3.org/2003/05/soap-envelope"


def _fault(code_value: str, detail: str) -> bytes:
    return (
        f'<soap:Envelope xmlns:soap="{SOAP}"><soap:Body><soap:Fault>'
        f"<soap:Code><soap:Value>{code_value}</soap:Value></soap:Code>"
        '<soap:Reason><soap:Text xml:lang="en">Account SUB-9004217 not found</soap:Text>'
        f"</soap:Reason>{detail}</soap:Fault></soap:Body></soap:Envelope>"
    ).encode()


def test_success_reply_has_no_fault() -> None:
    body = (
        f'<soap:Envelope xmlns:soap="{SOAP}"><soap:Body>'
        '<ns:accountSearchResponse xmlns:ns="http://www.iridium.com"/></soap:Body></soap:Envelope>'
    ).encode()
    assert read_reply(body) is None


@pytest.mark.parametrize("code", ["AUTH", "CONFIG", "FIELD", "SYS"])
def test_error_code_is_read_from_the_detail(code: str) -> None:
    detail = (
        '<soap:Detail><ns:IWSException xmlns:ns="http://www.iridium.com">'
        f"<errorCode>{code}</errorCode><message>Account SUB-9004217 not found</message>"
        "</ns:IWSException></soap:Detail>"
    )
    summary = read_reply(_fault("soap:Receiver", detail))
    assert summary == FaultSummary(soap_code="Receiver", error_code=code)
    assert summary is not None
    assert summary.outcome == code


def test_fault_without_a_known_code_is_unknown() -> None:
    summary = read_reply(_fault("soap:Sender", "<soap:Detail><x>BOGUS</x></soap:Detail>"))
    assert summary is not None
    assert summary.soap_code == "Sender"
    assert summary.outcome == "unknown"


def test_fault_without_detail_or_code() -> None:
    summary = read_reply(
        f'<soap:Envelope xmlns:soap="{SOAP}"><soap:Body><soap:Fault/></soap:Body>'
        "</soap:Envelope>".encode()
    )
    assert summary == FaultSummary(soap_code="unknown", error_code=None)


def test_fault_summary_holds_no_text() -> None:
    summary = read_reply(_fault("soap:Receiver", ""))
    assert "SUB-" not in repr(summary)


@pytest.mark.parametrize(
    "body",
    [
        b"",
        b"<html><body>502 Bad Gateway</body></html>",
        b'<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/"><s:Body/></s:Envelope>',
        f'<soap:Envelope xmlns:soap="{SOAP}"/>'.encode(),
        b"not xml at all",
    ],
)
def test_non_soap12_replies_are_refused(body: bytes) -> None:
    with pytest.raises(ResponseError) as raised:
        read_reply(body)
    assert raised.value.code == "REPLY_NOT_SOAP"


def test_entities_are_not_expanded() -> None:
    body = (
        b'<!DOCTYPE x [<!ENTITY e SYSTEM "file:///etc/hostname">]>'
        b'<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope"><soap:Body>'
        b"<r>&e;</r></soap:Body></soap:Envelope>"
    )
    assert read_reply(body) is None


@pytest.mark.parametrize(
    "body",
    [
        b"Too many connections!",
        b"<x>too MANY connections!</x>",
        "Too many connections!".encode("utf-16-le"),
    ],
)
def test_too_many_connections_is_detected(body: bytes) -> None:
    with pytest.raises(IwsThrottledError) as raised:
        raise_if_throttled(body)
    assert raised.value.code == "TOO_MANY_CONNECTIONS"


def test_other_replies_are_not_throttled() -> None:
    raise_if_throttled(b"<ok/>")
