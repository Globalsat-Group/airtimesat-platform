"""The SITEST port over a fake transport: no live call is ever made (design §7.1, §5.8).

Every credential is synthetic.
"""

import asyncio
import dataclasses
import io
import json
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from email.utils import format_datetime

import pytest
from lxml import etree

from airtimesat_platform.common.secrets import SecretNotAvailableError, SecretValue
from airtimesat_platform.common.secrets_stdin import StdinSecretsProvider
from airtimesat_platform.gateway import endpoints_sitest
from airtimesat_platform.gateway.endpoints_sitest import Endpoint, endpoint_url
from airtimesat_platform.gateway.errors import (
    GatewayError,
    IwsThrottledError,
    RefusedError,
    ResponseError,
    TransportError,
    TransportTimeoutError,
)
from airtimesat_platform.gateway.signing import sign
from airtimesat_platform.gateway.sitest_port import (
    TIMEOUT_COOLDOWN_S,
    InProcessSitestPort,
    SitestCredentials,
    SitestPort,
    SitestResult,
    check_clock,
    generated_field_map_text,
)
from airtimesat_platform.gateway.transport import TransportReply

SOAP = "http://www.w3.org/2003/05/soap-envelope"
NOW = datetime(2026, 10, 20, 12, 0, 0, tzinfo=UTC)
FAKE_KEY = "fake-secret-not-real-0001"
CREDENTIALS = SitestCredentials(
    iws_username=SecretValue("user-fake0001"),
    secret_key=SecretValue(FAKE_KEY),
    service_provider_account_number=SecretValue("SP-0001"),
)
CALLER = "rec.RP-2026-001"
OK_BODY = (
    f'<soap:Envelope xmlns:soap="{SOAP}"><soap:Body>'
    '<ns:accountSearchResponse xmlns:ns="http://www.iridium.com"/></soap:Body></soap:Envelope>'
).encode()


def _date(at: datetime) -> str:
    return format_datetime(at, usegmt=True)


@dataclass
class FakeTransport:
    """Records what would have been sent; returns a canned reply."""

    reply: TransportReply | None = None
    error: GatewayError | None = None
    sent: list[tuple[str, bytes, str]] = field(default_factory=list[tuple[str, bytes, str]])
    closed: bool = False

    async def post(self, url: str, envelope: bytes, action: str) -> TransportReply:
        self.sent.append((url, envelope, action))
        if self.error is not None:
            raise self.error
        assert self.reply is not None
        return self.reply

    async def close(self) -> None:
        self.closed = True


def _reply(body: bytes = OK_BODY, status: int = 200, date: str | None = None) -> TransportReply:
    return TransportReply(status=status, date_header=date or _date(NOW), body=body)


@dataclass
class Clock:
    now: datetime = NOW
    mono: float = 1000.0
    slept: list[float] = field(default_factory=list[float])

    def wall(self) -> datetime:
        return self.now

    def monotonic(self) -> float:
        return self.mono

    async def sleep(self, seconds: float) -> None:
        self.slept.append(seconds)
        self.mono += seconds


def _port(
    transport: FakeTransport, *, allow_writes: bool = False, clock: Clock | None = None
) -> InProcessSitestPort:
    clock = clock or Clock()
    return InProcessSitestPort(
        CREDENTIALS,
        allow_writes=allow_writes,
        transport=transport,
        clock=clock.wall,
        monotonic=clock.monotonic,
        sleep=clock.sleep,
    )


def _call(
    port: InProcessSitestPort,
    operation: str = "accountSearch",
    request: str = "<request><filterType>IMEI</filterType><limit>5</limit></request>",
    *,
    endpoint: Endpoint = Endpoint.PROVISIONING,
    caller: str = CALLER,
) -> SitestResult:
    return asyncio.run(port.call(endpoint, operation, request, caller))


def test_the_in_process_port_implements_the_protocol() -> None:
    port: SitestPort = _port(FakeTransport(reply=_reply()))
    assert port.auth_identifiers() == (SecretValue("user-fake0001"), SecretValue("SP-0001"))


def test_a_read_is_signed_and_sent_to_sitest() -> None:
    transport = FakeTransport(reply=_reply())
    result = _call(_port(transport))
    assert result.outcome == "ok"
    assert result.http_status == 200
    assert result.signed_timestamp == "2026-10-20T12:00:00Z"
    assert result.body == OK_BODY
    [(url, envelope, action)] = transport.sent
    assert url == endpoint_url(Endpoint.PROVISIONING)
    assert action == "accountSearch"
    request = etree.fromstring(envelope)[0][0][0]
    assert request.findtext("timestamp") == "2026-10-20T12:00:00Z"
    assert request.findtext("caller") == CALLER
    assert request.findtext("iwsUsername") == "user-fake0001"
    assert request.findtext("serviceProviderAccountNumber") == "SP-0001"
    # The signature covers the operation actually sent and the timestamp actually sent.
    assert request.findtext("signature") == sign(
        SecretValue(FAKE_KEY), "accountSearch", "2026-10-20T12:00:00Z"
    )


def test_host_names_in_the_request_never_change_the_destination() -> None:
    # Design §8.5 #9: the URL comes from the endpoint constant only, never from request text.
    transport = FakeTransport(reply=_reply())
    request = (
        "<request><filterType>EMAIL</filterType>"
        "<filterValue>https://h-k3f9q2m7.example.invalid:8443/iws-current/iws</filterValue>"
        "</request>"
    )
    _call(_port(transport), request=request)
    [(url, _, _)] = transport.sent
    assert url == endpoint_url(Endpoint.PROVISIONING)


def test_reporting_endpoint_url() -> None:
    transport = FakeTransport(reply=_reply())
    _call(_port(transport), "getReportTypes", "<request/>", endpoint=Endpoint.REPORTING)
    assert transport.sent[0][0] == endpoint_url(Endpoint.REPORTING)


def test_the_signature_never_leaves_the_port() -> None:
    signature = sign(SecretValue(FAKE_KEY), "accountSearch", "2026-10-20T12:00:00Z")
    echo = OK_BODY.replace(b"</soap:Body>", f"<x>{signature}</x></soap:Body>".encode())
    result = _call(_port(FakeTransport(reply=_reply(echo))))
    assert signature.encode() not in result.body
    assert b"<x>REDACTED</x>" in result.body
    assert signature not in repr(result)
    assert not any(signature in str(value) for value in dataclasses.astuple(result))


def test_an_echo_of_the_secret_key_is_redacted() -> None:
    echo = OK_BODY.replace(b"</soap:Body>", f"<x>{FAKE_KEY}</x></soap:Body>".encode())
    result = _call(_port(FakeTransport(reply=_reply(echo))))
    assert FAKE_KEY.encode() not in result.body
    assert b"<x>REDACTED</x>" in result.body


def test_signatures_of_earlier_calls_are_redacted_too() -> None:
    # A later read of the IWS log can return an earlier call of the same run, signature and
    # all; within IWS's unknown clock tolerance it could be replayed with any body.
    clock = Clock()
    transport = FakeTransport(reply=_reply())
    port = _port(transport, clock=clock)
    first = sign(SecretValue(FAKE_KEY), "accountSearch", "2026-10-20T12:00:00Z")

    async def scenario() -> SitestResult:
        await port.call(Endpoint.PROVISIONING, "accountSearch", "<request/>", CALLER)
        clock.now = NOW + timedelta(seconds=3)
        log = f"<log>&lt;signature&gt;{first}&lt;/signature&gt;</log>"
        transport.reply = _reply(
            OK_BODY.replace(b"</soap:Body>", f"{log}</soap:Body>".encode()), date=_date(clock.now)
        )
        return await port.call(Endpoint.PROVISIONING, "getIwsRequests", "<request/>", CALLER)

    result = asyncio.run(scenario())
    assert first.encode() not in result.body
    assert b"&lt;signature&gt;REDACTED&lt;/signature&gt;" in result.body
    # The history of signatures does not print (the fake transport keeps what it was sent).
    assert all(first not in repr(value) for key, value in vars(port).items() if key != "_transport")


def test_result_repr_hides_the_raw_reply() -> None:
    result = _call(_port(FakeTransport(reply=_reply())))
    assert "accountSearchResponse" not in repr(result)


def test_credentials_never_print() -> None:
    for text in (repr(CREDENTIALS), str(CREDENTIALS)):
        assert FAKE_KEY not in text
        assert "user-fake0001" not in text
        assert "SP-0001" not in text


# ---------------------------------------------------------------- refusals before any send


@pytest.mark.parametrize(
    ("operation", "request_xml", "allow_writes", "code"),
    [
        (
            "setSubscriberAccountStatus",
            "<request><newStatus>DEACTIVE</newStatus></request>",
            True,
            "ALWAYS_REFUSED_DEACTIVE",
        ),
        (
            "setSubscriberAccountStatus",
            "<request><newStatus>CLOSED</newStatus></request>",
            True,
            "ALWAYS_REFUSED_DEACTIVE",
        ),
        (
            "setSubscriberAccountStatus",
            "<request><newStatus>ACTIVE</newStatus><bypassQuarantine>TRUE</bypassQuarantine>"
            "</request>",
            True,
            "ALWAYS_REFUSED_DEACTIVE",
        ),
        (
            "setSubscriberAccountStatus",
            "<request><newStatus>ACTIVE</newStatus><newStatus>ACTIVE</newStatus></request>",
            True,
            "ALWAYS_REFUSED_DEACTIVE",
        ),
        (
            "accountUpdate",
            "<request><subscriberAccount><accountStatus>DEACTIVE</accountStatus>"
            "</subscriberAccount></request>",
            True,
            "ALWAYS_REFUSED_DEACTIVE",
        ),
        (
            "activateSubscriber",
            "<request><bulkAction>TRUE</bulkAction></request>",
            True,
            "ALWAYS_REFUSED_BULK",
        ),
        (
            "activateSubscriber",
            "<request><sbdBulkDetails/></request>",
            True,
            "ALWAYS_REFUSED_BULK",
        ),
        (
            "deviceTransferOwner",
            "<request><deviceString>BULK</deviceString></request>",
            True,
            "ALWAYS_REFUSED_METHOD",
        ),
        ("bulkAccountUpdate", "<request/>", True, "ALWAYS_REFUSED_METHOD"),
        ("manageDestinations", "<request/>", True, "ALWAYS_REFUSED_METHOD"),
        (
            "createOnDemandReport",
            "<request><background>TRUE</background></request>",
            True,
            "ALWAYS_REFUSED_METHOD",
        ),
        (
            "setSubscriberAccountStatus",
            "<request><newStatus>ACTIVE</newStatus></request>",
            False,
            "WRITES_NOT_ENABLED",
        ),
        ("AccountSearch", "<request/>", False, "OPERATION_NOT_ALLOWLISTED"),
        ("accountSearch", "<request><caller>x</caller></request>", False, "AUTH_FIELD_IN_REQUEST"),
    ],
)
def test_refused_calls_never_reach_the_transport(
    operation: str, request_xml: str, allow_writes: bool, code: str
) -> None:
    transport = FakeTransport(reply=_reply())
    with pytest.raises(RefusedError) as raised:
        _call(_port(transport, allow_writes=allow_writes), operation, request_xml)
    assert raised.value.code == code
    assert transport.sent == []


@pytest.mark.parametrize(
    "caller", ["", "gs.tenant.user", "rec.", "rec. RP", "REC.RP-1", "rec.RP-1\n", "x" * 70]
)
def test_caller_must_be_a_recording_caller(caller: str) -> None:
    transport = FakeTransport(reply=_reply())
    with pytest.raises(RefusedError) as raised:
        _call(_port(transport), caller=caller)
    assert raised.value.code == "CALLER_INVALID"
    assert transport.sent == []


def test_an_allowed_write_is_sent_when_writes_are_open() -> None:
    transport = FakeTransport(reply=_reply())
    result = _call(
        _port(transport, allow_writes=True),
        "setSubscriberAccountStatus",
        "<request><serviceType>SBD</serviceType><updateType>SUBSCRIBER_ACCOUNT_NUMBER</updateType>"
        "<value>SUB-9004217</value><newStatus> suspended </newStatus></request>",
    )
    assert result.outcome == "ok"
    assert b"<newStatus>SUSPENDED</newStatus>" in transport.sent[0][1]


# ---------------------------------------------------------------- replies


def test_fault_outcome_is_the_error_code() -> None:
    body = (
        f'<soap:Envelope xmlns:soap="{SOAP}"><soap:Body><soap:Fault>'
        "<soap:Code><soap:Value>soap:Sender</soap:Value></soap:Code>"
        "<soap:Detail><e><errorCode>FIELD</errorCode></e></soap:Detail>"
        "</soap:Fault></soap:Body></soap:Envelope>"
    ).encode()
    result = _call(_port(FakeTransport(reply=_reply(body, status=500))))
    assert result.outcome == "FIELD"
    assert result.http_status == 500


@pytest.mark.parametrize("status", [200, 500, 503])
def test_too_many_connections_stops_the_run(status: int) -> None:
    body = (
        f'<soap:Envelope xmlns:soap="{SOAP}"><soap:Body><soap:Fault><soap:Reason>'
        "<soap:Text>Too many connections!</soap:Text></soap:Reason></soap:Fault></soap:Body>"
        "</soap:Envelope>"
    ).encode()
    with pytest.raises(IwsThrottledError):
        _call(_port(FakeTransport(reply=_reply(body, status=status))))


def test_too_many_connections_as_plain_text_stops_the_run() -> None:
    with pytest.raises(IwsThrottledError):
        _call(_port(FakeTransport(reply=_reply(b"Too many connections!", status=500))))


@pytest.mark.parametrize(
    ("body", "status", "code"),
    [
        (b"<html>maintenance</html>", 200, "REPLY_NOT_SOAP"),
        (b"<html>maintenance</html>", 503, "UNEXPECTED_STATUS"),
        (OK_BODY, 404, "UNEXPECTED_STATUS"),
        (OK_BODY, 500, "ERROR_STATUS_WITHOUT_FAULT"),
    ],
)
def test_unexpected_replies_stop_the_run(body: bytes, status: int, code: str) -> None:
    with pytest.raises(ResponseError) as raised:
        _call(_port(FakeTransport(reply=_reply(body, status=status))))
    assert raised.value.code == code


# ---------------------------------------------------------------- clock (§5.8)


@pytest.mark.parametrize("offset_s", [0, 4, -4, 5, -5])
def test_clock_within_tolerance(offset_s: int) -> None:
    check_clock(_date(NOW + timedelta(seconds=offset_s)), NOW)


@pytest.mark.parametrize("offset_s", [6, -6, 3600, -86400])
def test_clock_skew_stops_the_run(offset_s: int) -> None:
    with pytest.raises(ResponseError) as raised:
        check_clock(_date(NOW + timedelta(seconds=offset_s)), NOW)
    assert raised.value.code == "CLOCK_SKEW"


def test_clock_compared_in_utc_whatever_the_local_zone() -> None:
    local = NOW.astimezone(datetime.now().astimezone().tzinfo)
    check_clock(_date(NOW), local)
    from datetime import timezone

    check_clock(_date(NOW), NOW.astimezone(timezone(timedelta(hours=-5))))


@pytest.mark.parametrize("header", [None, "", "yesterday", "Tue, 99 Oct 2026 12:00:00 GMT"])
def test_unreadable_date_header_stops_the_run(header: str | None) -> None:
    with pytest.raises(ResponseError) as raised:
        check_clock(header, NOW)
    assert raised.value.code == "CLOCK_UNVERIFIED"


def test_skewed_reply_is_not_returned() -> None:
    reply = _reply(date=_date(NOW + timedelta(seconds=30)))
    with pytest.raises(ResponseError) as raised:
        _call(_port(FakeTransport(reply=reply)))
    assert raised.value.code == "CLOCK_SKEW"


def test_the_signed_timestamp_follows_the_clock() -> None:
    clock = Clock(now=datetime(2027, 1, 1, 0, 0, 0, tzinfo=UTC))
    transport = FakeTransport(reply=_reply(date=_date(clock.now)))
    result = _call(_port(transport, clock=clock))
    assert result.signed_timestamp == "2027-01-01T00:00:00Z"


# ---------------------------------------------------------------- timeouts (§5.8)


def test_a_timeout_puts_the_next_call_into_cooldown() -> None:
    clock = Clock()
    transport = FakeTransport(error=TransportTimeoutError("TRANSPORT_TIMEOUT"))
    port = _port(transport, clock=clock)

    async def scenario() -> SitestResult:
        with pytest.raises(TransportTimeoutError):
            await port.call(Endpoint.PROVISIONING, "accountSearch", "<request/>", CALLER)
        transport.error = None
        transport.reply = _reply()
        return await port.call(Endpoint.PROVISIONING, "accountSearch", "<request/>", CALLER)

    result = asyncio.run(scenario())
    assert result.outcome == "ok"
    assert clock.slept == [TIMEOUT_COOLDOWN_S]


def test_a_cancelled_call_puts_the_next_call_into_cooldown() -> None:
    # The recorder's own deadline cancels the call mid-flight; IWS may still be working on it.
    clock = Clock()

    class HangingTransport(FakeTransport):
        async def post(self, url: str, envelope: bytes, action: str) -> TransportReply:
            self.sent.append((url, envelope, action))
            if len(self.sent) == 1:
                await asyncio.sleep(10)
            return _reply()

    transport = HangingTransport()
    port = _port(transport, clock=clock)

    async def scenario() -> SitestResult:
        with pytest.raises(TimeoutError):
            async with asyncio.timeout(0.01):
                await port.call(Endpoint.PROVISIONING, "accountSearch", "<request/>", CALLER)
        return await port.call(Endpoint.PROVISIONING, "accountSearch", "<request/>", CALLER)

    result = asyncio.run(scenario())
    assert result.outcome == "ok"
    assert clock.slept == [TIMEOUT_COOLDOWN_S]


def test_other_transport_errors_pass_through_without_cooldown() -> None:
    clock = Clock()
    transport = FakeTransport(error=TransportError("TRANSPORT_FAILED"))
    with pytest.raises(TransportError):
        _call(_port(transport, clock=clock))
    assert clock.slept == []


def test_calls_run_one_at_a_time() -> None:
    active = 0
    peak = 0

    class SlowTransport(FakeTransport):
        async def post(self, url: str, envelope: bytes, action: str) -> TransportReply:
            nonlocal active, peak
            active += 1
            peak = max(peak, active)
            await asyncio.sleep(0.01)
            active -= 1
            return _reply()

    port = InProcessSitestPort(CREDENTIALS, transport=SlowTransport(), clock=lambda: NOW)

    async def scenario() -> None:
        await asyncio.gather(
            *(
                port.call(Endpoint.PROVISIONING, "accountSearch", "<request/>", CALLER)
                for _ in range(3)
            )
        )

    asyncio.run(scenario())
    assert peak == 1


def test_close_closes_the_transport() -> None:
    transport = FakeTransport(reply=_reply())
    port = _port(transport)
    asyncio.run(port.close())
    assert transport.closed


def test_without_a_pinned_address_nothing_is_sent(monkeypatch: pytest.MonkeyPatch) -> None:
    # Set the tuple here: once the CTO pins SITEST, the real constant would let this test
    # build the real transport and send to SITEST from CI and every agent session.
    monkeypatch.setattr(endpoints_sitest, "SITEST_PINNED_ADDRESSES", ())
    port = InProcessSitestPort(CREDENTIALS, clock=lambda: NOW)
    with pytest.raises(TransportError) as raised:
        _call(port)
    assert raised.value.code == "SITEST_ADDRESS_NOT_PINNED"


# ---------------------------------------------------------------- credentials from stdin


def _provider(data: dict[str, str]) -> StdinSecretsProvider:
    return StdinSecretsProvider.from_stream(io.BytesIO(json.dumps(data).encode()))


def test_credentials_from_the_stdin_provider() -> None:
    credentials = SitestCredentials.from_provider(
        _provider(
            {
                "sitest.iws_username": "user-fake0001",
                "sitest.secret_key": FAKE_KEY,
                "sitest.sp_account_number": "SP-0001",
            }
        )
    )
    assert credentials == CREDENTIALS


def test_sp_account_is_optional_in_the_record() -> None:
    credentials = SitestCredentials.from_provider(
        _provider({"sitest.iws_username": "user-fake0001", "sitest.secret_key": FAKE_KEY})
    )
    assert credentials.service_provider_account_number is None


def test_missing_secret_names_the_secret_only() -> None:
    with pytest.raises(SecretNotAvailableError) as raised:
        SitestCredentials.from_provider(_provider({"sitest.iws_username": "user-fake0001"}))
    assert "sitest.secret_key" in str(raised.value)
    assert "user-fake0001" not in str(raised.value)


def test_errors_never_carry_secrets_or_the_signature() -> None:
    signature = sign(SecretValue(FAKE_KEY), "accountSearch", "2026-10-20T12:00:00Z")
    for error in (
        TransportTimeoutError("TRANSPORT_TIMEOUT"),
        TransportError("TRANSPORT_FAILED"),
    ):
        transport = FakeTransport(error=error)
        with pytest.raises(GatewayError) as raised:
            _call(_port(transport))
        text = f"{raised.value!s} {raised.value!r} {raised.value.args!r}"
        for value in (FAKE_KEY, signature, "user-fake0001", "SP-0001"):
            assert value not in text


def test_the_generated_field_map_is_packaged() -> None:
    # Generated from the WSDL snapshot (S2 PR W); tests/test_generate_fieldmap.py checks drift.
    text = generated_field_map_text()
    assert text is not None
    assert text.startswith("# GENERATED by scripts/generate_fieldmap.py")
