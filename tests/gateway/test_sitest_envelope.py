"""The outgoing envelope is rebuilt from scratch (design §5.7, §7.2)."""

from collections.abc import Callable

import pytest
from lxml import etree

from airtimesat_platform.common.secrets import SecretValue
from airtimesat_platform.gateway.envelope import (
    IWS_NS,
    SOAP12_NS,
    XSI_NS,
    AuthFields,
    build_envelope,
)
from airtimesat_platform.gateway.errors import RefusedError

FAKE_SIGNATURE = "c2lnbmF0dXJlLW5vdC1yZWFsLTAwMDE="


def _full_width(word: str) -> str:
    return "".join(chr(ord(ch) + 0xFEE0) for ch in word)


def _auth(signed: list[str]) -> Callable[[str], AuthFields]:
    def factory(operation: str) -> AuthFields:
        signed.append(operation)
        return AuthFields(
            iws_username=SecretValue("user-fake0001"),
            timestamp="2026-10-20T12:00:00Z",
            caller="rec.RP-2026-001",
            service_provider_account_number=SecretValue("SP-0001"),
            signature=FAKE_SIGNATURE,
        )

    return factory


def _build(operation: str, request: str) -> etree._Element:  # pyright: ignore[reportPrivateUsage]
    signed: list[str] = []
    envelope = build_envelope(operation, request, _auth(signed))
    assert signed == [operation]
    return etree.fromstring(envelope)


def test_envelope_shape_and_auth_order() -> None:
    root = _build(
        "accountSearch",
        "<request><filterType>IMEI</filterType><filterValue>990000000318651</filterValue>"
        "<limit>5</limit></request>",
    )
    assert root.tag == f"{{{SOAP12_NS}}}Envelope"
    assert [child.tag for child in root] == [f"{{{SOAP12_NS}}}Body"]
    body = root[0]
    assert [child.tag for child in body] == [f"{{{IWS_NS}}}accountSearch"]
    request = body[0][0]
    assert request.tag == "request"
    assert [child.tag for child in request] == [
        "iwsUsername",
        "signature",
        "serviceProviderAccountNumber",
        "timestamp",
        "caller",
        "callerPassword",
        "filterType",
        "filterValue",
        "limit",
    ]
    assert request.findtext("signature") == FAKE_SIGNATURE
    assert request.findtext("timestamp") == "2026-10-20T12:00:00Z"
    assert request.findtext("caller") == "rec.RP-2026-001"
    # Always present and always empty (design §13 #36): no password is ever sent.
    password = request.find("callerPassword")
    assert password is not None
    assert password.text is None
    assert len(password) == 0
    assert not password.attrib


def test_sp_account_is_optional() -> None:
    def factory(operation: str) -> AuthFields:
        return AuthFields(
            iws_username=SecretValue("user-fake0001"),
            timestamp="2026-10-20T12:00:00Z",
            caller="rec.RP-2026-001",
            service_provider_account_number=None,
            signature=FAKE_SIGNATURE,
        )

    root = etree.fromstring(build_envelope("authenticatedPing", "<request/>", factory))
    request = root[0][0][0]
    assert [child.tag for child in request] == [
        "iwsUsername",
        "signature",
        "timestamp",
        "caller",
        "callerPassword",
    ]


@pytest.mark.parametrize(
    ("given", "written"),
    [
        ("SUSPENDED", "SUSPENDED"),
        (" active ", "ACTIVE"),
        ("Suspended", "SUSPENDED"),
        (_full_width("ACTIVE"), "ACTIVE"),
    ],
)
def test_new_status_is_written_from_constants(given: str, written: str) -> None:
    root = _build(
        "setSubscriberAccountStatus",
        f"<request><serviceType>SBD</serviceType><updateType>SUBSCRIBER_ACCOUNT_NUMBER</updateType>"
        f"<value>SUB-9004217</value><newStatus>{given}</newStatus></request>",
    )
    assert root.findtext(".//newStatus") == written


@pytest.mark.parametrize(
    "status",
    [
        "DEACTIVE",
        "CLOSED",
        " DEACTIVE ",
        "Deactive",
        _full_width("DEACTIVE"),
        "DEAC\u200bTIVE",
        "PENDING",
        "",
    ],
)
def test_new_status_outside_constants_is_refused(status: str) -> None:
    with pytest.raises(RefusedError) as raised:
        _build(
            "setSubscriberAccountStatus",
            f"<request><value>SUB-9004217</value><newStatus>{status}</newStatus></request>",
        )
    assert raised.value.code == "ALWAYS_REFUSED_DEACTIVE"


@pytest.mark.parametrize("value", ["TRUE", "true", "yes", "", "BULK"])
def test_bulk_action_other_than_false_is_refused(value: str) -> None:
    with pytest.raises(RefusedError) as raised:
        _build("activateSubscriber", f"<request><bulkAction>{value}</bulkAction></request>")
    assert raised.value.code == "ALWAYS_REFUSED_BULK"


@pytest.mark.parametrize(
    ("operation", "element", "code"),
    [
        ("setSubscriberAccountStatus", "newStatus", "ALWAYS_REFUSED_DEACTIVE"),
        ("setSubscriberAccountStatus", "bypassQuarantine", "ALWAYS_REFUSED_DEACTIVE"),
        ("activateSubscriber", "bulkAction", "ALWAYS_REFUSED_BULK"),
    ],
)
def test_enum_constant_with_children_is_refused(operation: str, element: str, code: str) -> None:
    # A structure in place of the enum would otherwise be copied as is, never from constants.
    with pytest.raises(RefusedError) as raised:
        _build(operation, f"<request><{element}><v>DEACTIVE</v></{element}></request>")
    assert raised.value.code == code


def test_bypass_quarantine_false_is_written_from_constants() -> None:
    root = _build(
        "setSubscriberAccountStatus",
        "<request><newStatus>ACTIVE</newStatus><bypassQuarantine>false</bypassQuarantine>"
        "</request>",
    )
    assert root.findtext(".//bypassQuarantine") == "FALSE"


@pytest.mark.parametrize(
    "field",
    [
        "iwsUsername",
        "signature",
        "timestamp",
        "serviceProviderAccountNumber",
        "caller",
        "callerPassword",
    ],
)
def test_auth_fields_in_the_request_are_refused(field: str) -> None:
    with pytest.raises(RefusedError) as raised:
        _build("accountSearch", f"<request><{field}>x</{field}><limit>5</limit></request>")
    assert raised.value.code == "AUTH_FIELD_IN_REQUEST"


@pytest.mark.parametrize("field", ["Signature", "CALLER", "IwsUsername", "TimeStamp"])
def test_auth_fields_in_the_request_are_refused_in_any_case(field: str) -> None:
    with pytest.raises(RefusedError) as raised:
        _build("accountSearch", f"<request><{field}>x</{field}></request>")
    assert raised.value.code == "AUTH_FIELD_IN_REQUEST"


@pytest.mark.parametrize("field", ["signature", "callerPassword", "CallerPassword", "SIGNATURE"])
def test_secret_fields_are_refused_at_any_depth(field: str) -> None:
    with pytest.raises(RefusedError) as raised:
        _build("accountUpdate", f"<request><a><b><{field}>x</{field}></b></a></request>")
    assert raised.value.code == "AUTH_FIELD_IN_REQUEST"


@pytest.mark.parametrize(
    ("request_xml", "code"),
    [
        ("<request><!-- c --><limit>5</limit></request>", "REQUEST_MARKUP_NOT_ALLOWED"),
        ("<request><newStatus>DE<!---->ACTIVE</newStatus></request>", "REQUEST_MARKUP_NOT_ALLOWED"),
        ("<request><limit><![CDATA[5]]></limit></request>", "REQUEST_MARKUP_NOT_ALLOWED"),
        ("<?xml version='1.0'?><request/>", "REQUEST_MARKUP_NOT_ALLOWED"),
        ("<request><?pi x?></request>", "REQUEST_MARKUP_NOT_ALLOWED"),
        (
            '<!DOCTYPE r [<!ENTITY e SYSTEM "file:///etc/passwd">]><request>&e;</request>',
            "REQUEST_MARKUP_NOT_ALLOWED",
        ),
        ("<request><limit>5</limit>", "REQUEST_NOT_WELL_FORMED"),
        ("<request>&unknown;</request>", "REQUEST_NOT_WELL_FORMED"),
        ("<other/>", "REQUEST_ROOT_INVALID"),
        ('<request id="1"/>', "REQUEST_ROOT_INVALID"),
        ('<irid:request xmlns:irid="http://www.iridium.com"/>', "REQUEST_ROOT_INVALID"),
        ("<request>text<limit>5</limit></request>", "MIXED_CONTENT"),
        ("<request><limit>5</limit>tail</request>", "MIXED_CONTENT"),
        ("<request><a>t<b>1</b></a></request>", "MIXED_CONTENT"),
        ('<request><limit foo="1">5</limit></request>', "ATTRIBUTE_NOT_ALLOWED"),
        ('<request><x:limit xmlns:x="urn:x">5</x:limit></request>', "ELEMENT_NAME_INVALID"),
        (
            f'<request xmlns:xsi="{XSI_NS}"><a xsi:type="sbdSubscriberAccountImpl"/></request>',
            "XSI_TYPE_INVALID",
        ),
        (
            f'<request xmlns:xsi="{XSI_NS}" xmlns:o="urn:other"><a xsi:type="o:t"/></request>',
            "XSI_TYPE_NAMESPACE_INVALID",
        ),
        (f'<request xmlns:xsi="{XSI_NS}"><a xsi:nil="maybe"/></request>', "XSI_NIL_INVALID"),
    ],
)
def test_unsafe_requests_are_refused(request_xml: str, code: str) -> None:
    with pytest.raises(RefusedError) as raised:
        _build("accountSearch", request_xml)
    assert raised.value.code == code


def test_soap_header_or_second_body_in_the_request_cannot_reach_the_envelope() -> None:
    # A request can only ever become the content of <request>: a Header-like element is an
    # ordinary unqualified child, and a SOAP-namespaced one is refused.
    with pytest.raises(RefusedError):
        _build("accountSearch", f'<request><s:Header xmlns:s="{SOAP12_NS}"/></request>')


def test_xsi_type_is_normalized_to_the_irid_prefix() -> None:
    root = _build(
        "accountUpdate",
        f'<request xmlns:xsi="{XSI_NS}" xmlns:i="{IWS_NS}">'
        '<subscriberAccount xsi:type="i:sbdSubscriberAccountImpl" xsi:nil="0"/></request>',
    )
    account = root.find(".//subscriberAccount")
    assert account is not None
    assert account.get(f"{{{XSI_NS}}}type") == "irid:sbdSubscriberAccountImpl"
    assert account.get(f"{{{XSI_NS}}}nil") == "false"


def test_depth_limit() -> None:
    nested = "<a>" * 40 + "1" + "</a>" * 40
    with pytest.raises(RefusedError) as raised:
        _build("accountUpdate", f"<request>{nested}</request>")
    assert raised.value.code == "REQUEST_TOO_DEEP"


def test_size_limit() -> None:
    with pytest.raises(RefusedError) as raised:
        _build("accountSearch", "<request><a>" + "1" * 300_000 + "</a></request>")
    assert raised.value.code == "REQUEST_TOO_LARGE"


@pytest.mark.parametrize("operation", ["irid:accountSearch", "account Search", "", "a" * 101])
def test_operation_name_is_checked(operation: str) -> None:
    with pytest.raises(RefusedError) as raised:
        _build(operation, "<request/>")
    assert raised.value.code == "OPERATION_NAME_INVALID"


def test_request_that_cannot_be_encoded_is_refused_without_echo() -> None:
    request = "<request><filterValue>990000000318651\ud800</filterValue></request>"
    with pytest.raises(RefusedError) as raised:
        _build("accountSearch", request)
    assert raised.value.code == "REQUEST_NOT_WELL_FORMED"
    assert raised.value.__cause__ is None
    assert raised.value.__suppress_context__


def test_auth_value_that_is_not_xml_safe_is_refused() -> None:
    def factory(operation: str) -> AuthFields:
        return AuthFields(
            iws_username=SecretValue("user-fake0001\x00"),
            timestamp="2026-10-20T12:00:00Z",
            caller="rec.RP-2026-001",
            service_provider_account_number=None,
            signature=FAKE_SIGNATURE,
        )

    with pytest.raises(RefusedError) as raised:
        build_envelope("accountSearch", "<request/>", factory)
    assert raised.value.code == "AUTH_VALUE_NOT_XML_SAFE"
    assert "user-fake0001" not in repr(raised.value)


def test_text_is_escaped_not_parsed() -> None:
    root = _build("accountSearch", "<request><filterValue>&lt;x/&gt;</filterValue></request>")
    assert root.findtext(".//filterValue") == "<x/>"


def test_auth_fields_repr_hides_the_signature() -> None:
    auth = AuthFields(
        iws_username=SecretValue("user-fake0001"),
        timestamp="2026-10-20T12:00:00Z",
        caller="rec.RP-2026-001",
        service_provider_account_number=None,
        signature=FAKE_SIGNATURE,
    )
    assert FAKE_SIGNATURE not in repr(auth)
    assert "user-fake0001" not in repr(auth)
