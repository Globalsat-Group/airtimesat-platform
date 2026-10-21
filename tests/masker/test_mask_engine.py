"""Masking responses: per-shape synthetic tests with canaries (design §4, §8.2, §8.4)."""

from collections.abc import Callable

import pytest
from lxml import etree

from airtimesat_platform.masker.detect.canary import canary
from airtimesat_platform.masker.detect.patterns import Options, find_hits
from airtimesat_platform.masker.detect.scan import offline_exemption
from airtimesat_platform.masker.engine import MaskingEngine
from airtimesat_platform.masker.errors import MaskingBlockedError, RequestRefusedError
from airtimesat_platform.masker.tokenize.surrogates import SPECS, luhn_valid
from airtimesat_platform.masker.tokenize.vault import Vault

Envelope = Callable[..., bytes]
NS = 'xmlns:ns="urn:example:iws"'
XSI = "{http://www.w3.org/2001/XMLSchema-instance}"
OP = "getSubscriberAccount"

SBD_CANARIES = {
    "contract": canary("CONTRACT", 1),
    "imei": canary("IMEI", 1),
    "dest_imei": canary("IMEI", 2),
    "email": canary("EMAIL", 1),
    "ip": canary("IPV4", 1),
    "ref": "Canary Reference 1",
    "login": "canary.login.1",
    "msisdn": canary("MSISDN", 1),
}
TEL_CANARIES = {
    "contract": canary("CONTRACT", 2),
    "msisdn": canary("MSISDN", 2),
    "sim": canary("ICCID", 2),
    "imei": canary("IMEI", 3),
    "imsi": canary("IMSI", 2),
    "email": "Person2@Canary.Test",
    "ip": canary("IPV4", 2),
    "vessel": "Canary Vessel 2",
    "imo": canary("IMO", 2),
    "mmsi": canary("MMSI", 2),
}


def destination(method: str, value: str, port: str = "") -> str:
    port_xml = f"<port>{port}</port>" if port else ""
    return (
        f"<deliveryDestinations><deliveryMethod>{method}</deliveryMethod>"
        f"<destination>{value}</destination>{port_xml}</deliveryDestinations>"
    )


def sbd_account(destinations: int = 3, c: dict[str, str] = SBD_CANARIES) -> str:
    dests = [
        destination("IRIDIUM_DEVICE", c["dest_imei"]),
        destination("EMAIL", c["email"]),
        destination("DIRECT_IP", f"{c['ip']}:4000", "10800"),
    ]
    chosen = "".join(dests[i % 3] for i in range(destinations))
    return (
        '<account xsi:type="ns:sbdSubscriberAccountImpl">'
        f"<accountNumber>{c['contract']}</accountNumber>"
        "<accountStatus>ACTIVE</accountStatus>"
        f"<imei>{c['imei']}</imei>"
        "<serviceProviderAccountNumber>canary-sp-account-1</serviceProviderAccountNumber>"
        f"<subscriberAccountMetadata><spReference>{c['ref']}</spReference></subscriberAccountMetadata>"
        f"{chosen}"
        f"<createdBy>{c['login']}</createdBy>"
        "<activationDate>2026-10-01T10:00:00Z</activationDate>"
        f"<description>Call {c['msisdn']} about {c['ref']}</description>"
        "</account>"
    )


def tel_account(c: dict[str, str] = TEL_CANARIES) -> str:
    return (
        '<account xsi:type="ns:telephonySubscriberAccountImpl">'
        f"<accountNumber>{c['contract']}</accountNumber>"
        f"<msisdn>{c['msisdn']}</msisdn><sim>{c['sim']}</sim><imei>{c['imei']}</imei>"
        f"<imsi>{c['imsi']}</imsi>"
        "<twoStagePin>4821</twoStagePin><captainPin>7730</captainPin>"
        f"<contactEmail>{c['email']}</contactEmail><ip>{c['ip']}/30</ip>"
        "<latitude>-33.4569</latitude>"
        f"<vessel><vesselName>{c['vessel']}</vesselName><imo>{c['imo']}</imo>"
        f"<mmsi>{c['mmsi']}</mmsi><buildYear>1999</buildYear>"
        "<personCapacity>12</personCapacity><vesselTon>5000</vesselTon></vessel>"
        "</account>"
    )


def response(envelope: Envelope, account: str) -> bytes:
    return envelope(
        f"<ns:getSubscriberAccountResponse {NS}>{account}</ns:getSubscriberAccountResponse>"
    )


def mask(engine: MaskingEngine, body: bytes, operation: str = OP) -> bytes:
    return engine.mask_response(engine.start_call(operation), body).body


def element_paths(xml: bytes) -> list[str]:
    root = etree.fromstring(xml)
    out: list[str] = []
    for el in root.iter():
        name = etree.QName(el).localname
        out.append(name + (f"[{el.get(XSI + 'type')}]" if el.get(XSI + "type") else ""))
    return out


def text_of(xml: bytes, name: str) -> list[str]:
    root = etree.fromstring(xml)
    return [el.text or "" for el in root.iter() if etree.QName(el).localname == name]


def nil_of(xml: bytes, name: str) -> list[str | None]:
    root = etree.fromstring(xml)
    return [el.get(XSI + "nil") for el in root.iter() if etree.QName(el).localname == name]


def assert_no_canary(output: bytes, canaries: dict[str, str]) -> None:
    text = output.decode().casefold()
    for value in canaries.values():
        assert value.casefold() not in text
    # Offline scan, as leak_scan.py would run it on a committed recording: strict rules,
    # reserved prefixes allowed, canaries not allowed.
    assert find_hits(output.decode(), Options(), offline_exemption()) == []


@pytest.mark.parametrize("destinations", [1, 3])
def test_sbd_account_shape(engine: MaskingEngine, envelope: Envelope, destinations: int) -> None:
    raw = response(envelope, sbd_account(destinations))
    out = mask(engine, raw)
    assert_no_canary(out, SBD_CANARIES)
    assert element_paths(out) == element_paths(raw)
    [contract] = text_of(out, "accountNumber")
    assert SPECS["CONTRACT"].is_surrogate_shape(contract)
    [imei] = text_of(out, "imei")
    assert SPECS["IMEI"].is_surrogate_shape(imei)
    assert luhn_valid(imei)
    assert text_of(out, "serviceProviderAccountNumber") == ["SP-0001"]
    assert text_of(out, "accountStatus") == ["ACTIVE"]
    assert text_of(out, "activationDate") == ["2026-10-01T10:00:00Z"]
    [ref] = text_of(out, "spReference")
    assert ref.startswith("Ref-")
    [login] = text_of(out, "createdBy")
    assert login.startswith("user-")
    [description] = text_of(out, "description")
    assert description.startswith("Text-")
    dests = text_of(out, "destination")
    assert SPECS["IMEI"].is_surrogate_shape(dests[0])
    if destinations == 3:
        assert SPECS["EMAIL"].is_surrogate_shape(dests[1])
        host, port = dests[2].rsplit(":", 1)
        assert SPECS["IPV4"].is_surrogate_shape(host)
        assert port == "4000"
        assert text_of(out, "port") == ["10800"]


def test_telephony_account_shape(engine: MaskingEngine, envelope: Envelope, vault: Vault) -> None:
    raw = response(envelope, tel_account())
    out = mask(engine, raw)
    assert_no_canary(out, TEL_CANARIES)
    paths = element_paths(raw)
    paths.remove("buildYear")  # D on an optional int: removed
    assert element_paths(out) == paths
    assert text_of(out, "twoStagePin") == ["REDACTED"]
    assert text_of(out, "captainPin") == ["REDACTED"]
    assert nil_of(out, "personCapacity") == ["true"]
    assert text_of(out, "vesselTon") == ["0"]
    assert text_of(out, "latitude") == ["-33"]
    [sim] = text_of(out, "sim")
    assert SPECS["ICCID"].is_surrogate_shape(sim)
    assert vault.resolve("ICCID", sim) == TEL_CANARIES["sim"]
    [imsi] = text_of(out, "imsi")
    assert SPECS["IMSI"].is_surrogate_shape(imsi)
    [ip] = text_of(out, "ip")
    assert ip.endswith("/30")
    assert SPECS["IPV4"].is_surrogate_shape(ip[:-3])
    [email] = text_of(out, "contactEmail")
    assert vault.resolve("EMAIL", email) == TEL_CANARIES["email"]
    [vessel] = text_of(out, "vesselName")
    assert vault.resolve("VESSEL", vessel) == TEL_CANARIES["vessel"]
    [imo] = text_of(out, "imo")
    assert SPECS["IMO"].is_surrogate_shape(imo)


def test_surrogates_are_consistent_across_calls(engine: MaskingEngine, envelope: Envelope) -> None:
    raw = response(envelope, sbd_account())
    assert mask(engine, raw) == mask(engine, raw)


def test_nil_and_empty_variants(engine: MaskingEngine, envelope: Envelope) -> None:
    account = (
        '<account xsi:type="ns:sbdSubscriberAccountImpl">'
        "<accountNumber></accountNumber><accountStatus>ACTIVE</accountStatus><imei/>"
        "<serviceProviderAccountNumber>canary-sp-account-1</serviceProviderAccountNumber>"
        '<subscriberAccountMetadata><spReference xsi:nil="true"/></subscriberAccountMetadata>'
        "<activationDate>2026-10-01T10:00:00Z</activationDate>"
        "</account>"
    )
    out = mask(engine, response(envelope, account))
    assert text_of(out, "accountNumber") == [""]
    assert nil_of(out, "spReference") == ["true"]


def test_masked_exchange_is_returned_with_counts(engine: MaskingEngine, envelope: Envelope) -> None:
    result = engine.mask_response(engine.start_call(OP), response(envelope, tel_account()))
    assert result.fault is False
    assert result.dropped == 5
    assert result.surrogates_placed >= 10
    assert result.body.startswith(b"<?xml")


@pytest.mark.parametrize(
    ("account", "code"),
    [
        (
            '<account xsi:type="ns:sbdSubscriberAccountImpl">'
            "<imei>1</imei><colour>red</colour></account>",
            "UNKNOWN_ELEMENT",
        ),
        (
            '<account xsi:type="ns:certusSubscriberAccountImpl"><imei>1</imei></account>',
            "UNKNOWN_ELEMENT",
        ),
        (
            '<account xsi:type="ns:sbdSubscriberAccountImpl"><imei unit="x">1</imei></account>',
            "UNKNOWN_ATTRIBUTE",
        ),
        (
            '<account xsi:type="ns:sbdSubscriberAccountImpl">stray<imei>1</imei></account>',
            "MIXED_CONTENT",
        ),
        (
            '<account xsi:type="ns:sbdSubscriberAccountImpl"><imei>1</imei>tail</account>',
            "MIXED_CONTENT",
        ),
        (
            '<account xsi:type="ns:sbdSubscriberAccountImpl"><imei><x/></imei></account>',
            "UNEXPECTED_CHILDREN",
        ),
        (
            '<account xsi:type="ns:sbdSubscriberAccountImpl"><imei xsi:nil="true"/></account>',
            "NIL_NOT_ALLOWED",
        ),
        (
            '<account xsi:type="ns:sbdSubscriberAccountImpl"><imei xsi:nil="maybe"/></account>',
            "XSI_NIL_INVALID",
        ),
        (
            '<account xsi:type="ns:sbdSubscriberAccountImpl">'
            "<imei>1</imei><imei>2</imei></account>",
            "MAX_OCCURS",
        ),
        ('<account xsi:type="bad type"><imei>1</imei></account>', "XSI_TYPE_INVALID"),
        ("<account><imei>1</imei></account>", "UNKNOWN_ELEMENT"),
    ],
)
def test_unknown_or_malformed_content_blocks(
    engine: MaskingEngine, envelope: Envelope, account: str, code: str
) -> None:
    with pytest.raises(MaskingBlockedError) as info:
        mask(engine, response(envelope, account))
    assert info.value.code == code


def test_unknown_xsi_type_on_a_known_element_blocks(
    engine: MaskingEngine, envelope: Envelope
) -> None:
    body = (
        f"<ns:getSubscriberAccountResponse {NS}>"
        '<account xsi:type="ns:sbdSubscriberAccountImpl"><accountStatus xsi:type="xs:string">ACTIVE'
        "</accountStatus></account></ns:getSubscriberAccountResponse>"
    )
    with pytest.raises(MaskingBlockedError) as info:
        mask(engine, envelope(body))
    assert info.value.code == "UNKNOWN_XSI_TYPE"


def test_unclassified_element_blocks(engine: MaskingEngine, envelope: Envelope) -> None:
    body = (
        f"<ns:getSystemStatusResponse {NS}><status>UP</status>"
        "<buildHost>build-01</buildHost></ns:getSystemStatusResponse>"
    )
    with pytest.raises(MaskingBlockedError) as info:
        mask(engine, envelope(body), "getSystemStatus")
    assert info.value.code == "UNCLASSIFIED_ELEMENT"
    assert info.value.path == "getSystemStatusResponse/buildHost"


def test_block_messages_carry_no_values(engine: MaskingEngine, envelope: Envelope) -> None:
    value = canary("IMEI", 8)
    account = f'<account xsi:type="ns:sbdSubscriberAccountImpl"><x{value}>1</x{value}></account>'
    with pytest.raises(MaskingBlockedError) as info:
        mask(engine, response(envelope, account))
    assert value not in str(info.value)
    assert value not in repr(info.value)
    assert "?" in info.value.path


def test_unknown_constant_blocks(engine: MaskingEngine, envelope: Envelope) -> None:
    account = (
        '<account xsi:type="ns:sbdSubscriberAccountImpl"><serviceProviderAccountNumber>'
        "another-sp</serviceProviderAccountNumber></account>"
    )
    with pytest.raises(MaskingBlockedError) as info:
        mask(engine, response(envelope, account))
    assert info.value.code == "CONSTANT_UNKNOWN"


def test_generalize_refuses_non_numbers(engine: MaskingEngine, envelope: Envelope) -> None:
    account = (
        '<account xsi:type="ns:telephonySubscriberAccountImpl"><latitude>north</latitude></account>'
    )
    with pytest.raises(MaskingBlockedError) as info:
        mask(engine, response(envelope, account))
    assert info.value.code == "G_NOT_NUMERIC"


def test_untyped_destination_falls_back_to_detection(
    engine: MaskingEngine, envelope: Envelope
) -> None:
    account = (
        '<account xsi:type="ns:sbdSubscriberAccountImpl">'
        + destination("CARRIER_PIGEON", canary("EMAIL", 4))
        + destination("CARRIER_PIGEON", canary("IPV4", 4))
        + destination("CARRIER_PIGEON", canary("CONTRACT", 4))
        + destination("CARRIER_PIGEON", canary("IMEI", 4))
        + destination("CARRIER_PIGEON", "Canary Free Value")
        + "</account>"
    )
    out = mask(engine, response(envelope, account))
    dests = text_of(out, "destination")
    assert SPECS["EMAIL"].is_surrogate_shape(dests[0])
    assert SPECS["IPV4"].is_surrogate_shape(dests[1])
    assert SPECS["CONTRACT"].is_surrogate_shape(dests[2])
    assert SPECS["OTHER_NUMBER"].is_surrogate_shape(dests[3])
    assert SPECS["VALUE"].is_surrogate_shape(dests[4])


def test_hosts_keep_wildcards_and_ports(engine: MaskingEngine, envelope: Envelope) -> None:
    account = (
        '<account xsi:type="ns:sbdSubscriberAccountImpl">'
        + destination("DIRECT_IP", "*.host1.canary.test:2000")
        + destination("DIRECT_IP", "*.")
        + "</account>"
    )
    out = mask(engine, response(envelope, account))
    first, second = text_of(out, "destination")
    assert first.startswith("*.h-")
    assert first.endswith(".example.invalid:2000")
    assert second == "*."


def test_a_call_is_masked_once(engine: MaskingEngine, envelope: Envelope) -> None:
    call = engine.start_call(OP)
    engine.mask_response(call, response(envelope, tel_account()))
    with pytest.raises(MaskingBlockedError) as info:
        engine.mask_response(call, response(envelope, tel_account()))
    assert info.value.code == "CALL_ALREADY_MASKED"


def test_operations_outside_the_map_are_refused(engine: MaskingEngine) -> None:
    with pytest.raises(RequestRefusedError) as info:
        engine.start_call("deactivateEverything")
    assert info.value.code == "OPERATION_NOT_ALLOWED"


def test_soap_12_envelopes_are_accepted(engine: MaskingEngine) -> None:
    body = (
        '<env:Envelope xmlns:env="http://www.w3.org/2003/05/soap-envelope"><env:Header/><env:Body>'
        f"<ns:getSystemStatusResponse {NS}><status>UP</status></ns:getSystemStatusResponse>"
        "</env:Body></env:Envelope>"
    ).encode()
    out = mask(engine, body, "getSystemStatus")
    assert b"UP" in out


@pytest.mark.parametrize(
    ("body", "code"),
    [
        (b"<html><body>Service Unavailable</body></html>", "NON_SOAP_BODY"),
        (b"not xml at all", "XML_PARSE"),
        (
            b'<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"></soap:Envelope>',
            "NON_SOAP_BODY",
        ),
        (
            b'<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"><soap:Body>'
            b"<a/><b/></soap:Body></soap:Envelope>",
            "BODY_NOT_ONE_ELEMENT",
        ),
        (
            b'<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"><soap:Header>'
            b"<token>x</token></soap:Header><soap:Body><a/></soap:Body></soap:Envelope>",
            "ENVELOPE_UNEXPECTED_CONTENT",
        ),
        (
            b'<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/" a="1">'
            b"<soap:Body>"
            b"<a/></soap:Body></soap:Envelope>",
            "ENVELOPE_UNEXPECTED_CONTENT",
        ),
        (
            b'<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"><soap:Body>'
            b"<a/></soap:Body><soap:Body><b/></soap:Body></soap:Envelope>",
            "ENVELOPE_UNEXPECTED_CONTENT",
        ),
    ],
)
def test_non_soap_and_malformed_envelopes_block(
    engine: MaskingEngine, body: bytes, code: str
) -> None:
    with pytest.raises(MaskingBlockedError) as info:
        mask(engine, body, "getSystemStatus")
    assert info.value.code == code
