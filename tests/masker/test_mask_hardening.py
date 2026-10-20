"""Regression tests for masking gaps found in the adversarial review of S2 PR B.

Each test names the channel a canary used to get past the engine before the fix. Every
value is a canary or a surrogate (design §8.2).
"""

import base64
import ipaddress
from collections.abc import Callable

import pytest
from lxml import etree

from airtimesat_platform.masker.detect.canary import canary
from airtimesat_platform.masker.engine import MaskingEngine
from airtimesat_platform.masker.errors import (
    MaskingBlockedError,
    MaskingError,
    RequestRefusedError,
    VaultError,
)
from airtimesat_platform.masker.fieldmap.loader import build_field_map
from airtimesat_platform.masker.tokenize.surrogates import IPV6_RESERVED
from airtimesat_platform.masker.tokenize.vault import Vault

Envelope = Callable[..., bytes]
NS = 'xmlns:ns="urn:example:iws"'
SOAP11 = "http://schemas.xmlsoap.org/soap/envelope/"
XSI = "http://www.w3.org/2001/XMLSchema-instance"


def status(text: str, extra: str = "") -> str:
    return (
        f"<ns:getSystemStatusResponse {NS}{extra}><iwsVersion>1</iwsVersion>"
        f"<status>{text}</status><activeCount>1</activeCount></ns:getSystemStatusResponse>"
    )


def blocked(engine: MaskingEngine, operation: str, raw: bytes) -> MaskingBlockedError:
    with pytest.raises(MaskingBlockedError) as info:
        engine.mask_response(engine.start_call(operation), raw)
    return info.value


def text_of(xml: bytes, name: str) -> list[str]:
    root = etree.fromstring(xml)
    return [el.text or "" for el in root.iter() if etree.QName(el).localname == name]


# ---------------------------------------------------------------- markup channels


@pytest.mark.parametrize(
    "declaration",
    [
        f' xmlns:x="urn:device:{canary("IMEI", 21)}"',
        f' xmlns:x="mailto:{canary("EMAIL", 21)}"',
        f' xmlns:p{canary("MSISDN", 21)}="urn:x"',
    ],
)
def test_namespace_declarations_are_scanned(
    engine: MaskingEngine, envelope: Envelope, declaration: str
) -> None:
    error = blocked(engine, "getSystemStatus", envelope(status("OK", declaration)))
    assert error.code == "MASKING_BLOCKED"
    assert error.path == "markup"


def test_namespace_declarations_on_the_envelope_are_scanned(engine: MaskingEngine) -> None:
    raw = (
        f'<soap:Envelope xmlns:soap="{SOAP11}" xmlns:x="urn:{canary("ICCID", 21)}">'
        f"<soap:Body>{status('OK')}</soap:Body></soap:Envelope>"
    ).encode()
    assert blocked(engine, "getSystemStatus", raw).path == "markup"


def test_an_xsi_type_prefix_is_scanned(engine: MaskingEngine, envelope: Envelope) -> None:
    prefix = "p" + canary("IMEI", 22)
    raw = envelope(
        f"<ns:getSubscriberAccountResponse {NS}>"
        f'<account xmlns:{prefix}="urn:x" xsi:type="{prefix}:sbdSubscriberAccountImpl">'
        f"<accountNumber>{canary('CONTRACT', 22)}</accountNumber></account>"
        "</ns:getSubscriberAccountResponse>"
    )
    error = blocked(engine, "getSubscriberAccount", raw)
    assert error.path == "markup"
    assert error.detector == "IMEI"


def test_xml_lang_must_be_a_plain_language_tag(engine: MaskingEngine, envelope: Envelope) -> None:
    def fault(lang: str) -> bytes:
        return envelope(
            "<soap:Fault><faultcode>soap:Server</faultcode>"
            f'<faultstring xml:lang="{lang}">Service unavailable</faultstring></soap:Fault>'
        )

    for ok in ("en", "en-US", "es-419"):
        engine.mask_response(engine.start_call("getSystemStatus"), fault(ok))
    error = blocked(engine, "getSystemStatus", fault("x-98000123-45678901"))
    assert error.code == "UNKNOWN_ATTRIBUTE"


def test_declared_encodings_other_than_utf8_are_refused(
    engine: MaskingEngine, envelope: Envelope
) -> None:
    body = envelope(status("OK")).split(b"?>", 1)[1]
    for encoding in ("UTF-7", "ISO-8859-1"):
        raw = f'<?xml version="1.0" encoding="{encoding}"?>'.encode() + body
        assert blocked(engine, "getSystemStatus", raw).code == "XML_ENCODING"
        with pytest.raises(RequestRefusedError) as info:
            engine.unmask_request(
                engine.start_call("getSystemStatus"),
                f'<?xml version="1.0" encoding="{encoding}"?><request/>'.encode(),
            )
        assert info.value.code == "XML_ENCODING"
    lower = b'<?xml version="1.0" encoding="utf-8"?>' + body
    engine.mask_response(engine.start_call("getSystemStatus"), lower)


# ---------------------------------------------------------------- text tricks in kept fields


@pytest.mark.parametrize(
    "separator",
    ["\u200b", "\u00ad", "\u2060", "\ufeff", "\u0301", "\u2013", "\u2212", "\x7f"],
)
def test_invisible_characters_and_dashes_do_not_split_an_identifier(
    engine: MaskingEngine, envelope: Envelope, separator: str
) -> None:
    imei = canary("IMEI", 23)
    value = imei[:7] + separator + imei[7:]  # 7 + 8 digits: neither part fires alone
    error = blocked(engine, "getSystemStatus", envelope(status(f"OK {value}")))
    assert error.detector in ("IMEI", "IMSI", "LONG_DIGITS")


@pytest.mark.parametrize(
    "value",
    [
        "contact person23\u00e9@canary.test",  # a non-ASCII letter right before "@"
        "contact person23@c\u00e1nary.test",
        "ip:3fff::1234",
        "at 3fff::1234: ok",
        "addr=3fff::1234:port",
        base64.b64encode(canary("MSISDN", 23).encode()).decode(),
        base64.b64encode(canary("IMEI", 23).encode()).decode(),
        base64.b64encode(canary("ICCID", 23).encode()).decode().rstrip("="),
        "SUB" + canary("CONTRACT", 23)[4:],
    ],
)
def test_identifier_variants_in_a_kept_field_block(
    engine: MaskingEngine, envelope: Envelope, value: str
) -> None:
    blocked(engine, "getSystemStatus", envelope(status(value)))


def test_a_cross_call_name_in_template_text_is_tokenized(
    engine: MaskingEngine, envelope: Envelope
) -> None:
    """A template match whose text contains a name seen earlier becomes ``Text-<8>``."""
    engine.mask_response(
        engine.start_call("accountSearch"),
        envelope(
            f"<ns:accountSearchResponse {NS}><accounts><account>"
            f"<accountNumber>{canary('CONTRACT', 24)}</accountNumber>"
            "<vesselName>Normally</vesselName></account></accounts></ns:accountSearchResponse>"
        ),
    )
    out = engine.mask_response(
        engine.start_call("getSystemStatus"),
        envelope(
            f"<ns:getSystemStatusResponse {NS}><iwsVersion>1</iwsVersion><status>OK</status>"
            "<activeCount>1</activeCount>"
            "<statusDescription>System running normally</statusDescription>"
            "</ns:getSystemStatusResponse>"
        ),
    ).body
    [description] = text_of(out, "statusDescription")
    assert description.startswith("Text-")


# ---------------------------------------------------------------- hosts and requests


def test_an_ipv6_destination_is_masked_whole(engine: MaskingEngine, envelope: Envelope) -> None:
    address = canary("IPV6", 0x1233)  # ends in a group of digits, which looks like a port

    def destination(value: str) -> str:
        raw = envelope(
            f"<ns:getSubscriberAccountResponse {NS}>"
            '<account xsi:type="ns:sbdSubscriberAccountImpl">'
            f"<accountNumber>{canary('CONTRACT', 25)}</accountNumber>"
            "<deliveryDestinations><deliveryMethod>DIRECT_IP</deliveryMethod>"
            f"<destination>{value}</destination></deliveryDestinations>"
            "</account></ns:getSubscriberAccountResponse>"
        )
        out = engine.mask_response(engine.start_call("getSubscriberAccount"), raw).body
        [masked] = text_of(out, "destination")
        return masked

    # Before the fix the last group was kept as a "port" after a host surrogate.
    assert ipaddress.IPv6Address(destination(address)) in IPV6_RESERVED
    bracketed = destination(f"[{address}]:4000")
    assert ipaddress.IPv6Address(bracketed[1:].removesuffix("]:4000")) in IPV6_RESERVED


@pytest.mark.parametrize(
    "comment",
    [
        f"{canary('IMEI', 26)}.example.invalid",
        f"x {canary('IMEI', 26)}@example.invalid",
        f"{canary('EMAIL', 26)}.example.invalid",
        f"call +{canary('MSISDN', 26)}.example.invalid",
        f"{canary('IPV4', 26)}.example.invalid",
    ],
)
def test_request_free_text_glued_to_the_reserved_domain_is_refused(
    engine: MaskingEngine, comment: str
) -> None:
    body = (
        "<request><filterType>IMEI</filterType><filterValue></filterValue><limit>5</limit>"
        f"<comment>{comment}</comment></request>"
    ).encode()
    with pytest.raises(RequestRefusedError) as info:
        engine.unmask_request(engine.start_call("accountSearch"), body)
    assert info.value.code == "REAL_FORMAT_VALUE"


# ---------------------------------------------------------------- custom field maps

GENERATED = """
format: airtimesat-fieldmap/1
paths:
  - {{operation: op, direction: request, path: request, xsd_type: complex}}
  - {{operation: op, direction: request, path: request/secret, xsd_type: complex, min_occurs: 0}}
  - {{operation: op, direction: request, path: request/secret/value, xsd_type: string}}
  - {{operation: op, direction: response, path: opResponse, xsd_type: complex}}
  - {{operation: op, direction: response, path: opResponse/code, xsd_type: {code_type}}}
"""
OVERRIDES = """
format: airtimesat-overrides/1
entries:
  - {{operation: op, direction: request, path: request, treatment: KEEP}}
  - {{operation: op, direction: request, path: request/secret, treatment: D}}
  - {{operation: op, direction: request, path: request/secret/value, treatment: KEEP}}
  - {{operation: op, direction: response, path: opResponse, treatment: KEEP}}
  - {{operation: op, direction: response, path: opResponse/code, {code_treatment}}}
"""


def custom_engine(vault: Vault, code_type: str, code_treatment: str) -> MaskingEngine:
    field_map, _ = build_field_map(
        GENERATED.format(code_type=code_type),
        OVERRIDES.format(code_treatment=code_treatment),
    )
    return MaskingEngine(field_map, vault, constants={"SP": ["canary-sp-account-1"]})


@pytest.mark.parametrize(
    "treatment",
    ["treatment: T-STR, type: ID", "treatment: P-ONE, type: NAME", "treatment: C, type: SP"],
)
def test_numeric_outputs_must_fit_the_xsd_type(vault: Vault, treatment: str) -> None:
    custom_engine(vault, "int", treatment)  # 9 digits fit xsd:int
    with pytest.raises(MaskingError) as info:
        custom_engine(vault, "short", treatment)
    assert info.value.code == "FIELDMAP_SURROGATE_DOES_NOT_FIT"


def test_a_dropped_complex_element_in_a_request_is_refused(vault: Vault) -> None:
    engine = custom_engine(vault, "string", "treatment: KEEP")
    call = engine.start_call("op")
    engine.unmask_request(call, b"<request/>")
    with pytest.raises(RequestRefusedError) as info:
        engine.unmask_request(call, b"<request><secret><value>x</value></secret></request>")
    assert info.value.code == "NOT_REVERSIBLE"


# ---------------------------------------------------------------- vault


def test_a_padded_real_value_in_the_reserved_prefix_is_refused(vault: Vault) -> None:
    surrogate = vault.issue("IMEI", canary("IMEI", 27))
    with pytest.raises(VaultError) as info:
        vault.issue("IMEI", f" {surrogate} ")
    assert info.value.code == "REAL_VALUE_IN_RESERVED_PREFIX"
    assert vault.in_prefix["IMEI"] == 1
