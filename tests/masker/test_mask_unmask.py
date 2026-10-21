"""Unmasking plan requests: only issued surrogates map back (design §5.5, §8.5 #6-#8)."""

import pytest

from airtimesat_platform.masker.detect.canary import canary
from airtimesat_platform.masker.engine import MaskingEngine
from airtimesat_platform.masker.errors import RequestRefusedError
from airtimesat_platform.masker.tokenize.surrogates import luhn_check_digit
from airtimesat_platform.masker.tokenize.vault import InMemoryVaultStore, Vault


def search(filter_type: str, value: str, extra: str = "") -> bytes:
    return (
        f"<request><filterType>{filter_type}</filterType><filterValue>{value}</filterValue>"
        f"<filterCond>EQUALS</filterCond><limit>5</limit>{extra}</request>"
    ).encode()


def unmask(engine: MaskingEngine, operation: str, body: bytes) -> bytes:
    return engine.unmask_request(engine.start_call(operation), body).body


def refused(engine: MaskingEngine, operation: str, body: bytes) -> RequestRefusedError:
    with pytest.raises(RequestRefusedError) as info:
        unmask(engine, operation, body)
    return info.value


def test_issued_surrogates_are_replaced_by_real_values(engine: MaskingEngine, vault: Vault) -> None:
    real = canary("IMEI", 1)
    surrogate = vault.issue("IMEI", real)
    call = engine.start_call("accountSearch")
    result = engine.unmask_request(call, search("IMEI", surrogate))
    assert real.encode() in result.body
    assert surrogate.encode() not in result.body
    assert result.resolved == 1
    assert real not in repr(result)
    assert call.known.found_in(f"echo {real}")


@pytest.mark.parametrize(
    ("filter_type", "type_name"),
    [
        ("MSISDN", "MSISDN"),
        ("ACCOUNT_NUMBER", "CONTRACT"),
        ("VESSEL_NAME", "VESSEL"),
        ("IP_ADDRESS", "IPV4"),
    ],
)
def test_typed_filters_resolve_by_their_enum(
    engine: MaskingEngine, vault: Vault, filter_type: str, type_name: str
) -> None:
    real = canary(type_name, 3)
    surrogate = vault.issue(type_name, real)
    assert real.encode() in unmask(engine, "accountSearch", search(filter_type, surrogate))


def test_guessed_surrogates_are_not_issued(engine: MaskingEngine) -> None:
    # Enumeration: well-formed surrogates in the reserved prefix that the masker never issued.
    for n in range(3):
        payload = "99" + str(n).zfill(12)
        guess = payload + luhn_check_digit(payload)
        error = refused(engine, "accountSearch", search("IMEI", guess))
        assert error.code == "IDENTIFIER_NOT_ISSUED"


def test_real_format_values_are_not_surrogates(engine: MaskingEngine) -> None:
    error = refused(engine, "accountSearch", search("IMEI", canary("IMEI", 1)))
    assert error.code == "NOT_A_SURROGATE"
    assert canary("IMEI", 1) not in str(error)


def test_unknown_typing_value_is_refused(engine: MaskingEngine, vault: Vault) -> None:
    surrogate = vault.issue("IMEI", canary("IMEI", 1))
    assert refused(engine, "accountSearch", search("SMART", surrogate)).code == "TYPING_UNKNOWN"


@pytest.mark.parametrize("value", ["99000000*", "%Vessel", "Vessel-*"])
def test_wildcards_in_identifier_fields_are_refused(engine: MaskingEngine, value: str) -> None:
    assert refused(engine, "accountSearch", search("VESSEL_NAME", value)).code == "WILDCARD_REFUSED"


@pytest.mark.parametrize(
    "extra",
    [
        f"<comment>please check {canary('MSISDN', 1)}</comment>",
        f"<comment>{canary('EMAIL', 1)}</comment>",
        f"<comment>{canary('CONTRACT', 1)}</comment>",
    ],
)
def test_free_text_with_a_real_identifier_is_refused(
    engine: MaskingEngine, vault: Vault, extra: str
) -> None:
    surrogate = vault.issue("IMEI", canary("IMEI", 1))
    error = refused(engine, "accountSearch", search("IMEI", surrogate, extra))
    assert error.code == "REAL_FORMAT_VALUE"
    assert error.detector


def test_free_text_with_surrogates_only_is_accepted(engine: MaskingEngine, vault: Vault) -> None:
    surrogate = vault.issue("IMEI", canary("IMEI", 1))
    body = search("IMEI", surrogate, f"<comment>follow-up on {surrogate}</comment>")
    assert b"follow-up" in unmask(engine, "accountSearch", body)


@pytest.mark.parametrize(
    "auth",
    [
        "iwsUsername",
        "signature",
        "timestamp",
        "serviceProviderAccountNumber",
        "caller",
        "callerPassword",
        "CALLER",
    ],
)
def test_authentication_fields_are_refused(engine: MaskingEngine, auth: str) -> None:
    body = f"<request><{auth}>x</{auth}><filterType>IMEI</filterType></request>".encode()
    assert refused(engine, "accountSearch", body).code == "AUTH_FIELD_IN_REQUEST"


@pytest.mark.parametrize(
    ("body", "code"),
    [
        (b"<request><!-- note --><filterType>IMEI</filterType></request>", "XML_COMMENT"),
        (b"<request><?pi x?><filterType>IMEI</filterType></request>", "XML_PI"),
        (b"<request><filterType><![CDATA[IMEI]]></filterType></request>", "XML_CDATA"),
        (
            b'<!DOCTYPE r [<!ENTITY e "IMEI">]><request><filterType>&e;</filterType></request>',
            "XML_DTD",
        ),
        (
            b"<request><filterType>IMEI</filterType><filterType>MSISDN</filterType></request>",
            "MAX_OCCURS",
        ),
        (b"<request><filterType>IMEI</filterType><bogus/></request>", "UNKNOWN_ELEMENT"),
        (b'<request><filterType kind="x">IMEI</filterType></request>', "UNKNOWN_ATTRIBUTE"),
        (b"<request>text<filterType>IMEI</filterType></request>", "MIXED_CONTENT"),
        (b"<request><filterType>IMEI</filterType>", "XML_PARSE"),
        (b"<request/><!-- trailing -->", "XML_NODE"),
        ("<request><filterType>IMEI</filterType></request>".encode("utf-16"), "XML_ENCODING"),
    ],
)
def test_parser_tricks_are_refused(engine: MaskingEngine, body: bytes, code: str) -> None:
    assert refused(engine, "accountSearch", body).code == code


def test_constants_and_literals_map_back(engine: MaskingEngine) -> None:
    body = (
        b"<request><updateType>SUBSCRIBER_ACCOUNT_NUMBER</updateType>"
        b"<newStatus>SUSPENDED</newStatus><owner>SP-0001</owner></request>"
    )
    assert b"<owner>canary-sp-account-1</owner>" in unmask(
        engine, "setSubscriberAccountStatus", body
    )
    literal = b"<request><updateType>IMEI</updateType><owner>GLOBAL</owner></request>"
    assert b"<owner>GLOBAL</owner>" in unmask(engine, "setSubscriberAccountStatus", literal)
    for bad in (b"SP-0002", b"SP-1", b"someone-else"):
        body = b"<request><updateType>IMEI</updateType><owner>" + bad + b"</owner></request>"
        assert refused(engine, "setSubscriberAccountStatus", body).code == "CONSTANT_UNKNOWN"


def test_write_request_with_an_email_list(engine: MaskingEngine, vault: Vault) -> None:
    contract = vault.issue("CONTRACT", canary("CONTRACT", 9))
    mailbox = vault.issue("EMAIL", canary("EMAIL", 9))
    body = (
        f"<request><updateType>SUBSCRIBER_ACCOUNT_NUMBER</updateType><value>{contract}</value>"
        f"<newStatus>SUSPENDED</newStatus><contact>{mailbox}, {mailbox}</contact></request>"
    ).encode()
    out = unmask(engine, "setSubscriberAccountStatus", body)
    assert canary("CONTRACT", 9).encode() in out
    assert f"{canary('EMAIL', 9)}, {canary('EMAIL', 9)}".encode() in out


def test_a_real_identifier_in_a_write_reason_is_refused(
    engine: MaskingEngine, vault: Vault
) -> None:
    contract = vault.issue("CONTRACT", canary("CONTRACT", 9))
    body = (
        f"<request><updateType>SUBSCRIBER_ACCOUNT_NUMBER</updateType><value>{contract}</value>"
        f"<newStatus>SUSPENDED</newStatus><reason>moved to {canary('IMEI', 5)}</reason></request>"
    ).encode()
    assert refused(engine, "setSubscriberAccountStatus", body).code == "REAL_FORMAT_VALUE"


def test_tombstoned_surrogates_are_not_issued(
    engine: MaskingEngine, vault: Vault, store: InMemoryVaultStore
) -> None:
    surrogate = vault.issue("IMEI", canary("IMEI", 6))
    store.tombstone("IMEI", surrogate)
    assert (
        refused(engine, "accountSearch", search("IMEI", surrogate)).code == "IDENTIFIER_NOT_ISSUED"
    )


def test_ipv6_and_subnet_surrogates_map_back(engine: MaskingEngine, vault: Vault) -> None:
    v6 = vault.issue("IPV6", canary("IPV6", 1))
    assert canary("IPV6", 1).encode() in unmask(engine, "accountSearch", search("IP_ADDRESS", v6))
    v4 = vault.issue("IPV4", canary("IPV4", 1))
    out = unmask(engine, "accountSearch", search("IP_ADDRESS", v4 + "/29"))
    assert f"{canary('IPV4', 1)}/29".encode() in out
    assert refused(engine, "accountSearch", search("IP_ADDRESS", "a/b/c")).code == "NOT_A_SURROGATE"
