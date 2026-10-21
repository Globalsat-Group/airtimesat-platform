"""The vault-free request check that ``recorder check`` runs in CI (design §5.1, §5.5).

``check_request`` shares the request walk of ``unmask_request``: every refusal below is
also an ``unmask_request`` refusal with the same code. Only the identifier test differs:
the exact surrogate shape of the type instead of an issued vault row.
"""

import pytest

from airtimesat_platform.masker.detect.canary import canary
from airtimesat_platform.masker.engine import MaskingEngine, RequestRefusal
from airtimesat_platform.masker.errors import MaskingBlockedError, RequestRefusedError
from airtimesat_platform.masker.fieldmap.model import FieldMap
from airtimesat_platform.masker.freetext import Template
from airtimesat_platform.masker.tokenize.surrogates import SPECS
from airtimesat_platform.masker.tokenize.vault import Vault

XSI = "http://www.w3.org/2001/XMLSchema-instance"
STATUS = "setSubscriberAccountStatus"


def shaped(type_name: str) -> str:
    """Return a well-formed surrogate that no vault issued."""
    return SPECS[type_name].render(bytes(range(32)), "")


def search(filter_type: str, value: str, extra: str = "") -> bytes:
    return (
        f"<request><filterType>{filter_type}</filterType><filterValue>{value}</filterValue>"
        f"<filterCond>EQUALS</filterCond><limit>5</limit>{extra}</request>"
    ).encode()


def status(value: str, extra: str = "") -> bytes:
    return (
        "<request><updateType>SUBSCRIBER_ACCOUNT_NUMBER</updateType>"
        f"<value>{value}</value><newStatus>SUSPENDED</newStatus>{extra}</request>"
    ).encode()


@pytest.fixture(name="checker")
def checker_fixture(mapped: tuple[FieldMap, list[Template]]) -> MaskingEngine:
    """Return an engine with no vault: it can only check."""
    return MaskingEngine(mapped[0], None)


# Requests that fail, with the code and path. IMEI_SURROGATE and CONTRACT_SURROGATE are filled
# in by each test: well-formed surrogates for the check, issued ones for unmask_request.
REFUSALS: list[tuple[str, bytes, str, str]] = [
    ("accountSearch", search("IMEI", canary("IMEI", 1)), "NOT_A_SURROGATE", "request/filterValue"),
    ("accountSearch", search("IMEI", "99000000*"), "WILDCARD_REFUSED", "request/filterValue"),
    ("accountSearch", search("VESSEL_NAME", "%Vessel"), "WILDCARD_REFUSED", "request/filterValue"),
    (
        "accountSearch",
        search("VESSEL_NAME", "Ocean Explorer"),
        "NOT_A_SURROGATE",
        "request/filterValue",
    ),
    ("accountSearch", search("SMART", "IMEI_SURROGATE"), "TYPING_UNKNOWN", "request/filterValue"),
    (
        "accountSearch",
        search("IMEI", "IMEI_SURROGATE", f"<comment>call {canary('MSISDN', 1)}</comment>"),
        "REAL_FORMAT_VALUE",
        "request/comment",
    ),
    (
        "accountSearch",
        search("IMEI", "IMEI_SURROGATE", "<unknown>x</unknown>"),
        "UNKNOWN_ELEMENT",
        "request/unknown",
    ),
    (
        "accountSearch",
        search("IMEI", "IMEI_SURROGATE", "<limit>5</limit>"),
        "MAX_OCCURS",
        "request/limit",
    ),
    (
        "accountSearch",
        search("IMEI", "IMEI_SURROGATE").replace(b"<limit>", b'<limit a="1">'),
        "UNKNOWN_ATTRIBUTE",
        "request/limit",
    ),
    (
        "accountSearch",
        search("IMEI", "IMEI_SURROGATE").replace(
            b"<request>", f'<request xmlns:xsi="{XSI}" xmlns:t="urn:t" xsi:type="t:x">'.encode()
        ),
        "UNKNOWN_XSI_TYPE",
        "request[x]",
    ),
    (
        "accountSearch",
        search("IMEI", "IMEI_SURROGATE", "<comment><b/></comment>"),
        "UNEXPECTED_CHILDREN",
        "request/comment",
    ),
    ("accountSearch", b"<request>text<limit>5</limit></request>", "MIXED_CONTENT", "request"),
    ("accountSearch", search("IMEI", "IMEI_SURROGATE", "<!-- note -->"), "XML_COMMENT", ""),
    ("accountSearch", search("IMEI", "IMEI_SURROGATE", "<?pi x?>"), "XML_PI", ""),
    ("accountSearch", search("IMEI", "<![CDATA[x]]>"), "XML_CDATA", ""),
    ("accountSearch", b'<!DOCTYPE request [<!ENTITY e "x">]><request/>', "XML_DTD", ""),
    (
        "accountSearch",
        search("IMEI", "IMEI_SURROGATE", "<caller>rec.x</caller>"),
        "AUTH_FIELD_IN_REQUEST",
        "",
    ),
    (
        "accountSearch",
        search("IMEI", "IMEI_SURROGATE", "<Signature>x</Signature>"),
        "AUTH_FIELD_IN_REQUEST",
        "",
    ),
    (
        STATUS,
        status("CONTRACT_SURROGATE", "<owner>SP-01</owner>"),
        "CONSTANT_UNKNOWN",
        "request/owner",
    ),
    (
        STATUS,
        status("CONTRACT_SURROGATE", "<owner>SP-0000</owner>"),
        "CONSTANT_UNKNOWN",
        "request/owner",
    ),
    (
        STATUS,
        status("CONTRACT_SURROGATE", f"<contact>{canary('EMAIL', 1)}</contact>"),
        "NOT_A_SURROGATE",
        "request/contact",
    ),
    (
        STATUS,
        status("CONTRACT_SURROGATE", f"<reason>line {canary('IMEI', 2)}</reason>"),
        "REAL_FORMAT_VALUE",
        "request/reason",
    ),
    (STATUS, status("SUB-1234"), "NOT_A_SURROGATE", "request/value"),
]


def fill(body: bytes, imei: str, contract: str) -> bytes:
    return body.replace(b"IMEI_SURROGATE", imei.encode()).replace(
        b"CONTRACT_SURROGATE", contract.encode()
    )


@pytest.mark.parametrize(("operation", "body", "code", "path"), REFUSALS)
def test_refusals(
    checker: MaskingEngine, operation: str, body: bytes, code: str, path: str
) -> None:
    refusal = checker.check_request(operation, fill(body, shaped("IMEI"), shaped("CONTRACT")))
    assert refusal is not None
    assert (refusal.code, refusal.path) == (code, path)


@pytest.mark.parametrize(("operation", "body", "code", "path"), REFUSALS)
def test_the_check_shares_the_unmask_walk(
    engine: MaskingEngine, vault: Vault, operation: str, body: bytes, code: str, path: str
) -> None:
    # The same corpus through unmask_request, with issued surrogates: the same refusals.
    imei = vault.issue("IMEI", canary("IMEI", 7))
    contract = vault.issue("CONTRACT", canary("CONTRACT", 7))
    with pytest.raises(RequestRefusedError) as info:
        engine.unmask_request(engine.start_call(operation), fill(body, imei, contract))
    assert (info.value.code, info.value.path) == (code, path)


@pytest.mark.parametrize(
    ("operation", "body"),
    [
        ("accountSearch", search("IMEI", shaped("IMEI"))),
        ("accountSearch", search("MSISDN", shaped("MSISDN"))),
        ("accountSearch", search("ACCOUNT_NUMBER", shaped("CONTRACT"))),
        ("accountSearch", search("VESSEL_NAME", shaped("VESSEL"))),
        ("accountSearch", search("IP_ADDRESS", shaped("IPV4"))),
        ("accountSearch", search("IMEI", shaped("IMEI"), "<comment>Annex F ST-03</comment>")),
        (STATUS, status(shaped("CONTRACT"), "<owner>SP-0001</owner>")),
        (STATUS, status(shaped("CONTRACT"), "<owner>GLOBAL</owner>")),
        (STATUS, status(shaped("CONTRACT"), f"<contact>{shaped('EMAIL')}</contact>")),
        ("getSystemStatus", b"<request/>"),
    ],
)
def test_well_formed_surrogates_pass_without_a_vault(
    checker: MaskingEngine, operation: str, body: bytes
) -> None:
    assert checker.check_request(operation, body) is None


def test_issuing_is_a_run_time_check(engine: MaskingEngine, checker: MaskingEngine) -> None:
    # The same request passes the check and is refused at run time: no vault row.
    body = search("IMEI", shaped("IMEI"))
    assert checker.check_request("accountSearch", body) is None
    with pytest.raises(RequestRefusedError) as info:
        engine.unmask_request(engine.start_call("accountSearch"), body)
    assert info.value.code == "IDENTIFIER_NOT_ISSUED"


def test_an_operation_outside_the_field_map(checker: MaskingEngine) -> None:
    assert checker.check_request("getVessels", b"<request/>") == RequestRefusal(
        "OPERATION_NOT_IN_FIELD_MAP"
    )


def test_refusals_carry_codes_never_values(checker: MaskingEngine) -> None:
    real = canary("IMEI", 3)
    refusal = checker.check_request("accountSearch", search("IMEI", real))
    assert refusal is not None
    assert real not in f"{refusal} {refusal!r}"


def test_the_check_resolves_nothing_and_touches_no_vault(
    checker: MaskingEngine, vault: Vault
) -> None:
    assert checker.check_request("accountSearch", search("IMEI", shaped("IMEI"))) is None
    assert vault.issued.total() == 0


def test_an_engine_without_a_vault_cannot_mask_or_unmask(checker: MaskingEngine) -> None:
    with pytest.raises(RequestRefusedError) as unmasked:
        checker.unmask_request(checker.start_call("accountSearch"), search("IMEI", shaped("IMEI")))
    assert unmasked.value.code == "VAULT_UNAVAILABLE"
    body = (
        b'<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"><soap:Body>'
        b"<getSystemStatusResponse><status>OK</status></getSystemStatusResponse>"
        b"</soap:Body></soap:Envelope>"
    )
    with pytest.raises(MaskingBlockedError) as masked:
        checker.mask_response(checker.start_call("getSystemStatus"), body)
    assert masked.value.code == "VAULT_UNAVAILABLE"


def test_an_unexpected_error_fails_closed(
    checker: MaskingEngine, monkeypatch: pytest.MonkeyPatch
) -> None:
    def explode(*_: object) -> None:
        raise ZeroDivisionError

    monkeypatch.setattr(MaskingEngine, "_walk_element", explode)
    refusal = checker.check_request("accountSearch", search("IMEI", shaped("IMEI")))
    assert refusal == RequestRefusal("CHECK_FAILED", "", "ZeroDivisionError")
