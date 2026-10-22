"""WSDL schema validation of a plan request (design §5.5 step 1), against the real snapshot."""

import re
from collections.abc import Callable, Iterator
from importlib import resources
from pathlib import Path

import pytest

from airtimesat_platform.gateway import sitest_port
from airtimesat_platform.gateway.errors import GatewayError
from airtimesat_platform.gateway.sitest_port import Endpoint, SchemaRefusal, validate_request

P = Endpoint.PROVISIONING
XS = "http://www.w3.org/2001/XMLSchema"
# A value that must never reach a refusal. Letters only, so it is no identifier.
SENTINEL = "SntVal" + "q" * 10
SEARCH = (
    "<request><filterType>IMEI</filterType><filterCond>EQUALS</filterCond>"
    "<filterValue>{value}</filterValue><limit>{limit}</limit><startRow>0</startRow>{extra}"
    "</request>"
)


def _search(value: str = "x", limit: str = "5", extra: str = "") -> str:
    return SEARCH.format(value=value, limit=limit, extra=extra)


def test_valid_requests_pass() -> None:
    assert validate_request(P, "accountSearch", _search(SENTINEL)) is None
    assert validate_request(P, "getSystemStatus", "<request/>") is None
    assert validate_request(Endpoint.REPORTING, "getIwsReportVersion", "<request/>") is None


@pytest.mark.parametrize(
    ("request_xml", "refusal"),
    [
        # An unknown element, named by the plan: shown as "?".
        (
            _search(extra=f"<{SENTINEL}>1</{SENTINEL}>"),
            SchemaRefusal("SCHEMA_CONTENT", "request/?"),
        ),
        # A wrong type.
        (_search(limit=SENTINEL), SchemaRefusal("SCHEMA_VALUE", "request/limit")),
        # A wrong enumeration value.
        (
            _search().replace("EQUALS", SENTINEL),
            SchemaRefusal("SCHEMA_VALUE", "request/filterCond"),
        ),
        # A missing required element (startRow).
        (
            _search(SENTINEL).replace("<startRow>0</startRow>", ""),
            SchemaRefusal("SCHEMA_CONTENT", "request"),
        ),
        # A wrong namespace, on the request or on one element.
        (
            _search(SENTINEL).replace("<request>", '<request xmlns="urn:x">'),
            SchemaRefusal("SCHEMA_CONTENT", "?"),
        ),
        (
            _search(SENTINEL).replace("<limit>", '<limit xmlns="urn:x">'),
            SchemaRefusal("SCHEMA_CONTENT", "request/?"),
        ),
        # An authentication field: the signer core adds them, so a plan may not.
        (
            _search().replace("<request>", f"<request><iwsUsername>{SENTINEL}</iwsUsername>"),
            SchemaRefusal("SCHEMA_CONTENT", "request/?"),
        ),
        (f"<request>{SENTINEL}", SchemaRefusal("SCHEMA_NOT_PLAIN_XML", "")),
        (f"<!DOCTYPE r><request>{SENTINEL}</request>", SchemaRefusal("SCHEMA_NOT_PLAIN_XML", "")),
    ],
)
def test_invalid_requests_refuse_without_a_value(request_xml: str, refusal: SchemaRefusal) -> None:
    result = validate_request(P, "accountSearch", request_xml)
    assert result == refusal
    assert SENTINEL not in repr(result)


def test_an_operation_outside_the_endpoint_is_refused() -> None:
    result = validate_request(Endpoint.REPORTING, "accountSearch", _search())
    assert result == SchemaRefusal("SCHEMA_UNKNOWN_OPERATION", "")


def test_a_placeholder_is_not_judged_on_its_value() -> None:
    request = "<request><limit>${item}</limit><startRow>0</startRow></request>"
    assert validate_request(P, "getEvoucherInventory", request, placeholder="${item}") is None
    refused = validate_request(P, "getEvoucherInventory", request)
    assert refused == SchemaRefusal("SCHEMA_VALUE", "request/limit")
    # Only a value error is forgiven: a placeholder in an unknown element still refuses.
    unknown = request.replace("<startRow>", "<x>${item}</x><startRow>")
    assert validate_request(P, "getEvoucherInventory", unknown, placeholder="${item}") is not None


@pytest.mark.parametrize(
    ("operation", "element"),
    [
        (
            "getEvoucherInventory",
            f"<limit>${{item}}<x>{SENTINEL}</x></limit><startRow>0</startRow>",
        ),
        ("getEvoucherInventory", f'<limit a="{SENTINEL}">${{item}}</limit><startRow>0</startRow>'),
        ("getSubscriberAccount", f"<accountNo>${{item}}<x>{SENTINEL}</x></accountNo>"),
        ("getSubscriberAccount", f'<accountNo a="{SENTINEL}">${{item}}</accountNo>'),
    ],
)
def test_a_placeholder_does_not_excuse_children_or_attributes(operation: str, element: str) -> None:
    result = validate_request(P, operation, f"<request>{element}</request>", placeholder="${item}")
    assert result is not None
    assert result.code == "SCHEMA_CONTENT"
    assert SENTINEL not in repr(result)


@pytest.fixture
def fresh_schema() -> Iterator[None]:
    # The test changes where the snapshot is read from, so it resets the per-process schema
    # cache, which has no public reset.
    sitest_port._endpoint_schema.cache_clear()  # pyright: ignore[reportPrivateUsage]
    yield
    sitest_port._endpoint_schema.cache_clear()  # pyright: ignore[reportPrivateUsage]


@pytest.mark.usefixtures("fresh_schema")
def test_without_the_snapshot_nothing_is_checked(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(sitest_port, "WSDL_SNAPSHOT", ("wsdl", "absent"))
    assert validate_request(P, "accountSearch", "<request><x/></request>") is None


def _use_changed_snapshot(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, change: Callable[[bytes], bytes]
) -> None:
    """Point the port at a changed copy of the real provisioning snapshot in ``tmp_path``."""
    real = (
        resources.files("airtimesat_platform.gateway")
        .joinpath("wsdl", "sitest", "provisioning.wsdl")
        .read_bytes()
    )
    changed = change(real)
    assert changed != real
    (tmp_path / "provisioning.wsdl").write_bytes(changed)
    monkeypatch.setattr(sitest_port, "WSDL_SNAPSHOT", (str(tmp_path),))


@pytest.mark.usefixtures("fresh_schema")
@pytest.mark.parametrize("component", ["import", "include", "redefine", "override"])
def test_a_schema_that_loads_another_file_is_refused(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, component: str
) -> None:
    (tmp_path / "other.xsd").write_text(f'<xs:schema xmlns:xs="{XS}"/>', encoding="utf-8")
    load = f'<xs:{component} xmlns:xs="{XS}" schemaLocation="other.xsd"/>'.encode()
    _use_changed_snapshot(
        monkeypatch,
        tmp_path,
        lambda wsdl: re.sub(rb"(<xs:schema[^>]*>)", lambda m: m.group(1) + load, wsdl, count=1),
    )
    with pytest.raises(GatewayError) as raised:
        validate_request(P, "getSystemStatus", "<request/>")
    assert raised.value.code == "WSDL_SNAPSHOT_INVALID"


@pytest.mark.usefixtures("fresh_schema")
def test_an_unprefixed_message_name_is_resolved(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    old, new = b'message="tns:getSystemStatus"', b'message="getSystemStatus"'
    _use_changed_snapshot(monkeypatch, tmp_path, lambda wsdl: wsdl.replace(old, new, 1))
    assert validate_request(P, "getSystemStatus", "<request/>") is None
