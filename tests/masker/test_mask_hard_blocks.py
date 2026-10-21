"""The recorder's hard blocks (design §5.4, §5.7; §8.5 #8, #9, #11, #14).

The blocks are code, not plan data, and run before every other check of a plan. They are
an implementation independent of the signer core's guard, which has its own tests in
``tests/gateway/test_sitest_guard.py``.
"""

import ast
import inspect
from collections.abc import Mapping
from datetime import UTC, datetime

import pytest
import yaml

from airtimesat_platform.gateway import sitest_guard
from airtimesat_platform.recorder.errors import PlanRefusedError
from airtimesat_platform.recorder.plan import load_plan
from airtimesat_platform.recorder.policy import hard_blocks
from airtimesat_platform.recorder.policy.hard_blocks import (
    ALWAYS_REFUSED,
    check_call,
    check_document,
    check_text,
)

NOW = datetime(2026, 10, 21, 12, 0, tzinfo=UTC)
CONTRACT = "SUB-9004217"
STATUS = "setSubscriberAccountStatus"


def status_request(new_status: str = "SUSPENDED", extra: str = "") -> str:
    return (
        "<request><updateType>SUBSCRIBER_ACCOUNT_NUMBER</updateType>"
        f"<value>{CONTRACT}</value><newStatus>{new_status}</newStatus>{extra}</request>"
    )


def blocked(operation: str, request: str, endpoint: str = "provisioning", **extra: object) -> str:
    call: dict[str, object] = {
        "id": "a",
        "endpoint": endpoint,
        "operation": operation,
        "request": request,
    } | extra
    with pytest.raises(PlanRefusedError) as info:
        check_call(call)
    assert info.value.location in ("calls[0]", "")
    return info.value.code


def passes(operation: str, request: str, endpoint: str = "provisioning") -> None:
    check_call({"id": "a", "endpoint": endpoint, "operation": operation, "request": request})


def plan(*calls: Mapping[str, object], **top: object) -> str:
    doc: dict[str, object] = {
        "id": "RP-2026-003",
        "title": "Hard block test",
        "purpose": "Design 8.5",
        "expires_at": "2026-11-30T00:00:00Z",
        "max_calls": 10,
        "calls": list(calls),
    } | top
    return yaml.safe_dump(doc, sort_keys=False, width=1000)


def refused(text: str) -> str:
    with pytest.raises(PlanRefusedError) as info:
        load_plan(text, now=NOW)
    return info.value.code


# ---------------------------------------------------------------- independence


def test_the_blocks_share_nothing_with_the_gateway_guard() -> None:
    tree = ast.parse(inspect.getsource(hard_blocks))
    imported = [
        node.module or "" for node in ast.walk(tree) if isinstance(node, ast.ImportFrom)
    ] + [
        alias.name
        for node in ast.walk(tree)
        if isinstance(node, ast.Import)
        for alias in node.names
    ]
    assert imported
    assert not [name for name in imported if name.startswith("airtimesat_platform.gateway")]


def test_every_name_the_guard_refuses_is_refused_here() -> None:
    folded = {name.casefold() for name in ALWAYS_REFUSED}
    assert {name.casefold() for name in sitest_guard.ALWAYS_REFUSED} <= folded


# ---------------------------------------------------------------- DEACTIVE (§8.5 #11)


@pytest.mark.parametrize(
    "new_status",
    [
        "DEACTIVE",
        "CLOSED",
        " DEACTIVE ",
        "Deactive",
        "deactive",
        "\uff24\uff25\uff21\uff23\uff34\uff29\uff36\uff25",  # full-width DEACTIVE
        "DE\u200bACTIVE",  # zero-width space inside
        "&#68;EACTIVE",  # a character reference
        "\n\tclosed\n",
        "",
        "TERMINATED",
    ],
)
def test_new_status_other_than_suspended_or_active(new_status: str) -> None:
    assert blocked(STATUS, status_request(new_status)) == "ALWAYS_REFUSED_DEACTIVE"


def test_the_two_safe_statuses_pass() -> None:
    passes(STATUS, status_request("SUSPENDED"))
    passes(STATUS, status_request(" active "))


def test_new_status_exactly_once() -> None:
    twice = status_request("SUSPENDED", "<newStatus>SUSPENDED</newStatus>")
    assert blocked(STATUS, twice) == "ALWAYS_REFUSED_DEACTIVE"
    none = "<request><updateType>SUBSCRIBER_ACCOUNT_NUMBER</updateType></request>"
    assert blocked(STATUS, none) == "ALWAYS_REFUSED_DEACTIVE"
    nested = status_request("SUSPENDED").replace(
        "<newStatus>SUSPENDED</newStatus>", "<newStatus><x>SUSPENDED</x></newStatus>"
    )
    assert blocked(STATUS, nested) == "ALWAYS_REFUSED_DEACTIVE"


@pytest.mark.parametrize("operation", ["SetSubscriberAccountStatus", "setsubscriberaccountstatus"])
def test_deactive_in_a_wrong_case_operation_is_still_deactive(operation: str) -> None:
    assert blocked(operation, status_request("DEACTIVE")) == "ALWAYS_REFUSED_DEACTIVE"


def test_new_status_deactive_in_any_operation() -> None:
    request = f"<request><accountNo>{CONTRACT}</accountNo><NEWSTATUS>Closed</NEWSTATUS></request>"
    assert blocked("getSubscriberAccount", request) == "ALWAYS_REFUSED_DEACTIVE"


@pytest.mark.parametrize("value", ["TRUE", "true", "", "yes", "1", "FALSE FALSE", "<x>FALSE</x>"])
def test_bypass_quarantine_other_than_false(value: str) -> None:
    request = status_request("SUSPENDED", f"<bypassQuarantine>{value}</bypassQuarantine>")
    assert blocked(STATUS, request) == "ALWAYS_REFUSED_DEACTIVE"


@pytest.mark.parametrize("value", ["FALSE", "false", " False "])
def test_bypass_quarantine_false_is_accepted(value: str) -> None:
    passes(STATUS, status_request("SUSPENDED", f"<bypassQuarantine>{value}</bypassQuarantine>"))


@pytest.mark.parametrize("status", ["ACTIVE", "SUSPENDED", "DEACTIVE", ""])
def test_account_update_never_carries_account_status(status: str) -> None:
    request = f"<request><account><accountStatus>{status}</accountStatus></account></request>"
    assert blocked("accountUpdate", request) == "ALWAYS_REFUSED_DEACTIVE"


@pytest.mark.parametrize(
    "operation", ["activateSubscriber", "accountUpdate", "rechargePrepaidAccount"]
)
def test_a_terminal_literal_anywhere_in_a_write(operation: str) -> None:
    request = "<request><anything>closed</anything></request>"
    assert blocked(operation, request) == "ALWAYS_REFUSED_DEACTIVE"


def test_a_plan_that_lists_deactive_fails_before_writes_and_schema() -> None:
    call = {"endpoint": "provisioning", "operation": STATUS, "request": status_request("DEACTIVE")}
    # No call id (a schema error) and a writes section (a D3 refusal): DEACTIVE still wins.
    assert refused(plan(call, writes={"max_writes": 1})) == "ALWAYS_REFUSED_DEACTIVE"


def test_deactive_in_a_later_call_wins_over_an_earlier_refusal() -> None:
    first = {
        "id": "a",
        "endpoint": "provisioning",
        "operation": "noSuchMethod",
        "request": "<request/>",
    }
    second = {
        "id": "b",
        "endpoint": "provisioning",
        "operation": STATUS,
        "request": status_request("CLOSED"),
    }
    with pytest.raises(PlanRefusedError) as info:
        load_plan(plan(first, second), now=NOW)
    assert (info.value.code, info.value.location) == ("ALWAYS_REFUSED_DEACTIVE", "calls[1]")


# ---------------------------------------------------------------- bulk (§8.5 #11)


@pytest.mark.parametrize(
    ("operation", "body"),
    [
        ("activateSubscriber", "<request><bulkAction>TRUE</bulkAction></request>"),
        ("activateSubscriber", "<request><bulkAction>Yes</bulkAction></request>"),
        ("activateSubscriber", "<request><bulkAction/></request>"),
        ("activateSubscriber", "<request><sbdBulkDetails><x>1</x></sbdBulkDetails></request>"),
        ("activateSubscriber", "<request><BULKDETAILS/></request>"),
        ("activateSubscriber", "<request><m2MBulkDetailImpl/></request>"),
        ("activateSubscriber", "<request><deviceString> bulk </deviceString></request>"),
        ("accountSearch", "<request><imeiDevice>BULK</imeiDevice></request>"),
        (
            "activateSubscriber",
            '<request xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:t="urn:t">'
            '<account xsi:type="t:sbdBulkAccountImpl"/></request>',
        ),
        ("bulkAccountUpdate", "<request/>"),
        ("BulkAddPrepaid", "<request/>"),
        ("bulkDeletePrepaid", "<request/>"),
    ],
)
def test_bulk(operation: str, body: str) -> None:
    assert blocked(operation, body) == "ALWAYS_REFUSED_BULK"


def test_bulk_action_false_or_absent_passes_the_bulk_block() -> None:
    passes("activateSubscriber", "<request><bulkAction>FALSE</bulkAction></request>")
    passes("activateSubscriber", "<request><serviceType>SBD</serviceType></request>")


# ---------------------------------------------------------------- always refused (§8.5 #14)


@pytest.mark.parametrize("operation", sorted(ALWAYS_REFUSED))
def test_every_always_refused_method(operation: str) -> None:
    endpoint = "provisioning"
    code = blocked(operation, "<request/>", endpoint)
    assert code == ALWAYS_REFUSED[operation]
    assert code.startswith("ALWAYS_REFUSED_")


@pytest.mark.parametrize(
    "operation", ["createOnDemandReport", "CREATEONDEMANDREPORT", "createOnDemandReport "]
)
def test_on_demand_reports_in_any_mode_and_case(operation: str) -> None:
    request = "<request><background>TRUE</background></request>"
    assert blocked(operation, request, "reporting") == "ALWAYS_REFUSED_METHOD"
    inline = "<request><background>FALSE</background></request>"
    assert blocked(operation, inline, "reporting") == "ALWAYS_REFUSED_METHOD"


@pytest.mark.parametrize(
    ("operation", "code"),
    [
        ("manageDestinations", "ALWAYS_REFUSED_SP_WIDE"),
        ("sbdDestinationSearchReplace", "ALWAYS_REFUSED_SP_WIDE"),
        ("sbdMOQueuePurge", "ALWAYS_REFUSED_SP_WIDE"),
        ("updateEmailNotification", "ALWAYS_REFUSED_SP_WIDE"),
        ("getAccountPoolingGroups", "ALWAYS_REFUSED_METHOD"),
        ("resetIWSUserPassword", "ALWAYS_REFUSED_METHOD"),
        ("accountUpdateDevices", "ALWAYS_REFUSED_METHOD"),
    ],
)
def test_sp_wide_writes_and_others_by_name(operation: str, code: str) -> None:
    assert blocked(operation, "<request/>") == code


# ---------------------------------------------------------------- operation tricks (§8.5 #8)


@pytest.mark.parametrize(
    ("operation", "endpoint", "code"),
    [
        ("AccountSearch", "provisioning", "OPERATION_WRONG_CASE"),
        ("accountsearch", "provisioning", "OPERATION_WRONG_CASE"),
        ("getSubscriberOrganizations", "provisioning", "OPERATION_UNKNOWN"),
        ("accountSearch2", "provisioning", "OPERATION_UNKNOWN"),
        ("", "provisioning", "OPERATION_UNKNOWN"),
        ("getReportTypes", "provisioning", "OPERATION_ENDPOINT_MISMATCH"),
        ("accountSearch", "reporting", "OPERATION_ENDPOINT_MISMATCH"),
        ("activateSubscriber", "reporting", "OPERATION_ENDPOINT_MISMATCH"),
        ("accountSearch", "beta", "ENDPOINT_INVALID"),
        ("accountSearch", "Provisioning", "ENDPOINT_INVALID"),
    ],
)
def test_operation_and_endpoint(operation: str, endpoint: str, code: str) -> None:
    assert blocked(operation, "<request/>", endpoint) == code


@pytest.mark.parametrize(
    ("body", "code"),
    [
        ("<getSubscriberAccount><request/></getSubscriberAccount>", "OPERATION_ROOT_MISMATCH"),
        ("<accountSearch><request/></accountSearch>", "REQUEST_ROOT_INVALID"),
        ("<query/>", "REQUEST_ROOT_INVALID"),
        ("<request/><request/>", "TWO_OPERATIONS_IN_BODY"),
        ("<request/><getSubscriberAccount/>", "TWO_OPERATIONS_IN_BODY"),
        ("<request><getSubscriberAccount/></request>", "TWO_OPERATIONS_IN_BODY"),
        ("<request><SETSUBSCRIBERACCOUNTSTATUS/></request>", "TWO_OPERATIONS_IN_BODY"),
        ("text<request/>", "REQUEST_TEXT_OUTSIDE_ELEMENT"),
        (" ", "REQUEST_EMPTY"),
        ("<request>", "XML_PARSE"),
        ('<?xml version="1.0"?><request/>', "XML_PI"),
        ("<request><?pi x?></request>", "XML_PI"),
        ("<request><!-- c --></request>", "XML_COMMENT"),
        ("<request><newStatus>DE<!---->ACTIVE</newStatus></request>", "XML_COMMENT"),
        ("<request><newStatus><![CDATA[DEACTIVE]]></newStatus></request>", "XML_CDATA"),
        ('<!DOCTYPE request [<!ENTITY x "DEACTIVE">]><request>&x;</request>', "XML_DTD"),
        ("<request>&undefined;</request>", "XML_PARSE"),
        ('<x:request xmlns:x="urn:x"/>', "ELEMENT_NAMESPACE_REFUSED"),
        ('<request xmlns="urn:x"/>', "ELEMENT_NAMESPACE_REFUSED"),
    ],
)
def test_request_shape(body: str, code: str) -> None:
    assert blocked("accountSearch", body) == code


@pytest.mark.parametrize(
    "body",
    [
        '<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope"><soap:Body>'
        "<request/></soap:Body></soap:Envelope>",
        '<request><soap:Header xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"/></request>',
        "<Envelope><Body><request/></Body></Envelope>",
        "<Header/><request/>",
    ],
)
def test_soap_envelopes_and_headers(body: str) -> None:
    assert blocked("accountSearch", body) == "SOAP_ENVELOPE_IN_PLAN"


@pytest.mark.parametrize(
    "field",
    [
        "iwsUsername",
        "signature",
        "timestamp",
        "serviceProviderAccountNumber",
        "caller",
        "callerPassword",
        "CALLER",
        "CallerPassword",
    ],
)
def test_authentication_fields(field: str) -> None:
    request = f"<request><filterType>IMEI</filterType><{field}>x</{field}></request>"
    assert blocked("accountSearch", request) == "AUTH_FIELD_IN_REQUEST"
    nested = f"<request><a><{field}>x</{field}></a></request>"
    assert blocked("accountSearch", nested) == "AUTH_FIELD_IN_REQUEST"


@pytest.mark.parametrize(
    "key", ["action", "soapAction", "soap_action", "SOAPAction", "soap-action"]
)
def test_a_soap_action_in_the_plan(key: str) -> None:
    assert blocked("accountSearch", "<request/>", **{key: "accountSearch"}) == "SOAP_ACTION_IN_PLAN"


def test_a_caller_key_in_the_plan_is_refused_by_the_schema() -> None:
    call = {
        "id": "a",
        "endpoint": "provisioning",
        "operation": "getSystemStatus",
        "request": "<request/>",
    }
    assert refused(plan(call | {"caller": "rec.RP-2026-003"})) == "SCHEMA_UNKNOWN_KEY"


# ---------------------------------------------------------------- endpoint tricks (§8.5 #9)

# Host names are assembled at run time, so no Iridium host name sits in this file.
IRIDIUM = "iridium" + ".com"


@pytest.mark.parametrize(
    "host",
    [
        f"beta.{IRIDIUM}",
        f"www.{IRIDIUM}",
        f"BETA.{IRIDIUM.upper()}",
        f"iws.{IRIDIUM}:8443",
        f"https://iws.{IRIDIUM}/iws-current/iws",
        f"iws.iridium%2E{'com'}",
        f"iws.iridium\uff0e{'com'}",  # a full-width full stop
        # IDNA label separators that NFKC keeps or maps to U+3002
        f"iws.iridium\u3002{'com'}",  # the ideographic full stop
        f"iws.iridium\uff61{'com'}",  # the halfwidth ideographic full stop
        f"iws.iridium%E3%80%82{'com'}",
        # Encoded full stops and format characters, and double or triple encodings
        f"iws.iridium%EF%BC%8E{'com'}",
        f"iws.iridium%E2%80%8B.{'com'}",
        f"iws.iri%E2%80%8Bdium.{'com'}",
        f"iws.iridium%252e{'com'}",
        f"iws.iridium%25252e{'com'}",
    ],
)
def test_iridium_host_names_anywhere_in_the_plan(host: str) -> None:
    with pytest.raises(PlanRefusedError) as info:
        check_text(f"title: {host}\n")
    assert info.value.code == "IRIDIUM_HOST_IN_PLAN"
    assert refused(plan({"id": "a"}, title=host)) == "IRIDIUM_HOST_IN_PLAN"


def test_an_iridium_host_hidden_by_yaml_or_xml_escapes() -> None:
    escaped = 'title: "iws.iridium\\x2ecom"\n'
    assert IRIDIUM not in escaped
    with pytest.raises(PlanRefusedError) as info:
        check_document(yaml.safe_load(escaped))
    assert info.value.code == "IRIDIUM_HOST_IN_PLAN"
    request = "<request><filterValue>iws.iridium&#46;com</filterValue></request>"
    assert blocked("accountSearch", request) == "IRIDIUM_HOST_IN_PLAN"
    request = "<request><filterValue>iws.iridium&#x3002;com</filterValue></request>"
    assert blocked("accountSearch", request) == "IRIDIUM_HOST_IN_PLAN"


@pytest.mark.parametrize("text", ["100%", "100%25 done", "version 22.2", "a%2"])
def test_percent_signs_and_versions_are_not_host_names(text: str) -> None:
    check_text(f"title: '{text}'\n")


def test_the_iws_namespace_declaration_names_no_endpoint() -> None:
    request = (
        f'<request xmlns:irid="http://www.{IRIDIUM}" '
        'xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="irid:requestImpl"/>'
    )
    passes("getSystemStatus", request)
    check_text(f"request: '{request}'\n")
    with pytest.raises(PlanRefusedError):
        check_text(f"request: '<request xmlns:irid=\"http://beta.{IRIDIUM}\"/>'\n")


def test_refusals_carry_codes_never_values() -> None:
    marker = "Zq" + "x" * 3 + "MARK"
    with pytest.raises(PlanRefusedError) as info:
        check_call(
            {"operation": STATUS, "endpoint": "provisioning", "request": status_request(marker)}
        )
    text = f"{info.value} {info.value!r} {info.value.args}"
    assert marker not in text
    assert "ALWAYS_REFUSED_DEACTIVE" in text


def test_a_document_of_any_shape_is_read_safely() -> None:
    docs: list[object] = [None, [], "x", {"calls": "x"}, {"calls": [1, None, {"operation": 3}]}]
    for doc in docs:
        check_document(doc)
