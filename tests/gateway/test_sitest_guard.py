"""The signer core's independent guard (design §5.3, §5.4, §5.7, §8.5 #8, #11, #14).

Envelopes here are written by hand, not by the envelope builder, so each check is shown to
hold on its own on the final bytes.
"""

import pytest

from airtimesat_platform.gateway.endpoints_sitest import Endpoint
from airtimesat_platform.gateway.errors import RefusedError
from airtimesat_platform.gateway.sitest_guard import (
    ALWAYS_REFUSED,
    READS_PROVISIONING,
    READS_REPORTING,
    WRITES_PROVISIONING,
    check_envelope,
    check_operation,
    redact_echoes,
)

SOAP = "http://www.w3.org/2003/05/soap-envelope"
AUTH = (
    "<iwsUsername>user-fake0001</iwsUsername><signature>c2lnbmF0dXJlLW5vdC1yZWFsLTAwMDE=</signature>"
    "<timestamp>2026-10-20T12:00:00Z</timestamp><caller>rec.RP-2026-001</caller>"
    "<callerPassword></callerPassword>"
)
EMPTY_CP_ELEMENT = "<callerPassword></callerPassword>"
CALLER_ELEMENT = "<caller>rec.RP-2026-001</caller>"


def _full_width(word: str) -> str:
    return "".join(chr(ord(ch) + 0xFEE0) for ch in word)


def _envelope(operation: str, inner: str, *, auth: str = AUTH, header: str = "") -> bytes:
    return (
        "<?xml version='1.0' encoding='UTF-8'?>"
        f'<soap:Envelope xmlns:soap="{SOAP}" xmlns:irid="http://www.iridium.com">{header}'
        f"<soap:Body><irid:{operation}><request>{auth}{inner}</request></irid:{operation}>"
        "</soap:Body></soap:Envelope>"
    ).encode()


def _check(operation: str, inner: str, *, allow_writes: bool = True, **kwargs: str) -> None:
    check_envelope(
        _envelope(operation, inner, **kwargs),
        endpoint=Endpoint.PROVISIONING,
        operation=operation,
        allow_writes=allow_writes,
    )


def _refused(operation: str, inner: str, *, allow_writes: bool = True, **kwargs: str) -> str:
    with pytest.raises(RefusedError) as raised:
        _check(operation, inner, allow_writes=allow_writes, **kwargs)
    return raised.value.code


# ---------------------------------------------------------------- lists


def test_allowlist_and_always_refused_are_disjoint() -> None:
    allowed = READS_PROVISIONING | READS_REPORTING | WRITES_PROVISIONING
    folded_refused = {name.casefold() for name in ALWAYS_REFUSED}
    assert not {name.casefold() for name in allowed} & folded_refused


def test_writes_are_the_design_list() -> None:
    assert {
        "activateSubscriber",
        "accountUpdate",
        "setSubscriberAccountStatus",
        "rechargePrepaidAccount",
        "subscribeBurstService",
        "unsubscribeBurstService",
    } == WRITES_PROVISIONING


@pytest.mark.parametrize("operation", sorted(ALWAYS_REFUSED))
def test_always_refused_operations(operation: str) -> None:
    for endpoint in Endpoint:
        with pytest.raises(RefusedError) as raised:
            check_operation(endpoint, operation, allow_writes=True)
        assert raised.value.code == "ALWAYS_REFUSED_METHOD"


@pytest.mark.parametrize("operation", ["CreateOnDemandReport", "MANAGEDESTINATIONS", "loadimei"])
def test_always_refused_in_any_case(operation: str) -> None:
    with pytest.raises(RefusedError) as raised:
        check_operation(Endpoint.PROVISIONING, operation, allow_writes=True)
    assert raised.value.code == "ALWAYS_REFUSED_METHOD"


@pytest.mark.parametrize(
    ("endpoint", "operation"),
    [
        (Endpoint.PROVISIONING, "AccountSearch"),  # wrong case
        (Endpoint.PROVISIONING, "getReportTypes"),  # reporting operation on provisioning
        (Endpoint.REPORTING, "accountSearch"),  # provisioning operation on reporting
        (Endpoint.REPORTING, "setSubscriberAccountStatus"),
        (Endpoint.PROVISIONING, "getAccountPoolingGroups"),  # needs an SPNet password
        (Endpoint.PROVISIONING, "somethingNew"),  # default deny
    ],
)
def test_default_deny(endpoint: Endpoint, operation: str) -> None:
    with pytest.raises(RefusedError) as raised:
        check_operation(endpoint, operation, allow_writes=True)
    assert raised.value.code == "OPERATION_NOT_ALLOWLISTED"


@pytest.mark.parametrize("operation", sorted(WRITES_PROVISIONING))
def test_writes_need_the_port_opened_for_writes(operation: str) -> None:
    with pytest.raises(RefusedError) as raised:
        check_operation(Endpoint.PROVISIONING, operation, allow_writes=False)
    assert raised.value.code == "WRITES_NOT_ENABLED"


def test_system_status_on_both_endpoints() -> None:
    for endpoint in Endpoint:
        check_operation(endpoint, "getSystemStatus", allow_writes=False)


@pytest.mark.parametrize(
    ("endpoint", "operation"),
    [(Endpoint.PROVISIONING, "getIwsVersion"), (Endpoint.REPORTING, "getIwsReportVersion")],
)
def test_version_call_on_its_own_endpoint_only(endpoint: Endpoint, operation: str) -> None:
    check_operation(endpoint, operation, allow_writes=False)
    other = next(e for e in Endpoint if e is not endpoint)
    with pytest.raises(RefusedError) as raised:
        check_operation(other, operation, allow_writes=False)
    assert raised.value.code == "OPERATION_NOT_ALLOWLISTED"


# ---------------------------------------------------------------- envelope structure


def test_a_clean_read_passes() -> None:
    _check("accountSearch", "<filterType>IMEI</filterType><limit>5</limit>", allow_writes=False)


def test_a_clean_status_change_passes() -> None:
    _check(
        "setSubscriberAccountStatus",
        "<updateType>SUBSCRIBER_ACCOUNT_NUMBER</updateType><value>SUB-9004217</value>"
        "<newStatus>SUSPENDED</newStatus><bypassQuarantine>FALSE</bypassQuarantine>",
    )


def test_soap_header_is_refused() -> None:
    assert _refused("accountSearch", "", header="<soap:Header/>") == "ENVELOPE_HEADER_OR_EXTRA_PART"


def test_two_operations_in_one_body_are_refused() -> None:
    envelope = (
        f'<soap:Envelope xmlns:soap="{SOAP}" xmlns:irid="http://www.iridium.com"><soap:Body>'
        f"<irid:accountSearch><request>{AUTH}</request></irid:accountSearch>"
        f"<irid:setSubscriberAccountStatus><request>{AUTH}<newStatus>DEACTIVE</newStatus>"
        "</request></irid:setSubscriberAccountStatus></soap:Body></soap:Envelope>"
    ).encode()
    with pytest.raises(RefusedError) as raised:
        check_envelope(
            envelope, endpoint=Endpoint.PROVISIONING, operation="accountSearch", allow_writes=True
        )
    assert raised.value.code == "ENVELOPE_NOT_ONE_CALL"


def test_body_root_must_match_the_operation() -> None:
    envelope = _envelope("setSubscriberAccountStatus", "<newStatus>ACTIVE</newStatus>")
    with pytest.raises(RefusedError) as raised:
        check_envelope(
            envelope, endpoint=Endpoint.PROVISIONING, operation="accountSearch", allow_writes=True
        )
    assert raised.value.code == "ENVELOPE_OPERATION_MISMATCH"


@pytest.mark.parametrize(
    "envelope",
    [
        b"<!DOCTYPE x><x/>",
        _envelope("accountSearch", "<!-- c --><limit>5</limit>"),
        _envelope("accountSearch", "<limit><![CDATA[5]]></limit>"),
        _envelope("accountSearch", "<?pi x?>"),
    ],
)
def test_markup_in_final_bytes_is_refused(envelope: bytes) -> None:
    with pytest.raises(RefusedError) as raised:
        check_envelope(
            envelope, endpoint=Endpoint.PROVISIONING, operation="accountSearch", allow_writes=False
        )
    assert raised.value.code == "ENVELOPE_HAS_MARKUP"


def test_soap_11_envelope_is_refused() -> None:
    envelope = _envelope("accountSearch", "").replace(
        SOAP.encode(), b"http://schemas.xmlsoap.org/soap/envelope/"
    )
    with pytest.raises(RefusedError) as raised:
        check_envelope(
            envelope, endpoint=Endpoint.PROVISIONING, operation="accountSearch", allow_writes=False
        )
    assert raised.value.code == "ENVELOPE_ROOT_INVALID"


@pytest.mark.parametrize(
    "auth",
    [
        "",
        AUTH.replace("<caller>rec.RP-2026-001</caller>", ""),
        AUTH.replace("rec.RP-2026-001", "gs.tenant.user"),
        AUTH + "<callerPassword>x</callerPassword>",
        AUTH + EMPTY_CP_ELEMENT,
        AUTH.replace(EMPTY_CP_ELEMENT, ""),
        AUTH.replace(EMPTY_CP_ELEMENT, "<callerPassword>x</callerPassword>"),
        AUTH.replace(EMPTY_CP_ELEMENT, "<callerPassword> </callerPassword>"),
        AUTH.replace(EMPTY_CP_ELEMENT, "<callerPassword><x/></callerPassword>"),
        AUTH.replace(EMPTY_CP_ELEMENT, "<CallerPassword></CallerPassword>"),
        AUTH.replace(
            EMPTY_CP_ELEMENT,
            '<callerPassword xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"'
            ' xsi:nil="true"/>',
        ),
        AUTH.replace(EMPTY_CP_ELEMENT, "").replace(
            CALLER_ELEMENT, EMPTY_CP_ELEMENT + CALLER_ELEMENT
        ),
        AUTH + "<signature>c2lnbmF0dXJlLW5vdC1yZWFsLTAwMDI=</signature>",
        AUTH + "<serviceProviderAccountNumber>SP-0001</serviceProviderAccountNumber>" * 2,
    ],
)
def test_auth_fields_must_be_exactly_as_injected(auth: str) -> None:
    assert _refused("accountSearch", "", auth=auth, allow_writes=False) in {
        "AUTH_FIELDS_INVALID",
        "CALLER_INVALID",
    }


@pytest.mark.parametrize("name", ["callerPassword", "CallerPassword", "CALLERPASSWORD"])
@pytest.mark.parametrize("value", ["x", ""])
def test_caller_password_is_refused_at_any_depth_in_any_case(name: str, value: str) -> None:
    code = _refused("accountUpdate", f"<a><{name}>{value}</{name}></a>")
    assert code == "AUTH_FIELDS_INVALID"


def test_the_single_empty_caller_password_after_caller_passes() -> None:
    # Design §13 #36: the WSDL requires callerPassword, and an empty one keeps caller
    # audit-only. The self-closing form is the same element.
    _check("getSystemStatus", "", allow_writes=False)
    _check(
        "getSystemStatus",
        "",
        allow_writes=False,
        auth=AUTH.replace(EMPTY_CP_ELEMENT, "<callerPassword/>"),
    )


# ---------------------------------------------------------------- DEACTIVE (§5.7, §8.5 #11)


@pytest.mark.parametrize(
    "status",
    [
        "DEACTIVE",
        "CLOSED",
        " DEACTIVE ",
        "Deactive",
        "deactive",
        _full_width("DEACTIVE"),  # full-width
        "DEAC\u200bTIVE",  # zero-width space
        "\u00a0CLOSED\u00a0",
        "PENDING",
        "",
    ],
)
def test_new_status_other_than_suspended_or_active_is_refused(status: str) -> None:
    code = _refused("setSubscriberAccountStatus", f"<newStatus>{status}</newStatus>")
    assert code == "ALWAYS_REFUSED_DEACTIVE"


def test_duplicate_new_status_is_refused() -> None:
    code = _refused(
        "setSubscriberAccountStatus", "<newStatus>ACTIVE</newStatus><newStatus>DEACTIVE</newStatus>"
    )
    assert code == "ALWAYS_REFUSED_DEACTIVE"
    code = _refused(
        "setSubscriberAccountStatus", "<newStatus>ACTIVE</newStatus><newStatus>ACTIVE</newStatus>"
    )
    assert code == "ALWAYS_REFUSED_DEACTIVE"


def test_missing_new_status_is_refused() -> None:
    assert _refused("setSubscriberAccountStatus", "<value>SUB-9004217</value>") == (
        "ALWAYS_REFUSED_DEACTIVE"
    )


@pytest.mark.parametrize("value", ["TRUE", "true", "1", "", "yes"])
def test_bypass_quarantine_other_than_false_is_refused(value: str) -> None:
    code = _refused(
        "setSubscriberAccountStatus",
        f"<newStatus>ACTIVE</newStatus><bypassQuarantine>{value}</bypassQuarantine>",
    )
    assert code == "ALWAYS_REFUSED_DEACTIVE"


@pytest.mark.parametrize("status", ["DEACTIVE", "CLOSED", "Deactive", "ERROR"])
def test_account_update_to_another_status_is_refused(status: str) -> None:
    code = _refused(
        "accountUpdate",
        f"<subscriberAccount><accountStatus>{status}</accountStatus></subscriberAccount>",
    )
    assert code == "ALWAYS_REFUSED_DEACTIVE"


def test_account_update_keeping_active_passes() -> None:
    _check(
        "accountUpdate",
        "<subscriberAccount><accountStatus>ACTIVE</accountStatus></subscriberAccount>",
    )


@pytest.mark.parametrize("operation", sorted(WRITES_PROVISIONING))
def test_terminal_literal_anywhere_in_a_write_is_refused(operation: str) -> None:
    code = _refused(operation, "<newStatus>ACTIVE</newStatus><a><b> closed </b></a>")
    assert code == "ALWAYS_REFUSED_DEACTIVE"


@pytest.mark.parametrize(
    "value", [_full_width("DEACTIVE"), _full_width("closed"), "DE\u200bACTIVE"]
)
def test_terminal_literal_is_normalized_before_the_check(value: str) -> None:
    # A sub-service status in an update is not a status field the guard knows by name: only
    # normalization catches these forms there.
    code = _refused(
        "accountUpdate", f"<voiceServiceDetail><status>{value}</status></voiceServiceDetail>"
    )
    assert code == "ALWAYS_REFUSED_DEACTIVE"


@pytest.mark.parametrize(
    "inner",
    [
        "<newStatus>ACTIVE<x/>DEACTIVE</newStatus>",
        "<newStatus>ACTIVE</newStatus>DEACTIVE",
        "<a>DEACTIVE<b>1</b></a><newStatus>ACTIVE</newStatus>",
    ],
)
def test_mixed_content_in_final_bytes_is_refused(inner: str) -> None:
    # Text beside a child element is not read by the hard blocks, so it never passes.
    assert _refused("setSubscriberAccountStatus", inner) == "ENVELOPE_MIXED_CONTENT"


def test_reads_may_mention_deactive() -> None:
    # Reading deactivated accounts is harmless; only writes are blocked.
    _check("accountSearch", "<status>DEACTIVE</status>", allow_writes=False)


def test_the_guard_has_no_override() -> None:
    import inspect

    from airtimesat_platform.gateway import sitest_guard

    parameters = inspect.signature(sitest_guard.check_envelope).parameters
    assert set(parameters) == {"envelope", "endpoint", "operation", "allow_writes"}


# ---------------------------------------------------------------- bulk (§5.7)


@pytest.mark.parametrize("value", ["TRUE", "true", " True ", "", "BULK"])
def test_bulk_action_other_than_false_is_refused(value: str) -> None:
    code = _refused("activateSubscriber", f"<bulkAction>{value}</bulkAction>")
    assert code == "ALWAYS_REFUSED_BULK"


@pytest.mark.parametrize(
    "element", ["m2MBulkDetails", "sbdBulkDetails", "BulkDetails", "xBULKDETAILS"]
)
def test_bulk_details_are_refused(element: str) -> None:
    code = _refused("activateSubscriber", f"<{element}><imei>990000000318651</imei></{element}>")
    assert code == "ALWAYS_REFUSED_BULK"


@pytest.mark.parametrize("element", ["deviceString", "bulkDeviceString", "imeiDevice", "Device"])
def test_bulk_literal_in_a_device_field_is_refused(element: str) -> None:
    code = _refused("accountSearch", f"<{element}> bulk </{element}>", allow_writes=False)
    assert code == "ALWAYS_REFUSED_BULK"


def test_bulk_literal_is_normalized_before_the_check() -> None:
    code = _refused(
        "accountSearch", f"<deviceNumber>{_full_width('BULK')}</deviceNumber>", allow_writes=False
    )
    assert code == "ALWAYS_REFUSED_BULK"


XSI = 'xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"'


@pytest.mark.parametrize("type_name", ["irid:sbdBulkPlanUpdateImpl", "irid:m2MBULKDetailImpl"])
def test_bulk_xsi_type_in_a_write_is_refused(type_name: str) -> None:
    code = _refused("activateSubscriber", f'<subscriberAccount {XSI} xsi:type="{type_name}"/>')
    assert code == "ALWAYS_REFUSED_BULK"


def test_ordinary_xsi_type_in_a_write_passes() -> None:
    _check("accountUpdate", f'<subscriberAccount {XSI} xsi:type="irid:sbdSubscriberAccountImpl"/>')


@pytest.mark.parametrize("endpoint", ["beta", "https://h-k3f9q2m7.example.invalid/iws", None])
def test_unknown_endpoint_is_refused(endpoint: object) -> None:
    with pytest.raises(RefusedError) as raised:
        check_operation(endpoint, "accountSearch", allow_writes=False)  # pyright: ignore[reportArgumentType]
    assert raised.value.code == "ENDPOINT_INVALID"


def test_bulk_action_false_passes() -> None:
    _check("activateSubscriber", "<bulkAction>FALSE</bulkAction>")


# ---------------------------------------------------------------- redaction


SIG = "ab+cd/ef=="


@pytest.mark.parametrize(
    "echo",
    [
        SIG.encode(),
        b"ab%2Bcd%2Fef%3D%3D",
        b"ab%2bcd%2fef%3d%3d",
        SIG.encode("utf-16-le"),
        SIG.encode("utf-16-be"),
    ],
)
def test_signature_echoes_are_redacted(echo: bytes) -> None:
    body = b"<fault>bad signature " + echo + b" sent</fault>"
    redacted = redact_echoes(body, (SIG,))
    assert echo not in redacted


def test_redaction_leaves_other_text() -> None:
    assert redact_echoes(b"<ok>fine</ok>", (SIG, "")) == b"<ok>fine</ok>"
    assert redact_echoes(b"<e>" + SIG.encode() + b"</e>", (SIG,)) == b"<e>REDACTED</e>"


@pytest.mark.parametrize(
    ("envelope", "code"),
    [
        (b"<a>" + b"x" * (600 * 1024) + b"</a>", "ENVELOPE_TOO_LARGE"),
        (b"<soap:Envelope", "ENVELOPE_NOT_WELL_FORMED"),
        (
            f'<soap:Envelope xmlns:soap="{SOAP}" xmlns:irid="http://www.iridium.com"><soap:Body>'
            "<irid:accountSearch><other/></irid:accountSearch></soap:Body></soap:Envelope>".encode(),
            "ENVELOPE_REQUEST_INVALID",
        ),
    ],
)
def test_malformed_final_bytes_are_refused(envelope: bytes, code: str) -> None:
    with pytest.raises(RefusedError) as raised:
        check_envelope(
            envelope, endpoint=Endpoint.PROVISIONING, operation="accountSearch", allow_writes=False
        )
    assert raised.value.code == code
