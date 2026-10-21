"""The recorder's hard blocks: refused whatever the plan says (design §5.4, §5.7, §8.5).

This is one of two deliberately independent implementations. The other is the signer core's
guard (``gateway/sitest_guard.py``); this module imports nothing from it and shares no
helper with it, so a bug in one alone cannot send a DEACTIVE or a bulk call.

The blocks run before every other check of a plan, in this order, over every call:

1. Iridium host names anywhere in the plan (an endpoint trick, §8.5 #9). The one exception
   is the IWS namespace URI as a namespace declaration, which names no endpoint.
2. ``ALWAYS_REFUSED_DEACTIVE``: ``newStatus`` ``DEACTIVE`` or ``CLOSED`` (or anything but
   exactly one ``SUSPENDED`` or ``ACTIVE`` in ``setSubscriberAccountStatus``),
   ``bypassQuarantine`` other than ``FALSE``, an ``accountUpdate`` that carries
   ``accountStatus``, or a ``DEACTIVE`` or ``CLOSED`` literal in a write.
3. ``ALWAYS_REFUSED_BULK``: ``bulkAction`` other than ``FALSE``, any ``*BulkDetails``
   element, a ``BULK`` literal in a device field, a bulk ``xsi:type``, or a bulk method.
4. The always-refused methods of §5.4, SP-wide writes included, by name in any case.
5. Request shape: a SOAP action in the plan, an unknown endpoint, an unknown method or one
   in the wrong case, a method on the wrong endpoint, a request that is not one
   ``<request>`` element, a SOAP envelope, header or body, a namespaced element, an
   authentication field, or two operations in one body.

Names and values are compared after NFKC normalization, removal of format characters,
trimming and case folding, so `` DEACTIVE ``, ``Deactive`` and full-width text are caught.
Comments, CDATA sections and processing instructions are refused by the parser, so they
cannot split a value either. Every refusal carries a code and the call's index, never a
value.
"""

import re
from collections.abc import Iterator, Mapping
from dataclasses import dataclass
from typing import Final, cast
from urllib.parse import unquote

from airtimesat_platform.masker.errors import RequestRefusedError
from airtimesat_platform.masker.xmlsafe import (
    MAX_REQUEST_BYTES,
    SOAP_NAMESPACES,
    XSI_TYPE,
    Element,
    local_name,
    namespace,
    parse,
)
from airtimesat_platform.recorder.errors import PlanRefusedError
from airtimesat_platform.recorder.policy.allowlist import (
    ENDPOINTS,
    READS,
    WRITE_ENDPOINT,
    WRITES,
)
from airtimesat_platform.recorder.policy.text import fold

DEACTIVE: Final = "ALWAYS_REFUSED_DEACTIVE"
BULK: Final = "ALWAYS_REFUSED_BULK"
METHOD: Final = "ALWAYS_REFUSED_METHOD"
SP_WIDE: Final = "ALWAYS_REFUSED_SP_WIDE"

# TODO(W): confirm every name below against the WSDL snapshot. Where the catalog and the
# WSDL may spell a name differently, both spellings are listed; matching ignores case.
_SP_WIDE_WRITES: Final = frozenset(
    {
        "manageDestinations",
        "sbdDestinationSearchReplace",
        "sbdMOQueuePurge",
        "updateEmailNotification",
    }
)
_BULK_METHODS: Final = frozenset({"bulkAccountUpdate", "bulkAddPrepaid", "bulkDeletePrepaid"})
_OTHER_REFUSED: Final = frozenset(
    {
        # Destructive or inventory-moving
        "deletePrepaidAccount",
        "deactivateTelephonyScratchCard",
        "deactivateTelephonyScratchcard",
        "unquarantineDevice",
        "deviceTransferOwner",
        "loadIMEI",
        "restrictedSimSwap",
        "associateSimToImeiDevice",
        "disAssociateSimFromImeiDevice",
        # Not in S2: device swaps
        "accountUpdateDevices",
        # Credentials and users
        "resetIWSUserPassword",
        "resetUserPassword",
        "userAuthenticate",
        "findUserProfiles",
        "createUserProfile",
        "updateUserProfile",
        "changeUserProfileStatus",
        "unlockUser",
        "getSPNetGroups",
        "getSPNetPages",
        "resetTelephonyVMPin",
        # DIDWW
        "addDIDWWNumberInventory",
        "getDIDWWNumberInventory",
        "removeDIDWWNumberInventory",
        # Money and vouchers
        "orderScratchcards",
        "activateScratchCards",
        "activateTelephonyScratchCards",
        "updateScratchCardStatus",
        "refundPrepaidVoucher",
        "getScratchcards",
        "getScratchCardBatches",
        "getScratchcardDeals",
        "getScratchcardOrders",
        "getScratchCardActivationStatus",
        "searchVoucherOrder",
        "getPrepaidAccountSummary",
        "searchDeviceUsage",
        # Reports delivered outside the recorder or returning bulk rows
        "createScheduledReport",
        "updateScheduledReport",
        "getScheduledReports",
        "createOnDemandReport",
        # Report job metadata
        "getReportTransactionLog",
        "getFileList",
        # Raw usage
        "getCertusRawUsage",
        "getIOPRawUsage",
        "getSBDRawUsageNew",
        "getTelRawUsage",
        "getSubscriberUsage",
        # Configuration writes on the reporting endpoint
        "createTracker",
        "updateTracker",
        "addTrackerActionProfile",
        "addTrackerCallTypeProfile",
        "addTrackerMember",
        "addTrackerRule",
        "addTrackerRulesProfile",
        "updateTrackerActionProfile",
        "updateTrackerCallTypeProfile",
        "updateTrackerMember",
        "updateTrackerRule",
        "updateTrackerRulesProfile",
        "createResourceGroup",
        "updateResourceGroup",
        "updateResourceGroupMember",
        "addCommStatusConfig",
        "updateCommStatusConfig",
        "addEmailProfile",
        "updateEmailProfile",
        # Other configuration writes, and methods that need an SPNet password (§5.3)
        "updateTopicAssociation",
        "updateQueueEntry",
        "createVessel",
        "updateVessels",
        "createSecondaryDataService",
        "updateSecondaryDataService",
        "deleteSecondaryDataService",
        "createSubscriberOrganization",
        "updateSubscriberOrganization",
        "updateSubscriberOrg",
        "updatePTTSubOrgStatus",
        "getAccountPoolingGroups",
        "getAccountPoolingGroup",
    }
)
ALWAYS_REFUSED: Final[dict[str, str]] = (
    dict.fromkeys(_OTHER_REFUSED, METHOD)
    | dict.fromkeys(_BULK_METHODS, BULK)
    | dict.fromkeys(_SP_WIDE_WRITES, SP_WIDE)
)
_REFUSED_FOLDED: Final = {fold(name): code for name, code in ALWAYS_REFUSED.items()}

_ALL_READS: Final = frozenset[str]().union(*READS.values())
KNOWN_OPERATIONS: Final = _ALL_READS | WRITES | frozenset(ALWAYS_REFUSED)
_KNOWN_FOLDED: Final = frozenset(fold(name) for name in KNOWN_OPERATIONS)
_WRITES_FOLDED: Final = frozenset(fold(name) for name in WRITES)

AUTH_FIELDS: Final = frozenset(
    fold(name)
    for name in (
        "iwsUsername",
        "signature",
        "timestamp",
        "serviceProviderAccountNumber",
        "caller",
        "callerPassword",
    )
)
# Plan keys that would set the SOAP action; the signer core sets it itself (§5.4).
_ACTION_KEYS: Final = frozenset({"action", "soapaction", "soap_action", "soap-action"})
_SOAP_PARTS: Final = frozenset({"envelope", "header", "body"})
_SAFE_STATUS: Final = frozenset({"suspended", "active"})
_TERMINAL: Final = frozenset({"deactive", "closed"})
_REQUEST_ROOT: Final = "request"
_WRAPPER: Final = "recorder-plan-body"

# Iridium's registered domain, assembled so that no host name sits in src/ (the gateway's
# test keeps every Iridium host name but SITEST's out of the source, design §7.1).
_IRIDIUM: Final = ".".join(("iridium", "com"))
# Full stops that IDNA (UTS #46) reads as label separators but NFKC keeps: the ideographic
# full stop, and the halfwidth one (which NFKC maps to it).
_IDNA_DOTS: Final = str.maketrans({"\u3002": ".", "\uff61": "."})
_MAX_DECODES: Final = 4
# The IWS namespace URI, declared for an xsi:type prefix, is a name, not an endpoint.
_IWS_NAMESPACE_DECLARATION: Final = re.compile(
    r"""xmlns(?::[a-z_][a-z0-9_.\-]*)?\s*=\s*(["'])https?://www\.iridium\.com/?\1"""
)


@dataclass(frozen=True, slots=True)
class _Call:
    """What the blocks can read from one call, before the schema has checked it."""

    where: str
    keys: tuple[str, ...]
    endpoint: str | None
    operation: str | None
    elements: tuple[Element, ...]
    parse_error: PlanRefusedError | None


def _host_text(text: str) -> str:
    """Fold the text, map IDNA label separators to ``.`` and drop the IWS namespace URI."""
    return _IWS_NAMESPACE_DECLARATION.sub("", fold(text).translate(_IDNA_DOTS))


def _has_iridium_host(text: str) -> bool:
    """Return whether the text names an Iridium host, raw or percent-encoded (§8.5 #9).

    The text is decoded again and again until it stops changing, so a double encoding or an
    encoded full stop or format character is caught; text still changing after
    ``_MAX_DECODES`` rounds counts as a host name (fail closed).
    """
    current = _host_text(text)
    for _ in range(_MAX_DECODES):
        if _IRIDIUM in current:
            return True
        decoded = _host_text(unquote(current))
        if decoded == current:
            return False
        current = decoded
    return True


def check_text(text: str) -> None:
    """Refuse a plan whose raw text names an Iridium host (§8.5 #9)."""
    if _has_iridium_host(text):
        raise PlanRefusedError("IRIDIUM_HOST_IN_PLAN")


def _strings(value: object) -> Iterator[str]:
    if isinstance(value, str):
        yield value
    elif isinstance(value, Mapping):
        for key, item in cast(Mapping[object, object], value).items():
            yield from _strings(key)
            yield from _strings(item)
    elif isinstance(value, list):
        for item in cast(list[object], value):
            yield from _strings(item)


def _parse_body(request: str, where: str) -> tuple[Element, ...]:
    """Parse a request that may hold several top-level elements; refuse anything else."""
    if "<?" in request:
        # An XML declaration or a processing instruction: a request needs neither.
        raise PlanRefusedError("XML_PI", where)
    try:
        data = f"<{_WRAPPER}>{request}</{_WRAPPER}>".encode()
    except UnicodeEncodeError:
        raise PlanRefusedError("REQUEST_NOT_UTF8", where) from None
    try:
        wrapper = parse(
            data,
            max_bytes=MAX_REQUEST_BYTES + 2 * len(_WRAPPER) + 5,
            request=True,
            error=RequestRefusedError,
        )
    except RequestRefusedError as exc:
        raise PlanRefusedError(exc.code, where) from None
    if (wrapper.text or "").strip() or any((child.tail or "").strip() for child in wrapper):
        raise PlanRefusedError("REQUEST_TEXT_OUTSIDE_ELEMENT", where)
    elements = tuple(wrapper)
    if not elements:
        raise PlanRefusedError("REQUEST_EMPTY", where)
    return elements


def _read_call(n: int, raw: object) -> _Call | None:
    if not isinstance(raw, Mapping):
        return None
    call = cast(Mapping[object, object], raw)
    where = f"calls[{n}]"
    keys = tuple(k for k in call if isinstance(k, str))
    endpoint, operation, request = call.get("endpoint"), call.get("operation"), call.get("request")
    elements: tuple[Element, ...] = ()
    error: PlanRefusedError | None = None
    if isinstance(request, str):
        try:
            elements = _parse_body(request, where)
        except PlanRefusedError as exc:
            error = exc
    return _Call(
        where,
        keys,
        endpoint if isinstance(endpoint, str) else None,
        operation if isinstance(operation, str) else None,
        elements,
        error,
    )


def _all(call: _Call) -> Iterator[Element]:
    for top in call.elements:
        yield from top.iter()


def _fragments(element: Element) -> list[str]:
    """Return the element's own text pieces and their join: text beside a child counts too."""
    parts = [element.text or "", *(child.tail or "" for child in element)]
    return [*parts, "".join(parts)]


def _check_iridium(calls: list[_Call]) -> None:
    for call in calls:
        for element in _all(call):
            values = [*_fragments(element), *(str(v) for v in element.attrib.values())]
            if any(_has_iridium_host(value) for value in values):
                raise PlanRefusedError("IRIDIUM_HOST_IN_PLAN", call.where)


def _check_deactive(call: _Call) -> None:
    operation = fold(call.operation)
    statuses: list[str] = []
    for element in _all(call):
        name = fold(local_name(element))
        values = {fold(text) for text in _fragments(element)}
        if name == "newstatus":
            if len(element) or values & _TERMINAL:
                raise PlanRefusedError(DEACTIVE, call.where)
            statuses.append(fold(element.text))
        if name == "bypassquarantine" and (len(element) or values != {"false"}):
            raise PlanRefusedError(DEACTIVE, call.where)
        if name == "accountstatus" and operation == "accountupdate":
            raise PlanRefusedError(DEACTIVE, call.where)
        if operation in _WRITES_FOLDED and values & _TERMINAL:
            raise PlanRefusedError(DEACTIVE, call.where)
    if operation == "setsubscriberaccountstatus" and (
        len(statuses) != 1 or statuses[0] not in _SAFE_STATUS
    ):
        raise PlanRefusedError(DEACTIVE, call.where)


def _check_bulk(call: _Call) -> None:
    if _REFUSED_FOLDED.get(fold(call.operation)) == BULK:
        raise PlanRefusedError(BULK, call.where)
    for element in _all(call):
        name = fold(local_name(element))
        values = {fold(text) for text in _fragments(element)}
        if name == "bulkaction" and (len(element) or values != {"false"}):
            raise PlanRefusedError(BULK, call.where)
        if "bulkdetail" in name:
            raise PlanRefusedError(BULK, call.where)
        if "device" in name and "bulk" in values:
            raise PlanRefusedError(BULK, call.where)
        if "bulk" in fold(element.get(XSI_TYPE)):
            raise PlanRefusedError(BULK, call.where)


def _check_refused_method(call: _Call) -> None:
    code = _REFUSED_FOLDED.get(fold(call.operation))
    if code is not None:
        raise PlanRefusedError(code, call.where)


def _check_operation(call: _Call) -> None:
    if any(fold(key) in _ACTION_KEYS for key in call.keys):
        raise PlanRefusedError("SOAP_ACTION_IN_PLAN", call.where)
    if call.endpoint is not None and call.endpoint not in ENDPOINTS:
        raise PlanRefusedError("ENDPOINT_INVALID", call.where)
    operation = call.operation
    if operation is None:
        return
    if operation not in KNOWN_OPERATIONS:
        code = "OPERATION_WRONG_CASE" if fold(operation) in _KNOWN_FOLDED else "OPERATION_UNKNOWN"
        raise PlanRefusedError(code, call.where)
    if call.endpoint is None:
        return
    on_endpoint = operation in READS[call.endpoint] or (
        operation in WRITES and call.endpoint == WRITE_ENDPOINT
    )
    if not on_endpoint:
        raise PlanRefusedError("OPERATION_ENDPOINT_MISMATCH", call.where)


def _check_shape(call: _Call) -> None:
    if call.parse_error is not None:
        raise call.parse_error
    if not call.elements:
        return
    for element in _all(call):
        ns = namespace(element)
        if ns in SOAP_NAMESPACES:
            raise PlanRefusedError("SOAP_ENVELOPE_IN_PLAN", call.where)
        if ns:
            raise PlanRefusedError("ELEMENT_NAMESPACE_REFUSED", call.where)
    if any(fold(local_name(top)) in _SOAP_PARTS for top in call.elements):
        raise PlanRefusedError("SOAP_ENVELOPE_IN_PLAN", call.where)
    if any(fold(local_name(e)) in AUTH_FIELDS for e in _all(call)):
        raise PlanRefusedError("AUTH_FIELD_IN_REQUEST", call.where)
    if len(call.elements) > 1:
        raise PlanRefusedError("TWO_OPERATIONS_IN_BODY", call.where)
    root = next(iter(call.elements))
    name = local_name(root)
    if name != _REQUEST_ROOT:
        if fold(name) in _KNOWN_FOLDED and name != call.operation:
            raise PlanRefusedError("OPERATION_ROOT_MISMATCH", call.where)
        # The plan holds the <request> element only; the signer core builds the rest.
        raise PlanRefusedError("REQUEST_ROOT_INVALID", call.where)
    for element in root.iter():
        if element is not root and fold(local_name(element)) in _KNOWN_FOLDED:
            raise PlanRefusedError("TWO_OPERATIONS_IN_BODY", call.where)


def check_document(doc: object) -> None:
    """Run the hard blocks over a strictly loaded plan, before its schema is checked.

    Reads what it can from a document of any shape: a call with a missing or mistyped field
    is left to the schema check, which runs next.
    """
    if any(_has_iridium_host(text) for text in _strings(doc)):
        raise PlanRefusedError("IRIDIUM_HOST_IN_PLAN")
    raw_calls: object = (
        cast(Mapping[object, object], doc).get("calls") if isinstance(doc, Mapping) else None
    )
    calls: list[_Call] = []
    if isinstance(raw_calls, list):
        for n, raw in enumerate(cast(list[object], raw_calls)):
            call = _read_call(n, raw)
            if call is not None:
                calls.append(call)
    _check_iridium(calls)
    for stage in (
        _check_deactive,
        _check_bulk,
        _check_refused_method,
        _check_operation,
        _check_shape,
    ):
        for call in calls:
            stage(call)


def check_call(call: Mapping[str, object]) -> None:
    """Run the hard blocks over one call (for tests and the recorder's run-time re-check)."""
    check_document({"calls": [dict(call)]})
