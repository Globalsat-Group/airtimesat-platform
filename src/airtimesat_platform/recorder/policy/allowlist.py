"""The read allowlist and its per-method limits (design §5.3, §5.5 step 8, §8.5 #16, #18).

Default deny: an operation not listed for the call's endpoint is refused. Every limit is a
required inclusive range, so a missing limit (which IWS reads as "all rows") is refused too.
These are code constants, reviewed line by line; never configuration.

Writes are listed so that ``recorder check`` can refuse them with ``WRITES_NOT_SUPPORTED``
until writes arrive (S2 PR D3). The always-refused list lives in ``hard_blocks``.

A test asserts that these read sets equal the gateway guard's, endpoint by endpoint; the
recorder never imports the guard (design §5.7: two independent implementations).
"""

import re
from collections.abc import Iterator
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Final

from airtimesat_platform.masker.tokenize.surrogates import SPECS
from airtimesat_platform.masker.xmlsafe import Element, local_name
from airtimesat_platform.recorder.errors import PlanRefusedError
from airtimesat_platform.recorder.policy.text import fold

PROVISIONING: Final = "provisioning"
REPORTING: Final = "reporting"
ENDPOINTS: Final = (PROVISIONING, REPORTING)

# TODO(W): confirm every name below against the WSDL snapshot. They are the WSDL names
# where Annex D §2.2 gives them (getSubscriberOrgs, getEVoucherInventory) and catalog names
# otherwise.
_SYSTEM_BOTH: Final = frozenset({"getSystemStatus", "getProjectVersion"})
READS_PROVISIONING: Final = _SYSTEM_BOTH | frozenset(
    {
        # System
        "authenticatedPing",
        "findServiceProviderProfile",
        "getDemoAndTrialCounts",
        # Catalog cascades
        "getDemoAndTrialBundles",
        "getPromoBundles",
        "getSBDBundles",
        "getM2MBundles",
        "getVoiceBundles",
        "getDataBundles",
        "getVCSBundles",
        "getDataSpeeds",
        "getCommitmentPeriods",
        "getLanguages",
        "getLanguageChoices",
        "getBundle",
        "getServicePlans",
        "getServicePlan",
        "getSubmarkets",
        "getModels",
        "getModel",
        "getManufacturers",
        "getVerticals",
        "getRudicsGroups",
        "getAirlines",
        "getFlagStates",
        "getPrepaidPlans",
        "getVoucherDenominations",
        "getEVoucherInventory",
        "getSecondaryDataServices",
        "getBurstDeviceBundles",
        "getBurstServiceBundles",
        "getBurstSubscriptionNames",
        "getBurstBroadcastCoverageAreas",
        "getProgrammableButtons",
        "getLocalNumberRegions",
        "getVesselTypes",
        # Lines and devices
        "accountSearch",
        "getSubscriberAccount",
        "validateDeviceString",
        "getDevices",
        "searchSimLock",
        "getRechargeHistory",
        "getPrepaidAccountDetail",
        "getSubscriberOrgs",
        "getSubscriberOrgDetail",
        "getVessels",
        "getVessel",
        "bulkActionSearch",
        # Queue and IWS log
        "getQueueEntries",
        "getQueueEntry",
        "getIwsRequests",
        "getIwsRequest",
    }
)
READS_REPORTING: Final = _SYSTEM_BOTH | frozenset(
    {
        "getReportTypes",
        "getReportCategory",
        "getReportColumns",
        "getReportParameters",
        "getReportPlanNames",
        "getUsageUnits",
        "getUsageCallTypes",
    }
)
READS: Final[dict[str, frozenset[str]]] = {
    PROVISIONING: READS_PROVISIONING,
    REPORTING: READS_REPORTING,
}
# TODO(W): confirm against the WSDL snapshot. Refused in D1; allowed with a writes section
# in D3 (design §5.3, §5.6).
WRITES: Final = frozenset(
    {
        "activateSubscriber",
        "accountUpdate",
        "setSubscriberAccountStatus",
        "rechargePrepaidAccount",
        "subscribeBurstService",
        "unsubscribeBurstService",
    }
)
WRITE_ENDPOINT: Final = PROVISIONING


@dataclass(frozen=True, slots=True)
class Range:
    """An integer element that must lie in ``low..high`` (inclusive)."""

    element: str
    low: int
    high: int
    required: bool = True


@dataclass(frozen=True, slots=True)
class Window:
    """Two UTC timestamps, both required, at most ``max_hours`` apart."""

    start: str
    end: str
    max_hours: int


@dataclass(frozen=True, slots=True)
class EnumRule:
    """An enum element: absent, or one of ``allowed`` (or none of ``refused``)."""

    element: str
    code: str
    allowed: frozenset[str] | None = None
    refused: frozenset[str] = frozenset()


@dataclass(frozen=True, slots=True)
class MethodRules:
    """The limits of one read (design §5.3, "Limits")."""

    ranges: tuple[Range, ...] = ()
    window: Window | None = None
    enums: tuple[EnumRule, ...] = ()
    # Elements that must carry a value.
    required: tuple[str, ...] = ()
    # At least one of these must carry a value.
    one_of: tuple[str, ...] = ()
    # If set, no other element may carry a value: the only search inputs.
    only: frozenset[str] | None = None
    # Elements that must hold the exact surrogate shape of a type, whatever the field map says.
    shapes: tuple[tuple[str, str], ...] = ()
    # Elements a plan may not carry: the recorder sets them (design §5.5 step 8).
    set_by_recorder: tuple[str, ...] = ()
    # Kept literals that must not hold a wildcard character.
    no_wildcards: tuple[str, ...] = ()


# TODO(W): confirm every element name, and the timestamp format of the window, against the
# WSDL snapshot. The names follow the catalog. getQueueEntries has no window or limit in
# the catalog (design §13 #31, open); if the WSDL has them, they get the IWS log's rules.
LIMITS: Final[dict[str, MethodRules]] = {
    "accountSearch": MethodRules(
        ranges=(Range("limit", 1, 50), Range("startRow", 0, 200, required=False)),
        enums=(
            EnumRule("filterType", "FILTER_SMART_REFUSED", refused=frozenset({"SMART"})),
            EnumRule("filterCond", "FILTER_COND_REFUSED", allowed=frozenset({"EQUALS"})),
        ),
        required=("filterType", "filterValue"),
    ),
    "getDevices": MethodRules(ranges=(Range("numResults", 1, 20),)),
    "getRechargeHistory": MethodRules(ranges=(Range("limit", 1, 50),)),
    "getEVoucherInventory": MethodRules(ranges=(Range("limit", 1, 50),)),
    "getSubscriberOrgs": MethodRules(required=("Id",), only=frozenset({"Id"})),
    "getVessels": MethodRules(
        one_of=("id", "imo", "mmsi", "vesselName"),
        only=frozenset({"id", "imo", "mmsi", "vesselName"}),
        shapes=(("vesselName", "VESSEL"),),
    ),
    # One request, matched exactly: Wildcard absent or FALSE, no wildcard character.
    "bulkActionSearch": MethodRules(
        enums=(EnumRule("Wildcard", "WILDCARD_REFUSED", allowed=frozenset({"FALSE"})),),
        required=("bulkRequestId",),
        only=frozenset({"bulkRequestId", "Wildcard"}),
        no_wildcards=("bulkRequestId",),
    ),
    "getIwsRequests": MethodRules(
        ranges=(Range("Limit", 1, 100),),
        window=Window("startDate", "endDate", max_hours=24),
    ),
    "getQueueEntries": MethodRules(set_by_recorder=("createdBy",)),
}

_INTEGER: Final = re.compile(r"0|[1-9][0-9]{0,8}")
_TIMESTAMP: Final = re.compile(
    r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{1,6})?Z"
)
_REFERENCE_START: Final = "${"
_WILDCARDS: Final = ("*", "%")
# The one reference a request may hold: the current item of the call's for_each (§5.2).
ITEM: Final = "${item}"


def is_allowed_read(endpoint: str, operation: str) -> bool:
    """Return whether ``operation`` is an allowlisted read on ``endpoint``."""
    return operation in READS.get(endpoint, frozenset())


def _leaves(root: Element) -> Iterator[Element]:
    for element in root.iter():
        if element is not root and len(element) == 0:
            yield element


def _find(root: Element, name: str, where: str) -> Element | None:
    """Return the one element named ``name`` (any case), or ``None``; refuse duplicates."""
    wanted = fold(name)
    found = [e for e in root.iter() if e is not root and fold(local_name(e)) == wanted]
    if len(found) > 1:
        raise PlanRefusedError("LIMIT_DUPLICATE", f"{where}/{name}")
    if found and local_name(found[0]) != name:
        raise PlanRefusedError("ELEMENT_NAME_CASE", f"{where}/{name}")
    return found[0] if found else None


def _value(element: Element | None) -> str:
    return "" if element is None else (element.text or "")


def _no_reference(value: str, where: str) -> None:
    # A limit, a date or an enum is a literal the CTO reviews, never a reference (§5.2).
    if _REFERENCE_START in value:
        raise PlanRefusedError("REFERENCE_NOT_IDENTIFIER_FIELD", where)


def _check_range(root: Element, rule: Range, where: str) -> None:
    element = _find(root, rule.element, where)
    at = f"{where}/{rule.element}"
    if element is None:
        if rule.required:
            raise PlanRefusedError("LIMIT_MISSING", at)
        return
    text = _value(element)
    _no_reference(text, at)
    if not _INTEGER.fullmatch(text):
        raise PlanRefusedError("LIMIT_NOT_AN_INTEGER", at)
    if not rule.low <= int(text) <= rule.high:
        raise PlanRefusedError("LIMIT_OUT_OF_RANGE", at)


def _timestamp(root: Element, name: str, where: str) -> datetime:
    element = _find(root, name, where)
    at = f"{where}/{name}"
    text = _value(element)
    _no_reference(text, at)
    if element is None or not text:
        raise PlanRefusedError("WINDOW_MISSING", at)
    if not _TIMESTAMP.fullmatch(text):
        raise PlanRefusedError("WINDOW_INVALID", at)
    try:
        return datetime.fromisoformat(text).astimezone(UTC)
    except ValueError:
        raise PlanRefusedError("WINDOW_INVALID", at) from None


def _check_window(root: Element, window: Window, where: str) -> None:
    start = _timestamp(root, window.start, where)
    end = _timestamp(root, window.end, where)
    if end <= start:
        raise PlanRefusedError("WINDOW_INVALID", f"{where}/{window.end}")
    if end - start > timedelta(hours=window.max_hours):
        raise PlanRefusedError("WINDOW_TOO_LONG", f"{where}/{window.end}")


def _check_enum(root: Element, rule: EnumRule, where: str) -> None:
    element = _find(root, rule.element, where)
    if element is None:
        return
    at = f"{where}/{rule.element}"
    text = _value(element)
    _no_reference(text, at)
    # An allowed value is matched exactly: the plan's text is sent as written, and IWS may
    # read another spelling (equals, a full-width FALSE) differently. Refused values are
    # folded, so no spelling of one gets through.
    if rule.allowed is not None and text not in rule.allowed:
        raise PlanRefusedError(rule.code, at)
    if fold(text) in {fold(v) for v in rule.refused}:
        raise PlanRefusedError(rule.code, at)


def check_limits(operation: str, root: Element, where: str) -> None:
    """Refuse a read request that breaks its method's limits (design §5.3).

    ``root`` is the parsed ``<request>``; ``where`` is the call's location. Raises
    ``PlanRefusedError`` with a code and the element's name (a code constant), never a value.
    """
    rules = LIMITS.get(operation)
    if rules is None:
        return
    for name in rules.set_by_recorder:
        if _find(root, name, where) is not None:
            raise PlanRefusedError("SET_BY_RECORDER", f"{where}/{name}")
    for rule in rules.ranges:
        _check_range(root, rule, where)
    if rules.window is not None:
        _check_window(root, rules.window, where)
    for enum in rules.enums:
        _check_enum(root, enum, where)
    for name in rules.required:
        if not _value(_find(root, name, where)).strip():
            raise PlanRefusedError("SEARCH_INPUT_REQUIRED", f"{where}/{name}")
    if rules.one_of and not any(_value(_find(root, n, where)).strip() for n in rules.one_of):
        raise PlanRefusedError("SEARCH_INPUT_REQUIRED", where)
    if rules.only is not None:
        allowed = {fold(name) for name in rules.only}
        for leaf in _leaves(root):
            if (leaf.text or "").strip() and fold(local_name(leaf)) not in allowed:
                raise PlanRefusedError("SEARCH_INPUT_REFUSED", where)
    for name in rules.no_wildcards:
        if any(w in _value(_find(root, name, where)) for w in _WILDCARDS):
            raise PlanRefusedError("WILDCARD_REFUSED", f"{where}/{name}")
    for name, type_name in rules.shapes:
        text = _value(_find(root, name, where))
        # A reference is checked against the referenced field's type instead (plan.py).
        if text and text != ITEM and not SPECS[type_name].is_surrogate_shape(text):
            raise PlanRefusedError("SEARCH_INPUT_NOT_A_SURROGATE", f"{where}/{name}")
