"""The signer core's own guard: an independent re-check of every outgoing envelope.

This is a second implementation of the hard blocks, deliberately separate from the
recorder's (design ``docs/design/s2-recorder-masker.md`` §5.7, §7.1), so a recorder bug
alone cannot send a DEACTIVE or a bulk call. It parses the **final bytes** after
authentication injection and refuses, whatever the caller asks:

- any operation not in this module's allowlist for the endpoint (default deny), every
  always-refused operation of §5.4, and any write unless the port was opened for writes;
- ``setSubscriberAccountStatus`` with ``newStatus`` other than ``SUSPENDED`` or ``ACTIVE``
  (so ``DEACTIVE`` and ``CLOSED``), more than one ``newStatus``, or ``bypassQuarantine``
  other than ``FALSE``;
- ``accountUpdate`` with an ``accountStatus`` other than ``ACTIVE`` or ``SUSPENDED``;
- a ``DEACTIVE`` or ``CLOSED`` literal anywhere in a write;
- ``bulkAction`` other than ``FALSE``, any ``*BulkDetails`` element, a ``BULK`` literal in a
  device field, or an ``xsi:type`` naming a bulk type in a write;
- a SOAP Header, more than one Body child, comments, processing instructions, a DTD, mixed
  content (text beside child elements, which a parser on the IWS side may join differently),
  ``callerPassword``, or a ``caller`` without the ``rec.`` prefix.

Values are compared after NFKC normalization, removal of format characters, trimming and
case folding. No flag, option or argument lifts any of this.

It also redacts any echo of the signature in a response (``redact_echoes``).
"""

import unicodedata
from typing import Final, cast

from lxml import etree

from airtimesat_platform.gateway.endpoints_sitest import Endpoint
from airtimesat_platform.gateway.errors import RefusedError

_SOAP12: Final = "http://www.w3.org/2003/05/soap-envelope"
_IWS: Final = "http://www.iridium.com"
_XSI_TYPE: Final = "{http://www.w3.org/2001/XMLSchema-instance}type"
MAX_ENVELOPE_BYTES: Final = 512 * 1024

# ---------------------------------------------------------------- allowlist (§5.3)
# WSDL operation names (Annex D §2.2: getSubscriberOrgs, getEVoucherInventory). The test that
# every name exists in the WSDL snapshot arrives with the snapshot.
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
WRITES_PROVISIONING: Final = frozenset(
    {
        "activateSubscriber",
        "accountUpdate",
        "setSubscriberAccountStatus",
        "rechargePrepaidAccount",
        "subscribeBurstService",
        "unsubscribeBurstService",
    }
)

# ---------------------------------------------------------------- always refused (§5.4)
# Matched case-insensitively, before the allowlist. Where the catalog and the WSDL spell a
# name differently, both spellings are listed.
ALWAYS_REFUSED: Final = frozenset(
    {
        # SP-wide writes
        "manageDestinations",
        "sbdDestinationSearchReplace",
        "sbdMOQueuePurge",
        "updateEmailNotification",
        # Bulk
        "bulkAccountUpdate",
        "bulkAddPrepaid",
        "bulkDeletePrepaid",
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
        # Not in S2
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
        # Other configuration writes
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
    }
)
_ALWAYS_REFUSED_FOLDED: Final = frozenset(name.casefold() for name in ALWAYS_REFUSED)

_ALLOWED: Final[dict[Endpoint, frozenset[str]]] = {
    Endpoint.PROVISIONING: READS_PROVISIONING | WRITES_PROVISIONING,
    Endpoint.REPORTING: READS_REPORTING,
}

_REQUIRED_AUTH: Final = ("iwsUsername", "signature", "timestamp", "caller")
_OPTIONAL_AUTH: Final = ("serviceProviderAccountNumber",)
CALLER_PREFIX: Final = "rec."

_STATUS_SAFE: Final = frozenset({"suspended", "active"})
_TERMINAL: Final = frozenset({"deactive", "closed"})


def _fold(value: str | None) -> str:
    text = unicodedata.normalize("NFKC", value or "")
    text = "".join(ch for ch in text if unicodedata.category(ch) != "Cf")
    return text.strip().casefold()


def is_write(operation: str) -> bool:
    """Return whether ``operation`` is one of the allowlisted writes."""
    return operation in WRITES_PROVISIONING


def check_operation(endpoint: Endpoint, operation: str, *, allow_writes: bool) -> None:
    """Refuse ``operation`` unless it is allowlisted for ``endpoint`` (and writes are open)."""
    if endpoint not in _ALLOWED:
        raise RefusedError("ENDPOINT_INVALID")
    if _fold(operation) in _ALWAYS_REFUSED_FOLDED:
        raise RefusedError("ALWAYS_REFUSED_METHOD")
    if operation not in _ALLOWED[endpoint]:
        raise RefusedError("OPERATION_NOT_ALLOWLISTED")
    if is_write(operation) and not allow_writes:
        raise RefusedError("WRITES_NOT_ENABLED")


def _parse(envelope: bytes) -> etree._Element:  # pyright: ignore[reportPrivateUsage]
    if len(envelope) > MAX_ENVELOPE_BYTES:
        raise RefusedError("ENVELOPE_TOO_LARGE")
    # Our serializer escapes "<" in text, so "<!" (DOCTYPE, comment, CDATA) and "<?" (a PI)
    # can appear only as markup. The one allowed "<?" is the XML declaration at the start.
    declaration_end = envelope.find(b"?>") + 2 if envelope.startswith(b"<?xml ") else 0
    if b"<!" in envelope or b"<?" in envelope[declaration_end:]:
        raise RefusedError("ENVELOPE_HAS_MARKUP")
    parser = etree.XMLParser(
        resolve_entities=False,
        no_network=True,
        load_dtd=False,
        huge_tree=False,
        remove_comments=False,
        remove_pis=False,
    )
    try:
        tree = etree.fromstring(envelope, parser).getroottree()
    except etree.XMLSyntaxError:
        raise RefusedError("ENVELOPE_NOT_WELL_FORMED") from None
    if tree.docinfo.internalDTD is not None or tree.docinfo.externalDTD is not None:
        raise RefusedError("ENVELOPE_HAS_MARKUP")
    root = tree.getroot()
    for node in root.iter():
        if not _is_element(node):
            raise RefusedError("ENVELOPE_HAS_MARKUP")
    if root.getprevious() is not None or root.getnext() is not None:
        raise RefusedError("ENVELOPE_HAS_MARKUP")
    return root


def _is_element(node: etree._Element) -> bool:  # pyright: ignore[reportPrivateUsage]
    tag = cast(object, node.tag)
    return isinstance(tag, str)


def _elements(parent: etree._Element) -> list[etree._Element]:  # pyright: ignore[reportPrivateUsage]
    return [child for child in parent if _is_element(child)]


def _local(element: etree._Element) -> str:  # pyright: ignore[reportPrivateUsage]
    return etree.QName(element).localname


def check_envelope(
    envelope: bytes,
    *,
    endpoint: Endpoint,
    operation: str,
    allow_writes: bool,
) -> None:
    """Refuse the serialized ``envelope`` unless it is a single, allowed, safe call."""
    check_operation(endpoint, operation, allow_writes=allow_writes)
    root = _parse(envelope)
    if root.tag != f"{{{_SOAP12}}}Envelope":
        raise RefusedError("ENVELOPE_ROOT_INVALID")
    top = _elements(root)
    if len(top) != 1 or top[0].tag != f"{{{_SOAP12}}}Body":
        raise RefusedError("ENVELOPE_HEADER_OR_EXTRA_PART")
    calls = _elements(top[0])
    if len(calls) != 1:
        raise RefusedError("ENVELOPE_NOT_ONE_CALL")
    call = calls[0]
    if etree.QName(call).namespace != _IWS or _local(call) != operation:
        raise RefusedError("ENVELOPE_OPERATION_MISMATCH")
    requests = _elements(call)
    if len(requests) != 1 or requests[0].tag != "request":
        raise RefusedError("ENVELOPE_REQUEST_INVALID")
    request = requests[0]
    _check_no_mixed_content(root)
    _check_auth(request)
    _check_hard_blocks(operation, request)


def _check_no_mixed_content(root: etree._Element) -> None:  # pyright: ignore[reportPrivateUsage]
    # The hard blocks read each element's own text. Text beside a child element (for example
    # ``<newStatus>ACTIVE<x/>DEACTIVE</newStatus>``) would not be read, so it is refused.
    for element in root.iter():
        if len(element) != 0 and (element.text or "").strip():
            raise RefusedError("ENVELOPE_MIXED_CONTENT")
        if element is not root and (element.tail or "").strip():
            raise RefusedError("ENVELOPE_MIXED_CONTENT")


def _check_auth(request: etree._Element) -> None:  # pyright: ignore[reportPrivateUsage]
    direct = [_local(child) for child in _elements(request)]
    for name in _REQUIRED_AUTH:
        if direct.count(name) != 1:
            raise RefusedError("AUTH_FIELDS_INVALID")
    for name in _OPTIONAL_AUTH:
        if direct.count(name) > 1:
            raise RefusedError("AUTH_FIELDS_INVALID")
    for element in request.iter():
        if _is_element(element) and _fold(_local(element)) == "callerpassword":
            raise RefusedError("AUTH_FIELDS_INVALID")
    caller = request.find("caller")
    if caller is None or not (caller.text or "").startswith(CALLER_PREFIX):
        raise RefusedError("CALLER_INVALID")


def _check_hard_blocks(operation: str, request: etree._Element) -> None:  # pyright: ignore[reportPrivateUsage]
    write = is_write(operation)
    new_status: list[str] = []
    for element in request.iter():
        if not _is_element(element):
            continue
        name = _fold(_local(element))
        value = _fold(element.text)
        if name == "newstatus":
            new_status.append(value)
        if name == "bypassquarantine" and value != "false":
            raise RefusedError("ALWAYS_REFUSED_DEACTIVE")
        if write and value in _TERMINAL:
            raise RefusedError("ALWAYS_REFUSED_DEACTIVE")
        if operation == "accountUpdate" and name == "accountstatus" and value not in _STATUS_SAFE:
            raise RefusedError("ALWAYS_REFUSED_DEACTIVE")
        if name == "bulkaction" and value != "false":
            raise RefusedError("ALWAYS_REFUSED_BULK")
        if name.endswith("bulkdetails"):
            raise RefusedError("ALWAYS_REFUSED_BULK")
        if "device" in name and value == "bulk":
            raise RefusedError("ALWAYS_REFUSED_BULK")
        if write and "bulk" in _fold(element.get(_XSI_TYPE)):
            raise RefusedError("ALWAYS_REFUSED_BULK")
    if operation == "setSubscriberAccountStatus" and (
        len(new_status) != 1 or new_status[0] not in _STATUS_SAFE
    ):
        raise RefusedError("ALWAYS_REFUSED_DEACTIVE")


def _percent(value: str, hex_format: str) -> str:
    return "".join(
        ch if ch.isascii() and ch.isalnum() else "%" + format(ord(ch), hex_format) for ch in value
    )


def redact_echoes(body: bytes, values: tuple[str, ...]) -> bytes:
    """Replace every occurrence of each value in ``body`` with ``REDACTED``.

    Used for the signature (and the secret key, which is never sent but costs nothing to
    look for). Plain and percent-encoded forms, in UTF-8 and UTF-16, are covered; the
    masker's signature-length detector is the backstop for other encodings (§8.1).
    """
    for value in values:
        if not value:
            continue
        forms = {value, _percent(value, "02X"), _percent(value, "02x")}
        for form in sorted(forms):
            for encoding in ("utf-8", "utf-16-le", "utf-16-be"):
                body = body.replace(form.encode(encoding), "REDACTED".encode(encoding))
    return body
