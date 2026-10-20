"""Reading an IWS reply: SOAP 1.2 envelope check and fault classification.

The signer core reads a reply only far enough to give the run log an outcome code: ``ok``,
an ``errorCodeEnum`` value (``AUTH``, ``CONFIG``, ``FIELD``, ``SYS``) or ``unknown``. It never
returns or logs fault text, which can echo request values (design
``docs/design/s2-recorder-masker.md`` §4.4); the raw reply goes only to the masking engine.

The exact detail structure of an IWS fault is not documented in the catalog beyond the
error code and a message, so the error code is taken from any element in the fault detail
whose name contains ``code`` and whose whole value is one of the four codes. The WSDL
snapshot will let this become exact.
"""

from dataclasses import dataclass
from typing import Final, cast

from lxml import etree

from airtimesat_platform.gateway.errors import IwsThrottledError, ResponseError

SOAP12_NS: Final = "http://www.w3.org/2003/05/soap-envelope"
ERROR_CODES: Final = frozenset({"AUTH", "CONFIG", "FIELD", "SYS"})
OUTCOME_OK: Final = "ok"
OUTCOME_UNKNOWN: Final = "unknown"
_THROTTLED: Final = "too many connections"


@dataclass(frozen=True, slots=True)
class FaultSummary:
    """What the run log may record about a fault: codes only, never text."""

    soap_code: str
    error_code: str | None

    @property
    def outcome(self) -> str:
        """Return the error code, or ``unknown`` if none was recognized."""
        return self.error_code or OUTCOME_UNKNOWN


def _parser() -> etree.XMLParser:
    return etree.XMLParser(
        resolve_entities=False,
        no_network=True,
        load_dtd=False,
        huge_tree=False,
    )


def _soap_code(fault: etree._Element) -> str:  # pyright: ignore[reportPrivateUsage]
    value = fault.find(f"{{{SOAP12_NS}}}Code/{{{SOAP12_NS}}}Value")
    if value is None or not value.text:
        return OUTCOME_UNKNOWN
    local = value.text.strip().rpartition(":")[2]
    return (
        local
        if local in {"Sender", "Receiver", "VersionMismatch", "MustUnderstand"}
        else (OUTCOME_UNKNOWN)
    )


def _error_code(fault: etree._Element) -> str | None:  # pyright: ignore[reportPrivateUsage]
    detail = fault.find(f"{{{SOAP12_NS}}}Detail")
    if detail is None:
        return None
    for element in detail.iter():
        tag = cast(object, element.tag)
        if not isinstance(tag, str) or len(element) != 0:
            continue
        name = etree.QName(element).localname.casefold()
        value = (element.text or "").strip()
        if "code" in name and value in ERROR_CODES:
            return value
    return None


def raise_if_throttled(body: bytes) -> None:
    """Raise ``IwsThrottledError`` if the reply is IWS's "Too many connections!" error."""
    for encoding in ("utf-8", "utf-16-le", "utf-16-be"):
        if _THROTTLED.encode(encoding) in body.lower():
            raise IwsThrottledError("TOO_MANY_CONNECTIONS")


def read_reply(body: bytes) -> FaultSummary | None:
    """Return ``None`` for a SOAP 1.2 reply without a fault, or the fault's codes.

    Anything that is not a well-formed SOAP 1.2 envelope with a Body (an HTML error page,
    SOAP 1.1, an empty body) raises ``ResponseError``.
    """
    try:
        root = etree.fromstring(body, _parser())
    except etree.XMLSyntaxError:
        raise ResponseError("REPLY_NOT_SOAP") from None
    if root.tag != f"{{{SOAP12_NS}}}Envelope":
        raise ResponseError("REPLY_NOT_SOAP")
    reply_body = root.find(f"{{{SOAP12_NS}}}Body")
    if reply_body is None:
        raise ResponseError("REPLY_NOT_SOAP")
    fault = reply_body.find(f"{{{SOAP12_NS}}}Fault")
    if fault is None:
        return None
    return FaultSummary(soap_code=_soap_code(fault), error_code=_error_code(fault))
