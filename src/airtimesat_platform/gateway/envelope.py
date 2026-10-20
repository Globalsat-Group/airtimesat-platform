"""The outgoing SOAP 1.2 envelope, rebuilt from scratch for every call.

The request a caller hands in is the ``<request>`` element of an operation without the
authentication fields (design ``docs/design/s2-recorder-masker.md`` §5.2). It is parsed with
a locked-down parser, checked, and copied element by element into a new tree (§5.7):

- no SOAP Header, exactly one Body child, the operation element in the IWS namespace;
- authentication fields are refused in the request and injected by the signer core as the
  first children of ``<request>``, in the catalog's order;
- only unqualified elements, and only the ``xsi:type`` and ``xsi:nil`` attributes;
- no comments, processing instructions, CDATA sections, DTDs or entities;
- no mixed content;
- enum values the hard blocks depend on (``newStatus``, ``bypassQuarantine``,
  ``bulkAction``) are written from this module's own constants, never from the caller's
  bytes, and any other value is refused with ``ALWAYS_REFUSED_DEACTIVE`` or
  ``ALWAYS_REFUSED_BULK``.

The operation that is signed is read from the rebuilt tree's operation element, so the
signature always covers the operation actually sent.
"""

import re
import unicodedata
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Final, cast

from lxml import etree

from airtimesat_platform.common.secrets import SecretValue
from airtimesat_platform.gateway.errors import RefusedError
from airtimesat_platform.gateway.signing import OPERATION_PATTERN

SOAP12_NS: Final = "http://www.w3.org/2003/05/soap-envelope"
IWS_NS: Final = "http://www.iridium.com"
XSI_NS: Final = "http://www.w3.org/2001/XMLSchema-instance"
# The reporting endpoint is assumed to use the same operation namespace; the WSDL snapshot
# (S2, after the harvest) confirms or corrects it.

AUTH_FIELDS: Final = (
    "iwsUsername",
    "signature",
    "serviceProviderAccountNumber",
    "timestamp",
    "caller",
    "callerPassword",
)
# Never accepted anywhere in a request, at any depth. Both lists are matched case-insensitively,
# so a variant such as ``<CallerPassword>`` is refused too, whatever the IWS binding does with it.
SECRET_FIELDS: Final = frozenset({"signature", "callerPassword"})
_AUTH_FIELDS_FOLDED: Final = frozenset(name.casefold() for name in AUTH_FIELDS)
_SECRET_FIELDS_FOLDED: Final = frozenset(name.casefold() for name in SECRET_FIELDS)

MAX_REQUEST_CHARS: Final = 256 * 1024
MAX_DEPTH: Final = 32
_ELEMENT_NAME: Final = re.compile(r"\A[A-Za-z_][A-Za-z0-9_.-]{0,99}\Z")
_TYPE_LOCAL_NAME: Final = re.compile(r"\A[A-Za-z_][A-Za-z0-9_.-]{0,99}\Z")
_XSI_TYPE: Final = f"{{{XSI_NS}}}type"
_XSI_NIL: Final = f"{{{XSI_NS}}}nil"
_NIL_VALUES: Final = {"true": "true", "1": "true", "false": "false", "0": "false"}

# (operation, element) -> (the only values the signer core writes, refusal code). Values are
# matched after normalization (``normalize_token``) and written from these constants.
ENUM_CONSTANTS: Final[dict[tuple[str, str], tuple[tuple[str, ...], str]]] = {
    ("setSubscriberAccountStatus", "newStatus"): (
        ("SUSPENDED", "ACTIVE"),
        "ALWAYS_REFUSED_DEACTIVE",
    ),
    ("setSubscriberAccountStatus", "bypassQuarantine"): (("FALSE",), "ALWAYS_REFUSED_DEACTIVE"),
    ("activateSubscriber", "bulkAction"): (("FALSE",), "ALWAYS_REFUSED_BULK"),
}


def normalize_token(value: str) -> str:
    """Return ``value`` NFKC-normalized, without format characters, trimmed and case-folded."""
    text = unicodedata.normalize("NFKC", value)
    text = "".join(ch for ch in text if unicodedata.category(ch) != "Cf")
    return text.strip().casefold()


@dataclass(frozen=True, slots=True)
class AuthFields:
    """The authentication values injected into one request."""

    iws_username: SecretValue
    timestamp: str
    caller: str
    service_provider_account_number: SecretValue | None
    signature: str = field(repr=False)


def is_element(node: etree._Element) -> bool:  # pyright: ignore[reportPrivateUsage]
    """Return whether ``node`` is an element (not a comment, PI or entity)."""
    tag = cast(object, node.tag)
    return isinstance(tag, str)


def _parser() -> etree.XMLParser:
    return etree.XMLParser(
        resolve_entities=False,
        no_network=True,
        load_dtd=False,
        dtd_validation=False,
        huge_tree=False,
        remove_comments=False,
        remove_pis=False,
        strip_cdata=False,
        collect_ids=False,
    )


def _parse_request(request_xml: str) -> etree._Element:  # pyright: ignore[reportPrivateUsage]
    if len(request_xml) > MAX_REQUEST_CHARS:
        raise RefusedError("REQUEST_TOO_LARGE")
    # "<!" covers DOCTYPE, comments and CDATA; "<?" covers processing instructions and an XML
    # declaration. Neither belongs in a request body.
    if "<!" in request_xml or "<?" in request_xml:
        raise RefusedError("REQUEST_MARKUP_NOT_ALLOWED")
    try:
        # A lone surrogate fails the encoding; that error would carry the whole request.
        root = etree.fromstring(request_xml.encode("utf-8"), _parser())
    except (etree.XMLSyntaxError, UnicodeEncodeError):
        raise RefusedError("REQUEST_NOT_WELL_FORMED") from None
    if root.tag != "request" or len(root.attrib) != 0:
        raise RefusedError("REQUEST_ROOT_INVALID")
    return root


def _xsi_type(element: etree._Element, value: str) -> str:  # pyright: ignore[reportPrivateUsage]
    prefix, sep, local = value.strip().partition(":")
    if not sep or not _TYPE_LOCAL_NAME.fullmatch(local):
        raise RefusedError("XSI_TYPE_INVALID")
    if element.nsmap.get(prefix) != IWS_NS:
        raise RefusedError("XSI_TYPE_NAMESPACE_INVALID")
    return f"irid:{local}"


def _copy(
    operation: str,
    source: etree._Element,  # pyright: ignore[reportPrivateUsage]
    parent: etree._Element,  # pyright: ignore[reportPrivateUsage]
    depth: int,
) -> None:
    if depth > MAX_DEPTH:
        raise RefusedError("REQUEST_TOO_DEEP")
    if not is_element(source):
        raise RefusedError("REQUEST_MARKUP_NOT_ALLOWED")
    qname = etree.QName(source)
    if cast(str | None, qname.namespace) is not None or not _ELEMENT_NAME.fullmatch(
        qname.localname
    ):
        raise RefusedError("ELEMENT_NAME_INVALID")
    name = qname.localname
    if name.casefold() in _SECRET_FIELDS_FOLDED:
        raise RefusedError("AUTH_FIELD_IN_REQUEST")
    target = etree.SubElement(parent, name)
    for raw_attr, raw_value in source.attrib.items():
        attr, value = cast(str, raw_attr), cast(str, raw_value)
        if attr == _XSI_TYPE:
            target.set(_XSI_TYPE, _xsi_type(source, value))
        elif attr == _XSI_NIL:
            nil = _NIL_VALUES.get(value.strip())
            if nil is None:
                raise RefusedError("XSI_NIL_INVALID")
            target.set(_XSI_NIL, nil)
        else:
            raise RefusedError("ATTRIBUTE_NOT_ALLOWED")
    constants = ENUM_CONSTANTS.get((operation, name))
    children = list(source)
    if constants is not None and children:
        # An enum the hard blocks depend on is a single value, never a structure.
        raise RefusedError(constants[1])
    if children:
        if source.text is not None and source.text.strip():
            raise RefusedError("MIXED_CONTENT")
        for child in children:
            if child.tail is not None and child.tail.strip():
                raise RefusedError("MIXED_CONTENT")
            _copy(operation, child, target, depth + 1)
        return
    text: str = source.text or ""
    if constants is not None:
        allowed, refusal = constants
        wanted = normalize_token(text)
        matches = [constant for constant in allowed if constant.casefold() == wanted]
        if not matches:
            raise RefusedError(refusal)
        target.text = matches[0]
        return
    try:
        target.text = text
    except ValueError:
        raise RefusedError("TEXT_NOT_XML_SAFE") from None


def build_envelope(
    operation: str,
    request_xml: str,
    auth_for: Callable[[str], AuthFields],
) -> bytes:
    """Return the serialized SOAP 1.2 envelope for ``operation``.

    ``auth_for`` receives the operation name read from the rebuilt operation element and
    returns the authentication values, including the signature over that name.
    """
    if not OPERATION_PATTERN.fullmatch(operation):
        raise RefusedError("OPERATION_NAME_INVALID")
    source = _parse_request(request_xml)
    for child in source:
        if is_element(child) and etree.QName(child).localname.casefold() in _AUTH_FIELDS_FOLDED:
            raise RefusedError("AUTH_FIELD_IN_REQUEST")

    envelope = etree.Element(
        f"{{{SOAP12_NS}}}Envelope",
        nsmap={"soap": SOAP12_NS, "irid": IWS_NS, "xsi": XSI_NS},
    )
    body = etree.SubElement(envelope, f"{{{SOAP12_NS}}}Body")
    operation_element = etree.SubElement(body, f"{{{IWS_NS}}}{operation}")
    request = etree.SubElement(operation_element, "request")
    if source.text is not None and source.text.strip():
        raise RefusedError("MIXED_CONTENT")
    for child in source:
        if child.tail is not None and child.tail.strip():
            raise RefusedError("MIXED_CONTENT")
        _copy(operation, child, request, 1)

    signed_operation = etree.QName(operation_element).localname
    if signed_operation != operation:
        raise RefusedError("OPERATION_MISMATCH")
    auth = auth_for(signed_operation)
    values: list[tuple[str, str]] = [
        ("iwsUsername", auth.iws_username.reveal()),
        ("signature", auth.signature),
    ]
    if auth.service_provider_account_number is not None:
        values.append(
            ("serviceProviderAccountNumber", auth.service_provider_account_number.reveal())
        )
    values += [("timestamp", auth.timestamp), ("caller", auth.caller)]
    for index, (name, value) in enumerate(values):
        element = etree.Element(name)
        try:
            element.text = value
        except ValueError:
            # lxml refuses control characters; its message names no value, but say so in a code.
            raise RefusedError("AUTH_VALUE_NOT_XML_SAFE") from None
        request.insert(index, element)
    return etree.tostring(envelope, xml_declaration=True, encoding="UTF-8")
