"""Safe XML parsing and serialization for the masker (design §4.4, §4.5, §5.5, §8.5 #10).

The parser resolves no entities, loads no DTD, reaches no network and keeps lxml's
default size limits. Documents with a DTD, entity declarations, comments or processing
instructions are refused before or after parsing, as are documents that are too large or
too deep. Requests are also refused for CDATA sections, so that what the CTO reviews and
what is sent cannot differ.
"""

import re
from typing import Final, cast

from lxml import etree

from airtimesat_platform.masker.errors import MaskingError

Element = etree._Element  # pyright: ignore[reportPrivateUsage]

MAX_RESPONSE_BYTES: Final = 5 * 1024 * 1024
MAX_REQUEST_BYTES: Final = 256 * 1024
MAX_DEPTH: Final = 64
XSI_NS: Final = "http://www.w3.org/2001/XMLSchema-instance"
XML_NS: Final = "http://www.w3.org/XML/1998/namespace"
XSI_TYPE: Final = f"{{{XSI_NS}}}type"
XSI_NIL: Final = f"{{{XSI_NS}}}nil"
XML_LANG: Final = f"{{{XML_NS}}}lang"
# Declared encodings the raw-byte checks below can trust (compared case-insensitively).
ALLOWED_ENCODINGS: Final = frozenset({"UTF-8", "US-ASCII", "ASCII"})
SOAP_NAMESPACES: Final = frozenset(
    {"http://schemas.xmlsoap.org/soap/envelope/", "http://www.w3.org/2003/05/soap-envelope"}
)

_DTD: Final = re.compile(rb"<!\s*(?:DOCTYPE|ENTITY)", re.IGNORECASE)
_CDATA: Final = re.compile(rb"<!\[CDATA\[")
# SOAP 1.2 requires xml:lang on a fault's Reason/Text. Only a plain language tag ("en",
# "en-US", "es-419") is accepted: no room for a value beyond three digits.
_LANG: Final = re.compile(r"[A-Za-z]{2,3}(?:-(?:[A-Za-z]{2,4}|\d{3}))?")
_TYPE_NAME: Final = re.compile(r"(?:[A-Za-z_][\w.\-]*:)?([A-Za-z_][\w.\-]{0,127})")


def _parser() -> etree.XMLParser:
    return etree.XMLParser(
        resolve_entities=False,
        no_network=True,
        load_dtd=False,
        dtd_validation=False,
        huge_tree=False,
        remove_comments=False,
        remove_pis=False,
        collect_ids=False,
    )


def parse(data: bytes, *, max_bytes: int, request: bool, error: type[MaskingError]) -> Element:
    """Parse ``data`` safely, or raise ``error`` with a code (never the content)."""
    if len(data) > max_bytes:
        raise error("XML_TOO_LARGE")
    # Only UTF-8 (or its ASCII subset): the DTD and CDATA checks below read the raw bytes.
    if data.startswith((b"\xff\xfe", b"\xfe\xff", b"\x00\x00\xfe\xff")) or b"\x00" in data:
        raise error("XML_ENCODING")
    if _DTD.search(data):
        raise error("XML_DTD")
    if request and _CDATA.search(data):
        raise error("XML_CDATA")
    try:
        root = etree.fromstring(data, _parser())
    except (etree.XMLSyntaxError, ValueError):
        raise error("XML_PARSE") from None
    # A declared encoding such as UTF-7 would let a DTD or CDATA section past the byte checks.
    encoding = cast(str, getattr(root.getroottree().docinfo, "encoding", "") or "")
    if encoding.upper() not in ALLOWED_ENCODINGS:
        raise error("XML_ENCODING")
    doctype = cast(str, getattr(root.getroottree().docinfo, "doctype", ""))
    if doctype:
        raise error("XML_DTD")
    siblings = [*root.itersiblings(preceding=True), *root.itersiblings()]
    if siblings:
        raise error("XML_NODE")
    _check_nodes(root, error)
    return root


def _check_nodes(root: Element, error: type[MaskingError]) -> None:
    stack: list[tuple[Element, int]] = [(root, 1)]
    while stack:
        node, depth = stack.pop()
        if depth > MAX_DEPTH:
            raise error("XML_TOO_DEEP")
        for child in node:
            tag: object = child.tag
            if tag is etree.Comment:
                raise error("XML_COMMENT")
            if tag is etree.ProcessingInstruction:
                raise error("XML_PI")
            if tag is etree.Entity:
                raise error("XML_ENTITY")
            stack.append((child, depth + 1))


def local_name(element: Element) -> str:
    """Return an element's local name."""
    return etree.QName(element).localname


def namespace(element: Element) -> str:
    """Return an element's namespace URI, or an empty string."""
    return etree.QName(element).namespace or ""


def xsi_type(element: Element, error: type[MaskingError]) -> str | None:
    """Return the local part of an element's ``xsi:type``, or ``None``."""
    value = element.get(XSI_TYPE)
    if value is None:
        return None
    m = _TYPE_NAME.fullmatch(value.strip())
    if m is None:
        raise error("XSI_TYPE_INVALID")
    return m.group(1)


def is_nil(element: Element, error: type[MaskingError]) -> bool:
    """Return whether ``xsi:nil`` is true; refuse values other than true, false, 1 and 0."""
    value = element.get(XSI_NIL)
    if value is None:
        return False
    value = value.strip()
    if value not in ("true", "false", "1", "0"):
        raise error("XSI_NIL_INVALID")
    return value in ("true", "1")


def check_attributes(element: Element, error: type[MaskingError], path: str) -> None:
    """Refuse any attribute other than ``xsi:type``, ``xsi:nil`` and a plain ``xml:lang``.

    Design §4.5 allows ``xsi:type``, ``xsi:nil`` and a plain ``xml:lang`` (§13 #27, decided
    by the CTO on 21 Oct 2026), because SOAP 1.2 faults carry it.
    """
    for name, value in element.attrib.items():
        key = str(name)
        if key in (XSI_TYPE, XSI_NIL):
            continue
        if key == XML_LANG and _LANG.fullmatch(str(value)):
            continue
        raise error("UNKNOWN_ATTRIBUTE", path=path)


def set_nil(element: Element) -> None:
    """Make an element ``xsi:nil="true"`` with no content."""
    for child in list(element):
        element.remove(child)
    element.text = None
    element.set(XSI_NIL, "true")


def serialize(element: Element, *, declaration: bool) -> bytes:
    """Serialize an element tree as UTF-8."""
    return etree.tostring(element, encoding="UTF-8", xml_declaration=declaration)


def serialize_text(element: Element) -> str:
    """Serialize an element tree as a string, for an embedded payload."""
    return etree.tostring(element, encoding="unicode")
