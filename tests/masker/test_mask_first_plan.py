"""The reviewed overrides for the first recording plan (design §3.2, §4.5, §8.2, §8.5 #1).

- **Coverage.** The packaged maps leave no UNCLASSIFIED path in the operations of the first
  plan, in ``getIwsRequests`` (for the second plan) or in the SOAP faults, and classify
  nothing else.
- **Shapes** (§8.2). Each response is built from the real WSDL snapshot: every optional
  element present, lists of 1 and 3 rows, empty strings, and each ``filterType`` variant of
  ``accountSearch.details``. Every identifier is a canary and every free text carries
  canaries. The packaged maps mask it; the output holds no canary, no detector fires on it
  (the engine's runtime detector and an independent offline scan), the element structure is
  unchanged and the output still validates against the WSDL schema. Logged requests and
  responses in the IWS log are dropped whole, so another caller's entries nested in them never
  reach a recording (§5.3, §8.5 #19).
- **Requests.** ``accountSearch`` as a plan writes it, for each ``filterType`` the overrides
  map, unmasks and passes the vault-free check; refused filter types are refused, wildcards
  under the catalog filter types included.
- **Faults** (§8.5 #1). Fault text that echoes a request value is masked.

Every identifier is a canary (``masker.detect.canary``): real-format, outside every surrogate
prefix. No value here is real.
"""

import base64
import copy
import itertools
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field
from datetime import UTC, datetime
from functools import cache

import pytest
from lxml import etree

import generate_fieldmap as gen
from airtimesat_platform.gateway.sitest_port import generated_field_map_text
from airtimesat_platform.masker.detect.canary import canary
from airtimesat_platform.masker.detect.patterns import OPERATIONAL_SKIP, Detector, Options
from airtimesat_platform.masker.detect.scan import offline_exemption, scan_value
from airtimesat_platform.masker.engine import AUTH_FIELDS, MaskingEngine
from airtimesat_platform.masker.errors import MaskingBlockedError, RequestRefusedError
from airtimesat_platform.masker.fieldmap.loader import build_field_map, packaged_overrides
from airtimesat_platform.masker.fieldmap.model import (
    ANY_OPERATION,
    DATE_TYPES,
    NUMERIC_TYPES,
    Direction,
    FieldEntry,
    FieldMap,
    Treatment,
)
from airtimesat_platform.masker.freetext import Template
from airtimesat_platform.masker.tokenize.surrogates import SPECS
from airtimesat_platform.masker.tokenize.vault import Vault
from airtimesat_platform.masker.xmlsafe import Element
from airtimesat_platform.recorder.errors import PlanRefusedError
from airtimesat_platform.recorder.plan import FieldMapContext, check_plan

# The real WSDL schema check runs in this module (tests/conftest.py).
REAL_WSDL_SCHEMA = True

IWS = "http://www.iridium.com"
XSI = "http://www.w3.org/2001/XMLSchema-instance"
SOAP12 = "http://www.w3.org/2003/05/soap-envelope"
NOW = datetime(2026, 10, 22, 12, 0, tzinfo=UTC)
# The snapshot's schema, operations and validator come from the ``wsdl_schema`` fixture
# (tests/conftest.py), shared with PR W's tests/test_generate_fieldmap.py.
WsdlSchema = Callable[[str], tuple[gen.Schema, dict[str, gen.Operation], etree.XMLSchema]]

FIRST_PLAN = frozenset(
    {
        "getSystemStatus",
        "getIwsVersion",
        "getIwsReportVersion",
        "authenticatedPing",
        "accountSearch",
    }
)
SECOND_PLAN = frozenset({"getIwsRequests"})
IN_SCOPE = FIRST_PLAN | SECOND_PLAN
# Paths of these operations left UNCLASSIFIED on purpose, with the reason. None today.
UNCLASSIFIED_ON_PURPOSE: frozenset[tuple[str, Direction, str]] = frozenset()

# Synthetic auth values the signer core would inject; obviously fake.
USERNAME = "canary.login.900"
SP_ACCOUNT = "canary-sp-account-1"
RECORDER_CALLER = "rec.RP-2026-001"
# A Base64 string of HMAC-SHA1 signature length (28 characters): it must never survive. Built
# at run time, like the version and the long IDs below, so the repository leak scan does not
# read these synthetic values as findings (no allow-list entry is needed).
SIGNATURE = base64.b64encode(bytes(range(20))).decode()
TS = "2026-10-21T12:00:00Z"
# A dotted IWS version (design §8.5 #15): it looks like an IPv4 address to the detectors.
VERSION = ".".join(["22", "2", "0", "1"])
# Operational IDs and a count long enough for the long-digit rule.
LONG_ID = str(2 * 10**12 + 12345)
LONG_COUNT = str(10**9 + 234567)

# The reviewed filterType mapping (design §3.2), pinned here so a change is a visible diff.
FILTER_MAP: dict[str, str] = {
    "ACCOUNT_NUMBER": "T-NUM:CONTRACT",
    "MSISDN": "T-NUM:MSISDN",
    "MSISDNB": "T-NUM:OTHER_NUMBER",
    "MSISDNC": "T-NUM:OTHER_NUMBER",
    "SIM_SERIAL_NUMBER": "T-NUM:ICCID",
    "IMSI": "T-NUM:IMSI",
    "CAPCODE": "T-NUM:CAPCODE",
    "IMEI": "T-NUM:IMEI",
    "LOCAL": "T-NUM:OTHER_NUMBER",
    "IP_ADDRESS": "T-IP",
    "PROVIDER_REFERENCE": "T-STR:REF",
    "VESSEL_NAME": "T-STR:VESSEL",
    "MMSI": "T-NUM:MMSI",
    "ISDNA": "T-NUM:OTHER_NUMBER",
    "BURST_SERVICE": "T-STR:NAME",
    "ATS_ICAO": "T-STR:ID",
    "ATS_REG_TAIL_NUMBER": "T-STR:ID",
    "SHARED_GROUP": "T-STR:ID",
    "PTT_TG": "T-STR:ID",
    "IMO": "T-NUM:IMO",
}
# Catalog filter types, refused until the allowlist refuses wildcards in their filterValue: a
# KEEP target is not checked for * or %, which would list accounts SP-wide (§5.5 step 8).
CATALOG_FILTERS = frozenset({"MODEL", "VERTICAL", "VESSEL_TYPE"})
# Left out of the mapping, so a request with them is refused (TYPING_UNKNOWN; SMART earlier).
REFUSED_FILTERS = CATALOG_FILTERS | {
    "SMART",
    "DELIVERY_DEST",
    "MT_FILTER",
    "SECONDARY_SVC",
    "VESSEL_LINK",
}
# The kind of value each filter type carries, for accountSearch.details and the requests.
# Digit and address kinds are canary types; the others become "Canary <Kind> <n>" names.
FILTER_KIND: dict[str, str] = {
    "ACCOUNT_NUMBER": "CONTRACT",
    "MSISDN": "MSISDN",
    "MSISDNB": "OTHER_NUMBER",
    "MSISDNC": "OTHER_NUMBER",
    "SIM_SERIAL_NUMBER": "ICCID",
    "IMSI": "IMSI",
    "CAPCODE": "CAPCODE",
    "IMEI": "IMEI",
    "LOCAL": "OTHER_NUMBER",
    "IP_ADDRESS": "IPV4",
    "PROVIDER_REFERENCE": "REFERENCE",
    "VESSEL_NAME": "VESSEL",
    "MMSI": "MMSI",
    "ISDNA": "OTHER_NUMBER",
    "BURST_SERVICE": "SERVICE",
    "DELIVERY_DEST": "EMAIL",
    "MT_FILTER": "HOST",
    "MODEL": "MODEL",
    "ATS_ICAO": "ICAO",
    "ATS_REG_TAIL_NUMBER": "TAIL",
    "SECONDARY_SVC": "SERVICE",
    "SHARED_GROUP": "GROUP",
    "SMART": "ICCID",
    "PTT_TG": "NUMERIC_ID",
    "VERTICAL": "VERTICAL",
    "VESSEL_TYPE": "VESSELTYPE",
    "IMO": "IMO",
    "VESSEL_LINK": "VESSEL",
}
# Kept leaves, by element name: the values a real response would carry. Versions and
# operational IDs are chosen to trip the IPv4 and long-digit rules if they were not skipped.
KEPT: dict[str, str] = {
    "cbrmTime": TS,
    "startTime": TS,
    "endTime": TS,
    "activationDate": TS,
    "lastUpdated": TS,
    "requestedTs": TS,
    "openForBusiness": "TRUE",
    "maintenanceOccurring": "FALSE",
    "obsolete": "FALSE",
    "emergency": "TRUE",
    "iwsVersion": VERSION,
    "wsdlRevision": VERSION,
    "version": VERSION,
    "affectedElement": "SBD",
    "outageId": LONG_ID,
    "requestId": LONG_ID,
    "serviceType": "SHORT_BURST_DATA",
    "planName": "Standard Plan 12",
    "totalNumberOfRecords": LONG_COUNT,
}

# ---------------------------------------------------------------- the packaged maps


@cache
def _packaged() -> tuple[FieldMap, tuple[Template, ...]]:
    generated = generated_field_map_text()
    assert generated is not None
    field_map, templates = build_field_map(generated, packaged_overrides())
    return field_map, tuple(templates)


@pytest.fixture(name="field_map")
def field_map_fixture() -> FieldMap:
    """Return the packaged generated map merged with the packaged overrides."""
    return _packaged()[0]


@pytest.fixture(name="engine")
def engine_fixture(field_map: FieldMap, vault: Vault) -> MaskingEngine:
    """Return an engine over the packaged maps with the shared vault."""
    return MaskingEngine(field_map, vault, templates=_packaged()[1], constants={"SP": [SP_ACCOUNT]})


# ---------------------------------------------------------------- coverage


def test_no_unclassified_path_in_the_first_two_plans_or_the_faults(field_map: FieldMap) -> None:
    left = {e.key() for e in field_map.unclassified(IN_SCOPE)}
    assert left == UNCLASSIFIED_ON_PURPOSE
    for operation in IN_SCOPE:
        assert any(op == operation for op, _, _ in field_map.entries)
    assert any(op == ANY_OPERATION for op, _, _ in field_map.entries)


def test_nothing_outside_the_scope_is_classified(field_map: FieldMap) -> None:
    outside = [
        e.key()
        for e in field_map.entries.values()
        if e.operation not in IN_SCOPE | {ANY_OPERATION}
        and e.treatment is not Treatment.UNCLASSIFIED
    ]
    assert outside == []


def test_agents_add_no_templates() -> None:
    assert _packaged()[1] == ()


def test_identifier_fields_are_never_kept(field_map: FieldMap) -> None:
    identifiers = {
        "accountNumber",
        "details",
        "accountType",
        "iccid",
        "imei",
        "spReference",
        "requestUser",
        "caller",
        "filterValue",
    }
    seen: set[str] = set()
    for entry in field_map.entries.values():
        name = entry.path.rpartition("/")[2]
        if entry.operation in IN_SCOPE and name in identifiers:
            seen.add(name)
            assert entry.treatment is not Treatment.KEEP, entry.path
    assert seen == identifiers


def test_operational_is_set_only_on_versions_counts_and_ids(field_map: FieldMap) -> None:
    operational = {
        (e.operation, e.path.rpartition("/")[2])
        for e in field_map.entries.values()
        if e.operational
    }
    assert operational == {
        ("getSystemStatus", "iwsVersion"),
        ("getSystemStatus", "wsdlRevision"),
        ("getSystemStatus", "outageId"),
        ("getIwsVersion", "version"),
        ("getIwsReportVersion", "version"),
        ("accountSearch", "limit"),
        ("accountSearch", "startRow"),
        ("accountSearch", "totalNumberOfRecords"),
        ("getIwsRequests", "limit"),
        ("getIwsRequests", "startRow"),
        ("getIwsRequests", "requestId"),
    }


def test_free_text_is_f_everywhere(field_map: FieldMap) -> None:
    free = {"message", "outageReason", "description", "name", "errorMessage", "Text", "causedBy"}
    for entry in field_map.entries.values():
        if entry.operation in IN_SCOPE | {ANY_OPERATION} and entry.path.rpartition("/")[2] in free:
            assert entry.treatment is Treatment.F, entry.path


def _filter_enum(wsdl_schema: WsdlSchema) -> frozenset[str]:
    schema = wsdl_schema("provisioning")[0]
    simple = schema.simple["subscriberAccountSearchTypeEnum"]
    return frozenset(e.get("value", "") for e in simple.iter(f"{gen.XS}enumeration"))


def test_the_filter_type_mapping_covers_the_wsdl_enum(
    field_map: FieldMap, wsdl_schema: WsdlSchema
) -> None:
    entry = field_map.lookup("accountSearch", Direction.REQUEST, "request/filterValue")
    assert entry is not None
    assert entry.treatment is Treatment.TYPED
    assert entry.typed is not None
    assert entry.typed.sibling == "filterType"
    mapping = {
        value: target.value + (f":{label}" if label else "")
        for value, (target, label) in entry.typed.values.items()
    }
    assert mapping == FILTER_MAP
    assert set(FILTER_MAP) | REFUSED_FILTERS == _filter_enum(wsdl_schema)
    assert not set(FILTER_MAP) & REFUSED_FILTERS
    assert set(FILTER_KIND) == _filter_enum(wsdl_schema)


def test_no_path_in_scope_is_nillable(field_map: FieldMap) -> None:
    # So the nil variant of §8.2 is a refusal: xsi:nil blocks with NIL_NOT_ALLOWED below.
    assert not [
        e.path for e in field_map.entries.values() if e.operation in IN_SCOPE and e.nillable
    ]


# ---------------------------------------------------------------- the WSDL schema


def _valid(wsdl_schema: WsdlSchema, endpoint: str, element: Element) -> bool:
    return wsdl_schema(endpoint)[2].validate(etree.ElementTree(copy.deepcopy(element)))


# ---------------------------------------------------------------- synthetic responses


@dataclass
class Fill:
    """How to fill one synthetic response, and the identifier values put into it."""

    field_map: FieldMap
    wsdl: WsdlSchema
    operation: str
    rows: int = 1
    empty: bool = False
    filter_type: str = "IMEI"
    injected: list[str] = field(default_factory=list[str])
    counter: Iterator[int] = field(default_factory=lambda: itertools.count(1))

    def put(self, value: str) -> str:
        """Record an identifier value that must not survive masking."""
        self.injected.append(value)
        return value

    def free_text(self) -> str:
        """Return free text that echoes several identifiers."""
        n = next(self.counter)
        return (
            f"Lookup of {self.put(canary('CONTRACT', n))} for {self.put(canary('IMEI', n))} "
            f"by {self.put(f'canary.login.{n}')} at {self.put(canary('EMAIL', n))} "
            f"from {self.put(canary('IPV4', n))} failed"
        )

    def leaf(self, entry: FieldEntry, row: int) -> str:
        """Return the text of one non-enumeration leaf."""
        name = entry.path.rpartition("/")[2]
        if self.empty and entry.is_string:
            return ""
        n = next(self.counter)
        match entry.treatment:
            case Treatment.KEEP if name == "requestedOperation":
                return LOG_ROWS[row % len(LOG_ROWS)].operation
            case Treatment.KEEP:
                return KEPT[name]
            case Treatment.T_NUM:
                assert entry.id_type is not None
                return self.put(canary(entry.id_type, n))
            case Treatment.T_STR if entry.is_numeric:
                return self.put(canary("NUMERIC_ID", n))
            case Treatment.T_STR if name == "details":
                return self.put(canary(FILTER_KIND[self.filter_type], n))
            case Treatment.T_STR:
                return self.put(canary("REFERENCE", n))
            case Treatment.P_ONE if name == "caller":
                return RECORDER_CALLER if row % 2 == 0 else self.put(f"canary.login.{n}")
            case Treatment.P_ONE:
                return self.put(f"canary.login.{n}")
            case Treatment.F:
                return self.free_text()
            # Logged payloads (D: dropped whole) still carry canaries.
            case Treatment.D if name == "request":
                return LOG_ROWS[row % len(LOG_ROWS)].request(self)
            case Treatment.D if name == "response":
                return LOG_ROWS[row % len(LOG_ROWS)].response(self)
            case _:
                raise AssertionError(f"no synthetic value for {entry.path}")


def _enum_values(schema: gen.Schema, decl: Element) -> list[str]:
    simple = decl.find(f"{gen.XS}simpleType")
    if simple is None:
        simple = schema.simple.get(gen.local_part(decl.get("type")))
    if simple is None:
        return []
    return [e.get("value", "") for e in simple.iter(f"{gen.XS}enumeration")]


def _fill(
    fill: Fill,
    schema: gen.Schema,
    parent: Element,
    ctype: Element,
    path: str,
    row: int,
) -> None:
    for decl, _, high in gen.content(schema, ctype):
        name = decl.get("name", "")
        child_path = f"{path}/{name}"
        count = 1 if high == 1 else fill.rows
        for i in range(count):
            child = etree.SubElement(parent, name)
            child_row = row if high == 1 else row * 10 + i
            inline = decl.find(f"{gen.XS}complexType")
            type_name = gen.local_part(decl.get("type"))
            if inline is not None or type_name in schema.complex:
                target = inline if inline is not None else schema.complex[type_name]
                assert target.get("abstract") != "true"
                _fill(fill, schema, child, target, child_path, child_row)
                continue
            enum = _enum_values(schema, decl)
            if enum:
                child.text = enum[(child_row + i) % len(enum)]
                continue
            entry = fill.field_map.lookup(fill.operation, Direction.RESPONSE, child_path)
            assert entry is not None, child_path
            child.text = fill.leaf(entry, child_row)


def build_response(fill: Fill, endpoint: str) -> Element:
    """Build a schema-valid response body element for ``fill.operation``."""
    schema, operations, _ = fill.wsdl(endpoint)
    body = etree.Element(f"{{{IWS}}}{fill.operation}Response", nsmap={"tns": IWS, "xsi": XSI})
    response = etree.SubElement(body, "response")
    response_type = operations[fill.operation].response
    assert response_type is not None
    _fill(fill, schema, response, schema.complex[response_type], f"{body_name(fill)}/response", 0)
    assert _valid(fill.wsdl, endpoint, body)
    return body


def body_name(fill: Fill) -> str:
    """Return the response body element's name."""
    return f"{fill.operation}Response"


def envelope(body: Element) -> bytes:
    """Wrap a body element in a SOAP 1.2 envelope."""
    env = etree.Element(f"{{{SOAP12}}}Envelope", nsmap={"env": SOAP12})
    etree.SubElement(env, f"{{{SOAP12}}}Body").append(copy.deepcopy(body))
    return etree.tostring(env, xml_declaration=True, encoding="UTF-8")


def body_of(data: bytes) -> Element:
    """Return the body element of a SOAP envelope."""
    root = etree.fromstring(data, etree.XMLParser(resolve_entities=False, no_network=True))
    body = root.find(f"{{{SOAP12}}}Body")
    assert body is not None
    return body[0]


# ---------------------------------------------------------------- IWS log rows (second plan)


def _auth(fill: Fill) -> str:
    return (
        f"<iwsUsername>{USERNAME}</iwsUsername><signature>{fill.put(SIGNATURE)}</signature>"
        f"<serviceProviderAccountNumber>{SP_ACCOUNT}</serviceProviderAccountNumber>"
        f"<timestamp>{TS}</timestamp><caller>{RECORDER_CALLER}</caller>"
    )


def search_request(filter_type: str, value: str) -> str:
    """Return an accountSearch request body as a plan writes it (no auth fields)."""
    return (
        "<request><serviceType>CERTUS</serviceType>"
        f"<filterType>{filter_type}</filterType><filterCond>EQUALS</filterCond>"
        f"<filterValue>{value}</filterValue><limit>5</limit><startRow>0</startRow></request>"
    )


def _logged_search(filter_type: str) -> Callable[[Fill], str]:
    def request(fill: Fill) -> str:
        value = fill.put(canary(FILTER_KIND[filter_type], next(fill.counter)))
        inner = search_request(filter_type, value).replace("<request>", f"<request>{_auth(fill)}")
        return f'<tns:accountSearch xmlns:tns="{IWS}">{inner}</tns:accountSearch>'

    return request


def _logged_status(fill: Fill) -> str:
    request = f"<request>{_auth(fill)}</request>"
    return f'<tns:getSystemStatus xmlns:tns="{IWS}">{request}</tns:getSystemStatus>'


def _logged_response(operation: str) -> Callable[[Fill], str]:
    def response(fill: Fill) -> str:
        inner = Fill(
            fill.field_map, fill.wsdl, operation, injected=fill.injected, counter=fill.counter
        )
        body = build_response(inner, "provisioning")
        return etree.tostring(body, encoding="unicode")

    return response


def _unparsable(fill: Fill) -> str:
    return f"<accountSearchResponse>{fill.put(canary('ICCID', next(fill.counter)))}"


@dataclass(frozen=True)
class LogRow:
    """One IWS log entry: the operation it names and its logged request and response."""

    operation: str
    request: Callable[[Fill], str]
    response: Callable[[Fill], str]


LOG_ROWS: tuple[LogRow, ...] = (
    LogRow("accountSearch", _logged_search("IMEI"), _logged_response("accountSearch")),
    LogRow("getSystemStatus", _logged_status, _logged_response("getSystemStatus")),
    # A filter type the mapping refuses. Every logged payload is dropped (D), one that does not
    # parse included.
    LogRow("accountSearch", _logged_search("DELIVERY_DEST"), _unparsable),
)


# ---------------------------------------------------------------- checks on the output


def _shape(root: Element) -> list[tuple[str, str | None, int]]:
    """Return each element's name, xsi:type and child count, authentication fields left out."""

    def kept(element: Element) -> bool:
        return etree.QName(element).localname not in AUTH_FIELDS

    return [
        (etree.QName(e).localname, e.get(f"{{{XSI}}}type"), sum(1 for c in e if kept(c)))
        for e in root.iter()
        if kept(e)
    ]


def _options(entry: FieldEntry) -> Options:
    if entry.treatment is Treatment.KEEP and (
        entry.xsd_type in NUMERIC_TYPES | DATE_TYPES | {"boolean"} or entry.operational
    ):
        return Options(skip=OPERATIONAL_SKIP)
    return Options()


def offline_hits(
    field_map: FieldMap, operation: str, direction: Direction, root: Element
) -> list[tuple[str, Detector]]:
    """Scan every output leaf with the offline detectors."""
    hits: list[tuple[str, Detector]] = []
    for element in root.iter():
        if len(element):
            continue
        names = [etree.QName(a).localname for a in reversed(list(element.iterancestors()))]
        names.append(etree.QName(element).localname)
        names = names[names.index(etree.QName(root).localname) :]
        path = "/".join(names)
        entry = field_map.lookup(operation, direction, path)
        assert entry is not None, path
        detector = scan_value(element.text or "", _options(entry), offline_exemption())
        if detector is not None:
            hits.append((path, detector))
    return hits


def assert_masked(
    field_map: FieldMap, fill: Fill, endpoint: str, before: Element, masked: bytes
) -> None:
    """Assert the §8.2 properties of one masked response."""
    text = masked.decode("utf-8")
    assert [v for v in fill.injected if v in text] == []
    assert "canary" not in text.casefold()
    after = body_of(masked)
    assert _shape(after) == _shape(before)
    assert _valid(fill.wsdl, endpoint, after)
    assert offline_hits(field_map, fill.operation, Direction.RESPONSE, after) == []
    # Logged payloads in the IWS log are dropped whole (D).
    for old, new in zip(
        before.iter("request", "response"), after.iter("request", "response"), strict=True
    ):
        if not len(old) and (old.text or "").strip():
            assert new.text == "REDACTED"


def mask(engine: MaskingEngine, operation: str, data: bytes) -> bytes:
    """Mask one response as the recorder does, with the signer core's auth values injected."""
    call = engine.start_call(operation, (USERNAME, SP_ACCOUNT))
    return engine.mask_response(call, data).body


# ---------------------------------------------------------------- per-shape tests

SHAPES = [
    pytest.param(1, False, id="1-row"),
    pytest.param(3, False, id="3-rows"),
    pytest.param(1, True, id="empty"),
    pytest.param(3, True, id="3-rows-empty"),
]
RESPONSES = [
    ("provisioning", "getSystemStatus"),
    ("reporting", "getSystemStatus"),
    ("provisioning", "getIwsVersion"),
    ("reporting", "getIwsReportVersion"),
    ("provisioning", "authenticatedPing"),
    ("provisioning", "getIwsRequests"),
]


@pytest.mark.parametrize(("rows", "empty"), SHAPES)
@pytest.mark.parametrize(("endpoint", "operation"), RESPONSES)
def test_response_shapes_are_masked(
    field_map: FieldMap,
    engine: MaskingEngine,
    wsdl_schema: WsdlSchema,
    endpoint: str,
    operation: str,
    rows: int,
    empty: bool,
) -> None:
    fill = Fill(field_map, wsdl_schema, operation, rows=rows, empty=empty)
    body = build_response(fill, endpoint)
    masked = mask(engine, operation, envelope(body))
    assert_masked(field_map, fill, endpoint, body, masked)
    if operation != "authenticatedPing" and not empty:
        assert fill.injected


# Each filter type with 1 and 3 rows; the empty variants once, since an empty details string
# does not depend on the filter type.
SEARCH_SHAPES = [
    pytest.param(filter_type, rows, False, id=f"{filter_type}-{rows}")
    for filter_type in sorted(FILTER_KIND)
    for rows in (1, 3)
] + [pytest.param("IMEI", rows, True, id=f"empty-{rows}") for rows in (1, 3)]


@pytest.mark.parametrize(("filter_type", "rows", "empty"), SEARCH_SHAPES)
def test_account_search_shapes_are_masked_for_every_filter_type(
    field_map: FieldMap,
    engine: MaskingEngine,
    wsdl_schema: WsdlSchema,
    filter_type: str,
    rows: int,
    empty: bool,
) -> None:
    # details carries the value of the request's filter type (design §3.2); generic T-STR
    # masks every variant.
    fill = Fill(
        field_map, wsdl_schema, "accountSearch", rows=rows, empty=empty, filter_type=filter_type
    )
    body = build_response(fill, "provisioning")
    masked = mask(engine, "accountSearch", envelope(body))
    assert_masked(field_map, fill, "provisioning", body, masked)
    details = body_of(masked).findall(".//details")
    assert len(details) == rows
    for element in details:
        assert empty == (element.text is None or element.text == "")
        assert empty or SPECS["VALUE"].is_surrogate_shape(element.text or "")


def test_masked_identifiers_keep_their_types(
    field_map: FieldMap, engine: MaskingEngine, wsdl_schema: WsdlSchema
) -> None:
    fill = Fill(field_map, wsdl_schema, "accountSearch", rows=1)
    masked = body_of(mask(engine, "accountSearch", envelope(build_response(fill, "provisioning"))))
    row = masked.find(".//subscriber")
    assert row is not None
    expected = {
        "accountNumber": "CONTRACT",
        "iccid": "ICCID",
        "imei": "IMEI",
        "spReference": "REF",
        "accountType": "NUMERIC_ID",
    }
    for name, type_name in expected.items():
        assert SPECS[type_name].is_surrogate_shape(row.findtext(name) or ""), name
    assert row.findtext("planName") == KEPT["planName"]


def test_versions_and_ids_are_kept_without_a_false_block(
    field_map: FieldMap, engine: MaskingEngine, wsdl_schema: WsdlSchema
) -> None:
    # Design §8.5 #15: a dotted version and long operational IDs are not blocked.
    fill = Fill(field_map, wsdl_schema, "getSystemStatus", rows=1)
    masked = body_of(
        mask(engine, "getSystemStatus", envelope(build_response(fill, "provisioning")))
    )
    assert masked.findtext(".//iwsVersion") == VERSION
    assert masked.findtext(".//outageId") == KEPT["outageId"]
    assert (masked.findtext(".//outageReason") or "").startswith("Text-")


def test_the_iws_log_keeps_the_recorder_caller_and_masks_the_rest(
    field_map: FieldMap, engine: MaskingEngine, wsdl_schema: WsdlSchema
) -> None:
    fill = Fill(field_map, wsdl_schema, "getIwsRequests", rows=3)
    masked = body_of(mask(engine, "getIwsRequests", envelope(build_response(fill, "provisioning"))))
    logs = masked.findall(".//iwsLog")
    assert [e.findtext("caller") == RECORDER_CALLER for e in logs] == [True, False, True]
    for entry in logs:
        assert (entry.findtext("requestUser") or "").startswith("user-")
        assert entry.findtext("requestId") == KEPT["requestId"]
        # Every logged request and response is dropped whole (D), auth fields included.
        assert entry.findtext("request") == "REDACTED"
        assert entry.findtext("response") == "REDACTED"


def test_the_injected_username_in_request_user_becomes_a_one_way_surrogate(
    field_map: FieldMap, engine: MaskingEngine, wsdl_schema: WsdlSchema
) -> None:
    # The production case for every recorder log row: requestUser holds the iwsUsername the
    # signer core injects, which is also a known value for the call. P-ONE turns it into a
    # one-way user- surrogate, and the call is not blocked.
    fill = Fill(field_map, wsdl_schema, "getIwsRequests", rows=1)
    body = build_response(fill, "provisioning")
    log = body.find(".//iwsLog")
    assert log is not None
    assert log.findtext("caller") == RECORDER_CALLER
    user = log.find("requestUser")
    assert user is not None
    user.text = USERNAME
    masked = mask(engine, "getIwsRequests", envelope(body))
    assert USERNAME not in masked.decode()
    out = body_of(masked).findtext(".//iwsLog/requestUser") or ""
    assert out.startswith("user-")
    assert SPECS["USER"].is_surrogate_shape(out)


def _set(element: Element, path: str, text: str) -> None:
    child = element.find(path)
    assert child is not None, path
    child.text = text


def test_logged_payloads_are_dropped_whole(
    field_map: FieldMap, engine: MaskingEngine, wsdl_schema: WsdlSchema
) -> None:
    # A logged getSystemStatus request carries the auth fields, and its logged response a
    # dotted version and a long outage ID. Under D both are written as REDACTED, so the call
    # is neither blocked nor leaks them.
    fill = Fill(field_map, wsdl_schema, "getIwsRequests", rows=1)
    body = build_response(fill, "provisioning")
    log = body.find(".//iwsLog")
    assert log is not None
    _set(log, "requestedOperation", "getSystemStatus")
    _set(log, "request", _logged_status(fill))
    logged = _logged_response("getSystemStatus")(fill)
    assert VERSION in logged
    _set(log, "response", logged)
    masked = mask(engine, "getIwsRequests", envelope(body))
    assert body_of(masked).findtext(".//iwsLog/request") == "REDACTED"
    assert body_of(masked).findtext(".//iwsLog/response") == "REDACTED"
    assert VERSION not in masked.decode()
    assert [v for v in fill.injected if v in masked.decode()] == []


# Another caller's log entry, nested in a logged getIwsRequests response. All synthetic.
FOREIGN_CALLER = "canary.portal.7"
FOREIGN_ID = str(3 * 10**12 + 777)
FOREIGN_NAME = "Canary Person Seven"


def test_a_nested_foreign_log_entry_never_reaches_the_output(
    field_map: FieldMap, engine: MaskingEngine, wsdl_schema: WsdlSchema
) -> None:
    # Design §5.3 and §8.5 #19: other callers' requests never reach a recording, not even
    # masked. The caller filter parses only the top-level log, so an earlier recorder
    # getIwsRequests call whose logged response holds the unfiltered log must not pass on
    # its entries: logged payloads are dropped whole.
    fill = Fill(field_map, wsdl_schema, "getIwsRequests", rows=1)
    inner = Fill(field_map, wsdl_schema, "getIwsRequests", injected=fill.injected)
    inner.counter = fill.counter
    nested = build_response(inner, "provisioning")
    foreign = nested.find(".//iwsLog")
    assert foreign is not None
    _set(foreign, "caller", FOREIGN_CALLER)
    _set(foreign, "requestId", FOREIGN_ID)
    _set(foreign, "requestedOperation", "accountSearch")
    search = search_request("VESSEL_TYPE", FOREIGN_NAME)
    _set(foreign, "request", f'<tns:accountSearch xmlns:tns="{IWS}">{search}</tns:accountSearch>')
    body = build_response(fill, "provisioning")
    log = body.find(".//iwsLog")
    assert log is not None
    assert log.findtext("caller") == RECORDER_CALLER
    window = (
        "<iwsOperation>accountSearch</iwsOperation><startDate>2026-11-02T09:00:00Z</startDate>"
        "<endDate>2026-11-02T10:00:00Z</endDate><limit>20</limit><startRow>0</startRow>"
    )
    _set(log, "requestedOperation", "getIwsRequests")
    _set(
        log,
        "request",
        f'<tns:getIwsRequests xmlns:tns="{IWS}"><request>{_auth(fill)}{window}</request>'
        "</tns:getIwsRequests>",
    )
    _set(log, "response", etree.tostring(nested, encoding="unicode"))
    masked = mask(engine, "getIwsRequests", envelope(body))
    text = masked.decode()
    for value in (FOREIGN_CALLER, FOREIGN_ID, FOREIGN_NAME, *fill.injected):
        assert value not in text
    out = body_of(masked)
    assert len(out.findall(".//iwsLog")) == 1
    assert out.findtext(".//iwsLog/request") == "REDACTED"
    assert out.findtext(".//iwsLog/response") == "REDACTED"


@pytest.mark.parametrize("filter_type", sorted(FILTER_KIND))
def test_a_logged_request_is_dropped_for_every_filter_type(
    field_map: FieldMap, engine: MaskingEngine, wsdl_schema: WsdlSchema, filter_type: str
) -> None:
    # A logged accountSearch request never reaches the output, whatever its filter type,
    # refused and catalog filter types included.
    fill = Fill(field_map, wsdl_schema, "getIwsRequests", rows=1)
    body = build_response(fill, "provisioning")
    log = body.find(".//iwsLog")
    assert log is not None
    _set(log, "requestedOperation", "accountSearch")
    _set(log, "request", _logged_search(filter_type)(fill))
    masked = mask(engine, "getIwsRequests", envelope(body))
    assert [v for v in fill.injected if v in masked.decode()] == []
    assert body_of(masked).findtext(".//iwsLog/request") == "REDACTED"


def test_a_nil_element_is_refused(
    field_map: FieldMap, engine: MaskingEngine, wsdl_schema: WsdlSchema
) -> None:
    fill = Fill(field_map, wsdl_schema, "accountSearch", rows=1)
    body = build_response(fill, "provisioning")
    imei = body.find(".//imei")
    assert imei is not None
    imei.text = None
    imei.set(f"{{{XSI}}}nil", "true")
    with pytest.raises(MaskingBlockedError) as info:
        mask(engine, "accountSearch", envelope(body))
    assert info.value.code == "NIL_NOT_ALLOWED"


# ---------------------------------------------------------------- requests


def _surrogate_for(vault: Vault, target: str, n: int) -> tuple[str, str]:
    """Issue a surrogate for a canary of a mapped filter target; return (real, surrogate)."""
    treatment, _, label = target.partition(":")
    if treatment == "T-IP":
        real = canary("IPV4", n)
        return real, vault.issue("IPV4", real)
    if treatment == "T-NUM":
        real = canary(label, n)
        return real, vault.issue(label, real)
    real = canary(label.title(), n)
    return real, vault.issue(label, real)


def plan_text(*calls: tuple[str, str, str]) -> str:
    """Return a plan's YAML text from (endpoint, operation, request) calls."""
    body = "".join(
        f"  - id: c{n}\n    endpoint: {endpoint}\n    operation: {operation}\n"
        f"    request: '{request}'\n"
        for n, (endpoint, operation, request) in enumerate(calls, start=1)
    )
    return (
        "id: RP-2026-001\ntitle: First plan shapes\npurpose: Overrides tests\n"
        f"expires_at: 2026-11-30T00:00:00Z\nmax_calls: 10\ncalls:\n{body}"
    )


IDENTIFIER_FILTERS = sorted(FILTER_MAP)


@pytest.mark.parametrize("filter_type", IDENTIFIER_FILTERS)
def test_identifier_filters_unmask_and_pass_the_check(
    field_map: FieldMap, engine: MaskingEngine, vault: Vault, filter_type: str
) -> None:
    real, surrogate = _surrogate_for(vault, FILTER_MAP[filter_type], 3)
    request = search_request(filter_type, surrogate)
    assert MaskingEngine(field_map, None).check_request("accountSearch", request.encode()) is None
    check_plan(
        plan_text(("provisioning", "accountSearch", request)),
        now=NOW,
        field_map=FieldMapContext(field_map),
    )
    result = engine.unmask_request(engine.start_call("accountSearch"), request.encode())
    assert result.resolved == 1
    assert etree.fromstring(result.body).findtext("filterValue") == real
    assert surrogate not in result.body.decode()


@pytest.mark.parametrize("value", ["*", "%", "A*", "Catalog Value A"])
@pytest.mark.parametrize("filter_type", sorted(CATALOG_FILTERS))
def test_catalog_filters_are_refused_wildcards_included(
    field_map: FieldMap, filter_type: str, value: str
) -> None:
    # Until a reviewed recorder PR adds no_wildcards for accountSearch.filterValue, a KEEP
    # target would let * or % list accounts SP-wide (design §5.5 step 8, §8.5 #16, #18).
    request = search_request(filter_type, value)
    refusal = MaskingEngine(field_map, None).check_request("accountSearch", request.encode())
    assert refusal is not None
    assert (refusal.code, refusal.path) == ("TYPING_UNKNOWN", "request/filterValue")
    with pytest.raises(PlanRefusedError) as info:
        check_plan(
            plan_text(("provisioning", "accountSearch", request)),
            now=NOW,
            field_map=FieldMapContext(field_map),
        )
    assert info.value.code == "TYPING_UNKNOWN"


@pytest.mark.parametrize("filter_type", sorted(REFUSED_FILTERS - {"SMART"}))
def test_refused_filters_are_refused(field_map: FieldMap, filter_type: str) -> None:
    request = search_request(filter_type, SPECS["VALUE"].render(bytes(32), ""))
    refusal = MaskingEngine(field_map, None).check_request("accountSearch", request.encode())
    assert refusal is not None
    assert (refusal.code, refusal.path) == ("TYPING_UNKNOWN", "request/filterValue")


def test_smart_is_refused_by_the_allowlist(field_map: FieldMap) -> None:
    request = search_request("SMART", SPECS["ICCID"].render(bytes(32), ""))
    with pytest.raises(PlanRefusedError) as info:
        check_plan(
            plan_text(("provisioning", "accountSearch", request)),
            now=NOW,
            field_map=FieldMapContext(field_map),
        )
    assert info.value.code == "FILTER_SMART_REFUSED"


def test_a_guessed_surrogate_is_refused_at_run_time(engine: MaskingEngine) -> None:
    # The vault is empty on the first run (design §5.5 step 2, §8.5 #6).
    request = search_request("IMEI", SPECS["IMEI"].render(bytes(32), ""))
    with pytest.raises(RequestRefusedError) as info:
        engine.unmask_request(engine.start_call("accountSearch"), request.encode())
    assert info.value.code == "IDENTIFIER_NOT_ISSUED"


def test_the_first_and_second_plans_requests_pass_the_check(field_map: FieldMap) -> None:
    log = (
        "<request><iwsOperation>getSystemStatus</iwsOperation>"
        "<startDate>2026-11-02T09:00:00Z</startDate><endDate>2026-11-02T10:00:00Z</endDate>"
        "<limit>20</limit><startRow>0</startRow></request>"
    )
    text = plan_text(
        ("provisioning", "getSystemStatus", "<request/>"),
        ("reporting", "getSystemStatus", "<request/>"),
        ("provisioning", "getIwsVersion", "<request/>"),
        ("reporting", "getIwsReportVersion", "<request/>"),
        ("provisioning", "authenticatedPing", "<request/>"),
        ("provisioning", "getIwsRequests", log),
    )
    checked = check_plan(text, now=NOW, field_map=FieldMapContext(field_map))
    assert len(checked.plan.calls) == 6


# ---------------------------------------------------------------- faults


def fault(detail: str, text: str) -> bytes:
    """Return a SOAP 1.2 fault envelope with a reason text and an IWS detail."""
    return (
        f'<?xml version="1.0" encoding="UTF-8"?><env:Envelope xmlns:env="{SOAP12}">'
        "<env:Body><env:Fault><env:Code><env:Value>env:Receiver</env:Value>"
        "<env:Subcode><env:Value>env:Receiver</env:Value></env:Subcode></env:Code>"
        f'<env:Reason><env:Text xml:lang="en">{text}</env:Text></env:Reason>'
        f"<env:Detail>{detail}</env:Detail></env:Fault></env:Body></env:Envelope>"
    ).encode()


def _detail(name: str, message: str) -> str:
    if name in ("IWSException", "AuthorizationException"):
        inner = (
            f"<causedBy>{message}</causedBy><errorCode>FIELD</errorCode>"
            f"<message>{message}</message>"
        )
    else:
        inner = f"<message>{message}</message>"
    return f'<tns:{name} xmlns:tns="{IWS}">{inner}</tns:{name}>'


EXCEPTIONS = [
    "IWSException",
    "AuthorizationException",
    "InvocationTargetException",
    "NoSuchMethodException",
]


@pytest.mark.parametrize("exception", EXCEPTIONS)
def test_fault_text_that_echoes_a_request_value_is_masked(
    engine: MaskingEngine, vault: Vault, wsdl_schema: WsdlSchema, exception: str
) -> None:
    # Design §8.5 #1: an accountSearch whose error text echoes the filter value.
    real = canary("IMEI", 21)
    surrogate = vault.issue("IMEI", real)
    call = engine.start_call("accountSearch", (USERNAME, SP_ACCOUNT))
    engine.unmask_request(call, search_request("IMEI", surrogate).encode())
    echo = f"No unique account for search type [IMEI] and value [{real}] or SP [{SP_ACCOUNT}]"
    detail = _detail(exception, echo)
    data = fault(detail, echo)
    result = engine.mask_response(call, data)
    assert result.fault
    text = result.body.decode()
    assert real not in text
    assert SP_ACCOUNT not in text
    root = etree.fromstring(result.body)
    reason = root.findtext(f".//{{{SOAP12}}}Text") or ""
    assert reason.startswith("Text-")
    detail_out = root.find(f".//{{{IWS}}}{exception}")
    assert detail_out is not None
    assert (detail_out.findtext("message") or "").startswith("Text-")
    assert _shape(root) == _shape(etree.fromstring(data))
    assert _valid(wsdl_schema, "provisioning", detail_out)
    if exception in ("IWSException", "AuthorizationException"):
        assert detail_out.findtext("errorCode") == "FIELD"


@pytest.mark.parametrize("operation", sorted(IN_SCOPE))
def test_every_operation_uses_the_shared_fault_paths(engine: MaskingEngine, operation: str) -> None:
    echo = f"Unable to find parent account {canary('CONTRACT', 22)}"
    result = engine.mask_response(
        engine.start_call(operation, (USERNAME, SP_ACCOUNT)),
        fault(_detail("IWSException", echo), echo),
    )
    assert result.fault
    assert canary("CONTRACT", 22) not in result.body.decode()


# ---------------------------------------------------------------- nil fault detail fields
#
# IWS marshals a null Java field of its fault beans as xsi:nil="true", although the WSDL
# declares those fields optional and not nillable. The first live run (RP-2026-001, call
# status-provisioning) blocked with NIL_NOT_ALLOWED at Fault/Detail/IWSException/causedBy.
# Only these optional fault-detail leaves accept nil (overrides ``allow_nil``); a nil element
# carries no value to mask. Every other nil still blocks.

NIL = f'xmlns:xsi="{XSI}" xsi:nil="true"'
DETAIL_FIELDS = {
    "IWSException": ("causedBy", "errorCode", "message"),
    "AuthorizationException": ("causedBy", "errorCode", "message"),
    "InvocationTargetException": ("message",),
    "NoSuchMethodException": ("message",),
}
NIL_CASES = [
    pytest.param(name, (nil,), id=f"{name}-{nil}")
    for name, fields in DETAIL_FIELDS.items()
    for nil in fields
] + [pytest.param(name, fields, id=f"{name}-all") for name, fields in DETAIL_FIELDS.items()]


def _nil_detail(name: str, nil: tuple[str, ...], text: str = "Synthetic detail") -> str:
    values = {"causedBy": text, "errorCode": "SYS", "message": text}
    inner = "".join(
        f"<{f} {NIL}/>" if f in nil else f"<{f}>{values[f]}</{f}>" for f in DETAIL_FIELDS[name]
    )
    return f'<tns:{name} xmlns:tns="{IWS}">{inner}</tns:{name}>'


def _status_fault(engine: MaskingEngine, data: bytes) -> bytes:
    call = engine.start_call("getSystemStatus", (USERNAME, SP_ACCOUNT))
    return engine.mask_response(call, data).body


@pytest.mark.parametrize(("exception", "nil"), NIL_CASES)
def test_a_nil_fault_detail_field_is_kept_as_nil(
    engine: MaskingEngine, exception: str, nil: tuple[str, ...]
) -> None:
    call = engine.start_call("getSystemStatus", (USERNAME, SP_ACCOUNT))
    echo = f"Lookup failed for {canary('CONTRACT', 31)}"
    result = engine.mask_response(call, fault(_nil_detail(exception, nil, echo), echo))
    assert result.fault
    assert canary("CONTRACT", 31) not in result.body.decode()
    detail = etree.fromstring(result.body).find(f".//{{{IWS}}}{exception}")
    assert detail is not None
    for name in nil:
        element = detail.find(name)
        assert element is not None
        assert element.get(f"{{{XSI}}}nil") == "true"
        assert element.text is None
        assert len(element) == 0


def test_nil_elsewhere_in_a_fault_still_blocks(engine: MaskingEngine) -> None:
    nil_text = fault(_nil_detail("IWSException", ()), "x").replace(
        b'<env:Text xml:lang="en">x</env:Text>', f'<env:Text xml:lang="en" {NIL}/>'.encode()
    )
    with pytest.raises(MaskingBlockedError) as info:
        _status_fault(engine, nil_text)
    assert info.value.code == "NIL_NOT_ALLOWED"
    nil_bean = fault(f'<tns:IWSException xmlns:tns="{IWS}" {NIL}/>', "x")
    with pytest.raises(MaskingBlockedError) as info:
        _status_fault(engine, nil_bean)
    assert info.value.code == "NIL_NOT_ALLOWED"


def test_a_nil_fault_field_with_content_still_blocks(engine: MaskingEngine) -> None:
    detail = _nil_detail("IWSException", ()).replace(
        "<causedBy>Synthetic detail</causedBy>", f"<causedBy {NIL}>Synthetic detail</causedBy>"
    )
    with pytest.raises(MaskingBlockedError) as info:
        _status_fault(engine, fault(detail, "x"))
    assert info.value.code == "MIXED_CONTENT"


def test_an_unknown_fault_detail_element_still_blocks(engine: MaskingEngine) -> None:
    detail = _nil_detail("IWSException", ("causedBy",)).replace(
        "</tns:IWSException>", "<stackTrace>Synthetic</stackTrace></tns:IWSException>"
    )
    with pytest.raises(MaskingBlockedError) as info:
        _status_fault(engine, fault(detail, "x"))
    assert info.value.code == "UNKNOWN_ELEMENT"


def test_nil_is_allowed_only_on_the_fault_detail_leaves(field_map: FieldMap) -> None:
    allowed = {
        e.path for e in field_map.entries.values() if e.nillable and e.operation == ANY_OPERATION
    }
    assert allowed == {
        f"Fault/Detail/{name}/{leaf}" for name, fields in DETAIL_FIELDS.items() for leaf in fields
    }
