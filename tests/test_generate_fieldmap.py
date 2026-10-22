"""Tests for scripts/generate_fieldmap.py: synthetic WSDL, drift, coverage and engine paths."""

import copy
from collections.abc import Iterator
from functools import cache

import pytest
from lxml import etree

import generate_fieldmap as gen
from airtimesat_platform.gateway.sitest_port import generated_field_map_text
from airtimesat_platform.masker.engine import MaskingEngine
from airtimesat_platform.masker.fieldmap.loader import build_field_map, load_generated
from airtimesat_platform.masker.fieldmap.model import FieldEntry, FieldMap, propose
from airtimesat_platform.masker.tokenize.vault import Vault
from airtimesat_platform.masker.xmlsafe import Element

IWS = "http://www.iridium.com"
XS = "http://www.w3.org/2001/XMLSchema"
XSI = "http://www.w3.org/2001/XMLSchema-instance"
SOAP12 = "http://www.w3.org/2003/05/soap-envelope"

SYNTHETIC = f"""<?xml version="1.0" encoding="UTF-8"?>
<wsdl:definitions xmlns:wsdl="http://schemas.xmlsoap.org/wsdl/" xmlns:xs="{XS}"
    xmlns:tns="{IWS}" targetNamespace="{IWS}">
 <wsdl:types>
  <xs:schema targetNamespace="{IWS}" elementFormDefault="unqualified">
   <xs:element name="IWSException" type="tns:iwsException"/>
   <xs:complexType name="iwsException"><xs:sequence>
     <xs:element name="errorCode" type="tns:errorCode" minOccurs="0"/>
     <xs:element name="cause" type="tns:iwsException" minOccurs="0"/>
   </xs:sequence></xs:complexType>
   <xs:simpleType name="errorCode"><xs:restriction base="xs:string">
     <xs:enumeration value="AUTH"/><xs:enumeration value="SYS"/>
   </xs:restriction></xs:simpleType>
   <xs:simpleType name="shortText"><xs:restriction base="xs:string">
     <xs:maxLength value="8"/>
   </xs:restriction></xs:simpleType>
   <xs:complexType name="baseRequest"><xs:sequence>
     <xs:element name="iwsUsername" type="xs:string"/>
     <xs:element name="signature" type="xs:string"/>
   </xs:sequence></xs:complexType>
   <xs:complexType name="lookupRequest"><xs:complexContent>
    <xs:extension base="tns:baseRequest"><xs:sequence>
     <xs:element name="limit" type="xs:int"/>
     <xs:choice minOccurs="0">
      <xs:element name="byId" type="xs:string"/>
      <xs:element name="byName" type="tns:shortText"/>
     </xs:choice>
    </xs:sequence></xs:extension>
   </xs:complexContent></xs:complexType>
   <xs:complexType name="lookupResponse"><xs:sequence>
     <xs:element name="device" type="tns:device" minOccurs="0" maxOccurs="unbounded"/>
     <xs:element name="node" type="tns:node" minOccurs="0"/>
   </xs:sequence></xs:complexType>
   <xs:complexType name="device" abstract="true"><xs:sequence>
     <xs:element name="status" type="tns:errorCode"/>
     <xs:element name="updated" type="xs:dateTime" nillable="true"/>
   </xs:sequence></xs:complexType>
   <xs:complexType name="imeiDevice"><xs:complexContent><xs:extension base="tns:device">
     <xs:sequence><xs:element name="imei" type="xs:string"/></xs:sequence>
   </xs:extension></xs:complexContent></xs:complexType>
   <xs:complexType name="simDevice"><xs:complexContent><xs:extension base="tns:device">
     <xs:sequence><xs:element name="iccid" type="xs:string"/></xs:sequence>
   </xs:extension></xs:complexContent></xs:complexType>
   <xs:complexType name="node"><xs:sequence>
     <xs:element name="label" type="xs:string"/>
     <xs:element name="node" type="tns:node" minOccurs="0"/>
   </xs:sequence></xs:complexType>
  </xs:schema>
 </wsdl:types>
 <wsdl:message name="lookup"><wsdl:part name="request" type="tns:lookupRequest"/></wsdl:message>
 <wsdl:message name="lookupResponse">
  <wsdl:part name="response" type="tns:lookupResponse"/>
 </wsdl:message>
 <wsdl:message name="IWSException">
  <wsdl:part name="IWSException" element="tns:IWSException"/>
 </wsdl:message>
 <wsdl:portType name="iws">
  <wsdl:operation name="lookup">
   <wsdl:input message="tns:lookup"/><wsdl:output message="tns:lookupResponse"/>
   <wsdl:fault message="tns:IWSException" name="IWSException"/>
  </wsdl:operation>
 </wsdl:portType>
</wsdl:definitions>
""".encode()


def _rows(text: str) -> dict[tuple[str, str], FieldEntry]:
    return {(e.direction.value, e.path): e for e in load_generated(text)}


def test_the_generator_on_a_synthetic_wsdl(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(gen, "MAX_DEPTH", 4)
    generated = gen.generate(
        {"provisioning": SYNTHETIC}, {"provisioning": frozenset({"lookup"})}, "x"
    )
    rows = _rows(generated.text)
    request = {path for direction, path in rows if direction == "request"}
    # Base content first, the authentication fields left to the signer core.
    assert request == {"request", "request/limit", "request/byId", "request/byName"}
    assert rows["request", "request/limit"].xsd_type == "int"
    # A choice branch may be absent; a restricted string keeps its base type.
    assert rows["request", "request/byName"].min_occurs == 0
    assert rows["request", "request/byName"].xsd_type == "string"
    base = "lookupResponse/response"
    # The abstract declared type gets no path of its own; each concrete subtype gets one.
    assert ("response", f"{base}/device") not in rows
    for sub, leaf in (("imeiDevice", "imei"), ("simDevice", "iccid")):
        device = rows["response", f"{base}/device[{sub}]"]
        assert (device.min_occurs, device.max_occurs) == (0, None)
        assert rows["response", f"{base}/device[{sub}]/status"].xsd_type == "enum"
        assert rows["response", f"{base}/device[{sub}]/{leaf}"].proposed is None
        updated = rows["response", f"{base}/device[{sub}]/updated"]
        assert updated.nillable
        assert updated.proposed is not None
    # The recursive type stops at the cap: the capped element exists, nothing below it.
    capped = f"{base}/node/node/node"
    assert ("response", capped) in rows
    assert not any(path.startswith(f"{capped}/") for _, path in rows)
    # A recursive fault detail is cut at the cap too, and the cut is reported.
    fault_capped = "Fault/Detail/IWSException/cause/cause"
    assert ("fault", fault_capped) in rows
    assert not any(path.startswith(f"{fault_capped}/") for _, path in rows)
    assert generated.capped == (f"lookup response {capped}", f"* fault {fault_capped}")
    for cut in generated.capped:
        assert f"#   {cut}" in generated.text
    assert rows["fault", "Fault/Detail/IWSException/errorCode"].proposed is not None


def test_an_unsupported_construct_writes_nothing() -> None:
    wsdl = SYNTHETIC.replace(
        b'<xs:element name="label"', b'<xs:attribute name="a"/><xs:element name="label"'
    )
    with pytest.raises(gen.GeneratorError):
        gen.generate({"provisioning": wsdl}, {"provisioning": frozenset({"lookup"})}, "x")


@pytest.mark.parametrize("component", ["import", "include", "redefine", "override"])
def test_a_schema_that_loads_another_file_is_refused(component: str) -> None:
    wsdl = SYNTHETIC.replace(
        b'elementFormDefault="unqualified">',
        f'elementFormDefault="unqualified"><xs:{component} schemaLocation="x.xsd"/>'.encode(),
    )
    with pytest.raises(gen.GeneratorError):
        gen.generate({"provisioning": wsdl}, {"provisioning": frozenset({"lookup"})}, "x")


def test_an_operation_missing_from_the_wsdl_is_refused() -> None:
    with pytest.raises(gen.GeneratorError):
        gen.generate({"provisioning": SYNTHETIC}, {"provisioning": frozenset({"absent"})}, "x")


# ---------------------------------------------------------------- the committed map


@cache
def _regenerated() -> gen.Generated:
    wsdls, source = gen.snapshot()
    return gen.generate(wsdls, gen.allowlists(), source)


def test_the_committed_map_has_not_drifted() -> None:
    assert generated_field_map_text() == _regenerated().text


def test_the_map_covers_exactly_the_recorder_allowlists() -> None:
    generated = _regenerated()
    operations = {e.operation for e in load_generated(generated.text)} - {"*"}
    assert operations == set().union(*gen.allowlists().values())
    assert generated.capped == ()


def test_keep_is_proposed_exactly_where_propose_says() -> None:
    for entry in load_generated(_regenerated().text):
        expected = None if entry.is_complex else propose(entry.xsd_type, entry.xsd_type == "enum")
        assert entry.proposed == expected
        assert entry.treatment.value == "UNCLASSIFIED"


# ---------------------------------------------------------------- engine path match
#
# A schema-valid response is built from the real schema (required elements, plus the ones
# named), validated with libxml2, and masked by the engine with the generated map and an
# override file that keeps every path of the operation: no UNCLASSIFIED, no unknown element.


@cache
def _schema(endpoint: str) -> tuple[gen.Schema, dict[str, gen.Operation], etree.XMLSchema]:
    wsdl = etree.fromstring(gen.snapshot()[0][endpoint], etree.XMLParser(resolve_entities=False))
    schema, operations = gen.read_schema(wsdl), gen.read_operations(wsdl)
    xs = copy.deepcopy(wsdl.find(f"{gen.WSDL}types/{gen.XS}schema"))
    assert xs is not None
    for name, op in operations.items():
        wrapper = etree.SubElement(xs, f"{{{XS}}}element", name=f"{name}Response")
        seq = etree.SubElement(
            etree.SubElement(wrapper, f"{{{XS}}}complexType"), f"{{{XS}}}sequence"
        )
        etree.SubElement(seq, f"{{{XS}}}element", name="response", type=f"tns:{op.response}")
    return schema, operations, etree.XMLSchema(etree.ElementTree(xs))


def _leaf_value(schema: gen.Schema, decl: Element) -> str:
    simple = decl.find(f"{gen.XS}simpleType")
    if simple is None:
        simple = schema.simple.get(gen.local_part(decl.get("type")))
    enum = None if simple is None else simple.find(f"{gen.XS}restriction/{gen.XS}enumeration")
    if enum is not None:
        return enum.get("value", "")
    kind = gen.leaf_type(schema, gen.local_part(decl.get("type")), simple)[0]
    return {"int": "1", "long": "1", "dateTime": "2026-01-01T00:00:00Z"}.get(kind, "x")


def _fill(
    schema: gen.Schema, parent: Element, ctype: Element, path: str, include: dict[str, str]
) -> None:
    for decl, low, _ in gen.content(schema, ctype):
        name = decl.get("name", "")
        child_path = f"{path}/{name}"
        if low == 0 and child_path not in include:
            continue
        child = etree.SubElement(parent, name)
        type_name = gen.local_part(decl.get("type"))
        inline = decl.find(f"{gen.XS}complexType")
        if inline is None and type_name not in schema.complex:
            child.text = _leaf_value(schema, decl)
            continue
        sub = include.get(child_path, "")
        if sub:
            child.set(f"{{{XSI}}}type", f"tns:{sub}")
        target = inline if inline is not None else schema.complex[sub or type_name]
        _fill(schema, child, target, child_path, include)


def _response(endpoint: str, operation: str, include: dict[str, str]) -> Element:
    schema, operations, xsd = _schema(endpoint)
    body = etree.Element(f"{{{IWS}}}{operation}Response", nsmap={"tns": IWS, "xsi": XSI})
    response = etree.SubElement(body, "response")
    response_type = operations[operation].response
    assert response_type is not None
    _fill(schema, response, schema.complex[response_type], "response", include)
    assert xsd.validate(etree.ElementTree(copy.deepcopy(body)))
    return body


def _envelope(body: Element) -> bytes:
    envelope = etree.Element(f"{{{SOAP12}}}Envelope")
    etree.SubElement(envelope, f"{{{SOAP12}}}Body").append(body)
    return etree.tostring(envelope, xml_declaration=True, encoding="UTF-8")


CASES: list[tuple[str, str, dict[str, str]]] = [
    ("provisioning", "getSystemStatus", {}),
    ("reporting", "getSystemStatus", {}),
    (
        "provisioning",
        "accountSearch",
        {"response/subscribers/subscriber": "", "response/subscribers/subscriber/imei": ""},
    ),
    (
        "provisioning",
        "getSubscriberAccount",
        {
            "response/m2mSubscriberAccount": "",
            "response/m2mSubscriberAccount/msisdnb": "deviceImeiImpl",
            "response/m2mSubscriberAccount/msisdnc": "deviceSimImpl",
        },
    ),
    ("provisioning", "getIwsRequests", {"response/iwsLogs/iwsLog": ""}),
]


def _keep_all(operations: set[str]) -> Iterator[str]:
    yield "format: airtimesat-overrides/1\nentries:"
    for entry in load_generated(_regenerated().text):
        if entry.operation in operations:
            yield (
                f'  - {{operation: "{entry.operation}", direction: {entry.direction.value},'
                f' path: "{entry.path}", treatment: KEEP}}'
            )


@pytest.fixture(scope="module")
def kept_map() -> FieldMap:
    overrides = "\n".join(_keep_all({op for _, op, _ in CASES})) + "\n"
    return build_field_map(_regenerated().text, overrides)[0]


@pytest.mark.parametrize(("endpoint", "operation", "include"), CASES)
def test_engine_paths_match_the_generated_map(
    kept_map: FieldMap, vault: Vault, endpoint: str, operation: str, include: dict[str, str]
) -> None:
    data = _envelope(_response(endpoint, operation, include))
    for sub in filter(None, include.values()):
        assert f'xsi:type="tns:{sub}"'.encode() in data
    engine = MaskingEngine(kept_map, vault)
    # Raises on an UNCLASSIFIED path, an unknown element or an unknown xsi:type.
    masked = engine.mask_response(engine.start_call(operation), data)
    assert not masked.fault


def test_a_plan_request_path_matches_the_generated_map(kept_map: FieldMap) -> None:
    request = (
        b"<request><filterType>IMEI</filterType><filterCond>EQUALS</filterCond>"
        b"<filterValue>Text-AAAAAAAA</filterValue><limit>5</limit><startRow>0</startRow></request>"
    )
    assert MaskingEngine(kept_map, None).check_request("accountSearch", request) is None
