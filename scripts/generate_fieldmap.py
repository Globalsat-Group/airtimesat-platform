"""Generate the field map from the SITEST WSDL snapshot (design §4.5, §7.2).

Reads ``gateway/wsdl/sitest/{provisioning,reporting}.wsdl`` with the masker's safe parser (no
network, no entities, no DTD, a size limit) and writes ``gateway/wsdl/fieldmap/generated.yaml``
in the format ``masker.fieldmap.loader.load_generated`` reads. Every path is UNCLASSIFIED;
``proposed: KEEP`` appears exactly where ``masker.fieldmap.model.propose`` says so.

Covered operations are the recorder's read and write allowlists (``recorder.policy.allowlist``),
per endpoint, plus the SOAP 1.2 fault, shared by every operation (``*``). Paths are built as
the masking engine builds them for a real message (RPC/literal, SOAP 1.2):

- request: the plan's ``<request>`` element and its children (the operation wrapper and the
  authentication fields belong to the signer core, design §5.2);
- response: ``<operation>Response/response/...``;
- fault: ``Fault/Code/Value``, ``Fault/Reason/Text``, ``Fault/Detail/<fault element>/...``.

An element whose declared type has subtypes (``complexContent`` extensions) gets one
``name[Subtype]`` path per concrete subtype, as the engine writes an element that carries
``xsi:type``, plus ``name`` if the declared type is concrete. Roots are not expanded: the
signer core and IWS write them with their declared types. Below ``MAX_DEPTH`` element levels
nothing is generated, so the engine fails closed (``UNCLASSIFIED``) on anything deeper; each
place the cap cut is listed as a comment in the output.

The output is deterministic (schema order, no timestamps) and is checked by the drift test.
Usage: ``uv run python scripts/generate_fieldmap.py`` (``make fieldmap``).
"""

import hashlib
import sys
from collections.abc import Iterable, Iterator, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Final

from lxml import etree

from airtimesat_platform.masker.engine import AUTH_FIELDS
from airtimesat_platform.masker.errors import MaskingError
from airtimesat_platform.masker.fieldmap.loader import build_field_map
from airtimesat_platform.masker.fieldmap.model import (
    ANY_OPERATION,
    GENERATED_FORMAT,
    OVERRIDES_FORMAT,
    XSD_TYPES,
    Treatment,
    propose,
)
from airtimesat_platform.masker.xmlsafe import Element, local_name, parse
from airtimesat_platform.recorder.policy.allowlist import READS, WRITE_ENDPOINT, WRITES

REPO_ROOT: Final = Path(__file__).resolve().parent.parent
GATEWAY: Final = REPO_ROOT / "src" / "airtimesat_platform" / "gateway"
WSDL_DIR: Final = GATEWAY / "wsdl" / "sitest"
OUTPUT: Final = GATEWAY / "wsdl" / "fieldmap" / "generated.yaml"
ENDPOINTS: Final = ("provisioning", "reporting")
MAX_WSDL_BYTES: Final = 4 * 1024 * 1024
# Element levels below a root. The deepest allowlisted path in the snapshot is far above it;
# only recursive types reach it.
MAX_DEPTH: Final = 12
XS: Final = "{http://www.w3.org/2001/XMLSchema}"
WSDL: Final = "{http://schemas.xmlsoap.org/wsdl/}"
UNBOUNDED: Final = -1


class GeneratorError(Exception):
    """The WSDL uses a construct the generator does not handle; nothing is written."""


@dataclass(frozen=True, slots=True)
class Row:
    """One generated path."""

    operation: str
    direction: str
    path: str
    xsd_type: str
    min_occurs: int = 1
    max_occurs: int = 1
    nillable: bool = False
    enum: bool = False


@dataclass(slots=True)
class Schema:
    """The named types of one embedded ``xs:schema``."""

    complex: dict[str, Element] = field(default_factory=dict[str, Element])
    simple: dict[str, Element] = field(default_factory=dict[str, Element])
    elements: dict[str, Element] = field(default_factory=dict[str, Element])
    subtypes: dict[str, list[str]] = field(default_factory=dict[str, list[str]])


@dataclass(frozen=True, slots=True)
class Operation:
    """An operation's part types and fault element names, from ``wsdl:portType``."""

    request: str | None
    response: str | None
    faults: tuple[str, ...]


@dataclass(slots=True)
class Walk:
    """The rows of one root and the places the depth cap cut."""

    schema: Schema
    operation: str
    direction: str
    rows: dict[str, Row] = field(default_factory=dict[str, Row])
    capped: list[str] = field(default_factory=list[str])


def local_part(qname: str | None) -> str:
    """Return the local part of a QName (``tns:x`` or ``x``)."""
    return (qname or "").rpartition(":")[2]


def _occurs(element: Element) -> tuple[int, int]:
    high = element.get("maxOccurs", "1")
    return int(element.get("minOccurs", "1")), UNBOUNDED if high == "unbounded" else int(high)


def _times(a: int, b: int) -> int:
    return UNBOUNDED if UNBOUNDED in (a, b) else a * b


def read_schema(wsdl: Element) -> Schema:
    """Index the named types and global elements of the WSDL's one embedded schema."""
    schemas = wsdl.findall(f"{WSDL}types/{XS}schema")
    external = ("import", "include", "redefine", "override")
    if len(schemas) != 1 or any(schemas[0].find(f"{XS}{n}") is not None for n in external):
        raise GeneratorError("expected one embedded xs:schema without imports or includes")
    schema = Schema()
    for node in schemas[0]:
        name = node.get("name", "")
        if node.tag == f"{XS}complexType":
            schema.complex[name] = node
            extension = node.find(f"{XS}complexContent/{XS}extension")
            if extension is not None:
                schema.subtypes.setdefault(local_part(extension.get("base")), []).append(name)
        elif node.tag == f"{XS}simpleType":
            schema.simple[name] = node
        elif node.tag == f"{XS}element":
            schema.elements[name] = node
    return schema


def read_operations(wsdl: Element) -> dict[str, Operation]:
    """Return each portType operation's request and response part types and fault elements."""
    messages = {m.get("name", ""): m for m in wsdl.iter(f"{WSDL}message")}

    def part_type(message: str | None, name: str) -> str | None:
        node = messages.get(local_part(message))
        part = None if node is None else node.find(f"{WSDL}part[@name='{name}']")
        return None if part is None else local_part(part.get("type"))

    def fault_element(message: str | None) -> str:
        part = messages[local_part(message)].find(f"{WSDL}part")
        if part is None or part.get("element") is None:
            raise GeneratorError("fault message without an element part")
        return local_part(part.get("element"))

    operations: dict[str, Operation] = {}
    for port_type in wsdl.iter(f"{WSDL}portType"):
        for op in port_type.iter(f"{WSDL}operation"):
            node_in, node_out = op.find(f"{WSDL}input"), op.find(f"{WSDL}output")
            operations[op.get("name", "")] = Operation(
                part_type(None if node_in is None else node_in.get("message"), "request"),
                part_type(None if node_out is None else node_out.get("message"), "response"),
                tuple(fault_element(f.get("message")) for f in op.iter(f"{WSDL}fault")),
            )
    return operations


def concrete_subtypes(schema: Schema, type_name: str) -> list[str]:
    """Return every concrete type derived from ``type_name`` by extension, in schema order."""
    found: list[str] = []
    for sub in schema.subtypes.get(type_name, []):
        if schema.complex[sub].get("abstract") != "true":
            found.append(sub)
        found.extend(concrete_subtypes(schema, sub))
    return found


def _particles(node: Element, low: int, high: int) -> Iterator[tuple[Element, int, int]]:
    """Yield the element declarations of a model group with their effective occurrences."""
    for child in node:
        if child.tag in (f"{XS}attribute", f"{XS}attributeGroup", f"{XS}anyAttribute", f"{XS}any"):
            raise GeneratorError(f"unsupported {local_name(child)}")
        if child.tag == f"{XS}element":
            c_low, c_high = _occurs(child)
            # One branch of a choice: any other branch may stand in its place.
            if node.tag == f"{XS}choice" and len(node) > 1:
                c_low = 0
            yield child, c_low * low, _times(c_high, high)
        elif child.tag in (f"{XS}sequence", f"{XS}choice", f"{XS}all"):
            g_low, g_high = _occurs(child)
            if node.tag == f"{XS}choice" and len(node) > 1:
                g_low = 0
            yield from _particles(child, g_low * low, _times(g_high, high))
        elif child.tag != f"{XS}annotation":
            raise GeneratorError(f"unsupported {local_name(child)}")


def content(schema: Schema, ctype: Element) -> Iterator[tuple[Element, int, int]]:
    """Yield a complex type's element declarations: base content first for an extension."""
    if ctype.find(f"{XS}simpleContent") is not None:
        raise GeneratorError("unsupported simpleContent")
    complex_content = ctype.find(f"{XS}complexContent")
    if complex_content is None:
        yield from _particles(ctype, 1, 1)
        return
    extension = complex_content.find(f"{XS}extension")
    if extension is not None:
        base = local_part(extension.get("base"))
        if base not in schema.complex:
            raise GeneratorError("extension of an unknown base type")
        yield from content(schema, schema.complex[base])
        yield from _particles(extension, 1, 1)
        return
    restriction = complex_content.find(f"{XS}restriction")
    if restriction is None:
        raise GeneratorError("complexContent without extension or restriction")
    yield from _particles(restriction, 1, 1)


def leaf_type(schema: Schema, type_name: str | None, simple: Element | None) -> tuple[str, bool]:
    """Return the field-map type of a simple type and whether it is an enumeration."""
    if simple is None and type_name in schema.simple:
        simple = schema.simple[type_name]
    if simple is None:
        if type_name not in XSD_TYPES or type_name in ("enum", "complex"):
            raise GeneratorError("unsupported built-in type")
        return type_name, False
    restriction = simple.find(f"{XS}restriction")
    if restriction is None:
        raise GeneratorError("unsupported simpleType (list or union)")
    if restriction.find(f"{XS}enumeration") is not None:
        return "enum", True
    return leaf_type(
        schema, local_part(restriction.get("base")), restriction.find(f"{XS}simpleType")
    )


def _add(walk: Walk, row: Row) -> None:
    existing = walk.rows.get(row.path)
    if existing is not None and existing != row:
        raise GeneratorError(f"conflicting declarations of one path in {walk.operation}")
    walk.rows[row.path] = row


def walk_element(
    walk: Walk, decl: Element, parent: str, low: int, high: int, depth: int, root: bool = False
) -> None:
    """Add the rows of one element declaration and, below the cap, of its content."""
    name = decl.get("name", "")
    nillable = decl.get("nillable") == "true"
    type_name = local_part(decl.get("type")) if decl.get("type") else None
    inline = decl.find(f"{XS}complexType")
    if type_name is None and inline is None and decl.find(f"{XS}simpleType") is None:
        raise GeneratorError("element without a type")
    path = f"{parent}/{name}" if parent else name
    if inline is None and type_name not in walk.schema.complex:
        xsd_type, enum = leaf_type(walk.schema, type_name, decl.find(f"{XS}simpleType"))
        _add(walk, Row(walk.operation, walk.direction, path, xsd_type, low, high, nillable, enum))
        return
    variants: list[tuple[str, Element]] = []
    if inline is not None:
        variants.append((path, inline))
    else:
        declared = walk.schema.complex[type_name or ""]
        if declared.get("abstract") != "true":
            variants.append((path, declared))
        if not root:  # a message part keeps its declared type
            for sub in concrete_subtypes(walk.schema, type_name or ""):
                variants.append((f"{path}[{sub}]", walk.schema.complex[sub]))
    for variant_path, ctype in variants:
        _add(
            walk, Row(walk.operation, walk.direction, variant_path, "complex", low, high, nillable)
        )
        if depth >= MAX_DEPTH:
            walk.capped.append(f"{walk.operation} {walk.direction} {variant_path}")
            continue
        for child, c_low, c_high in content(walk.schema, ctype):
            walk_element(walk, child, variant_path, c_low, c_high, depth + 1)


def _part(name: str, type_name: str) -> Element:
    """Declare a message part, which RPC/literal writes as an unqualified element."""
    return etree.Element(f"{XS}element", name=name, type=f"tns:{type_name}")


def operation_rows(schema: Schema, name: str, op: Operation) -> Walk:
    """Return the request and response rows of one operation."""
    walk = Walk(schema, name, "request")
    if op.request is not None:
        walk_element(walk, _part("request", op.request), "", 1, 1, 0, root=True)
    # The signer core adds the authentication fields; a plan never carries them (design §5.2).
    walk.rows = {p: r for p, r in walk.rows.items() if p.partition("/")[2] not in AUTH_FIELDS}
    if op.response is None:
        raise GeneratorError(f"{name} has no response part")
    response = Walk(schema, name, "response", capped=walk.capped)
    wrapper = f"{name}Response"
    response.rows[wrapper] = Row(name, "response", wrapper, "complex")
    walk_element(response, _part("response", op.response), wrapper, 1, 1, 1, root=True)
    walk.rows.update(response.rows)
    return walk


# The SOAP 1.2 fault (Code, Reason, Detail); Node and Role are not expected from IWS.
_FAULT: Final = (
    Row(ANY_OPERATION, "fault", "Fault", "complex"),
    Row(ANY_OPERATION, "fault", "Fault/Code", "complex"),
    Row(ANY_OPERATION, "fault", "Fault/Code/Value", "string"),
    Row(ANY_OPERATION, "fault", "Fault/Code/Subcode", "complex", 0),
    Row(ANY_OPERATION, "fault", "Fault/Code/Subcode/Value", "string"),
    Row(ANY_OPERATION, "fault", "Fault/Reason", "complex"),
    Row(ANY_OPERATION, "fault", "Fault/Reason/Text", "string", 1, UNBOUNDED),
    Row(ANY_OPERATION, "fault", "Fault/Detail", "complex", 0),
)


def fault_rows(schema: Schema, elements: Iterable[str]) -> Walk:
    """Return the SOAP 1.2 fault rows, with the WSDL's fault elements under ``Detail``."""
    walk = Walk(schema, ANY_OPERATION, "fault", rows={r.path: r for r in _FAULT})
    for element in elements:
        walk_element(walk, schema.elements[element], "Fault/Detail", 0, 1, 2)
    return walk


def _merge(rows: dict[tuple[str, str, str], Row], walk: Walk) -> None:
    for row in walk.rows.values():
        key = (row.operation, row.direction, row.path)
        if rows.setdefault(key, row) != row:
            raise GeneratorError(f"{row.operation} differs between the endpoints")


@dataclass(frozen=True, slots=True)
class Generated:
    """The rendered map and the depth-cap cuts."""

    text: str
    capped: tuple[str, ...]


def allowlists() -> dict[str, frozenset[str]]:
    """Return the operations the recorder may ever send, per endpoint."""
    return {
        endpoint: reads | (WRITES if endpoint == WRITE_ENDPOINT else frozenset())
        for endpoint, reads in READS.items()
    }


def snapshot() -> tuple[dict[str, bytes], str]:
    """Read both WSDL files; name them with their SHA-256, checked against ``SHA256SUMS``."""
    sums: dict[str, str] = {}
    for line in (WSDL_DIR / "SHA256SUMS").read_text(encoding="utf-8").splitlines():
        digest, name = line.split()
        sums[name] = digest
    wsdls: dict[str, bytes] = {}
    for endpoint in ENDPOINTS:
        data = wsdls[endpoint] = (WSDL_DIR / f"{endpoint}.wsdl").read_bytes()
        if hashlib.sha256(data).hexdigest() != sums.get(f"{endpoint}.wsdl"):
            raise GeneratorError(f"{endpoint}.wsdl does not match SHA256SUMS")
    return wsdls, "; ".join(f"{e}.wsdl sha256:{sums[f'{e}.wsdl']}" for e in ENDPOINTS)


def _render(row: Row) -> str:
    items = [
        f'operation: "{row.operation}"',
        f"direction: {row.direction}",
        f'path: "{row.path}"',
        f"xsd_type: {row.xsd_type}",
    ]
    if row.min_occurs != 1:
        items.append(f"min_occurs: {row.min_occurs}")
    if row.max_occurs != 1:
        items.append(
            f"max_occurs: {'unbounded' if row.max_occurs == UNBOUNDED else row.max_occurs}"
        )
    if row.nillable:
        items.append("nillable: true")
    if row.xsd_type != "complex" and propose(row.xsd_type, row.enum) is Treatment.KEEP:
        items.append("proposed: KEEP")
    return "  - {" + ", ".join(items) + "}"


def generate(
    wsdls: Mapping[str, bytes], operations: Mapping[str, frozenset[str]], source: str
) -> Generated:
    """Build the field map of ``operations`` (per endpoint) from the endpoints' WSDL bytes."""
    rows: dict[tuple[str, str, str], Row] = {}
    faults: dict[tuple[str, str, str], Row] = {}
    capped: list[str] = []
    for endpoint, wanted in operations.items():
        wsdl = parse(wsdls[endpoint], max_bytes=MAX_WSDL_BYTES, request=False, error=MaskingError)
        schema, declared = read_schema(wsdl), read_operations(wsdl)
        if wanted - declared.keys():
            raise GeneratorError(f"not in {endpoint}.wsdl: {sorted(wanted - declared.keys())}")
        fault_elements: set[str] = set()
        for name in sorted(wanted):
            walk = operation_rows(schema, name, declared[name])
            _merge(rows, walk)
            capped.extend(c for c in walk.capped if c not in capped)
            fault_elements.update(declared[name].faults)
        fault_walk = fault_rows(schema, sorted(fault_elements))
        _merge(faults, fault_walk)
        capped.extend(c for c in fault_walk.capped if c not in capped)
    ordered = sorted(rows.values(), key=lambda r: (r.operation, r.direction))
    lines = [
        "# GENERATED by scripts/generate_fieldmap.py from the SITEST WSDL snapshot: do not edit.",
        "# Regenerate with `make fieldmap`; tests/test_generate_fieldmap.py checks for drift.",
        "# Every path is UNCLASSIFIED. A proposal has no effect until a reviewer copies it into",
        "# masker/fieldmap/overrides.yaml (design s2-recorder-masker §4.5).",
        f"# Depth cap: {MAX_DEPTH} element levels below a root. Nothing is generated below:",
        *(f"#   {c}" for c in capped),
        f"format: {GENERATED_FORMAT}",
        f'source: "{source}"',
        "paths:",
        *(_render(r) for r in [*ordered, *faults.values()]),
    ]
    text = "\n".join(lines) + "\n"
    build_field_map(text, f"format: {OVERRIDES_FORMAT}\n")  # the map must load
    return Generated(text, tuple(capped))


def main() -> int:
    """Write the generated map; print the counts."""
    wsdls, source = snapshot()
    operations = allowlists()
    generated = generate(wsdls, operations, source)
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT.write_text(generated.text, encoding="utf-8")
    paths = generated.text.count("\n  - {")
    print(f"wrote {OUTPUT.relative_to(REPO_ROOT)}: {paths} paths")
    for endpoint, ops in operations.items():
        print(f"  {endpoint}: {len(ops)} operations")
    print(f"  depth cap hit at {len(generated.capped)} places")
    return 0


if __name__ == "__main__":
    sys.exit(main())
