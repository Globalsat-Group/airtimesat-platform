"""The field map: every element path of every allowed operation, classified (design §4.5).

Two files make it:

- The **generated** map lists every path read from the WSDL, each one UNCLASSIFIED. It may
  carry a ``proposed: KEEP`` hint for booleans, enumerations, dates and numeric
  quantities, which has no effect until a reviewer copies it into the overrides. It lives
  under ``gateway/wsdl/fieldmap/`` (``CLAUDE.md``: WSDL-derived files stay in the gateway)
  and the recorder passes its text to the engine.
- The **overrides** file (``masker/fieldmap/overrides.yaml``) is the only place a
  treatment is assigned, KEEP included. Every override must name a generated path.

A path is the chain of element local names from the root of the request, the response
body element or the SOAP fault. An element that carries ``xsi:type`` is written
``name[type]``, so each subtype has its own paths: the key is (operation, direction, path),
which carries the (operation, ``xsi:type``, path) key of the design.

Whatever is not classified is UNCLASSIFIED, and an UNCLASSIFIED path blocks at runtime.
"""

from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Final

from airtimesat_platform.masker.errors import FieldMapError
from airtimesat_platform.masker.tokenize.surrogates import (
    ONE_WAY_SPECS,
    T_NUM_TYPES,
    T_STR_LABELS,
)

GENERATED_FORMAT: Final = "airtimesat-fieldmap/1"
OVERRIDES_FORMAT: Final = "airtimesat-overrides/1"
# Faults are shared by every operation of an endpoint.
ANY_OPERATION: Final = "*"


class Treatment(StrEnum):
    """Treatment codes of design §4.1, plus UNCLASSIFIED, KEEP and TYPED (§3.2)."""

    UNCLASSIFIED = "UNCLASSIFIED"
    KEEP = "KEEP"
    T_NUM = "T-NUM"
    T_STR = "T-STR"
    T_IP = "T-IP"
    T_HOST = "T-HOST"
    T_EMAIL = "T-EMAIL"
    P_ONE = "P-ONE"
    C = "C"
    G = "G"
    D = "D"
    F = "F"
    N = "N"
    # The class depends on a sibling enum (design §3.2).
    TYPED = "TYPED"


REVERSIBLE: Final = frozenset(
    {Treatment.T_NUM, Treatment.T_STR, Treatment.T_IP, Treatment.T_HOST, Treatment.T_EMAIL}
)
IDENTIFIER_TREATMENTS: Final = REVERSIBLE | {Treatment.P_ONE, Treatment.C, Treatment.TYPED}


class Direction(StrEnum):
    """Which message a path belongs to."""

    REQUEST = "request"
    RESPONSE = "response"
    FAULT = "fault"


NUMERIC_TYPES: Final = frozenset(
    {
        "int",
        "integer",
        "long",
        "short",
        "byte",
        "decimal",
        "double",
        "float",
        "nonNegativeInteger",
        "positiveInteger",
        "negativeInteger",
        "nonPositiveInteger",
        "unsignedInt",
        "unsignedLong",
        "unsignedShort",
        "unsignedByte",
    }
)
DATE_TYPES: Final = frozenset({"date", "dateTime", "time", "gYear", "duration"})
STRING_TYPES: Final = frozenset({"string", "normalizedString", "token", "enum"})
OTHER_TYPES: Final = frozenset({"boolean", "base64Binary", "complex"})
XSD_TYPES: Final = NUMERIC_TYPES | DATE_TYPES | STRING_TYPES | OTHER_TYPES
# Proposals the generator may make (design §4.5): booleans, enumerations, dates and
# numeric quantities; never strings or integers, which may be IDs.
PROPOSABLE_TYPES: Final = frozenset({"boolean", "enum", "decimal", "double", "float"}) | DATE_TYPES


@dataclass(frozen=True, slots=True)
class TypedRule:
    """A field typed by a sibling enum: sibling value -> (treatment, type or label)."""

    sibling: str
    values: Mapping[str, tuple[Treatment, str | None]]


@dataclass(frozen=True, slots=True)
class EmbeddedRule:
    """An embedded XML payload, masked with the map of the operation it names (§4.4)."""

    operation_from: str
    direction: Direction


@dataclass(frozen=True, slots=True)
class FieldEntry:
    """One classified path."""

    operation: str
    direction: Direction
    path: str
    xsd_type: str
    treatment: Treatment = Treatment.UNCLASSIFIED
    id_type: str | None = None
    nillable: bool = False
    min_occurs: int = 1
    max_occurs: int | None = 1
    sentinel: str | None = None
    operational: bool = False
    typed: TypedRule | None = None
    embedded: EmbeddedRule | None = None
    literals: frozenset[str] = field(default_factory=frozenset[str])
    proposed: Treatment | None = None

    @property
    def is_numeric(self) -> bool:
        """Return whether the XSD type is numeric."""
        return self.xsd_type in NUMERIC_TYPES

    @property
    def is_string(self) -> bool:
        """Return whether the XSD type is a string type."""
        return self.xsd_type in STRING_TYPES

    @property
    def is_complex(self) -> bool:
        """Return whether the element has element content."""
        return self.xsd_type == "complex"

    def key(self) -> tuple[str, Direction, str]:
        """Return the lookup key."""
        return (self.operation, self.direction, self.path)


def sentinel_valid(xsd_type: str, value: str) -> bool:
    """Return whether a D sentinel is valid for its XSD type."""
    if xsd_type in NUMERIC_TYPES:
        try:
            float(value)
        except ValueError:
            return False
        return value.strip() == value and value != ""
    if xsd_type == "boolean":
        return value in ("true", "false", "0", "1")
    if xsd_type in DATE_TYPES:
        return value[:4].isdigit()
    return False


def _check_id_type(entry: FieldEntry) -> None:
    t, kind = entry.id_type, entry.treatment
    where = f"{entry.operation}:{entry.path}"
    if kind is Treatment.T_NUM and t not in T_NUM_TYPES:
        raise FieldMapError("FIELDMAP_BAD_TYPE", path=where)
    if kind is Treatment.T_STR and t not in T_STR_LABELS:
        raise FieldMapError("FIELDMAP_BAD_TYPE", path=where)
    if kind is Treatment.P_ONE and t not in ONE_WAY_SPECS:
        raise FieldMapError("FIELDMAP_BAD_TYPE", path=where)
    if kind is Treatment.C and not (t and t.replace("-", "").isalnum()):
        raise FieldMapError("FIELDMAP_BAD_TYPE", path=where)


def validate_entry(entry: FieldEntry) -> None:
    """Refuse an entry whose treatment cannot produce type-valid output (design §4.1)."""
    where = f"{entry.operation}:{entry.path}"
    kind = entry.treatment
    if entry.xsd_type not in XSD_TYPES:
        raise FieldMapError("FIELDMAP_BAD_XSD_TYPE", path=where)
    if entry.is_complex and kind not in (Treatment.KEEP, Treatment.D, Treatment.UNCLASSIFIED):
        raise FieldMapError("FIELDMAP_COMPLEX_TREATMENT", path=where)
    if kind is Treatment.G and not entry.is_numeric:
        raise FieldMapError("FIELDMAP_G_NOT_NUMERIC", path=where)
    if kind is Treatment.N and entry.embedded is None:
        raise FieldMapError("FIELDMAP_N_WITHOUT_RULE", path=where)
    if kind is Treatment.TYPED and entry.typed is None:
        raise FieldMapError("FIELDMAP_TYPED_WITHOUT_RULE", path=where)
    if kind is Treatment.D and not (entry.is_string or entry.is_complex):
        needs_sentinel = not entry.nillable and entry.min_occurs > 0
        if needs_sentinel and (
            entry.sentinel is None or not sentinel_valid(entry.xsd_type, entry.sentinel)
        ):
            raise FieldMapError("FIELDMAP_D_NEEDS_SENTINEL", path=where)
    if kind is Treatment.D and entry.is_complex and not entry.nillable and entry.min_occurs > 0:
        raise FieldMapError("FIELDMAP_D_REQUIRED_COMPLEX", path=where)
    if entry.literals and kind is not Treatment.C:
        raise FieldMapError("FIELDMAP_LITERALS_ONLY_FOR_C", path=where)
    if entry.operational and kind is not Treatment.KEEP:
        raise FieldMapError("FIELDMAP_OPERATIONAL_ONLY_FOR_KEEP", path=where)
    if entry.operation == ANY_OPERATION and entry.direction is not Direction.FAULT:
        raise FieldMapError("FIELDMAP_WILDCARD_OPERATION", path=where)
    _check_id_type(entry)
    if entry.typed is not None:
        for target, label in entry.typed.values.values():
            probe = FieldEntry(
                entry.operation, entry.direction, entry.path, entry.xsd_type, target, label
            )
            if target not in REVERSIBLE | {Treatment.KEEP}:
                raise FieldMapError("FIELDMAP_TYPED_TARGET", path=where)
            _check_id_type(probe)


@dataclass(frozen=True)
class FieldMap:
    """The merged, validated field map."""

    entries: Mapping[tuple[str, Direction, str], FieldEntry]
    source: str = ""

    def lookup(self, operation: str, direction: Direction, path: str) -> FieldEntry | None:
        """Return the entry for a path, or ``None`` if the path is unknown."""
        entry = self.entries.get((operation, direction, path))
        if entry is None and direction is Direction.FAULT:
            entry = self.entries.get((ANY_OPERATION, direction, path))
        return entry

    def operations(self) -> frozenset[str]:
        """Return the operations the map covers (faults excluded)."""
        return frozenset(op for op, _, _ in self.entries if op != ANY_OPERATION)

    def unclassified(self, operations: Iterable[str] | None = None) -> list[FieldEntry]:
        """Return the UNCLASSIFIED entries of the given operations (all if ``None``).

        CI fails on any of them in an allowed method (design §4.5).
        """
        wanted = None if operations is None else set(operations) | {ANY_OPERATION}
        return [
            e
            for e in self.entries.values()
            if e.treatment is Treatment.UNCLASSIFIED and (wanted is None or e.operation in wanted)
        ]

    def keep_proposals(self) -> list[FieldEntry]:
        """Return the generator's KEEP proposals not yet adopted in the overrides."""
        return [
            e
            for e in self.entries.values()
            if e.proposed is Treatment.KEEP and e.treatment is Treatment.UNCLASSIFIED
        ]


def propose(xsd_type: str, is_enum: bool = False) -> Treatment | None:
    """Return the generator's proposal for a leaf type (KEEP or nothing).

    KEEP for booleans, enumerations, dates and decimal quantities. Never for strings or
    integers: the CTO classifies those one by one (design §4.5).
    """
    if is_enum or xsd_type in PROPOSABLE_TYPES:
        return Treatment.KEEP
    return None
