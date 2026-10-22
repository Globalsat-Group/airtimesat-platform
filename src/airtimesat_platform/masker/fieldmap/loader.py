"""Load and merge the generated field map and the reviewed overrides (design §4.5).

Both files are strict YAML with a fixed schema; an unknown key, a duplicate path, an
override for a path the generated map does not have, or an entry that cannot produce
type-valid output refuses the whole map.
"""

import re
from collections.abc import Mapping
from dataclasses import replace
from importlib import resources
from typing import Final, cast

from airtimesat_platform.masker.errors import FieldMapError
from airtimesat_platform.masker.fieldmap.model import (
    GENERATED_FORMAT,
    OVERRIDES_FORMAT,
    Direction,
    EmbeddedRule,
    FieldEntry,
    FieldMap,
    Treatment,
    TypedRule,
    validate_entry,
)
from airtimesat_platform.masker.fieldmap.strict_yaml import load_strict
from airtimesat_platform.masker.freetext import Template

_NAME: Final = r"[A-Za-z_][A-Za-z0-9_.\-]{0,127}"
# The generated map of the SITEST snapshot is about 2.3 MB; plans and overrides keep the
# strict loader's default limit.
MAX_GENERATED_BYTES: Final = 4 * 1024 * 1024
_PATH: Final = re.compile(rf"{_NAME}(?:\[{_NAME}\])?(?:/{_NAME}(?:\[{_NAME}\])?)*")

_GENERATED_KEYS: Final = frozenset(
    {
        "operation",
        "direction",
        "path",
        "xsd_type",
        "nillable",
        "min_occurs",
        "max_occurs",
        "proposed",
    }
)
_OVERRIDE_KEYS: Final = frozenset(
    {
        "operation",
        "direction",
        "path",
        "treatment",
        "type",
        "sentinel",
        "operational",
        "typed_by",
        "embedded",
        "literals",
        "allow_nil",
        "reason",
    }
)


def _mapping(value: object, where: str) -> dict[str, object]:
    if not isinstance(value, dict):
        raise FieldMapError("FIELDMAP_SCHEMA", path=where)
    return cast(dict[str, object], value)


def _list(value: object, where: str) -> list[object]:
    if not isinstance(value, list):
        raise FieldMapError("FIELDMAP_SCHEMA", path=where)
    return cast(list[object], value)


def _str(value: object, where: str) -> str:
    if not isinstance(value, str) or not value:
        raise FieldMapError("FIELDMAP_SCHEMA", path=where)
    return value


def _bool(value: object, where: str) -> bool:
    if not isinstance(value, bool):
        raise FieldMapError("FIELDMAP_SCHEMA", path=where)
    return value


def _int(value: object, where: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise FieldMapError("FIELDMAP_SCHEMA", path=where)
    return value


def _keys(item: dict[str, object], allowed: frozenset[str], required: set[str], where: str) -> None:
    if not set(item) <= allowed or not required <= set(item):
        raise FieldMapError("FIELDMAP_SCHEMA", path=where)


def _path(item: dict[str, object], where: str) -> str:
    path = _str(item["path"], where)
    if not _PATH.fullmatch(path):
        raise FieldMapError("FIELDMAP_BAD_PATH", path=where)
    return path


def _direction(value: object, where: str) -> Direction:
    try:
        return Direction(_str(value, where))
    except ValueError:
        raise FieldMapError("FIELDMAP_SCHEMA", path=where) from None


def _treatment(value: object, where: str) -> Treatment:
    try:
        return Treatment(_str(value, where))
    except ValueError:
        raise FieldMapError("FIELDMAP_BAD_TREATMENT", path=where) from None


def _target(value: object, where: str) -> tuple[Treatment, str | None]:
    text = _str(value, where)
    name, _, label = text.partition(":")
    return _treatment(name, where), (label or None)


def load_generated(text: str) -> list[FieldEntry]:
    """Parse the generated map: every path UNCLASSIFIED, with optional KEEP proposals."""
    doc = _mapping(load_strict(text, max_bytes=MAX_GENERATED_BYTES), "generated")
    _keys(doc, frozenset({"format", "source", "paths"}), {"format", "paths"}, "generated")
    if doc["format"] != GENERATED_FORMAT:
        raise FieldMapError("FIELDMAP_FORMAT", path="generated")
    entries: list[FieldEntry] = []
    for n, raw in enumerate(_list(doc["paths"], "generated.paths")):
        where = f"generated.paths[{n}]"
        item = _mapping(raw, where)
        _keys(item, _GENERATED_KEYS, {"operation", "direction", "path", "xsd_type"}, where)
        max_raw = item.get("max_occurs", 1)
        proposed = item.get("proposed")
        entry = FieldEntry(
            operation=_str(item["operation"], where),
            direction=_direction(item["direction"], where),
            path=_path(item, where),
            xsd_type=_str(item["xsd_type"], where),
            nillable=_bool(item.get("nillable", False), where),
            min_occurs=_int(item.get("min_occurs", 1), where),
            max_occurs=None if max_raw == "unbounded" else _int(max_raw, where),
            proposed=None if proposed is None else _treatment(proposed, where),
        )
        if entry.proposed not in (None, Treatment.KEEP):
            raise FieldMapError("FIELDMAP_BAD_PROPOSAL", path=where)
        validate_entry(entry)
        entries.append(entry)
    return entries


def _typed(raw: object, where: str) -> TypedRule:
    item = _mapping(raw, where)
    _keys(item, frozenset({"sibling", "values"}), {"sibling", "values"}, where)
    values = {_str(k, where): _target(v, where) for k, v in _mapping(item["values"], where).items()}
    if not values:
        raise FieldMapError("FIELDMAP_SCHEMA", path=where)
    return TypedRule(_str(item["sibling"], where), values)


def _embedded(raw: object, where: str) -> EmbeddedRule:
    item = _mapping(raw, where)
    _keys(
        item,
        frozenset({"format", "operation_from", "direction"}),
        {"operation_from", "direction"},
        where,
    )
    if item.get("format", "xml") != "xml":
        # CSV rows need the report's column map (design §4.4, §13 #8): refused for now.
        raise FieldMapError("FIELDMAP_N_FORMAT_NOT_SUPPORTED", path=where)
    direction = _direction(item.get("direction"), where)
    if direction is Direction.FAULT:
        raise FieldMapError("FIELDMAP_SCHEMA", path=where)
    return EmbeddedRule(_str(item.get("operation_from"), where), direction)


def _apply_override(base: FieldEntry, item: dict[str, object], where: str) -> FieldEntry:
    treatment = _treatment(item["treatment"], where)
    if treatment is Treatment.UNCLASSIFIED:
        raise FieldMapError("FIELDMAP_BAD_TREATMENT", path=where)
    literals_raw = item.get("literals", [])
    allow_nil = _bool(item.get("allow_nil", False), where)
    # IWS writes a null field of its fault beans as xsi:nil, which the WSDL does not allow:
    # an override may accept nil on an optional fault leaf only. A nil element has no value.
    if allow_nil and (base.direction is not Direction.FAULT or base.min_occurs or base.is_complex):
        raise FieldMapError("FIELDMAP_BAD_ALLOW_NIL", path=where)
    entry = replace(
        base,
        treatment=treatment,
        nillable=base.nillable or allow_nil,
        id_type=None if "type" not in item else _str(item["type"], where),
        sentinel=None if "sentinel" not in item else _str(item["sentinel"], where),
        operational=_bool(item.get("operational", False), where),
        typed=None if "typed_by" not in item else _typed(item["typed_by"], where),
        embedded=None if "embedded" not in item else _embedded(item["embedded"], where),
        literals=frozenset(_str(v, where) for v in _list(literals_raw, where)),
    )
    validate_entry(entry)
    return entry


def load_overrides(text: str) -> tuple[list[dict[str, object]], list[Template]]:
    """Parse the overrides file: its entries (checked when merged) and its templates."""
    doc = _mapping(load_strict(text), "overrides")
    _keys(doc, frozenset({"format", "entries", "templates"}), {"format"}, "overrides")
    if doc["format"] != OVERRIDES_FORMAT:
        raise FieldMapError("FIELDMAP_FORMAT", path="overrides")
    entries: list[dict[str, object]] = []
    for n, raw in enumerate(_list(doc.get("entries") or [], "overrides.entries")):
        where = f"overrides.entries[{n}]"
        item = _mapping(raw, where)
        _keys(item, _OVERRIDE_KEYS, {"operation", "direction", "path", "treatment"}, where)
        entries.append(item)
    templates: list[Template] = []
    seen_ids: set[str] = set()
    for n, raw in enumerate(_list(doc.get("templates") or [], "overrides.templates")):
        where = f"overrides.templates[{n}]"
        item = _mapping(raw, where)
        _keys(item, frozenset({"id", "text"}), {"id", "text"}, where)
        template_id = _str(item["id"], where)
        if template_id in seen_ids:
            raise FieldMapError("TEMPLATE_DUPLICATE_ID", path=where)
        seen_ids.add(template_id)
        templates.append(Template.compile(template_id, _str(item["text"], where)))
    return entries, templates


def build_field_map(generated_text: str, overrides_text: str) -> tuple[FieldMap, list[Template]]:
    """Merge the generated map with the overrides into a validated ``FieldMap``."""
    merged: dict[tuple[str, Direction, str], FieldEntry] = {}
    for entry in load_generated(generated_text):
        if entry.key() in merged:
            raise FieldMapError("FIELDMAP_DUPLICATE_PATH", path=f"{entry.operation}:{entry.path}")
        merged[entry.key()] = entry
    items, templates = load_overrides(overrides_text)
    overridden: set[tuple[str, Direction, str]] = set()
    for n, item in enumerate(items):
        where = f"overrides.entries[{n}]"
        key = (
            _str(item["operation"], where),
            _direction(item["direction"], where),
            _path(item, where),
        )
        if key in overridden:
            raise FieldMapError("FIELDMAP_DUPLICATE_PATH", path=where)
        overridden.add(key)
        base = merged.get(key)
        if base is None:
            raise FieldMapError("OVERRIDE_UNKNOWN_PATH", path=where)
        merged[key] = _apply_override(base, item, where)
    _check_siblings(merged)
    return FieldMap(merged), templates


def _check_siblings(entries: Mapping[tuple[str, Direction, str], FieldEntry]) -> None:
    """Require a TYPED field's sibling and an N field's operation sibling to be KEEP."""
    for (operation, direction, path), entry in entries.items():
        sibling = None
        if entry.typed is not None:
            sibling = entry.typed.sibling
        elif entry.embedded is not None:
            sibling = entry.embedded.operation_from
        if sibling is None:
            continue
        parent = path.rpartition("/")[0]
        sibling_path = f"{parent}/{sibling}" if parent else sibling
        sibling_entry = entries.get((operation, direction, sibling_path))
        if sibling_entry is None or sibling_entry.treatment is not Treatment.KEEP:
            raise FieldMapError("FIELDMAP_SIBLING_NOT_KEPT", path=f"{operation}:{path}")


def packaged_overrides() -> str:
    """Return the text of the reviewed ``masker/fieldmap/overrides.yaml``."""
    return (
        resources.files("airtimesat_platform.masker.fieldmap")
        .joinpath("overrides.yaml")
        .read_text(encoding="utf-8")
    )
