"""Recording plans: strict loader, schema, references and canonical digest (design §5.2).

A plan is a strict YAML file under ``recording-plans/``. ``recorder check`` judges it in
this order, and the first refusal wins:

1. The raw text: size, and no Iridium host name (hard block, §8.5 #9).
2. Strict YAML (``masker.fieldmap.strict_yaml``): no duplicate keys, anchors, aliases, merge
   keys or tags.
3. The hard blocks over every call (``policy.hard_blocks``), before anything else.
4. No escape in a double-quoted scalar, so the parsed text is the text the CTO reviews.
5. Writes: a ``writes`` section or a write operation is refused until S2 PR D3.
6. The schema: unknown keys refused, every error a code and a safe location. Title,
   purpose, call ids and references are scanned by the §8.1 detectors.
7. The read allowlist, references and the call budget, then each method's limits
   (``policy.allowlist``).
8. With the generated field map: every reference fills an identifier field from an
   identifier field of an earlier response, every request passes the masker's vault-free
   request check (``MaskingEngine.check_request``), and, every call being a read, no
   free-text field carries a value and no identifier field is blank (§5.5 step 8).

**References.** ``for_each: ${<call-id>.<field>[a:b]}`` takes the values of ``field`` from
the masked responses of an earlier call, in order, sliced ``[a:b]``; the request then names
the current value as ``${item}``, which must be the whole text of an identifier element.
``field`` is an element name, or a dotted suffix of an element path (``account.imei``). A
slice is required, at most ``MAX_SLICE`` long, and its full length counts against
``max_calls``.

**Digest.** SHA-256 over a canonical JSON form of the parsed plan: sorted keys, strings
NFC-normalized and trimmed, the timestamp in one form, and each request as its element tree
(whitespace between elements dropped, leaf text kept as it is sent). It is stable across
YAML formatting changes and changes with anything the recorder would send.

Nothing here prints or returns a plan value except through ``Plan`` itself.
"""

import hashlib
import json
import re
import unicodedata
from collections.abc import Iterator, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Final, cast

import yaml

from airtimesat_platform.masker.detect.patterns import Options
from airtimesat_platform.masker.detect.scan import offline_exemption, scan_value
from airtimesat_platform.masker.engine import MaskingEngine
from airtimesat_platform.masker.errors import RequestRefusedError
from airtimesat_platform.masker.fieldmap.model import (
    IDENTIFIER_TREATMENTS,
    REVERSIBLE,
    Direction,
    FieldEntry,
    FieldMap,
    Treatment,
)
from airtimesat_platform.masker.fieldmap.strict_yaml import StrictYamlError, load_strict
from airtimesat_platform.masker.tokenize.surrogates import SPECS
from airtimesat_platform.masker.xmlsafe import (
    MAX_REQUEST_BYTES,
    Element,
    local_name,
    parse,
    serialize,
    xsi_type,
)
from airtimesat_platform.recorder.errors import PlanRefusedError
from airtimesat_platform.recorder.policy import allowlist, hard_blocks
from airtimesat_platform.recorder.policy.allowlist import ITEM, WRITES

MAX_PLAN_BYTES: Final = 256 * 1024
# The most calls one plan may make, references expanded (design §5.3, *Inferred*).
MAX_CALLS: Final = 200
# The most items one for_each may expand to (*Inferred*).
MAX_SLICE: Final = 50
MAX_TITLE_CHARS: Final = 120
MAX_PURPOSE_CHARS: Final = 1000
MAX_REQUEST_CHARS: Final = 64 * 1024
DIGEST_FORMAT: Final = "airtimesat-plan-digest/1"

PLAN_ID: Final = re.compile(r"RP-[0-9]{4}-[0-9]{3}")
CALL_ID: Final = re.compile(r"[a-z][a-z0-9-]{0,31}")
_NAME: Final = r"[A-Za-z_][A-Za-z0-9_]{0,63}"
REFERENCE: Final = re.compile(
    rf"\$\{{(?P<call>[a-z][a-z0-9-]{{0,31}})\.(?P<field>{_NAME}(?:\.{_NAME}){{0,7}})"
    r"\[(?P<start>0|[1-9][0-9]{0,2}):(?P<stop>[1-9][0-9]{0,2})\]\}"
)
_TIMESTAMP: Final = r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{1,6})?"
_EXPIRES_TEXT: Final = re.compile(rf"{_TIMESTAMP}Z")
# PyYAML turns an unquoted timestamp into a datetime and forgets how its zone was written,
# so the raw line is checked for the trailing Z (after normalizing CRLF and CR line ends).
_EXPIRES_LINE: Final = re.compile(rf"^expires_at:[ \t]*{_TIMESTAMP}Z[ \t]*(?:#.*)?$", re.MULTILINE)
_TOP_KEYS: Final = frozenset({"id", "title", "purpose", "expires_at", "max_calls", "calls"})
_CALL_KEYS: Final = frozenset({"id", "endpoint", "operation", "request"})
_CALL_OPTIONAL: Final = frozenset({"for_each"})
_REFERENCE_START: Final = "${"


@dataclass(frozen=True, slots=True)
class Reference:
    """``${call.field[start:stop]}``: values of an earlier call's response field."""

    call: str
    field: tuple[str, ...]
    start: int
    stop: int

    @property
    def size(self) -> int:
        """Return the most items the reference can yield."""
        return self.stop - self.start


@dataclass(frozen=True, slots=True)
class Call:
    """One call of a plan."""

    index: int
    id: str
    endpoint: str
    operation: str
    request: str
    for_each: Reference | None
    for_each_text: str | None

    @property
    def where(self) -> str:
        """Return the call's location: its index, never its id (a plan value)."""
        return f"calls[{self.index}]"


@dataclass(frozen=True, slots=True)
class Plan:
    """A plan that passed every check that needs no field map."""

    id: str
    title: str
    purpose: str
    expires_at: datetime
    max_calls: int
    calls: tuple[Call, ...]

    @property
    def expansion(self) -> int:
        """Return the most calls the plan can make, every reference at its full slice."""
        return sum(call.for_each.size if call.for_each else 1 for call in self.calls)


@dataclass(frozen=True, slots=True)
class CheckedPlan:
    """A plan that passed ``recorder check``, with its canonical digest."""

    plan: Plan
    digest: str


class FieldMapContext:
    """The generated field map with the overrides, a vault-free engine, and its names."""

    def __init__(self, field_map: FieldMap) -> None:
        """Wrap a validated field map."""
        self.field_map = field_map
        self.engine = MaskingEngine(field_map, None)
        # Every path segment the map knows. Locations show only these, so an element name
        # a plan made up never reaches the output.
        self.segments = frozenset(
            segment for (_, _, path) in field_map.entries for segment in path.split("/")
        )

    def location(self, where: str, path: str, detector: str = "") -> str:
        """Return ``where/<path>`` with unknown segments as ``?`` and the detector after ``#``."""
        shown = "/".join(s if s in self.segments else "?" for s in path.split("/") if s)
        location = f"{where}/{shown}" if shown else where
        return f"{location}#{detector}" if detector else location


# ---------------------------------------------------------------- typed helpers


def _mapping(value: object, where: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping):
        raise PlanRefusedError("SCHEMA_NOT_MAPPING", where)
    return cast(Mapping[str, object], value)


def _keys(
    item: Mapping[str, object], required: frozenset[str], optional: frozenset[str], where: str
) -> None:
    if not set(item) <= required | optional:
        raise PlanRefusedError("SCHEMA_UNKNOWN_KEY", where)
    missing = sorted(required - set(item))
    if missing:
        # A required key's name is a code constant, so it may be shown.
        key = missing[0] if where == "plan" else f"{where}.{missing[0]}"
        raise PlanRefusedError("SCHEMA_MISSING_KEY", key)


def _str(value: object, where: str) -> str:
    if not isinstance(value, str):
        raise PlanRefusedError("SCHEMA_WRONG_TYPE", where)
    return value


def _text(value: object, where: str, limit: int, *, multiline: bool) -> str:
    """Short plain text: printable, capped, and clean of real-format identifiers (§8.1)."""
    text = _str(value, where).strip()
    if not text:
        raise PlanRefusedError("TEXT_EMPTY", where)
    if len(text) > limit:
        raise PlanRefusedError("TEXT_TOO_LONG", where)
    if not all(ch.isprintable() or (multiline and ch == "\n") for ch in text):
        raise PlanRefusedError("TEXT_NOT_PLAIN", where)
    _no_real_format(text, where)
    return text


def _no_real_format(text: str, where: str) -> None:
    """Refuse plan text that holds a real-format identifier (§8.1 detectors)."""
    detector = scan_value(text, Options(), offline_exemption())
    if detector is not None:
        raise PlanRefusedError("REAL_FORMAT_VALUE", f"{where}#{detector}")


def _expires_at(value: object, raw_text: str, now: datetime) -> datetime:
    where = "expires_at"
    if isinstance(value, datetime):
        lines = raw_text.replace("\r\n", "\n").replace("\r", "\n")
        if value.utcoffset() != timedelta(0) or not _EXPIRES_LINE.search(lines):
            raise PlanRefusedError("EXPIRES_AT_NOT_UTC", where)
        when = value
    elif isinstance(value, str):
        if not _EXPIRES_TEXT.fullmatch(value):
            code = "EXPIRES_AT_NOT_UTC" if re.match(_TIMESTAMP, value) else "EXPIRES_AT_INVALID"
            raise PlanRefusedError(code, where)
        try:
            when = datetime.fromisoformat(value)
        except ValueError:
            raise PlanRefusedError("EXPIRES_AT_INVALID", where) from None
    else:
        raise PlanRefusedError("EXPIRES_AT_INVALID", where)
    when = when.astimezone(UTC)
    if when <= now:
        raise PlanRefusedError("EXPIRES_AT_PAST", where)
    return when


def _reference(text: str, where: str) -> Reference:
    m = REFERENCE.fullmatch(text)
    if m is None:
        raise PlanRefusedError("REFERENCE_GRAMMAR", where)
    start, stop = int(m.group("start")), int(m.group("stop"))
    if not start < stop or stop - start > MAX_SLICE:
        raise PlanRefusedError("REFERENCE_SLICE_INVALID", where)
    return Reference(m.group("call"), tuple(m.group("field").split(".")), start, stop)


def _call(n: int, raw: object) -> Call:
    where = f"calls[{n}]"
    item = _mapping(raw, where)
    _keys(item, _CALL_KEYS, _CALL_OPTIONAL, where)
    call_id = _str(item["id"], f"{where}.id")
    if not CALL_ID.fullmatch(call_id):
        raise PlanRefusedError("CALL_ID_INVALID", f"{where}.id")
    _no_real_format(call_id, f"{where}.id")
    request = _str(item["request"], f"{where}.request")
    if not request.strip():
        raise PlanRefusedError("REQUEST_EMPTY", f"{where}.request")
    if len(request) > MAX_REQUEST_CHARS:
        raise PlanRefusedError("REQUEST_TOO_LARGE", f"{where}.request")
    for_each_text: str | None = None
    for_each: Reference | None = None
    if "for_each" in item:
        for_each_text = _str(item["for_each"], f"{where}.for_each")
        _no_real_format(for_each_text, f"{where}.for_each")
        for_each = _reference(for_each_text, f"{where}.for_each")
    return Call(
        index=n,
        id=call_id,
        endpoint=_str(item["endpoint"], f"{where}.endpoint"),
        operation=_str(item["operation"], f"{where}.operation"),
        request=request,
        for_each=for_each,
        for_each_text=for_each_text,
    )


def _schema(doc: object, raw_text: str, now: datetime) -> Plan:
    plan = _mapping(doc, "plan")
    _keys(plan, _TOP_KEYS, frozenset(), "plan")
    plan_id = _str(plan["id"], "id")
    if not PLAN_ID.fullmatch(plan_id):
        raise PlanRefusedError("PLAN_ID_INVALID", "id")
    title = _text(plan["title"], "title", MAX_TITLE_CHARS, multiline=False)
    purpose = _text(plan["purpose"], "purpose", MAX_PURPOSE_CHARS, multiline=True)
    expires_at = _expires_at(plan["expires_at"], raw_text, now)
    max_calls = plan["max_calls"]
    if not isinstance(max_calls, int) or isinstance(max_calls, bool):
        raise PlanRefusedError("SCHEMA_WRONG_TYPE", "max_calls")
    if not 1 <= max_calls <= MAX_CALLS:
        raise PlanRefusedError("MAX_CALLS_OUT_OF_RANGE", "max_calls")
    raw_calls = plan["calls"]
    if not isinstance(raw_calls, list):
        raise PlanRefusedError("SCHEMA_WRONG_TYPE", "calls")
    if not raw_calls:
        raise PlanRefusedError("CALLS_EMPTY", "calls")
    calls = tuple(_call(n, raw) for n, raw in enumerate(cast(list[object], raw_calls)))
    seen: set[str] = set()
    for call in calls:
        if call.id in seen:
            raise PlanRefusedError("CALL_ID_DUPLICATE", f"{call.where}.id")
        seen.add(call.id)
    return Plan(plan_id, title, purpose, expires_at, max_calls, calls)


# ---------------------------------------------------------------- checks


def _check_escapes(text: str) -> None:
    """Refuse a double-quoted scalar with a backslash (design §5.2, §8.1).

    An escape (a backslash with ``x``, ``u`` and hex digits, or a line continuation) makes
    the parsed text differ from the raw text the CTO reviews and the leak scan reads, so
    digits could hide in it.
    """
    try:
        # PyYAML's stubs leave yaml.scan's stream and return types unknown; the cast fixes them.
        tokens = cast(
            Iterator[yaml.Token],
            yaml.scan(text, Loader=yaml.SafeLoader),  # pyright: ignore[reportUnknownMemberType]
        )
        for token in tokens:
            if isinstance(token, yaml.ScalarToken) and token.style == '"':
                start, end = token.start_mark, token.end_mark
                if "\\" in text[start.index : end.index]:
                    raise PlanRefusedError("YAML_ESCAPE", f"line:{start.line + 1}")
    except yaml.YAMLError:
        return  # the strict loader has already refused it


def _check_writes(doc: object) -> None:
    """Refuse writes until they arrive in S2 PR D3 (design §5.6)."""
    if not isinstance(doc, Mapping):
        return
    plan = cast(Mapping[str, object], doc)
    if "writes" in plan:
        raise PlanRefusedError("WRITES_NOT_SUPPORTED", "writes")
    raw_calls = plan.get("calls")
    if not isinstance(raw_calls, list):
        return
    for n, raw in enumerate(cast(list[object], raw_calls)):
        if isinstance(raw, Mapping):
            operation = cast(Mapping[str, object], raw).get("operation")
            if isinstance(operation, str) and operation in WRITES:
                raise PlanRefusedError("WRITES_NOT_SUPPORTED", f"calls[{n}]")


def _parse_request(call: Call) -> Element:
    where = f"{call.where}/request"
    try:
        data = call.request.encode("utf-8")
    except UnicodeEncodeError:
        raise PlanRefusedError("REQUEST_NOT_UTF8", where) from None
    try:
        return parse(data, max_bytes=MAX_REQUEST_BYTES, request=True, error=RequestRefusedError)
    except RequestRefusedError as exc:
        raise PlanRefusedError(exc.code, where) from None


def _check_references(plan: Plan, roots: Mapping[int, Element]) -> None:
    index = {call.id: call.index for call in plan.calls}
    for call in plan.calls:
        reference = call.for_each
        if reference is not None:
            if reference.call not in index:
                raise PlanRefusedError("REFERENCE_UNKNOWN_CALL", f"{call.where}.for_each")
            if index[reference.call] >= call.index:
                raise PlanRefusedError("REFERENCE_FORWARD", f"{call.where}.for_each")
        items = 0
        for element in roots[call.index].iter():
            attributes = [str(value) for value in element.attrib.values()]
            if any(_REFERENCE_START in value for value in attributes):
                raise PlanRefusedError("REFERENCE_GRAMMAR", f"{call.where}/request")
            text = element.text or ""
            if _REFERENCE_START in (element.tail or "") or (
                _REFERENCE_START in text and text != ITEM
            ):
                raise PlanRefusedError("REFERENCE_GRAMMAR", f"{call.where}/request")
            items += text == ITEM
        if items and reference is None:
            raise PlanRefusedError("ITEM_WITHOUT_FOR_EACH", f"{call.where}/request")
        if reference is not None and not items:
            raise PlanRefusedError("FOR_EACH_WITHOUT_ITEM", f"{call.where}.for_each")
    if plan.expansion > plan.max_calls:
        raise PlanRefusedError("CALLS_OVER_MAX", "max_calls")


def load_plan(text: str, *, now: datetime) -> Plan:
    """Run every check that needs no field map; return the parsed plan or refuse it."""
    if len(text.encode("utf-8", "surrogatepass")) > MAX_PLAN_BYTES:
        raise PlanRefusedError("PLAN_TOO_LARGE")
    hard_blocks.check_text(text)
    try:
        doc = load_strict(text)
    except StrictYamlError as exc:
        raise PlanRefusedError(exc.code, exc.path.replace("line ", "line:")) from None
    hard_blocks.check_document(doc)
    _check_escapes(text)
    _check_writes(doc)
    plan = _schema(doc, text, now)
    for call in plan.calls:
        if not allowlist.is_allowed_read(call.endpoint, call.operation):
            raise PlanRefusedError("OPERATION_NOT_ALLOWLISTED", call.where)
    roots = {call.index: _parse_request(call) for call in plan.calls}
    _check_references(plan, roots)
    for call in plan.calls:
        allowlist.check_limits(call.operation, roots[call.index], f"{call.where}/request")
    return plan


# ---------------------------------------------------------------- field map checks


def _names(path: str) -> list[str]:
    return [segment.partition("[")[0] for segment in path.split("/")]


def _kind(entry: FieldEntry, treatment: Treatment, type_name: str | None) -> str:
    """Return the surrogate type a reversible treatment produces on this entry."""
    match treatment:
        case Treatment.T_NUM:
            return type_name or "NUMERIC_ID"
        case Treatment.T_STR:
            return "NUMERIC_ID" if entry.is_numeric else (type_name or "VALUE")
        case Treatment.T_IP:
            return "IPV4"
        case Treatment.T_HOST:
            return "HOST"
        case _:
            return "EMAIL"


def _targets(entry: FieldEntry) -> list[tuple[Treatment, str | None]]:
    if entry.treatment is Treatment.TYPED and entry.typed is not None:
        return list(entry.typed.values.values())
    return [(entry.treatment, entry.id_type)]


def _source_kinds(
    ctx: FieldMapContext, operation: str, field: tuple[str, ...], where: str
) -> set[str]:
    """Return the surrogate types an earlier response field holds; refuse non-identifiers."""
    entries = [
        entry
        for (op, direction, path), entry in ctx.field_map.entries.items()
        if op == operation
        and direction is Direction.RESPONSE
        and _names(path)[-len(field) :] == list(field)
    ]
    if not entries:
        raise PlanRefusedError("REFERENCE_SOURCE_UNKNOWN", where)
    kinds: set[str] = set()
    for entry in entries:
        for treatment, type_name in _targets(entry):
            if entry.is_complex or treatment not in REVERSIBLE:
                raise PlanRefusedError("REFERENCE_SOURCE_NOT_IDENTIFIER", where)
            kinds.add(_kind(entry, treatment, type_name))
    return kinds


def _segments(element: Element) -> list[str]:
    segments: list[str] = []
    node: Element | None = element
    while node is not None:
        type_name = xsi_type(node, RequestRefusedError)
        name = local_name(node)
        segments.append(f"{name}[{type_name}]" if type_name else name)
        node = node.getparent()
    return segments[::-1]


def _treatment(entry: FieldEntry, element: Element) -> tuple[Treatment, str | None] | None:
    """Return the entry's treatment, a TYPED one resolved by its sibling; ``None`` if unknown."""
    if entry.treatment is not Treatment.TYPED or entry.typed is None:
        return entry.treatment, entry.id_type
    parent = element.getparent()
    if parent is not None:
        for sibling in parent:
            if local_name(sibling) == entry.typed.sibling:
                return entry.typed.values.get((sibling.text or "").strip())
    return None


def _target_kind(ctx: FieldMapContext, call: Call, element: Element) -> str:
    """Return the surrogate type ``${item}`` needs here; refuse a non-identifier field."""
    segments = _segments(element)
    where = ctx.location(call.where, "/".join(segments))
    entry = ctx.field_map.lookup(call.operation, Direction.REQUEST, "/".join(segments))
    if entry is None:
        raise PlanRefusedError("UNKNOWN_ELEMENT", where)
    resolved = _treatment(entry, element)
    if resolved is None:
        raise PlanRefusedError("REFERENCE_TYPING_UNKNOWN", where)
    treatment, type_name = resolved
    if entry.is_complex or treatment not in REVERSIBLE:
        raise PlanRefusedError("REFERENCE_NOT_IDENTIFIER_FIELD", where)
    return _kind(entry, treatment, type_name)


def _check_identifiers(ctx: FieldMapContext, plan: Plan, call: Call) -> None:
    root = _parse_request(call)
    reference = call.for_each
    if reference is not None:
        source = next(c for c in plan.calls if c.id == reference.call)
        kinds = _source_kinds(ctx, source.operation, reference.field, f"{call.where}.for_each")
        for element in root.iter():
            if element.text != ITEM:
                continue
            try:
                kind = _target_kind(ctx, call, element)
            except RequestRefusedError as exc:
                raise PlanRefusedError(exc.code, f"{call.where}/request") from None
            if kind not in kinds:
                raise PlanRefusedError(
                    "REFERENCE_TYPE_MISMATCH",
                    ctx.location(call.where, "/".join(_segments(element))),
                )
            # A placeholder of the right shape, so the request check judges the rest.
            element.text = SPECS[kind].render(bytes(32), "")
    refusal = ctx.engine.check_request(call.operation, serialize(root, declaration=False))
    if refusal is not None:
        raise PlanRefusedError(
            refusal.code, ctx.location(call.where, refusal.path, refusal.detector)
        )
    _check_search_inputs(ctx, call, root)


# Identifier treatments whose blank value is a blank filter. TYPED is resolved to its class
# first. A P-ONE request field can only ever be blank, so its presence alone is refused.
_BLANK_REFUSED: Final = IDENTIFIER_TREATMENTS - {Treatment.TYPED}


def _check_search_inputs(ctx: FieldMapContext, call: Call, root: Element) -> None:
    """Every input of a read is a search input (design §5.5 step 8).

    So a free-text (F) field must be empty, and an identifier field that is present must not
    be blank or nil: IWS may read a blank filter as "all rows" (§8.5 #18); leaving the
    element out is how a plan sends no filter. Writes (S2 PR D3) keep the detector-only
    rule for their F fields, so this lives here, not in the masker's shared request walk.
    """
    for element in root.iter():
        if element is root or len(element):
            continue
        path = "/".join(_segments(element))
        entry = ctx.field_map.lookup(call.operation, Direction.REQUEST, path)
        resolved = None if entry is None or entry.is_complex else _treatment(entry, element)
        if resolved is None:
            continue  # the request check has judged it already
        treatment, _ = resolved
        blank = not (element.text or "").strip()
        if treatment is Treatment.F and not blank:
            raise PlanRefusedError("FREE_TEXT_IN_SEARCH_INPUT", ctx.location(call.where, path))
        if treatment in _BLANK_REFUSED and blank:
            raise PlanRefusedError("IDENTIFIER_BLANK", ctx.location(call.where, path))


def check_plan(
    text: str,
    *,
    now: datetime,
    field_map: FieldMapContext | None,
    field_map_refusal: str = "FIELD_MAP_MISSING",
) -> CheckedPlan:
    """Run ``recorder check`` on one plan's text; return it with its digest, or refuse it.

    ``field_map`` is ``None`` while the generated map is absent or invalid; every plan that
    passes the other checks is then refused with ``field_map_refusal`` (fail closed).
    """
    plan = load_plan(text, now=now)
    if field_map is None:
        raise PlanRefusedError(field_map_refusal)
    for call in plan.calls:
        _check_identifiers(field_map, plan, call)
    return CheckedPlan(plan, digest(plan))


# ---------------------------------------------------------------- digest


def _normalized(text: str) -> str:
    return unicodedata.normalize("NFC", text.replace("\r\n", "\n").replace("\r", "\n")).strip()


def _canonical(element: Element) -> dict[str, object]:
    node: dict[str, object] = {
        "name": local_name(element),
        "attributes": sorted((str(k), str(v)) for k, v in element.attrib.items()),
    }
    children = list(element)
    if children:
        node["children"] = [_canonical(child) for child in children]
    else:
        node["text"] = element.text or ""
    return node


def digest(plan: Plan) -> str:
    """Return the SHA-256 of the plan's canonical form (hex)."""
    canonical = {
        "format": DIGEST_FORMAT,
        "id": plan.id,
        "title": _normalized(plan.title),
        "purpose": _normalized(plan.purpose),
        "expires_at": plan.expires_at.isoformat().replace("+00:00", "Z"),
        "max_calls": plan.max_calls,
        "calls": [
            {
                "id": call.id,
                "endpoint": call.endpoint,
                "operation": call.operation,
                "for_each": call.for_each_text,
                "request": _canonical(_parse_request(call)),
            }
            for call in plan.calls
        ],
    }
    data = json.dumps(canonical, sort_keys=True, ensure_ascii=False, separators=(",", ":"))
    return hashlib.sha256(data.encode("utf-8")).hexdigest()
