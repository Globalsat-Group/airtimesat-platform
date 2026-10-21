"""The masking engine: mask a response, unmask a request (design §4, §5.5, §8.4).

Pure functions over XML, a field map and a vault; no network I/O. The engine masks every
element by its field-map class, then runs the field-aware detectors over the result, and
returns masked bytes only when every stage is clean. Anything else raises: an unknown
element, attribute or ``xsi:type``, a detector hit, a vault failure, a timeout or an
unexpected exception. The caller then writes nothing for the call and stops the run.

``check_request`` runs the same request walk as ``unmask_request`` without a vault, for
``recorder check`` in CI (design §5.1, §5.5): it classifies every element and checks the
shape of every identifier, but resolves nothing.

The engine never logs and never puts a value in an exception.
"""

import ipaddress
import re
import time
from collections import Counter
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from enum import Enum
from typing import Final

from airtimesat_platform.masker.detect.patterns import (
    OPERATIONAL_SKIP,
    Detector,
    Options,
)
from airtimesat_platform.masker.detect.scan import (
    REDACTED,
    SECRET_ELEMENT_NAMES,
    CallKnownValues,
    cross_call_hit,
    offline_exemption,
    placed_exemption,
    scan_value,
)
from airtimesat_platform.masker.errors import (
    MaskingBlockedError,
    MaskingError,
    RequestRefusedError,
    VaultError,
    safe_path,
)
from airtimesat_platform.masker.fieldmap.model import (
    DATE_TYPES,
    NUMERIC_TYPES,
    Direction,
    FieldEntry,
    FieldMap,
    Treatment,
)
from airtimesat_platform.masker.freetext import Template, slot_treatment
from airtimesat_platform.masker.tokenize.surrogates import SPECS, one_way
from airtimesat_platform.masker.tokenize.vault import Vault
from airtimesat_platform.masker.xmlsafe import (
    MAX_REQUEST_BYTES,
    MAX_RESPONSE_BYTES,
    SOAP_NAMESPACES,
    Element,
    check_attributes,
    is_nil,
    local_name,
    namespace,
    parse,
    serialize,
    serialize_text,
    set_nil,
    xsi_type,
)

# Masking budget per response (design §8.4, *Inferred*).
BUDGET_SECONDS: Final = 2.0
# Authentication fields: never in a plan's request; dropped from embedded payloads first.
AUTH_FIELDS: Final = frozenset(
    {
        "iwsUsername",
        "signature",
        "timestamp",
        "serviceProviderAccountNumber",
        "caller",
        "callerPassword",
    }
)
_AUTH_FOLDED: Final = frozenset(name.casefold() for name in AUTH_FIELDS)
_WILDCARDS: Final = ("*", "%")
_PORT: Final = re.compile(r"^(?P<host>.*?)(?P<port>:\d{1,5})?$")
_BRACKETED: Final = re.compile(r"\[(?P<addr>[^\]]+)\](?P<port>:\d{1,5})?")
# Width of the digit surrogate of T-STR and P-ONE on a numeric element, and of a C constant.
_NUMERIC_ID_DIGITS: Final = 9
_CONSTANT_DIGITS: Final = 6
_EMAIL_SPLIT: Final = re.compile(r"([,;\s]+)")
_SUBNET: Final = re.compile(r"^(?P<addr>[^/]+)(?P<prefix>/\d{1,3})?$")
# The largest digit count of a "99"-prefixed surrogate each numeric XSD type can hold.
_NUMERIC_DIGITS: Final[dict[str, int]] = {
    "int": 9,
    "unsignedInt": 9,
    "long": 18,
    "unsignedLong": 19,
    "double": 15,
    "float": 6,
    "short": 4,
    "unsignedShort": 4,
    "byte": 2,
    "unsignedByte": 2,
}


@dataclass(frozen=True, slots=True)
class MaskResult:
    """A masked response, safe to write. Counts go to the run manifest (design §5.1)."""

    body: bytes
    fault: bool
    dropped: int
    surrogates_placed: int


@dataclass(frozen=True, slots=True)
class RequestRefusal:
    """Why ``check_request`` refused a request: a code, an element path and a detector id."""

    code: str
    path: str = ""
    detector: str = ""


@dataclass(frozen=True, slots=True)
class UnmaskResult:
    """An unmasked request body. It holds real values: keep it in memory only."""

    body: bytes = field(repr=False)
    resolved: int


@dataclass
class CallContext:
    """State for one call: the operation and the real values seen in it (design §4.4)."""

    operation: str
    known: CallKnownValues = field(default_factory=CallKnownValues)
    masked: bool = False


@dataclass
class _Record:
    """One output leaf, scanned after the whole tree is masked."""

    path: str
    name: str
    value: str
    options: Options
    sentinel: str | None


class _Mode(Enum):
    """What a pass does with each leaf."""

    # Mask a response (or an embedded payload).
    MASK = "mask"
    # Replace each surrogate in a plan's request with its real value from the vault.
    UNMASK = "unmask"
    # Classify a plan's request and check each surrogate's shape; resolve nothing.
    CHECK = "check"


@dataclass
class _Walk:
    """State of one masking, unmasking or checking pass."""

    operation: str
    direction: Direction
    call: CallContext
    error: type[MaskingError]
    deadline: float
    mode: _Mode = _Mode.MASK
    records: list[_Record] = field(default_factory=list[_Record])
    placed: set[str] = field(default_factory=set[str])
    dropped: int = 0
    resolved: int = 0

    @property
    def unmask(self) -> bool:
        """Return whether leaves are a plan's request (unmasked or checked), not masked."""
        return self.mode is not _Mode.MASK


def _fits(type_name: str, xsd_type: str) -> bool:
    spec = SPECS[type_name]
    if not spec.prefix.isdigit() or spec.same_length:
        return False
    width = len(spec.prefix) + spec.derived + (1 if spec.check else 0)
    limit = _NUMERIC_DIGITS.get(xsd_type)
    return limit is None or width <= limit


def _width_fits(width: int, xsd_type: str) -> bool:
    limit = _NUMERIC_DIGITS.get(xsd_type)
    return limit is None or width <= limit


def _numeric_output_fits(treatment: Treatment, type_name: str | None, xsd_type: str) -> bool:
    """Return whether a treatment's digit output fits a numeric XSD type (design §4.1)."""
    if treatment is Treatment.T_NUM and type_name is not None:
        return _fits(type_name, xsd_type)
    if treatment in (Treatment.T_STR, Treatment.P_ONE):
        return _width_fits(_NUMERIC_ID_DIGITS, xsd_type)
    if treatment is Treatment.C:
        return _width_fits(_CONSTANT_DIGITS, xsd_type)
    return True


def _surrogate_shape(type_name: str, value: str, where: str) -> str:
    """Return ``value`` if it has the exact surrogate shape of its type; refuse otherwise."""
    if not SPECS[type_name].is_surrogate_shape(value):
        raise RequestRefusedError("NOT_A_SURROGATE", path=where, detector=type_name)
    return value


def _check_constant(entry: FieldEntry, label: str, value: str, where: str) -> None:
    """Check a C value's form without the constants: a literal, or ``<label>-NNNN``."""
    if value in entry.literals:
        return
    m = re.fullmatch(rf"{re.escape(label)}-(\d{{4}})", value)
    if m is None or int(m.group(1)) < 1:
        raise RequestRefusedError("CONSTANT_UNKNOWN", path=where, detector=label)


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return False
    return True


class MaskingEngine:
    """Masks responses and unmasks requests for one run."""

    def __init__(
        self,
        field_map: FieldMap,
        vault: Vault | None,
        *,
        templates: Sequence[Template] = (),
        constants: Mapping[str, Sequence[str]] | None = None,
        budget_seconds: float = BUDGET_SECONDS,
        max_response_bytes: int = MAX_RESPONSE_BYTES,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        """Build an engine over a validated field map and a vault.

        With ``vault=None`` the engine can only ``check_request``; masking and unmasking
        then refuse with ``VAULT_UNAVAILABLE``.

        ``constants`` maps a C label (such as ``SP``) to the ordered real values that get
        ``<label>-0001``, ``<label>-0002`` and so on; the recorder passes Globalsat's SP
        numbers and names from the SITEST record. A C value not listed blocks.
        """
        self._map = field_map
        self._vault_or_none = vault
        self._templates = tuple(templates)
        self._constants = {label: tuple(values) for label, values in (constants or {}).items()}
        self._budget = budget_seconds
        self._max_bytes = max_response_bytes
        self._clock = clock
        self._operations = field_map.operations()
        self._check_numeric_entries()

    def _check_numeric_entries(self) -> None:
        for entry in self._map.entries.values():
            targets: list[tuple[Treatment, str | None]] = [(entry.treatment, entry.id_type)]
            if entry.typed is not None:
                targets += list(entry.typed.values.values())
            for treatment, type_name in targets:
                if entry.is_numeric and not _numeric_output_fits(
                    treatment, type_name, entry.xsd_type
                ):
                    raise MaskingError(
                        "FIELDMAP_SURROGATE_DOES_NOT_FIT",
                        path=f"{entry.operation}:{entry.path}",
                    )
                if entry.is_numeric and treatment in (
                    Treatment.T_IP,
                    Treatment.T_HOST,
                    Treatment.T_EMAIL,
                ):
                    raise MaskingError(
                        "FIELDMAP_TYPE_MISMATCH", path=f"{entry.operation}:{entry.path}"
                    )

    @property
    def _vault(self) -> Vault:
        if self._vault_or_none is None:
            raise MaskingError("VAULT_UNAVAILABLE")
        return self._vault_or_none

    # ------------------------------------------------------------------ public API

    def start_call(self, operation: str, injected: Iterable[str] = ()) -> CallContext:
        """Start a call. ``injected`` are the auth values the signer core added.

        They are known values for this call: an echo of one in the response is replaced
        by its constant (if it is one) or ``REDACTED``, and blocks in a kept field.
        """
        if operation not in self._operations:
            raise RequestRefusedError("OPERATION_NOT_ALLOWED")
        call = CallContext(operation)
        for value in injected:
            call.known.add(value, self._constant_for(value) or REDACTED)
        return call

    def unmask_request(self, call: CallContext, request: bytes) -> UnmaskResult:
        """Replace every surrogate in a plan's request with its real value (design §5.5).

        Raises ``RequestRefusedError`` before any IWS call for: an unknown element,
        attribute or ``xsi:type``; mixed content, a comment, a processing instruction,
        CDATA or a DTD; an element beyond its ``maxOccurs``; an authentication field; a
        value that is not a surrogate, or a surrogate the masker never issued; a wildcard
        in an identifier field; a real-format value in a kept or free-text field.
        """
        walk = _Walk(
            call.operation,
            Direction.REQUEST,
            call,
            RequestRefusedError,
            self._deadline(),
            mode=_Mode.UNMASK,
        )
        root = self._walk_request(walk, request)
        return UnmaskResult(serialize(root, declaration=False), walk.resolved)

    def check_request(self, operation: str, request: bytes) -> RequestRefusal | None:
        """Check a plan's request without a vault; return ``None`` if it passes.

        The same walk as ``unmask_request``, with the same refusals, except that an
        identifier passes on the exact surrogate shape of its type instead of a vault row
        (``IDENTIFIER_NOT_ISSUED`` is checked at run time), and a C value on its
        ``<label>-NNNN`` form. Returns refusal codes and paths, never a value.
        """
        if operation not in self._operations:
            return RequestRefusal("OPERATION_NOT_IN_FIELD_MAP")
        walk = _Walk(
            operation,
            Direction.REQUEST,
            CallContext(operation),
            RequestRefusedError,
            self._deadline(),
            mode=_Mode.CHECK,
        )
        try:
            self._walk_request(walk, request)
        except RequestRefusedError as exc:
            return RequestRefusal(exc.code, exc.path, exc.detector)
        return None

    def _walk_request(self, walk: _Walk, request: bytes) -> Element:
        """Parse a plan's request and walk it in ``walk.mode`` (unmask or check)."""
        try:
            root = parse(
                request, max_bytes=MAX_REQUEST_BYTES, request=True, error=RequestRefusedError
            )
            for element in root.iter():
                if local_name(element).casefold() in _AUTH_FOLDED:
                    raise RequestRefusedError("AUTH_FIELD_IN_REQUEST")
            self._walk_element(walk, root, "", [])
        except MaskingError as exc:
            raise RequestRefusedError(exc.code, exc.path, exc.detector) from None
        except Exception as exc:  # fail closed; report the type only
            failed = "UNMASK_FAILED" if walk.mode is _Mode.UNMASK else "CHECK_FAILED"
            raise RequestRefusedError(failed, detector=type(exc).__name__) from None
        return root

    def mask_response(self, call: CallContext, response: bytes) -> MaskResult:
        """Mask a raw SOAP response, then run the runtime detector over the result.

        Returns the masked envelope only when every element is classified and every
        detector is clean. Otherwise raises ``MaskingBlockedError`` with a code, an element
        path and a detector id.
        """
        if call.masked:
            raise MaskingBlockedError("CALL_ALREADY_MASKED")
        call.masked = True
        walk = _Walk(
            call.operation, Direction.RESPONSE, call, MaskingBlockedError, self._deadline()
        )
        try:
            envelope = parse(
                response, max_bytes=self._max_bytes, request=False, error=MaskingBlockedError
            )
            body_child, fault = self._open_envelope(envelope)
            walk.direction = Direction.FAULT if fault else Direction.RESPONSE
            self._walk_element(walk, body_child, "", [])
            self._record_markup(walk, envelope)
            self._scan(walk)
            body = serialize(envelope, declaration=True)
        except MaskingError as exc:
            raise MaskingBlockedError(exc.code, exc.path, exc.detector) from None
        except Exception as exc:  # fail closed; report the type only
            raise MaskingBlockedError("MASKING_FAILED", detector=type(exc).__name__) from None
        return MaskResult(body, fault, walk.dropped, len(walk.placed))

    # ------------------------------------------------------------------ envelope

    def _open_envelope(self, envelope: Element) -> tuple[Element, bool]:
        ns = namespace(envelope)
        if local_name(envelope) != "Envelope" or ns not in SOAP_NAMESPACES:
            raise MaskingBlockedError("NON_SOAP_BODY")
        if envelope.attrib or (envelope.text or "").strip():
            raise MaskingBlockedError("ENVELOPE_UNEXPECTED_CONTENT")
        children = list(envelope)
        body: Element | None = None
        for child in children:
            name = local_name(child)
            if (child.tail or "").strip() or namespace(child) != ns or child.attrib:
                raise MaskingBlockedError("ENVELOPE_UNEXPECTED_CONTENT")
            if (
                name == "Header"
                and body is None
                and len(child) == 0
                and not (child.text or "").strip()
            ):
                continue
            if name == "Body" and body is None:
                body = child
                continue
            raise MaskingBlockedError("ENVELOPE_UNEXPECTED_CONTENT", path=safe_path([name]))
        if body is None:
            raise MaskingBlockedError("NON_SOAP_BODY")
        payload = list(body)
        if len(payload) != 1 or (body.text or "").strip() or (payload[0].tail or "").strip():
            raise MaskingBlockedError("BODY_NOT_ONE_ELEMENT")
        child = payload[0]
        fault = local_name(child) == "Fault" and namespace(child) == ns
        return child, fault

    # ------------------------------------------------------------------ walking

    def _deadline(self) -> float:
        return self._clock() + self._budget

    def _walk_element(self, walk: _Walk, element: Element, parent: str, shown: list[str]) -> None:
        if self._clock() > walk.deadline:
            raise walk.error("MASKING_TIMEOUT")
        name = local_name(element)
        type_name = xsi_type(element, walk.error)
        segment = f"{name}[{type_name}]" if type_name else name
        path = f"{parent}/{segment}" if parent else segment
        shown_path = [*shown, segment]
        where = safe_path(shown_path)
        check_attributes(element, walk.error, where)
        entry = self._map.lookup(walk.operation, walk.direction, path)
        if entry is None:
            if type_name and self._map.lookup(
                walk.operation, walk.direction, f"{parent}/{name}" if parent else name
            ):
                raise walk.error("UNKNOWN_XSI_TYPE", path=where)
            raise walk.error("UNKNOWN_ELEMENT", path=where)
        if entry.treatment is Treatment.UNCLASSIFIED:
            raise walk.error("UNCLASSIFIED_ELEMENT", path=where)
        children = list(element)
        text = element.text or ""
        if any((child.tail or "").strip() for child in children):
            raise walk.error("MIXED_CONTENT", path=where)
        if is_nil(element, walk.error):
            if not entry.nillable:
                raise walk.error("NIL_NOT_ALLOWED", path=where)
            if children or text.strip():
                raise walk.error("MIXED_CONTENT", path=where)
            return
        if entry.is_complex:
            if text.strip():
                raise walk.error("MIXED_CONTENT", path=where)
            if entry.treatment is Treatment.D:
                if walk.unmask:
                    # Never drop part of a plan's request silently: what is sent must be
                    # what the CTO reviewed.
                    raise walk.error("NOT_REVERSIBLE", path=where)
                self._drop(walk, element, entry, where)
                return
            counts: Counter[str] = Counter()
            for child in children:
                child_type = xsi_type(child, walk.error)
                child_name = local_name(child)
                counts[child_name] += 1
                child_path = (
                    f"{path}/{child_name}[{child_type}]" if child_type else f"{path}/{child_name}"
                )
                child_entry = self._map.lookup(walk.operation, walk.direction, child_path)
                limit = None if child_entry is None else child_entry.max_occurs
                if limit is not None and counts[child_name] > limit:
                    raise walk.error("MAX_OCCURS", path=safe_path([*shown_path, child_name]))
                self._walk_element(walk, child, path, shown_path)
            return
        if children:
            raise walk.error("UNEXPECTED_CHILDREN", path=where)
        if walk.unmask:
            self._unmask_leaf(walk, element, entry, where)
        else:
            self._mask_leaf(walk, element, entry, where)

    def _drop(self, walk: _Walk, element: Element, entry: FieldEntry, where: str) -> None:
        """Treatment D on a non-string element: nil, removal or sentinel (design §4.1)."""
        walk.dropped += 1
        if entry.is_string:
            element.text = REDACTED
            self._record(walk, element, entry, where, REDACTED)
        elif entry.nillable:
            set_nil(element)
        elif entry.min_occurs == 0:
            parent = element.getparent()
            if parent is None:
                raise walk.error("D_ON_ROOT", path=where)
            parent.remove(element)
        else:
            if entry.sentinel is None:
                raise walk.error("D_NEEDS_SENTINEL", path=where)
            element.text = entry.sentinel
            self._record(walk, element, entry, where, entry.sentinel)

    # ------------------------------------------------------------------ response leaves

    def _mask_leaf(self, walk: _Walk, element: Element, entry: FieldEntry, where: str) -> None:
        value = element.text or ""
        treatment, type_name = entry.treatment, entry.id_type
        if treatment is Treatment.TYPED:
            treatment, type_name = self._typing(walk, element, entry, value, where)
        if treatment is Treatment.D:
            self._drop(walk, element, entry, where)
            return
        if treatment is Treatment.KEEP:
            self._record(walk, element, entry, where, value)
            return
        if treatment is Treatment.N:
            out = self._embedded(walk, element, entry, value, where)
        elif treatment is Treatment.F:
            out = self._free_text(walk, value)
        elif not value.strip():
            out = value
        else:
            out = self._mask_value(walk, entry, treatment, type_name, value, where)
            walk.call.known.add(value, out)
        if out is None:
            self._drop(walk, element, entry, where)
            return
        element.text = out
        self._record(walk, element, entry, where, out)

    def _mask_value(
        self,
        walk: _Walk,
        entry: FieldEntry,
        treatment: Treatment,
        type_name: str | None,
        value: str,
        where: str,
    ) -> str:
        try:
            out = self._mask_typed(entry, treatment, type_name, value, where, walk.placed)
        except VaultError as exc:
            raise walk.error(exc.code, path=where, detector=exc.detector) from None
        walk.placed.add(out)
        if treatment in (Treatment.T_STR, Treatment.P_ONE, Treatment.T_EMAIL):
            self._vault.add_known(value)
        return out

    def _mask_typed(
        self,
        entry: FieldEntry,
        treatment: Treatment,
        type_name: str | None,
        value: str,
        where: str,
        placed: set[str],
    ) -> str:
        key = self._vault.keys.k_mask.material()
        match treatment:
            case Treatment.T_NUM:
                return self._issue(type_name or "NUMERIC_ID", value, placed)
            case Treatment.T_STR:
                if entry.is_numeric:
                    return self._issue("NUMERIC_ID", value, placed)
                return self._issue(type_name or "VALUE", value, placed)
            case Treatment.T_IP:
                return self._mask_ip(value, placed)
            case Treatment.T_HOST:
                return self._mask_host(value, placed)
            case Treatment.T_EMAIL:
                return self._mask_emails(value, placed)
            case Treatment.P_ONE:
                if entry.is_numeric:
                    return one_way(key, "NUMERIC_ID", value)
                return one_way(key, type_name or "NAME", value)
            case Treatment.C:
                return self._mask_constant(entry, type_name or "C", value, where)
            case Treatment.G:
                return self._generalize(value, where)
            case _:
                raise MaskingBlockedError("TREATMENT_NOT_APPLICABLE", path=where)

    def _issue(self, type_name: str, real: str, placed: set[str]) -> str:
        surrogate = self._vault.issue(type_name, real)
        placed.add(surrogate)
        return surrogate

    def _mask_ip(self, value: str, placed: set[str]) -> str:
        m = _SUBNET.match(value.strip())
        if m is not None:
            try:
                address = ipaddress.ip_address(m.group("addr"))
            except ValueError:
                address = None
            if address is not None:
                kind = "IPV4" if address.version == 4 else "IPV6"
                return self._issue(kind, str(address), placed) + (m.group("prefix") or "")
        return self._issue("VALUE", value, placed)

    def _mask_host(self, value: str, placed: set[str]) -> str:
        stripped = value.strip()
        # A whole address first: an IPv6 address ends in what looks like a port.
        bracketed = _BRACKETED.fullmatch(stripped)
        if bracketed is not None:
            port = bracketed.group("port") or ""
            return "[" + self._mask_ip(bracketed.group("addr"), placed) + "]" + port
        if _is_ip(stripped):
            return self._mask_ip(stripped, placed)
        m = _PORT.match(stripped)
        assert m is not None  # the pattern matches any string  # noqa: S101
        host, port = m.group("host"), m.group("port") or ""
        wildcard = ""
        while host.startswith("*."):
            wildcard += "*."
            host = host[2:]
        if not host:
            return value
        try:
            ipaddress.ip_address(host)
        except ValueError:
            return wildcard + self._issue("HOST", host, placed) + port
        return wildcard + self._mask_ip(host, placed) + port

    def _mask_emails(self, value: str, placed: set[str]) -> str:
        parts: list[str] = []
        for part in _EMAIL_SPLIT.split(value):
            if not part or _EMAIL_SPLIT.fullmatch(part):
                parts.append(part)
            elif part.startswith("*@"):
                parts.append("*@" + self._issue("HOST", part[2:], placed))
            elif "@" in part:
                parts.append(self._issue("EMAIL", part, placed))
            else:
                parts.append(self._issue("VALUE", part, placed))
        return "".join(parts)

    def _constant_for(self, value: str) -> str | None:
        for label, values in self._constants.items():
            if value in values:
                return f"{label}-{values.index(value) + 1:04d}"
        return None

    def _mask_constant(self, entry: FieldEntry, label: str, value: str, where: str) -> str:
        if value in entry.literals:
            return value
        values = self._constants.get(label, ())
        if value not in values:
            raise MaskingBlockedError("CONSTANT_UNKNOWN", path=where, detector=label)
        index = values.index(value) + 1
        if entry.is_numeric:
            return str(990000 + index)
        return f"{label}-{index:04d}"

    def _generalize(self, value: str, where: str) -> str:
        """Coordinates to whole degrees (design §4.1, *Inferred* precision)."""
        try:
            number = float(value)
        except ValueError:
            raise MaskingBlockedError("G_NOT_NUMERIC", path=where) from None
        if number != number or number in (float("inf"), float("-inf")):
            raise MaskingBlockedError("G_NOT_NUMERIC", path=where)
        return str(int(number))

    def _typing(
        self, walk: _Walk, element: Element, entry: FieldEntry, value: str, where: str
    ) -> tuple[Treatment, str | None]:
        """Resolve a field typed by a sibling enum (design §3.2)."""
        assert entry.typed is not None  # noqa: S101 - validated at load
        parent = element.getparent()
        typing_value: str | None = None
        if parent is not None:
            for sibling in parent:
                if local_name(sibling) == entry.typed.sibling:
                    typing_value = (sibling.text or "").strip()
                    break
        if typing_value is not None and typing_value in entry.typed.values:
            return entry.typed.values[typing_value]
        if walk.unmask:
            raise walk.error("TYPING_UNKNOWN", path=where)
        return self._detect_type(value)

    def _detect_type(self, value: str) -> tuple[Treatment, str | None]:
        """Classify an untyped identifier in a response by pattern, else a generic T-STR."""
        stripped = value.strip()
        if "@" in stripped:
            return Treatment.T_EMAIL, None
        try:
            ipaddress.ip_address(stripped)
        except ValueError:
            pass
        else:
            return Treatment.T_IP, None
        if re.fullmatch(r"SUB-\d{7}", stripped):
            return Treatment.T_NUM, "CONTRACT"
        if stripped.isascii() and stripped.isdigit():
            return Treatment.T_NUM, "OTHER_NUMBER"
        return Treatment.T_STR, "VALUE"

    def _free_text(self, walk: _Walk, value: str) -> str:
        """Treatment F: keep a template match with typed slots masked, else ``Text-<8>``."""
        if not value.strip():
            return value
        key = self._vault.keys.k_mask.material()
        for template in self._templates:
            slots = template.match(value)
            if slots is None:
                continue
            out: list[str] = []
            pos = 0
            for slot, start, end in slots:
                out.append(value[pos:start])
                treatment, type_name = slot_treatment(slot)
                probe = FieldEntry(
                    walk.operation, walk.direction, "", "string", treatment, type_name
                )
                try:
                    masked = self._mask_typed(
                        probe, treatment, type_name, value[start:end], "", walk.placed
                    )
                except VaultError as exc:
                    raise walk.error(exc.code, detector=exc.detector) from None
                walk.placed.add(masked)
                walk.call.known.add(value[start:end], masked)
                out.append(masked)
                pos = end
            out.append(value[pos:])
            result = walk.call.known.replace_in("".join(out))
            if not cross_call_hit(result, self._vault):
                return result
            break
        text = one_way(key, "TEXT", value)
        walk.placed.add(text)
        return text

    def _embedded(
        self, walk: _Walk, element: Element, entry: FieldEntry, value: str, where: str
    ) -> str | None:
        """Treatment N: mask an embedded XML payload with its operation's map (§4.4).

        Returns ``None`` to drop it: no operation sibling, an operation outside the map, a
        root that does not match the operation, or a payload that does not parse.
        """
        assert entry.embedded is not None  # noqa: S101 - validated at load
        rule = entry.embedded
        if not value.strip():
            return value
        parent = element.getparent()
        operation = None
        if parent is not None:
            for sibling in parent:
                if local_name(sibling) == rule.operation_from:
                    operation = (sibling.text or "").strip()
                    break
        if not operation or operation not in self._operations:
            return None
        try:
            inner = parse(
                value.encode("utf-8"),
                max_bytes=self._max_bytes,
                request=False,
                error=MaskingBlockedError,
            )
        except MaskingBlockedError:
            return None
        expected = operation if rule.direction is Direction.REQUEST else f"{operation}Response"
        if local_name(inner) != expected:
            return None
        check_attributes(inner, MaskingBlockedError, where)
        for node in list(inner.iter()):
            if local_name(node).casefold() in _AUTH_FOLDED:
                node_parent = node.getparent()
                if node_parent is not None:
                    node_parent.remove(node)
                    walk.dropped += 1
        inner_walk = _Walk(operation, rule.direction, walk.call, MaskingBlockedError, walk.deadline)
        inner_walk.placed = walk.placed
        roots = list(inner) if rule.direction is Direction.REQUEST else [inner]
        if (inner.text or "").strip() and rule.direction is Direction.REQUEST:
            return None
        base = where.split("/")
        for root in roots:
            # Embedded requests use the request map, but their leaves are masked one way.
            self._walk_element(inner_walk, root, "", base)
        walk.records.extend(inner_walk.records)
        walk.dropped += inner_walk.dropped
        return serialize_text(inner)

    # ------------------------------------------------------------------ request leaves

    def _unmask_leaf(self, walk: _Walk, element: Element, entry: FieldEntry, where: str) -> None:
        value = element.text or ""
        treatment, type_name = entry.treatment, entry.id_type
        if treatment is Treatment.TYPED:
            treatment, type_name = self._typing(walk, element, entry, value, where)
        if treatment in (Treatment.KEEP, Treatment.F):
            self._check_request_text(entry, treatment, value, where)
            return
        if not value.strip():
            return
        if treatment is Treatment.C and walk.mode is _Mode.CHECK:
            _check_constant(entry, type_name or "C", value, where)
            return
        if treatment is Treatment.C:
            element.text = self._unmask_constant(entry, type_name or "C", value, where)
            walk.call.known.add(element.text, value)
            walk.resolved += 1
            return
        if treatment not in (
            Treatment.T_NUM,
            Treatment.T_STR,
            Treatment.T_IP,
            Treatment.T_HOST,
            Treatment.T_EMAIL,
        ):
            raise RequestRefusedError("NOT_REVERSIBLE", path=where)
        if any(w in value for w in _WILDCARDS):
            raise RequestRefusedError("WILDCARD_REFUSED", path=where)
        resolve = self._resolve if walk.mode is _Mode.UNMASK else _surrogate_shape
        try:
            real = self._unmask_value(entry, treatment, type_name, value, where, resolve)
        except VaultError as exc:
            raise RequestRefusedError(exc.code, path=where, detector=exc.detector) from None
        if walk.mode is _Mode.CHECK:
            return
        walk.call.known.add(real, value)
        walk.resolved += 1
        element.text = real

    def _check_request_text(
        self, entry: FieldEntry, treatment: Treatment, value: str, where: str
    ) -> None:
        """Kept and free-text request values: no real-format identifier (design §5.5 step 4)."""
        skip: frozenset[Detector] = frozenset()
        if treatment is Treatment.KEEP and (
            entry.xsd_type in NUMERIC_TYPES | DATE_TYPES | {"boolean"} or entry.operational
        ):
            skip = OPERATIONAL_SKIP
        detector = scan_value(value, Options(skip=skip), offline_exemption())
        if detector is not None:
            raise RequestRefusedError("REAL_FORMAT_VALUE", path=where, detector=detector)

    def _unmask_value(
        self,
        entry: FieldEntry,
        treatment: Treatment,
        type_name: str | None,
        value: str,
        where: str,
        resolve: Callable[[str, str, str], str],
    ) -> str:
        """Map each surrogate in ``value`` through ``resolve(type, surrogate, where)``."""
        if treatment is Treatment.T_NUM or (treatment is Treatment.T_STR and entry.is_numeric):
            kind = "NUMERIC_ID" if treatment is Treatment.T_STR else (type_name or "NUMERIC_ID")
            return resolve(kind, value, where)
        if treatment is Treatment.T_STR:
            return resolve(type_name or "VALUE", value, where)
        if treatment is Treatment.T_IP:
            m = _SUBNET.match(value.strip())
            if m is None:
                raise RequestRefusedError("NOT_A_SURROGATE", path=where)
            addr = m.group("addr")
            kind = "IPV6" if ":" in addr else "IPV4"
            return resolve(kind, addr, where) + (m.group("prefix") or "")
        if treatment is Treatment.T_HOST:
            stripped = value.strip()
            bracketed = _BRACKETED.fullmatch(stripped)
            if bracketed is not None:
                real = resolve("IPV6", bracketed.group("addr"), where)
                return "[" + real + "]" + (bracketed.group("port") or "")
            if SPECS["IPV6"].is_surrogate_shape(stripped):
                return resolve("IPV6", stripped, where)
            m = _PORT.match(stripped)
            assert m is not None  # noqa: S101 - matches any string
            host = m.group("host")
            if SPECS["HOST"].is_surrogate_shape(host):
                return resolve("HOST", host, where) + (m.group("port") or "")
            kind = "IPV6" if ":" in host else "IPV4"
            return resolve(kind, host, where) + (m.group("port") or "")
        parts: list[str] = []
        for part in _EMAIL_SPLIT.split(value):
            if not part or _EMAIL_SPLIT.fullmatch(part):
                parts.append(part)
            else:
                parts.append(resolve("EMAIL", part, where))
        return "".join(parts)

    def _resolve(self, type_name: str, value: str, where: str) -> str:
        return self._vault.resolve(type_name, _surrogate_shape(type_name, value, where))

    def _unmask_constant(self, entry: FieldEntry, label: str, value: str, where: str) -> str:
        if value in entry.literals:
            return value
        m = re.fullmatch(rf"{re.escape(label)}-(\d{{4}})", value)
        values = self._constants.get(label, ())
        if m is None or not 1 <= int(m.group(1)) <= len(values):
            raise RequestRefusedError("CONSTANT_UNKNOWN", path=where, detector=label)
        return values[int(m.group(1)) - 1]

    # ------------------------------------------------------------------ scanning

    def _record(
        self, walk: _Walk, element: Element, entry: FieldEntry, where: str, value: str
    ) -> None:
        skip: frozenset[Detector] = frozenset()
        if entry.treatment is Treatment.KEEP and (
            entry.xsd_type in NUMERIC_TYPES | DATE_TYPES | {"boolean"} or entry.operational
        ):
            skip = OPERATIONAL_SKIP
        walk.records.append(
            _Record(where, local_name(element), value, Options(skip=skip), entry.sentinel)
        )

    def _record_markup(self, walk: _Walk, root: Element) -> None:
        """Scan namespace declarations and attribute values: they reach the output too.

        Neither is classified by the field map, so a namespace URI, a prefix or an
        ``xsi:type`` value could otherwise carry a value past every detector (design §8.4).
        """
        seen: set[str] = set()
        for node in root.iter():
            values = [*node.nsmap.keys(), *node.nsmap.values(), *node.attrib.values()]
            for value in values:
                text = "" if value is None else str(value)
                if text and text not in seen:
                    seen.add(text)
                    walk.records.append(_Record("markup", "markup", text, Options(), None))

    def _scan(self, walk: _Walk) -> None:
        """Run the runtime detector over every output leaf (design §8.4)."""
        exempt = placed_exemption(walk.placed)
        for record in walk.records:
            if self._clock() > walk.deadline:
                raise MaskingBlockedError("MASKING_TIMEOUT")
            if record.name.casefold() in SECRET_ELEMENT_NAMES and record.value not in (
                REDACTED,
                "",
                record.sentinel,
            ):
                raise MaskingBlockedError(
                    "MASKING_BLOCKED", path=record.path, detector=Detector.SENSITIVE_NAME
                )
            detector = scan_value(
                record.value, record.options, exempt, walk.call.known, self._vault
            )
            if detector is not None:
                raise MaskingBlockedError("MASKING_BLOCKED", path=record.path, detector=detector)
