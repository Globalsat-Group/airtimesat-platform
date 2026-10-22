"""SITEST port of the IWS gateway: the recorder's only entry point into the gateway.

``SitestPort`` has one call (endpoint, operation, request, ``caller``) that returns the raw
reply, the signed UTC timestamp, the IWS duration and an outcome code (design
``docs/design/s2-recorder-masker.md`` §7.1). ``InProcessSitestPort`` implements it over the
signer core and is the only holder of the SITEST secret. For each call it:

1. waits out the cooldown after a call that timed out (§5.8), and runs one call at a time;
2. checks ``caller`` (``rec.<plan-id>``, §5.8) and runs the guard's operation check;
3. rebuilds the envelope from scratch, signing the operation read from its root element
   with an explicit UTC timestamp (``envelope``, ``signing``);
4. runs the guard again on the final bytes (``sitest_guard``), independently of the
   recorder's own hard blocks;
5. sends through the pinned, single-connection transport (``transport``);
6. replaces any echo of a signature in the reply with ``REDACTED``: this call's and those of
   the port's earlier calls, which a later read of the IWS log (``getIwsRequests``) could
   return; the signatures never leave this module;
7. stops on clock skew above 5 s between the reply's ``Date`` header and the local clock, on
   "Too many connections!", and on anything that is not a SOAP 1.2 reply.

It reaches the SITEST endpoints only: there is no Beta or production endpoint in the
gateway, and the ``sitest-only`` import contract keeps this module away from ``gateway.api``.

``generated_field_map_text`` returns the generated field map (design §4.5, §7.2) for the
recorder to hand to the masker; without it every ``recorder check`` fails closed.

``validate_request`` checks one plan request against the embedded schema of its endpoint's
WSDL snapshot (§5.5 step 1), for ``recorder check`` and the run's own check.
"""

import asyncio
import copy
import functools
import re
import time
from collections import deque
from collections.abc import Awaitable, Callable, Iterable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from email.utils import parsedate_to_datetime
from importlib import resources
from typing import Final, Protocol, cast

from lxml import etree

from airtimesat_platform.common.secrets import (
    SecretNotAvailableError,
    SecretsProvider,
    SecretValue,
)

# Endpoint and TransportTimeoutError are re-exported: the port's call takes the one and
# raises the other, and the recorder may import nothing else from the gateway.
from airtimesat_platform.gateway.endpoints_sitest import Endpoint as Endpoint
from airtimesat_platform.gateway.endpoints_sitest import endpoint_url
from airtimesat_platform.gateway.envelope import AUTH_FIELDS, IWS_NS, AuthFields, build_envelope
from airtimesat_platform.gateway.errors import (
    GatewayError,
    RefusedError,
    ResponseError,
    SigningError,
)
from airtimesat_platform.gateway.errors import TransportTimeoutError as TransportTimeoutError
from airtimesat_platform.gateway.faults import OUTCOME_OK, raise_if_throttled, read_reply
from airtimesat_platform.gateway.signing import sign, utc_timestamp
from airtimesat_platform.gateway.sitest_guard import (
    check_envelope,
    check_operation,
    redact_echoes,
)
from airtimesat_platform.gateway.transport import AiohttpTransport, Transport

# Names of the SITEST record's fields, in sitest.json.age or on standard input (names only).
# These are names, not values (hence the S105 waivers).
SECRET_IWS_USERNAME: Final = "sitest.iws_username"  # noqa: S105
SECRET_KEY: Final = "sitest.secret_key"  # noqa: S105
SECRET_SP_ACCOUNT: Final = "sitest.sp_account_number"  # noqa: S105

MAX_CLOCK_SKEW_S: Final = 5.0
TIMEOUT_COOLDOWN_S: Final = 60.0
# Signatures of earlier calls kept for redaction; above the plan cap of 200 calls (§5.3).
MAX_REMEMBERED_SIGNATURES: Final = 256
CALLER_PATTERN: Final = re.compile(r"\Arec\.[A-Za-z0-9][A-Za-z0-9._-]{0,63}\Z")
_FAULT_STATUSES: Final = frozenset({400, 500})
# Package path of the generated field map; WSDL-derived files stay in the gateway (CLAUDE.md).
GENERATED_FIELD_MAP: Final = ("wsdl", "fieldmap", "generated.yaml")
WSDL_SNAPSHOT: Final = ("wsdl", "sitest")
MAX_WSDL_BYTES: Final = 4 * 1024 * 1024
MAX_PLAN_REQUEST_BYTES: Final = 256 * 1024
_XS: Final = "{http://www.w3.org/2001/XMLSchema}"
_WSDL: Final = "{http://schemas.xmlsoap.org/wsdl/}"
# libxml2 error types of a wrong value (a type, an enumeration or a facet), matched exactly.
# Everything else is wrong content: an element or attribute unknown, missing, misplaced or in
# the wrong namespace, or children or attributes in a simple-typed element (CVC_TYPE_3_1_*).
_VALUE_ERRORS: Final = frozenset(
    f"SCHEMAV_CVC_{name}"
    for name in (
        "DATATYPE_VALID_1_2_1",
        "DATATYPE_VALID_1_2_2",
        "DATATYPE_VALID_1_2_3",
        "ENUMERATION_VALID",
        "FACET_VALID",
        "LENGTH_VALID",
        "MINLENGTH_VALID",
        "MAXLENGTH_VALID",
        "MININCLUSIVE_VALID",
        "MAXINCLUSIVE_VALID",
        "MINEXCLUSIVE_VALID",
        "MAXEXCLUSIVE_VALID",
        "PATTERN_VALID",
        "TOTALDIGITS_VALID",
        "FRACTIONDIGITS_VALID",
    )
)
# Schema components that load another file through libxml2's own I/O, which the parser's
# no_network flag does not cover. The snapshot has none; one in it is refused.
_EXTERNAL: Final = ("import", "include", "redefine", "override")
_AUTH_BASE: Final = "authenticatedIwsRequestImpl"


def generated_field_map_text() -> str | None:
    """Return the generated field map's text, or ``None`` while it does not exist.

    The gateway does not parse it: the recorder hands it to the masker with the reviewed
    overrides (``gateway-one-way``: the gateway never imports the masker).
    """
    resource = resources.files("airtimesat_platform.gateway").joinpath(*GENERATED_FIELD_MAP)
    if not resource.is_file():
        return None
    return resource.read_text(encoding="utf-8")


@dataclass(frozen=True, slots=True)
class SchemaRefusal:
    """Why a plan request failed the WSDL schema: a code and a path of schema names only."""

    code: str
    path: str


class _LogEntry(Protocol):
    """The two fields read from an lxml error-log entry; never its message."""

    type_name: str
    path: str


@dataclass(frozen=True, slots=True)
class _Schema:
    schema: etree.XMLSchema
    operations: frozenset[str]
    names: frozenset[str]


def _safe_parser() -> etree.XMLParser:
    return etree.XMLParser(resolve_entities=False, no_network=True, load_dtd=False, huge_tree=False)


@functools.cache
def _endpoint_schema(endpoint: Endpoint) -> _Schema | None:
    """Compile the endpoint's embedded schema once per process; ``None`` without a snapshot.

    Each operation gets a global element ``tns:<operation>`` holding the unqualified part
    ``request``, as an RPC/literal message writes it. The authentication fields of the base
    request type are removed: the signer core adds them, so a plan never carries them.
    """
    resource = resources.files("airtimesat_platform.gateway").joinpath(
        *WSDL_SNAPSHOT, f"{endpoint.value}.wsdl"
    )
    if not resource.is_file():
        return None
    data = resource.read_bytes()
    if len(data) > MAX_WSDL_BYTES or b"<!DOCTYPE" in data or b"<!ENTITY" in data:
        raise GatewayError("WSDL_SNAPSHOT_INVALID")
    wsdl = etree.fromstring(data, _safe_parser())
    schema = copy.deepcopy(wsdl.find(f"{_WSDL}types/{_XS}schema"))
    base = None if schema is None else schema.find(f"{_XS}complexType[@name='{_AUTH_BASE}']")
    if (
        schema is None
        or base is None
        or any(schema.find(f"{_XS}{n}") is not None for n in _EXTERNAL)
    ):
        raise GatewayError("WSDL_SNAPSHOT_INVALID")
    for sequence in base.iterfind(f"{_XS}sequence"):
        for element in [e for e in sequence if e.get("name") in AUTH_FIELDS]:
            sequence.remove(element)
    parts = {
        m.get("name"): m.find(f"{_WSDL}part[@name='request']") for m in wsdl.iter(f"{_WSDL}message")
    }
    operations: set[str] = set()
    for operation in wsdl.iterfind(f"{_WSDL}portType/{_WSDL}operation"):
        name, message = operation.get("name", ""), operation.find(f"{_WSDL}input")
        part = None if message is None else parts.get(message.get("message", "").rpartition(":")[2])
        if part is None:
            continue
        wrapper = etree.SubElement(schema, f"{_XS}element", name=name)
        group = etree.SubElement(etree.SubElement(wrapper, f"{_XS}complexType"), f"{_XS}sequence")
        etree.SubElement(group, f"{_XS}element", name="request", type=part.get("type", ""))
        operations.add(name)
    names = frozenset(e.get("name", "") for e in schema.iter(f"{_XS}element"))
    return _Schema(etree.XMLSchema(etree.ElementTree(schema)), frozenset(operations), names)


def _shown(path: str, names: frozenset[str]) -> str:
    """Turn libxml2's node path into ``request/...`` with prefixes and positions dropped.

    A name the schema does not declare is shown as ``?``: a plan could put data in one.
    """
    segments = [re.sub(r"\[.*\]$|^[^:\[]*:", "", s) for s in path.split("/") if s][1:]
    return "/".join(s if s in names else "?" for s in segments)


def _is_bare(node: object, placeholder: str) -> bool:
    # _Element is lxml's public element class, private only by its name.
    return (
        isinstance(node, etree._Element)  # pyright: ignore[reportPrivateUsage]
        and len(node) == 0
        and not node.attrib
        and node.text == placeholder
    )


def validate_request(
    endpoint: Endpoint, operation: str, request: str, *, placeholder: str | None = None
) -> SchemaRefusal | None:
    """Validate one plan request against the WSDL schema; ``None`` if it passes.

    ``request`` is the plan's ``<request>`` element. It is wrapped in the operation element in
    the IWS namespace, as the signer core sends it. A wrong value in an element whose whole
    text is ``placeholder`` (``${item}``, filled at run time) is not counted. Returns a code and
    a safe path, never an lxml message, which can echo values. Without the WSDL snapshot
    nothing is checked and ``None`` is returned, as before the snapshot existed.
    """
    compiled = _endpoint_schema(endpoint)
    if compiled is None:
        return None
    if operation not in compiled.operations:
        return SchemaRefusal("SCHEMA_UNKNOWN_OPERATION", "")
    data = request.encode("utf-8")
    if len(data) > MAX_PLAN_REQUEST_BYTES or b"<!" in data:
        return SchemaRefusal("SCHEMA_NOT_PLAIN_XML", "")
    try:
        root = etree.fromstring(data, _safe_parser())
    except etree.XMLSyntaxError:
        return SchemaRefusal("SCHEMA_NOT_PLAIN_XML", "")
    wrapper = etree.Element(f"{{{IWS_NS}}}{operation}", nsmap={"tns": IWS_NS})
    wrapper.append(root)
    document = etree.ElementTree(wrapper)
    if compiled.schema.validate(document):
        return None
    for error in cast(Iterable[_LogEntry], compiled.schema.error_log):
        value_error = error.type_name in _VALUE_ERRORS
        if value_error and placeholder is not None:
            nodes = cast(list[object], document.xpath(error.path, namespaces={"tns": IWS_NS}))
            # Only a bare placeholder is forgiven: no children, no attributes, no other text.
            if nodes and all(_is_bare(node, placeholder) for node in nodes):
                continue
        code = "SCHEMA_VALUE" if value_error else "SCHEMA_CONTENT"
        return SchemaRefusal(code, _shown(error.path, compiled.names))
    return None


@dataclass(frozen=True, slots=True)
class SitestCredentials:
    """The SITEST record: never printed, never logged."""

    iws_username: SecretValue
    secret_key: SecretValue
    service_provider_account_number: SecretValue | None = None

    @classmethod
    def from_provider(cls, provider: SecretsProvider) -> "SitestCredentials":
        """Read the SITEST record from ``provider``; the SP account number is optional."""
        try:
            sp_account: SecretValue | None = provider.get_secret(SECRET_SP_ACCOUNT)
        except SecretNotAvailableError:
            sp_account = None
        return cls(
            iws_username=provider.get_secret(SECRET_IWS_USERNAME),
            secret_key=provider.get_secret(SECRET_KEY),
            service_provider_account_number=sp_account,
        )


@dataclass(frozen=True, slots=True)
class SitestResult:
    """One call's result. ``body`` is raw SITEST data: mask it before anything else."""

    http_status: int
    outcome: str
    signed_timestamp: str
    duration_s: float
    body: bytes = field(repr=False)


class SitestPort(Protocol):
    """The recorder's view of the gateway."""

    async def call(
        self, endpoint: Endpoint, operation: str, request: str, caller: str
    ) -> SitestResult:
        """Sign and send one request to SITEST; return the raw reply and its metadata."""
        ...

    def auth_identifiers(self) -> tuple[SecretValue, ...]:
        """Return ``iwsUsername`` and the SP account number(s), which the masker must mask."""
        ...


def _utc_now() -> datetime:
    return datetime.now(UTC)


def check_clock(date_header: str | None, local_now: datetime) -> None:
    """Refuse a reply whose ``Date`` header is missing, unreadable or more than 5 s off."""
    if date_header is None:
        raise ResponseError("CLOCK_UNVERIFIED")
    try:
        server = parsedate_to_datetime(date_header)
    except (TypeError, ValueError, IndexError):
        raise ResponseError("CLOCK_UNVERIFIED") from None
    if server.tzinfo is None:
        server = server.replace(tzinfo=UTC)
    if local_now.utcoffset() is None:
        raise SigningError("TIMESTAMP_NOT_TIMEZONE_AWARE")
    if abs((local_now - server).total_seconds()) > MAX_CLOCK_SKEW_S:
        raise ResponseError("CLOCK_SKEW")


def _outcome(status: int, body: bytes) -> str:
    if status != 200 and status not in _FAULT_STATUSES:
        raise_if_throttled(body)
        raise ResponseError("UNEXPECTED_STATUS")
    try:
        fault = read_reply(body)
    except ResponseError:
        raise_if_throttled(body)
        raise
    if fault is None:
        if status != 200:
            raise ResponseError("ERROR_STATUS_WITHOUT_FAULT")
        return OUTCOME_OK
    raise_if_throttled(body)
    return fault.outcome


class InProcessSitestPort:
    """The S2 implementation of ``SitestPort``, in the recorder's process.

    ``allow_writes`` is set only for a run the CTO started with ``--writes``; otherwise the
    guard refuses every write. ``transport``, ``clock``, ``monotonic`` and ``sleep`` are
    replaced only in tests; the default transport is ``AiohttpTransport``.
    """

    def __init__(
        self,
        credentials: SitestCredentials,
        *,
        allow_writes: bool = False,
        transport: Transport | None = None,
        clock: Callable[[], datetime] = _utc_now,
        monotonic: Callable[[], float] = time.monotonic,
        sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
    ) -> None:
        """Hold the credentials; nothing is sent until ``call``."""
        self._credentials = credentials
        self._allow_writes = allow_writes
        self._transport = transport
        self._clock = clock
        self._monotonic = monotonic
        self._sleep = sleep
        self._lock = asyncio.Lock()
        self._cooldown_until = 0.0
        # Held as SecretValue so that no repr or vars() of the port shows them.
        self._signatures: deque[SecretValue] = deque(maxlen=MAX_REMEMBERED_SIGNATURES)

    def auth_identifiers(self) -> tuple[SecretValue, ...]:
        """Return ``iwsUsername`` and the SP account number, if any."""
        sp_account = self._credentials.service_provider_account_number
        return (self._credentials.iws_username,) + ((sp_account,) if sp_account else ())

    async def call(
        self, endpoint: Endpoint, operation: str, request: str, caller: str
    ) -> SitestResult:
        """Check, sign and send one request; see the module docstring for the steps."""
        async with self._lock:
            remaining = self._cooldown_until - self._monotonic()
            if remaining > 0:
                await self._sleep(remaining)
            if not CALLER_PATTERN.fullmatch(caller):
                raise RefusedError("CALLER_INVALID")
            check_operation(endpoint, operation, allow_writes=self._allow_writes)

            signed: list[tuple[str, str]] = []

            def auth_for(signed_operation: str) -> AuthFields:
                timestamp = utc_timestamp(self._clock())
                signature = sign(self._credentials.secret_key, signed_operation, timestamp)
                signed.append((timestamp, signature))
                return AuthFields(
                    iws_username=self._credentials.iws_username,
                    timestamp=timestamp,
                    caller=caller,
                    service_provider_account_number=(
                        self._credentials.service_provider_account_number
                    ),
                    signature=signature,
                )

            envelope = build_envelope(operation, request, auth_for)
            if len(signed) != 1:
                raise SigningError("SIGNATURE_NOT_UNIQUE")
            timestamp, signature = signed[0]
            self._signatures.append(SecretValue(signature))
            check_envelope(
                envelope,
                endpoint=endpoint,
                operation=operation,
                allow_writes=self._allow_writes,
            )
            transport = self._transport
            if transport is None:
                transport = AiohttpTransport()
                self._transport = transport
            started = self._monotonic()
            try:
                reply = await transport.post(endpoint_url(endpoint), envelope, operation)
            except (TransportTimeoutError, asyncio.CancelledError):
                # Cut off by a timeout, or cancelled by the caller's own deadline: IWS may still
                # be working on the call, so the next one waits.
                self._cooldown_until = self._monotonic() + TIMEOUT_COOLDOWN_S
                raise
            duration = self._monotonic() - started
            # This call's signature is the newest in the history.
            echoes = (
                *(issued.reveal() for issued in reversed(self._signatures)),
                self._credentials.secret_key.reveal(),
            )
            body = redact_echoes(reply.body, echoes)
            check_clock(reply.date_header, self._clock())
            outcome = _outcome(reply.status, body)
            return SitestResult(
                http_status=reply.status,
                outcome=outcome,
                signed_timestamp=timestamp,
                duration_s=duration,
                body=body,
            )

    async def close(self) -> None:
        """Close the transport, if one was opened."""
        if self._transport is not None:
            await self._transport.close()
            self._transport = None
