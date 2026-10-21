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
recorder to hand to the masker. It is absent until the WSDL harvest, and then every
``recorder check`` fails closed.
"""

import asyncio
import re
import time
from collections import deque
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from email.utils import parsedate_to_datetime
from importlib import resources
from typing import Final, Protocol

from airtimesat_platform.common.secrets import (
    SecretNotAvailableError,
    SecretsProvider,
    SecretValue,
)

# Endpoint and TransportTimeoutError are re-exported: the port's call takes the one and
# raises the other, and the recorder may import nothing else from the gateway.
from airtimesat_platform.gateway.endpoints_sitest import Endpoint as Endpoint
from airtimesat_platform.gateway.endpoints_sitest import endpoint_url
from airtimesat_platform.gateway.envelope import AuthFields, build_envelope
from airtimesat_platform.gateway.errors import (
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

# Names of the SITEST record's fields as piped by the Keeper CLI (common.secrets_stdin).
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
