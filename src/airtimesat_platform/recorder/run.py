"""``recorder run <plan> [--dry-run]``: read calls from a reviewed plan (design §5.1).

In order; any refusal before step 5 stops the run before any IWS call:

1. Reviewed code only (``checkout``): a clean checkout of a commit on ``origin/main``.
2. Process hardening, before standard input is read: no core dumps; on Linux, not dumpable.
3. The masking keys, and for a live run the SITEST record, from standard input.
4. Checks: ``recorder check`` again; every surrogate in the plan issued
   (``IDENTIFIER_NOT_ISSUED``, §5.5); no open incident on a planned method; for a live run,
   no pending cooldown after an earlier run's timeout (§5.8).
5. Calls, one at a time: resolve references on earlier masked responses, unmask, call the
   SITEST port as ``rec.<plan-id>``, filter the IWS log by caller, mask, and only then write
   the masked request and response to the staging folder (``output``).
6. Fail closed: on any refusal, block, exception or timeout nothing is written for that call,
   an incident is recorded (codes and paths only), the run stops and exits non-zero. A hit or
   an unknown element also refuses the method until the incident is cleared (§8.4). An
   exception, interrupt, SIGTERM or SIGHUP that escapes the run deletes the staging folder
   unscanned.
7. Before git: the manifest, then the scans of the staging folder (``output``).

A dry run does steps 1 to 4, shows each masked request with its verdict, records the plan
digest in the run log, and never contacts IWS.

The terminal carries allowlisted fields only (``masker.logsafe``); the one exception is a
dry run's masked request, which is the reviewed plan's own text.
"""

import asyncio
import contextlib
import ctypes
import logging
import re
import resource
import signal
import sys
import time
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Final, TextIO, override
from xml.sax.saxutils import escape

from airtimesat_platform.common.secrets import SecretNotAvailableError
from airtimesat_platform.common.secrets_stdin import StdinSecretsProvider
from airtimesat_platform.gateway.sitest_port import (
    SECRET_IWS_USERNAME,
    SECRET_KEY,
    TIMEOUT_COOLDOWN_S,
    Endpoint,
    InProcessSitestPort,
    SitestCredentials,
    SitestPort,
    TransportTimeoutError,
)
from airtimesat_platform.masker.detect.scan import REDACTED
from airtimesat_platform.masker.engine import MaskingEngine
from airtimesat_platform.masker.errors import (
    MaskingBlockedError,
    MaskingError,
    RequestRefusedError,
)
from airtimesat_platform.masker.fieldmap.loader import build_field_map
from airtimesat_platform.masker.iwslog import LOG_ENTRY, filter_callers
from airtimesat_platform.masker.keys import MaskingKeys
from airtimesat_platform.masker.logsafe import ALLOWED_FIELDS, SafeLogFilter
from airtimesat_platform.masker.tokenize.surrogates import SPECS
from airtimesat_platform.masker.tokenize.vault import Vault
from airtimesat_platform.masker.xmlsafe import (
    MAX_REQUEST_BYTES,
    MAX_RESPONSE_BYTES,
    Element,
    local_name,
    parse,
    serialize,
)
from airtimesat_platform.recorder.checkout import CODE, verify_checkout
from airtimesat_platform.recorder.config import Config
from airtimesat_platform.recorder.errors import PlanRefusedError, RecorderError
from airtimesat_platform.recorder.output import (
    Finding,
    Scanner,
    Staging,
    secret_hit,
    secret_needles,
    tool_scan,
)
from airtimesat_platform.recorder.plan import (
    Call,
    FieldMapContext,
    Plan,
    check_plan,
    load_plan,
    read_plan_file,
)
from airtimesat_platform.recorder.policy.allowlist import ITEM, LIMITS
from airtimesat_platform.recorder.store import Incident, LogRow, SqliteStore, open_store, utc_text

EXIT_OK: Final = 0
EXIT_FAILED: Final = 1

# Names of the masker-keys record's fields as piped by the Keeper CLI (names, not values).
MASKING_KEYS: Final = ("masker.k_mask", "masker.vault_key", "masker.known_value_key")
KEY_NAMES: Final = (*MASKING_KEYS, "masker.inventory_key")
SITEST_SECRETS: Final = (SECRET_IWS_USERNAME, SECRET_KEY)
# Distinct subscriber records per run (design §5.3, *Inferred*), counted as contract surrogates.
RECORD_CAP: Final = 500
SUBSCRIBER: Final = SPECS["CONTRACT"]
IWS_LOG: Final = "getIwsRequests"
# Its input may name only an IWS request id of a recorder call (§5.3). The WSDL names the
# input requestId, as the IWS log entries name their id.
IWS_REQUEST: Final = "getIwsRequest"
REQUEST_ID: Final = "requestId"
# Its input is queueEntryId. The WSDL confirms queue entries are their own id space (a queue
# entry's id; no IWS request id in it), and D2's reads create no queue entry, so no recorded
# id could match: refused until the recorder records queue entry ids of its own writes.
QUEUE_ENTRY: Final = "getQueueEntry"
# Fail-closed failures that write nothing and stop the run but leave the method enabled (§8.4):
# an exception, a timeout, the vault or a key, a non-SOAP or oversized body, too many rows.
# Every other masking code (a hit, an unknown element) refuses the method until cleared.
NOT_BLOCKING: Final = frozenset(
    {
        "MASKING_FAILED",
        "MASKING_TIMEOUT",
        "NON_SOAP_BODY",
        "XML_PARSE",
        "XML_TOO_LARGE",
        "TOO_MANY_ROWS",
        # The vault or a key (a wrong key, a corrupt row, a full surrogate space): no
        # field-map fix to the method can clear these.
        "VAULT_WRITE_FAILED",
        "VAULT_INTEGRITY",
        "COLLISION_LIMIT",
        "SURROGATE_SPACE_EXHAUSTED",
        "KEY_INVALID",
        "KEY_REUSED",
    }
)
PR_SET_DUMPABLE: Final = 4
_CODE: Final = re.compile(r"[A-Z][A-Z0-9_]{0,63}")
BACKUP_REMINDER: Final = "Next: run `recorder backup` and attach the file to Keeper (runbook 04).\n"

FieldMapSource = Callable[[], tuple[str, str] | None]
SecretsSource = Callable[[], StdinSecretsProvider]
PortFactory = Callable[[SitestCredentials], SitestPort]


def _utc_now() -> datetime:
    return datetime.now(UTC)


def harden_process() -> None:
    """No core dumps; on Linux, mark the process non-dumpable (design §5.1 step 2).

    Non-dumpable also stops other processes of the same user from reading its memory. Where
    the OS has no such call, it is skipped.
    """
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    if sys.platform.startswith("linux"):
        libc = ctypes.CDLL(None, use_errno=True)
        if libc.prctl(PR_SET_DUMPABLE, 0, 0, 0, 0) != 0:
            raise RecorderError("HARDENING_FAILED")


# ---------------------------------------------------------------- terminal output


class _Formatter(logging.Formatter):
    """``CODE key=value ...`` with the allowlisted fields only."""

    @override
    def format(self, record: logging.LogRecord) -> str:
        fields = [f"{k}={v}" for k, v in vars(record).items() if k in ALLOWED_FIELDS and v != ""]
        return " ".join([record.getMessage(), *fields])


class _Index:
    """The cross-call known values for the log filter, once the vault is open."""

    vault: Vault | None = None

    def is_known(self, value: str) -> bool:
        return self.vault is not None and self.vault.is_known(value)


class _Log:
    """The terminal: allowlisted, detector-checked records (``masker.logsafe``)."""

    def __init__(self, out: TextIO, index: _Index) -> None:
        self.out = out
        self.filter = SafeLogFilter(index=index)
        handler = logging.StreamHandler(out)
        handler.setFormatter(_Formatter())
        handler.addFilter(self.filter)
        self._logger = logging.getLogger("airtimesat.recorder.run")
        self._logger.handlers = [handler]
        self._logger.propagate = False
        self._logger.setLevel(logging.INFO)

    def emit(self, message: str, **fields: object) -> None:
        self._logger.info(message, extra=fields)

    def check(self, message: str, **fields: object) -> bool:
        """Return whether ``emit`` would print this record; trip the filter if not."""
        return self.filter.filter(logging.makeLogRecord({"msg": message, **fields}))


# ---------------------------------------------------------------- XML helpers


def _parse_request(text: str | bytes) -> Element:
    data = text.encode("utf-8") if isinstance(text, str) else text
    return parse(data, max_bytes=MAX_REQUEST_BYTES, request=True, error=RequestRefusedError)


def _leaf_values(root: Element, name: str) -> list[str]:
    return [e.text or "" for e in root.iter() if local_name(e) == name and not len(e)]


def _without_items(request: str) -> bytes:
    """Return the request with every ``${item}`` element removed, for the check before any call."""
    root = _parse_request(request)
    for element in list(root.iter()):
        parent = element.getparent()
        if element.text == ITEM and parent is not None:
            parent.remove(element)
    return serialize(root, declaration=False)


def _field_values(body: bytes, field: tuple[str, ...]) -> list[str]:
    """Values of the leaves whose path ends in ``field``, in document order (§5.2)."""
    root = parse(body, max_bytes=MAX_RESPONSE_BYTES, request=False, error=MaskingBlockedError)
    values: list[str] = []
    for element in root.iter():
        if len(element) or not (element.text or "").strip():
            continue
        names: list[str] = []
        node: Element | None = element
        while node is not None and len(names) < len(field):
            names.append(local_name(node))
            node = node.getparent()
        if tuple(reversed(names)) == field:
            values.append(element.text or "")
    return values


def _protected(checkout: Path, now: datetime, current: Plan) -> set[str]:
    """Surrogates named by plans still within their validity: retention keeps them (§6.4)."""
    plans = [current]
    folder = checkout / "recording-plans"
    for path in sorted(folder.glob("*.y*ml")) if folder.is_dir() else []:
        try:
            plans.append(load_plan(read_plan_file(str(path)), now=now))
        except PlanRefusedError:
            continue  # expired or invalid: it protects nothing
    values: set[str] = set()
    for plan in plans:
        for call in plan.calls:
            root = _parse_request(call.request)
            values |= {e.text for e in root.iter() if e.text and not len(e)}
    return values


# ---------------------------------------------------------------- the run


class _Runner:
    """One run's state after every check passed."""

    def __init__(
        self,
        *,
        plan: Plan,
        digest: str,
        commit: str,
        run_utc: str,
        store: SqliteStore,
        engine: MaskingEngine,
        vault: Vault,
        port: SitestPort | None,
        staging: Staging,
        log: _Log,
        now: Callable[[], datetime],
    ) -> None:
        self.plan, self.digest, self.commit = plan, digest, commit
        self.run_utc = run_utc
        self.store, self.engine, self.vault, self.port = store, engine, vault, port
        self.staging, self.log, self.now = staging, log, now
        self.caller = f"rec.{plan.id}"
        self.injected = [v.reveal() for v in port.auth_identifiers()] if port else []
        self.responses: dict[str, list[bytes]] = {}
        self.subscribers: set[str] = set()
        self.calls: list[dict[str, object]] = []
        self.stopped: str | None = None
        self.failed = False
        # The call sent and not yet answered, and the current call's IWS metadata (no body).
        self.in_flight: tuple[Call, datetime] | None = None
        self.answered: dict[str, Any] = {}

    def _row(self, call: Call, started: datetime, decision: str, **fields: Any) -> LogRow:
        return LogRow(
            run_utc=self.run_utc,
            plan_id=self.plan.id,
            commit_sha=self.commit,
            plan_digest=self.digest,
            dry_run=self.port is None,
            started_utc=utc_text(started),
            ended_utc=utc_text(self.now()),
            decision=decision,
            call_index=call.index,
            call_id=call.id,
            operation=call.operation,
            endpoint=call.endpoint,
            **fields,
        )

    # ------------------------------------------------------------ dry run

    def dry_run(self) -> None:
        """Show each masked request and its verdict; record the plan digest (§5.6 step 7)."""
        for call in self.plan.calls:
            started = self.now()
            self.log.emit("DRY_RUN_CALL", call_id=call.id, operation=call.operation)
            self.log.out.write(call.request.strip() + "\n")
            self.store.log(self._row(call, started, "would_send"))

    # ------------------------------------------------------------ live run

    async def live(self) -> None:
        """Make every call in order; stop at the first failure or at the record cap."""
        seq = 0
        for call in self.plan.calls:
            for n, item in enumerate(self._items(call)):
                seq += 1
                if not await self._call(call, n, item, seq) or self.stopped:
                    return

    def _items(self, call: Call) -> list[str | None]:
        reference = call.for_each
        if reference is None:
            return [None]
        values: list[str] = []
        for body in self.responses.get(reference.call, []):
            values += _field_values(body, reference.field)
        return list(values[reference.start : reference.stop])

    async def _call(self, call: Call, n: int, item: str | None, seq: int) -> bool:
        """One call; return False when the run must stop because it failed."""
        started = self.now()
        self.answered = {}
        request = call.request if item is None else call.request.replace(ITEM, escape(item))
        try:
            self._check_recorder_ids(call, request)
            context = self.engine.start_call(call.operation, self.injected)
            unmasked = self.engine.unmask_request(context, request.encode("utf-8"))
            body = self._set_by_recorder(call, unmasked.body)
            issued = sum(self.vault.issued.values())
            assert self.port is not None  # noqa: S101 - a live run has a port
            self.in_flight = (call, started)
            result = await self.port.call(
                Endpoint(call.endpoint), call.operation, body.decode("utf-8"), self.caller
            )
            self.in_flight = None
            duration_ms = round(result.duration_s * 1000)
            self.answered = {
                "outcome": result.outcome,
                "iws_duration_ms": duration_ms,
                "signed_ts": result.signed_timestamp,
            }
            context.known.add(result.signed_timestamp, REDACTED)
            raw, filtered = result.body, 0
            del result
            limit = self._row_limit(call, request)
            if call.operation == IWS_LOG:
                log = filter_callers(raw)
                raw, filtered = log.body, log.removed
                if limit is not None and log.kept + log.removed > limit:
                    raise MaskingBlockedError("TOO_MANY_ROWS")
            masked = self.engine.mask_response(context, raw, max_rows=limit)
            del raw
            subscribers = {s for s in masked.placed if SUBSCRIBER.is_surrogate_shape(s)}
            if len(self.subscribers | subscribers) > RECORD_CAP:
                self.stopped = "RECORD_CAP_REACHED"
                self._manifest_entry(seq, call, n, "not_written", self.stopped)
                self.store.log(
                    self._row(call, started, "not_written", code=self.stopped, **self.answered)
                )
                self.log.emit("RUN_STOPPED", call_id=call.id, code=self.stopped)
                return True
            new = sum(self.vault.issued.values()) - issued
            ok = {
                "call_id": call.id,
                "operation": call.operation,
                "outcome": self.answered["outcome"],
                "duration_ms": duration_ms,
                "dropped": masked.dropped,
                "issued": new,
                "count": filtered,
            }
            if not self.log.check("CALL_OK", **ok):
                raise RecorderError("LOG_BLOCKED")
            # The run-log row and the request ids record a written exchange: all or nothing.
            written = self.staging.write_exchange(
                seq, call.id, request.encode("utf-8"), masked.body
            )
            try:
                with self.store.transaction():
                    if call.operation == IWS_LOG:
                        ids = _field_values(masked.body, (LOG_ENTRY, REQUEST_ID))
                        self.store.add_recorder_requests(ids, self.plan.id, self.run_utc)
                    self.store.log(
                        self._row(
                            call,
                            started,
                            "sent",
                            caller=self.caller,
                            dropped=masked.dropped,
                            detector_hits=0,
                            **self.answered,
                        )
                    )
            except BaseException:
                for path in written:
                    path.unlink(missing_ok=True)
                raise
            self.log.emit("CALL_OK", **ok)
        except Exception as exc:  # fail closed: codes only, never the message
            self._fail(call, started, exc, seq, n)
            return False
        self.subscribers |= subscribers
        self.responses.setdefault(call.id, []).append(masked.body)
        self.calls.append(
            {
                "seq": seq,
                "call_id": call.id,
                "item": n,
                "operation": call.operation,
                "decision": "sent",
                "outcome": self.answered["outcome"],
                "iws_duration_ms": duration_ms,
                "elements_dropped": masked.dropped,
                "surrogates_issued": new,
                "filtered_log_entries": filtered,
            }
        )
        return True

    def _manifest_entry(self, seq: int, call: Call, n: int, decision: str, code: str) -> None:
        """Add the manifest entry of a call that was not written: its decision and code.

        If IWS answered, the entry keeps its outcome and duration too.
        """
        answered = {k: v for k, v in self.answered.items() if k != "signed_ts"}
        self.calls.append(
            {
                "seq": seq,
                "call_id": call.id,
                "item": n,
                "operation": call.operation,
                "decision": decision,
                "code": code,
                **answered,
            }
        )

    def _check_recorder_ids(self, call: Call, request: str) -> None:
        if call.operation != IWS_REQUEST:
            return
        values = _leaf_values(_parse_request(request), REQUEST_ID)
        if not values or not all(self.store.is_recorder_request(v) for v in values):
            raise RecorderError("REQUEST_ID_NOT_RECORDED")

    def _set_by_recorder(self, call: Call, body: bytes) -> bytes:
        """Set D1's ``set_by_recorder`` elements to the recorder's caller (§5.5 step 8).

        That is ``getQueueEntries.createdBy``: only the recorder's own entries come back. It is
        appended last, where the WSDL puts it (after ``endpoint`` and ``status``).
        """
        rules = LIMITS.get(call.operation)
        if rules is None or not rules.set_by_recorder:
            return body
        root = _parse_request(body)
        namespace = root.tag[1:].partition("}")[0] if root.tag.startswith("{") else ""
        for name in rules.set_by_recorder:
            element = root.makeelement(f"{{{namespace}}}{name}" if namespace else name)
            element.text = self.caller
            root.append(element)
        return serialize(root, declaration=False)

    def _row_limit(self, call: Call, request: str) -> int | None:
        """Return the rows a list read asked for: D1's first range for the method (§8.4)."""
        rules = LIMITS.get(call.operation)
        if rules is None or not rules.ranges:
            return None
        values = _leaf_values(_parse_request(request), rules.ranges[0].element)
        return int(values[0]) if values else None

    def _fail(self, call: Call, started: datetime, exc: Exception, seq: int, n: int) -> None:
        """Record the failure as codes only, write an incident, and stop the run."""
        self.failed = True
        self.in_flight = None
        code, path, detector = "CALL_FAILED", "", type(exc).__name__
        if isinstance(exc, MaskingError):
            code, path, detector = exc.code, exc.path, exc.detector
        elif isinstance(exc, PlanRefusedError):
            code, detector = exc.code, ""
        elif _CODE.fullmatch(gateway_code := str(getattr(exc, "code", ""))):
            # A gateway error: its code is a fixed constant, never text from IWS.
            code, detector = gateway_code, ""
        blocks = isinstance(exc, MaskingBlockedError) and code not in NOT_BLOCKING
        self._manifest_entry(seq, call, n, "blocked" if blocks else "failed", code)
        cooldown = None
        if isinstance(exc, TransportTimeoutError):
            cooldown = utc_text(self.now() + timedelta(seconds=TIMEOUT_COOLDOWN_S))
        incident = self.store.add_incident(
            Incident(
                self.run_utc, self.plan.id, call.operation, call.index, code, path, detector, blocks
            ),
            self.now(),
        )
        self.store.log(
            self._row(
                call,
                started,
                "blocked" if blocks else "failed",
                code=code,
                caller=self.caller,
                detector_hits=int(code == "MASKING_BLOCKED"),
                cooldown_until=cooldown,
                **self.answered,
            )
        )
        self.stopped = code
        self.log.emit(
            "CALL_BLOCKED" if blocks else "CALL_FAILED",
            call_id=call.id,
            operation=call.operation,
            code=code,
            path=path,
            detector=detector,
            incident=incident,
        )

    # ------------------------------------------------------------ before git

    def finish(self, checkout: Path, scanner: Scanner, needles: dict[bytes, str]) -> int:
        """Write the manifest, scan the staging folder, and print the summary."""
        if self.staging.files():
            self.staging.write_manifest(
                {
                    "plan_id": self.plan.id,
                    "commit": self.commit,
                    "plan_digest": self.digest,
                    "run_utc": self.run_utc,
                    "stopped": self.stopped,
                    "in_prefix": dict(sorted(self.vault.in_prefix.items())),
                    "in_canary_range": dict(sorted(self.vault.in_canary_range.items())),
                    "calls": self.calls,
                }
            )
            found = scanner(checkout, self.staging.path)
            hits = (found or []) + secret_hit(checkout, self.staging.files(), needles)
            if hits or found is None:
                return self._scan_failed(hits)
        self.log.emit(
            "RUN_STOPPED" if self.failed else "RUN_DONE",
            plan_id=self.plan.id,
            run_utc=self.run_utc,
            count=sum(c["decision"] == "sent" for c in self.calls),
            code=self.stopped or "",
        )
        self.log.out.write(BACKUP_REMINDER)
        return EXIT_FAILED if self.failed else EXIT_OK

    def _scan_failed(self, hits: list[Finding]) -> int:
        """Show where each finding is, delete the staging folder and record an incident.

        A finding is a run-level incident that refuses every run until it is cleared (§8.4);
        a scanner that could not run is not.
        """
        for path, detector in hits:
            self.log.emit("SCAN_FINDING", path=path, detector=detector)
        self._delete_staging()
        code = "STAGING_SCAN_HIT" if hits else "SCANNER_UNAVAILABLE"
        path, detector = hits[0] if hits else ("", "")
        incident = self.store.add_incident(
            Incident(self.run_utc, self.plan.id, "", None, code, path, detector, bool(hits)),
            self.now(),
        )
        self.log.emit("RUN_FAILED", code=code, incident=incident)
        return EXIT_FAILED

    def _delete_staging(self) -> None:
        try:
            self.staging.delete()
        except OSError:
            self.log.emit("STAGING_DELETE_FAILED", code="STAGING_DELETE_FAILED")

    def abort(self) -> None:
        """Clean up after an exception or interrupt escaped the run (§5.1 step 6).

        The scans did not finish, so delete the staging folder unscanned and record
        ``RUN_INTERRUPTED``. If a call was sent but not answered, keep its cooldown across
        runs: IWS may still be working on it (§5.8). Every step is attempted even if one
        before it fails.
        """
        self._delete_staging()
        pending, self.in_flight = self.in_flight, None
        call = pending[0] if pending else None
        with contextlib.suppress(Exception):
            self.store.add_incident(
                Incident(
                    self.run_utc,
                    self.plan.id,
                    call.operation if call else "",
                    call.index if call else None,
                    "RUN_INTERRUPTED",
                ),
                self.now(),
            )
        if pending is not None:
            with contextlib.suppress(Exception):
                cooldown = utc_text(self.now() + timedelta(seconds=TIMEOUT_COOLDOWN_S))
                self.store.log(
                    self._row(
                        pending[0],
                        pending[1],
                        "failed",
                        code="RUN_INTERRUPTED",
                        caller=self.caller,
                        cooldown_until=cooldown,
                    )
                )
        self.log.emit("RUN_FAILED", code="RUN_INTERRUPTED")


async def _live(runner: _Runner, port: SitestPort) -> None:
    try:
        await runner.live()
    finally:
        if isinstance(port, InProcessSitestPort):
            await port.close()


def _terminate(signum: int, _: object) -> None:
    """Raise on SIGTERM or SIGHUP, so that the run's abort path cleans up (§5.1 step 6).

    A closing terminal or a logout often sends a second signal; it is ignored from here on,
    so it cannot cut the clean-up short. The run restores the previous handlers at the end.
    """
    for number in (signal.SIGTERM, signal.SIGHUP):
        signal.signal(number, signal.SIG_IGN)
    raise SystemExit(128 + signum)


def _secrets(source: SecretsSource, dry_run: bool) -> StdinSecretsProvider:
    try:
        provider = source()
    except SecretNotAvailableError:
        raise RecorderError("SECRETS_UNREADABLE") from None
    names = provider.names()
    if dry_run and any(name.startswith("sitest.") for name in names):
        raise RecorderError("SITEST_SECRET_IN_DRY_RUN")
    required = MASKING_KEYS if dry_run else (*MASKING_KEYS, *SITEST_SECRETS)
    missing = [name for name in required if name not in names]
    if missing:
        raise RecorderError("SECRET_MISSING", missing[0])
    return provider


def run_plan(
    plan_path: Path,
    *,
    config: Config,
    dry_run: bool,
    out: TextIO,
    field_map_source: FieldMapSource,
    now: Callable[[], datetime] = _utc_now,
    secrets: SecretsSource = StdinSecretsProvider.from_stdin,
    port_factory: PortFactory = InProcessSitestPort,
    scanner: Scanner = tool_scan,
    monotonic: Callable[[], float] = time.monotonic,
    code_file: Path = CODE,
) -> int:
    """Run a plan, or dry-run it; return the exit code (0 done, 1 refused or stopped).

    ``code_file`` is a file of the running recorder; tests point it into their checkout.
    """
    index = _Index()
    log = _Log(out, index)
    try:
        commit = verify_checkout(config.checkout, plan_path, dry_run=dry_run, code=code_file)
        harden_process()
        provider = _secrets(secrets, dry_run)
        try:
            keys = MaskingKeys.from_secrets(*(provider.get_secret(n) for n in MASKING_KEYS))
            texts = field_map_source()
            if texts is None:
                raise RecorderError("FIELD_MAP_MISSING")
            field_map, templates = build_field_map(*texts)
            context = FieldMapContext(field_map)
        except MaskingError as exc:
            code = exc.code if exc.code.startswith("KEY_") else "FIELD_MAP_INVALID"
            raise RecorderError(code) from None
        started = now()
        run_utc = started.strftime("%Y%m%dT%H%M%SZ")
        checked = check_plan(read_plan_file(str(plan_path)), now=started, field_map=context)
        plan = checked.plan
        with open_store(config.data_dir) as store:
            store.apply_retention(started, _protected(config.checkout, started, plan))
            blocked = store.open_incidents(call.operation for call in plan.calls)
            if blocked:
                raise RecorderError("INCIDENT_OPEN", f"incident:{blocked[0][0]}")
            cooldown = store.cooldown_until()
            if not dry_run and cooldown is not None and cooldown > started:
                raise RecorderError("COOLDOWN_PENDING")
            vault = Vault(store, keys, clock=now)
            index.vault = vault
            port = None if dry_run else port_factory(SitestCredentials.from_provider(provider))
            sp_accounts = [v.reveal() for v in port.auth_identifiers()[1:]] if port else []
            engine = MaskingEngine(
                field_map,
                vault,
                templates=templates,
                constants={"SP": sp_accounts} if sp_accounts else {},
                # A dry run has no SITEST record: C values are checked on their form only.
                constants_by_shape=dry_run,
                clock=monotonic,
            )
            for call in plan.calls:
                if call.operation == QUEUE_ENTRY:
                    raise RecorderError("QUEUE_ENTRY_NOT_SUPPORTED", call.where)
                try:
                    engine.unmask_request(
                        engine.start_call(call.operation), _without_items(call.request)
                    )
                except RequestRefusedError as exc:
                    where = f"{call.where}/{exc.path}".rstrip("/")
                    detector = f"#{exc.detector}" if exc.detector else ""
                    raise RecorderError(exc.code, where + detector) from None
            runner = _Runner(
                plan=plan,
                digest=checked.digest,
                commit=commit,
                run_utc=run_utc,
                store=store,
                engine=engine,
                vault=vault,
                port=port,
                staging=Staging(config.checkout, plan.id, run_utc),
                log=log,
                now=now,
            )
            log.emit(
                "RUN_START",
                plan_id=plan.id,
                run_utc=runner.run_utc,
                decision="dry_run" if dry_run else "live",
            )
            if port is None:
                runner.dry_run()
                log.emit("DRY_RUN_DONE", plan_id=plan.id, count=len(plan.calls))
                return EXIT_OK
            # Closing the terminal or a shutdown must not skip the abort path either.
            previous = {n: signal.signal(n, _terminate) for n in (signal.SIGTERM, signal.SIGHUP)}
            try:
                asyncio.run(_live(runner, port))
                names = sorted(provider.names())
                needles = secret_needles((n, provider.get_secret(n)) for n in names)
                return runner.finish(config.checkout, scanner, needles)
            except BaseException:
                runner.abort()
                raise
            finally:
                for number, handler in previous.items():
                    signal.signal(number, handler)
    except PlanRefusedError as exc:
        index.vault = None  # the store is closed by now
        path, _, detector = exc.location.partition("#")
        log.emit("REFUSED", code=exc.code, path=path, detector=detector)
        return EXIT_FAILED
