"""The vault store on the trusted machine: one SQLite file (design §6.1, §6.4, §5.8, §8.4).

It implements the masker's ``VaultStore`` (vault rows, tombstones, known values) and holds
the recorder's own tables: the run log, incidents, the IWS request ids of recorder calls,
and, for S2 PR D3, the test inventory and derived accounts (schema only).

Real values appear in the file only as AES-GCM ciphertext written by the masker's vault;
every other column is a code, a count, a time, a surrogate or a keyed hash. The file is
created with mode 0600 and held under an exclusive SQLite lock for as long as the store is
open, so there is one writer.
"""

import os
import sqlite3
from collections.abc import Generator, Iterable, Set
from contextlib import contextmanager
from dataclasses import asdict, dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Final, Self, cast

from airtimesat_platform.masker.errors import VaultError
from airtimesat_platform.masker.tokenize.vault import VaultRow
from airtimesat_platform.recorder.errors import RecorderError

DB_NAME: Final = "vault.sqlite"
# Working periods (design §6.4, §13 #15).
VALUE_RETENTION: Final = timedelta(days=90)
RUN_LOG_RETENTION: Final = timedelta(days=548)  # 18 months

SCHEMA: Final = """
CREATE TABLE IF NOT EXISTS vault (
    type TEXT NOT NULL, surrogate TEXT NOT NULL, counter INTEGER NOT NULL,
    ciphertext BLOB, first_seen TEXT NOT NULL, last_seen TEXT NOT NULL,
    PRIMARY KEY (type, surrogate));
CREATE TABLE IF NOT EXISTS known_values (digest BLOB PRIMARY KEY, last_seen TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS run_log (
    id INTEGER PRIMARY KEY, run_utc TEXT NOT NULL, plan_id TEXT NOT NULL,
    commit_sha TEXT NOT NULL, plan_digest TEXT NOT NULL, kind TEXT NOT NULL,
    dry_run INTEGER NOT NULL, started_utc TEXT NOT NULL, ended_utc TEXT NOT NULL,
    decision TEXT NOT NULL, call_index INTEGER, call_id TEXT, operation TEXT, endpoint TEXT,
    code TEXT, outcome TEXT, iws_duration_ms INTEGER, caller TEXT, signed_ts TEXT,
    iws_request_id TEXT, dropped INTEGER, detector_hits INTEGER, cooldown_until TEXT);
CREATE TABLE IF NOT EXISTS incidents (
    id INTEGER PRIMARY KEY, created_utc TEXT NOT NULL, run_utc TEXT NOT NULL,
    plan_id TEXT NOT NULL, operation TEXT NOT NULL, call_index INTEGER, code TEXT NOT NULL,
    path TEXT NOT NULL, detector TEXT NOT NULL, blocks_method INTEGER NOT NULL,
    cleared_utc TEXT);
CREATE TABLE IF NOT EXISTS recorder_requests (
    iws_request_id TEXT PRIMARY KEY, plan_id TEXT NOT NULL, run_utc TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS test_inventory (
    type TEXT NOT NULL, surrogate TEXT NOT NULL, service TEXT NOT NULL,
    value_hmac BLOB NOT NULL, registered_utc TEXT NOT NULL, PRIMARY KEY (type, surrogate));
CREATE TABLE IF NOT EXISTS derived_accounts (
    plan_id TEXT NOT NULL, surrogate TEXT NOT NULL, derived_utc TEXT NOT NULL,
    PRIMARY KEY (plan_id, surrogate));
"""


def utc_text(when: datetime) -> str:
    """Return a UTC time in the one text form the store compares (sortable)."""
    return when.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _utc(text: str) -> datetime:
    return datetime.strptime(text, "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=UTC)


@dataclass(frozen=True, slots=True)
class LogRow:
    """One run-log row (design §5.8): codes, counts, times and ids only, never a value."""

    run_utc: str
    plan_id: str
    commit_sha: str
    plan_digest: str
    dry_run: bool
    started_utc: str
    ended_utc: str
    decision: str
    kind: str = "read"
    call_index: int | None = None
    call_id: str | None = None
    operation: str | None = None
    endpoint: str | None = None
    code: str | None = None
    outcome: str | None = None
    iws_duration_ms: int | None = None
    caller: str | None = None
    signed_ts: str | None = None
    iws_request_id: str | None = None
    dropped: int | None = None
    detector_hits: int | None = None
    cooldown_until: str | None = None


@dataclass(frozen=True, slots=True)
class Incident:
    """One incident (design §8.4): where and why, never a value."""

    run_utc: str
    plan_id: str
    operation: str
    call_index: int | None
    code: str
    path: str = ""
    detector: str = ""
    blocks_method: bool = False


class SqliteStore:
    """The vault store, the run log and the incidents in one locked SQLite file."""

    def __init__(self, db: sqlite3.Connection) -> None:
        """Wrap an open, locked connection; use ``open_store``."""
        self._db = db

    def __enter__(self) -> Self:
        """Return the store."""
        return self

    def __exit__(self, *_: object) -> None:
        """Close the store and release the lock."""
        self.close()

    def close(self) -> None:
        """Close the connection, which releases the lock."""
        self._db.close()

    @contextmanager
    def transaction(self) -> Generator[None]:
        """Make the writes inside one transaction: all of them, or none if anything raises."""
        self._db.execute("BEGIN")
        with self._db:  # commits, or rolls back on an exception
            yield

    def _one(self, sql: str, *args: object) -> tuple[object, ...] | None:
        return cast(tuple[object, ...] | None, self._db.execute(sql, args).fetchone())

    # ------------------------------------------------------------ masker.VaultStore

    def get(self, type_name: str, surrogate: str) -> VaultRow | None:
        """Return the row for ``(type, surrogate)``, tombstones included, or ``None``."""
        row = self._one(
            "SELECT counter, ciphertext, first_seen, last_seen FROM vault"
            " WHERE type = ? AND surrogate = ?",
            type_name,
            surrogate,
        )
        if row is None:
            return None
        counter, ciphertext, first, last = row
        return VaultRow(
            type_name,
            surrogate,
            cast(int, counter),
            cast(bytes | None, ciphertext),
            _utc(cast(str, first)),
            _utc(cast(str, last)),
        )

    def insert(self, row: VaultRow) -> None:
        """Add a row to a free slot; ``VAULT_WRITE_FAILED`` if it is taken or the write fails."""
        try:
            self._db.execute(
                "INSERT INTO vault VALUES (?, ?, ?, ?, ?, ?)",
                (
                    row.type_name,
                    row.surrogate,
                    row.counter,
                    row.ciphertext,
                    utc_text(row.first_seen),
                    utc_text(row.last_seen),
                ),
            )
        except sqlite3.Error:
            raise VaultError("VAULT_WRITE_FAILED") from None

    def touch(self, type_name: str, surrogate: str, when: datetime) -> None:
        """Set the row's last-seen time."""
        self._db.execute(
            "UPDATE vault SET last_seen = ? WHERE type = ? AND surrogate = ?",
            (utc_text(when), type_name, surrogate),
        )

    def count(self, type_name: str) -> int:
        """Return the number of rows of a type, tombstones included."""
        row = self._one("SELECT COUNT(*) FROM vault WHERE type = ?", type_name)
        return cast(int, row[0]) if row else 0

    def add_known_value(self, digest: bytes, when: datetime) -> None:
        """Record the keyed hash of a real name-like value, or refresh its last-seen time."""
        self._db.execute(
            "INSERT INTO known_values VALUES (?, ?)"
            " ON CONFLICT (digest) DO UPDATE SET last_seen = excluded.last_seen",
            (digest, utc_text(when)),
        )

    def has_known_value(self, digest: bytes) -> bool:
        """Return whether a keyed hash is in the known-value set."""
        return self._one("SELECT 1 FROM known_values WHERE digest = ?", digest) is not None

    # ------------------------------------------------------------ retention (§6.4)

    def apply_retention(self, now: datetime, protected: Set[str]) -> int:
        """Tombstone vault values unused for 90 days; drop old known values and log rows.

        Test inventory and the surrogates in ``protected`` (named by a plan still within its
        validity) never expire. A tombstone keeps its slot and forgets its value (§13 #30).
        Returns the number of values tombstoned.
        """
        cutoff = utc_text(now - VALUE_RETENTION)
        rows = cast(
            list[tuple[str, str]],
            self._db.execute(
                "SELECT type, surrogate FROM vault v WHERE ciphertext IS NOT NULL"
                " AND last_seen < ? AND NOT EXISTS (SELECT 1 FROM test_inventory t"
                " WHERE t.type = v.type AND t.surrogate = v.surrogate)",
                (cutoff,),
            ).fetchall(),
        )
        expired = [(t, s) for t, s in rows if s not in protected]
        self._db.executemany(
            "UPDATE vault SET ciphertext = NULL WHERE type = ? AND surrogate = ?", expired
        )
        self._db.execute("DELETE FROM known_values WHERE last_seen < ?", (cutoff,))
        self._db.execute(
            "DELETE FROM run_log WHERE started_utc < ?", (utc_text(now - RUN_LOG_RETENTION),)
        )
        return len(expired)

    # ------------------------------------------------------------ run log and incidents

    def log(self, row: LogRow) -> None:
        """Append a run-log row."""
        fields = asdict(row)
        names = ", ".join(fields)
        marks = ", ".join(f":{name}" for name in fields)
        self._db.execute(f"INSERT INTO run_log ({names}) VALUES ({marks})", fields)  # noqa: S608 - column names from LogRow

    def cooldown_until(self) -> datetime | None:
        """Return the latest cooldown end any run recorded after a timeout (§5.8)."""
        row = self._one("SELECT MAX(cooldown_until) FROM run_log")
        return _utc(cast(str, row[0])) if row and row[0] else None

    def add_incident(self, incident: Incident, now: datetime) -> int:
        """Record an incident; return its id."""
        cursor = self._db.execute(
            "INSERT INTO incidents (created_utc, run_utc, plan_id, operation, call_index, code,"
            " path, detector, blocks_method) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                utc_text(now),
                incident.run_utc,
                incident.plan_id,
                incident.operation,
                incident.call_index,
                incident.code,
                incident.path,
                incident.detector,
                int(incident.blocks_method),
            ),
        )
        return cast(int, cursor.lastrowid)

    def open_incidents(self, operations: Iterable[str]) -> list[tuple[int, str]]:
        """Return ``(id, operation)`` of the open incidents that block one of ``operations``.

        A blocking run-level incident (no operation, such as a staging-scan hit) blocks every
        operation.
        """
        wanted = set(operations)
        rows = cast(
            list[tuple[int, str]],
            self._db.execute(
                "SELECT id, operation FROM incidents"
                " WHERE cleared_utc IS NULL AND blocks_method = 1 ORDER BY id"
            ).fetchall(),
        )
        return [(n, op) for n, op in rows if op in wanted or not op]

    def clear_incident(self, incident_id: int, now: datetime) -> str | None:
        """Clear an open incident; return the method it blocked, or ``None`` if none is open."""
        row = self._one(
            "SELECT operation FROM incidents WHERE id = ? AND cleared_utc IS NULL", incident_id
        )
        if row is None:
            return None
        self._db.execute(
            "UPDATE incidents SET cleared_utc = ? WHERE id = ?", (utc_text(now), incident_id)
        )
        return cast(str, row[0])

    # ------------------------------------------------------------ recorder request ids

    def add_recorder_requests(self, ids: Iterable[str], plan_id: str, run_utc: str) -> None:
        """Remember IWS request ids that the IWS log shows as recorder calls (§5.3)."""
        self._db.executemany(
            "INSERT OR IGNORE INTO recorder_requests VALUES (?, ?, ?)",
            [(i, plan_id, run_utc) for i in ids],
        )

    def is_recorder_request(self, iws_request_id: str) -> bool:
        """Return whether an IWS request id belongs to a recorder call."""
        row = self._one("SELECT 1 FROM recorder_requests WHERE iws_request_id = ?", iws_request_id)
        return row is not None

    # ------------------------------------------------------------ backup (§6.3)

    def snapshot(self) -> bytes:
        """Return a consistent copy of the database, taken in memory with the backup API."""
        memory = sqlite3.connect(":memory:")
        try:
            self._db.backup(memory)
            return memory.serialize()
        finally:
            memory.close()


def open_store(data_dir: Path, *, create: bool = True) -> SqliteStore:
    """Open (or create) the vault in ``data_dir``, mode 0600, and lock it for this process.

    Refuses with ``VAULT_LOCKED`` while another process holds it. With ``create`` false, a
    missing vault is refused with ``VAULT_MISSING`` instead of created empty.
    """
    path = data_dir / DB_NAME
    if not create and not path.is_file():
        raise RecorderError("VAULT_MISSING")
    flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0)
    try:
        data_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
        os.close(os.open(path, flags, 0o600))
        os.chmod(path, 0o600)
    except OSError:
        raise RecorderError("VAULT_UNAVAILABLE") from None
    db = sqlite3.connect(path, timeout=0, isolation_level=None)
    code = "VAULT_LOCKED"
    try:
        db.execute("PRAGMA locking_mode = EXCLUSIVE")
        # Zero freed bytes: a tombstoned ciphertext must not survive in free pages, in the
        # file or in a backup taken from it (§6.4). Many SQLite builds leave this off.
        db.execute("PRAGMA secure_delete = ON")
        # The first write takes the exclusive lock, which the connection then keeps.
        db.execute("BEGIN EXCLUSIVE")
        db.execute("COMMIT")
        code = "VAULT_UNAVAILABLE"
        db.executescript(SCHEMA)
    except sqlite3.Error:
        db.close()
        raise RecorderError(code) from None
    return SqliteStore(db)
