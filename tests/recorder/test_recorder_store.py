"""The SQLite vault store (design §6.1, §6.4, §13 #30).

Round trips, tombstones, retention, file mode and the one-writer lock. Real-format values
are canaries built at run time.
"""

import sqlite3
import stat
from collections.abc import Callable
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest

from airtimesat_platform.masker.detect.canary import canary
from airtimesat_platform.masker.errors import VaultError
from airtimesat_platform.masker.keys import MaskingKeys
from airtimesat_platform.masker.tokenize.vault import Vault
from airtimesat_platform.recorder.errors import RecorderError
from airtimesat_platform.recorder.store import (
    DB_NAME,
    Incident,
    LogRow,
    SqliteStore,
    open_store,
    utc_text,
)

NOW = datetime(2026, 10, 21, 12, 0, tzinfo=UTC)
Keys = Callable[[int], MaskingKeys]


@pytest.fixture(name="data_dir")
def data_dir_fixture(tmp_path: Path) -> Path:
    return tmp_path / "data"


def vault_at(store: SqliteStore, keys: MaskingKeys, when: datetime) -> Vault:
    return Vault(store, keys, clock=lambda: when)


def row(started: datetime, **fields: Any) -> LogRow:
    base = LogRow(
        run_utc="20261021T120000Z",
        plan_id="RP-2026-003",
        commit_sha="0" * 40,
        plan_digest="f" * 64,
        dry_run=False,
        started_utc=utc_text(started),
        ended_utc=utc_text(started),
        decision="sent",
    )
    return replace(base, **fields)


def tombstoned(store: SqliteStore, type_name: str, surrogate: str) -> bool:
    stored = store.get(type_name, surrogate)
    assert stored is not None
    return stored.tombstone


def test_the_file_is_private_and_values_are_ciphertext(data_dir: Path, keys_factory: Keys) -> None:
    imei = canary("IMEI", 41)
    with open_store(data_dir) as store:
        surrogate = vault_at(store, keys_factory(1), NOW).issue("IMEI", imei)
    path = data_dir / DB_NAME
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert stat.S_IMODE(data_dir.stat().st_mode) == 0o700
    raw = path.read_bytes()
    assert imei.encode() not in raw
    assert surrogate.encode() in raw
    with open_store(data_dir) as store:
        assert vault_at(store, keys_factory(1), NOW).resolve("IMEI", surrogate) == imei


def test_round_trip_of_rows_and_known_values(data_dir: Path, keys_factory: Keys) -> None:
    with open_store(data_dir) as store:
        vault = vault_at(store, keys_factory(1), NOW)
        name = "Canary Vessel 41"
        surrogate = vault.issue("VESSEL", name)
        vault.add_known(name)
        assert store.count("VESSEL") == 1
        assert vault.is_known(name.upper())
        stored = store.get("VESSEL", surrogate)
        assert stored is not None
        assert (stored.counter, stored.first_seen, stored.tombstone) == (0, NOW, False)
        store.touch("VESSEL", surrogate, NOW + timedelta(days=1))
        assert store.get("VESSEL", surrogate) == stored.__class__(
            "VESSEL", surrogate, 0, stored.ciphertext, NOW, NOW + timedelta(days=1)
        )
        with pytest.raises(VaultError) as info:
            store.insert(stored)
        assert info.value.code == "VAULT_WRITE_FAILED"
        assert store.get("VESSEL", "Vessel-aaaaaaaa") is None


def test_one_writer_at_a_time(data_dir: Path) -> None:
    store = open_store(data_dir)
    with pytest.raises(RecorderError) as info:
        open_store(data_dir)
    assert info.value.code == "VAULT_LOCKED"
    store.close()
    open_store(data_dir).close()


def test_an_unusable_data_folder(tmp_path: Path) -> None:
    (tmp_path / "file").write_text("x", encoding="utf-8")
    with pytest.raises(RecorderError) as info:
        open_store(tmp_path / "file" / "data")
    assert info.value.code == "VAULT_UNAVAILABLE"


# ---------------------------------------------------------------- retention (§6.4)


def test_retention_tombstones_old_values_and_keeps_their_slot(
    data_dir: Path, keys_factory: Keys
) -> None:
    keys = keys_factory(1)
    old, fresh = canary("IMEI", 42), canary("IMEI", 43)
    then = NOW - timedelta(days=91)
    with open_store(data_dir) as store:
        old_surrogate = vault_at(store, keys, then).issue("IMEI", old)
        fresh_surrogate = vault_at(store, keys, NOW - timedelta(days=89)).issue("IMEI", fresh)
        vault_at(store, keys, then).add_known("Canary Name 42")
        assert store.apply_retention(NOW, protected=set()) == 1
        assert tombstoned(store, "IMEI", old_surrogate)
        vault = vault_at(store, keys, NOW)
        with pytest.raises(VaultError) as info:
            vault.resolve("IMEI", old_surrogate)
        assert info.value.code == "IDENTIFIER_NOT_ISSUED"
        assert vault.resolve("IMEI", fresh_surrogate) == fresh
        assert not vault.is_known("Canary Name 42")
        # The value comes back: a new surrogate at the next counter; the old slot stays.
        again = vault.issue("IMEI", old)
        assert again != old_surrogate
        new_row = store.get("IMEI", again)
        assert new_row is not None
        assert new_row.counter == 1
        assert store.count("IMEI") == 3


def test_retention_spares_test_inventory_and_plan_surrogates(
    data_dir: Path, keys_factory: Keys
) -> None:
    keys = keys_factory(1)
    then = NOW - timedelta(days=200)
    with open_store(data_dir) as store:
        vault = vault_at(store, keys, then)
        inventory = vault.issue("IMEI", canary("IMEI", 44))
        planned = vault.issue("IMEI", canary("IMEI", 45))
        other = vault.issue("IMEI", canary("IMEI", 46))
    with sqlite3.connect(data_dir / DB_NAME) as db:
        db.execute(
            "INSERT INTO test_inventory VALUES (?, ?, ?, ?, ?)",
            ("IMEI", inventory, "SBD", b"\0" * 32, utc_text(then)),
        )
    db.close()
    with open_store(data_dir) as store:
        assert store.apply_retention(NOW, protected={planned}) == 1
        assert [tombstoned(store, "IMEI", s) for s in (inventory, planned, other)] == [
            False,
            False,
            True,
        ]


def test_retention_leaves_no_ciphertext_in_the_file(
    data_dir: Path, keys_factory: Keys, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Many SQLite builds leave secure_delete off: start each connection with it off.
    connect = sqlite3.connect
    opened: list[sqlite3.Connection] = []

    def insecure(*args: Any, **kwargs: Any) -> sqlite3.Connection:
        db = connect(*args, **kwargs)
        db.execute("PRAGMA secure_delete = OFF")
        opened.append(db)
        return db

    monkeypatch.setattr(sqlite3, "connect", insecure)
    then = NOW - timedelta(days=91)
    with open_store(data_dir) as store:
        assert opened[0].execute("PRAGMA secure_delete").fetchone() == (1,)
        vault = vault_at(store, keys_factory(1), then)
        surrogates = [vault.issue("IMEI", canary("IMEI", 50 + n)) for n in range(50)]
        stored = store.get("IMEI", surrogates[3])
        assert stored is not None
        assert stored.ciphertext is not None
        assert store.apply_retention(NOW, protected=set(surrogates) - {surrogates[3]}) == 1
    assert stored.ciphertext not in (data_dir / DB_NAME).read_bytes()


def test_retention_deletes_run_log_rows_older_than_18_months(data_dir: Path) -> None:
    with open_store(data_dir) as store:
        store.log(row(NOW - timedelta(days=549), call_id="old"))
        store.log(row(NOW - timedelta(days=500), call_id="kept"))
        store.apply_retention(NOW, protected=set())
    with sqlite3.connect(data_dir / DB_NAME) as db:
        ids = [r[0] for r in db.execute("SELECT call_id FROM run_log")]
    db.close()
    assert ids == ["kept"]


# ---------------------------------------------------------------- run log and incidents


def test_the_cooldown_is_the_latest_one_any_run_recorded(data_dir: Path) -> None:
    with open_store(data_dir) as store:
        assert store.cooldown_until() is None
        store.log(row(NOW, cooldown_until=utc_text(NOW + timedelta(seconds=60))))
        store.log(row(NOW, cooldown_until=utc_text(NOW + timedelta(seconds=10))))
        store.log(row(NOW))
    with open_store(data_dir) as store:
        assert store.cooldown_until() == NOW + timedelta(seconds=60)


def test_incidents_block_their_method_until_cleared(data_dir: Path) -> None:
    with open_store(data_dir) as store:
        blocking = store.add_incident(
            Incident(
                "r", "RP-2026-003", "accountSearch", 0, "MASKING_BLOCKED", "a/b", "IMEI", True
            ),
            NOW,
        )
        store.add_incident(Incident("r", "RP-2026-003", "getVessels", 1, "TRANSPORT_TIMEOUT"), NOW)
        assert store.open_incidents(["accountSearch", "getVessels"]) == [
            (blocking, "accountSearch")
        ]
        assert store.open_incidents(["getVessels"]) == []
        assert store.clear_incident(blocking, NOW) == "accountSearch"
        assert store.clear_incident(blocking, NOW) is None
        assert store.clear_incident(999, NOW) is None
        assert store.open_incidents(["accountSearch"]) == []


def test_recorder_request_ids(data_dir: Path) -> None:
    with open_store(data_dir) as store:
        store.add_recorder_requests(["req-1", "req-2", "req-1"], "RP-2026-003", "r")
        assert store.is_recorder_request("req-2")
        assert not store.is_recorder_request("req-3")


def test_the_snapshot_is_a_whole_database(data_dir: Path, keys_factory: Keys) -> None:
    with open_store(data_dir) as store:
        surrogate = vault_at(store, keys_factory(1), NOW).issue("IMEI", canary("IMEI", 47))
        data = store.snapshot()
    assert data.startswith(b"SQLite format 3\0")
    copy = sqlite3.connect(":memory:")
    copy.deserialize(data)
    assert copy.execute("SELECT surrogate FROM vault").fetchall() == [(surrogate,)]
    copy.close()
