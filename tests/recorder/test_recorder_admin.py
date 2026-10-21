"""``keys init``, ``backup``, ``incident clear`` and the configuration file (design §6.2, §6.3)."""

import io
import json
import os
import stat
import sys
import threading
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from airtimesat_platform.common.secrets import SecretValue
from airtimesat_platform.masker.keys import MaskingKeys, decode_key
from airtimesat_platform.recorder.__main__ import main
from airtimesat_platform.recorder.admin import BACKUP_RETENTION, prune_backups
from airtimesat_platform.recorder.config import load_config
from airtimesat_platform.recorder.errors import RecorderError
from airtimesat_platform.recorder.run import KEY_NAMES, MASKING_KEYS
from airtimesat_platform.recorder.store import DB_NAME, Incident, open_store

NOW = datetime(2026, 10, 21, 12, 0, tzinfo=UTC)
RECIPIENT = "age1" + "q" * 58


@pytest.fixture(autouse=True)
def restore_hooks(monkeypatch: pytest.MonkeyPatch) -> None:
    """Put the test runner's exception hooks back after ``main`` installs the safe ones."""
    monkeypatch.setattr(sys, "excepthook", sys.excepthook)
    monkeypatch.setattr(sys, "unraisablehook", sys.unraisablehook)
    monkeypatch.setattr(threading, "excepthook", threading.excepthook)


def write_config(tmp_path: Path, **override: str) -> Path:
    values = {
        "data_dir": str(tmp_path / "data"),
        "checkout": str(tmp_path / "checkout"),
        "backup_recipient": RECIPIENT,
        "backup_dir": str(tmp_path / "backups"),
    } | override
    path = tmp_path / "recorder.toml"
    lines = [f'{key} = "{value}"' for key, value in values.items() if value != "-"]
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return path


def cli(*argv: str) -> tuple[int, str]:
    out = io.StringIO()
    return main(list(argv), out=out, now=lambda: NOW), out.getvalue()


# ---------------------------------------------------------------- keys init


class Terminal(io.StringIO):
    def isatty(self) -> bool:
        return True


def test_keys_init_refuses_a_terminal() -> None:
    out = Terminal()
    assert main(["keys", "init"], out=out) == 1
    assert out.getvalue() == "REFUSED KEYS_TO_TERMINAL\n"


def keys_through_a_pipe() -> tuple[int, str]:
    """Run ``keys init`` with standard output on a pipe, as into the Keeper CLI."""
    read_fd, write_fd = os.pipe()
    with os.fdopen(write_fd, "w", encoding="utf-8") as writer:
        code = main(["keys", "init"], out=writer)
    with os.fdopen(read_fd, encoding="utf-8") as reader:
        return code, reader.read()


def test_keys_init_writes_four_distinct_keys_the_masker_accepts() -> None:
    code, text = keys_through_a_pipe()
    assert code == 0
    keys = json.loads(text)
    assert list(keys) == list(KEY_NAMES)
    assert len(set(keys.values())) == 4
    assert all(len(value) == 64 for value in keys.values())
    MaskingKeys.from_secrets(*(SecretValue(keys[name]) for name in MASKING_KEYS))
    decode_key(SecretValue(keys["masker.inventory_key"]))
    assert keys_through_a_pipe()[1] != text


def test_keys_init_refuses_a_file_or_a_stream_without_a_descriptor(tmp_path: Path) -> None:
    # Design §6.2: the keys go to the Keeper CLI, never to a file.
    target = tmp_path / "keys.json"
    with target.open("w", encoding="utf-8") as handle:
        assert main(["keys", "init"], out=handle) == 1
    assert target.read_text(encoding="utf-8") == "REFUSED KEYS_NOT_PIPED\n"
    assert cli("keys", "init") == (1, "REFUSED KEYS_NOT_PIPED\n")


# ---------------------------------------------------------------- configuration


def test_a_valid_configuration(tmp_path: Path) -> None:
    config = load_config(write_config(tmp_path))
    assert config.data_dir == (tmp_path / "data").resolve()
    assert config.backup_recipient == RECIPIENT


@pytest.mark.parametrize(
    ("override", "code"),
    [
        ({"extra": "x"}, "CONFIG_UNKNOWN_KEY"),
        ({"backup_dir": "-"}, "CONFIG_MISSING_KEY backup_dir"),
        ({"backup_recipient": "age1short"}, "CONFIG_INVALID_RECIPIENT backup_recipient"),
        ({"data_dir": "relative/data"}, "CONFIG_PATH_NOT_ABSOLUTE data_dir"),
        ({"data_dir": "CHECKOUT/data"}, "CONFIG_PATH_IN_CHECKOUT data_dir"),
        ({"backup_dir": "CHECKOUT"}, "CONFIG_PATH_IN_CHECKOUT backup_dir"),
    ],
)
def test_configuration_refusals(tmp_path: Path, override: dict[str, str], code: str) -> None:
    checkout = str(tmp_path / "checkout")
    values = {k: v.replace("CHECKOUT", checkout) for k, v in override.items()}
    with pytest.raises(RecorderError) as info:
        load_config(write_config(tmp_path, **values))
    assert str(info.value) == code


def test_an_unreadable_or_invalid_configuration(tmp_path: Path) -> None:
    with pytest.raises(RecorderError) as info:
        load_config(tmp_path / "absent.toml")
    assert info.value.code == "CONFIG_UNREADABLE"
    bad = tmp_path / "bad.toml"
    bad.write_text("data_dir = [", encoding="utf-8")
    with pytest.raises(RecorderError) as info:
        load_config(bad)
    assert info.value.code == "CONFIG_INVALID"
    assert cli("backup", "--config", str(bad)) == (1, "REFUSED CONFIG_INVALID\n")


# ---------------------------------------------------------------- backup


@pytest.fixture(name="fake_age")
def fake_age_fixture(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Put an ``age`` on PATH that records its arguments and input size, and writes no plaintext."""
    folder = tmp_path / "bin"
    folder.mkdir()
    script = folder / "age"
    script.write_text(
        f"#!{sys.executable}\n"
        "import os, sys\n"
        "data = sys.stdin.buffer.read()\n"
        "if os.environ.get('FAKE_AGE_FAIL'):\n"
        "    sys.exit(1)\n"
        "head = data[:16].hex()\n"
        "sys.stdout.write(f'fake-age {sys.argv[1]} {sys.argv[2]} {len(data)} {head}')\n",
        encoding="utf-8",
    )
    script.chmod(0o700)
    monkeypatch.setenv("PATH", f"{folder}{os.pathsep}{os.environ['PATH']}")
    return script


def files_with_plaintext(root: Path) -> list[Path]:
    """Every file under ``root`` holding a SQLite database, except the vault itself."""
    return [
        p
        for p in root.rglob("*")
        if p.is_file() and p.name != DB_NAME and b"SQLite format 3" in p.read_bytes()
    ]


def test_backup_pipes_the_snapshot_through_age(tmp_path: Path, fake_age: Path) -> None:
    config = write_config(tmp_path)
    with open_store(tmp_path / "data") as store:
        store.add_recorder_requests(["req-1"], "RP-2026-003", "r")
    code, text = cli("backup", "--config", str(config))
    name = "vault-20261021T120000Z.sqlite.age"
    assert code == 0
    assert text.splitlines()[0] == f"BACKUP_WRITTEN {name} pruned=0"
    target = tmp_path / "backups" / name
    assert stat.S_IMODE(target.stat().st_mode) == 0o600
    _, flag, recipient, size, head = target.read_text(encoding="utf-8").split()
    assert (flag, recipient) == ("-r", RECIPIENT)
    assert int(size) > 0
    assert bytes.fromhex(head) == b"SQLite format 3\0"
    assert files_with_plaintext(tmp_path) == []


def test_a_failed_age_leaves_no_file(
    tmp_path: Path, fake_age: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("FAKE_AGE_FAIL", "1")
    config = write_config(tmp_path)
    open_store(tmp_path / "data").close()
    assert cli("backup", "--config", str(config)) == (1, "REFUSED BACKUP_FAILED\n")
    assert list((tmp_path / "backups").iterdir()) == []
    assert files_with_plaintext(tmp_path) == []


def test_backup_without_age_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("PATH", str(tmp_path / "empty"))
    config = write_config(tmp_path)
    open_store(tmp_path / "data").close()
    assert cli("backup", "--config", str(config)) == (1, "REFUSED BACKUP_FAILED\n")


def test_backups_older_than_30_days_are_deleted(tmp_path: Path, fake_age: Path) -> None:
    folder = tmp_path / "backups"
    folder.mkdir()
    old = NOW - BACKUP_RETENTION - timedelta(minutes=1)
    recent = NOW - BACKUP_RETENTION + timedelta(minutes=1)
    for when in (old, recent):
        (folder / f"vault-{when:%Y%m%dT%H%M%SZ}.sqlite.age").write_text("x", encoding="utf-8")
    (folder / "notes.txt").write_text("x", encoding="utf-8")
    open_store(tmp_path / "data").close()
    assert prune_backups(folder, NOW) == 1
    assert sorted(p.name for p in folder.iterdir()) == [
        "notes.txt",
        f"vault-{recent:%Y%m%dT%H%M%SZ}.sqlite.age",
    ]
    code, text = cli("backup", "--config", str(write_config(tmp_path)))
    assert code == 0
    assert "pruned=0" in text


def test_backup_waits_for_no_run(tmp_path: Path, fake_age: Path) -> None:
    config = write_config(tmp_path)
    with open_store(tmp_path / "data"):
        assert cli("backup", "--config", str(config)) == (1, "REFUSED VAULT_LOCKED\n")


# ---------------------------------------------------------------- incident clear


def test_incident_clear_re_enables_the_method(tmp_path: Path) -> None:
    config = write_config(tmp_path)
    with open_store(tmp_path / "data") as store:
        incident = store.add_incident(
            Incident("r", "RP-2026-003", "accountSearch", 0, "MASKING_BLOCKED", "", "", True), NOW
        )
    assert cli("incident", "clear", str(incident), "--config", str(config)) == (
        0,
        f"INCIDENT_CLEARED {incident} operation=accountSearch\n",
    )
    assert cli("incident", "clear", str(incident), "--config", str(config)) == (
        1,
        "REFUSED INCIDENT_NOT_OPEN\n",
    )


def test_backup_and_incident_clear_never_create_a_vault(tmp_path: Path, fake_age: Path) -> None:
    # A wrong data_dir must not produce an empty "successful" backup or a new vault.
    config = write_config(tmp_path)
    assert cli("backup", "--config", str(config)) == (1, "REFUSED VAULT_MISSING\n")
    assert cli("incident", "clear", "1", "--config", str(config)) == (
        1,
        "REFUSED VAULT_MISSING\n",
    )
    assert not (tmp_path / "data").exists()
    assert not (tmp_path / "backups").exists()
