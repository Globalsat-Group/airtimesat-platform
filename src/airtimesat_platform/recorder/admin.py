"""``recorder keys init``, ``recorder backup`` and ``recorder incident clear``.

- ``keys init`` (design §6.2) generates the four 256-bit masking keys once and writes one
  JSON object of name-to-hex pairs to standard output, for the Keeper CLI to store. It
  writes only to a pipe or a socket: never to a terminal (scrollback) or a file.
- ``backup`` (§6.3) snapshots the vault with SQLite's backup API into memory and pipes the
  bytes through ``age`` to the configured recipient: no plaintext file, ever. It writes
  ``vault-<UTC>.sqlite.age`` and deletes backups older than 30 days in the backup folder.
- ``incident clear`` (§8.4) marks an incident cleared and returns the method it re-enables.
"""

import json
import os
import re
import secrets
import stat
import subprocess
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Final, TextIO

from airtimesat_platform.masker.keys import KEY_BYTES
from airtimesat_platform.recorder.config import Config
from airtimesat_platform.recorder.errors import RecorderError
from airtimesat_platform.recorder.run import KEY_NAMES
from airtimesat_platform.recorder.store import open_store

BACKUP_RETENTION: Final = timedelta(days=30)
BACKUP_NAME: Final = re.compile(r"vault-([0-9]{8}T[0-9]{6}Z)\.sqlite\.age")
AGE_TIMEOUT_S: Final = 300


def keys_init(out: TextIO) -> None:
    """Write four new keys as one JSON object; refuse anything but a pipe or a socket."""
    if out.isatty():
        raise RecorderError("KEYS_TO_TERMINAL")
    try:
        mode = os.fstat(out.fileno()).st_mode
    except (OSError, ValueError):
        mode = 0
    if not (stat.S_ISFIFO(mode) or stat.S_ISSOCK(mode)):
        raise RecorderError("KEYS_NOT_PIPED")
    keys = {name: secrets.token_hex(KEY_BYTES) for name in KEY_NAMES}
    out.write(json.dumps(keys) + "\n")
    out.flush()


def prune_backups(folder: Path, now: datetime) -> int:
    """Delete the backups in ``folder`` older than 30 days (by the time in their name)."""
    deleted = 0
    for path in folder.iterdir():
        m = BACKUP_NAME.fullmatch(path.name)
        if m is None or not path.is_file():
            continue
        taken = datetime.strptime(m.group(1), "%Y%m%dT%H%M%SZ").replace(tzinfo=UTC)
        if taken < now - BACKUP_RETENTION:
            path.unlink()
            deleted += 1
    return deleted


def backup(config: Config, now: datetime) -> tuple[Path, int]:
    """Write an age-encrypted vault backup; return its path and the number of old ones deleted."""
    with open_store(config.data_dir, create=False) as store:
        data = store.snapshot()
    config.backup_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    target = config.backup_dir / f"vault-{now.astimezone(UTC):%Y%m%dT%H%M%SZ}.sqlite.age"
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(target, flags, 0o600)
    except OSError:
        raise RecorderError("BACKUP_UNWRITABLE") from None
    returncode = None
    try:
        with os.fdopen(fd, "wb") as handle:
            returncode = subprocess.run(  # noqa: S603 - fixed program; the recipient is checked
                ["age", "-r", config.backup_recipient],  # noqa: S607 - age from PATH
                input=data,
                stdout=handle,
                stderr=subprocess.DEVNULL,
                check=False,
                timeout=AGE_TIMEOUT_S,
            ).returncode
    except (OSError, subprocess.TimeoutExpired):
        returncode = None
    finally:
        del data
    if returncode != 0 or target.stat().st_size == 0:
        target.unlink(missing_ok=True)
        raise RecorderError("BACKUP_FAILED")
    return target, prune_backups(config.backup_dir, now)


def incident_clear(config: Config, incident_id: int, now: datetime) -> str:
    """Clear an open incident; return the method it re-enables (empty for a run-level one)."""
    with open_store(config.data_dir, create=False) as store:
        operation = store.clear_incident(incident_id, now)
    if operation is None:
        raise RecorderError("INCIDENT_NOT_OPEN")
    return operation
