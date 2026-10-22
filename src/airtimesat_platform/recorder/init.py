"""``recorder init``: the one-time setup of the recorder's files (design §6.2, runbook 03 Part D).

Idempotent, and it never overwrites: each file is made only if missing. It first makes the
dry-run checks of reviewed code (``checkout``) on the checkout its own code comes from,
because it generates keys. Then, in this order, so that no prompt follows age's work (text
typed ahead of a prompt would echo):

1. If ``sitest.json.age`` is missing: three hidden prompts (``getpass``) for the SITEST
   record. The values are checked and held in memory only.
2. If ``recorder-identity.age`` is missing: ``age-keygen`` into memory, piped to ``age -p``,
   which asks for the new passphrase twice on the terminal. Its public key is the recipient;
   if the file exists, the recipient comes from the configuration.
3. The configuration, if missing (mode 0600): the four keys, never a secret.
4. If ``masker-keys.json.age`` is missing, and only if there is no vault: four new keys,
   generated in process, piped to ``age -r <recipient>``. Only with a new identity, or with
   ``--new-keys`` (runbook 06 case 4); otherwise the file is restored from Keeper.
5. The SITEST values of step 1, piped to ``age -r <recipient>``.

Before the first prompt the process is hardened like ``recorder run`` (``hardening``).
Refusals carry a code and a key or file name, never a value. To redo ``sitest.json.age``
after a rotation, delete it and run ``recorder init`` again.

``recorder rekey`` (an exposed passphrase, runbook 06 case 7) decrypts both secrets files
with the current identity (the old passphrase, once), makes a new identity under a new
passphrase, encrypts both files to it, moves the three old files into ``retired-<UTC>`` in
``data_dir`` and points the configuration at the new recipient. The keys stay the same.
"""

import contextlib
import getpass
import hashlib
import json
import os
import shutil
import warnings
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Final, TextIO

from airtimesat_platform.common.secrets import SecretNotAvailableError
from airtimesat_platform.gateway.sitest_port import (
    SECRET_IWS_USERNAME,
    SECRET_KEY,
    SECRET_SP_ACCOUNT,
)
from airtimesat_platform.recorder import checkout as checkout_module
from airtimesat_platform.recorder.admin import new_keys
from airtimesat_platform.recorder.agefiles import (
    IDENTITY,
    MASKER_KEYS,
    PREFIXES,
    SITEST,
    age,
    load_secret_files,
    recipient_of,
    write_new,
)
from airtimesat_platform.recorder.checkout import code_checkout, verify_checkout
from airtimesat_platform.recorder.config import AGE_RECIPIENT, DEFAULT_PATH, Config, load_config
from airtimesat_platform.recorder.errors import RecorderError
from airtimesat_platform.recorder.hardening import harden_process
from airtimesat_platform.recorder.store import DB_NAME

PROMPTS: Final = (
    (SECRET_IWS_USERNAME, "SITEST username: "),
    (SECRET_KEY, "SITEST secret key: "),
    (SECRET_SP_ACCOUNT, "SP account number (Enter if none): "),
)
REMINDER: Final = (
    "Next: attach recorder-identity.age and masker-keys.json.age to the Keeper record and "
    "give the escrow its copies (runbook 03 Part D).\n"
    "sitest.json.age stays in data_dir: never copy it.\n"
)

Prompt = Callable[[str], str]


def hidden_prompt(text: str) -> str:
    """Ask on the terminal with echo off; refuse rather than fall back to echoed input."""
    with warnings.catch_warnings():
        warnings.simplefilter("error", getpass.GetPassWarning)
        try:
            return getpass.getpass(text)
        except getpass.GetPassWarning:
            raise RecorderError("INIT_NO_TERMINAL") from None


def _sitest_values(prompt: Prompt) -> dict[str, str]:
    """Ask for the SITEST record; refuse an empty or malformed value by its name only."""
    values: dict[str, str] = {}
    for name, text in PROMPTS:
        value = prompt(text)
        if not value and name == SECRET_SP_ACCOUNT:
            continue
        if not value:
            raise RecorderError("INIT_SITEST_EMPTY", name)
        if not value.isprintable() or value != value.strip():
            raise RecorderError("INIT_SITEST_INVALID", name)
        values[name] = value
    return values


def _new_identity(target: Path) -> str:
    """Generate an identity straight into ``age -p``; return its public recipient."""
    identity = age([], program="age-keygen")
    if identity is None:
        raise RecorderError("INIT_AGE_FAILED", "age-keygen")
    try:
        recipient = recipient_of(identity)
        if not AGE_RECIPIENT.fullmatch(recipient):
            raise RecorderError("INIT_AGE_FAILED", "age-keygen")
        write_new(target, ["-p"], identity)
    finally:
        del identity
    return recipient


def _write_config(file: Path, data_dir: Path, checkout: Path, recipient: str, backup: Path) -> None:
    """Create the configuration file, mode 0600; never replace one."""
    values = {
        "data_dir": str(data_dir),
        "checkout": str(checkout),
        "backup_recipient": recipient,
        "backup_dir": str(backup),
    }
    file.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(file, flags, 0o600)
    except OSError:
        raise RecorderError("INIT_CONFIG_UNWRITABLE") from None
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        handle.writelines(f"{key} = {json.dumps(value)}\n" for key, value in values.items())


def _check_config(config: Config, wanted: dict[str, Path]) -> None:
    """Refuse a configuration that names other folders or another checkout."""
    found = {
        "data_dir": config.data_dir,
        "backup_dir": config.backup_dir,
        "checkout": config.checkout,
    }
    for key, path in wanted.items():
        if found[key] != path:
            raise RecorderError("INIT_CONFIG_MISMATCH", key)


def init(
    data_dir: Path,
    backup_dir: Path,
    *,
    config_path: Path | None,
    out: TextIO,
    prompt: Prompt | None = None,
    code: Path | None = None,
    new_masker_keys: bool = False,
) -> None:
    """Create whatever is missing of the identity, configuration and secrets files.

    Masking keys are made only with a new identity, or with ``new_masker_keys``
    (``--new-keys``, runbook 06 case 4): a missing keys file next to an existing identity
    is restored from Keeper, never replaced by new keys.
    """
    ask = prompt or hidden_prompt
    code = code or checkout_module.CODE
    checkout = code_checkout(code)
    wanted = {"data_dir": data_dir, "backup_dir": backup_dir}
    for key, path in wanted.items():
        if not path.is_absolute():
            raise RecorderError("INIT_PATH_NOT_ABSOLUTE", key)
        wanted[key] = path.resolve()
        if wanted[key].is_relative_to(checkout):
            raise RecorderError("INIT_PATH_IN_CHECKOUT", key)
    data_dir, backup_dir = wanted["data_dir"], wanted["backup_dir"]
    verify_checkout(checkout, None, dry_run=True, code=code)
    config_file = (config_path or DEFAULT_PATH).expanduser()
    config = load_config(config_file) if config_file.exists() else None
    if config is not None:
        _check_config(config, wanted | {"checkout": checkout})
    files = {name: data_dir / name for name in (IDENTITY, MASKER_KEYS, SITEST)}
    if config is not None and not files[IDENTITY].exists():
        raise RecorderError("INIT_IDENTITY_MISSING", IDENTITY)
    if config is None and files[IDENTITY].exists():
        raise RecorderError("INIT_CONFIG_MISSING")
    for name in (MASKER_KEYS, SITEST):
        # A new identity could not open a file encrypted to an earlier one.
        if config is None and files[name].exists():
            raise RecorderError("INIT_FILE_WITHOUT_IDENTITY", name)
    if not files[MASKER_KEYS].exists():
        if (data_dir / DB_NAME).exists():
            raise RecorderError("INIT_VAULT_EXISTS", DB_NAME)
        if config is not None and not new_masker_keys:
            raise RecorderError("INIT_KEYS_MISSING", MASKER_KEYS)

    def done(created: bool, name: str) -> None:
        out.write(f"{'CREATED' if created else 'EXISTS'} {name}\n")
        out.flush()

    harden_process()  # before the first secret enters memory; age inherits the core limit
    previous_umask = os.umask(0o077)
    try:
        for folder in (data_dir, backup_dir):
            folder.mkdir(mode=0o700, parents=True, exist_ok=True)
            folder.chmod(0o700)
        sitest = None if files[SITEST].exists() else _sitest_values(ask)
        if config is None:
            recipient = _new_identity(files[IDENTITY])
            done(True, IDENTITY)
            _write_config(config_file, data_dir, checkout, recipient, backup_dir)
            done(True, config_file.name)
        else:
            recipient = config.backup_recipient
            done(False, IDENTITY)
            done(False, config_file.name)
        if not files[MASKER_KEYS].exists():
            write_new(files[MASKER_KEYS], ["-r", recipient], json.dumps(new_keys()).encode())
            done(True, MASKER_KEYS)
        else:
            done(False, MASKER_KEYS)
        if sitest is not None:
            write_new(files[SITEST], ["-r", recipient], json.dumps(sitest).encode())
            done(True, SITEST)
        else:
            done(False, SITEST)
        del sitest
    finally:
        os.umask(previous_umask)
    digest = hashlib.sha256(files[MASKER_KEYS].read_bytes()).hexdigest()
    out.write(f"RECIPIENT {recipient}\nMASKER_KEYS_SHA256 {digest}\n{REMINDER}")


def rekey(
    config_path: Path | None, *, out: TextIO, now: datetime, code: Path | None = None
) -> None:
    """Re-encrypt both secrets files to a new identity under a new passphrase."""
    code = code or checkout_module.CODE
    checkout = code_checkout(code)
    verify_checkout(checkout, None, dry_run=True, code=code)
    config_file = (config_path or DEFAULT_PATH).expanduser()
    config = load_config(config_file)
    _check_config(config, {"checkout": checkout})
    data = config.data_dir
    harden_process()
    try:  # the old passphrase, once
        provider = load_secret_files(data, dry_run=False, recipient=config.backup_recipient)
    except SecretNotAvailableError:
        raise RecorderError("SECRETS_UNREADABLE") from None
    staged = data / f".rekey-{now.astimezone(UTC):%Y%m%dT%H%M%SZ}"
    retired = data / f"retired-{now.astimezone(UTC):%Y%m%dT%H%M%SZ}"
    new_config = config_file.with_name(f".{config_file.name}.rekey")
    previous_umask = os.umask(0o077)
    moved = finished = False
    try:
        staged.mkdir(mode=0o700)
        retired.mkdir(mode=0o700)
        recipient = _new_identity(staged / IDENTITY)  # the new passphrase, twice
        for name, prefix in PREFIXES.items():
            names = sorted(n for n in provider.names() if n.startswith(prefix))
            plain = json.dumps({n: provider.get_secret(n).reveal() for n in names}).encode()
            write_new(staged / name, ["-r", recipient], plain)
            del plain
        _write_config(new_config, data, checkout, recipient, config.backup_dir)
        shutil.copy2(config_file, retired / config_file.name)
        # The configuration follows the identity at once: the new identity never sits next
        # to the old recipient.
        moved = True
        (data / IDENTITY).rename(retired / IDENTITY)
        (staged / IDENTITY).rename(data / IDENTITY)
        os.replace(new_config, config_file)
        for name in (MASKER_KEYS, SITEST):
            (data / name).rename(retired / name)
            (staged / name).rename(data / name)
        finished = True
    except OSError as exc:
        if moved:
            # Half swapped: the old files and configuration are in ``retired``, the new ones
            # stay in ``staged``. Runbook 06 case 7 puts the old ones back.
            raise RecorderError("REKEY_INCOMPLETE", retired.name) from None
        if isinstance(exc, FileExistsError):
            raise RecorderError("REKEY_IN_PROGRESS") from None
        raise RecorderError("REKEY_FAILED") from None
    finally:
        os.umask(previous_umask)
        if finished or not moved:
            shutil.rmtree(staged, ignore_errors=True)
        new_config.unlink(missing_ok=True)
        with contextlib.suppress(OSError):
            retired.rmdir()  # only when nothing was retired
    out.write(f"RETIRED {retired.name}\nRECIPIENT {recipient}\n")
    digest = hashlib.sha256((data / MASKER_KEYS).read_bytes()).hexdigest()
    out.write(f"MASKER_KEYS_SHA256 {digest}\n{REMINDER}")
