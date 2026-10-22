"""The recorder's age files in ``data_dir`` and the age calls on them (design §6.2, §13 #34).

- ``recorder-identity.age``: an age X25519 identity encrypted with the CTO's passphrase
  (``age -p``), the only thing the passphrase protects. Its public recipient is the
  configuration's ``backup_recipient``, which also encrypts the vault backups.
- ``masker-keys.json.age`` (the four ``masker.*`` keys) and ``sitest.json.age`` (the
  ``sitest.*`` names): one JSON object each, encrypted to that recipient (``age -r``).

When ``recorder run``'s standard input is a terminal, ``load_secret_files`` decrypts the
identity once (age asks for the passphrase on the terminal, never on standard input), then
each needed file with ``age -d -i -``, the identity on age's standard input. A dry run never
opens ``sitest.json.age``. The identity and the JSON exist only in this process's memory and
in the pipes to and from age: never in an argument, an environment variable, a file or the
terminal. age's own error messages, which hold no secret, reach the terminal.
"""

import io
import os
import re
import secrets
import subprocess
from collections.abc import Sequence
from pathlib import Path
from typing import Final

from airtimesat_platform.common.secrets import SecretNotAvailableError, SecretValue
from airtimesat_platform.common.secrets_stdin import StdinSecretsProvider
from airtimesat_platform.recorder.errors import RecorderError

IDENTITY: Final = "recorder-identity.age"
MASKER_KEYS: Final = "masker-keys.json.age"
SITEST: Final = "sitest.json.age"
# Each secrets file and the prefix of every name it may hold.
PREFIXES: Final = {MASKER_KEYS: "masker.", SITEST: "sitest."}
# The comment line age-keygen writes into every identity.
PUBLIC_KEY: Final = re.compile(rb"^# public key: (\S+)$", re.MULTILINE)
# Long enough for the CTO to type a passphrase (twice for ``age -p``).
AGE_TIMEOUT_S: Final = 300


def age(args: Sequence[str], data: bytes = b"", *, program: str = "age") -> bytes | None:
    """Run ``program`` (age or age-keygen) with fixed arguments and ``data`` on its stdin.

    Return its standard output, or ``None`` if it failed. Its standard error, where age
    writes its errors (never a secret), goes to the terminal; age-keygen's is dropped.
    """
    try:
        result = subprocess.run(  # noqa: S603 - fixed program, arguments from the recorder
            [program, *args],
            input=data,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL if program == "age-keygen" else None,
            check=False,
            timeout=AGE_TIMEOUT_S,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    return result.stdout if result.returncode == 0 else None


def write_new(target: Path, args: Sequence[str], data: bytes) -> None:
    """Encrypt ``data`` with ``age <args>`` into ``target``, which must not exist yet.

    age writes a temporary file next to it, which is then linked into place (a link never
    replaces a file). The temporary file is removed whatever happens.
    """
    temp = target.with_name(f".{target.name}.{secrets.token_hex(8)}.tmp")
    try:
        if age([*args, "-o", str(temp)], data) is None or not temp.is_file():
            raise RecorderError("INIT_AGE_FAILED", target.name)
        temp.chmod(0o600)
        os.link(temp, target)
    except FileExistsError:
        raise RecorderError("INIT_FILE_EXISTS", target.name) from None
    except OSError:
        raise RecorderError("INIT_WRITE_FAILED", target.name) from None
    finally:
        temp.unlink(missing_ok=True)


def recipient_of(identity: bytes) -> str:
    """Return the public recipient on an identity's ``# public key:`` line, or ``""``."""
    found = PUBLIC_KEY.search(identity)
    return found.group(1).decode("ascii", "replace") if found else ""


def load_secret_files(data_dir: Path, *, dry_run: bool, recipient: str) -> StdinSecretsProvider:
    """Decrypt the identity once, then the masker keys and, for a live run, the SITEST file.

    The identity must belong to ``recipient`` (the configuration's ``backup_recipient``),
    else new files and vault backups would go to another key. Each file is parsed and
    checked as standard input would be (``StdinSecretsProvider``), and may hold only its own
    names.
    """
    names = [MASKER_KEYS] if dry_run else [MASKER_KEYS, SITEST]
    for name in (IDENTITY, *names):
        if not (data_dir / name).is_file():
            raise RecorderError("SECRETS_FILE_MISSING", name)
    identity = age(["-d", str(data_dir / IDENTITY)])
    if identity is None:
        raise RecorderError("SECRETS_DECRYPT_FAILED", IDENTITY)
    loaded: dict[str, SecretValue] = {}
    try:
        if recipient_of(identity) != recipient:
            raise RecorderError("IDENTITY_RECIPIENT_MISMATCH", IDENTITY)
        for name in names:
            plain = age(["-d", "-i", "-", str(data_dir / name)], identity)
            if plain is None:
                raise RecorderError("SECRETS_DECRYPT_FAILED", name)
            try:
                provider = StdinSecretsProvider.from_stream(io.BytesIO(plain))
            finally:
                del plain
            for key in provider.names():
                if not key.startswith(PREFIXES[name]):
                    raise SecretNotAvailableError(f"{name} holds a name of another file")
                loaded[key] = provider.get_secret(key)
    finally:
        del identity
    return StdinSecretsProvider(loaded)
