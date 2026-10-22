"""Secrets read once from standard input.

``StdinSecretsProvider`` reads named secrets piped on standard input into ``SecretValue``
objects for one recorder run: no file, no environment variable, no AWS (design
``docs/design/s2-recorder-masker.md`` §6.2, §7.2). The recorder also parses each decrypted
age file through ``from_stream`` (``recorder.agefiles``), so both paths apply the same checks.

Input format: one JSON object whose keys are secret names and whose values are non-empty
strings, for example ``{"sitest.iws_username": "...", "sitest.secret_key": "..."}``.
Names are lower-case ``[a-z0-9._-]``. Duplicate names, other value types and input over
64 KiB are refused.

Standard input is read at most once per process, and never from a terminal, where typed
secrets would be echoed and kept in scrollback. Errors name a secret, never a value, and
never include the input.
"""

import json
import re
import sys
from collections.abc import Mapping
from typing import IO, ClassVar, Final, final

from airtimesat_platform.common.secrets import SecretNotAvailableError, SecretValue

MAX_INPUT_BYTES: Final = 64 * 1024
_NAME: Final = re.compile(r"\A[a-z0-9][a-z0-9._-]{0,63}\Z")


def _no_duplicates(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise SecretNotAvailableError("secret input repeats a name")
        result[key] = value
    return result


@final
class StdinSecretsProvider:
    """A ``SecretsProvider`` over secrets read once from a pipe."""

    _stdin_consumed: ClassVar[bool] = False

    def __init__(self, secrets: Mapping[str, SecretValue]) -> None:
        """Hold already-parsed ``secrets``; use ``from_stdin`` or ``from_stream``."""
        self._secrets = dict(secrets)

    @classmethod
    def from_stdin(cls) -> "StdinSecretsProvider":
        """Read the process's standard input, once."""
        if cls._stdin_consumed:
            raise SecretNotAvailableError("standard input was already read for secrets")
        cls._stdin_consumed = True
        return cls.from_stream(sys.stdin.buffer)

    @classmethod
    def from_stream(cls, stream: IO[bytes]) -> "StdinSecretsProvider":
        """Read and parse the whole of ``stream``, which must not be a terminal."""
        if stream.isatty():
            raise SecretNotAvailableError("secrets must be piped, not typed at a terminal")
        raw = stream.read(MAX_INPUT_BYTES + 1)
        if len(raw) > MAX_INPUT_BYTES:
            raise SecretNotAvailableError("secret input is larger than 64 KiB")
        try:
            data: object = json.loads(raw.decode("utf-8"), object_pairs_hook=_no_duplicates)
        except (UnicodeDecodeError, ValueError, RecursionError):
            # RecursionError: input nested deeply enough to exhaust the JSON parser.
            raise SecretNotAvailableError("secret input is not a UTF-8 JSON object") from None
        finally:
            del raw
        if not isinstance(data, dict):
            raise SecretNotAvailableError("secret input is not a UTF-8 JSON object")
        secrets: dict[str, SecretValue] = {}
        for name, value in data.items():  # pyright: ignore[reportUnknownVariableType]
            if not isinstance(name, str) or not _NAME.fullmatch(name):
                raise SecretNotAvailableError("secret input has an invalid name")
            if not isinstance(value, str) or not value:
                raise SecretNotAvailableError(f"secret {name!r} is not a non-empty string")
            secrets[name] = SecretValue(value)
        return cls(secrets)

    def names(self) -> frozenset[str]:
        """Return the names of the secrets held (never their values)."""
        return frozenset(self._secrets)

    def get_secret(self, name: str) -> SecretValue:
        """Return the secret called ``name`` or raise ``SecretNotAvailableError``."""
        try:
            return self._secrets[name]
        except KeyError:
            raise SecretNotAvailableError(f"secret {name!r} was not provided") from None
