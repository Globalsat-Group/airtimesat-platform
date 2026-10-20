"""Secrets access interface.

Code asks a ``SecretsProvider`` for a secret by name at the moment it needs it. No secret
value lives in code, settings, logs or fixtures. The AWS Secrets Manager provider comes
with the infrastructure; until then only ``UnconfiguredSecretsProvider`` exists, and it
refuses every request.
"""

from typing import Final, Protocol, final, override

_MASK: Final = "**********"


class SecretNotAvailableError(LookupError):
    """The secret cannot be provided. The message names the secret, never its value."""


@final
class SecretValue:
    """A secret value that does not print itself.

    ``str()`` and ``repr()`` return a mask, so a value passed to a logger or an exception
    by mistake does not leak. Call ``reveal()`` only where the raw value is handed to the
    system that needs it.
    """

    __slots__ = ("_value",)

    def __init__(self, value: str) -> None:
        """Wrap ``value``."""
        self._value = value

    def reveal(self) -> str:
        """Return the raw value."""
        return self._value

    @override
    def __repr__(self) -> str:
        """Return a mask."""
        return f"SecretValue({_MASK})"

    @override
    def __str__(self) -> str:
        """Return a mask."""
        return _MASK

    @override
    def __eq__(self, other: object) -> bool:
        """Compare raw values."""
        if not isinstance(other, SecretValue):
            return NotImplemented
        return self._value == other._value

    @override
    def __hash__(self) -> int:
        """Hash the raw value."""
        return hash(self._value)


class SecretsProvider(Protocol):
    """Source of secrets, such as AWS Secrets Manager."""

    def get_secret(self, name: str) -> SecretValue:
        """Return the secret called ``name`` or raise ``SecretNotAvailableError``."""
        ...


@final
class UnconfiguredSecretsProvider:
    """Provider used until a real one is wired in. Every request fails."""

    def get_secret(self, name: str) -> SecretValue:
        """Raise ``SecretNotAvailableError``."""
        raise SecretNotAvailableError(f"no secrets provider configured; cannot read {name!r}")
