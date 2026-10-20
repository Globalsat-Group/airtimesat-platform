"""The masking keys, held in memory for one run (design §4.3, §6.2).

The recorder reads them from the Keeper CLI on standard input into ``SecretValue`` objects
and hands them here. This module decodes and checks them; it never reads a file, an
environment variable or a log, and nothing in it prints a key.
"""

import base64
import binascii
import hmac
from dataclasses import dataclass, field
from typing import Final, final, override

from airtimesat_platform.common.secrets import SecretValue
from airtimesat_platform.masker.errors import MaskingError

KEY_BYTES: Final = 32


@final
class Key:
    """A 256-bit key that does not print itself."""

    __slots__ = ("_material",)

    def __init__(self, material: bytes) -> None:
        """Wrap ``material``, which must be exactly 32 bytes."""
        if len(material) != KEY_BYTES:
            raise MaskingError("KEY_INVALID")
        self._material = material

    def material(self) -> bytes:
        """Return the raw key bytes, only for the HMAC or AES call that needs them."""
        return self._material

    @override
    def __repr__(self) -> str:
        """Return a mask."""
        return "Key(**********)"

    @override
    def __str__(self) -> str:
        """Return a mask."""
        return "**********"

    @override
    def __eq__(self, other: object) -> bool:
        """Compare key material in constant time."""
        if not isinstance(other, Key):
            return NotImplemented
        return hmac.compare_digest(self._material, other._material)

    @override
    def __hash__(self) -> int:
        """Return a constant: a hash of the material would be a value derived from the key."""
        return 0


def decode_key(secret: SecretValue) -> Key:
    """Decode a key piped from Keeper: 64 hexadecimal characters or standard Base64.

    Raises ``MaskingError("KEY_INVALID")`` without the value.
    """
    text = secret.reveal().strip()
    raw: bytes | None = None
    if len(text) == 2 * KEY_BYTES:
        try:
            raw = bytes.fromhex(text)
        except ValueError:
            raw = None
    if raw is None:
        try:
            raw = base64.b64decode(text, validate=True)
        except (binascii.Error, ValueError):
            raise MaskingError("KEY_INVALID") from None
    return Key(raw)


@dataclass(frozen=True, slots=True)
class MaskingKeys:
    """The three keys the masking engine uses. The inventory key belongs to the recorder."""

    k_mask: Key = field(repr=False)
    vault_key: Key = field(repr=False)
    known_value_key: Key = field(repr=False)

    def __post_init__(self) -> None:
        """Refuse a key reused for two purposes."""
        keys = (self.k_mask, self.vault_key, self.known_value_key)
        for i, a in enumerate(keys):
            for b in keys[i + 1 :]:
                if a == b:
                    raise MaskingError("KEY_REUSED")

    @classmethod
    def from_secrets(
        cls, k_mask: SecretValue, vault_key: SecretValue, known_value_key: SecretValue
    ) -> "MaskingKeys":
        """Decode the keys loaded from Keeper."""
        return cls(decode_key(k_mask), decode_key(vault_key), decode_key(known_value_key))
