"""Issue and resolve reversible surrogates over a vault store (design §4.3, §5.5, §6.1).

The vault is the record of what the masker issued: a surrogate is valid in a request only
if a row exists for it. Real values are stored only as AES-256-GCM ciphertext under the
vault key, with the type, surrogate and counter as associated data, so a row moved to
another slot does not decrypt.

The store is an interface. The recorder's encrypted SQLite store (with the run log, test
inventory and incidents) implements it on the trusted machine; ``InMemoryVaultStore`` is
the reference implementation for tests.
"""

import hashlib
import hmac
import os
from collections import Counter
from collections.abc import Callable
from dataclasses import dataclass, replace
from datetime import UTC, datetime
from typing import Final, Protocol, final

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from airtimesat_platform.masker.detect.canary import in_canary_range
from airtimesat_platform.masker.detect.patterns import normalize
from airtimesat_platform.masker.errors import VaultError
from airtimesat_platform.masker.keys import MaskingKeys
from airtimesat_platform.masker.tokenize.surrogates import MAX_OCCUPANCY, SPECS, derive, tlv

NONCE_BYTES: Final = 12
# Collisions are expected (design §4.3); at most 50% occupancy, 64 in a row is ~1e-19.
MAX_COUNTER: Final = 64


@dataclass(frozen=True, slots=True)
class VaultRow:
    """One issued slot: ``(type, surrogate, counter) -> AES-256-GCM(real value)``.

    ``ciphertext`` is ``None`` for a tombstone: the value was deleted by retention, and the
    slot stays reserved forever so an old surrogate never comes to mean someone else.
    """

    type_name: str
    surrogate: str
    counter: int
    ciphertext: bytes | None
    first_seen: datetime
    last_seen: datetime

    @property
    def tombstone(self) -> bool:
        """Return whether the value has been deleted."""
        return self.ciphertext is None


class VaultStore(Protocol):
    """Storage for vault rows and the cross-call known-value set."""

    def get(self, type_name: str, surrogate: str) -> VaultRow | None:
        """Return the row for ``(type, surrogate)``, tombstones included, or ``None``."""
        ...

    def insert(self, row: VaultRow) -> None:
        """Add a new row; raise ``VaultError("VAULT_WRITE_FAILED")`` if the slot is taken."""
        ...

    def touch(self, type_name: str, surrogate: str, when: datetime) -> None:
        """Set the row's last-seen time."""
        ...

    def count(self, type_name: str) -> int:
        """Return the number of rows of a type, tombstones included."""
        ...

    def add_known_value(self, digest: bytes, when: datetime) -> None:
        """Record the keyed hash of a real name-like value."""
        ...

    def has_known_value(self, digest: bytes) -> bool:
        """Return whether a keyed hash is in the known-value set."""
        ...


class InMemoryVaultStore:
    """A vault store in a dictionary. Reference implementation and test double."""

    def __init__(self) -> None:
        """Start empty."""
        self.rows: dict[tuple[str, str], VaultRow] = {}
        self.known: dict[bytes, datetime] = {}

    def get(self, type_name: str, surrogate: str) -> VaultRow | None:
        """Return the row or ``None``."""
        return self.rows.get((type_name, surrogate))

    def insert(self, row: VaultRow) -> None:
        """Add a row to a free slot."""
        key = (row.type_name, row.surrogate)
        if key in self.rows:
            raise VaultError("VAULT_WRITE_FAILED")
        self.rows[key] = row

    def touch(self, type_name: str, surrogate: str, when: datetime) -> None:
        """Update last-seen."""
        key = (type_name, surrogate)
        self.rows[key] = replace(self.rows[key], last_seen=when)

    def count(self, type_name: str) -> int:
        """Count rows of a type."""
        return sum(1 for t, _ in self.rows if t == type_name)

    def add_known_value(self, digest: bytes, when: datetime) -> None:
        """Record a keyed hash."""
        self.known[digest] = when

    def has_known_value(self, digest: bytes) -> bool:
        """Look up a keyed hash."""
        return digest in self.known

    def tombstone(self, type_name: str, surrogate: str) -> None:
        """Delete a row's value and keep its slot (retention, design §6.4)."""
        key = (type_name, surrogate)
        self.rows[key] = replace(self.rows[key], ciphertext=None)


def normalize_known(value: str) -> str:
    """Normalize a value for known-value matching.

    The detectors' normalization (NFKC, no invisible characters), case folding, single spaces.
    """
    return " ".join(normalize(value).casefold().split())


@final
class Vault:
    """Issue and resolve surrogates for one run, with its counters."""

    def __init__(
        self,
        store: VaultStore,
        keys: MaskingKeys,
        clock: Callable[[], datetime] = lambda: datetime.now(UTC),
    ) -> None:
        """Use ``store`` and ``keys``; ``clock`` gives first-seen and last-seen times."""
        self._store = store
        self._keys = keys
        self._aead = AESGCM(keys.vault_key.material())
        self._clock = clock
        self._cache: dict[tuple[str, str], str] = {}
        # Real values refused because they fall in a reserved prefix, per type (count only).
        self.in_prefix: Counter[str] = Counter()
        # Real values that fall in the documented canary range, per type (count only).
        self.in_canary_range: Counter[str] = Counter()
        self.issued: Counter[str] = Counter()

    @property
    def keys(self) -> MaskingKeys:
        """Return the masking keys."""
        return self._keys

    def _aad(self, type_name: str, surrogate: str, counter: int) -> bytes:
        return tlv(type_name.encode()) + tlv(surrogate.encode()) + tlv(str(counter).encode())

    def _decrypt(self, row: VaultRow) -> str:
        if row.ciphertext is None or len(row.ciphertext) <= NONCE_BYTES:
            raise VaultError("VAULT_INTEGRITY", detector=row.type_name)
        nonce, body = row.ciphertext[:NONCE_BYTES], row.ciphertext[NONCE_BYTES:]
        try:
            plain = self._aead.decrypt(
                nonce, body, self._aad(row.type_name, row.surrogate, row.counter)
            )
        except InvalidTag:
            raise VaultError("VAULT_INTEGRITY", detector=row.type_name) from None
        return plain.decode("utf-8")

    def _encrypt(self, type_name: str, surrogate: str, counter: int, real: str) -> bytes:
        nonce = os.urandom(NONCE_BYTES)
        aad = self._aad(type_name, surrogate, counter)
        return nonce + self._aead.encrypt(nonce, real.encode("utf-8"), aad)

    def issue(self, type_name: str, real: str) -> str:
        """Return the surrogate of ``real``, issuing a vault row if it has none yet.

        Deterministic: the same real value gets the same surrogate for as long as ``K_mask``
        and its vault row exist. A slot held by another value, or by a tombstone, moves the
        derivation to the next counter.
        """
        cached = self._cache.get((type_name, real))
        if cached is not None:
            return cached
        spec = SPECS[type_name]
        if spec.in_reserved_space(real.strip()):
            self.in_prefix[type_name] += 1
            raise VaultError("REAL_VALUE_IN_RESERVED_PREFIX", detector=type_name)
        if in_canary_range(type_name, real):
            self.in_canary_range[type_name] += 1
        k_mask = self._keys.k_mask.material()
        for counter in range(MAX_COUNTER):
            surrogate = spec.render(derive(k_mask, type_name, real, counter), real)
            row = self._store.get(type_name, surrogate)
            now = self._clock()
            if row is None:
                if self._store.count(type_name) + 1 > MAX_OCCUPANCY * spec.space(real):
                    raise VaultError("SURROGATE_SPACE_EXHAUSTED", detector=type_name)
                ciphertext = self._encrypt(type_name, surrogate, counter, real)
                self._store.insert(VaultRow(type_name, surrogate, counter, ciphertext, now, now))
                self.issued[type_name] += 1
                self._cache[(type_name, real)] = surrogate
                return surrogate
            if row.counter == counter and not row.tombstone and self._decrypt(row) == real:
                self._store.touch(type_name, surrogate, now)
                self._cache[(type_name, real)] = surrogate
                return surrogate
        raise VaultError("COLLISION_LIMIT", detector=type_name)

    def resolve(self, type_name: str, surrogate: str) -> str:
        """Return the real value behind an issued surrogate.

        Raises ``VaultError("IDENTIFIER_NOT_ISSUED")`` for a surrogate with no row, or whose
        value was deleted, so a guessed surrogate maps to nothing (design §4.6, §5.5).
        """
        if type_name not in SPECS:
            raise VaultError("IDENTIFIER_NOT_ISSUED", detector=type_name)
        row = self._store.get(type_name, surrogate)
        if row is None or row.tombstone:
            raise VaultError("IDENTIFIER_NOT_ISSUED", detector=type_name)
        real = self._decrypt(row)
        self._store.touch(type_name, surrogate, self._clock())
        return real

    def known_digest(self, value: str) -> bytes:
        """Return the keyed hash of a normalized name-like value."""
        key = self._keys.known_value_key.material()
        return hmac.new(key, normalize_known(value).encode("utf-8"), hashlib.sha256).digest()

    def add_known(self, value: str) -> None:
        """Remember a real T-STR, P-ONE or T-EMAIL value of 4 or more characters (§4.4)."""
        if len(normalize_known(value)) >= 4:
            self._store.add_known_value(self.known_digest(value), self._clock())

    def is_known(self, value: str) -> bool:
        """Return whether a value (after normalization) was seen in a structured field."""
        return self._store.has_known_value(self.known_digest(value))
