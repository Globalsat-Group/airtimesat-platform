"""Field-aware detection over masked output, known values and exemptions (design §8.1, §8.4).

Runtime detection exempts only surrogates the masker placed in this response. Offline
scans, which have no such set, exempt the reserved prefixes, ranges and domain instead
(and, under the test folders, the canary range).
"""

import ipaddress
import re
import string
from collections.abc import Iterator, Set
from typing import Final, Protocol

from airtimesat_platform.masker.detect.canary import is_canary, is_canary_token
from airtimesat_platform.masker.detect.patterns import (
    Detector,
    Exemption,
    Options,
    find_hits,
    normalize,
)
from airtimesat_platform.masker.tokenize.surrogates import (
    IPV4_RESERVED,
    IPV6_RESERVED,
    RESERVED_DOMAIN,
    is_reserved_surrogate,
)

REDACTED: Final = "REDACTED"

# Element names of secrets (design §3.1, "Secrets"). Their value must be REDACTED, empty,
# nil or absent in any output. Compared case-insensitively. Names that also carry
# non-secret data elsewhere (``spName``, ``dpName``, ``newValue``) are left to the field map.
SECRET_ELEMENT_NAMES: Final = frozenset(
    name.casefold()
    for name in (
        "signature",
        "callerPassword",
        "didwwUserApiKey",
        "password",
        "newPassword",
        "pin",
        "pinNumber",
        "pin1",
        "pin2",
        "puk",
        "puk1",
        "puk2",
        "captainPin",
        "twoStagePin",
        "dpPassword",
        "spPassword",
        "deliveryUserKey",
        "deliveryPwSecret",
        "gmdssPw",
        "token",
        "associationKey",
    )
)

_TOKEN_CHAR: Final = re.compile(r"[A-Za-z0-9@.:\-_+%]")
_EDGE_PUNCTUATION: Final = ".:-_+%"
_WORD_EDGE: Final = string.punctuation + "".join(map(chr, (0x2018, 0x2019, 0x201C, 0x201D)))


def token_around(text: str, start: int, end: int) -> str:
    """Return the token that contains ``text[start:end]``, without edge punctuation."""
    left, right = start, end
    while left > 0 and _TOKEN_CHAR.match(text[left - 1]):
        left -= 1
    while right < len(text) and _TOKEN_CHAR.match(text[right]):
        right += 1
    return text[left:right].strip(_EDGE_PUNCTUATION)


def offline_exempt_value(value: str) -> bool:
    """Return whether a hit is a reserved surrogate, address or e-mail address (design §8.1).

    An e-mail address counts only directly under the reserved domain: the labels of a
    subdomain could spell out a real domain.
    """
    if is_reserved_surrogate(value):
        return True
    local, at, domain = value.rpartition("@")
    if at and local and domain.casefold() == RESERVED_DOMAIN:
        return True
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return False
    if isinstance(address, ipaddress.IPv4Address):
        return address in IPV4_RESERVED
    return address in IPV6_RESERVED


def offline_exemption(allow_canary: bool = False) -> Exemption:
    """Exempt reserved surrogates, and canaries too when ``allow_canary`` is set.

    The hit itself may be a reserved surrogate, address or e-mail address. The token around
    it is exempt only if it is a whole surrogate (or canary) shape, so a real value glued to
    a reserved name (``<IMEI>.example.invalid``) still counts.
    """

    def exempt(text: str, start: int, end: int) -> bool:
        hit = text[start:end]
        if offline_exempt_value(hit) or (allow_canary and is_canary(hit)):
            return True
        token = token_around(text, start, end)
        return is_reserved_surrogate(token) or (allow_canary and is_canary_token(token))

    return exempt


def placed_exemption(placed: Set[str]) -> Exemption:
    """Exempt only values byte-equal to a surrogate placed in this response."""

    def exempt(text: str, start: int, end: int) -> bool:
        return text[start:end] in placed or token_around(text, start, end) in placed

    return exempt


class KnownValueIndex(Protocol):
    """The cross-call known-value set (keyed hashes, held by the vault)."""

    def is_known(self, value: str) -> bool:
        """Return whether a normalized value was seen in a structured field."""
        ...


class CallKnownValues:
    """Real values seen in this call, with what replaces each (design §4.4).

    Holds the real values replaced in structured fields, the real values put into the
    request, and the authentication values injected for the call. In memory only.
    """

    MIN_LENGTH: Final = 4

    def __init__(self) -> None:
        """Start empty."""
        self._values: dict[str, str] = {}

    @staticmethod
    def _fold(text: str) -> str:
        """Normalize, case-fold and collapse whitespace, so spacing changes do not hide a value."""
        return " ".join(normalize(text).casefold().split())

    def add(self, real: str, replacement: str) -> None:
        """Remember ``real`` (normalized) and its surrogate, constant or ``REDACTED``."""
        key = self._fold(real)
        if len(key) >= self.MIN_LENGTH:
            self._values.setdefault(key, replacement)

    def __len__(self) -> int:
        """Return the number of values held."""
        return len(self._values)

    def found_in(self, text: str) -> bool:
        """Return whether any known value occurs in ``text`` (normalized, case-folded)."""
        folded = self._fold(text)
        return any(value in folded for value in self._values)

    def replace_in(self, text: str) -> str:
        """Replace every occurrence of a known value, ignoring case and spacing."""
        out = normalize(text)
        for value in sorted(self._values, key=len, reverse=True):
            pattern = r"\s+".join(re.escape(word) for word in value.split(" "))
            replacement = self._values[value]
            out = re.sub(pattern, lambda _m, r=replacement: r, out, flags=re.IGNORECASE)
        return out


def word_sequences(text: str, max_words: int = 4) -> Iterator[str]:
    """Yield every sequence of 1 to ``max_words`` words, raw and with edge punctuation cut."""
    raw = normalize(text).casefold().split()
    stripped = [w.strip(_WORD_EDGE) for w in raw]
    for words in (raw, stripped):
        for i in range(len(words)):
            for n in range(1, max_words + 1):
                if i + n > len(words):
                    break
                sequence = " ".join(w for w in words[i : i + n] if w)
                if sequence:
                    yield sequence


def cross_call_hit(text: str, index: KnownValueIndex) -> bool:
    """Return whether a word sequence in ``text`` is a real name-like value seen before."""
    return any(len(seq) >= 4 and index.is_known(seq) for seq in word_sequences(text))


def scan_value(
    text: str,
    options: Options,
    exempt: Exemption,
    call_known: CallKnownValues | None = None,
    index: KnownValueIndex | None = None,
) -> Detector | None:
    """Return the first detector that fires on one output value, or ``None`` if clean."""
    hits = find_hits(text, options, exempt)
    if hits:
        return hits[0].detector
    if call_known is not None and call_known.found_in(text):
        return Detector.KNOWN_VALUE
    if index is not None and cross_call_hit(text, index):
        return Detector.CROSS_CALL_VALUE
    return None
