"""Pattern detectors for real identifiers in text (design §8.1).

Each detector has an id. A hit names the detector and the span; its text is kept only so
the caller can test the exemption, and is never printed or logged.

All expressions are bounded or free of nested quantifiers, so matching stays linear in the
input length (design §8.1). Text is normalized first: NFKC, every Unicode decimal digit
mapped to its ASCII digit, every dash mapped to a hyphen, and invisible characters (format,
control and combining characters) removed, so they cannot split an identifier. Spans refer
to the normalized text.
"""

import base64
import binascii
import ipaddress
import re
import unicodedata
from collections.abc import Callable
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Final

from airtimesat_platform.masker.tokenize.surrogates import imo_valid, luhn_valid


class Detector(StrEnum):
    """Detector ids, as reported in incidents and scan output."""

    IMEI = "IMEI"
    ICCID = "ICCID"
    IMSI = "IMSI"
    MSISDN = "MSISDN"
    PHONE = "PHONE"
    CONTRACT = "CONTRACT"
    VOUCHER_SERIAL = "VOUCHER_SERIAL"
    IPV4 = "IPV4"
    IPV6 = "IPV6"
    EMAIL = "EMAIL"
    IMO = "IMO"
    MMSI = "MMSI"
    LONG_DIGITS = "LONG_DIGITS"
    SIGNATURE = "SIGNATURE"
    KNOWN_VALUE = "KNOWN_VALUE"
    CROSS_CALL_VALUE = "CROSS_CALL_VALUE"
    SENSITIVE_NAME = "SENSITIVE_NAME"


# Rules skipped on kept elements with a numeric, date or boolean XSD type, and on kept
# elements the overrides mark as operational (versions, sizes, counts, operational IDs).
# They are still checked against known values (design §8.4).
OPERATIONAL_SKIP: Final = frozenset(
    {Detector.IPV4, Detector.MMSI, Detector.IMSI, Detector.LONG_DIGITS}
)


class Boundary(StrEnum):
    """What may not touch a digit run for it to count.

    ``DIGIT``: any non-digit ends a run (runtime detector and strict scans). ``ALNUM``: a
    run touching a letter is part of a longer token, such as a hash in a lock file
    (standard scans of code and documents).
    """

    DIGIT = "digit"
    ALNUM = "alnum"


@dataclass(frozen=True, slots=True)
class Hit:
    """One detector match. ``text`` is for the exemption test only; never print it."""

    detector: Detector
    start: int
    end: int
    text: str = field(repr=False, compare=False)


# Returns whether a hit in ``text`` from ``start`` to ``end`` is exempt.
Exemption = Callable[[str, int, int], bool]


def no_exemption(text: str, start: int, end: int) -> bool:
    """Exempt nothing."""
    del text, start, end
    return False


@dataclass(frozen=True, slots=True)
class Options:
    """How to run the detectors on one string."""

    boundary: Boundary = Boundary.DIGIT
    skip: frozenset[Detector] = frozenset()
    decode_base64: bool = True
    join_separators: bool = True


DEFAULT_OPTIONS: Final = Options()

_DIGIT_RUN: Final = {
    Boundary.DIGIT: re.compile(r"(?<!\d)\d{7,}(?!\d)"),
    Boundary.ALNUM: re.compile(r"(?<![0-9A-Za-z])\d{7,}(?![0-9A-Za-z])"),
}
_PHONE: Final = re.compile(r"(?<![\d+])\+\d{8,15}(?!\d)")
# ``SC-`` voucher accounts have an undocumented length; 3 or more digits (*Inferred*), so
# the bare reserved prefix ``SC-99`` in documentation does not count.
# ``SUB`` also with an underscore, a space or no separator (identifier variants, §8.5 #4).
_CONTRACT: Final = re.compile(r"(?<![A-Za-z0-9])(?:SUB[-_ ]?\d{7}|SC-\d{3,})(?!\d)", re.IGNORECASE)
_IPV4: Final = re.compile(r"(?<![\d.])\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?!\.?\d)")
# Not inside a word (so ``Upgrade::Allowed`` does not count), but after a word and one colon
# (``ip:2001:db8::1``), and with a trailing colon allowed (``2001:db8::1:``).
_IPV6: Final = re.compile(
    r"(?:(?<![\w:])|(?<=[^:]:)(?=[0-9A-Fa-f]))[0-9A-Fa-f:]{2,39}(?![0-9A-Za-z_])"
)
# Unicode letters too: an accented local part or an IDN domain is still an address.
_EMAIL: Final = re.compile(r"[\w.%+\-]{1,64}@[\w\-]{1,63}(?:\.[\w\-]{1,63}){1,8}")
_SIGNATURE: Final = re.compile(r"(?<![A-Za-z0-9+/=])[A-Za-z0-9+/]{27}=?(?![A-Za-z0-9+/=])")
# 16 characters hold 12 bytes, the shortest identifier (an MSISDN); padding may be missing.
_BASE64: Final = re.compile(r"(?<![A-Za-z0-9+/=])[A-Za-z0-9+/]{16,}={0,2}(?![A-Za-z0-9+/=])")
_SEPARATED: Final = re.compile(r"\d{1,20}(?:[ .\-]\d{1,20}){1,19}")
_TIMESTAMP: Final = re.compile(
    r"\d{4}-\d{2}-\d{2}(?:[T ]\d{2}:\d{2}(?::\d{2}(?:[.,]\d{1,9})?)?(?:Z|[+\-]\d{2}:?\d{2})?)?"
    r"|\d{2}-[A-Za-z]{3}-\d{4}(?: \d{2}:\d{2}:\d{2})?"
)


# Removed before detection: format (zero-width space, soft hyphen, bidi controls), control
# (except tab, line feed and carriage return), and combining characters left after NFKC.
_INVISIBLE: Final = frozenset({"Cf", "Cc", "Mn", "Me"})
_KEPT_CONTROLS: Final = frozenset("\t\n\r")
_MINUS_SIGN: Final = "\u2212"


def normalize(text: str) -> str:
    """Return NFKC text with digits in ASCII, dashes as ``-`` and invisible characters removed.

    NFKC and the removal can change the length of a string, so spans refer to the
    normalized string. Callers test exemptions on the same normalized string.
    """
    out: list[str] = []
    for ch in unicodedata.normalize("NFKC", text):
        if ch.isascii():
            if ch.isprintable() or ch in _KEPT_CONTROLS:
                out.append(ch)
            continue
        category = unicodedata.category(ch)
        if category in _INVISIBLE:
            continue
        if ch.isdecimal():
            out.append(str(unicodedata.decimal(ch)))
        elif category == "Pd" or ch == _MINUS_SIGN:
            out.append("-")
        else:
            out.append(ch)
    return "".join(out)


def classify_digits(run: str) -> list[Detector]:
    """Return the detectors that fire on a run of ASCII digits."""
    hits: list[Detector] = []
    n = len(run)
    if n == 15:
        hits += [Detector.IMEI, Detector.IMSI]
    if (18 <= n <= 20 and run.startswith("89") and luhn_valid(run)) or n == 19:
        hits.append(Detector.ICCID)
    if n == 19:
        hits.append(Detector.VOUCHER_SERIAL)
    if (n == 12 and run[:4] in ("8816", "8817")) or (
        n == 14 and run.startswith("00") and run[2:6] in ("8816", "8817")
    ):
        hits.append(Detector.MSISDN)
    if n == 7 and imo_valid(run):
        hits.append(Detector.IMO)
    if n == 9:
        hits.append(Detector.MMSI)
    if n >= 9:
        hits.append(Detector.LONG_DIGITS)
    return hits


def _ipv4_ok(candidate: str) -> bool:
    return all(int(octet) <= 255 for octet in candidate.split("."))


def _ipv6_ok(candidate: str) -> bool:
    if candidate.count(":") < 2:
        return False
    try:
        address = ipaddress.IPv6Address(candidate)
    except ValueError:
        return False
    return not (address.is_unspecified or address.is_loopback)


def _ipv6_span(candidate: str) -> tuple[int, int] | None:
    """Return the span of a valid address in a candidate, allowing one stray edge colon."""
    end = len(candidate)
    for start, stop in ((0, end), (0, end - 1), (1, end), (1, end - 1)):
        part = candidate[start:stop]
        if part.startswith(":") and not part.startswith("::"):
            continue
        if part.endswith(":") and not part.endswith("::"):
            continue
        if _ipv6_ok(part):
            return start, stop
    return None


def _signature_like(candidate: str) -> bool:
    """Return whether a candidate looks like an HMAC-SHA1 in Base64.

    The signature is 28 characters ending in ``=``.

    Without the padding, 27 characters also need a digit, ``+`` or ``/`` and both letter
    cases, so long identifiers such as class names do not count (*Inferred* refinement of
    the length rule; a random 27-character Base64 string fails it about 0.4% of the time).
    """
    if candidate.endswith("="):
        return True
    return (
        any(ch.isdigit() or ch in "+/" for ch in candidate)
        and any(ch.isupper() for ch in candidate)
        and any(ch.islower() for ch in candidate)
    )


def _mask_timestamps(text: str) -> str:
    return _TIMESTAMP.sub(lambda m: "\x00" * len(m.group(0)), text)


def find_hits(
    text: str, options: Options = DEFAULT_OPTIONS, exempt: Exemption = no_exemption
) -> list[Hit]:
    """Return every non-exempt detector hit in ``text`` (normalized first)."""
    norm = normalize(text)
    hits: list[Hit] = []

    def add(detector: Detector, start: int, end: int) -> None:
        if detector in options.skip or exempt(norm, start, end):
            return
        hits.append(Hit(detector, start, end, norm[start:end]))

    for m in _DIGIT_RUN[options.boundary].finditer(norm):
        for detector in classify_digits(m.group(0)):
            add(detector, m.start(), m.end())
    for m in _PHONE.finditer(norm):
        add(Detector.PHONE, m.start(), m.end())
    for m in _CONTRACT.finditer(norm):
        add(Detector.CONTRACT, m.start(), m.end())
    for m in _IPV4.finditer(norm):
        if _ipv4_ok(m.group(0)):
            add(Detector.IPV4, m.start(), m.end())
    for m in _IPV6.finditer(norm):
        span = _ipv6_span(m.group(0))
        if span is not None:
            add(Detector.IPV6, m.start() + span[0], m.start() + span[1])
    for m in _EMAIL.finditer(norm):
        add(Detector.EMAIL, m.start(), m.end())
    for m in _SIGNATURE.finditer(norm):
        if _signature_like(m.group(0)):
            add(Detector.SIGNATURE, m.start(), m.end())
    if options.join_separators:
        _find_joined(norm, options, exempt, hits)
    if options.decode_base64:
        _find_decoded(norm, options, exempt, hits)
    return hits


def _find_joined(norm: str, options: Options, exempt: Exemption, hits: list[Hit]) -> None:
    """Digit groups joined only by spaces, hyphens or dots, 12 to 20 digits in total."""
    masked = _mask_timestamps(norm)
    for m in _SEPARATED.finditer(masked):
        group = m.group(0)
        joined = re.sub(r"[ .\-]", "", group)
        if not 12 <= len(joined) <= 20:
            continue
        if exempt(joined, 0, len(joined)) or exempt(norm, m.start(), m.end()):
            continue
        for detector in classify_digits(joined):
            if detector not in options.skip:
                hits.append(Hit(detector, m.start(), m.end(), norm[m.start() : m.end()]))


def _find_decoded(norm: str, options: Options, exempt: Exemption, hits: list[Hit]) -> None:
    """Detectors over the decoded text of long Base64-looking strings (one level)."""
    inner = Options(options.boundary, options.skip, decode_base64=False, join_separators=True)
    for m in _BASE64.finditer(norm):
        candidate = m.group(0)
        if "=" not in candidate:
            candidate += "=" * (-len(candidate) % 4)
        if len(candidate) % 4:
            continue
        try:
            decoded = base64.b64decode(candidate, validate=True).decode("utf-8")
        except (binascii.Error, ValueError):
            continue
        if not decoded.isprintable():
            continue
        for hit in find_hits(decoded, inner, exempt):
            hits.append(Hit(hit.detector, m.start(), m.end(), m.group(0)))
