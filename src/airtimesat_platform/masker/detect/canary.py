"""The documented canary range: real-format synthetic values for leak tests (design §8.2, §8.3).

Canaries look like real identifiers, so every detector fires on them, but they sit outside
every surrogate prefix. Tests feed them to the masker as if they were real values and
assert that none survives. ``scripts/leak_scan.py`` allows them only under ``tests/leak/``
and ``tests/masker/``. The vault counts real values that fall in this range, so the first
recordings confirm that SITEST holds none (design §4.2).

Every canary is fake. The digit prefixes start ``98000`` (or ``8998000`` for ICCIDs and
``88169800`` for MSISDNs, which must keep the real leading digits for their detectors to
fire); addresses come from documentation ranges, and names and domains say ``canary``.
"""

import ipaddress
import re
from typing import Final

from airtimesat_platform.masker.tokenize.surrogates import imo_check_digit, luhn_check_digit

CANARY_DIGIT_PREFIXES: Final[dict[str, str]] = {
    "IMEI": "980001",
    "ICCID": "8998000",
    "IMSI": "980002",
    "MSISDN": "88169800",
    "OTHER_NUMBER": "980003",
    "CAPCODE": "980004",
    "SERIAL": "980005",
    "NUMERIC_ID": "98000",
    "MMSI": "98000",
    "IMO": "98",
}
CANARY_CONTRACT_PREFIX: Final = "SUB-80"
CANARY_VOUCHER_PREFIX: Final = "SC-80"
CANARY_IPV4: Final = ipaddress.IPv4Network("198.51.100.0/24")  # TEST-NET-2 (RFC 5737)
CANARY_IPV6: Final = ipaddress.IPv6Network("3fff::/20")  # documentation (RFC 9637)
CANARY_DOMAIN: Final = "canary.test"
CANARY_NAME_PREFIX: Final = "Canary "

_LENGTHS: Final[dict[str, int]] = {
    "IMEI": 15,
    "ICCID": 19,
    "IMSI": 15,
    "MSISDN": 12,
    "OTHER_NUMBER": 12,
    "CAPCODE": 12,
    "SERIAL": 19,
    "NUMERIC_ID": 9,
    "MMSI": 9,
    "IMO": 7,
}


def canary(type_name: str, n: int) -> str:
    """Return the ``n``-th canary of a type (``n`` from 0), in real format."""
    if type_name in CANARY_DIGIT_PREFIXES:
        prefix = CANARY_DIGIT_PREFIXES[type_name]
        length = _LENGTHS[type_name]
        if type_name in ("IMEI", "ICCID"):
            payload = prefix + str(n).zfill(length - len(prefix) - 1)
            return payload + luhn_check_digit(payload)
        if type_name == "IMO":
            payload = prefix + str(n).zfill(4)
            return payload + imo_check_digit(payload)
        return prefix + str(n).zfill(length - len(prefix))
    match type_name:
        case "CONTRACT":
            return CANARY_CONTRACT_PREFIX + str(n).zfill(5)
        case "VOUCHER_ACCOUNT":
            return CANARY_VOUCHER_PREFIX + str(n).zfill(6)
        case "IPV4":
            return str(CANARY_IPV4.network_address + 1 + n % 250)
        case "IPV6":
            return str(CANARY_IPV6.network_address + 1 + n)
        case "HOST":
            return f"host{n}.{CANARY_DOMAIN}"
        case "EMAIL":
            return f"person{n}@{CANARY_DOMAIN}"
        case _:
            return f"{CANARY_NAME_PREFIX}{type_name.title()} {n}"


_CANARY_TOKEN: Final = re.compile(
    r"(?:98000\d{4,14}|8998000\d{12}|88169800\d{4}|98\d{5}|SUB-80\d{5}|SC-80\d+)"
)


def is_canary_token(value: str) -> bool:
    """Return whether ``value`` is exactly a canary number, contract or voucher account."""
    return _CANARY_TOKEN.fullmatch(value) is not None


def is_canary(value: str) -> bool:
    """Return whether ``value`` is in the canary range (any type)."""
    if is_canary_token(value):
        return True
    if value.casefold().endswith("." + CANARY_DOMAIN) or value.casefold().endswith(
        "@" + CANARY_DOMAIN
    ):
        return True
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return False
    if isinstance(address, ipaddress.IPv4Address):
        return address in CANARY_IPV4
    return address in CANARY_IPV6


def in_canary_range(type_name: str, value: str) -> bool:
    """Return whether a real value of a type falls in the canary range (counted, not refused)."""
    prefix = CANARY_DIGIT_PREFIXES.get(type_name)
    if prefix is not None:
        return value.startswith(prefix) and len(value) == _LENGTHS[type_name]
    return is_canary(value) or value.startswith(CANARY_NAME_PREFIX)
