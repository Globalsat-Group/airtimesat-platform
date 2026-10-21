"""Surrogate formats, keyed derivation and check digits (design §4.2, §4.3).

A surrogate is derived from the real value with HMAC-SHA256 under ``K_mask``. Every
reversible surrogate sits in a reserved prefix, range or domain, so a reader can tell it is
not real. The prefixes are reviewed constants: changing one changes every surrogate of
that type, so it is a reviewed code change, never configuration.
"""

import hashlib
import hmac
import ipaddress
import re
from dataclasses import dataclass
from enum import StrEnum
from typing import Final

DERIVATION_VERSION: Final = 1
BASE32_ALPHABET: Final = "abcdefghijklmnopqrstuvwxyz234567"
RESERVED_DOMAIN: Final = "example.invalid"
IPV4_RESERVED: Final = ipaddress.IPv4Network("240.0.0.0/4")
IPV6_RESERVED: Final = ipaddress.IPv6Network("2001:db8::/32")
# The highest usable fraction of a type's surrogate space (tombstones count). Past it the
# masker refuses to issue and stops the run (design §4.3, *Inferred* threshold).
MAX_OCCUPANCY: Final = 0.5


class Kind(StrEnum):
    """How a surrogate body is rendered."""

    DIGITS = "digits"
    LABEL = "label"
    IPV4 = "ipv4"
    IPV6 = "ipv6"
    HOST = "host"
    EMAIL = "email"


class Check(StrEnum):
    """Check digit appended to a digit surrogate."""

    LUHN = "luhn"
    IMO = "imo"


def tlv(data: bytes) -> bytes:
    """Return ``data`` prefixed by its length, so distinct field lists never collide."""
    return len(data).to_bytes(4, "big") + data


def derive(key: bytes, type_name: str, real: str, counter: int) -> bytes:
    """Return ``HMAC-SHA256(key, TLV(type) || TLV(version) || TLV(real) || TLV(counter))``."""
    message = b"".join(
        (
            tlv(type_name.encode()),
            tlv(str(DERIVATION_VERSION).encode()),
            tlv(real.encode("utf-8")),
            tlv(str(counter).encode()),
        )
    )
    return hmac.new(key, message, hashlib.sha256).digest()


def digits_from(h: bytes, count: int) -> str:
    """Return ``count`` decimal digits from ``h`` (``h`` as an integer modulo ``10**count``)."""
    if count <= 0:
        return ""
    return str(int.from_bytes(h, "big") % 10**count).zfill(count)


def base32_from(h: bytes, count: int = 8) -> str:
    """Return ``count`` lower-case base32 characters from the leading bits of ``h``."""
    value = int.from_bytes(h, "big")
    total_bits = len(h) * 8
    chars: list[str] = []
    for i in range(count):
        shift = total_bits - 5 * (i + 1)
        chars.append(BASE32_ALPHABET[(value >> shift) & 0x1F])
    return "".join(chars)


def luhn_check_digit(payload: str) -> str:
    """Return the Luhn check digit for the digit string ``payload``."""
    total = 0
    for i, ch in enumerate(reversed(payload)):
        d = ord(ch) - 48
        if i % 2 == 0:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return str((10 - total % 10) % 10)


def luhn_valid(number: str) -> bool:
    """Return whether the digit string ``number`` ends in a valid Luhn check digit."""
    if len(number) < 2 or not number.isascii() or not number.isdigit():
        return False
    return luhn_check_digit(number[:-1]) == number[-1]


def imo_check_digit(payload: str) -> str:
    """Return the IMO check digit for a 6-digit payload (weights 7 to 2, modulo 10)."""
    total = sum((ord(ch) - 48) * w for ch, w in zip(payload, range(7, 1, -1), strict=True))
    return str(total % 10)


def imo_valid(number: str) -> bool:
    """Return whether ``number`` is 7 digits with a valid IMO check digit."""
    return (
        len(number) == 7
        and number.isascii()
        and number.isdigit()
        and imo_check_digit(number[:6]) == number[6]
    )


_LABEL_BODY: Final = f"[{BASE32_ALPHABET}]{{8}}"


@dataclass(frozen=True, slots=True)
class SurrogateSpec:
    """The surrogate format of one identifier type."""

    name: str
    kind: Kind
    prefix: str = ""
    derived: int = 0
    check: Check | None = None
    # Digit types whose real length varies keep it (voucher accounts, design §4.2).
    same_length: bool = False

    def _derived_count(self, real: str) -> int:
        if not self.same_length:
            return self.derived
        digits = sum(1 for ch in real if ch.isdigit())
        return max(digits - (len(self.prefix) - self.prefix.rfind("-") - 1), 1)

    def render(self, h: bytes, real: str) -> str:
        """Return the surrogate for derivation output ``h`` of the real value ``real``."""
        match self.kind:
            case Kind.DIGITS:
                body = self.prefix + digits_from(h, self._derived_count(real))
                if self.check is Check.LUHN:
                    body += luhn_check_digit(body)
                elif self.check is Check.IMO:
                    body += imo_check_digit(body)
                return body
            case Kind.LABEL:
                return self.prefix + base32_from(h)
            case Kind.IPV4:
                offset = int.from_bytes(h, "big") % (IPV4_RESERVED.num_addresses - 1)
                return str(IPV4_RESERVED.network_address + offset)
            case Kind.IPV6:
                offset = int.from_bytes(h, "big") % IPV6_RESERVED.num_addresses
                return str(IPV6_RESERVED.network_address + offset)
            case Kind.HOST:
                return f"h-{base32_from(h)}.{RESERVED_DOMAIN}"
            case Kind.EMAIL:
                return f"u-{base32_from(h)}@{RESERVED_DOMAIN}"

    def space(self, real: str) -> int:
        """Return the number of distinct surrogates of this type for ``real``'s length."""
        match self.kind:
            case Kind.DIGITS:
                return 10 ** self._derived_count(real)
            case Kind.LABEL | Kind.HOST | Kind.EMAIL:
                return 32**8
            case Kind.IPV4:
                return IPV4_RESERVED.num_addresses - 1
            case Kind.IPV6:
                return IPV6_RESERVED.num_addresses

    def is_surrogate_shape(self, value: str) -> bool:
        """Return whether ``value`` has exactly the surrogate format of this type."""
        match self.kind:
            case Kind.DIGITS:
                if not value.startswith(self.prefix):
                    return False
                rest = value[len(self.prefix) :]
                if not (rest.isascii() and rest.isdigit()):
                    return False
                if not self.same_length:
                    expected = self.derived + (1 if self.check else 0)
                    if len(rest) != expected:
                        return False
                if self.check is Check.LUHN:
                    return luhn_valid(value[value.rfind("-") + 1 :])
                if self.check is Check.IMO:
                    return imo_valid(value)
                return True
            case Kind.LABEL:
                return re.fullmatch(re.escape(self.prefix) + _LABEL_BODY, value) is not None
            case Kind.IPV4:
                return _in_network(value, IPV4_RESERVED)
            case Kind.IPV6:
                return _in_network(value, IPV6_RESERVED)
            case Kind.HOST:
                return re.fullmatch(f"h-{_LABEL_BODY}\\.example\\.invalid", value) is not None
            case Kind.EMAIL:
                return re.fullmatch(f"u-{_LABEL_BODY}@example\\.invalid", value) is not None

    def in_reserved_space(self, value: str) -> bool:
        """Return whether a real value falls inside this type's reserved prefix or range.

        The masker refuses to issue a surrogate for such a value and counts it, so the
        reserved prefixes stay free of real data (design §4.2).
        """
        match self.kind:
            case Kind.DIGITS:
                return value.startswith(self.prefix)
            case Kind.LABEL:
                return self.is_surrogate_shape(value)
            case Kind.IPV4 | Kind.IPV6:
                return self.is_surrogate_shape(value)
            case Kind.HOST | Kind.EMAIL:
                return value.casefold().endswith(".invalid")


def _in_network(value: str, network: ipaddress.IPv4Network | ipaddress.IPv6Network) -> bool:
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return False
    return address.version == network.version and address in network and str(address) == value


def _label(name: str, prefix: str) -> SurrogateSpec:
    return SurrogateSpec(name, Kind.LABEL, prefix=prefix, derived=8)


# Reversible types (T-NUM, T-STR, T-IP, T-HOST, T-EMAIL). Formats from design §4.2.
SPECS: Final[dict[str, SurrogateSpec]] = {
    s.name: s
    for s in (
        SurrogateSpec("IMEI", Kind.DIGITS, prefix="99", derived=12, check=Check.LUHN),
        SurrogateSpec("ICCID", Kind.DIGITS, prefix="99", derived=16, check=Check.LUHN),
        SurrogateSpec("IMSI", Kind.DIGITS, prefix="99", derived=13),
        SurrogateSpec("MSISDN", Kind.DIGITS, prefix="99", derived=10),
        # Fixed 12 digits whatever the real length, so the length does not reveal the country.
        SurrogateSpec("OTHER_NUMBER", Kind.DIGITS, prefix="99", derived=10),
        SurrogateSpec("CAPCODE", Kind.DIGITS, prefix="99", derived=10),
        SurrogateSpec("CONTRACT", Kind.DIGITS, prefix="SUB-9", derived=6),
        SurrogateSpec("VOUCHER_ACCOUNT", Kind.DIGITS, prefix="SC-99", same_length=True),
        SurrogateSpec("IMO", Kind.DIGITS, prefix="99", derived=4, check=Check.IMO),
        SurrogateSpec("MMSI", Kind.DIGITS, prefix="99", derived=7),
        SurrogateSpec("SERIAL", Kind.DIGITS, prefix="99", derived=17),
        # T-STR on an element with a numeric XSD type: 9 digits, which fits xsd:int.
        SurrogateSpec("NUMERIC_ID", Kind.DIGITS, prefix="99", derived=7),
        SurrogateSpec("IPV4", Kind.IPV4),
        SurrogateSpec("IPV6", Kind.IPV6),
        SurrogateSpec("HOST", Kind.HOST),
        SurrogateSpec("EMAIL", Kind.EMAIL),
        _label("NAME", "Name-"),
        _label("VESSEL", "Vessel-"),
        _label("ORG", "Org-"),
        _label("GROUP", "Group-"),
        _label("USER", "user-"),
        _label("REF", "Ref-"),
        _label("ID", "Id-"),
        _label("VPN", "Vpn-"),
        _label("FILE", "File-"),
        _label("VALUE", "Value-"),
    )
}

# One-way formats (P-ONE and F): the same derivation under a separate type key, no vault row.
ONE_WAY_SPECS: Final[dict[str, SurrogateSpec]] = {
    s.name: s
    for s in (
        _label("NAME", "Name-"),
        _label("USER", "user-"),
        _label("TEXT", "Text-"),
        _label("PHONE", "Phone-"),
        _label("ADDRESS", "Addr-"),
        SurrogateSpec("NUMERIC_ID", Kind.DIGITS, prefix="99", derived=7),
    )
}

# Labels a T-STR entry in the field map may name, mapped to their reversible type.
T_STR_LABELS: Final = frozenset(
    {"NAME", "VESSEL", "ORG", "GROUP", "USER", "REF", "ID", "VPN", "FILE", "VALUE"}
)
# Types a T-NUM entry in the field map may name.
T_NUM_TYPES: Final = frozenset(
    {
        "IMEI",
        "ICCID",
        "IMSI",
        "MSISDN",
        "OTHER_NUMBER",
        "CAPCODE",
        "CONTRACT",
        "VOUCHER_ACCOUNT",
        "IMO",
        "MMSI",
        "SERIAL",
        "NUMERIC_ID",
    }
)


def one_way(key: bytes, label: str, real: str) -> str:
    """Return the one-way pseudonym of ``real`` (P-ONE, and F's ``Text-<8>``)."""
    spec = ONE_WAY_SPECS[label]
    return spec.render(derive(key, f"PONE:{label}", real, 0), real)


def is_reserved_surrogate(value: str) -> bool:
    """Return whether ``value`` has the shape of any reversible or one-way surrogate.

    Offline scans have no per-response set of placed surrogates, so they allow these
    shapes (design §8.1, Exemption; §8.3).
    """
    return any(s.is_surrogate_shape(value) for s in SPECS.values()) or any(
        s.is_surrogate_shape(value) for s in ONE_WAY_SPECS.values()
    )
