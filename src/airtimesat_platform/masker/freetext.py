"""Reviewed message templates for free text (treatment F, design §4.4).

A free-text value is kept only if it fully matches a template. Each template slot is
typed, and its value is masked by that type; there is no untyped "keep" slot. Templates
are added by the CTO after reading the text in a manual reproduction, never by agents and
never copied from the catalog. Anything else becomes ``Text-<8>``.

Template text uses ``{TYPE}`` for a slot, where TYPE is a T-NUM type (``{CONTRACT}``), a
T-STR label (``{NAME}``), or ``EMAIL``, ``IPV4``, ``IPV6`` or ``HOST``. ``{{`` and ``}}``
are literal braces.
"""

import re
from dataclasses import dataclass
from typing import Final

from airtimesat_platform.masker.errors import FieldMapError
from airtimesat_platform.masker.fieldmap.model import Treatment
from airtimesat_platform.masker.tokenize.surrogates import T_NUM_TYPES, T_STR_LABELS

MAX_LABEL_SLOTS: Final = 2

_SLOT_PATTERNS: Final[dict[str, str]] = {
    "CONTRACT": r"SUB-\d{7}",
    "VOUCHER_ACCOUNT": r"SC-\d{1,20}",
    "EMAIL": r"[A-Za-z0-9._%+\-]{1,64}@[A-Za-z0-9.\-]{1,253}",
    "IPV4": r"\d{1,3}(?:\.\d{1,3}){3}",
    "IPV6": r"[0-9A-Fa-f:]{2,39}",
    "HOST": r"[A-Za-z0-9.\-]{1,253}",
}
_DIGIT_SLOT: Final = r"\d{1,20}"
_LABEL_SLOT: Final = r".{1,200}?"
_SLOT: Final = re.compile(r"\{([A-Z_0-9]+)\}")


def slot_treatment(slot: str) -> tuple[Treatment, str | None]:
    """Return the treatment that masks a slot's value."""
    if slot in T_NUM_TYPES:
        return Treatment.T_NUM, slot
    if slot in T_STR_LABELS:
        return Treatment.T_STR, slot
    if slot == "EMAIL":
        return Treatment.T_EMAIL, None
    if slot in ("IPV4", "IPV6"):
        return Treatment.T_IP, None
    if slot == "HOST":
        return Treatment.T_HOST, None
    raise FieldMapError("TEMPLATE_BAD_SLOT", detector=slot if slot.isidentifier() else "?")


@dataclass(frozen=True, slots=True)
class Template:
    """One compiled template."""

    template_id: str
    pattern: re.Pattern[str]
    slots: tuple[str, ...]

    @classmethod
    def compile(cls, template_id: str, text: str) -> "Template":
        """Compile ``text`` into an anchored pattern with typed slots."""
        parts: list[str] = []
        slots: list[str] = []
        pos = 0
        literal = text.replace("{{", "\x01").replace("}}", "\x02")
        for m in _SLOT.finditer(literal):
            parts.append(_literal(literal[pos : m.start()]))
            slot = m.group(1)
            slot_treatment(slot)
            slots.append(slot)
            if slot in _SLOT_PATTERNS:
                parts.append(f"({_SLOT_PATTERNS[slot]})")
            elif slot in T_NUM_TYPES:
                parts.append(f"({_DIGIT_SLOT})")
            else:
                parts.append(f"({_LABEL_SLOT})")
            pos = m.end()
        parts.append(_literal(literal[pos:]))
        if sum(1 for s in slots if s in T_STR_LABELS) > MAX_LABEL_SLOTS:
            raise FieldMapError("TEMPLATE_TOO_MANY_LABEL_SLOTS", detector=template_id)
        return cls(template_id, re.compile("".join(parts), re.DOTALL), tuple(slots))

    def match(self, value: str) -> list[tuple[str, int, int]] | None:
        """Return ``(slot type, start, end)`` per slot if ``value`` fully matches."""
        m = self.pattern.fullmatch(value)
        if m is None:
            return None
        return [(slot, m.start(i + 1), m.end(i + 1)) for i, slot in enumerate(self.slots)]


def _literal(text: str) -> str:
    if "{" in text or "}" in text:
        raise FieldMapError("TEMPLATE_SYNTAX")
    return re.escape(text.replace("\x01", "{").replace("\x02", "}"))
