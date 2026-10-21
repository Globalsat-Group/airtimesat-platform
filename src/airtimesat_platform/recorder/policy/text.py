"""Text normalization for policy comparisons (design §5.7)."""

import unicodedata


def fold(value: str | None) -> str:
    """Return ``value`` NFKC-normalized, without format characters, trimmed and case-folded.

    So `` DEACTIVE ``, ``Deactive``, full-width text and text split by a zero-width
    character all compare equal to ``deactive``.
    """
    text = unicodedata.normalize("NFKC", value or "")
    text = "".join(ch for ch in text if unicodedata.category(ch) != "Cf")
    return text.strip().casefold()
