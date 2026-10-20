"""Refusals raised by the masking engine.

Every refusal carries a code, and optionally an element path and a detector id. None of
them ever carries a value: a message is what the CTO would paste into an agent chat, so it
holds names and codes only (design §8.4).
"""

import re
from typing import Final, override

# Element names come from IWS and, inside embedded payloads, from other callers' requests.
# A path segment that is not a plain XML name of reasonable length is shown as "?".
_SAFE_SEGMENT: Final = re.compile(
    r"[A-Za-z_][A-Za-z0-9_.\-]{0,63}(\[[A-Za-z_][A-Za-z0-9_.\-]{0,63}\])?"
)
_DIGIT_RUN: Final = re.compile(r"\d{5,}")


def safe_path(segments: list[str] | tuple[str, ...]) -> str:
    """Join path segments, replacing any segment that could carry data with ``?``."""
    shown: list[str] = []
    for segment in segments:
        if _SAFE_SEGMENT.fullmatch(segment) and not _DIGIT_RUN.search(segment):
            shown.append(segment)
        else:
            shown.append("?")
    return "/".join(shown)


class MaskingError(Exception):
    """Base class: the call is refused or blocked and nothing is written for it."""

    def __init__(self, code: str, path: str = "", detector: str = "") -> None:
        """Store the refusal code, the element path and the detector id (never a value)."""
        super().__init__(code)
        self.code = code
        self.path = path
        self.detector = detector

    @override
    def __str__(self) -> str:
        """Return the code, the path and the detector id only."""
        parts = [self.code]
        if self.path:
            parts.append(f"path={self.path}")
        if self.detector:
            parts.append(f"detector={self.detector}")
        return " ".join(parts)

    @override
    def __repr__(self) -> str:
        """Return the same text as ``str()``."""
        return f"{type(self).__name__}({self})"


class MaskingBlockedError(MaskingError):
    """A response could not be masked safely (``MASKING_BLOCKED``, design §8.4)."""


class RequestRefusedError(MaskingError):
    """A request cannot be unmasked: refused before any IWS call (design §5.5)."""


class FieldMapError(MaskingError):
    """The field map or the overrides file is invalid. Raised at load time."""


class VaultError(MaskingError):
    """The vault refused an operation (not issued, space exhausted, reserved prefix)."""
