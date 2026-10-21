"""The refusal ``recorder check`` raises for a plan.

It carries a code and a location, never a value: CI logs are stored at GitHub, and a plan
might hold a real identifier (design §8.3, §8.4). A location names a plan field or a call
by its index (``calls[2]``), and an element path made only of field-map names.
"""

from typing import override


class PlanRefusedError(Exception):
    """A plan is refused: a code and a safe location."""

    def __init__(self, code: str, location: str = "") -> None:
        """Store the refusal code and the location (never a value)."""
        super().__init__(code)
        self.code = code
        self.location = location

    @override
    def __str__(self) -> str:
        """Return the code and the location only."""
        return f"{self.code} {self.location}".strip()

    @override
    def __repr__(self) -> str:
        """Return the same text as ``str()``."""
        return f"{type(self).__name__}({self})"
