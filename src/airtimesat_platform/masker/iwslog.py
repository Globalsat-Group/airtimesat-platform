"""The IWS log's caller rules: the ``getIwsRequests`` caller filter and the caller keep.

- **Caller filter** (design §5.3). Before masking, every IWS log entry whose ``caller`` does
  not start with ``rec.`` is removed, so other callers' requests never reach a recording, not
  even masked. The removed count goes to the run manifest.
- **Caller keep** (design §13 #29). The recorder's own ``caller``, ``rec.<plan-id>``, is kept
  unmasked in caller fields. Every other caller value keeps its field-map treatment.

Values are tested here and never returned or raised.
"""

import re
from dataclasses import dataclass, field
from typing import Final

from airtimesat_platform.masker.errors import MaskingBlockedError
from airtimesat_platform.masker.xmlsafe import MAX_RESPONSE_BYTES, local_name, parse, serialize

# Names confirmed against the WSDL snapshot: getIwsRequests returns iwsLogs/iwsLog entries,
# each with one caller and one requestId (both xs:string).
LOG_ENTRY: Final = "iwsLog"
CALLER_FIELD: Final = "caller"
RECORDER_PREFIX: Final = "rec."
RECORDER_CALLER: Final = re.compile(r"rec\.RP-[0-9]{4}-[0-9]{3}")


def is_recorder_caller(name: str, value: str) -> bool:
    """Return whether a leaf is a caller field holding exactly ``rec.RP-YYYY-NNN``."""
    return name == CALLER_FIELD and RECORDER_CALLER.fullmatch(value) is not None


@dataclass(frozen=True, slots=True)
class FilteredLog:
    """A ``getIwsRequests`` response with other callers' entries removed. Still raw."""

    body: bytes = field(repr=False)
    kept: int
    removed: int


def filter_callers(response: bytes) -> FilteredLog:
    """Remove every log entry whose single ``caller`` does not start with ``rec.``.

    An entry with no ``caller``, or with more than one, is removed too. A ``caller`` element
    outside a log entry blocks the response, because the filter would not know its entry.
    """
    root = parse(response, max_bytes=MAX_RESPONSE_BYTES, request=False, error=MaskingBlockedError)
    kept = removed = 0
    for entry in [e for e in root.iter() if local_name(e) == LOG_ENTRY]:
        callers = [c for c in entry if local_name(c) == CALLER_FIELD]
        if len(callers) == 1 and (callers[0].text or "").startswith(RECORDER_PREFIX):
            kept += 1
            continue
        parent = entry.getparent()
        if parent is None:
            raise MaskingBlockedError("CALLER_FILTER_ROOT")
        parent.remove(entry)
        removed += 1
    for element in root.iter():
        parent = element.getparent()
        if local_name(element) == CALLER_FIELD and (
            parent is None or local_name(parent) != LOG_ENTRY
        ):
            raise MaskingBlockedError("CALLER_OUTSIDE_LOG_ENTRY")
    return FilteredLog(serialize(root, declaration=True), kept, removed)
