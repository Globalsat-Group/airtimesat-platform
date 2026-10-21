"""IWS request signing.

The rule (catalog signature algorithm; Annex D §2.3):

- ``timestamp`` is the current time in UTC, formatted ``yyyy-MM-dd'T'HH:mm:ss'Z'``. It is
  always computed in explicit UTC, never in the host time zone.
- The data signed is the exact, case-sensitive WSDL operation name immediately followed by
  the timestamp, with no separator.
- ``signature = Base64(HMAC-SHA1(key=secret, data))``.
- The ``timestamp`` element sent must be byte-for-byte the string that was signed.

The operation name comes from the body's root element (``operation_from_envelope`` in
``envelope``), never from a hand-written string. The signature is returned only to the
envelope builder inside the signer core; it is never logged and never leaves the gateway.
"""

import base64
import hashlib
import hmac
import re
from datetime import UTC, datetime
from typing import Final

from airtimesat_platform.common.secrets import SecretValue
from airtimesat_platform.gateway.errors import SigningError

TIMESTAMP_FORMAT: Final = "%Y-%m-%dT%H:%M:%SZ"
TIMESTAMP_PATTERN: Final = re.compile(r"\A\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z\Z")
# A WSDL operation name: an ASCII letter, then ASCII letters and digits (camelCase).
OPERATION_PATTERN: Final = re.compile(r"\A[A-Za-z][A-Za-z0-9]{0,99}\Z")


def utc_timestamp(now: datetime) -> str:
    """Return ``now`` as an IWS timestamp in UTC, truncated to whole seconds.

    ``now`` must be timezone-aware. A naive datetime is refused, because its zone is
    unknown and a literal ``Z`` on local time is exactly the bug the rule warns about.
    """
    offset = now.utcoffset()
    if offset is None:
        raise SigningError("TIMESTAMP_NOT_TIMEZONE_AWARE")
    return now.astimezone(UTC).strftime(TIMESTAMP_FORMAT)


def sign(secret: SecretValue, operation: str, timestamp: str) -> str:
    """Return the Base64 HMAC-SHA1 signature of ``operation + timestamp`` under ``secret``."""
    if not OPERATION_PATTERN.fullmatch(operation):
        raise SigningError("OPERATION_NAME_INVALID")
    if not TIMESTAMP_PATTERN.fullmatch(timestamp):
        raise SigningError("TIMESTAMP_FORMAT_INVALID")
    key = secret.reveal().encode("utf-8")
    if not key:
        raise SigningError("SECRET_EMPTY")
    digest = hmac.new(key, (operation + timestamp).encode("utf-8"), hashlib.sha1).digest()
    return base64.b64encode(digest).decode("ascii")
