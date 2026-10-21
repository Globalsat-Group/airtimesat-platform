"""The SITEST endpoints: the only IWS destinations the S2 signer core can reach.

Nothing else lives here, and nothing changes these values at run time: no setting,
environment variable, flag or plan field. There is no Beta or production endpoint in this
package (design ``docs/design/s2-recorder-masker.md`` §7.1); a test keeps every other
Iridium host name out of ``src/``.

The transport connects only to an address in ``SITEST_PINNED_ADDRESSES`` and never asks DNS
for the IWS host. The CTO recorded SITEST's address and certificate in the first live step
(§10.2 step 1, 21 Oct 2026; ``docs/runbooks/sitest_endpoint_record.md``) and pinned it here
in a reviewed change (runbook ``02``). The certificate is a wildcard that also covers Beta's
name, so this address, not the TLS name check, is what separates SITEST from Beta. If SITEST
moves, every send fails until a reviewed re-pin.
"""

from enum import StrEnum
from typing import Final

SITEST_HOST: Final = "iwstraining.iridium.com"
"""Sent as SNI and ``Host``; the TLS certificate is verified for this name."""

SITEST_PORT: Final = 8443
"""The IWS port, confirmed by both SITEST WSDLs' ``soap12:address`` (21 Oct 2026)."""

SITEST_PINNED_ADDRESSES: Final[tuple[str, ...]] = ("174.68.1.46",)
"""Reviewed IP addresses of SITEST, from the endpoint record of 21 Oct 2026."""


class Endpoint(StrEnum):
    """The two IWS services on SITEST."""

    PROVISIONING = "provisioning"
    REPORTING = "reporting"


ENDPOINT_PATHS: Final[dict[Endpoint, str]] = {
    Endpoint.PROVISIONING: "/iws-current/iws",
    Endpoint.REPORTING: "/iwsReport-current/iws-report",
}


def endpoint_url(endpoint: Endpoint) -> str:
    """Return the SITEST URL of ``endpoint``."""
    return f"https://{SITEST_HOST}:{SITEST_PORT}{ENDPOINT_PATHS[endpoint]}"
