"""The SITEST endpoints: the only IWS destinations the S2 signer core can reach.

Nothing else lives here, and nothing changes these values at run time: no setting,
environment variable, flag or plan field. There is no Beta or production endpoint in this
package (design ``docs/design/s2-recorder-masker.md`` §7.1); a test keeps every other
Iridium host name out of ``src/``.

The transport connects only to an address in ``SITEST_PINNED_ADDRESSES`` and never asks DNS
for the IWS host. The tuple stays empty until the CTO records SITEST's address and
certificate in the first live step (§10.2 step 1) and pins it here in a reviewed change,
checked against the runbook's record of SITEST's and Beta's addresses. While it is empty,
every send is refused.
"""

from enum import StrEnum
from typing import Final

SITEST_HOST: Final = "iwstraining.iridium.com"
"""Sent as SNI and ``Host``; the TLS certificate is verified for this name."""

SITEST_PORT: Final = 8443
"""The IWS port in the catalog. Annex D also mentions 8843, to be confirmed with Iridium."""

SITEST_PINNED_ADDRESSES: Final[tuple[str, ...]] = ()
"""Reviewed IP addresses of SITEST. Empty until the CTO pins them (§10.2 step 1)."""


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
