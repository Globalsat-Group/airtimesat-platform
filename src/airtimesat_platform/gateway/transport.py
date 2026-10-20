"""HTTP transport to SITEST: one connection, pinned address, no DNS, no redirects.

Layer 2 of Beta unreachability (design ``docs/design/s2-recorder-masker.md`` §7.1):

- It sends only to the two SITEST URLs, and checks before each send that the URL's scheme,
  host and port are the SITEST constants.
- It never asks DNS for the IWS host: a resolver of its own answers only for the SITEST host,
  with the reviewed addresses in ``endpoints_sitest.SITEST_PINNED_ADDRESSES``, and refuses
  every other name. While no address is pinned, every send is refused.
- SNI and ``Host`` carry the SITEST name, and the TLS certificate is verified for it (system
  trust store, TLS 1.2 or later).
- Redirects are never followed; a 3xx reply is an error.
- At most one connection (and so one request) at a time, which leaves the IWS user's second
  slot to the CTO (§5.8).
- No proxy from the environment, no cookies, no compressed replies, and a 5 MB reply cap.

aiohttp errors can carry request details, so they are replaced by codes (``errors``).
"""

import socket
import ssl
from dataclasses import dataclass, field
from typing import Final, Protocol, override

import aiohttp
from aiohttp.abc import AbstractResolver, ResolveResult
from yarl import URL

from airtimesat_platform.gateway import endpoints_sitest
from airtimesat_platform.gateway.errors import (
    ResponseError,
    TransportError,
    TransportTimeoutError,
)

MAX_REPLY_BYTES: Final = 5 * 1024 * 1024
CONNECT_TIMEOUT_S: Final = 15.0
TOTAL_TIMEOUT_S: Final = 120.0
_CHUNK: Final = 64 * 1024


@dataclass(frozen=True, slots=True)
class TransportReply:
    """A raw HTTP reply. ``body`` is raw SITEST data: never log or print it."""

    status: int
    date_header: str | None
    body: bytes = field(repr=False)


class Transport(Protocol):
    """Sends one SOAP 1.2 request to a SITEST URL."""

    async def post(self, url: str, envelope: bytes, action: str) -> TransportReply:
        """Send ``envelope`` with SOAP action ``action`` and return the raw reply."""
        ...

    async def close(self) -> None:
        """Release the connection."""
        ...


def check_sitest_url(url: str) -> URL:
    """Return ``url`` parsed, or refuse it unless it is one of the two SITEST URLs."""
    parsed = URL(url)
    allowed = {endpoints_sitest.endpoint_url(endpoint) for endpoint in endpoints_sitest.Endpoint}
    if (
        url not in allowed
        or parsed.scheme != "https"
        or parsed.host != endpoints_sitest.SITEST_HOST
        or parsed.port != endpoints_sitest.SITEST_PORT
        or parsed.user is not None
        or parsed.query_string
        or parsed.fragment
    ):
        raise TransportError("DESTINATION_NOT_SITEST")
    return parsed


class PinnedResolver(AbstractResolver):
    """Answers only for the SITEST host, with the pinned addresses; never asks DNS."""

    def __init__(self, addresses: tuple[str, ...]) -> None:
        """Hold the reviewed SITEST ``addresses``."""
        for address in addresses:
            socket.inet_pton(socket.AF_INET6 if ":" in address else socket.AF_INET, address)
        self._addresses = addresses

    @override
    async def resolve(
        self, host: str, port: int = 0, family: socket.AddressFamily = socket.AF_INET
    ) -> list[ResolveResult]:
        """Return the pinned addresses for the SITEST host; refuse any other host or port."""
        if host != endpoints_sitest.SITEST_HOST or port != endpoints_sitest.SITEST_PORT:
            raise OSError("host is not the pinned SITEST host")
        if not self._addresses:
            raise OSError("no SITEST address is pinned")
        return [
            ResolveResult(
                hostname=endpoints_sitest.SITEST_HOST,
                host=address,
                port=port,
                family=socket.AF_INET6 if ":" in address else socket.AF_INET,
                proto=0,
                flags=socket.AI_NUMERICHOST,
            )
            for address in self._addresses
        ]

    @override
    async def close(self) -> None:
        """Nothing to release."""


def tls_context() -> ssl.SSLContext:
    """Return the client TLS context: system trust store, hostname check, TLS 1.2 or later.

    ``ssl.create_default_context`` writes the TLS session keys to the file named by the
    ``SSLKEYLOGFILE`` environment variable, if set. With those keys a packet capture of a
    call shows the signature, ``iwsUsername`` and the raw SITEST reply, so key logging is
    switched off whatever the environment says.
    """
    context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
    context.keylog_filename = None  # pyright: ignore[reportAttributeAccessIssue]
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.check_hostname = True
    context.verify_mode = ssl.CERT_REQUIRED
    return context


class AiohttpTransport:
    """The real transport. Create it inside the event loop that will use it."""

    def __init__(self) -> None:
        """Build the session; refuse if no SITEST address is pinned."""
        addresses = endpoints_sitest.SITEST_PINNED_ADDRESSES
        if not addresses:
            raise TransportError("SITEST_ADDRESS_NOT_PINNED")
        connector = aiohttp.TCPConnector(
            limit=1,
            limit_per_host=1,
            resolver=PinnedResolver(addresses),
            ssl=tls_context(),
            use_dns_cache=False,
        )
        self._session = aiohttp.ClientSession(
            connector=connector,
            timeout=aiohttp.ClientTimeout(total=TOTAL_TIMEOUT_S, connect=CONNECT_TIMEOUT_S),
            trust_env=False,
            cookie_jar=aiohttp.DummyCookieJar(),
            auto_decompress=False,
            raise_for_status=False,
        )

    async def post(self, url: str, envelope: bytes, action: str) -> TransportReply:
        """Send ``envelope`` to the SITEST ``url``; return the raw reply."""
        target = check_sitest_url(url)
        headers = {
            "Content-Type": f'application/soap+xml; charset=utf-8; action="{action}"',
            "Accept": "application/soap+xml, text/xml",
            "Accept-Encoding": "identity",
        }
        try:
            async with self._session.post(
                target, data=envelope, headers=headers, allow_redirects=False
            ) as response:
                if 300 <= response.status < 400:
                    raise ResponseError("REDIRECT_REFUSED")
                encoding = response.headers.get("Content-Encoding", "identity").strip().lower()
                if encoding not in {"", "identity"}:
                    raise ResponseError("REPLY_ENCODING_REFUSED")
                declared = response.content_length
                if declared is not None and declared > MAX_REPLY_BYTES:
                    raise ResponseError("REPLY_TOO_LARGE")
                body = bytearray()
                async for chunk in response.content.iter_chunked(_CHUNK):
                    body += chunk
                    if len(body) > MAX_REPLY_BYTES:
                        raise ResponseError("REPLY_TOO_LARGE")
                return TransportReply(
                    status=response.status,
                    date_header=response.headers.get("Date"),
                    body=bytes(body),
                )
        except TimeoutError:
            raise TransportTimeoutError("TRANSPORT_TIMEOUT") from None
        except aiohttp.ClientSSLError:
            raise TransportError("TLS_FAILED") from None
        except aiohttp.ClientError:
            raise TransportError("TRANSPORT_FAILED") from None

    async def close(self) -> None:
        """Close the session and its connection."""
        await self._session.close()
