"""Errors raised by the SITEST signer core.

Every error carries a fixed code and nothing else: no request or response text, no
identifier, no secret and no signature. IWS, lxml and aiohttp messages can echo input, so
they are never copied into these errors, and the underlying exception is not chained.
"""

from typing import override


class GatewayError(Exception):
    """Base class. ``str()`` is the code only."""

    def __init__(self, code: str) -> None:
        """Hold ``code``, a fixed upper-case identifier."""
        super().__init__(code)
        self.code = code

    @override
    def __str__(self) -> str:
        """Return the code."""
        return self.code


class RefusedError(GatewayError):
    """The guard or the envelope builder refused the call before anything was sent."""


class SigningError(GatewayError):
    """The signature or its timestamp could not be produced."""


class TransportError(GatewayError):
    """The request could not be sent, or the reply could not be read."""


class TransportTimeoutError(TransportError):
    """The call was cut off by a timeout; IWS may still be working on it."""


class ResponseError(GatewayError):
    """The reply is not acceptable (not SOAP, too large, unexpected status, clock skew)."""


class IwsThrottledError(ResponseError):
    """IWS answered "Too many connections!"; the run stops."""
