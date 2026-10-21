"""The SITEST transport against a local TLS server: no IWS host is ever contacted.

The test points the pinned address at 127.0.0.1 and the port at a local test server, and
trusts a throwaway CA generated in memory. Everything else is the production code path:
the pinned resolver, SNI and ``Host`` for the SITEST name, certificate verification, no
redirects, one connection, no proxy from the environment and the reply cap.
"""

import asyncio
import datetime as dt
import ipaddress
import ssl
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path

import pytest
from aiohttp import web
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from airtimesat_platform.gateway import endpoints_sitest, transport
from airtimesat_platform.gateway.endpoints_sitest import Endpoint, endpoint_url
from airtimesat_platform.gateway.errors import ResponseError, TransportError, TransportTimeoutError
from airtimesat_platform.gateway.transport import (
    MAX_REPLY_BYTES,
    AiohttpTransport,
    PinnedResolver,
    check_sitest_url,
)

SITEST = endpoints_sitest.SITEST_HOST
SYSTEM_TLS_CONTEXT = transport.tls_context  # captured before any test replaces it


@dataclass
class Pki:
    ca_path: Path
    cert_path: Path
    key_path: Path


def _name(common_name: str) -> x509.Name:
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])


def _make_pki(directory: Path, server_name: str) -> Pki:
    now = dt.datetime.now(dt.UTC)
    ca_key = ec.generate_private_key(ec.SECP256R1())
    ca = (
        x509.CertificateBuilder()
        .subject_name(_name("test-only CA"))
        .issuer_name(_name("test-only CA"))
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(minutes=5))
        .not_valid_after(now + dt.timedelta(hours=1))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()), critical=False
        )
        .sign(ca_key, hashes.SHA256())
    )
    key = ec.generate_private_key(ec.SECP256R1())
    cert = (
        x509.CertificateBuilder()
        .subject_name(_name(server_name))
        .issuer_name(ca.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(minutes=5))
        .not_valid_after(now + dt.timedelta(hours=1))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(server_name)]), critical=False)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.SERVER_AUTH]), critical=False
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()),
            critical=False,
        )
        .sign(ca_key, hashes.SHA256())
    )
    pki = Pki(directory / "ca.pem", directory / "cert.pem", directory / "key.pem")
    pki.ca_path.write_bytes(ca.public_bytes(serialization.Encoding.PEM))
    pki.cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    pki.key_path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    return pki


@dataclass
class Seen:
    hosts: list[str] = field(default_factory=list[str])
    paths: list[str] = field(default_factory=list[str])
    content_types: list[str] = field(default_factory=list[str])
    accept_encodings: list[str] = field(default_factory=list[str])
    sni: list[str | None] = field(default_factory=list[str | None])
    active: int = 0
    peak: int = 0


async def _serve(
    pki: Pki, seen: Seen, reply: Callable[[web.Request], web.StreamResponse], delay: float = 0.0
) -> tuple[web.AppRunner, int]:
    async def handle(request: web.Request) -> web.StreamResponse:
        seen.hosts.append(request.host)
        seen.paths.append(request.path)
        seen.content_types.append(request.headers.get("Content-Type", ""))
        seen.accept_encodings.append(request.headers.get("Accept-Encoding", ""))
        await request.read()
        seen.active += 1
        seen.peak = max(seen.peak, seen.active)
        try:
            if delay:
                await asyncio.sleep(delay)
            return reply(request)
        finally:
            seen.active -= 1

    app = web.Application()
    app.router.add_route("*", "/{tail:.*}", handle)
    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    context.load_cert_chain(pki.cert_path, pki.key_path)

    def on_sni(sock: ssl.SSLObject, name: str | None, ctx: ssl.SSLContext) -> None:
        seen.sni.append(name)

    context.sni_callback = on_sni
    runner = web.AppRunner(app, access_log=None)
    await runner.setup()
    site = web.TCPSite(runner, "127.0.0.1", 0, ssl_context=context)
    await site.start()
    port = runner.addresses[0][1]
    return runner, port


@pytest.fixture
def local_sitest(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Pki:
    pki = _make_pki(tmp_path, SITEST)
    monkeypatch.setattr(endpoints_sitest, "SITEST_PINNED_ADDRESSES", ("127.0.0.1",))

    def trusting_context() -> ssl.SSLContext:
        context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=str(pki.ca_path))
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        return context

    monkeypatch.setattr(transport, "tls_context", trusting_context)
    # A proxy in the environment must be ignored.
    monkeypatch.setenv("HTTPS_PROXY", "http://127.0.0.1:9")
    monkeypatch.setenv("https_proxy", "http://127.0.0.1:9")
    return pki


def _ok(request: web.Request) -> web.StreamResponse:
    return web.Response(body=b"<ok/>", content_type="application/soap+xml")


def _run(
    monkeypatch: pytest.MonkeyPatch,
    pki: Pki,
    reply: Callable[[web.Request], web.StreamResponse] = _ok,
    *,
    calls: int = 1,
    delay: float = 0.0,
    endpoint: Endpoint = Endpoint.PROVISIONING,
) -> tuple[Seen, list[transport.TransportReply | BaseException]]:
    seen = Seen()

    async def scenario() -> list[transport.TransportReply | BaseException]:
        runner, port = await _serve(pki, seen, reply, delay)
        monkeypatch.setattr(endpoints_sitest, "SITEST_PORT", port)
        client = AiohttpTransport()
        try:
            return await asyncio.gather(
                *(
                    client.post(endpoint_url(endpoint), b"<e/>", "accountSearch")
                    for _ in range(calls)
                ),
                return_exceptions=True,
            )
        finally:
            await client.close()
            await runner.cleanup()

    return seen, asyncio.run(scenario())


def test_post_reaches_the_pinned_address_with_the_sitest_name(
    monkeypatch: pytest.MonkeyPatch, local_sitest: Pki
) -> None:
    seen, [reply] = _run(monkeypatch, local_sitest)
    assert isinstance(reply, transport.TransportReply)
    assert reply.status == 200
    assert reply.body == b"<ok/>"
    assert reply.date_header
    port = endpoints_sitest.SITEST_PORT
    assert seen.hosts == [f"{SITEST}:{port}"]
    assert seen.sni == [SITEST]
    assert seen.paths == ["/iws-current/iws"]
    assert seen.content_types == ['application/soap+xml; charset=utf-8; action="accountSearch"']
    assert seen.accept_encodings == ["identity"]


def test_reporting_path(monkeypatch: pytest.MonkeyPatch, local_sitest: Pki) -> None:
    seen, _ = _run(monkeypatch, local_sitest, endpoint=Endpoint.REPORTING)
    assert seen.paths == ["/iwsReport-current/iws-report"]


def test_one_connection_at_a_time(monkeypatch: pytest.MonkeyPatch, local_sitest: Pki) -> None:
    seen, replies = _run(monkeypatch, local_sitest, calls=3, delay=0.05)
    assert all(isinstance(reply, transport.TransportReply) for reply in replies)
    assert seen.peak == 1


def test_redirects_are_never_followed(monkeypatch: pytest.MonkeyPatch, local_sitest: Pki) -> None:
    def redirect(request: web.Request) -> web.StreamResponse:
        if request.path == "/elsewhere":
            return _ok(request)
        return web.Response(status=302, headers={"Location": "/elsewhere"})

    seen, [reply] = _run(monkeypatch, local_sitest, redirect)
    assert isinstance(reply, ResponseError)
    assert reply.code == "REDIRECT_REFUSED"
    assert seen.paths == ["/iws-current/iws"]


def test_reply_cap(monkeypatch: pytest.MonkeyPatch, local_sitest: Pki) -> None:
    def huge(request: web.Request) -> web.StreamResponse:
        return web.Response(body=b"x" * (MAX_REPLY_BYTES + 1))

    _, [reply] = _run(monkeypatch, local_sitest, huge)
    assert isinstance(reply, ResponseError)
    assert reply.code == "REPLY_TOO_LARGE"


def test_compressed_replies_are_refused(monkeypatch: pytest.MonkeyPatch, local_sitest: Pki) -> None:
    def gzipped(request: web.Request) -> web.StreamResponse:
        return web.Response(body=b"\x1f\x8b", headers={"Content-Encoding": "gzip"})

    _, [reply] = _run(monkeypatch, local_sitest, gzipped)
    assert isinstance(reply, ResponseError)
    assert reply.code == "REPLY_ENCODING_REFUSED"


def test_certificate_for_another_name_fails(
    monkeypatch: pytest.MonkeyPatch, local_sitest: Pki, tmp_path: Path
) -> None:
    (tmp_path / "wrong").mkdir()
    wrong = _make_pki(tmp_path / "wrong", "other.example.invalid")

    def trusting_wrong_ca() -> ssl.SSLContext:
        return ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=str(wrong.ca_path))

    monkeypatch.setattr(transport, "tls_context", trusting_wrong_ca)
    _, [reply] = _run(monkeypatch, wrong)
    assert isinstance(reply, TransportError)
    assert reply.code == "TLS_FAILED"


def test_untrusted_certificate_fails(monkeypatch: pytest.MonkeyPatch, local_sitest: Pki) -> None:
    # The real context trusts only the system store, which does not hold the test CA.
    monkeypatch.setattr(transport, "tls_context", SYSTEM_TLS_CONTEXT)
    _, [reply] = _run(monkeypatch, local_sitest)
    assert isinstance(reply, TransportError)
    assert reply.code == "TLS_FAILED"


# ---------------------------------------------------------------- without a server


def test_no_pinned_address_refuses_to_build(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(endpoints_sitest, "SITEST_PINNED_ADDRESSES", ())

    async def build() -> None:
        AiohttpTransport()

    with pytest.raises(TransportError) as raised:
        asyncio.run(build())
    assert raised.value.code == "SITEST_ADDRESS_NOT_PINNED"


def test_every_pinned_address_is_one_global_ip_address() -> None:
    # Empty until the CTO pins SITEST (runbook 02); then each entry is a plain, global IP.
    pinned = endpoints_sitest.SITEST_PINNED_ADDRESSES
    assert len(set(pinned)) == len(pinned)
    for value in pinned:
        address = ipaddress.ip_address(value)
        assert str(address) == value
        assert address.is_global


@pytest.mark.parametrize(
    "url",
    [
        "https://iwstraining.iridium.com:8443/iws-current/iws?x=1",
        "https://iwstraining.iridium.com:8443/other",
        "http://iwstraining.iridium.com:8443/iws-current/iws",
        "https://iwstraining.iridium.com/iws-current/iws",
        "https://user@iwstraining.iridium.com:8443/iws-current/iws",
        "https://127.0.0.1:8443/iws-current/iws",
        "https://iwstraining.iridium.com.example.invalid:8443/iws-current/iws",
        "https://h-k3f9q2m7.example.invalid:8443/iws-current/iws",
    ],
)
def test_only_the_two_sitest_urls_are_accepted(url: str) -> None:
    with pytest.raises(TransportError) as raised:
        check_sitest_url(url)
    assert raised.value.code == "DESTINATION_NOT_SITEST"


@pytest.mark.parametrize("endpoint", list(Endpoint))
def test_the_sitest_urls_are_accepted(endpoint: Endpoint) -> None:
    assert check_sitest_url(endpoint_url(endpoint)).host == SITEST


def test_resolver_answers_only_for_sitest() -> None:
    resolver = PinnedResolver(("192.0.2.10",))

    async def scenario() -> None:
        [result] = await resolver.resolve(SITEST, endpoints_sitest.SITEST_PORT)
        assert result["host"] == "192.0.2.10"
        assert result["hostname"] == SITEST
        for host in ("h-k3f9q2m7.example.invalid", SITEST.upper(), "127.0.0.1"):
            with pytest.raises(OSError, match="not the pinned"):
                await resolver.resolve(host, endpoints_sitest.SITEST_PORT)
        with pytest.raises(OSError, match="not the pinned"):
            await resolver.resolve(SITEST, 443)
        await resolver.close()

    asyncio.run(scenario())


def test_resolver_with_no_address_refuses() -> None:
    async def scenario() -> None:
        with pytest.raises(OSError, match="no SITEST address"):
            await PinnedResolver(()).resolve(SITEST, endpoints_sitest.SITEST_PORT)

    asyncio.run(scenario())


def test_resolver_accepts_only_ip_literals() -> None:
    with pytest.raises(OSError, match="illegal IP address"):
        PinnedResolver(("h-k3f9q2m7.example.invalid",))


def test_tls_context_ignores_a_key_log_file_in_the_environment(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    # SSLKEYLOGFILE would make the TLS session keys, and so every signature and raw reply in
    # a packet capture, readable to whoever holds the file.
    monkeypatch.setenv("SSLKEYLOGFILE", str(tmp_path / "keys.log"))
    assert ssl.create_default_context().keylog_filename  # the stdlib honours it by default
    assert SYSTEM_TLS_CONTEXT().keylog_filename is None


def test_post_refuses_any_url_but_sitest_before_connecting(
    monkeypatch: pytest.MonkeyPatch, local_sitest: Pki
) -> None:
    # An IP-literal URL would skip the pinned resolver, so the URL check is what stops it.
    seen = Seen()

    async def scenario() -> TransportError:
        runner, port = await _serve(local_sitest, seen, _ok)
        monkeypatch.setattr(endpoints_sitest, "SITEST_PORT", port)
        client = AiohttpTransport()
        try:
            with pytest.raises(TransportError) as raised:
                await client.post(f"https://127.0.0.1:{port}/iws-current/iws", b"<e/>", "x")
            return raised.value
        finally:
            await client.close()
            await runner.cleanup()

    error = asyncio.run(scenario())
    assert error.code == "DESTINATION_NOT_SITEST"
    assert seen.paths == []
    assert seen.sni == []


def test_tls_context_verifies_names() -> None:
    context = transport.tls_context()
    assert context.check_hostname is True
    assert context.verify_mode == ssl.CERT_REQUIRED
    assert context.minimum_version >= ssl.TLSVersion.TLSv1_2


def test_timeout_is_reported_as_a_timeout(
    monkeypatch: pytest.MonkeyPatch, local_sitest: Pki
) -> None:
    monkeypatch.setattr(transport, "TOTAL_TIMEOUT_S", 0.05)
    _, [reply] = _run(monkeypatch, local_sitest, delay=0.5)
    assert isinstance(reply, TransportTimeoutError)
    assert reply.code == "TRANSPORT_TIMEOUT"


def test_nothing_listening_is_a_transport_failure(
    monkeypatch: pytest.MonkeyPatch, local_sitest: Pki
) -> None:
    import socket

    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        free_port = probe.getsockname()[1]
    monkeypatch.setattr(endpoints_sitest, "SITEST_PORT", free_port)

    async def scenario() -> TransportError:
        client = AiohttpTransport()
        try:
            with pytest.raises(TransportError) as raised:
                await client.post(endpoint_url(Endpoint.PROVISIONING), b"<e/>", "accountSearch")
            return raised.value
        finally:
            await client.close()

    error = asyncio.run(scenario())
    assert error.code == "TRANSPORT_FAILED"
    assert "127.0.0.1" not in repr(error)
