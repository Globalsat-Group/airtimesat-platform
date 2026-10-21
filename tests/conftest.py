"""Shared fixtures: the network guard, and fake keys, an in-memory vault and the synthetic map.

Every key is an obviously fake constant and every identifier is a canary (design §8.2). The
network guard lets tests open loopback connections only, so no test can reach SITEST or any
other host, whatever the pinned address holds (CLAUDE.md: agents never call SITEST).
"""

import ipaddress
import socket
from collections.abc import Callable
from pathlib import Path
from typing import Any, cast

import pytest

from airtimesat_platform.common.secrets import SecretValue
from airtimesat_platform.masker.engine import MaskingEngine
from airtimesat_platform.masker.fieldmap.loader import build_field_map
from airtimesat_platform.masker.fieldmap.model import FieldMap
from airtimesat_platform.masker.freetext import Template
from airtimesat_platform.masker.keys import MaskingKeys
from airtimesat_platform.masker.tokenize.vault import InMemoryVaultStore, Vault

DATA = Path(__file__).parent / "masker" / "data"
SOAP11 = "http://schemas.xmlsoap.org/soap/envelope/"
XSI = "http://www.w3.org/2001/XMLSchema-instance"
# The synthetic SP account number and name the recorder would pass as constants.
SP_ACCOUNT = "canary-sp-account-1"
SP_NAME = "Canary SP Name"


class NetworkBlockedError(OSError):
    """A test tried to reach a host other than this machine."""


def _local(host: object) -> bool:
    text = host.decode() if isinstance(host, bytes) else str(host)
    if text == "localhost":
        return True
    try:
        return ipaddress.ip_address(text.split("%", 1)[0]).is_loopback
    except ValueError:
        return False


def _local_address(address: object) -> bool:
    # AF_INET and AF_INET6 addresses are tuples; anything else (an AF_UNIX path) is local.
    if isinstance(address, tuple):
        host: object = cast(tuple[object, ...], address)[0] if address else None
        return _local(host)
    return True


@pytest.fixture(autouse=True)
def _no_network(monkeypatch: pytest.MonkeyPatch) -> None:
    connect = socket.socket.connect
    connect_ex = socket.socket.connect_ex
    getaddrinfo = socket.getaddrinfo

    def guarded_connect(self: socket.socket, address: Any) -> None:
        if not _local_address(address):
            raise NetworkBlockedError("tests may connect to loopback addresses only")
        connect(self, address)

    def guarded_connect_ex(self: socket.socket, address: Any) -> int:
        if not _local_address(address):
            raise NetworkBlockedError("tests may connect to loopback addresses only")
        return connect_ex(self, address)

    def guarded_getaddrinfo(host: Any, *args: Any, **kwargs: Any) -> Any:
        if host is not None and not _local(host):
            raise NetworkBlockedError("tests may resolve loopback names only")
        return getaddrinfo(host, *args, **kwargs)

    monkeypatch.setattr(socket.socket, "connect", guarded_connect)
    monkeypatch.setattr(socket.socket, "connect_ex", guarded_connect_ex)
    monkeypatch.setattr(socket, "getaddrinfo", guarded_getaddrinfo)


def fake_keys(seed: int = 1) -> MaskingKeys:
    """Return three distinct, obviously fake 256-bit keys."""
    return MaskingKeys.from_secrets(
        SecretValue(f"{seed:02x}" * 32),
        SecretValue(f"{seed + 1:02x}" * 32),
        SecretValue(f"{seed + 2:02x}" * 32),
    )


def generated_text() -> str:
    """Return the synthetic generated map."""
    return (DATA / "generated.yaml").read_text(encoding="utf-8")


def overrides_text() -> str:
    """Return the synthetic overrides."""
    return (DATA / "overrides.yaml").read_text(encoding="utf-8")


def envelope(body: str, header: str = "") -> bytes:
    """Wrap a body element in a SOAP 1.1 envelope."""
    return (
        f'<?xml version="1.0" encoding="UTF-8"?>'
        f'<soap:Envelope xmlns:soap="{SOAP11}" xmlns:xsi="{XSI}">{header}'
        f"<soap:Body>{body}</soap:Body></soap:Envelope>"
    ).encode()


@pytest.fixture
def store() -> InMemoryVaultStore:
    """Return an empty in-memory vault store."""
    return InMemoryVaultStore()


@pytest.fixture
def vault(store: InMemoryVaultStore) -> Vault:
    """Return a vault over the store with fake keys."""
    return Vault(store, fake_keys())


@pytest.fixture
def mapped() -> tuple[FieldMap, list[Template]]:
    """Return the synthetic field map and its templates."""
    return build_field_map(generated_text(), overrides_text())


@pytest.fixture
def make_engine(
    mapped: tuple[FieldMap, list[Template]], vault: Vault
) -> Callable[..., MaskingEngine]:
    """Return a factory for engines over the synthetic map and the shared vault."""
    field_map, templates = mapped

    def make(**kwargs: Any) -> MaskingEngine:
        options: dict[str, Any] = {
            "templates": templates,
            "constants": {"SP": [SP_ACCOUNT], "SP-Name": [SP_NAME]},
        }
        options.update(kwargs)
        return MaskingEngine(field_map, vault, **options)

    return make


@pytest.fixture
def engine(make_engine: Callable[..., MaskingEngine]) -> MaskingEngine:
    """Return an engine with the default settings."""
    return make_engine()


Envelope = Callable[..., bytes]


@pytest.fixture(name="envelope")
def envelope_fixture() -> Envelope:
    """Return the SOAP 1.1 envelope builder."""
    return envelope


@pytest.fixture(name="map_texts")
def map_texts_fixture() -> tuple[str, str]:
    """Return the synthetic generated map and overrides texts."""
    return generated_text(), overrides_text()


@pytest.fixture(name="keys_factory")
def keys_factory_fixture() -> Callable[[int], MaskingKeys]:
    """Return the fake key factory."""
    return fake_keys
