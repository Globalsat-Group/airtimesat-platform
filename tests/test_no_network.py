"""The suite-wide network guard of ``tests/conftest.py``: loopback only, nothing else."""

import socket

import pytest

# Documentation addresses and a reserved name: blocked before any packet is sent.
REMOTE = [("192.0.2.1", 8443), ("2001:db8::1", 8443, 0, 0)]


@pytest.mark.parametrize("address", REMOTE)
def test_a_remote_connect_is_blocked(address: tuple[object, ...]) -> None:
    # The guard refuses before the system call, so one IPv4 socket serves both address forms
    # (some CI and agent containers have no IPv6).
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        with pytest.raises(OSError, match="loopback"):
            sock.connect(address)
        with pytest.raises(OSError, match="loopback"):
            sock.connect_ex(address)


def test_name_resolution_is_blocked() -> None:
    with pytest.raises(OSError, match="loopback"):
        socket.getaddrinfo("h-k3f9q2m7.example.invalid", 8443)


def test_loopback_still_works() -> None:
    with socket.socket() as server:
        server.bind(("127.0.0.1", 0))
        server.listen(1)
        with socket.create_connection(server.getsockname(), timeout=5):
            pass
