"""Secrets piped once on standard input (design §6.2, §7.2). All values are synthetic."""

import io
import json
import logging

import pytest

from airtimesat_platform.common.secrets import SecretNotAvailableError, SecretsProvider, SecretValue
from airtimesat_platform.common.secrets_stdin import MAX_INPUT_BYTES, StdinSecretsProvider

FAKE = "fake-secret-not-real-0001"


def _read(raw: bytes) -> StdinSecretsProvider:
    return StdinSecretsProvider.from_stream(io.BytesIO(raw))


def test_reads_named_secrets() -> None:
    provider: SecretsProvider = _read(
        json.dumps({"sitest.secret_key": FAKE, "masker.k_mask": "fake-key-0002"}).encode()
    )
    assert provider.get_secret("sitest.secret_key") == SecretValue(FAKE)
    assert provider.get_secret("masker.k_mask").reveal() == "fake-key-0002"


def test_names_only() -> None:
    provider = _read(json.dumps({"sitest.secret_key": FAKE}).encode())
    assert provider.names() == frozenset({"sitest.secret_key"})


def test_missing_secret_names_the_secret() -> None:
    provider = _read(json.dumps({"sitest.secret_key": FAKE}).encode())
    with pytest.raises(SecretNotAvailableError, match=r"sitest\.iws_username"):
        provider.get_secret("sitest.iws_username")


@pytest.mark.parametrize(
    "raw",
    [
        b"",
        b"not json " + FAKE.encode(),
        json.dumps([FAKE]).encode(),
        json.dumps(FAKE).encode(),
        b'{"sitest.secret_key": "' + FAKE.encode() + b'", "sitest.secret_key": "x"}',
        json.dumps({"sitest.secret_key": 12345}).encode(),
        json.dumps({"sitest.secret_key": ""}).encode(),
        json.dumps({"sitest.secret_key": None}).encode(),
        json.dumps({FAKE: "value"}).encode().replace(b"fake", b"FAKE"),
        json.dumps({"Upper.Case": FAKE}).encode(),
        json.dumps({"": FAKE}).encode(),
        b"\xff\xfe" + FAKE.encode(),
        b"[" * 60_000,  # nested deeply enough to exhaust the JSON parser
    ],
)
def test_bad_input_is_refused_without_echoing_it(raw: bytes) -> None:
    with pytest.raises(SecretNotAvailableError) as raised:
        _read(raw)
    text = f"{raised.value!s} {raised.value!r}"
    assert FAKE not in text
    assert FAKE.upper() not in text
    assert raised.value.__cause__ is None
    assert raised.value.__suppress_context__ or raised.value.__context__ is None


def test_input_size_is_capped() -> None:
    raw = json.dumps({"sitest.secret_key": "x" * MAX_INPUT_BYTES}).encode()
    with pytest.raises(SecretNotAvailableError, match="64 KiB"):
        _read(raw)


def test_a_terminal_is_refused() -> None:
    class Terminal(io.BytesIO):
        def isatty(self) -> bool:
            return True

    with pytest.raises(SecretNotAvailableError, match="piped"):
        StdinSecretsProvider.from_stream(Terminal(json.dumps({"a": FAKE}).encode()))


def test_stdin_is_read_once(monkeypatch: pytest.MonkeyPatch) -> None:
    class FakeStdin:
        buffer = io.BytesIO(json.dumps({"sitest.secret_key": FAKE}).encode())

    monkeypatch.setattr("sys.stdin", FakeStdin())
    monkeypatch.setattr(StdinSecretsProvider, "_stdin_consumed", False)
    provider = StdinSecretsProvider.from_stdin()
    assert provider.get_secret("sitest.secret_key") == SecretValue(FAKE)
    with pytest.raises(SecretNotAvailableError, match="already read"):
        StdinSecretsProvider.from_stdin()


def test_values_never_print_or_log(caplog: pytest.LogCaptureFixture) -> None:
    provider = _read(json.dumps({"sitest.secret_key": FAKE}).encode())
    secret = provider.get_secret("sitest.secret_key")
    with caplog.at_level(logging.DEBUG):
        logging.getLogger("test").info("secret %s %r", secret, secret)
        logging.getLogger("test").info("provider %r", provider)
    assert FAKE not in caplog.text
    assert FAKE not in f"{secret} {secret!r} {provider!r} {provider.names()!r}"
