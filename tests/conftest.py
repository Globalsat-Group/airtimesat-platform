"""Shared fixtures: the network guard, fake keys, a vault, the map and the run harness.

Every key is an obviously fake constant and every identifier is a canary (design §8.2). The
network guard lets tests open loopback connections only, so no test can reach SITEST or any
other host, whatever the pinned address holds (CLAUDE.md: agents never call SITEST).
"""

import copy
import io
import ipaddress
import json
import secrets
import socket
import sqlite3
import string
import subprocess
import time
from collections.abc import Callable
from datetime import UTC, datetime
from functools import cache
from pathlib import Path
from typing import Any, cast

import pytest
from lxml import etree

import generate_fieldmap as gen
from airtimesat_platform.common.secrets import SecretValue
from airtimesat_platform.common.secrets_stdin import StdinSecretsProvider
from airtimesat_platform.gateway.sitest_port import (
    Endpoint,
    SitestCredentials,
    SitestPort,
    SitestResult,
)
from airtimesat_platform.masker.engine import MaskingEngine
from airtimesat_platform.masker.fieldmap.loader import build_field_map
from airtimesat_platform.masker.fieldmap.model import FieldMap
from airtimesat_platform.masker.freetext import Template
from airtimesat_platform.masker.keys import MaskingKeys
from airtimesat_platform.masker.tokenize.vault import InMemoryVaultStore, Vault
from airtimesat_platform.recorder import plan as plan_module
from airtimesat_platform.recorder.config import Config
from airtimesat_platform.recorder.run import run_plan
from airtimesat_platform.recorder.store import DB_NAME, open_store

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


@pytest.fixture(autouse=True)
def _synthetic_schema(request: pytest.FixtureRequest, monkeypatch: pytest.MonkeyPatch) -> None:
    """Pass the WSDL schema check, except in modules that set ``REAL_WSDL_SCHEMA = True``.

    Most plans in the tests are written against the synthetic field maps, whose structure is
    invented, so the real snapshot's schema would refuse them before the check under test.
    The schema check itself is tested against the snapshot (``REAL_WSDL_SCHEMA`` modules).
    """
    if not getattr(getattr(request, "module", None), "REAL_WSDL_SCHEMA", False):

        def passes(*_: object, **__: object) -> None:
            return None

        monkeypatch.setattr(plan_module, "validate_request", passes)


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


# ---------------------------------------------------------------- the real WSDL schema
#
# Shared by tests/test_generate_fieldmap.py (PR W) and tests/masker/test_mask_first_plan.py,
# which build schema-valid responses from the CTO's snapshot. Test modules cannot import
# conftest, so the builder is a fixture.

WSDL_XS = "http://www.w3.org/2001/XMLSchema"
WsdlSchema = tuple[gen.Schema, dict[str, gen.Operation], etree.XMLSchema]


@cache
def _wsdl_schema(endpoint: str) -> WsdlSchema:
    """Return the snapshot's schema, operations and a validator with response wrappers.

    Each operation gets a global ``<op>Response`` element holding its response part, so a
    response body element validates on its own.
    """
    wsdl = etree.fromstring(gen.snapshot()[0][endpoint], etree.XMLParser(resolve_entities=False))
    schema, operations = gen.read_schema(wsdl), gen.read_operations(wsdl)
    xs = copy.deepcopy(wsdl.find(f"{gen.WSDL}types/{gen.XS}schema"))
    assert xs is not None
    for name, op in operations.items():
        wrapper = etree.SubElement(xs, f"{{{WSDL_XS}}}element", name=f"{name}Response")
        seq = etree.SubElement(
            etree.SubElement(wrapper, f"{{{WSDL_XS}}}complexType"), f"{{{WSDL_XS}}}sequence"
        )
        etree.SubElement(seq, f"{{{WSDL_XS}}}element", name="response", type=f"tns:{op.response}")
    return schema, operations, etree.XMLSchema(etree.ElementTree(xs))


@pytest.fixture(name="wsdl_schema", scope="session")
def wsdl_schema_fixture() -> Callable[[str], WsdlSchema]:
    """Return the cached builder of the snapshot's schema, by endpoint."""
    return _wsdl_schema


# ---------------------------------------------------------------- recorder run harness
#
# Shared by tests/recorder (run refusals, full runs, fail closed) and tests/leak (no raw data
# on disk). A temporary git checkout with a local origin, a fake SITEST port that returns
# synthetic SOAP replies, obviously fake keys, and a SITEST record built at run time.

RUN_NOW = datetime(2026, 10, 21, 12, 0, tzinfo=UTC)
RECORDER_DATA = Path(__file__).parent / "recorder" / "data"
RECIPIENT = "age1" + "q" * 58
NS = 'xmlns:ns="urn:example:iws"'
Reply = Callable[[str], bytes | BaseException]


def git(cwd: Path, *args: str) -> str:
    """Run git in ``cwd`` (fixed program, arguments from the test)."""
    result = subprocess.run(  # noqa: S603
        ["git", *args],  # noqa: S607
        cwd=cwd,
        capture_output=True,
        text=True,
        check=True,
    )
    return result.stdout


class FakePort:
    """A ``SitestPort`` that answers from per-operation reply functions and records requests."""

    def __init__(self, username: str, sp_account: str) -> None:
        """Answer nothing until replies are set."""
        self.replies: dict[str, Reply] = {}
        self.requests: list[tuple[str, str, str, str]] = []
        self._auth = (SecretValue(username), SecretValue(sp_account))

    async def call(
        self, endpoint: Endpoint, operation: str, request: str, caller: str
    ) -> SitestResult:
        """Return the reply for ``operation``, or raise it."""
        self.requests.append((str(endpoint), operation, request, caller))
        reply = self.replies[operation](request)
        if isinstance(reply, BaseException):
            raise reply
        return SitestResult(200, "ok", "2026-10-21T12:00:01Z", 0.25, reply)

    def auth_identifiers(self) -> tuple[SecretValue, ...]:
        """Return the fake ``iwsUsername`` and SP account number."""
        return self._auth


def search_reply(*rows: tuple[str, str]) -> bytes:
    """Return an ``accountSearch`` reply with ``(contract, imei)`` rows."""
    subscribers = "".join(
        f"<subscriber><accountNumber>{c}</accountNumber><imei>{i}</imei>"
        "<accountStatus>ACTIVE</accountStatus></subscriber>"
        for c, i in rows
    )
    return envelope(
        f"<ns:accountSearchResponse {NS}><totalNumberOfRecords>{len(rows)}"
        f"</totalNumberOfRecords><subscribers>{subscribers}</subscribers>"
        "</ns:accountSearchResponse>"
    )


def account_reply(contract: str, imei: str, status: str = "ACTIVE") -> bytes:
    """Return a ``getSubscriberAccount`` reply for one SBD account."""
    return envelope(
        f"<ns:getSubscriberAccountResponse {NS}>"
        '<account xsi:type="ns:sbdSubscriberAccountImpl">'
        f"<accountNumber>{contract}</accountNumber><imei>{imei}</imei>"
        f"<accountStatus>{status}</accountStatus></account></ns:getSubscriberAccountResponse>"
    )


def log_reply(*entries: tuple[str, str, str]) -> bytes:
    """Return a ``getIwsRequests`` reply with ``(request id, operation, caller)`` entries."""
    logs = "".join(
        f"<iwsLog><requestId>{n}</requestId><requestedOperation>{op}</requestedOperation>"
        f"<caller>{caller}</caller></iwsLog>"
        for n, op, caller in entries
    )
    return envelope(f"<ns:getIwsRequestsResponse {NS}>{logs}</ns:getIwsRequestsResponse>")


def plan_yaml(*calls: str, plan_id: str = "RP-2026-003", max_calls: int = 10) -> str:
    """Return a plan's YAML text from call blocks (see ``plan_call``)."""
    return (
        f"id: {plan_id}\ntitle: Run test\npurpose: Recorder run tests\n"
        f"expires_at: 2026-11-30T00:00:00Z\nmax_calls: {max_calls}\ncalls:\n" + "".join(calls)
    )


def plan_call(call_id: str, operation: str, request: str, for_each: str = "") -> str:
    """Return one call block of a plan."""
    reference = f"    for_each: ${{{for_each}}}\n" if for_each else ""
    return (
        f"  - id: {call_id}\n    endpoint: provisioning\n    operation: {operation}\n"
        f"{reference}    request: '{request}'\n"
    )


class Harness:
    """A trusted checkout, a vault folder, a fake port and the secrets for one test.

    Test modules cannot import this file (pytest's importlib mode), so the reply and plan
    builders are reachable through the harness too.
    """

    search_reply = staticmethod(search_reply)
    account_reply = staticmethod(account_reply)
    log_reply = staticmethod(log_reply)
    plan_yaml = staticmethod(plan_yaml)
    plan_call = staticmethod(plan_call)
    envelope = staticmethod(envelope)

    def __init__(self, tmp: Path) -> None:
        """Create the origin, the checkout and the configuration."""
        self.tmp = tmp
        origin = tmp / "origin.git"
        git(tmp, "init", "-q", "--bare", "-b", "main", str(origin))
        self.checkout = tmp / "checkout"
        git(tmp, "clone", "-q", str(origin), str(self.checkout))
        (self.checkout / "README.md").write_text("test checkout\n", encoding="utf-8")
        self.commit("initial")
        self.config = Config(
            data_dir=tmp / "data",
            checkout=self.checkout.resolve(),
            backup_recipient=RECIPIENT,
            backup_dir=tmp / "backups",
        )
        self.secret_key = "S" + secrets.token_urlsafe(16)
        self.username = "user" + "".join(secrets.choice(string.ascii_lowercase) for _ in range(8))
        self.port = FakePort(self.username, "canary-sp-account-9")
        self.secrets: dict[str, str] = {
            "masker.k_mask": "a1" * 32,
            "masker.vault_key": "b2" * 32,
            "masker.known_value_key": "c3" * 32,
            "masker.inventory_key": "d4" * 32,
            "sitest.iws_username": self.username,
            "sitest.secret_key": self.secret_key,
            "sitest.sp_account_number": "canary-sp-account-9",
        }
        # The recorder's code, as if imported from the checkout (it checks where it runs from).
        self.code_file = self.checkout / "src" / "airtimesat_platform" / "recorder" / "checkout.py"
        # What the fake scanner reports: findings, or None for a scanner that could not run.
        self.scan_result: list[tuple[str, str]] | None = []
        self.scanner_error: Exception | None = None
        self.scanned: list[Path] = []
        self.now = RUN_NOW
        self.monotonic: Callable[[], float] = time.monotonic
        self.field_map: tuple[str, str] | None = (
            (RECORDER_DATA / "generated.yaml").read_text(encoding="utf-8"),
            (RECORDER_DATA / "overrides.yaml").read_text(encoding="utf-8"),
        )

    def commit(self, message: str, *, push: bool = True) -> None:
        """Commit everything in the checkout, and push it to origin's main."""
        git(self.checkout, "add", "-A")
        git(self.checkout, "commit", "-q", "-m", message)
        if push:
            git(self.checkout, "push", "-q", "origin", "HEAD:main")

    def plan(self, text: str, *, push: bool = True) -> Path:
        """Commit a plan under ``recording-plans/`` and return its path."""
        folder = self.checkout / "recording-plans"
        folder.mkdir(exist_ok=True)
        path = folder / "RP-2026-003.yaml"
        path.write_text(text, encoding="utf-8")
        self.commit("plan", push=push)
        return path

    def keys(self) -> MaskingKeys:
        """Return the masking keys of ``secrets``."""
        names = ("masker.k_mask", "masker.vault_key", "masker.known_value_key")
        return MaskingKeys.from_secrets(*(SecretValue(self.secrets[n]) for n in names))

    def issue(self, type_name: str, real: str) -> str:
        """Issue a surrogate in the vault, as an earlier recording would have."""
        with open_store(self.config.data_dir) as store:
            return Vault(store, self.keys(), clock=lambda: self.now).issue(type_name, real)

    def run(
        self, plan: Path, *, dry_run: bool = False, sitest: bool | None = None
    ) -> tuple[int, str]:
        """Run ``recorder run`` with the fakes; return the exit code and the terminal text.

        The SITEST record is piped for a live run only, unless ``sitest`` says otherwise.
        """
        out = io.StringIO()
        with_sitest = not dry_run if sitest is None else sitest
        piped = {
            k: v for k, v in self.secrets.items() if with_sitest or not k.startswith("sitest.")
        }
        data = json.dumps(piped).encode()

        def scanner(checkout: Path, staging: Path) -> list[tuple[str, str]] | None:
            self.scanned.append(staging)
            if self.scanner_error is not None:
                raise self.scanner_error
            return None if self.scan_result is None else list(self.scan_result)

        def port_factory(_: SitestCredentials) -> SitestPort:
            return self.port

        code = run_plan(
            plan,
            config=self.config,
            dry_run=dry_run,
            out=out,
            field_map_source=lambda: self.field_map,
            now=lambda: self.now,
            secrets=lambda: StdinSecretsProvider.from_stream(io.BytesIO(data)),
            port_factory=port_factory,
            scanner=scanner,
            monotonic=self.monotonic,
            code_file=self.code_file,
        )
        return code, out.getvalue()

    def query(self, sql: str) -> list[tuple[Any, ...]]:
        """Read the vault database (the run is over, so it is unlocked)."""
        db = sqlite3.connect(self.config.data_dir / DB_NAME)
        try:
            return db.execute(sql).fetchall()
        finally:
            db.close()

    def staged(self) -> list[Path]:
        """Return every file under the checkout's recordings folder."""
        root = self.checkout / "tests" / "fixtures" / "masked" / "recordings"
        return sorted(p for p in root.rglob("*") if p.is_file()) if root.exists() else []


@pytest.fixture(name="harness")
def harness_fixture(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Harness:
    """Return a fresh harness with git isolated from the user's configuration."""
    gitconfig = tmp_path / "gitconfig"
    gitconfig.write_text(
        "[user]\n\tname = Test\n\temail = test@example.invalid\n"
        "[init]\n\tdefaultBranch = main\n[commit]\n\tgpgsign = false\n",
        encoding="utf-8",
    )
    monkeypatch.setenv("GIT_CONFIG_GLOBAL", str(gitconfig))
    monkeypatch.setenv("GIT_CONFIG_NOSYSTEM", "1")
    return Harness(tmp_path)
