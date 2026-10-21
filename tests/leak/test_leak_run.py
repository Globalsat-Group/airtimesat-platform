"""No raw data on disk or on the terminal after a recorder run (design §8.5 #21, §5.1 step 2).

A run against a fake SITEST port that returns canary values, including runs that end in a
failed call and in an uncaught exception, leaves no canary in the staging folder, the vault
file (values there are AES-GCM ciphertext), the run log or the terminal output. Core dumps
are off and the process is not dumpable.
"""

import io
import subprocess
import sys
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

from airtimesat_platform.common.secrets_stdin import StdinSecretsProvider
from airtimesat_platform.masker.detect.canary import canary
from airtimesat_platform.masker.logsafe import safe_excepthook
from airtimesat_platform.recorder import run as run_module

Harness = Any  # tests/conftest.py's Harness


def answer(h: Harness, operation: str, reply: Callable[[str], bytes | BaseException]) -> None:
    """Set the fake port's reply to ``operation``."""
    h.port.replies[operation] = reply


IMEI = canary("IMEI", 91)
CONTRACTS = [canary("CONTRACT", 91), canary("CONTRACT", 92)]
SEARCH = (
    "<request><filterType>IMEI</filterType><filterValue>{imei}</filterValue>"
    "<filterCond>EQUALS</filterCond><limit>5</limit></request>"
)


def setup_run(h: Harness) -> Path:
    surrogate = h.issue("IMEI", IMEI)
    plan = h.plan(
        h.plan_yaml(
            h.plan_call("search", "accountSearch", SEARCH.format(imei=surrogate)),
            h.plan_call(
                "account",
                "getSubscriberAccount",
                "<request><accountNo>${item}</accountNo></request>",
                "search.accountNumber[0:2]",
            ),
        )
    )
    answer(h, "accountSearch", lambda _: h.search_reply(*((c, IMEI) for c in CONTRACTS)))
    answer(
        h,
        "getSubscriberAccount",
        lambda r: h.account_reply(next(c for c in CONTRACTS if c in r), IMEI),
    )
    return plan


def raw_values(h: Harness) -> list[bytes]:
    values = [IMEI, *CONTRACTS, h.username, h.secret_key, "canary-sp-account-9"]
    return [v.encode() for v in values]


def assert_nothing_raw(h: Harness, *printed: str) -> None:
    disk = [p for p in h.tmp.rglob("*") if p.is_file() and "origin.git" not in p.parts]
    disk = [p for p in disk if ".git" not in p.relative_to(h.tmp).parts]
    assert any(p.name == "vault.sqlite" for p in disk)
    for path in disk:
        data = path.read_bytes()
        for value in raw_values(h):
            assert value not in data, (path.name, "raw value on disk")
    for text in printed:
        for value in raw_values(h):
            assert value.decode() not in text


def test_a_successful_run_leaves_nothing_raw(
    harness: Harness, capsys: pytest.CaptureFixture[str]
) -> None:
    plan = setup_run(harness)
    code, out = harness.run(plan)
    assert code == 0, out
    assert len(harness.staged()) == 7
    captured = capsys.readouterr()
    assert_nothing_raw(harness, out, captured.out, captured.err)


def test_a_failed_call_leaves_nothing_raw(
    harness: Harness, capsys: pytest.CaptureFixture[str]
) -> None:
    plan = setup_run(harness)
    # An error whose message echoes a raw value, as lxml or aiohttp errors can.
    answer(harness, "getSubscriberAccount", lambda _: RuntimeError(f"bad {IMEI}"))
    code, out = harness.run(plan)
    assert code == 1
    assert "CALL_FAILED call_id=account operation=getSubscriberAccount code=CALL_FAILED" in out
    captured = capsys.readouterr()
    assert_nothing_raw(harness, out, captured.out, captured.err)


def test_an_uncaught_exception_leaves_nothing_raw(
    harness: Harness, capsys: pytest.CaptureFixture[str]
) -> None:
    plan = setup_run(harness)
    harness.scanner_error = RuntimeError(f"scanner saw {CONTRACTS[0]} and {IMEI}")
    with pytest.raises(RuntimeError) as info:
        harness.run(plan)
    hook = io.StringIO()
    safe_excepthook(type(info.value), info.value, info.tb, hook)
    assert hook.getvalue() == "UNCAUGHT RuntimeError\n"
    captured = capsys.readouterr()
    assert_nothing_raw(harness, hook.getvalue(), captured.out, captured.err)


def test_the_process_is_hardened_before_secrets_are_read(
    harness: Harness, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Spec 4.2, design §5.1 step 2: hardening comes before standard input is read.
    plan = setup_run(harness)
    order: list[str] = []
    monkeypatch.setattr(run_module, "harden_process", lambda: order.append("harden"))
    real = StdinSecretsProvider.from_stream

    def from_stream(stream: Any) -> StdinSecretsProvider:
        order.append("secrets")
        return real(stream)

    monkeypatch.setattr(StdinSecretsProvider, "from_stream", from_stream)
    code, out = harness.run(plan, dry_run=True)
    assert code == 0, out
    assert order == ["harden", "secrets"]


def test_hardening_disables_core_dumps_and_dumping() -> None:
    script = (
        "import ctypes, resource, sys\n"
        "from airtimesat_platform.recorder.run import harden_process\n"
        "harden_process()\n"
        "assert resource.getrlimit(resource.RLIMIT_CORE) == (0, 0)\n"
        "if sys.platform.startswith('linux'):\n"
        "    assert ctypes.CDLL(None).prctl(3, 0, 0, 0, 0) == 0  # PR_GET_DUMPABLE\n"
        "print('hardened')\n"
    )
    result = subprocess.run(  # noqa: S603 - fixed program and script
        [sys.executable, "-c", script], capture_output=True, text=True, check=False
    )
    assert (result.returncode, result.stdout) == (0, "hardened\n"), result.stderr
