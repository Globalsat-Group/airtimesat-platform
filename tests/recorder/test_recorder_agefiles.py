"""``recorder run`` with a terminal on standard input: secrets from the age files (design §6.2).

The fake ``age`` (``fake_tools``) logs each call, so the tests see how often the identity is
decrypted and which files are opened. Values are the harness's, built at run time.
"""

import io
import json
import subprocess
from pathlib import Path
from typing import Any, cast

import pytest

from airtimesat_platform.common.secrets_stdin import StdinSecretsProvider
from airtimesat_platform.masker.detect.canary import canary
from airtimesat_platform.recorder import checkout as checkout_module

Harness = Any  # tests/conftest.py's Harness
Tools = Any  # tests/conftest.py's FakeTools

SEARCH = (
    "<request><filterType>IMEI</filterType><filterValue>{imei}</filterValue>"
    "<filterCond>EQUALS</filterCond><limit>5</limit></request>"
)
IMEI = canary("IMEI", 71)
CONTRACT = canary("CONTRACT", 71)


def setup(h: Harness, tools: Tools) -> Path:
    """Write the three age files for the harness's secrets and commit a one-call plan."""
    tools.write_files(h.config.data_dir, h.secrets)
    surrogate = h.issue("IMEI", IMEI)

    def reply(_: str) -> bytes:
        return h.search_reply((CONTRACT, IMEI))

    h.port.replies["accountSearch"] = reply
    return h.plan(
        h.plan_yaml(h.plan_call("search", "accountSearch", SEARCH.format(imei=surrogate)))
    )


def refusal(out: str) -> str:
    return out.splitlines()[-1].removeprefix("REFUSED ")


def test_a_dry_run_decrypts_the_identity_once_and_never_opens_sitest(
    harness: Harness, fake_tools: Tools
) -> None:
    plan = setup(harness, fake_tools)
    (harness.config.data_dir / "sitest.json.age").unlink()
    code, out = harness.run(plan, dry_run=True, terminal=True)
    assert code == 0, out
    assert fake_tools.log() == ["age -d recorder-identity.age", "age -d -i masker-keys.json.age"]


def test_a_live_run_decrypts_the_identity_once_then_both_files(
    harness: Harness, fake_tools: Tools
) -> None:
    plan = setup(harness, fake_tools)
    code, out = harness.run(plan, terminal=True)
    assert code == 0, out
    assert fake_tools.log() == [
        "age -d recorder-identity.age",
        "age -d -i masker-keys.json.age",
        "age -d -i sitest.json.age",
    ]
    # The SITEST record from the file reached the port: its username signs the call.
    assert [r[1] for r in harness.port.requests] == ["accountSearch"]


@pytest.mark.parametrize(
    ("dry_run", "missing"),
    [
        (True, "recorder-identity.age"),
        (True, "masker-keys.json.age"),
        (False, "sitest.json.age"),
    ],
)
def test_a_missing_file(harness: Harness, fake_tools: Tools, dry_run: bool, missing: str) -> None:
    plan = setup(harness, fake_tools)
    (harness.config.data_dir / missing).unlink()
    code, out = harness.run(plan, dry_run=dry_run, terminal=True)
    assert code == 1
    assert refusal(out) == f"code=SECRETS_FILE_MISSING path={missing}"
    assert fake_tools.log() == []  # no passphrase is asked for a run that cannot start


@pytest.mark.parametrize(
    ("fail", "where"),
    [("-d", "recorder-identity.age"), ("-i", "masker-keys.json.age")],
)
def test_a_decryption_failure(
    harness: Harness, fake_tools: Tools, monkeypatch: pytest.MonkeyPatch, fail: str, where: str
) -> None:
    plan = setup(harness, fake_tools)
    monkeypatch.setenv("FAKE_AGE_FAIL", fail)
    code, out = harness.run(plan, terminal=True)
    assert code == 1
    assert refusal(out) == f"code=SECRETS_DECRYPT_FAILED path={where}"
    assert harness.port.requests == []


def test_a_file_must_hold_only_its_own_names(harness: Harness, fake_tools: Tools) -> None:
    plan = setup(harness, fake_tools)
    data = harness.config.data_dir
    recipient = harness.config.backup_recipient
    mixed = json.dumps(harness.secrets).encode()  # masker keys in the SITEST file
    fake_tools.encrypt(data / "sitest.json.age", f"fake-x25519 {recipient}", mixed)
    code, out = harness.run(plan, terminal=True)
    assert code == 1
    assert refusal(out) == "code=SECRETS_UNREADABLE"


def test_a_file_encrypted_to_another_identity(harness: Harness, fake_tools: Tools) -> None:
    plan = setup(harness, fake_tools)
    data = harness.config.data_dir
    other = "age1" + "p" * 58
    fake_tools.encrypt(data / "masker-keys.json.age", f"fake-x25519 {other}", b"{}")
    code, out = harness.run(plan, dry_run=True, terminal=True)
    assert code == 1
    assert refusal(out) == "code=SECRETS_DECRYPT_FAILED path=masker-keys.json.age"


def test_an_identity_of_another_recipient_is_refused(harness: Harness, fake_tools: Tools) -> None:
    # The configuration names another key than the identity: refused before any other file.
    plan = setup(harness, fake_tools)
    data = harness.config.data_dir
    other = f"# public key: age1{'p' * 58}\nAGE-SECRET-KEY-1{'F' * 58}\n".encode()
    fake_tools.encrypt(data / "recorder-identity.age", "fake-scrypt", other)
    code, out = harness.run(plan, terminal=True)
    assert code == 1
    assert refusal(out) == "code=IDENTITY_RECIPIENT_MISMATCH path=recorder-identity.age"
    assert fake_tools.log() == ["age -d recorder-identity.age"]


def test_the_pipe_path_is_unchanged(
    harness: Harness, fake_tools: Tools, monkeypatch: pytest.MonkeyPatch
) -> None:
    plan = setup(harness, fake_tools)
    masker = {k: v for k, v in harness.secrets.items() if k.startswith("masker.")}
    piped: list[str] = []

    def from_stdin() -> StdinSecretsProvider:
        piped.append("stdin")
        return StdinSecretsProvider.from_stream(io.BytesIO(json.dumps(masker).encode()))

    monkeypatch.setattr(StdinSecretsProvider, "from_stdin", from_stdin)
    code, out = harness.run(plan, dry_run=True, terminal=False)
    assert code == 0, out
    assert piped == ["stdin"]
    assert fake_tools.log() == []  # no age call


def test_git_never_prompts_for_credentials(
    harness: Harness, monkeypatch: pytest.MonkeyPatch
) -> None:
    seen: list[tuple[str | None, str | None, Any]] = []
    real = subprocess.run

    def spy(args: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        env = kwargs["env"]
        seen.append((env.get("GIT_TERMINAL_PROMPT"), env.get("GIT_SSH_COMMAND"), kwargs["stdin"]))
        return cast("subprocess.CompletedProcess[str]", real(args, **kwargs))

    monkeypatch.setattr(subprocess, "run", spy)
    monkeypatch.delenv("GIT_SSH_COMMAND", raising=False)
    assert checkout_module.git(harness.checkout, "status").returncode == 0
    # Git never reads the recorder's standard input, and the CTO's ssh settings stay his.
    assert seen == [("0", None, subprocess.DEVNULL)]
    monkeypatch.setenv("GIT_SSH_COMMAND", "ssh -i /own/key")
    assert checkout_module.git(harness.checkout, "status").returncode == 0
    assert seen[-1] == ("0", "ssh -i /own/key", subprocess.DEVNULL)


def test_a_missing_age_fails_closed(harness: Harness, fake_tools: Tools) -> None:
    plan = setup(harness, fake_tools)
    (fake_tools.bin / "age").unlink()
    code, out = harness.run(plan, dry_run=True, terminal=True)
    assert code == 1
    assert refusal(out) == "code=SECRETS_DECRYPT_FAILED path=recorder-identity.age"
