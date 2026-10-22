"""``recorder init``: the identity, the configuration and the two secrets files (design §6.2).

Fake ``age`` and ``age-keygen`` run on a ``PATH`` of their own (``fake_tools``); the SITEST
values are built at run time. No test needs a terminal, a passphrase or a real age.
"""

import getpass
import io
import json
import shutil
import stat
import warnings
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

from airtimesat_platform.recorder import admin
from airtimesat_platform.recorder import checkout as checkout_module
from airtimesat_platform.recorder import init as init_module
from airtimesat_platform.recorder.__main__ import main
from airtimesat_platform.recorder.config import load_config
from airtimesat_platform.recorder.errors import RecorderError
from airtimesat_platform.recorder.init import init
from airtimesat_platform.recorder.run import KEY_NAMES
from airtimesat_platform.recorder.store import DB_NAME

Harness = Any  # tests/conftest.py's Harness
Tools = Any  # tests/conftest.py's FakeTools

FILES = ("recorder-identity.age", "masker-keys.json.age", "sitest.json.age")
USER = "SITEST username: "
KEY = "SITEST secret key: "
SP = "SP account number (Enter if none): "


def answers(h: Harness, sp: str = "") -> dict[str, str]:
    return {USER: h.username, KEY: h.secret_key, SP: sp}


def run_init(
    h: Harness,
    tools: Tools,
    replies: dict[str, str] | None = None,
    *,
    data_dir: Path | None = None,
    backup_dir: Path | None = None,
    new_keys: bool = False,
) -> str:
    out = io.StringIO()
    init(
        data_dir or h.tmp / "data",
        backup_dir or h.tmp / "backups",
        config_path=h.tmp / "config" / "recorder.toml",
        out=out,
        prompt=tools.prompt(replies if replies is not None else answers(h)),
        code=h.code_file,
        new_masker_keys=new_keys,
    )
    return out.getvalue()


def refusal(h: Harness, tools: Tools, **kwargs: Any) -> str:
    with pytest.raises(RecorderError) as info:
        run_init(h, tools, **kwargs)
    return str(info.value)


def mode(path: Path) -> int:
    return stat.S_IMODE(path.stat().st_mode)


def log_hardening(tools: Tools, monkeypatch: pytest.MonkeyPatch) -> None:
    """Replace the process hardening by a line in the fake tools' log."""

    def harden() -> None:
        with tools.log_file.open("a", encoding="utf-8") as handle:
            handle.write("harden\n")

    monkeypatch.setattr(init_module, "harden_process", harden)


def test_init_creates_everything_in_order(harness: Harness, fake_tools: Tools) -> None:
    text = run_init(harness, fake_tools, answers(harness, sp="canary-sp-account-9"))
    # Every prompt comes before age's: nothing is typed ahead while age works.
    assert fake_tools.log() == [
        "prompt SITEST username",
        "prompt SITEST secret key",
        "prompt SP account number",
        "age-keygen",
        "age -p recorder-identity.age",
        "age -r masker-keys.json.age",
        "age -r sitest.json.age",
    ]
    data = harness.tmp / "data"
    config = load_config(harness.tmp / "config" / "recorder.toml")
    assert config.data_dir == data.resolve()
    assert config.backup_dir == (harness.tmp / "backups").resolve()
    assert config.checkout == harness.checkout
    lines = text.splitlines()
    assert lines[:5] == [
        "CREATED recorder-identity.age",
        "CREATED recorder.toml",
        "CREATED masker-keys.json.age",
        "CREATED sitest.json.age",
        f"RECIPIENT {config.backup_recipient}",
    ]
    assert lines[5].startswith("MASKER_KEYS_SHA256 ")
    assert len(lines[5].split()[1]) == 64
    assert "Keeper" in lines[6]
    identity = fake_tools.decrypt(data / "recorder-identity.age")
    assert f"# public key: {config.backup_recipient}".encode() in identity
    keys = json.loads(fake_tools.decrypt(data / "masker-keys.json.age"))
    assert list(keys) == list(KEY_NAMES)
    assert len(set(keys.values())) == 4
    assert json.loads(fake_tools.decrypt(data / "sitest.json.age")) == {
        "sitest.iws_username": harness.username,
        "sitest.secret_key": harness.secret_key,
        "sitest.sp_account_number": "canary-sp-account-9",
    }
    for header in ("masker-keys.json.age", "sitest.json.age"):
        assert (
            (data / header)
            .read_bytes()
            .startswith(f"fake-x25519 {config.backup_recipient}\n".encode())
        )


def test_modes_and_no_temp_files(harness: Harness, fake_tools: Tools) -> None:
    (harness.tmp / "backups").mkdir(mode=0o755)
    run_init(harness, fake_tools)
    data = harness.tmp / "data"
    assert mode(data) == 0o700
    assert mode(harness.tmp / "backups") == 0o700
    assert mode(harness.tmp / "config") == 0o700
    assert mode(harness.tmp / "config" / "recorder.toml") == 0o600
    assert {p.name for p in data.iterdir()} == set(FILES)
    assert all(mode(data / name) == 0o600 for name in FILES)


def test_an_empty_sp_account_is_left_out(harness: Harness, fake_tools: Tools) -> None:
    run_init(harness, fake_tools)
    sitest = json.loads(fake_tools.decrypt(harness.tmp / "data" / "sitest.json.age"))
    assert sorted(sitest) == ["sitest.iws_username", "sitest.secret_key"]


def test_init_is_idempotent_and_never_overwrites(harness: Harness, fake_tools: Tools) -> None:
    first = run_init(harness, fake_tools)
    data = harness.tmp / "data"
    before = {name: (data / name).read_bytes() for name in FILES}
    config = (harness.tmp / "config" / "recorder.toml").read_bytes()
    calls = len(fake_tools.log())
    second = run_init(harness, fake_tools, {})
    assert len(fake_tools.log()) == calls  # no prompt, no age
    assert second.splitlines()[:4] == [
        "EXISTS recorder-identity.age",
        "EXISTS recorder.toml",
        "EXISTS masker-keys.json.age",
        "EXISTS sitest.json.age",
    ]
    assert second.splitlines()[4:6] == first.splitlines()[4:6]  # recipient and digest
    assert {name: (data / name).read_bytes() for name in FILES} == before
    assert (harness.tmp / "config" / "recorder.toml").read_bytes() == config


def test_a_deleted_sitest_file_is_made_again(harness: Harness, fake_tools: Tools) -> None:
    # Rotation: delete sitest.json.age and run init again; nothing else changes.
    run_init(harness, fake_tools)
    data = harness.tmp / "data"
    keys = (data / "masker-keys.json.age").read_bytes()
    (data / "sitest.json.age").unlink()
    harness.secret_key = "R" + harness.secret_key
    text = run_init(harness, fake_tools)
    assert "CREATED sitest.json.age" in text.splitlines()
    assert "EXISTS masker-keys.json.age" in text.splitlines()
    assert (data / "masker-keys.json.age").read_bytes() == keys
    sitest = json.loads(fake_tools.decrypt(data / "sitest.json.age"))
    assert sitest["sitest.secret_key"] == harness.secret_key
    assert fake_tools.log()[-4:] == [
        "prompt SITEST username",
        "prompt SITEST secret key",
        "prompt SP account number",
        "age -r sitest.json.age",
    ]


def test_no_new_keys_for_an_existing_vault(harness: Harness, fake_tools: Tools) -> None:
    data = harness.tmp / "data"
    data.mkdir()
    (data / DB_NAME).write_bytes(b"")
    assert refusal(harness, fake_tools) == "INIT_VAULT_EXISTS vault.sqlite"
    assert fake_tools.log() == []
    assert not (harness.tmp / "config").exists()


def test_an_existing_identity_needs_its_configuration(harness: Harness, fake_tools: Tools) -> None:
    run_init(harness, fake_tools)
    (harness.tmp / "config" / "recorder.toml").unlink()
    assert refusal(harness, fake_tools) == "INIT_CONFIG_MISSING"


def test_secrets_files_without_their_identity_are_refused(
    harness: Harness, fake_tools: Tools
) -> None:
    # A new identity could not open them: refused before any prompt, nothing written.
    run_init(harness, fake_tools)
    (harness.tmp / "config" / "recorder.toml").unlink()
    (harness.tmp / "data" / "recorder-identity.age").unlink()
    calls = len(fake_tools.log())
    assert refusal(harness, fake_tools) == "INIT_FILE_WITHOUT_IDENTITY masker-keys.json.age"
    (harness.tmp / "data" / "masker-keys.json.age").unlink()
    assert refusal(harness, fake_tools) == "INIT_FILE_WITHOUT_IDENTITY sitest.json.age"
    assert len(fake_tools.log()) == calls
    assert not (harness.tmp / "config" / "recorder.toml").exists()
    assert not (harness.tmp / "data" / "recorder-identity.age").exists()


def test_missing_keys_of_an_existing_identity_are_not_remade(
    harness: Harness, fake_tools: Tools
) -> None:
    # A dead disk: the identity and configuration are back, the keys not yet. No new keys.
    run_init(harness, fake_tools)
    data = harness.tmp / "data"
    (data / "masker-keys.json.age").unlink()
    (data / "sitest.json.age").unlink()
    calls = len(fake_tools.log())
    assert refusal(harness, fake_tools) == "INIT_KEYS_MISSING masker-keys.json.age"
    assert len(fake_tools.log()) == calls  # before any prompt
    assert not (data / "masker-keys.json.age").exists()
    # Runbook 06 case 4: new keys only on request.
    text = run_init(harness, fake_tools, new_keys=True)
    assert "CREATED masker-keys.json.age" in text.splitlines()
    assert "EXISTS recorder-identity.age" in text.splitlines()


def test_init_hardens_the_process_before_the_first_prompt(
    harness: Harness, fake_tools: Tools, monkeypatch: pytest.MonkeyPatch
) -> None:
    log_hardening(fake_tools, monkeypatch)
    run_init(harness, fake_tools)
    assert fake_tools.log()[:2] == ["harden", "prompt SITEST username"]


def test_a_configuration_without_its_identity_is_refused(
    harness: Harness, fake_tools: Tools
) -> None:
    run_init(harness, fake_tools)
    (harness.tmp / "data" / "recorder-identity.age").unlink()
    assert refusal(harness, fake_tools) == "INIT_IDENTITY_MISSING recorder-identity.age"


@pytest.mark.parametrize("key", ["data_dir", "backup_dir"])
def test_a_configuration_mismatch_is_refused(harness: Harness, fake_tools: Tools, key: str) -> None:
    run_init(harness, fake_tools)
    other = {key: harness.tmp / "elsewhere"}
    assert refusal(harness, fake_tools, **other) == f"INIT_CONFIG_MISMATCH {key}"


def test_a_configuration_for_another_checkout_is_refused(
    harness: Harness, fake_tools: Tools
) -> None:
    run_init(harness, fake_tools)
    config = harness.tmp / "config" / "recorder.toml"
    text = config.read_text(encoding="utf-8")
    config.write_text(
        text.replace(str(harness.checkout), str(harness.tmp / "other")), encoding="utf-8"
    )
    assert refusal(harness, fake_tools) == "INIT_CONFIG_MISMATCH checkout"


@pytest.mark.parametrize(
    ("data_dir", "code"),
    [
        ("relative/data", "INIT_PATH_NOT_ABSOLUTE data_dir"),
        ("CHECKOUT/data", "INIT_PATH_IN_CHECKOUT data_dir"),
    ],
)
def test_bad_paths(harness: Harness, fake_tools: Tools, data_dir: str, code: str) -> None:
    path = Path(data_dir.replace("CHECKOUT", str(harness.checkout)))
    assert refusal(harness, fake_tools, data_dir=path) == code
    assert refusal(harness, fake_tools, backup_dir=harness.checkout) == (
        "INIT_PATH_IN_CHECKOUT backup_dir"
    )
    assert fake_tools.log() == []


def test_unreviewed_code_is_refused(harness: Harness, fake_tools: Tools) -> None:
    (harness.checkout / "stray.txt").write_text("x", encoding="utf-8")
    assert refusal(harness, fake_tools) == "CHECKOUT_NOT_CLEAN"
    assert fake_tools.log() == []


@pytest.mark.parametrize(
    ("field", "value", "code"),
    [
        (USER, "", "INIT_SITEST_EMPTY sitest.iws_username"),
        (KEY, "", "INIT_SITEST_EMPTY sitest.secret_key"),
        (KEY, " {}", "INIT_SITEST_INVALID sitest.secret_key"),
        (KEY, "{} ", "INIT_SITEST_INVALID sitest.secret_key"),
        (USER, "{}\t", "INIT_SITEST_INVALID sitest.iws_username"),
        (KEY, "a{}\x1b[2J", "INIT_SITEST_INVALID sitest.secret_key"),
        (SP, "\n{}", "INIT_SITEST_INVALID sitest.sp_account_number"),
    ],
)
def test_bad_sitest_input_names_no_value(
    harness: Harness, fake_tools: Tools, field: str, value: str, code: str
) -> None:
    replies = answers(harness) | {field: value.format(harness.secret_key)}
    text = refusal(harness, fake_tools, replies=replies)
    assert text == code
    assert harness.secret_key not in text
    assert harness.username not in text
    # Refused before any age call: no file was made, and init can simply run again.
    assert not any(line.startswith("age") for line in fake_tools.log())
    assert not (harness.tmp / "data" / "sitest.json.age").exists()


@pytest.mark.parametrize(
    ("fail", "where"),
    [
        ("keygen", "INIT_AGE_FAILED age-keygen"),
        ("-p", "INIT_AGE_FAILED recorder-identity.age"),
        ("-r", "INIT_AGE_FAILED masker-keys.json.age"),
    ],
)
def test_temp_files_are_removed_on_failure(
    harness: Harness, fake_tools: Tools, monkeypatch: pytest.MonkeyPatch, fail: str, where: str
) -> None:
    monkeypatch.setenv("FAKE_AGE_FAIL", fail)
    assert refusal(harness, fake_tools) == where
    data = harness.tmp / "data"
    assert not [p for p in data.iterdir() if p.name.endswith(".tmp")]
    monkeypatch.delenv("FAKE_AGE_FAIL")
    # Run again: whatever exists is kept, the rest is made. Keys for an identity that
    # already exists are made only on request.
    text = run_init(harness, fake_tools, new_keys=fail == "-r")
    assert "CREATED sitest.json.age" in text.splitlines()
    assert {p.name for p in data.iterdir()} == set(FILES)


def test_an_interrupted_prompt_leaves_nothing(harness: Harness, fake_tools: Tools) -> None:
    def interrupted(_: str) -> str:
        raise KeyboardInterrupt

    with pytest.raises(KeyboardInterrupt):
        init(
            harness.tmp / "data",
            harness.tmp / "backups",
            config_path=harness.tmp / "config" / "recorder.toml",
            out=io.StringIO(),
            prompt=interrupted,
            code=harness.code_file,
        )
    assert list((harness.tmp / "data").iterdir()) == []
    assert not (harness.tmp / "config").exists()


def test_a_file_appearing_meanwhile_is_never_replaced(
    harness: Harness, fake_tools: Tools, monkeypatch: pytest.MonkeyPatch
) -> None:
    data = harness.tmp / "data"
    real = admin.new_keys

    def racing() -> dict[str, str]:
        (data / "masker-keys.json.age").write_bytes(b"theirs")
        return real()

    monkeypatch.setattr(init_module, "new_keys", racing)
    assert refusal(harness, fake_tools) == "INIT_FILE_EXISTS masker-keys.json.age"
    assert (data / "masker-keys.json.age").read_bytes() == b"theirs"
    assert not [p for p in data.iterdir() if p.name.endswith(".tmp")]


def test_hidden_prompt_refuses_echoed_input(monkeypatch: pytest.MonkeyPatch) -> None:
    # Without a terminal, getpass would warn and read echoed input: init refuses instead.
    def no_terminal(prompt: str = "") -> str:
        warnings.warn("no terminal", getpass.GetPassWarning, stacklevel=1)
        return prompt

    monkeypatch.setattr(getpass, "getpass", no_terminal)
    with pytest.raises(RecorderError) as info:
        init_module.hidden_prompt("SITEST username: ")
    assert info.value.code == "INIT_NO_TERMINAL"


def test_init_from_the_command_line(
    harness: Harness, fake_tools: Tools, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(checkout_module, "CODE", harness.code_file)
    monkeypatch.setattr(init_module, "hidden_prompt", fake_tools.prompt(answers(harness)))
    config = harness.tmp / "config" / "recorder.toml"
    out = io.StringIO()
    argv = ["init", "--data-dir", str(harness.tmp / "data")]
    argv += ["--backup-dir", str(harness.tmp / "backups"), "--config", str(config)]
    assert main(argv, out=out) == 0, out.getvalue()
    assert out.getvalue().startswith("CREATED recorder-identity.age\n")
    out = io.StringIO()
    argv[2] = "data"
    assert main(argv, out=out) == 1
    assert out.getvalue() == "REFUSED INIT_PATH_NOT_ABSOLUTE data_dir\n"


# ---------------------------------------------------------------- rekey (runbook 06 case 7)

NOW = datetime(2026, 10, 22, 12, 0, tzinfo=UTC)


def rekey(h: Harness) -> str:
    out = io.StringIO()
    init_module.rekey(h.tmp / "config" / "recorder.toml", out=out, now=NOW, code=h.code_file)
    return out.getvalue()


def test_rekey_moves_every_file_to_a_new_identity(harness: Harness, fake_tools: Tools) -> None:
    run_init(harness, fake_tools, answers(harness, sp="canary-sp-account-9"))
    data = harness.tmp / "data"
    config_file = harness.tmp / "config" / "recorder.toml"
    old_recipient = load_config(config_file).backup_recipient
    keys = json.loads(fake_tools.decrypt(data / "masker-keys.json.age"))
    sitest = json.loads(fake_tools.decrypt(data / "sitest.json.age"))
    old_files = {name: (data / name).read_bytes() for name in FILES}
    calls = len(fake_tools.log())
    text = rekey(harness)
    assert fake_tools.log()[calls:] == [
        "age -d recorder-identity.age",
        "age -d -i masker-keys.json.age",
        "age -d -i sitest.json.age",
        "age-keygen",
        "age -p recorder-identity.age",
        "age -r masker-keys.json.age",
        "age -r sitest.json.age",
    ]
    recipient = load_config(config_file).backup_recipient
    assert recipient != old_recipient
    assert text.splitlines()[:2] == ["RETIRED retired-20261022T120000Z", f"RECIPIENT {recipient}"]
    assert f"# public key: {recipient}".encode() in fake_tools.decrypt(data / FILES[0])
    assert json.loads(fake_tools.decrypt(data / "masker-keys.json.age")) == keys
    assert json.loads(fake_tools.decrypt(data / "sitest.json.age")) == sitest
    retired = data / "retired-20261022T120000Z"
    assert {name: (retired / name).read_bytes() for name in FILES} == old_files
    assert load_config(retired / "recorder.toml").backup_recipient == old_recipient
    assert sorted(p.name for p in data.iterdir()) == sorted([*FILES, retired.name])
    assert all(mode(data / name) == 0o600 for name in FILES)
    assert mode(config_file) == 0o600
    assert mode(retired) == 0o700


def test_rekey_hardens_the_process_before_decrypting(
    harness: Harness, fake_tools: Tools, monkeypatch: pytest.MonkeyPatch
) -> None:
    run_init(harness, fake_tools)
    log_hardening(fake_tools, monkeypatch)
    calls = len(fake_tools.log())
    rekey(harness)
    assert fake_tools.log()[calls : calls + 2] == ["harden", "age -d recorder-identity.age"]


def test_a_rekey_that_cannot_keep_the_old_configuration_changes_nothing(
    harness: Harness, fake_tools: Tools, monkeypatch: pytest.MonkeyPatch
) -> None:
    # The old configuration is kept before any file moves: the new identity never sits
    # next to the old recipient.
    run_init(harness, fake_tools)
    data = harness.tmp / "data"
    config_file = harness.tmp / "config" / "recorder.toml"
    before = {name: (data / name).read_bytes() for name in FILES}
    config = config_file.read_bytes()

    def full(*_: Any, **__: Any) -> None:
        raise OSError(28, "No space left on device")

    monkeypatch.setattr(shutil, "copy2", full)
    with pytest.raises(RecorderError) as info:
        rekey(harness)
    assert str(info.value) == "REKEY_FAILED"
    assert sorted(p.name for p in data.iterdir()) == sorted(FILES)
    assert {name: (data / name).read_bytes() for name in FILES} == before
    assert config_file.read_bytes() == config
    assert sorted(p.name for p in config_file.parent.iterdir()) == ["recorder.toml"]


def test_rekey_refuses_an_unreadable_secrets_file(
    harness: Harness, fake_tools: Tools, monkeypatch: pytest.MonkeyPatch
) -> None:
    run_init(harness, fake_tools)
    data = harness.tmp / "data"
    config_file = harness.tmp / "config" / "recorder.toml"
    recipient = load_config(config_file).backup_recipient
    fake_tools.encrypt(data / "sitest.json.age", f"fake-x25519 {recipient}", b"not json")
    before = {name: (data / name).read_bytes() for name in FILES}
    monkeypatch.setattr(checkout_module, "CODE", harness.code_file)
    out = io.StringIO()
    assert main(["rekey", "--config", str(config_file)], out=out) == 1
    assert out.getvalue() == "REFUSED SECRETS_UNREADABLE\n"
    assert sorted(p.name for p in data.iterdir()) == sorted(FILES)
    assert {name: (data / name).read_bytes() for name in FILES} == before


def test_a_failed_rekey_changes_nothing(
    harness: Harness, fake_tools: Tools, monkeypatch: pytest.MonkeyPatch
) -> None:
    run_init(harness, fake_tools)
    data = harness.tmp / "data"
    config_file = harness.tmp / "config" / "recorder.toml"
    before = {name: (data / name).read_bytes() for name in FILES}
    config = config_file.read_bytes()
    monkeypatch.setenv("FAKE_AGE_FAIL", "-p")
    with pytest.raises(RecorderError) as info:
        rekey(harness)
    assert str(info.value) == "INIT_AGE_FAILED recorder-identity.age"
    assert sorted(p.name for p in data.iterdir()) == sorted(FILES)
    assert {name: (data / name).read_bytes() for name in FILES} == before
    assert config_file.read_bytes() == config


def test_a_half_swapped_rekey_keeps_both_sets_and_says_where(
    harness: Harness, fake_tools: Tools, monkeypatch: pytest.MonkeyPatch
) -> None:
    run_init(harness, fake_tools)
    data = harness.tmp / "data"
    old_files = {name: (data / name).read_bytes() for name in FILES}
    real_rename = Path.rename

    def rename(self: Path, target: Path) -> Path:
        if self.parent.name.startswith(".rekey-") and self.name == "masker-keys.json.age":
            raise PermissionError
        return real_rename(self, target)

    monkeypatch.setattr(Path, "rename", rename)
    with pytest.raises(RecorderError) as info:
        rekey(harness)
    assert str(info.value) == "REKEY_INCOMPLETE retired-20261022T120000Z"
    retired = data / "retired-20261022T120000Z"
    # The old identity, keys file and configuration can all be put back from retired-...
    assert (retired / FILES[0]).read_bytes() == old_files[FILES[0]]
    assert (retired / FILES[1]).read_bytes() == old_files[FILES[1]]
    assert (retired / "recorder.toml").exists()
    # ... and the new encrypted copies are kept, not deleted.
    assert (data / ".rekey-20261022T120000Z" / "masker-keys.json.age").exists()


def test_rekey_needs_the_current_passphrase(
    harness: Harness, fake_tools: Tools, monkeypatch: pytest.MonkeyPatch
) -> None:
    run_init(harness, fake_tools)
    monkeypatch.setenv("FAKE_AGE_FAIL", "-d")
    monkeypatch.setattr(checkout_module, "CODE", harness.code_file)
    out = io.StringIO()
    argv = ["rekey", "--config", str(harness.tmp / "config" / "recorder.toml")]
    assert main(argv, out=out) == 1
    assert out.getvalue() == "REFUSED SECRETS_DECRYPT_FAILED recorder-identity.age\n"
    assert sorted(p.name for p in (harness.tmp / "data").iterdir()) == sorted(FILES)
