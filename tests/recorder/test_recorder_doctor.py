"""``recorder doctor``: read-only checks, each ``OK`` and ``FIX`` (runbook 03 Part A).

The macOS tools (``fdesetup``, ``sysctl``, ``tmutil``), age and gitleaks are fakes on a
``PATH`` of their own (``fake_tools``); the platform is passed in, so the macOS checks run on
any OS.
"""

import io
import resource
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

from airtimesat_platform.recorder import checkout as checkout_module
from airtimesat_platform.recorder import doctor as doctor_module
from airtimesat_platform.recorder.__main__ import main

Harness = Any  # tests/conftest.py's Harness
Tools = Any  # tests/conftest.py's FakeTools

FILES = ("recorder-identity.age", "masker-keys.json.age", "sitest.json.age")


def core_limit(soft: int) -> Callable[[int], tuple[int, int]]:
    """Return a ``getrlimit`` stand-in with this soft core-dump limit."""

    def getrlimit(_: int) -> tuple[int, int]:
        return soft, 0

    return getrlimit


@pytest.fixture(name="ready")
def ready_fixture(harness: Harness, fake_tools: Tools, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Set up a machine where every check passes; return the configuration file."""
    fake_tools.write_files(harness.config.data_dir, harness.secrets)
    harness.config.backup_dir.mkdir(mode=0o700)
    config = harness.tmp / "recorder.toml"
    c = harness.config
    config.write_text(
        f'data_dir = "{c.data_dir}"\ncheckout = "{c.checkout}"\n'
        f'backup_recipient = "{c.backup_recipient}"\nbackup_dir = "{c.backup_dir}"\n',
        encoding="utf-8",
    )
    monkeypatch.setattr(resource, "getrlimit", core_limit(0))
    return config


def doctor(h: Harness, config: Path, platform: str = "darwin") -> tuple[int, list[str]]:
    out = io.StringIO()
    code = doctor_module.doctor(config, out=out, platform=platform, code=h.code_file)
    return code, out.getvalue().splitlines()


def fixes(lines: list[str]) -> list[str]:
    return [line for line in lines if line.startswith("FIX ")]


def test_every_check_passes(harness: Harness, fake_tools: Tools, ready: Path) -> None:
    code, lines = doctor(harness, ready)
    assert code == 0, lines
    assert [line.split(":")[0] for line in lines] == [
        "OK filevault",
        "OK core-dumps",
        "OK kern.coredump",
        "OK age",
        "OK age-keygen",
        "OK gitleaks",
        "OK git",
        "OK config",
        "OK data_dir",
        "OK backup_dir",
        "OK recorder-identity.age",
        "OK masker-keys.json.age",
        "OK sitest.json.age",
        "OK time-machine",
        "OK time-machine",
        "OK time-machine",
        "OK checkout",
        "MANUAL handoff",
        "MANUAL clipboard-history",
        "MANUAL secure-keyboard-entry",
        "MANUAL keeper-copies",
    ]


def test_it_never_decrypts_or_reads_a_secret_file(
    harness: Harness, fake_tools: Tools, ready: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    opened: list[str] = []
    real = Path.open

    def spy(self: Path, *args: Any, **kwargs: Any) -> Any:
        opened.append(self.name)
        return real(self, *args, **kwargs)  # pyright: ignore[reportUnknownVariableType]

    monkeypatch.setattr(Path, "open", spy)
    assert doctor(harness, ready)[0] == 0
    assert not set(opened) & set(FILES)
    assert not [line for line in fake_tools.log() if line.startswith("age -")]


def test_another_os_gets_manual_lines(harness: Harness, fake_tools: Tools, ready: Path) -> None:
    code, lines = doctor(harness, ready, platform="linux")
    assert code == 0
    assert lines[0].startswith("MANUAL disk-encryption: ")
    assert not [line for line in lines if "time-machine" in line or "kern." in line]
    assert fake_tools.log() == []


@pytest.mark.parametrize(
    ("variable", "value", "line"),
    [
        ("FAKE_FILEVAULT", "FileVault is Off.", "FIX filevault: turn FileVault on"),
        ("FAKE_COREDUMP", "1", "FIX kern.coredump: sudo sysctl kern.coredump=0"),
        ("FAKE_AGE_VERSION", "v1.0.0", "FIX age: install age 1.1.0+"),
        ("FAKE_GITLEAKS_VERSION", "8.24.0", "FIX gitleaks: install gitleaks 8.21.2"),
        ("FAKE_TM_INCLUDED", "data", "FIX time-machine:data_dir: tmutil addexclusion "),
        ("FAKE_TM_INCLUDED", "backups", "FIX time-machine:backup_dir: tmutil addexclusion "),
        ("FAKE_TM_INCLUDED", "checkout", "FIX time-machine:checkout: tmutil addexclusion "),
    ],
)
def test_machine_fixes(
    harness: Harness,
    fake_tools: Tools,
    ready: Path,
    monkeypatch: pytest.MonkeyPatch,
    variable: str,
    value: str,
    line: str,
) -> None:
    monkeypatch.setenv(variable, value)
    code, lines = doctor(harness, ready)
    assert code == 1
    assert len(fixes(lines)) == 1, lines
    assert fixes(lines)[0].startswith(line), lines


def test_core_dumps_and_missing_tools(
    harness: Harness, fake_tools: Tools, ready: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(resource, "getrlimit", core_limit(resource.RLIM_INFINITY))
    for name in ("age", "age-keygen", "gitleaks"):
        (fake_tools.bin / name).unlink()
    code, lines = doctor(harness, ready)
    assert code == 1
    assert [line.split(":")[0] for line in fixes(lines)] == [
        "FIX core-dumps",
        "FIX age",
        "FIX age-keygen",
        "FIX gitleaks",
    ]


def test_a_missing_git(harness: Harness, fake_tools: Tools, ready: Path) -> None:
    (fake_tools.bin / "git").unlink()
    code, lines = doctor(harness, ready)
    assert code == 1
    assert [line.split(":")[0] for line in fixes(lines)] == ["FIX git", "FIX checkout"]


def test_file_and_folder_fixes(harness: Harness, fake_tools: Tools, ready: Path) -> None:
    data = harness.config.data_dir
    backups = harness.config.backup_dir
    data.chmod(0o755)
    backups.chmod(0o755)
    (data / "recorder-identity.age").chmod(0o644)
    (data / "masker-keys.json.age").chmod(0o644)
    (data / "sitest.json.age").unlink()
    code, lines = doctor(harness, ready)
    assert code == 1
    assert fixes(lines) == [
        f"FIX data_dir: chmod 700 {data}",
        f"FIX backup_dir: chmod 700 {backups}",
        f"FIX recorder-identity.age: chmod 600 {data / 'recorder-identity.age'}",
        f"FIX masker-keys.json.age: chmod 600 {data / 'masker-keys.json.age'}",
        "FIX sitest.json.age: recorder init (runbook 03 Part D)",
    ]


def test_configuration_fixes(harness: Harness, fake_tools: Tools, ready: Path) -> None:
    code, lines = doctor(harness, harness.tmp / "absent.toml")
    assert code == 1
    assert fixes(lines) == ["FIX config: CONFIG_UNREADABLE: recorder init (runbook 03 Part D)"]
    text = ready.read_text(encoding="utf-8")
    ready.write_text(text.replace(str(harness.checkout), str(harness.tmp / "x")), "utf-8")
    code, lines = doctor(harness, ready)
    assert fixes(lines)[0] == "FIX config: its checkout is not this checkout: correct the file"


def test_checkout_fixes(harness: Harness, fake_tools: Tools, ready: Path) -> None:
    (harness.checkout / "stray.txt").write_text("x", encoding="utf-8")
    assert fixes(doctor(harness, ready)[1]) == [
        "FIX checkout: a clean checkout of main (runbook 03 Part C)"
    ]
    (harness.checkout / "stray.txt").unlink()
    checkout_module.git(harness.checkout, "switch", "-q", "-c", "other")
    assert doctor(harness, ready)[0] == 1


def test_doctor_from_the_command_line(
    harness: Harness, fake_tools: Tools, ready: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(checkout_module, "CODE", harness.code_file)
    out = io.StringIO()
    code = main(["doctor", "--config", str(ready)], out=out)
    assert code == 0, out.getvalue()
    assert "OK config\n" in out.getvalue()
    assert out.getvalue().rstrip().endswith("MANUAL keeper-copies: " + doctor_module.MANUAL[-1][1])
    monkeypatch.setenv("FAKE_GITLEAKS_VERSION", "8.24.0")
    out = io.StringIO()
    assert main(["doctor", "--config", str(ready)], out=out) == 1
    assert "FIX gitleaks: " in out.getvalue()
