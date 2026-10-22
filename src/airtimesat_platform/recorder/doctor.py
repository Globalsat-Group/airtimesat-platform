"""``recorder doctor``: read-only checks of the trusted machine (design §6.5, runbook 03).

One line per check: ``OK <check>``, ``FIX <check>: <one command or runbook pointer>``, or
``MANUAL <check>: <what to do>`` for what no command can see. Exit 0 when there is no
``FIX``, else 1. It reads no secret and decrypts nothing (it looks at the ``.age`` files'
modes only), never fetches, installs or changes anything, and runs each tool with a fixed
argument list, no shell and a timeout.
"""

import re
import resource
import shlex
import shutil
import stat
import subprocess
import sys
from pathlib import Path
from typing import Final, TextIO

from airtimesat_platform.recorder import checkout as checkout_module
from airtimesat_platform.recorder.agefiles import IDENTITY, MASKER_KEYS, SITEST
from airtimesat_platform.recorder.checkout import code_checkout, git
from airtimesat_platform.recorder.config import load_config
from airtimesat_platform.recorder.errors import RecorderError

TOOL_TIMEOUT_S: Final = 30
AGE_MINIMUM: Final = (1, 1, 0)
GITLEAKS_PIN: Final = (8, 21, 2)  # the CI and pre-commit pin
VERSION: Final = re.compile(r"v?(\d+)\.(\d+)\.(\d+)")
PART_A: Final = "(runbook 03 Part A)"
INIT: Final = "recorder init (runbook 03 Part D)"
MANUAL: Final = (
    ("handoff", "turn Handoff off in System Settings (runbook 03 Part A)"),
    ("clipboard-history", "quit every clipboard history tool"),
    ("secure-keyboard-entry", "turn on Terminal > Secure Keyboard Entry"),
    ("keeper-copies", f"{IDENTITY} and {MASKER_KEYS} are attached in Keeper and escrowed"),
)


def _tool(*args: str) -> str | None:
    """Run a tool; return its standard output, or None if it is missing or failed."""
    try:
        result = subprocess.run(  # noqa: S603 - fixed programs and arguments from this module
            list(args),
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            check=False,
            timeout=TOOL_TIMEOUT_S,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    return result.stdout if result.returncode == 0 else None


def _version(text: str | None) -> tuple[int, ...] | None:
    found = VERSION.search(text or "")
    return tuple(int(part) for part in found.groups()) if found else None


def _mode(path: Path, *, folder: bool) -> int | None:
    """Return the permission bits of a real folder or regular file (no symlink), else None."""
    try:
        st = path.lstat()
    except OSError:
        return None
    kind = stat.S_ISDIR(st.st_mode) if folder else stat.S_ISREG(st.st_mode)
    return stat.S_IMODE(st.st_mode) if kind else None


class _Report:
    def __init__(self, out: TextIO) -> None:
        self.out = out
        self.fixes = 0

    def check(self, name: str, ok: bool, fix: str) -> None:
        if ok:
            self.out.write(f"OK {name}\n")
        else:
            self.fixes += 1
            self.out.write(f"FIX {name}: {fix}\n")

    def manual(self, name: str, what: str) -> None:
        self.out.write(f"MANUAL {name}: {what}\n")


def _machine(report: _Report, mac: bool) -> None:
    if mac:
        on = "FileVault is On." in (_tool("fdesetup", "status") or "")
        report.check("filevault", on, f"turn FileVault on {PART_A}")
    else:
        report.manual("disk-encryption", f"check full-disk encryption by hand {PART_A}")
    soft = resource.getrlimit(resource.RLIMIT_CORE)[0]
    report.check("core-dumps", soft == 0, f"ulimit -c 0, and add it to ~/.zshrc {PART_A}")
    if mac:
        off = (_tool("sysctl", "-n", "kern.coredump") or "").strip() == "0"
        report.check("kern.coredump", off, f"sudo sysctl kern.coredump=0 {PART_A}")
    age = _version(_tool("age", "--version"))
    report.check("age", age is not None and age >= AGE_MINIMUM, f"install age 1.1.0+ {PART_A}")
    keygen = shutil.which("age-keygen") is not None
    report.check("age-keygen", keygen, f"install age 1.1.0+ {PART_A}")
    pinned = _version(_tool("gitleaks", "version")) == GITLEAKS_PIN
    report.check("gitleaks", pinned, f"install gitleaks 8.21.2, checksum checked {PART_A}")
    report.check("git", _tool("git", "--version") is not None, f"install git {PART_A}")


def doctor(
    config_path: Path | None, *, out: TextIO, platform: str = sys.platform, code: Path | None = None
) -> int:
    """Print one line per check; return 0 when nothing needs a fix, else 1."""
    report = _Report(out)
    mac = platform == "darwin"
    _machine(report, mac)
    checkout = code_checkout(code or checkout_module.CODE)
    try:
        config = load_config(config_path)
    except RecorderError as exc:
        report.check("config", False, f"{exc}: {INIT}")
        config = None
    else:
        same = config.checkout == checkout
        report.check("config", same, "its checkout is not this checkout: correct the file")
    if config is not None:
        folders = {"data_dir": config.data_dir, "backup_dir": config.backup_dir}
        for key, folder in folders.items():
            exists = folder.is_dir()
            fix = f"chmod 700 {shlex.quote(str(folder))}" if exists else INIT
            report.check(key, _mode(folder, folder=True) == 0o700, fix)
        for name in (IDENTITY, MASKER_KEYS, SITEST):
            path = config.data_dir / name
            fix = f"chmod 600 {shlex.quote(str(path))}" if path.is_file() else INIT
            report.check(name, _mode(path, folder=False) == 0o600, fix)
        if mac:
            for key, folder in (folders | {"checkout": checkout}).items():
                excluded = "[Excluded]" in (_tool("tmutil", "isexcluded", str(folder)) or "")
                fix = f"tmutil addexclusion {shlex.quote(str(folder))}"
                report.check(f"time-machine:{key}", excluded, fix)
    try:
        status = git(checkout, "status", "--porcelain", "--untracked-files=all")
        branch = git(checkout, "symbolic-ref", "--quiet", "--short", "HEAD")
        clean = status.returncode == 0 and not status.stdout.strip()
        on_main = clean and branch.stdout.strip() == "main"
    except RecorderError:
        on_main = False
    report.check("checkout", on_main, "a clean checkout of main (runbook 03 Part C)")
    for name, what in MANUAL:
        report.manual(name, what)
    return 0 if report.fixes == 0 else 1
