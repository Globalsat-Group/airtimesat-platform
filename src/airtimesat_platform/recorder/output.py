"""Masked exchange files, the run manifest and the end-of-run scans (design §5.1 steps 4 and 6).

Each run stages its files under ``tests/fixtures/masked/recordings/<plan-id>/<run-utc>/`` in
the trusted checkout: per call, the plan's request with surrogates (never the unmasked or
signed one) and the masked response, then ``manifest.json``. Before the CTO commits them,
``scripts/leak_scan.py`` and ``gitleaks dir`` scan the folder, and every staged file is
searched for the SITEST secret and each loaded key (raw, hex and Base64), which have no
fixed format a scanner could recognize. A hit deletes the run's staging folder; so does a
scanner that could not run. A finding names the file, the line where known and the detector
or secret name, never the value.
"""

import base64
import contextlib
import json
import shutil
import subprocess
import sys
from collections.abc import Callable, Iterable
from pathlib import Path
from typing import Final

from airtimesat_platform.common.secrets import SecretValue
from airtimesat_platform.masker.errors import MaskingError
from airtimesat_platform.masker.keys import decode_key

STAGING_ROOT: Final = Path("tests", "fixtures", "masked", "recordings")
MANIFEST: Final = "manifest.json"
MANIFEST_FORMAT: Final = "airtimesat-recording-manifest/1"
SCAN_TIMEOUT_S: Final = 300
# Shorter needles would match by chance.
MIN_NEEDLE_BYTES: Final = 6

# Exit code that tells a gitleaks finding apart from its own errors (1, or 2 for a panic).
GITLEAKS_HIT: Final = 3

# A finding: (file or file:line, detector or secret name). Never a value.
Finding = tuple[str, str]
# (checkout, staging folder) -> the findings, or None if a scanner could not run and none
# of the others found anything.
Scanner = Callable[[Path, Path], list[Finding] | None]


class Staging:
    """One run's staging folder, created on the first write."""

    def __init__(self, checkout: Path, plan_id: str, run_utc: str) -> None:
        """Name the folder; nothing is created yet."""
        self.path = checkout / STAGING_ROOT / plan_id / run_utc

    def files(self) -> list[Path]:
        """Return the staged files, sorted."""
        return sorted(p for p in self.path.rglob("*") if p.is_file()) if self.path.exists() else []

    def write_exchange(
        self, seq: int, call_id: str, request: bytes, response: bytes
    ) -> tuple[Path, Path]:
        """Write one call's masked request and masked response; return their paths."""
        self.path.mkdir(parents=True, exist_ok=True)
        stem = f"{seq:03d}-{call_id}"
        files = (self.path / f"{stem}.request.xml", self.path / f"{stem}.response.xml")
        try:
            files[0].write_bytes(request)
            files[1].write_bytes(response)
        except BaseException:
            for path in files:
                path.unlink(missing_ok=True)
            raise
        return files

    def write_manifest(self, manifest: dict[str, object]) -> None:
        """Write ``manifest.json``."""
        self.path.mkdir(parents=True, exist_ok=True)
        text = json.dumps({"format": MANIFEST_FORMAT, **manifest}, indent=2, ensure_ascii=True)
        (self.path / MANIFEST).write_text(text + "\n", encoding="utf-8")

    def delete(self) -> None:
        """Delete the run's staging folder; raise ``OSError`` if any of it remains."""
        if self.path.exists():
            shutil.rmtree(self.path)


def _tool(command: list[str], cwd: Path) -> tuple[int, str]:
    """Run one scanner; return its exit code (-1 if it cannot run) and its standard output."""
    try:
        result = subprocess.run(  # noqa: S603 - fixed programs, arguments from this module
            command,
            cwd=cwd,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            check=False,
            timeout=SCAN_TIMEOUT_S,
        )
    except (OSError, subprocess.TimeoutExpired):
        return -1, ""
    return result.returncode, result.stdout


def _leak_scan_findings(stdout: str) -> list[Finding]:
    """Parse ``leak_scan``'s ``path:line: DETECTOR`` lines."""
    findings: list[Finding] = []
    for line in stdout.splitlines():
        where, _, detector = line.rpartition(": ")
        if where and detector:
            findings.append((where, f"leak_scan:{detector}"))
    return findings


def _gitleaks_findings(stdout: str, checkout: Path) -> list[Finding]:
    """Parse the ``RuleID``, ``File`` and ``Line`` fields of ``gitleaks --redact --verbose``."""
    findings: list[Finding] = []
    rule = file = ""
    for line in stdout.splitlines():
        key, _, value = line.partition(":")
        value = value.strip()
        if key == "RuleID":
            rule = value
        elif key == "File":
            path = Path(value)
            file = str(path.relative_to(checkout)) if path.is_relative_to(checkout) else value
        elif key == "Line" and rule:
            findings.append((f"{file}:{value}", f"gitleaks:{rule}"))
            rule = file = ""
    return findings


def tool_scan(checkout: Path, staging: Path) -> list[Finding] | None:
    """Run ``scripts/leak_scan.py`` and ``gitleaks dir`` over the staging folder.

    Return their findings (paths, lines and detector ids: the tools never print values), or
    None if a scanner could not run (missing, crashed, timed out) and the other found nothing.
    """
    files = [str(p.relative_to(checkout)) for p in sorted(staging.rglob("*")) if p.is_file()]
    leak_scan = [sys.executable, str(checkout / "scripts" / "leak_scan.py"), *files]
    gitleaks = ["gitleaks", "dir", str(staging), "--redact", "--verbose", "--no-color"]
    gitleaks += ["--no-banner", "--exit-code", str(GITLEAKS_HIT)]
    config = checkout / ".gitleaks.toml"
    if config.is_file():
        gitleaks += ["--config", str(config)]
    findings: list[Finding] = []
    ran = True
    code, out = _tool(leak_scan, checkout)
    # leak_scan exits 1 on findings, which it prints; a crash exits 1 too, with no findings.
    found = _leak_scan_findings(out) if code == 1 else []
    findings += found
    ran &= code == 0 or bool(found)
    code, out = _tool(gitleaks, checkout)
    if code == GITLEAKS_HIT:
        folder = str(staging.relative_to(checkout))
        findings += _gitleaks_findings(out, checkout) or [(folder, "gitleaks")]
    ran &= code in (0, GITLEAKS_HIT)
    return findings if findings or ran else None


def _forms(data: bytes) -> set[bytes]:
    encoded = base64.b64encode(data)
    return {
        data,
        data.hex().encode(),
        data.hex().upper().encode(),
        encoded,
        encoded.rstrip(b"="),
        base64.urlsafe_b64encode(data).rstrip(b"="),
    }


def secret_needles(secrets: Iterable[tuple[str, SecretValue]]) -> dict[bytes, str]:
    """Return every form of each named secret to search for (raw, hex and Base64) and its name.

    A value that decodes as a 256-bit key is searched for as key bytes too.
    """
    needles: dict[bytes, str] = {}
    for name, value in secrets:
        forms = _forms(value.reveal().encode("utf-8"))
        with contextlib.suppress(MaskingError):
            forms |= _forms(decode_key(value).material())
        needles |= {form: name for form in forms if len(form) >= MIN_NEEDLE_BYTES}
    return needles


def secret_hit(checkout: Path, files: Iterable[Path], needles: dict[bytes, str]) -> list[Finding]:
    """Return (file, secret name) for each staged file that holds a form of a secret."""
    findings: list[Finding] = []
    for path in files:
        data = path.read_bytes()
        names = sorted({name for needle, name in needles.items() if needle in data})
        findings += [(str(path.relative_to(checkout)), f"secret:{name}") for name in names]
    return findings
