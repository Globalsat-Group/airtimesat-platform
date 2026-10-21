"""Masked exchange files, the run manifest and the end-of-run scans (design §5.1 steps 4 and 6).

Each run stages its files under ``tests/fixtures/masked/recordings/<plan-id>/<run-utc>/`` in
the trusted checkout: per call, the plan's request with surrogates (never the unmasked or
signed one) and the masked response, then ``manifest.json``. Before the CTO commits them,
``scripts/leak_scan.py`` and ``gitleaks dir`` scan the folder, and every staged file is
searched for the SITEST secret and each loaded key (raw, hex and Base64), which have no
fixed format a scanner could recognize. Any hit deletes the run's staging folder.
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

# (checkout, staging folder) -> True when a scanner found something or could not run.
Scanner = Callable[[Path, Path], bool]


class Staging:
    """One run's staging folder, created on the first write."""

    def __init__(self, checkout: Path, plan_id: str, run_utc: str) -> None:
        """Name the folder; nothing is created yet."""
        self.path = checkout / STAGING_ROOT / plan_id / run_utc

    def files(self) -> list[Path]:
        """Return the staged files, sorted."""
        return sorted(p for p in self.path.rglob("*") if p.is_file()) if self.path.exists() else []

    def write_exchange(self, seq: int, call_id: str, request: bytes, response: bytes) -> None:
        """Write one call's masked request and masked response."""
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

    def write_manifest(self, manifest: dict[str, object]) -> None:
        """Write ``manifest.json``."""
        self.path.mkdir(parents=True, exist_ok=True)
        text = json.dumps({"format": MANIFEST_FORMAT, **manifest}, indent=2, ensure_ascii=True)
        (self.path / MANIFEST).write_text(text + "\n", encoding="utf-8")

    def delete(self) -> None:
        """Delete the run's staging folder; raise ``OSError`` if any of it remains."""
        if self.path.exists():
            shutil.rmtree(self.path)


def _tool(command: list[str], cwd: Path) -> bool:
    """Run one scanner; return True on a finding or if it cannot run (fail closed)."""
    try:
        result = subprocess.run(  # noqa: S603 - fixed programs, arguments from this module
            command, cwd=cwd, capture_output=True, check=False, timeout=SCAN_TIMEOUT_S
        )
    except (OSError, subprocess.TimeoutExpired):
        return True
    return result.returncode != 0


def tool_scan(checkout: Path, staging: Path) -> bool:
    """Run ``scripts/leak_scan.py`` and ``gitleaks dir`` over the staging folder.

    Their output is discarded: the recorder reports the hit as a code, and the CTO runs the
    tools again by hand to see where (they print paths and detector ids, never values).
    """
    files = [str(p.relative_to(checkout)) for p in sorted(staging.rglob("*")) if p.is_file()]
    leak_scan = [sys.executable, str(checkout / "scripts" / "leak_scan.py"), *files]
    gitleaks = ["gitleaks", "dir", str(staging), "--redact", "--no-banner", "--exit-code", "1"]
    config = checkout / ".gitleaks.toml"
    if config.is_file():
        gitleaks += ["--config", str(config)]
    hit_leak = _tool(leak_scan, checkout)
    hit_gitleaks = _tool(gitleaks, checkout)
    return hit_leak or hit_gitleaks


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


def secret_needles(values: Iterable[SecretValue]) -> frozenset[bytes]:
    """Return every form of each secret to search for: raw, hex and Base64.

    A value that decodes as a 256-bit key is searched for as key bytes too.
    """
    needles: set[bytes] = set()
    for value in values:
        needles |= _forms(value.reveal().encode("utf-8"))
        with contextlib.suppress(MaskingError):
            needles |= _forms(decode_key(value).material())
    return frozenset(n for n in needles if len(n) >= MIN_NEEDLE_BYTES)


def secret_hit(files: Iterable[Path], needles: frozenset[bytes]) -> bool:
    """Return whether any file holds any needle."""
    for path in files:
        data = path.read_bytes()
        if any(needle in data for needle in needles):
            return True
    return False
