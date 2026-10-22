"""Leak scan: run the identifier detectors over the repository before anything reaches git.

Design ``docs/design/s2-recorder-masker.md`` §8.3. Every detector of §8.1 runs over every
text file. Two modes, chosen by path:

- **strict** under ``tests/fixtures/`` and ``recording-plans/``: every detector, digit runs
  bounded by any non-digit, and binary, compressed or non-UTF-8 files refused.
- **standard** everywhere else (code, docs, configuration): digit runs must not touch a
  letter (so hashes in lock files do not count), the IMO rule is off (one 7-digit number in
  ten has a valid IMO check digit), and only global IP addresses count.

Reserved-prefix surrogates are allowed everywhere; the canary range only under
``tests/leak/`` and ``tests/masker/``. A finding prints the file, the line and the detector
id, never the matched value, because CI logs are stored at GitHub.

A known false positive can be allowed only by a reviewed entry in
``scripts/leak_scan_allow.toml`` that names the path, the detector, the SHA-256 of the
matched text and a reason. The file is gate configuration (mandatory CTO review).

Usage:
  ``uv run python scripts/leak_scan.py``                  every tracked or unignored file
  ``uv run python scripts/leak_scan.py FILE...``          the given files (pre-commit hook)
  ``uv run python scripts/leak_scan.py --history [RANGE]`` lines added by every commit in
                                                          RANGE (default: all history)
"""

import argparse
import codecs
import hashlib
import ipaddress
import subprocess
import sys
import tomllib
from collections.abc import Iterable, Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Final, cast

from airtimesat_platform.masker.detect.patterns import (
    Boundary,
    Detector,
    Options,
    find_hits,
    normalize,
)
from airtimesat_platform.masker.detect.scan import offline_exemption, token_around

REPO_ROOT: Final = Path(__file__).resolve().parent.parent
DEFAULT_ALLOWLIST: Final = REPO_ROOT / "scripts" / "leak_scan_allow.toml"
STRICT_PREFIXES: Final = ("tests/fixtures/", "recording-plans/")
CANARY_PREFIXES: Final = ("tests/leak/", "tests/masker/")
STANDARD_SKIP: Final = frozenset({Detector.IMO})
# The generated field map holds only element and type names of the WSDL snapshot (scanned
# itself), joined by "/"; the drift test (tests/test_generate_fieldmap.py) keeps it equal to
# scripts/generate_fieldmap.py's output. A path run of exactly 27 such characters looks like
# an unpadded HMAC-SHA1 to SIGNATURE (78 paths of the first map), so that one detector is off
# for that one file. Every other detector still runs on it.
PATH_SKIP: Final = {
    "src/airtimesat_platform/gateway/wsdl/fieldmap/generated.yaml": frozenset({Detector.SIGNATURE})
}
COMPRESSED_SUFFIXES: Final = frozenset(
    {".gz", ".zip", ".bz2", ".xz", ".zst", ".7z", ".tar", ".tgz", ".jar", ".whl", ".age"}
)
MAX_FILE_BYTES: Final = 16 * 1024 * 1024
# Text in another Unicode encoding is decoded and scanned in standard mode (strict mode
# refuses it). UTF-32 first: its little-endian mark starts with the UTF-16 one.
UNICODE_BOMS: Final = (
    (codecs.BOM_UTF32_LE, "utf-32"),
    (codecs.BOM_UTF32_BE, "utf-32"),
    (codecs.BOM_UTF16_LE, "utf-16"),
    (codecs.BOM_UTF16_BE, "utf-16"),
)


@dataclass(frozen=True, slots=True, order=True)
class Finding:
    """One finding: where, and which detector. Never the value."""

    path: str
    line: int
    detector: str
    commit: str = ""

    def render(self) -> str:
        """Return ``path:line: DETECTOR`` (with the commit in history mode)."""
        prefix = f"{self.commit[:12]} " if self.commit else ""
        return f"{prefix}{self.path}:{self.line}: {self.detector}"


@dataclass(frozen=True, slots=True)
class AllowEntry:
    """A reviewed false positive: path, detector and SHA-256 of the matched text."""

    path: str
    detector: str
    sha256: str


def load_allowlist(path: Path) -> frozenset[AllowEntry]:
    """Read the allow-list. Every entry needs a path, a detector, a sha256 and a reason."""
    if not path.exists():
        return frozenset()
    data = tomllib.loads(path.read_text(encoding="utf-8"))
    entries: set[AllowEntry] = set()
    raw_entries = cast(list[dict[str, object]], data.get("allow", []))
    for raw in raw_entries:
        keys = {"path", "detector", "sha256", "reason"}
        if set(raw) != keys or not all(isinstance(raw[k], str) and raw[k] for k in keys):
            raise ValueError(f"{path}: each [[allow]] entry needs exactly {sorted(keys)}")
        sha = str(raw["sha256"])
        if len(sha) != 64 or any(c not in "0123456789abcdef" for c in sha):
            raise ValueError(f"{path}: sha256 must be 64 lower-case hex characters")
        entries.add(AllowEntry(str(raw["path"]), str(raw["detector"]), sha))
    return frozenset(entries)


def is_strict(path: str) -> bool:
    """Return whether a repository path is scanned in strict mode."""
    return path.startswith(STRICT_PREFIXES)


# Domains reserved by RFC 2606 and RFC 6761: no real person's mailbox lives there.
RESERVED_SECOND_LEVEL: Final = frozenset({"example.com", "example.net", "example.org"})
RESERVED_TOP_LEVEL: Final = frozenset({"test", "example", "invalid", "localhost"})


def reserved_email_domain(address: str) -> bool:
    """Return whether an e-mail address is under a reserved domain.

    At most one label may precede the reserved name (``mail.example.com``, ``canary.test``),
    so a real domain written in front of it (``gmail.com.invalid``) still counts.
    """
    domain = address.rpartition("@")[2].casefold().rstrip(".")
    labels = domain.split(".")
    if labels[-1] in RESERVED_TOP_LEVEL:
        return len(labels) <= 2
    return ".".join(labels[-2:]) in RESERVED_SECOND_LEVEL and len(labels) <= 3


def standard_exempt(value: str, detector: Detector) -> bool:
    """Exemptions of standard mode (code, docs, configuration), on top of the surrogates.

    Only global IP addresses count (loopback, private, documentation and the reserved
    240.0.0.0/4 range do not, also when written with leading zeros), and e-mail addresses
    under reserved domains do not count.
    """
    if detector is Detector.EMAIL:
        return reserved_email_domain(value)
    if detector is Detector.IPV4:
        try:
            octets = [int(part) for part in value.split(".")]
            address = ipaddress.IPv4Address(".".join(str(o) for o in octets))
        except ValueError:
            return False
        return not address.is_global
    if detector is Detector.IPV6:
        try:
            return not ipaddress.IPv6Address(value).is_global
        except ValueError:
            return False
    return False


class Scanner:
    """Scans lines of text for one repository path."""

    def __init__(self, allow: frozenset[AllowEntry]) -> None:
        """Use the reviewed allow-list."""
        self._allow = allow

    def scan_line(self, path: str, line: str) -> list[str]:
        """Return the detector ids that fire on one line of a file at ``path``."""
        strict = is_strict(path)
        options = Options(
            boundary=Boundary.DIGIT if strict else Boundary.ALNUM,
            skip=(frozenset[Detector]() if strict else STANDARD_SKIP)
            | PATH_SKIP.get(path, frozenset[Detector]()),
        )
        exempt = offline_exemption(allow_canary=path.startswith(CANARY_PREFIXES))
        found: list[str] = []
        for hit in find_hits(line, options, exempt):
            if not strict and standard_exempt(hit.text, hit.detector):
                continue
            if self._allowed(path, hit.detector, hit.text, line, hit.start, hit.end):
                continue
            found.append(hit.detector.value)
        return found

    def _allowed(
        self, path: str, detector: Detector, text: str, line: str, start: int, end: int
    ) -> bool:
        # Hit spans refer to the normalized line.
        candidates = {text, token_around(normalize(line), start, end)}
        for value in candidates:
            digest = hashlib.sha256(value.encode("utf-8")).hexdigest()
            if AllowEntry(path, detector.value, digest) in self._allow:
                return True
        return False

    def scan_text(self, path: str, text: str, commit: str = "") -> list[Finding]:
        """Scan every line of a file's text."""
        findings: list[Finding] = []
        for number, line in enumerate(text.splitlines(), start=1):
            findings.extend(
                Finding(path, number, d, commit) for d in sorted(set(self.scan_line(path, line)))
            )
        return findings


def read_text_file(path: Path, rel: str) -> tuple[str | None, Finding | None]:
    """Read a file as UTF-8 text; refuse binary, compressed or non-UTF-8 files in strict mode."""
    strict = is_strict(rel)
    if path.suffix.lower() in COMPRESSED_SUFFIXES:
        return None, Finding(rel, 0, "COMPRESSED_FILE") if strict else None
    data = path.read_bytes()
    if len(data) > MAX_FILE_BYTES:
        return None, Finding(rel, 0, "FILE_TOO_LARGE")
    if not strict:
        for bom, encoding in UNICODE_BOMS:
            if data.startswith(bom):
                try:
                    return data.decode(encoding), None
                except UnicodeDecodeError:
                    return None, Finding(rel, 0, "NOT_UTF8")
    if b"\x00" in data:
        return None, Finding(rel, 0, "BINARY_FILE") if strict else None
    try:
        return data.decode("utf-8"), None
    except UnicodeDecodeError:
        return None, Finding(rel, 0, "NOT_UTF8") if strict else None


def git(*args: str) -> str:
    """Run git in the repository and return its standard output."""
    result = subprocess.run(  # noqa: S603 - fixed program, arguments from this script
        ["git", *args],  # noqa: S607 - git from PATH, like the Makefile
        cwd=REPO_ROOT,
        check=True,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    return result.stdout


def repository_files() -> list[str]:
    """Return every tracked file and every untracked file git does not ignore."""
    out = git("ls-files", "-z", "--cached", "--others", "--exclude-standard")
    return sorted({p for p in out.split("\0") if p})


def scan_files(scanner: Scanner, paths: Iterable[str]) -> list[Finding]:
    """Scan the working-tree files at the given repository paths."""
    findings: list[Finding] = []
    for rel in paths:
        path = REPO_ROOT / rel
        if not path.is_file():
            continue
        text, problem = read_text_file(path, rel)
        if problem is not None:
            findings.append(problem)
        if text is not None:
            findings.extend(scanner.scan_text(rel, text))
    return findings


def unquote_path(text: str) -> str:
    """Undo git's C-style quoting of a path with special characters (octal escapes, quotes)."""
    if len(text) < 2 or not (text.startswith('"') and text.endswith('"')):
        return text
    raw: bytes = codecs.escape_decode(text[1:-1].encode("utf-8"))[0]
    return raw.decode("utf-8", errors="replace")


def added_lines(diff: str) -> Iterator[tuple[str, int, str]]:
    """Yield ``(path, line number, text)`` for every added line of a unified diff."""
    path = ""
    number = 0
    for line in diff.splitlines():
        if line.startswith("+++ "):
            target = unquote_path(line[4:])
            path = target[2:] if target.startswith("b/") else ""
        elif line.startswith("Binary files ") and line.endswith(" differ"):
            target = unquote_path(line.removesuffix(" differ").rpartition(" and ")[2])
            if target.startswith("b/"):
                yield target[2:], 0, "\0BINARY"
        elif line.startswith("@@"):
            new = line.split("+", 1)[1].split(" ", 1)[0]
            number = int(new.split(",", 1)[0])
        elif line.startswith("+") and path:
            yield path, number, line[1:]
            number += 1
        elif line.startswith(" ") and path:
            number += 1


def scan_history(scanner: Scanner, revision_range: str | None) -> list[Finding]:
    """Scan the lines each commit in the range added (all history if no range)."""
    rev_args = [revision_range] if revision_range else ["--all"]
    commits = git("rev-list", "--reverse", *rev_args).split()
    findings: list[Finding] = []
    for sha in commits:
        diff = git("show", "--format=", "--no-color", "--unified=0", "--no-renames", "-p", sha)
        for path, number, text in added_lines(diff):
            if text == "\0BINARY":
                if is_strict(path) or Path(path).suffix.lower() in COMPRESSED_SUFFIXES:
                    findings.append(Finding(path, 0, "BINARY_FILE", sha))
                continue
            findings.extend(
                Finding(path, number, d, sha) for d in sorted(set(scanner.scan_line(path, text)))
            )
    return findings


def main(argv: list[str] | None = None) -> int:
    """Run the scan and return the exit code: 0 clean, 1 findings."""
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0] if __doc__ else None)
    parser.add_argument("paths", nargs="*", help="files to scan (default: the repository)")
    parser.add_argument("--history", action="store_true", help="scan lines added by commits")
    parser.add_argument("--allowlist", type=Path, default=DEFAULT_ALLOWLIST)
    args = parser.parse_args(argv)
    scanner = Scanner(load_allowlist(args.allowlist))
    paths = cast(list[str], args.paths)
    if args.history:
        if len(paths) > 1:
            parser.error("--history takes at most one revision range")
        findings = scan_history(scanner, paths[0] if paths else None)
    else:
        rels = [str(Path(p).resolve().relative_to(REPO_ROOT)) for p in paths]
        findings = scan_files(scanner, rels or repository_files())
    for finding in sorted(set(findings)):
        print(finding.render())
    if findings:
        print(
            f"leak scan: {len(set(findings))} finding(s). Values are not shown. Remove the "
            "value, or replace it with a surrogate or a canary (tests only).",
            file=sys.stderr,
        )
        return 1
    print("leak scan: clean")
    return 0


if __name__ == "__main__":
    sys.exit(main())
