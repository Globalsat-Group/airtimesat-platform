"""Licence gate: fail if an installed package has a licence that is not allowed.

Reads the licences of every package in the current environment with pip-licenses and
checks them against ``licensing/allowlist.toml``. A package that fails can pass only
through a reviewed entry in ``licensing/exceptions.toml``.

Rules:
- An SPDX expression passes if it is satisfied by allowed licences (``OR``: any side,
  ``AND``: both sides). ``WITH`` clauses are not evaluated and fail.
- Several classifier names (pip-licenses joins them with ``"; "``) pass only if each one
  is allowed.
- Anything unknown fails.

Usage: ``uv run python scripts/licence_gate.py``
"""

import argparse
import json
import re
import subprocess
import sys
import tomllib
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any, cast

REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_ALLOWLIST = REPO_ROOT / "licensing" / "allowlist.toml"
DEFAULT_EXCEPTIONS = REPO_ROOT / "licensing" / "exceptions.toml"
OWN_PROJECT = "airtimesat-platform"

_TOKEN = re.compile(r"\(|\)|[^\s()]+")


@dataclass(frozen=True)
class Package:
    """One installed distribution and the licence pip-licenses reports for it."""

    name: str
    version: str
    licence: str


@dataclass(frozen=True)
class Policy:
    """Allowed SPDX identifiers, name aliases and reviewed exceptions."""

    allowed: frozenset[str]
    aliases: Mapping[str, str]
    exceptions: Mapping[str, str]  # normalized package name -> licence string reviewed


class _ExpressionError(ValueError):
    pass


def normalize_name(name: str) -> str:
    """Return the PEP 503 normalized form of a distribution name."""
    return re.sub(r"[-_.]+", "-", name).lower()


def _term_allowed(term: str, policy: Policy) -> bool:
    spdx = policy.aliases.get(term, term)
    return spdx in policy.allowed


def _is_spdx_expression(licence: str) -> bool:
    return bool(re.search(r"\s(OR|AND|WITH)\s", licence))


def _evaluate_expression(licence: str, policy: Policy) -> bool:
    """Evaluate an SPDX expression. AND binds tighter than OR."""
    tokens = _TOKEN.findall(licence)
    position = 0

    def peek() -> str | None:
        return tokens[position] if position < len(tokens) else None

    def take() -> str:
        nonlocal position
        if position >= len(tokens):
            raise _ExpressionError(licence)
        token = tokens[position]
        position += 1
        return token

    def parse_or() -> bool:
        result = parse_and()
        while peek() == "OR":
            take()
            right = parse_and()
            result = result or right
        return result

    def parse_and() -> bool:
        result = parse_atom()
        while peek() == "AND":
            take()
            right = parse_atom()
            result = result and right
        return result

    def parse_atom() -> bool:
        symbol = take()
        if symbol == "(":
            result = parse_or()
            if take() != ")":
                raise _ExpressionError(licence)
            return result
        if symbol in {")", "OR", "AND", "WITH"}:
            raise _ExpressionError(licence)
        if peek() == "WITH":
            take()
            take()
            return False
        return _term_allowed(symbol, policy)

    result = parse_or()
    if position != len(tokens):
        raise _ExpressionError(licence)
    return result


def licence_allowed(licence: str, policy: Policy) -> bool:
    """Return True if ``licence`` is allowed by the allow-list alone."""
    licence = licence.strip()
    if not licence or licence.upper() == "UNKNOWN":
        return False
    if _term_allowed(licence, policy):
        return True
    if _is_spdx_expression(licence):
        try:
            return _evaluate_expression(licence, policy)
        except _ExpressionError:
            return False
    return all(_term_allowed(part.strip(), policy) for part in licence.split(";"))


def violations(packages: Iterable[Package], policy: Policy) -> list[Package]:
    """Return the packages that fail the gate, sorted by name."""
    failed: list[Package] = []
    for package in packages:
        name = normalize_name(package.name)
        if name == OWN_PROJECT:
            continue
        if licence_allowed(package.licence, policy):
            continue
        if policy.exceptions.get(name) == package.licence:
            continue
        failed.append(package)
    return sorted(failed, key=lambda p: normalize_name(p.name))


def _as_table(value: object, what: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise SystemExit(f"licence gate: {what} must be a table")
    return cast(dict[str, Any], value)


def _as_str(value: object, what: str) -> str:
    if not isinstance(value, str):
        raise SystemExit(f"licence gate: {what} must be a string")
    return value


def load_policy(allowlist: Path, exceptions: Path) -> Policy:
    """Read the allow-list and exceptions files."""
    allow_data = tomllib.loads(allowlist.read_text(encoding="utf-8"))
    allowed_raw = allow_data.get("allowed", [])
    if not isinstance(allowed_raw, list):
        raise SystemExit("licence gate: 'allowed' must be a list")
    allowed = frozenset(_as_str(v, "allowed entry") for v in cast(list[object], allowed_raw))
    aliases = {
        _as_str(k, "alias"): _as_str(v, "alias target")
        for k, v in _as_table(allow_data.get("aliases", {}), "aliases").items()
    }

    exc_data = tomllib.loads(exceptions.read_text(encoding="utf-8"))
    entries_raw = exc_data.get("exception", [])
    if not isinstance(entries_raw, list):
        raise SystemExit("licence gate: 'exception' must be an array of tables")
    reviewed: dict[str, str] = {}
    for raw in cast(list[object], entries_raw):
        entry = _as_table(raw, "exception")
        for field in ("package", "licence", "reason", "reviewed_by", "reviewed_on"):
            if field not in entry:
                raise SystemExit(f"licence gate: exception entry is missing '{field}': {entry}")
        package = normalize_name(_as_str(entry["package"], "exception package"))
        reviewed[package] = _as_str(entry["licence"], "exception licence")
    return Policy(allowed=allowed, aliases=aliases, exceptions=reviewed)


def installed_packages() -> list[Package]:
    """List installed distributions with pip-licenses."""
    output = subprocess.run(  # fixed argument list, no user input
        [sys.executable, "-m", "piplicenses", "--from=mixed", "--with-system", "--format=json"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout
    rows = cast(list[dict[str, str]], json.loads(output))
    return [Package(name=r["Name"], version=r["Version"], licence=r["License"]) for r in rows]


def main(argv: list[str] | None = None) -> int:
    """Run the gate and print the result."""
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0] if __doc__ else None)
    parser.add_argument("--allowlist", type=Path, default=DEFAULT_ALLOWLIST)
    parser.add_argument("--exceptions", type=Path, default=DEFAULT_EXCEPTIONS)
    args = parser.parse_args(argv)
    policy = load_policy(cast(Path, args.allowlist), cast(Path, args.exceptions))
    packages = installed_packages()
    failed = violations(packages, policy)

    installed = {normalize_name(p.name) for p in packages}
    for stale in sorted(set(policy.exceptions) - installed):
        print(f"licence gate: warning: exception for '{stale}' matches no installed package")

    if failed:
        print("licence gate: FAILED. Licences not allowed and not in licensing/exceptions.toml:")
        for package in failed:
            print(f"  {package.name} {package.version}: {package.licence or 'UNKNOWN'}")
        return 1
    print(f"licence gate: passed ({len(packages)} packages checked)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
