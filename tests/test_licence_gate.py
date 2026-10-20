"""Tests for scripts/licence_gate.py."""

from pathlib import Path

import pytest

from licence_gate import (
    DEFAULT_ALLOWLIST,
    DEFAULT_EXCEPTIONS,
    Package,
    Policy,
    licence_allowed,
    load_policy,
    violations,
)


@pytest.fixture
def policy() -> Policy:
    return load_policy(DEFAULT_ALLOWLIST, DEFAULT_EXCEPTIONS)


@pytest.mark.parametrize(
    "licence",
    [
        "MIT",
        "MIT License",
        "Apache-2.0",
        "Apache Software License",
        "BSD-3-Clause",
        "BSD License",
        "PSF-2.0",
        "Mozilla Public License 2.0 (MPL 2.0)",
        "Apache-2.0 OR BSD-2-Clause",
        "MIT AND (Apache-2.0 OR BSD-2-Clause)",
        "MIT License; BSD License",
    ],
)
def test_allowed_licences_pass(policy: Policy, licence: str) -> None:
    assert licence_allowed(licence, policy)


@pytest.mark.parametrize(
    "licence",
    [
        "",
        "UNKNOWN",
        "GPL-3.0-only",
        "GNU General Public License v3 (GPLv3)",
        "AGPL-3.0-or-later",
        "LGPL-2.1-or-later",
        "GNU Lesser General Public License v3 (LGPLv3)",
        "MIT AND GPL-3.0-only",
        "MIT License; GNU General Public License v2 (GPLv2)",
        "GPL-2.0-or-later WITH Classpath-exception-2.0",
        "MIT OR",
        "(MIT",
        "Proprietary",
    ],
)
def test_other_licences_fail(policy: Policy, licence: str) -> None:
    assert not licence_allowed(licence, policy)


def test_own_project_is_skipped(policy: Policy) -> None:
    packages = [Package("airtimesat_platform", "0.0.0", "LicenseRef-Proprietary")]
    assert violations(packages, policy) == []


def test_exception_needs_the_exact_licence(tmp_path: Path) -> None:
    exceptions = tmp_path / "exceptions.toml"
    exceptions.write_text(
        "[[exception]]\n"
        'package = "Some_Lib"\n'
        'licence = "LGPL-3.0-or-later"\n'
        'reason = "test"\n'
        'reviewed_by = "@reviewer"\n'
        "reviewed_on = 2026-10-20\n",
        encoding="utf-8",
    )
    policy = load_policy(DEFAULT_ALLOWLIST, exceptions)
    reviewed = Package("some-lib", "1.0", "LGPL-3.0-or-later")
    changed = Package("some-lib", "2.0", "GPL-3.0-only")
    assert violations([reviewed, changed], policy) == [changed]


def test_incomplete_exception_is_rejected(tmp_path: Path) -> None:
    exceptions = tmp_path / "exceptions.toml"
    exceptions.write_text('[[exception]]\npackage = "x"\nlicence = "GPL-3.0-only"\n')
    with pytest.raises(SystemExit, match="missing"):
        load_policy(DEFAULT_ALLOWLIST, exceptions)
