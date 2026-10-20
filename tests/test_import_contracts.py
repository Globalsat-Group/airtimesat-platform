"""The import-linter contracts that enforce module boundaries must stay in place.

lint-imports checks that the code keeps the contracts; this test checks that nobody
removed or weakened a contract to make lint-imports pass.
"""

import tomllib
from pathlib import Path
from typing import Any, cast

import pytest

PYPROJECT = Path(__file__).resolve().parent.parent / "pyproject.toml"
APP = "airtimesat_platform"

# The production endpoint module arrives in stage S4. import-linter skips a forbidden module
# that is not in the graph yet, so the name is pinned here (design s2-recorder-masker §7.3).
PRODUCTION_ENDPOINTS = f"{APP}.gateway.endpoints_production"

# contract id -> (sources, forbidden modules that must stay forbidden)
EXPECTED: dict[str, tuple[set[str], set[str]]] = {
    "console-boundary": (
        {f"{APP}.console"},
        {f"{APP}.gateway", f"{APP}.masker", f"{APP}.archive", f"{APP}.recorder"},
    ),
    "domain-pure": (
        {f"{APP}.domain"},
        {
            f"{APP}.gateway",
            f"{APP}.masker",
            f"{APP}.console",
            f"{APP}.archive",
            f"{APP}.common",
            f"{APP}.recorder",
        },
    ),
    "domain-no-io-frameworks": (
        {f"{APP}.domain"},
        {"fastapi", "starlette", "uvicorn", "jinja2", "pydantic_settings"},
    ),
    "masker-isolated": (
        {f"{APP}.masker"},
        {f"{APP}.gateway", f"{APP}.domain", f"{APP}.console", f"{APP}.archive", f"{APP}.recorder"},
    ),
    "masker-no-transport": (
        {f"{APP}.masker"},
        {"aiohttp", "xsdata"},
    ),
    "archive-isolated": (
        {f"{APP}.archive"},
        {f"{APP}.gateway", f"{APP}.masker", f"{APP}.console", f"{APP}.recorder"},
    ),
    "soap-libraries-gateway-only": (
        {f"{APP}.console", f"{APP}.domain", f"{APP}.archive", f"{APP}.common"},
        {"aiohttp", "xsdata", "lxml"},
    ),
    "recorder-boundary": (
        {f"{APP}.recorder"},
        {f"{APP}.gateway", f"{APP}.console", f"{APP}.domain", f"{APP}.archive"},
    ),
    "recorder-no-soap-libraries": (
        {f"{APP}.recorder"},
        {"aiohttp", "xsdata", "lxml"},
    ),
    "sitest-only": (
        {f"{APP}.recorder", f"{APP}.masker", f"{APP}.gateway.sitest_port"},
        {f"{APP}.gateway.api", PRODUCTION_ENDPOINTS},
    ),
    "gateway-one-way": (
        {f"{APP}.gateway"},
        {f"{APP}.masker", f"{APP}.recorder"},
    ),
    "ports-apart": (
        {f"{APP}.gateway.api"},
        {f"{APP}.gateway.sitest_port"},
    ),
}

# Contracts whose indirect imports must be checked too (allow_indirect_imports = false).
CHECKS_INDIRECT_IMPORTS = ["masker-no-transport", "sitest-only"]

# The only contracts allowed to skip imports, and exactly what each may skip.
ALLOWED_IGNORES: dict[str, list[str]] = {
    "console-boundary": [
        f"{APP}.console -> {APP}.gateway.api",
        f"{APP}.console.** -> {APP}.gateway.api",
    ],
    "recorder-boundary": [
        f"{APP}.recorder -> {APP}.gateway.sitest_port",
        f"{APP}.recorder.** -> {APP}.gateway.sitest_port",
    ],
}


def _config() -> dict[str, Any]:
    data = tomllib.loads(PYPROJECT.read_text(encoding="utf-8"))
    return cast(dict[str, Any], data["tool"]["importlinter"])


def _contracts() -> dict[str, dict[str, Any]]:
    contracts = cast(list[dict[str, Any]], _config()["contracts"])
    return {cast(str, c["id"]): c for c in contracts}


def test_root_package_and_external_packages_are_configured() -> None:
    config = _config()
    assert config["root_packages"] == [APP]
    assert config["include_external_packages"] is True


@pytest.mark.parametrize("contract_id", sorted(EXPECTED))
def test_contract_exists_and_is_not_weakened(contract_id: str) -> None:
    contract = _contracts().get(contract_id)
    assert contract is not None, f"import-linter contract {contract_id!r} is missing"
    assert contract["type"] == "forbidden"
    sources, forbidden = EXPECTED[contract_id]
    assert sources <= set(cast(list[str], contract["source_modules"]))
    assert forbidden <= set(cast(list[str], contract["forbidden_modules"]))


@pytest.mark.parametrize("contract_id", CHECKS_INDIRECT_IMPORTS)
def test_contract_checks_indirect_imports(contract_id: str) -> None:
    assert _contracts()[contract_id].get("allow_indirect_imports") is False


def test_sitest_only_pins_the_production_endpoint_module() -> None:
    forbidden = cast(list[str], _contracts()["sitest-only"]["forbidden_modules"])
    assert PRODUCTION_ENDPOINTS in forbidden


def test_console_may_only_skip_the_gateway_public_port() -> None:
    contract = _contracts()["console-boundary"]
    assert contract.get("ignore_imports") == ALLOWED_IGNORES["console-boundary"]


def test_recorder_may_only_skip_the_sitest_port() -> None:
    contract = _contracts()["recorder-boundary"]
    assert contract.get("ignore_imports") == ALLOWED_IGNORES["recorder-boundary"]


def test_only_allow_listed_contracts_ignore_imports() -> None:
    ignoring = {cid for cid, c in _contracts().items() if "ignore_imports" in c}
    assert ignoring <= set(ALLOWED_IGNORES)
