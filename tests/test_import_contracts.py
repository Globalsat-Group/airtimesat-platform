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

# contract id -> (sources, forbidden modules that must stay forbidden)
EXPECTED: dict[str, tuple[set[str], set[str]]] = {
    "console-boundary": (
        {f"{APP}.console"},
        {f"{APP}.gateway", f"{APP}.masker", f"{APP}.archive"},
    ),
    "domain-pure": (
        {f"{APP}.domain"},
        {f"{APP}.gateway", f"{APP}.masker", f"{APP}.console", f"{APP}.archive", f"{APP}.common"},
    ),
    "domain-no-io-frameworks": (
        {f"{APP}.domain"},
        {"fastapi", "starlette", "uvicorn", "jinja2", "pydantic_settings"},
    ),
    "masker-isolated": (
        {f"{APP}.masker"},
        {f"{APP}.gateway", f"{APP}.domain", f"{APP}.console", f"{APP}.archive"},
    ),
    "archive-isolated": (
        {f"{APP}.archive"},
        {f"{APP}.gateway", f"{APP}.masker", f"{APP}.console"},
    ),
    "soap-libraries-gateway-only": (
        {f"{APP}.console", f"{APP}.domain", f"{APP}.archive", f"{APP}.common"},
        {"aiohttp", "xsdata", "lxml"},
    ),
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


def test_console_may_only_skip_the_gateway_public_port() -> None:
    contract = _contracts()["console-boundary"]
    assert contract.get("ignore_imports") == [
        f"{APP}.console -> {APP}.gateway.api",
        f"{APP}.console.** -> {APP}.gateway.api",
    ]


@pytest.mark.parametrize("contract_id", sorted(set(EXPECTED) - {"console-boundary"}))
def test_other_contracts_ignore_no_imports(contract_id: str) -> None:
    assert "ignore_imports" not in _contracts()[contract_id]
