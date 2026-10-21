"""Fixtures for the recorder tests: a synthetic field map and a plan builder.

Identifiers are reserved-prefix surrogates built at run time; real-format values are built
at run time too, so no identifier-like literal sits in these files (design §8.3).
"""

import hashlib
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path

import pytest
import yaml

from airtimesat_platform.masker.fieldmap.loader import build_field_map
from airtimesat_platform.masker.tokenize.surrogates import SPECS
from airtimesat_platform.recorder.errors import PlanRefusedError
from airtimesat_platform.recorder.plan import CheckedPlan, FieldMapContext, check_plan

DATA = Path(__file__).parent / "data"
NOW = datetime(2026, 10, 21, 12, 0, tzinfo=UTC)
EXPIRES = "2026-11-30T00:00:00Z"


def map_texts() -> tuple[str, str]:
    """Return the synthetic generated map and overrides."""
    return (
        (DATA / "generated.yaml").read_text(encoding="utf-8"),
        (DATA / "overrides.yaml").read_text(encoding="utf-8"),
    )


def surrogate(type_name: str, n: int = 0) -> str:
    """Return a well-formed surrogate of a type (never issued: there is no vault in D1)."""
    return SPECS[type_name].render(hashlib.sha256(f"{type_name}-{n}".encode()).digest(), "")


def search(
    value: str,
    *,
    filter_type: str = "IMEI",
    cond: str = "EQUALS",
    limit: str = "5",
    extra: str = "",
) -> str:
    """Return an ``accountSearch`` request."""
    return (
        f"<request><filterType>{filter_type}</filterType><filterValue>{value}</filterValue>"
        f"<filterCond>{cond}</filterCond><limit>{limit}</limit>{extra}</request>"
    )


def call(
    call_id: str,
    operation: str,
    request: str,
    *,
    endpoint: str = "provisioning",
    **extra: object,
) -> dict[str, object]:
    """Return one call of a plan."""
    return {"id": call_id, "endpoint": endpoint, "operation": operation, "request": request} | extra


def build(calls: list[dict[str, object]] | None = None, **top: object) -> str:
    """Return a plan's YAML text: a valid one-call plan, with ``top`` keys replaced.

    A key given as ``None`` is removed.
    """
    plan: dict[str, object] = {
        "id": "RP-2026-003",
        "title": "SBD account shapes for ST-03",
        "purpose": "Annex F ST-03: SBD account variants present in SITEST",
        "expires_at": EXPIRES,
        "max_calls": 10,
        "calls": calls
        if calls is not None
        else [call("search", "accountSearch", search(surrogate("IMEI")))],
    }
    for key, value in top.items():
        if value is None:
            plan.pop(key, None)
        else:
            plan[key] = value
    return yaml.safe_dump(plan, sort_keys=False, allow_unicode=True, width=1000)


@pytest.fixture(name="context")
def context_fixture() -> FieldMapContext:
    """Return the synthetic field map as the recorder uses it."""
    field_map, _ = build_field_map(*map_texts())
    return FieldMapContext(field_map)


@pytest.fixture(name="check")
def check_fixture(context: FieldMapContext) -> Callable[[str], CheckedPlan]:
    """Return a function that checks a plan's text at the fixed test time."""

    def run(text: str) -> CheckedPlan:
        return check_plan(text, now=NOW, field_map=context)

    return run


@pytest.fixture(name="refuse")
def refuse_fixture(check: Callable[[str], CheckedPlan]) -> Callable[[str], PlanRefusedError]:
    """Return a function that asserts a plan is refused and returns the refusal."""

    def run(text: str) -> PlanRefusedError:
        with pytest.raises(PlanRefusedError) as info:
            check(text)
        return info.value

    return run


# Test modules cannot import this file (pytest's importlib mode), so the helpers above are
# also handed out as fixtures.


@pytest.fixture(name="build")
def build_fixture() -> Callable[..., str]:
    """Return the plan builder."""
    return build


@pytest.fixture(name="make_call")
def make_call_fixture() -> Callable[..., dict[str, object]]:
    """Return the call builder."""
    return call


@pytest.fixture(name="search")
def search_fixture() -> Callable[..., str]:
    """Return the ``accountSearch`` request builder."""
    return search


@pytest.fixture(name="surrogate")
def surrogate_fixture() -> Callable[..., str]:
    """Return the surrogate builder."""
    return surrogate


@pytest.fixture(name="texts")
def texts_fixture() -> tuple[str, str]:
    """Return the synthetic generated map and overrides texts."""
    return map_texts()
