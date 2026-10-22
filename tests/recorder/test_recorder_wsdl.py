"""The recorder against the real WSDL snapshot: operation names and the schema check.

Design §5.3: every allowlisted and refused name exists in the WSDL snapshot. Refused names that
do not exist are listed here with the reason they are kept.
"""

from datetime import UTC, datetime
from functools import cache
from importlib import resources

import pytest
from lxml import etree

from airtimesat_platform.gateway import sitest_guard
from airtimesat_platform.recorder.errors import PlanRefusedError
from airtimesat_platform.recorder.plan import check_plan
from airtimesat_platform.recorder.policy import allowlist, hard_blocks

# The real schema check runs in this module (tests/conftest.py).
REAL_WSDL_SCHEMA = True
NOW = datetime(2026, 10, 21, 12, 0, tzinfo=UTC)
WSDL = "{http://schemas.xmlsoap.org/wsdl/}"
# Refused names that are not WSDL operations. Matching ignores case, so the refusal of a
# name that does not exist is harmless; each is kept so that no spelling of it ever passes.
ABSENT_REFUSED = {
    "updateVessels": "catalog spelling; the WSDL operation is updateVessel, refused too",
    "updateSubscriberOrg": "catalog short name; the WSDL has updateSubscriberOrganization "
    "and updateSubscriberOrgStatus, both refused",
}


@cache
def operations(endpoint: str) -> frozenset[str]:
    """Return the portType operation names of one endpoint's WSDL snapshot."""
    data = (
        resources.files("airtimesat_platform.gateway")
        .joinpath("wsdl", "sitest", f"{endpoint}.wsdl")
        .read_bytes()
    )
    root = etree.fromstring(data, etree.XMLParser(resolve_entities=False, no_network=True))
    return frozenset(op.get("name", "") for op in root.iterfind(f"{WSDL}portType/{WSDL}operation"))


@pytest.mark.parametrize("endpoint", allowlist.ENDPOINTS)
def test_every_allowlisted_read_exists_on_its_endpoint(endpoint: str) -> None:
    assert allowlist.READS[endpoint] <= operations(endpoint)


def test_every_write_exists_on_the_write_endpoint() -> None:
    assert operations(allowlist.WRITE_ENDPOINT) >= allowlist.WRITES


@pytest.mark.parametrize(
    "refused", [frozenset(hard_blocks.ALWAYS_REFUSED), sitest_guard.ALWAYS_REFUSED]
)
def test_every_refused_name_exists_or_is_listed_as_absent(refused: frozenset[str]) -> None:
    known = operations("provisioning") | operations("reporting")
    assert refused - known == set(ABSENT_REFUSED)


def test_the_guard_refuses_the_same_names_case_insensitively() -> None:
    def folded(names: frozenset[str]) -> set[str]:
        return {n.casefold() for n in names}

    guard, recorder = sitest_guard.ALWAYS_REFUSED, frozenset(hard_blocks.ALWAYS_REFUSED)
    # The recorder alone refuses the methods that need an SPNet password (design §5.3); the
    # guard's default deny refuses them too.
    assert folded(recorder) - folded(guard) == {"getaccountpoolinggroups", "getaccountpoolinggroup"}
    assert folded(guard) <= folded(recorder)


# ---------------------------------------------------------------- the schema check in a plan


def plan(operation: str, request: str, endpoint: str = "provisioning") -> str:
    return (
        "id: RP-2026-003\ntitle: Schema check\npurpose: WSDL schema check test\n"
        "expires_at: 2026-11-30T00:00:00Z\nmax_calls: 5\ncalls:\n"
        f"  - id: one\n    endpoint: {endpoint}\n    operation: {operation}\n"
        f"    request: '{request}'\n"
    )


def refusal(text: str) -> PlanRefusedError:
    with pytest.raises(PlanRefusedError) as raised:
        check_plan(text, now=NOW, field_map=None)
    return raised.value


@pytest.mark.parametrize(
    ("endpoint", "operation", "request_xml"),
    [
        ("provisioning", "getSystemStatus", "<request/>"),
        ("reporting", "getIwsReportVersion", "<request/>"),
        # createdBy is required by the WSDL and added by the recorder (§5.5 step 8).
        (
            "provisioning",
            "getQueueEntries",
            "<request><endpoint>IWS</endpoint><status>ERROR</status></request>",
        ),
    ],
)
def test_a_schema_valid_plan_reaches_the_field_map_check(
    endpoint: str, operation: str, request_xml: str
) -> None:
    assert refusal(plan(operation, request_xml, endpoint)).code == "FIELD_MAP_MISSING"


def test_a_schema_invalid_plan_is_refused_with_a_safe_location() -> None:
    sentinel = "SntVal" + "q" * 10
    # getSystemStatus takes an empty request: libxml2 names the request itself.
    text = plan("getSystemStatus", f"<request><{sentinel}>x</{sentinel}></request>")
    refused = refusal(text)
    assert (refused.code, refused.location) == (
        "WSDL_SCHEMA_INVALID",
        "calls[0]/request#SCHEMA_CONTENT",
    )
    assert sentinel not in str(refused)


def test_a_wrong_value_names_the_element() -> None:
    text = plan(
        "getQueueEntries", "<request><endpoint>NOWHERE</endpoint><status>ERROR</status></request>"
    )
    refused = refusal(text)
    assert (refused.code, refused.location) == (
        "WSDL_SCHEMA_INVALID",
        "calls[0]/request/endpoint#SCHEMA_VALUE",
    )


def test_get_vessels_needs_every_input_present_design_open_point_32() -> None:
    # The WSDL requires all five getVessels inputs, while §5.5 step 8 lets a plan leave out
    # an unused identifier filter. Until the CTO decides (design §13 #32), the plan fails.
    refused = refusal(plan("getVessels", "<request><id>Text-AAAAAAAA</id></request>"))
    assert (refused.code, refused.location) == (
        "WSDL_SCHEMA_INVALID",
        "calls[0]/request#SCHEMA_CONTENT",
    )
