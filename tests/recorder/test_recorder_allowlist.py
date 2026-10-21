"""The read allowlist and its limits (design §5.3, §5.5 step 8, §8.5 #16 and #18)."""

from collections.abc import Callable

import pytest

from airtimesat_platform.gateway import sitest_guard
from airtimesat_platform.gateway.endpoints_sitest import Endpoint
from airtimesat_platform.recorder.errors import PlanRefusedError
from airtimesat_platform.recorder.plan import CheckedPlan
from airtimesat_platform.recorder.policy import allowlist

Build = Callable[..., str]
MakeCall = Callable[..., dict[str, object]]
Search = Callable[..., str]
Surrogate = Callable[..., str]
Check = Callable[[str], CheckedPlan]
Refuse = Callable[[str], PlanRefusedError]


# ---------------------------------------------------------------- the two implementations


def test_the_read_allowlist_matches_the_gateway_guard_endpoint_by_endpoint() -> None:
    # Two independent lists (design §5.7); they must say the same thing.
    assert allowlist.READS[allowlist.PROVISIONING] == sitest_guard.READS_PROVISIONING
    assert allowlist.READS[allowlist.REPORTING] == sitest_guard.READS_REPORTING
    assert set(allowlist.ENDPOINTS) == {endpoint.value for endpoint in Endpoint}


def test_the_write_list_matches_the_gateway_guard() -> None:
    assert allowlist.WRITES == sitest_guard.WRITES_PROVISIONING
    assert Endpoint(allowlist.WRITE_ENDPOINT) is Endpoint.PROVISIONING


def test_every_limited_method_is_an_allowlisted_read() -> None:
    reads = allowlist.READS[allowlist.PROVISIONING] | allowlist.READS[allowlist.REPORTING]
    assert set(allowlist.LIMITS) <= reads
    for rules in allowlist.LIMITS.values():
        for rule in rules.ranges:
            assert 0 <= rule.low <= rule.high


def test_no_read_is_also_a_write() -> None:
    for reads in allowlist.READS.values():
        assert not reads & allowlist.WRITES


# ---------------------------------------------------------------- valid reads


@pytest.mark.parametrize(
    ("operation", "request_xml", "endpoint"),
    [
        ("getSystemStatus", "<request/>", "provisioning"),
        ("getSystemStatus", "<request/>", "reporting"),
        ("getReportTypes", "<request/>", "reporting"),
        (
            "getDevices",
            "<request><serviceType>SBD</serviceType><deviceType>IMEI</deviceType>"
            "<numResults>20</numResults></request>",
            "provisioning",
        ),
        ("getVessels", "<request><imo>{IMO}</imo></request>", "provisioning"),
        ("getVessels", "<request><vesselName>{VESSEL}</vesselName></request>", "provisioning"),
        ("getSubscriberOrgs", "<request><Id>{ORG}</Id></request>", "provisioning"),
        (
            "bulkActionSearch",
            "<request><bulkRequestId>4711</bulkRequestId></request>",
            "provisioning",
        ),
        (
            "getRechargeHistory",
            "<request><msisdn>{MSISDN}</msisdn><limit>50</limit><startRow>0</startRow></request>",
            "provisioning",
        ),
        (
            "getEVoucherInventory",
            "<request><limit>1</limit><startRow>0</startRow></request>",
            "provisioning",
        ),
        (
            "getIwsRequests",
            "<request><iwsOperation>accountSearch</iwsOperation>"
            "<startDate>2026-10-20T00:00:00Z</startDate><endDate>2026-10-21T00:00:00Z</endDate>"
            "<Limit>100</Limit></request>",
            "provisioning",
        ),
        (
            "getQueueEntries",
            "<request><Endpoint>PROVISIONING</Endpoint><status>DONE</status></request>",
            "provisioning",
        ),
    ],
)
def test_reads_within_their_limits_pass(
    check: Check,
    build: Build,
    make_call: MakeCall,
    surrogate: Surrogate,
    operation: str,
    request_xml: str,
    endpoint: str,
) -> None:
    filled = request_xml.format(
        IMO=surrogate("IMO"),
        VESSEL=surrogate("VESSEL"),
        ORG=surrogate("ORG"),
        MSISDN=surrogate("MSISDN"),
    )
    assert check(build([make_call("read", operation, filled, endpoint=endpoint)]))


def test_an_account_search_within_its_limits_passes(
    check: Check, build: Build, make_call: MakeCall, search: Search, surrogate: Surrogate
) -> None:
    request_xml = search(
        surrogate("CONTRACT"),
        filter_type="ACCOUNT_NUMBER",
        limit="50",
        extra="<startRow>200</startRow>",
    )
    assert check(build([make_call("search", "accountSearch", request_xml)]))
    no_cond = (
        "<request><filterType>IMEI</filterType>"
        f"<filterValue>{surrogate('IMEI')}</filterValue><limit>1</limit></request>"
    )
    assert check(build([make_call("search", "accountSearch", no_cond)]))


# ---------------------------------------------------------------- search oracles (§8.5 #16)


@pytest.mark.parametrize(
    "cond",
    [
        "NOT_EQUAL",
        "CONTAINS",
        "LIKE",
        "STARTS_WITH",
        " contains ",
        "",
        # Only the exact literal: the plan's text is sent as written.
        "equals",
        "Equals",
        " EQUALS ",
        "\uff25\uff31\uff35\uff21\uff2c\uff33",  # full-width EQUALS
    ],
)
def test_account_search_matches_exactly(
    refuse: Refuse,
    build: Build,
    make_call: MakeCall,
    search: Search,
    surrogate: Surrogate,
    cond: str,
) -> None:
    error = refuse(build([make_call("s", "accountSearch", search(surrogate("IMEI"), cond=cond))]))
    assert (error.code, error.location) == ("FILTER_COND_REFUSED", "calls[0]/request/filterCond")


@pytest.mark.parametrize("value", ["99*", "%0000", "Vessel-*"])
def test_wildcards_on_identifier_filters_are_refused(
    refuse: Refuse, build: Build, make_call: MakeCall, search: Search, value: str
) -> None:
    request_xml = search(value, filter_type="VESSEL_NAME")
    assert refuse(build([make_call("s", "accountSearch", request_xml)])).code == "WILDCARD_REFUSED"


def test_free_text_in_a_search_input_is_refused(
    refuse: Refuse, build: Build, make_call: MakeCall, search: Search
) -> None:
    request_xml = search("Ocean Explorer", filter_type="VESSEL_NAME")
    assert refuse(build([make_call("s", "accountSearch", request_xml)])).code == "NOT_A_SURROGATE"


@pytest.mark.parametrize("name", ["Vessel-ab", "Vessel-", "Ocean", "vessel-abcdefgh"])
def test_a_vessel_name_prefix_is_refused(
    refuse: Refuse, build: Build, make_call: MakeCall, name: str
) -> None:
    request_xml = f"<request><vesselName>{name}</vesselName></request>"
    error = refuse(build([make_call("v", "getVessels", request_xml)]))
    assert (error.code, error.location) == (
        "SEARCH_INPUT_NOT_A_SURROGATE",
        "calls[0]/request/vesselName",
    )


def test_vessels_are_searched_by_their_identifiers_only(
    refuse: Refuse, build: Build, make_call: MakeCall, surrogate: Surrogate
) -> None:
    by_call_sign = f"<request><callSign>{surrogate('ID')}</callSign></request>"
    assert (
        refuse(build([make_call("v", "getVessels", by_call_sign)])).code == "SEARCH_INPUT_REQUIRED"
    )
    mixed = (
        f"<request><imo>{surrogate('IMO')}</imo><callSign>{surrogate('ID')}</callSign></request>"
    )
    assert refuse(build([make_call("v", "getVessels", mixed)])).code == "SEARCH_INPUT_REFUSED"
    assert (
        refuse(build([make_call("v", "getVessels", "<request/>")])).code == "SEARCH_INPUT_REQUIRED"
    )


def test_organizations_are_searched_by_id_only(
    refuse: Refuse, build: Build, make_call: MakeCall, surrogate: Surrogate
) -> None:
    by_name = f"<request><Name>{surrogate('ORG')}</Name></request>"
    assert (
        refuse(build([make_call("o", "getSubscriberOrgs", by_name)])).code
        == "SEARCH_INPUT_REQUIRED"
    )
    both = f"<request><Id>{surrogate('ORG')}</Id><Name>{surrogate('ORG', 1)}</Name></request>"
    assert refuse(build([make_call("o", "getSubscriberOrgs", both)])).code == "SEARCH_INPUT_REFUSED"


@pytest.mark.parametrize("value", ["", "user-abcdefgh", "rec.RP-2026-003"])
def test_queue_entries_created_by_is_set_by_the_recorder(
    refuse: Refuse, build: Build, make_call: MakeCall, value: str
) -> None:
    request_xml = (
        "<request><Endpoint>PROVISIONING</Endpoint><status>DONE</status>"
        f"<createdBy>{value}</createdBy></request>"
    )
    error = refuse(build([make_call("q", "getQueueEntries", request_xml)]))
    assert (error.code, error.location) == ("SET_BY_RECORDER", "calls[0]/request/createdBy")


@pytest.mark.parametrize(
    ("request_xml", "code", "location"),
    [
        (
            "<request><bulkRequestId>4711</bulkRequestId><Wildcard>*</Wildcard></request>",
            "WILDCARD_REFUSED",
            "calls[0]/request/Wildcard",
        ),
        (
            "<request><bulkRequestId>4711</bulkRequestId><Wildcard>TRUE</Wildcard></request>",
            "WILDCARD_REFUSED",
            "calls[0]/request/Wildcard",
        ),
        # Only the exact literal FALSE: the plan's text is sent as written.
        *(
            (
                f"<request><bulkRequestId>4711</bulkRequestId><Wildcard>{value}</Wildcard></request>",
                "WILDCARD_REFUSED",
                "calls[0]/request/Wildcard",
            )
            for value in ("false", "False", " FALSE ", "\uff26\uff21\uff2c\uff33\uff25")
        ),
        (
            "<request><bulkRequestId>*</bulkRequestId></request>",
            "WILDCARD_REFUSED",
            "calls[0]/request/bulkRequestId",
        ),
        (
            "<request><bulkRequestId>47%</bulkRequestId><Wildcard>FALSE</Wildcard></request>",
            "WILDCARD_REFUSED",
            "calls[0]/request/bulkRequestId",
        ),
        (
            "<request><bulkRequestId>4711</bulkRequestId><status>DONE</status></request>",
            "SEARCH_INPUT_REFUSED",
            "calls[0]/request",
        ),
    ],
)
def test_bulk_action_search_matches_one_request_exactly(
    refuse: Refuse, build: Build, make_call: MakeCall, request_xml: str, code: str, location: str
) -> None:
    error = refuse(build([make_call("b", "bulkActionSearch", request_xml)]))
    assert (error.code, error.location) == (code, location)


@pytest.mark.parametrize("wildcard", ["", "<Wildcard>FALSE</Wildcard>"])
def test_bulk_action_search_exact_match_passes(
    check: Check, build: Build, make_call: MakeCall, wildcard: str
) -> None:
    request_xml = f"<request><bulkRequestId>4711</bulkRequestId>{wildcard}</request>"
    assert check(build([make_call("b", "bulkActionSearch", request_xml)]))


def test_bulk_action_search_by_request_id_only(
    refuse: Refuse, build: Build, make_call: MakeCall
) -> None:
    blank = "<request><bulkRequestId> </bulkRequestId></request>"
    assert (
        refuse(build([make_call("b", "bulkActionSearch", blank)])).code == "SEARCH_INPUT_REQUIRED"
    )


# ---------------------------------------------------------------- bulk pulls (§8.5 #18)


@pytest.mark.parametrize(
    ("operation", "request_xml", "code", "location"),
    [
        (
            "getDevices",
            "<request><serviceType>SBD</serviceType><deviceType>IMEI</deviceType><numResults>0</numResults></request>",
            "LIMIT_OUT_OF_RANGE",
            "calls[0]/request/numResults",
        ),
        (
            "getDevices",
            "<request><serviceType>SBD</serviceType><deviceType>IMEI</deviceType><numResults>21</numResults></request>",
            "LIMIT_OUT_OF_RANGE",
            "calls[0]/request/numResults",
        ),
        (
            "getDevices",
            "<request><serviceType>SBD</serviceType><deviceType>IMEI</deviceType></request>",
            "LIMIT_MISSING",
            "calls[0]/request/numResults",
        ),
        (
            "getEVoucherInventory",
            "<request><limit>0</limit></request>",
            "LIMIT_OUT_OF_RANGE",
            "calls[0]/request/limit",
        ),
        (
            "getEVoucherInventory",
            "<request><limit>51</limit></request>",
            "LIMIT_OUT_OF_RANGE",
            "calls[0]/request/limit",
        ),
        (
            "getEVoucherInventory",
            "<request><limit>-1</limit></request>",
            "LIMIT_NOT_AN_INTEGER",
            "calls[0]/request/limit",
        ),
        (
            "getEVoucherInventory",
            "<request><limit>05</limit></request>",
            "LIMIT_NOT_AN_INTEGER",
            "calls[0]/request/limit",
        ),
        (
            "getEVoucherInventory",
            "<request><limit>1e3</limit></request>",
            "LIMIT_NOT_AN_INTEGER",
            "calls[0]/request/limit",
        ),
        (
            "getRechargeHistory",
            "<request><msisdn>x</msisdn></request>",
            "LIMIT_MISSING",
            "calls[0]/request/limit",
        ),
        (
            "getSubscriberOrgs",
            "<request><Id></Id></request>",
            "SEARCH_INPUT_REQUIRED",
            "calls[0]/request/Id",
        ),
        (
            "getSubscriberOrgs",
            "<request><Id>  </Id></request>",
            "SEARCH_INPUT_REQUIRED",
            "calls[0]/request/Id",
        ),
        ("getSubscriberOrgs", "<request/>", "SEARCH_INPUT_REQUIRED", "calls[0]/request/Id"),
        (
            "getIwsRequests",
            "<request><iwsOperation>x</iwsOperation><startDate>2026-10-20T00:00:00Z</startDate>"
            "<endDate>2026-10-21T00:00:01Z</endDate><Limit>10</Limit></request>",
            "WINDOW_TOO_LONG",
            "calls[0]/request/endDate",
        ),
        (
            "getIwsRequests",
            "<request><iwsOperation>x</iwsOperation><startDate>2026-10-21T00:00:00Z</startDate>"
            "<endDate>2026-10-20T00:00:00Z</endDate><Limit>10</Limit></request>",
            "WINDOW_INVALID",
            "calls[0]/request/endDate",
        ),
        (
            "getIwsRequests",
            "<request><iwsOperation>x</iwsOperation><startDate>2026-10-20</startDate>"
            "<endDate>2026-10-21T00:00:00Z</endDate><Limit>10</Limit></request>",
            "WINDOW_INVALID",
            "calls[0]/request/startDate",
        ),
        (
            "getIwsRequests",
            "<request><iwsOperation>x</iwsOperation><startDate>2026-13-01T00:00:00Z</startDate>"
            "<endDate>2026-10-21T00:00:00Z</endDate><Limit>10</Limit></request>",
            "WINDOW_INVALID",
            "calls[0]/request/startDate",
        ),
        (
            "getIwsRequests",
            "<request><iwsOperation>x</iwsOperation><endDate>2026-10-21T00:00:00Z</endDate><Limit>10</Limit></request>",
            "WINDOW_MISSING",
            "calls[0]/request/startDate",
        ),
        (
            "getIwsRequests",
            "<request><iwsOperation>x</iwsOperation><startDate>2026-10-20T00:00:00Z</startDate>"
            "<endDate>2026-10-21T00:00:00Z</endDate><Limit>101</Limit></request>",
            "LIMIT_OUT_OF_RANGE",
            "calls[0]/request/Limit",
        ),
        (
            "getIwsRequests",
            "<request><iwsOperation>x</iwsOperation><startDate>2026-10-20T00:00:00Z</startDate>"
            "<endDate>2026-10-21T00:00:00Z</endDate></request>",
            "LIMIT_MISSING",
            "calls[0]/request/Limit",
        ),
    ],
)
def test_bulk_pulls_are_refused(
    refuse: Refuse,
    build: Build,
    make_call: MakeCall,
    operation: str,
    request_xml: str,
    code: str,
    location: str,
) -> None:
    error = refuse(build([make_call("read", operation, request_xml)]))
    assert (error.code, error.location) == (code, location)


@pytest.mark.parametrize(
    ("value", "extra", "code", "location"),
    [
        ("{imei}", "<startRow>201</startRow>", "LIMIT_OUT_OF_RANGE", "calls[0]/request/startRow"),
        ("{imei}", "<limit>5</limit>", "LIMIT_DUPLICATE", "calls[0]/request/limit"),
        ("{imei}", "<LIMIT>5</LIMIT>", "LIMIT_DUPLICATE", "calls[0]/request/limit"),
        ("", "", "SEARCH_INPUT_REQUIRED", "calls[0]/request/filterValue"),
    ],
)
def test_account_search_limits(
    refuse: Refuse,
    build: Build,
    make_call: MakeCall,
    search: Search,
    surrogate: Surrogate,
    value: str,
    extra: str,
    code: str,
    location: str,
) -> None:
    request_xml = search(value.format(imei=surrogate("IMEI")), extra=extra)
    error = refuse(build([make_call("s", "accountSearch", request_xml)]))
    assert (error.code, error.location) == (code, location)


def test_an_unfiltered_account_search_is_refused(
    refuse: Refuse, build: Build, make_call: MakeCall
) -> None:
    error = refuse(build([make_call("s", "accountSearch", "<request><limit>5</limit></request>")]))
    assert (error.code, error.location) == ("SEARCH_INPUT_REQUIRED", "calls[0]/request/filterType")


@pytest.mark.parametrize("filter_type", ["SMART", "smart", " Smart "])
def test_the_smart_filter_is_refused(
    refuse: Refuse,
    build: Build,
    make_call: MakeCall,
    search: Search,
    surrogate: Surrogate,
    filter_type: str,
) -> None:
    request_xml = search(surrogate("IMEI"), filter_type=filter_type)
    assert (
        refuse(build([make_call("s", "accountSearch", request_xml)])).code == "FILTER_SMART_REFUSED"
    )


def test_a_limit_name_in_the_wrong_case(refuse: Refuse, build: Build, make_call: MakeCall) -> None:
    error = refuse(
        build([make_call("e", "getEVoucherInventory", "<request><Limit>5</Limit></request>")])
    )
    assert (error.code, error.location) == ("ELEMENT_NAME_CASE", "calls[0]/request/limit")
