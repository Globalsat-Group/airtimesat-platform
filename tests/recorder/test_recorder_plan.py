"""The plan loader, references and the canonical digest (design §5.2, §8.5 #12)."""

import hashlib
from collections.abc import Callable
from datetime import UTC, datetime

import pytest

from airtimesat_platform.masker.tokenize.surrogates import SPECS
from airtimesat_platform.recorder.errors import PlanRefusedError
from airtimesat_platform.recorder.plan import (
    MAX_CALLS,
    CheckedPlan,
    FieldMapContext,
    check_plan,
    load_plan,
)

Build = Callable[..., str]
MakeCall = Callable[..., dict[str, object]]
Search = Callable[..., str]
Surrogate = Callable[..., str]
Check = Callable[[str], CheckedPlan]
Refuse = Callable[[str], PlanRefusedError]

NOW = datetime(2026, 10, 21, 12, 0, tzinfo=UTC)
# A real-format IMEI shape built at run time: 15 digits outside the reserved prefix.
REAL_IMEI = "35" + "0" * 12 + "7"
# A well-formed IMEI surrogate: the reserved prefix and a valid Luhn digit.
IMEI = SPECS["IMEI"].render(hashlib.sha256(b"chained").digest(), "")

VALID = """\
id: RP-2026-003
title: SBD account shapes for ST-03
purpose: Annex F ST-03, SBD account variants present in SITEST
expires_at: 2026-11-30T00:00:00Z        # a live run after this time is refused
max_calls: 4
calls:
  - id: search
    endpoint: provisioning
    operation: accountSearch
    request: |
      <request>
        <filterType>IMEI</filterType>
        <filterValue>{imei}</filterValue>
        <filterCond>EQUALS</filterCond>
        <limit>5</limit>
      </request>
  - id: account
    endpoint: provisioning
    operation: getSubscriberAccount
    for_each: ${{search.accountNumber[0:3]}}
    request: |
      <request><accountNo>${{item}}</accountNo></request>
"""


def valid(surrogate: Surrogate) -> str:
    return VALID.format(imei=surrogate("IMEI"))


def chained(
    make_call: MakeCall, request: str, for_each: str, operation: str
) -> list[dict[str, object]]:
    """Return an accountSearch call followed by a call that iterates over its results."""
    first = make_call(
        "search",
        "accountSearch",
        f"<request><filterType>IMEI</filterType><filterValue>{IMEI}</filterValue>"
        "<limit>5</limit></request>",
    )
    return [first, make_call("next", operation, request, for_each=for_each)]


# ---------------------------------------------------------------- a valid plan


def test_the_design_example_passes(check: Check, surrogate: Surrogate) -> None:
    checked = check(valid(surrogate))
    assert checked.plan.id == "RP-2026-003"
    assert checked.plan.expansion == 4
    assert len(checked.digest) == 64
    assert int(checked.digest, 16) >= 0


def test_without_a_field_map_every_plan_fails_closed(surrogate: Surrogate) -> None:
    with pytest.raises(PlanRefusedError) as info:
        check_plan(valid(surrogate), now=NOW, field_map=None)
    assert info.value.code == "FIELD_MAP_MISSING"


def test_a_hard_block_is_reported_before_the_missing_field_map(
    build: Build, make_call: MakeCall
) -> None:
    text = build([make_call("x", "createOnDemandReport", "<request/>", endpoint="reporting")])
    with pytest.raises(PlanRefusedError) as info:
        check_plan(text, now=NOW, field_map=None)
    assert info.value.code == "ALWAYS_REFUSED_METHOD"


# ---------------------------------------------------------------- strict YAML


@pytest.mark.parametrize(
    ("text", "code"),
    [
        ("id: RP-2026-003\nid: RP-2026-004\n", "YAML_DUPLICATE_KEY"),
        ("id: &x RP-2026-003\n", "YAML_ANCHOR"),
        ("title: *x\n", "YAML_ALIAS"),
        ("<<: {id: RP-2026-003}\n", "YAML_MERGE_KEY"),
        ("id: !!str RP-2026-003\n", "YAML_TAG"),
        ("id: [unclosed\n", "YAML_SYNTAX"),
        ("1: x\n", "YAML_NON_STRING_KEY"),
    ],
)
def test_strict_yaml(refuse: Refuse, text: str, code: str) -> None:
    error = refuse(text)
    assert error.code == code
    assert error.location.startswith("line:") or code == "YAML_SYNTAX"


def test_duplicate_keys_inside_a_call(refuse: Refuse, surrogate: Surrogate) -> None:
    text = valid(surrogate).replace(
        "    operation: getSubscriberAccount\n",
        "    operation: getSubscriberAccount\n    operation: getSubscriberAccount\n",
    )
    assert refuse(text).code == "YAML_DUPLICATE_KEY"


# ---------------------------------------------------------------- schema


@pytest.mark.parametrize(
    ("changes", "code", "location"),
    [
        ({"extra": "x"}, "SCHEMA_UNKNOWN_KEY", "plan"),
        ({"title": None}, "SCHEMA_MISSING_KEY", "title"),
        ({"id": "RP-26-3"}, "PLAN_ID_INVALID", "id"),
        ({"id": 2026}, "SCHEMA_WRONG_TYPE", "id"),
        ({"title": 5}, "SCHEMA_WRONG_TYPE", "title"),
        ({"title": "  "}, "TEXT_EMPTY", "title"),
        ({"title": "x" * 121}, "TEXT_TOO_LONG", "title"),
        ({"title": "two\nlines"}, "TEXT_NOT_PLAIN", "title"),
        ({"purpose": "no-break\u00a0space"}, "TEXT_NOT_PLAIN", "purpose"),
        # A control character can only be written as an escape, which is refused.
        ({"purpose": "bell\x07"}, "YAML_ESCAPE", "line:3"),
        ({"max_calls": "5"}, "SCHEMA_WRONG_TYPE", "max_calls"),
        ({"max_calls": True}, "SCHEMA_WRONG_TYPE", "max_calls"),
        ({"max_calls": 0}, "MAX_CALLS_OUT_OF_RANGE", "max_calls"),
        ({"max_calls": MAX_CALLS + 1}, "MAX_CALLS_OUT_OF_RANGE", "max_calls"),
        ({"calls": []}, "CALLS_EMPTY", "calls"),
        ({"calls": {"a": 1}}, "SCHEMA_WRONG_TYPE", "calls"),
        ({"calls": ["x"]}, "SCHEMA_NOT_MAPPING", "calls[0]"),
        ({"expires_at": "2026-10-01T00:00:00Z"}, "EXPIRES_AT_PAST", "expires_at"),
        ({"expires_at": "2026-11-30T00:00:00+00:00"}, "EXPIRES_AT_NOT_UTC", "expires_at"),
        ({"expires_at": "2026-11-30T00:00:00"}, "EXPIRES_AT_NOT_UTC", "expires_at"),
        ({"expires_at": "next month"}, "EXPIRES_AT_INVALID", "expires_at"),
        ({"expires_at": 20261130}, "EXPIRES_AT_INVALID", "expires_at"),
    ],
)
def test_schema_refusals(
    refuse: Refuse, build: Build, changes: dict[str, object], code: str, location: str
) -> None:
    error = refuse(build(**changes))
    assert (error.code, error.location) == (code, location)


def test_a_plan_that_is_not_a_mapping(refuse: Refuse) -> None:
    assert refuse("- just\n- a list\n").code == "SCHEMA_NOT_MAPPING"


@pytest.mark.parametrize(
    ("line", "code"),
    [
        ("expires_at: 2026-11-30T02:00:00+02:00", "EXPIRES_AT_NOT_UTC"),
        ("expires_at: 2026-11-30 00:00:00", "EXPIRES_AT_NOT_UTC"),
        ("expires_at: 2026-11-30", "EXPIRES_AT_INVALID"),
        ("expires_at: 2026-10-20T00:00:00Z", "EXPIRES_AT_PAST"),
    ],
)
def test_unquoted_timestamps(refuse: Refuse, surrogate: Surrogate, line: str, code: str) -> None:
    text = valid(surrogate).replace(
        "expires_at: 2026-11-30T00:00:00Z        # a live run after this time is refused", line
    )
    assert refuse(text).code == code


@pytest.mark.parametrize("newline", ["\r\n", "\r"])
@pytest.mark.parametrize("comment", ["", "  # a comment"])
def test_unquoted_timestamps_with_other_line_ends(
    check: Check, surrogate: Surrogate, newline: str, comment: str
) -> None:
    text = valid(surrogate).replace("        # a live run after this time is refused", comment)
    assert check(text.replace("\n", newline)).digest == check(text).digest


def test_the_clock_is_injected(surrogate: Surrogate, context: FieldMapContext) -> None:
    late = datetime(2026, 12, 1, tzinfo=UTC)
    with pytest.raises(PlanRefusedError) as info:
        check_plan(valid(surrogate), now=late, field_map=context)
    assert info.value.code == "EXPIRES_AT_PAST"


@pytest.mark.parametrize(
    ("change", "code", "location"),
    [
        ({"caller": "rec.RP-2026-003"}, "SCHEMA_UNKNOWN_KEY", "calls[0]"),
        ({"id": "Search"}, "CALL_ID_INVALID", "calls[0].id"),
        ({"id": 7}, "SCHEMA_WRONG_TYPE", "calls[0].id"),
        ({"request": " "}, "REQUEST_EMPTY", "calls[0]"),
        (
            {"request": "<request>" + "<limit>5</limit>" * 5000 + "</request>"},
            "REQUEST_TOO_LARGE",
            "calls[0].request",
        ),
        ({"for_each": 3}, "SCHEMA_WRONG_TYPE", "calls[0].for_each"),
    ],
)
def test_call_schema(
    refuse: Refuse,
    build: Build,
    make_call: MakeCall,
    search: Search,
    surrogate: Surrogate,
    change: dict[str, object],
    code: str,
    location: str,
) -> None:
    one = make_call("search", "accountSearch", search(surrogate("IMEI"))) | change
    error = refuse(build([one]))
    assert (error.code, error.location) == (code, location)


@pytest.mark.parametrize("plan_id", ["RP-2026-00\uff13", "RP-\u0662\u0660\u0662\u0666-003"])
def test_a_plan_id_has_ascii_digits_only(refuse: Refuse, build: Build, plan_id: str) -> None:
    error = refuse(build(id=plan_id))
    assert (error.code, error.location) == ("PLAN_ID_INVALID", "id")


@pytest.mark.parametrize("call_id", ["a" + REAL_IMEI, "line-" + REAL_IMEI])
def test_call_ids_pass_the_detectors(
    refuse: Refuse, build: Build, make_call: MakeCall, call_id: str
) -> None:
    error = refuse(build([make_call(call_id, "getSystemStatus", "<request/>")]))
    assert (error.code, error.location) == ("REAL_FORMAT_VALUE", "calls[0].id#IMEI")


def test_a_reference_passes_the_detectors(
    refuse: Refuse, build: Build, make_call: MakeCall
) -> None:
    calls = chained(
        make_call,
        "<request><accountNo>${item}</accountNo></request>",
        "${search.a" + REAL_IMEI + "[0:2]}",
        "getSubscriberAccount",
    )
    error = refuse(build(calls))
    assert (error.code, error.location) == ("REAL_FORMAT_VALUE", "calls[1].for_each#IMEI")


def _hex_escaped(text: str) -> str:
    return "".join(f"\\x{ord(ch):02x}" for ch in text)


@pytest.mark.parametrize(
    ("old", "new", "line"),
    [
        # Escaped digits that the leak scan and the reviewer would not see as digits
        ("  - id: search", f'  - id: "a{_hex_escaped(REAL_IMEI)}"', "line:7"),
        ("  - id: account", '  - id: "acc\\u006fun\\x74"', "line:17"),
        # A line continuation splits a value across lines
        ("title: SBD account", 'title: "SBD \\\n  account"\ntext:', "line:2"),
    ],
)
def test_escapes_in_double_quoted_scalars_are_refused(
    refuse: Refuse, surrogate: Surrogate, old: str, new: str, line: str
) -> None:
    text = valid(surrogate)
    assert old in text
    error = refuse(text.replace(old, new, 1))
    assert (error.code, error.location) == ("YAML_ESCAPE", line)


def test_double_quoted_scalars_without_escapes_pass(check: Check, surrogate: Surrogate) -> None:
    text = valid(surrogate).replace("  - id: search", '  - id: "search"')
    assert check(text).digest == check(valid(surrogate)).digest


def test_a_missing_call_key(refuse: Refuse, build: Build) -> None:
    error = refuse(build([{"id": "a", "endpoint": "provisioning", "operation": "getSystemStatus"}]))
    assert (error.code, error.location) == ("SCHEMA_MISSING_KEY", "calls[0].request")


def test_duplicate_call_ids(refuse: Refuse, build: Build, make_call: MakeCall) -> None:
    calls = [make_call("status", "getSystemStatus", "<request/>") for _ in range(2)]
    error = refuse(build(calls))
    assert (error.code, error.location) == ("CALL_ID_DUPLICATE", "calls[1].id")


def test_calls_over_max_calls(
    check: Check, refuse: Refuse, build: Build, make_call: MakeCall
) -> None:
    calls = [make_call(f"s{n}", "getSystemStatus", "<request/>") for n in range(3)]
    assert refuse(build(calls, max_calls=2)).code == "CALLS_OVER_MAX"
    assert check(build(calls, max_calls=3)).plan.expansion == 3


def test_title_and_purpose_pass_the_detectors(refuse: Refuse, build: Build) -> None:
    error = refuse(build(purpose=f"Check the line {REAL_IMEI} for ST-03"))
    assert (error.code, error.location) == ("REAL_FORMAT_VALUE", "purpose#IMEI")


def test_surrogates_in_text_are_allowed(check: Check, build: Build, surrogate: Surrogate) -> None:
    assert check(build(purpose=f"Follow-up on {surrogate('CONTRACT')} from RP-2026-001"))


# ---------------------------------------------------------------- writes (D3)


def test_a_writes_section_is_refused(refuse: Refuse, build: Build) -> None:
    error = refuse(build(writes={"max_writes": 1}))
    assert (error.code, error.location) == ("WRITES_NOT_SUPPORTED", "writes")


def test_a_write_call_without_writes_is_refused(
    refuse: Refuse, build: Build, make_call: MakeCall, surrogate: Surrogate
) -> None:
    request = (
        "<request><updateType>SUBSCRIBER_ACCOUNT_NUMBER</updateType>"
        f"<value>{surrogate('CONTRACT')}</value><newStatus>SUSPENDED</newStatus></request>"
    )
    error = refuse(build([make_call("pause", "setSubscriberAccountStatus", request)]))
    assert (error.code, error.location) == ("WRITES_NOT_SUPPORTED", "calls[0]")


def test_a_deactive_plan_reports_the_hard_block_first(
    refuse: Refuse, build: Build, make_call: MakeCall, surrogate: Surrogate
) -> None:
    request = (
        "<request><updateType>SUBSCRIBER_ACCOUNT_NUMBER</updateType>"
        f"<value>{surrogate('CONTRACT')}</value><newStatus>DEACTIVE</newStatus></request>"
    )
    text = build([make_call("x", "setSubscriberAccountStatus", request)], writes={"max_writes": 1})
    assert refuse(text).code == "ALWAYS_REFUSED_DEACTIVE"


# ---------------------------------------------------------------- references


def test_forward_and_self_references(refuse: Refuse, build: Build, make_call: MakeCall) -> None:
    item = "<request><accountNo>${item}</accountNo></request>"
    forward = [
        make_call("account", "getSubscriberAccount", item, for_each="${search.accountNumber[0:2]}"),
        make_call("search", "accountSearch", "<request/>"),
    ]
    assert refuse(build(forward)).code == "REFERENCE_FORWARD"
    selfish = [make_call("a", "getSubscriberAccount", item, for_each="${a.accountNumber[0:2]}")]
    assert refuse(build(selfish)).code == "REFERENCE_FORWARD"


def test_unknown_call(refuse: Refuse, build: Build, make_call: MakeCall) -> None:
    item = "<request><accountNo>${item}</accountNo></request>"
    calls = [make_call("a", "getSubscriberAccount", item, for_each="${zz.accountNumber[0:2]}")]
    error = refuse(build(calls))
    assert (error.code, error.location) == ("REFERENCE_UNKNOWN_CALL", "calls[0].for_each")


@pytest.mark.parametrize(
    "for_each",
    [
        "${search.accountNumber}",
        "${search.accountNumber[0:]}",
        "${search.accountNumber[:3]}",
        "${search.accountNumber[-1:3]}",
        "${Search.accountNumber[0:3]}",
        "${search.accountNumber[0:3]} ",
        "$(search.accountNumber[0:3])",
        "${search..accountNumber[0:3]}",
        "${search.account Number[0:3]}",
        "${search.accountNumber[00:3]}",
    ],
)
def test_reference_grammar(
    refuse: Refuse, build: Build, make_call: MakeCall, for_each: str
) -> None:
    calls = chained(
        make_call,
        "<request><accountNo>${item}</accountNo></request>",
        for_each,
        "getSubscriberAccount",
    )
    error = refuse(build(calls))
    assert (error.code, error.location) == ("REFERENCE_GRAMMAR", "calls[1].for_each")


@pytest.mark.parametrize(
    "for_each",
    [
        "${search.accountNumber[0:51]}",
        "${search.accountNumber[3:3]}",
        "${search.accountNumber[5:2]}",
    ],
)
def test_slices_are_bounded(
    refuse: Refuse, build: Build, make_call: MakeCall, for_each: str
) -> None:
    calls = chained(
        make_call,
        "<request><accountNo>${item}</accountNo></request>",
        for_each,
        "getSubscriberAccount",
    )
    assert refuse(build(calls, max_calls=200)).code == "REFERENCE_SLICE_INVALID"


def test_the_worst_case_of_every_slice_must_fit(
    check: Check, refuse: Refuse, build: Build, make_call: MakeCall
) -> None:
    calls = chained(
        make_call,
        "<request><accountNo>${item}</accountNo></request>",
        "${search.accountNumber[0:50]}",
        "getSubscriberAccount",
    )
    error = refuse(build(calls, max_calls=50))
    assert (error.code, error.location) == ("CALLS_OVER_MAX", "max_calls")
    assert check(build(calls, max_calls=51)).plan.expansion == 51


@pytest.mark.parametrize(
    ("field", "code"),
    [
        ("accountStatus", "REFERENCE_SOURCE_NOT_IDENTIFIER"),
        ("totalNumberOfRecords", "REFERENCE_SOURCE_NOT_IDENTIFIER"),
        ("subscriber", "REFERENCE_SOURCE_NOT_IDENTIFIER"),
        ("nothing", "REFERENCE_SOURCE_UNKNOWN"),
        ("imei", "REFERENCE_TYPE_MISMATCH"),
    ],
)
def test_the_referenced_field_must_be_a_matching_identifier(
    refuse: Refuse, build: Build, make_call: MakeCall, field: str, code: str
) -> None:
    calls = chained(
        make_call,
        "<request><accountNo>${item}</accountNo></request>",
        f"${{search.{field}[0:2]}}",
        "getSubscriberAccount",
    )
    assert refuse(build(calls)).code == code


def test_a_dotted_field_names_a_path_suffix(
    check: Check, build: Build, make_call: MakeCall
) -> None:
    calls = chained(
        make_call,
        "<request><accountNo>${item}</accountNo></request>",
        "${search.subscriber.accountNumber[0:2]}",
        "getSubscriberAccount",
    )
    assert check(build(calls))


@pytest.mark.parametrize(
    ("request_xml", "code"),
    [
        # An enum, a status and a limit are literals the CTO reviews (§8.5 #12).
        (
            "<request><filterType>${item}</filterType><filterValue>x</filterValue><limit>5</limit></request>",
            "REFERENCE_NOT_IDENTIFIER_FIELD",
        ),
        (
            "<request><filterType>ACCOUNT_NUMBER</filterType><filterValue>${item}</filterValue>"
            "<limit>5</limit><status>${item}</status></request>",
            "REFERENCE_NOT_IDENTIFIER_FIELD",
        ),
        (
            "<request><filterType>ACCOUNT_NUMBER</filterType><filterValue>${item}</filterValue>"
            "<limit>${item}</limit></request>",
            "REFERENCE_NOT_IDENTIFIER_FIELD",
        ),
        (
            "<request><filterType>ACCOUNT_NUMBER</filterType><filterValue>${item}</filterValue>"
            "<limit>5</limit><comment>${item}</comment></request>",
            "REFERENCE_NOT_IDENTIFIER_FIELD",
        ),
        # The typed field resolves by its enum; an unmapped or mismatched type is refused.
        (
            "<request><filterType>CAPCODE</filterType><filterValue>${item}</filterValue><limit>5</limit></request>",
            "REFERENCE_TYPING_UNKNOWN",
        ),
        (
            "<request><filterType>IMEI</filterType><filterValue>${item}</filterValue><limit>5</limit></request>",
            "REFERENCE_TYPE_MISMATCH",
        ),
        # ${item} is the whole text of one element, nothing else.
        (
            "<request><filterType>ACCOUNT_NUMBER</filterType><filterValue>x${item}</filterValue><limit>5</limit></request>",
            "REFERENCE_GRAMMAR",
        ),
        (
            "<request><filterType>ACCOUNT_NUMBER</filterType>"
            "<filterValue>${search.accountNumber[0:1]}</filterValue><limit>5</limit></request>",
            "REFERENCE_GRAMMAR",
        ),
        (
            "<request><filterType>ACCOUNT_NUMBER</filterType><filterValue>${item}</filterValue>"
            "<limit>5</limit><nothing>${item}</nothing></request>",
            "UNKNOWN_ELEMENT",
        ),
    ],
)
def test_references_fill_only_identifier_fields(
    refuse: Refuse, build: Build, make_call: MakeCall, request_xml: str, code: str
) -> None:
    calls = chained(make_call, request_xml, "${search.accountNumber[0:2]}", "accountSearch")
    assert refuse(build(calls)).code == code


def test_a_typed_reference_passes(check: Check, build: Build, make_call: MakeCall) -> None:
    request_xml = (
        "<request><filterType>ACCOUNT_NUMBER</filterType><filterValue>${item}</filterValue>"
        "<limit>5</limit></request>"
    )
    assert check(
        build(chained(make_call, request_xml, "${search.accountNumber[0:2]}", "accountSearch"))
    )


def test_item_needs_for_each_and_for_each_needs_item(
    refuse: Refuse, build: Build, make_call: MakeCall
) -> None:
    lonely = [
        make_call("a", "getSubscriberAccount", "<request><accountNo>${item}</accountNo></request>")
    ]
    assert refuse(build(lonely)).code == "ITEM_WITHOUT_FOR_EACH"
    calls = chained(
        make_call,
        "<request><accountNo>SUB-9000000</accountNo></request>",
        "${search.accountNumber[0:2]}",
        "getSubscriberAccount",
    )
    error = refuse(build(calls))
    assert (error.code, error.location) == ("FOR_EACH_WITHOUT_ITEM", "calls[1].for_each")


def test_a_reference_in_an_attribute_is_refused(
    refuse: Refuse, build: Build, make_call: MakeCall
) -> None:
    request_xml = '<request xmlns:x="urn:x" x:a="${item}"><accountNo>${item}</accountNo></request>'
    calls = chained(make_call, request_xml, "${search.accountNumber[0:2]}", "getSubscriberAccount")
    assert refuse(build(calls)).code == "REFERENCE_GRAMMAR"


# ---------------------------------------------------------------- identifiers (vault-free)


@pytest.mark.parametrize(
    ("value", "extra", "code", "location"),
    [
        (REAL_IMEI, "", "NOT_A_SURROGATE", "calls[0]/request/filterValue#IMEI"),
        ("99000000*", "", "WILDCARD_REFUSED", "calls[0]/request/filterValue"),
        (
            "{imei}",
            f"<comment>call {REAL_IMEI}</comment>",
            "REAL_FORMAT_VALUE",
            "calls[0]/request/comment#IMEI",
        ),
        ("{imei}", "<madeUpName>x</madeUpName>", "UNKNOWN_ELEMENT", "calls[0]/request/?"),
        (
            "{imei}",
            "<comment>a</comment><comment>b</comment>",
            "MAX_OCCURS",
            "calls[0]/request/comment",
        ),
    ],
)
def test_identifier_checks(
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
    error = refuse(build([make_call("search", "accountSearch", request_xml)]))
    assert (error.code, error.location) == (code, location)


def test_duplicate_account_numbers(
    refuse: Refuse, build: Build, make_call: MakeCall, surrogate: Surrogate
) -> None:
    contract = surrogate("CONTRACT")
    request_xml = (
        f"<request><accountNo>{contract}</accountNo><accountNo>{contract}</accountNo></request>"
    )
    error = refuse(build([make_call("a", "getSubscriberAccount", request_xml)]))
    assert (error.code, error.location) == ("MAX_OCCURS", "calls[0]/request/accountNo")


def test_xsi_type_substitution(
    refuse: Refuse, build: Build, make_call: MakeCall, surrogate: Surrogate
) -> None:
    request_xml = (
        '<request xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:t="urn:t" '
        f'xsi:type="t:otherRequestImpl"><accountNo>{surrogate("CONTRACT")}</accountNo></request>'
    )
    assert (
        refuse(build([make_call("a", "getSubscriberAccount", request_xml)])).code
        == "UNKNOWN_XSI_TYPE"
    )


def test_an_allowlisted_read_outside_the_field_map(
    refuse: Refuse, build: Build, make_call: MakeCall
) -> None:
    error = refuse(build([make_call("a", "getModels", "<request/>")]))
    assert (error.code, error.location) == ("OPERATION_NOT_IN_FIELD_MAP", "calls[0]")


# ---------------------------------------------------------------- search inputs (§5.5 step 8)


@pytest.mark.parametrize("text", ["Smith", "Annex F ST-03", "x"])
def test_free_text_in_a_read_is_refused(
    refuse: Refuse,
    build: Build,
    make_call: MakeCall,
    search: Search,
    surrogate: Surrogate,
    text: str,
) -> None:
    request_xml = search(surrogate("IMEI"), extra=f"<comment>{text}</comment>")
    error = refuse(build([make_call("search", "accountSearch", request_xml)]))
    assert (error.code, error.location) == (
        "FREE_TEXT_IN_SEARCH_INPUT",
        "calls[0]/request/comment",
    )


@pytest.mark.parametrize("comment", ["", "<comment/>", "<comment> </comment>"])
def test_an_empty_free_text_field_passes(
    check: Check,
    build: Build,
    make_call: MakeCall,
    search: Search,
    surrogate: Surrogate,
    comment: str,
) -> None:
    request_xml = search(surrogate("IMEI"), extra=comment)
    assert check(build([make_call("search", "accountSearch", request_xml)]))


XSI = 'xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"'


@pytest.mark.parametrize(
    ("msisdn", "code"),
    [
        ("<msisdn/>", "IDENTIFIER_BLANK"),
        ("<msisdn></msisdn>", "IDENTIFIER_BLANK"),
        ("<msisdn> </msisdn>", "IDENTIFIER_BLANK"),
        # The masker refuses nil on an element the map does not mark nillable.
        ('<msisdn xsi:nil="true"/>', "NIL_NOT_ALLOWED"),
    ],
)
def test_a_blank_identifier_filter_is_refused(
    refuse: Refuse, build: Build, make_call: MakeCall, msisdn: str, code: str
) -> None:
    request_xml = f"<request {XSI}>{msisdn}<limit>50</limit></request>"
    error = refuse(build([make_call("r", "getRechargeHistory", request_xml)]))
    assert (error.code, error.location) == (code, "calls[0]/request/msisdn")


@pytest.mark.parametrize(
    "field",
    [
        "<spAccount/>",
        "<spAccount> </spAccount>",  # C: an account constant
        "<ownerName/>",
        "<ownerName> </ownerName>",  # P-ONE: only ever blank, so never present
    ],
)
def test_a_blank_constant_or_personal_filter_is_refused(
    refuse: Refuse, build: Build, make_call: MakeCall, field: str
) -> None:
    error = refuse(
        build([make_call("p", "getPrepaidAccountDetail", f"<request>{field}</request>")])
    )
    name = field[1:].split(">")[0].split("/")[0]
    assert (error.code, error.location) == ("IDENTIFIER_BLANK", f"calls[0]/request/{name}")


def test_an_identifier_filter_left_out_or_given_passes(
    check: Check, build: Build, make_call: MakeCall, surrogate: Surrogate
) -> None:
    for msisdn in ("", f"<msisdn>{surrogate('MSISDN')}</msisdn>"):
        request_xml = f"<request>{msisdn}<limit>50</limit></request>"
        assert check(build([make_call("r", "getRechargeHistory", request_xml)]))
    assert check(build([make_call("p", "getPrepaidAccountDetail", "<request/>")]))


# ---------------------------------------------------------------- digest


def test_the_digest_is_stable_across_yaml_formatting(check: Check, surrogate: Surrogate) -> None:
    imei = surrogate("IMEI")
    reformatted = f"""\
# the same plan, written differently
max_calls: 4
calls:
- operation: accountSearch
  request: >-
    <request><filterType>IMEI</filterType>
    <filterValue>{imei}</filterValue><filterCond>EQUALS</filterCond>
    <limit>5</limit></request>
  endpoint: provisioning
  id: search
- {{id: account, endpoint: provisioning, operation: getSubscriberAccount,
   for_each: "${{search.accountNumber[0:3]}}", request: '<request>
    <accountNo>${{item}}</accountNo>
  </request>'}}
expires_at: "2026-11-30T00:00:00Z"
purpose: "Annex F ST-03, SBD account variants present in SITEST  "
title: 'SBD account shapes for ST-03'
id: "RP-2026-003"
"""
    assert check(reformatted).digest == check(valid(surrogate)).digest


@pytest.mark.parametrize(
    ("old", "new"),
    [
        ("<limit>5</limit>", "<limit>6</limit>"),
        ("SBD account variants", "SBD account variant"),
        ("[0:3]", "[0:2]"),
        ("max_calls: 4", "max_calls: 5"),
        ("SBD account shapes", "SBD account shape"),
        ("2026-11-30T00:00:00Z", "2026-11-30T00:00:01Z"),
    ],
)
def test_the_digest_changes_with_any_value(
    check: Check, surrogate: Surrogate, old: str, new: str
) -> None:
    text = valid(surrogate)
    assert old in text
    assert check(text.replace(old, new, 1)).digest != check(text).digest


def test_the_digest_follows_call_order(check: Check, build: Build, make_call: MakeCall) -> None:
    a = make_call("a", "getSystemStatus", "<request/>")
    b = make_call("b", "getSystemStatus", "<request/>", endpoint="reporting")
    assert check(build([a, b])).digest != check(build([b, a])).digest


def test_load_plan_needs_no_field_map(surrogate: Surrogate) -> None:
    plan = load_plan(valid(surrogate), now=NOW)
    assert [call.where for call in plan.calls] == ["calls[0]", "calls[1]"]


def test_a_typed_response_field_offers_each_of_its_types(
    check: Check, refuse: Refuse, build: Build, make_call: MakeCall
) -> None:
    by_imei = (
        "<request><filterType>IMEI</filterType><filterValue>${item}</filterValue>"
        "<limit>5</limit></request>"
    )
    assert check(build(chained(make_call, by_imei, "${search.details[0:2]}", "accountSearch")))
    by_contract = "<request><accountNo>${item}</accountNo></request>"
    calls = chained(make_call, by_contract, "${search.details[0:2]}", "getSubscriberAccount")
    assert refuse(build(calls)).code == "REFERENCE_TYPE_MISMATCH"


def test_a_label_surrogate_reference(
    check: Check, build: Build, make_call: MakeCall, surrogate: Surrogate
) -> None:
    calls = [
        make_call("vessels", "getVessels", f"<request><imo>{surrogate('IMO')}</imo></request>"),
        make_call(
            "again",
            "getVessels",
            "<request><vesselName>${item}</vesselName></request>",
            for_each="${vessels.vesselName[0:5]}",
        ),
    ]
    assert check(build(calls)).plan.expansion == 6
