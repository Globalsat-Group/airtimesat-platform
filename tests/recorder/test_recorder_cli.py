"""``recorder check`` on the command line: output, exit codes, no plan value ever printed."""

import ast
import io
import os
import re
import secrets
import string
import subprocess
import sys
import threading
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Final

import pytest
import yaml

from airtimesat_platform.masker import xmlsafe
from airtimesat_platform.masker.logsafe import safe_excepthook
from airtimesat_platform.masker.tokenize.surrogates import SPECS
from airtimesat_platform.recorder import __main__ as cli
from airtimesat_platform.recorder.__main__ import main, packaged_field_map

Build = Callable[..., str]
MakeCall = Callable[..., dict[str, object]]
Search = Callable[..., str]
Surrogate = Callable[..., str]

NOW = datetime(2026, 10, 21, 12, 0, tzinfo=UTC)
# Built at run time: a real-format IMEI shape and an Iridium host suffix.
REAL_IMEI = "35" + "0" * 12 + "7"
IRIDIUM = "iridium" + ".com"
# A plan value that must never reach the output. Random, so no literal can match it; letters
# only, so it trips no detector by itself.
SENTINEL = "Snt" + "".join(secrets.choice(string.ascii_letters) for _ in range(16))


@pytest.fixture(autouse=True)
def restore_hooks(monkeypatch: pytest.MonkeyPatch) -> None:
    """Put the test runner's exception hooks back after ``main`` installs the safe ones."""
    monkeypatch.setattr(sys, "excepthook", sys.excepthook)
    monkeypatch.setattr(sys, "unraisablehook", sys.unraisablehook)
    monkeypatch.setattr(threading, "excepthook", threading.excepthook)


@pytest.fixture(name="run")
def run_fixture(
    texts: tuple[str, str], tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> Callable[..., tuple[int, str]]:
    """Write plan texts to files, run ``recorder check`` on them, return the code and output.

    The plans are named relative to ``tmp_path``, so the output does not depend on where the
    temporary directory is (a macOS one has segments that ``_shown_path`` hides).
    """
    monkeypatch.chdir(tmp_path)

    def run(*plans: str | bytes, field_map: bool = True) -> tuple[int, str]:
        paths: list[str] = []
        for n, plan in enumerate(plans):
            path = tmp_path / f"plan-{n}.yaml"
            if isinstance(plan, bytes):
                path.write_bytes(plan)
            else:
                path.write_text(plan, encoding="utf-8")
            paths.append(path.name)
        out = io.StringIO()
        code = main(
            ["check", *paths],
            out=out,
            now=lambda: NOW,
            field_map_source=(lambda: texts) if field_map else (lambda: None),
        )
        return code, out.getvalue()

    return run


Run = Callable[..., tuple[int, str]]


# ---------------------------------------------------------------- output and exit codes


def test_valid_plans_exit_zero(run: Run, build: Build) -> None:
    code, out = run(build(), build(id="RP-2026-004"))
    lines = out.splitlines()
    assert code == 0
    assert [line.split()[:2] for line in lines] == [["OK", "RP-2026-003"], ["OK", "RP-2026-004"]]
    assert all(len(line.split()[2]) == 64 for line in lines)


def test_one_refused_plan_exits_one_and_every_plan_gets_a_line(run: Run, build: Build) -> None:
    code, out = run(build(), build(id="bad"), build())
    assert code == 1
    first, second, third = out.splitlines()
    assert first.startswith("OK RP-2026-003 ")
    assert second.startswith("REFUSED ")
    assert second.endswith(" PLAN_ID_INVALID id")
    assert third.startswith("OK RP-2026-003 ")


def test_the_refusal_line_format(run: Run) -> None:
    code, out = run("id: a\nid: b\n")
    assert code == 1
    assert out == "REFUSED plan-0.yaml YAML_DUPLICATE_KEY line:2\n"


@pytest.mark.parametrize(
    "argv",
    [
        [],
        ["check"],
        ["run"],
        ["keys"],
        ["incident", "clear"],
        ["incident", "clear", "x"],
        ["inventory", "add"],
        ["--verbose"],
    ],
)
def test_usage_errors_exit_two(argv: list[str], capsys: pytest.CaptureFixture[str]) -> None:
    assert main(argv, field_map_source=lambda: None) == 2
    assert capsys.readouterr().out == ""


def test_help_exits_zero(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["check", "--help"]) == 0
    assert "Exit 0" in capsys.readouterr().out


def test_without_the_generated_field_map_every_plan_fails_closed(run: Run, build: Build) -> None:
    code, out = run(build(), field_map=False)
    assert (code, out.split()[2]) == (1, "FIELD_MAP_MISSING")
    assert packaged_field_map() is None


@pytest.mark.parametrize(
    ("generated", "overrides"),
    [
        ("x", "y"),
        # Valid YAML, but a 15-digit IMEI surrogate cannot fit an xsd:int element.
        (
            "format: airtimesat-fieldmap/1\npaths:\n"
            "  - {operation: getVessel, direction: request, path: request, xsd_type: complex}\n"
            "  - {operation: getVessel, direction: request, path: request/id, xsd_type: int}\n",
            "format: airtimesat-overrides/1\nentries:\n"
            "  - {operation: getVessel, direction: request, path: request, treatment: KEEP}\n"
            "  - {operation: getVessel, direction: request, path: request/id, treatment: T-NUM,"
            " type: IMEI}\n",
        ),
    ],
)
def test_an_invalid_field_map_refuses_every_plan(
    build: Build, tmp_path: Path, generated: str, overrides: str
) -> None:
    path = tmp_path / "plan.yaml"
    path.write_text(build(), encoding="utf-8")
    out = io.StringIO()
    code = main(
        ["check", str(path)],
        out=out,
        now=lambda: NOW,
        field_map_source=lambda: (generated, overrides),
    )
    assert (code, out.getvalue().split()[2]) == (1, "FIELD_MAP_INVALID")


@pytest.mark.parametrize(
    ("content", "code"),
    [
        (b"id: \xff\xfe\n", "PLAN_NOT_UTF8"),
        (b"title: " + b"x" * (256 * 1024), "PLAN_TOO_LARGE"),
    ],
)
def test_unreadable_plans(run: Run, content: bytes, code: str) -> None:
    status, out = run(content)
    assert (status, out.split()[2]) == (1, code)


def test_a_missing_file(tmp_path: Path) -> None:
    out = io.StringIO()
    code = main(["check", str(tmp_path / "absent.yaml")], out=out, field_map_source=lambda: None)
    assert (code, out.getvalue().split()[2]) == (1, "PLAN_UNREADABLE")


def test_a_plan_must_be_a_regular_file(
    texts: tuple[str, str], tmp_path: Path, monkeypatch: pytest.MonkeyPatch, build: Build
) -> None:
    monkeypatch.chdir(tmp_path)
    Path("target.yaml").write_text(build(), encoding="utf-8")
    Path("link.yaml").symlink_to("target.yaml")
    Path("folder.yaml").mkdir()
    names = ["link.yaml", "folder.yaml"]
    if hasattr(os, "mkfifo"):
        # A FIFO with no writer would block a plain read forever.
        os.mkfifo("fifo.yaml")
        names.append("fifo.yaml")
    out = io.StringIO()
    code = main(["check", *names], out=out, now=lambda: NOW, field_map_source=lambda: texts)
    assert code == 1
    assert out.getvalue() == "".join(f"REFUSED {name} PLAN_NOT_REGULAR_FILE\n" for name in names)
    # The target itself is a valid plan.
    assert (
        main(
            ["check", "target.yaml"],
            out=io.StringIO(),
            now=lambda: NOW,
            field_map_source=lambda: texts,
        )
        == 0
    )


def test_a_path_segment_that_could_carry_data_is_hidden(tmp_path: Path, build: Build) -> None:
    digits = "4" * 15
    folder = tmp_path / digits
    folder.mkdir()
    (folder / "plan.yaml").write_text(build(), encoding="utf-8")
    out = io.StringIO()
    main(
        ["check", str(folder / "plan.yaml")],
        out=out,
        now=lambda: NOW,
        field_map_source=lambda: None,
    )
    assert digits not in out.getvalue()
    assert "/?/plan.yaml FIELD_MAP_MISSING" in out.getvalue()


def test_the_safe_exception_hook_is_installed() -> None:
    main(["check", "--help"])
    assert sys.excepthook is safe_excepthook


def test_an_unexpected_error_refuses_the_plan_quietly(
    run: Run, build: Build, monkeypatch: pytest.MonkeyPatch
) -> None:
    def explode(*_: object, **__: object) -> None:
        raise ValueError(SENTINEL)

    monkeypatch.setattr(cli, "check_plan", explode)
    code, out = run(build())
    assert (code, out.split()[2]) == (1, "CHECK_FAILED")
    assert SENTINEL not in out


# ---------------------------------------------------------------- no plan value in the output


def plan(calls: list[dict[str, object]] | None = None, **top: object) -> str:
    doc: dict[str, object] = {
        "id": "RP-2026-003",
        "title": f"Sentinel {SENTINEL}",
        "purpose": f"Purpose {SENTINEL}",
        "expires_at": "2026-11-30T00:00:00Z",
        "max_calls": 10,
        "calls": calls or [],
    } | top
    return yaml.safe_dump(doc, sort_keys=False, allow_unicode=True, width=1000)


def one(operation: str, request: str, **extra: object) -> list[dict[str, object]]:
    return [
        {"id": "a", "endpoint": "provisioning", "operation": operation, "request": request} | extra
    ]


def searching(
    value: str, *, filter_type: str = "IMEI", cond: str = "EQUALS", extra: str = ""
) -> str:
    return (
        f"<request><filterType>{filter_type}</filterType><filterValue>{value}</filterValue>"
        f"<filterCond>{cond}</filterCond><limit>5</limit>{extra}</request>"
    )


def chain(
    for_each: str, request: str, operation: str = "getSubscriberAccount"
) -> list[dict[str, object]]:
    return [
        {
            "id": "search",
            "endpoint": "provisioning",
            "operation": "accountSearch",
            "request": searching(IMEI),
        },
        {
            "id": "next",
            "endpoint": "provisioning",
            "operation": operation,
            "request": request,
            "for_each": for_each,
        },
    ]


def calls(*requests: tuple[str, str]) -> list[dict[str, object]]:
    return [
        {"id": f"c{n}", "endpoint": "provisioning", "operation": operation, "request": request}
        for n, (operation, request) in enumerate(requests)
    ]


IMEI = SPECS["IMEI"].render(bytes(32), "")
IMO = SPECS["IMO"].render(bytes(32), "")
CONTRACT = SPECS["CONTRACT"].render(bytes(32), "")
S = SENTINEL
LOW = SENTINEL.lower()
STATUS = "<request><updateType>SUBSCRIBER_ACCOUNT_NUMBER</updateType><value>SUB-9000000</value>"
XSI = 'xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:t="urn:t"'
IWS_LOG = "<request><Limit>5</Limit>{dates}<iwsOperation>{S}</iwsOperation></request>"

CASES: list[tuple[str | bytes, str]] = [
    (f"id: {S}\nid: {S}\n", "YAML_DUPLICATE_KEY"),
    (f"id: [{S}\n", "YAML_SYNTAX"),
    (f"id: &{S} x\n", "YAML_ANCHOR"),
    (f"id: *{S}\n", "YAML_ALIAS"),
    (f"id: !{S} x\n", "YAML_TAG"),
    (f"<<: {{{S}: 1}}\n", "YAML_MERGE_KEY"),
    (f"title: {S}\n1: {S}\n", "YAML_NON_STRING_KEY"),
    (f"title: {S}\n".encode() + b"\xff", "PLAN_NOT_UTF8"),
    (plan(title=f"{S}.{IRIDIUM}"), "IRIDIUM_HOST_IN_PLAN"),
    (plan(one("accountSearch", searching(f"{S}.iridium&#46;com"))), "IRIDIUM_HOST_IN_PLAN"),
    (
        plan(one("setSubscriberAccountStatus", f"{STATUS}<newStatus>{S}</newStatus></request>")),
        "ALWAYS_REFUSED_DEACTIVE",
    ),
    (
        plan(
            one(
                "setSubscriberAccountStatus",
                f"{STATUS}<newStatus>DEACTIVE</newStatus><x>{S}</x></request>",
            )
        ),
        "ALWAYS_REFUSED_DEACTIVE",
    ),
    (
        plan(one("activateSubscriber", f"<request><bulkAction>{S}</bulkAction></request>")),
        "ALWAYS_REFUSED_BULK",
    ),
    (plan(one("createOnDemandReport", f"<request><x>{S}</x></request>")), "ALWAYS_REFUSED_METHOD"),
    (plan(one("manageDestinations", f"<request><x>{S}</x></request>")), "ALWAYS_REFUSED_SP_WIDE"),
    (plan(one(S, "<request/>")), "OPERATION_UNKNOWN"),
    (plan(one("AccountSearch", f"<request><x>{S}</x></request>")), "OPERATION_WRONG_CASE"),
    (plan(one("getReportTypes", f"<request><x>{S}</x></request>")), "OPERATION_ENDPOINT_MISMATCH"),
    (
        plan([{"id": "a", "endpoint": S, "operation": "accountSearch", "request": "<request/>"}]),
        "ENDPOINT_INVALID",
    ),
    (plan(one("accountSearch", "<request/>", action=S)), "SOAP_ACTION_IN_PLAN"),
    (plan(one("accountSearch", f"<{S}><request/></{S}>")), "REQUEST_ROOT_INVALID"),
    (plan(one("accountSearch", f"<request/><{S}/>")), "TWO_OPERATIONS_IN_BODY"),
    (plan(one("accountSearch", f'<request xmlns="urn:{S}"/>')), "ELEMENT_NAMESPACE_REFUSED"),
    (
        plan(
            one(
                "accountSearch",
                f'<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"><s:Body><{S}/></s:Body></s:Envelope>',
            )
        ),
        "SOAP_ENVELOPE_IN_PLAN",
    ),
    (
        plan(one("accountSearch", f"<request><caller>{S}</caller></request>")),
        "AUTH_FIELD_IN_REQUEST",
    ),
    (plan(one("accountSearch", f"<request>{S}")), "XML_PARSE"),
    (plan(one("accountSearch", f"<request><!--{S}--></request>")), "XML_COMMENT"),
    (plan(one("accountSearch", "<request/>"), writes={S: S}), "WRITES_NOT_SUPPORTED"),
    (plan(one("accountSearch", "<request/>"), **{S: S}), "SCHEMA_UNKNOWN_KEY"),
    (
        plan(
            [
                {
                    "id": "a",
                    "endpoint": "provisioning",
                    "operation": "accountSearch",
                    "request": "<request/>",
                    S: S,
                }
            ]
        ),
        "SCHEMA_UNKNOWN_KEY",
    ),
    (plan(one("accountSearch", "<request/>"), id=S), "PLAN_ID_INVALID"),
    (
        plan(
            [
                {
                    "id": S,
                    "endpoint": "provisioning",
                    "operation": "getSystemStatus",
                    "request": "<request/>",
                }
            ]
        ),
        "CALL_ID_INVALID",
    ),
    (plan(one("getSystemStatus", "<request/>"), title=S * 20), "TEXT_TOO_LONG"),
    (plan(one("getSystemStatus", "<request/>"), purpose=f"{S} {REAL_IMEI}"), "REAL_FORMAT_VALUE"),
    (plan(one("getSystemStatus", "<request/>"), expires_at=S), "EXPIRES_AT_INVALID"),
    (
        plan(one("getSystemStatus", "<request/>"), expires_at="2026-01-01T00:00:00Z"),
        "EXPIRES_AT_PAST",
    ),
    (plan(one("getSystemStatus", "<request/>"), max_calls=S), "SCHEMA_WRONG_TYPE"),
    (
        plan(chain("${" + S, "<request><accountNo>${item}</accountNo></request>")),
        "REFERENCE_GRAMMAR",
    ),
    (
        plan(
            chain(
                f"${{{LOW}.accountNumber[0:2]}}",
                "<request><accountNo>${item}</accountNo></request>",
            )
        ),
        "REFERENCE_UNKNOWN_CALL",
    ),
    (
        plan(chain(f"${{search.{S}[0:2]}}", "<request><accountNo>${item}</accountNo></request>")),
        "REFERENCE_SOURCE_UNKNOWN",
    ),
    (
        plan(
            chain("${search.accountNumber[0:2]}", f"<request><accountNo>{S}</accountNo></request>")
        ),
        "FOR_EACH_WITHOUT_ITEM",
    ),
    (
        plan(one("getEVoucherInventory", f"<request><limit>{S}</limit></request>")),
        "LIMIT_NOT_AN_INTEGER",
    ),
    (
        plan(one("getEVoucherInventory", "<request><limit>999</limit></request>")),
        "LIMIT_OUT_OF_RANGE",
    ),
    (
        plan(one("getVessels", f"<request><vesselName>{S}</vesselName></request>")),
        "SEARCH_INPUT_NOT_A_SURROGATE",
    ),
    (
        plan(one("getVessels", f"<request><imo>{IMO}</imo><callSign>{S}</callSign></request>")),
        "SEARCH_INPUT_REFUSED",
    ),
    (
        plan(one("getQueueEntries", f"<request><createdBy>{S}</createdBy></request>")),
        "SET_BY_RECORDER",
    ),
    (plan(one("accountSearch", searching(IMEI, cond=S))), "FILTER_COND_REFUSED"),
    (plan(one("accountSearch", searching(S))), "NOT_A_SURROGATE"),
    (plan(one("accountSearch", searching(S + "*"))), "WILDCARD_REFUSED"),
    (plan(one("accountSearch", searching(IMEI, filter_type=S))), "TYPING_UNKNOWN"),
    (
        plan(one("accountSearch", searching(IMEI, extra=f"<comment>{S} {REAL_IMEI}</comment>"))),
        "REAL_FORMAT_VALUE",
    ),
    (plan(one("accountSearch", searching(IMEI, extra=f"<{S}>x</{S}>"))), "UNKNOWN_ELEMENT"),
    (
        plan(
            one(
                "accountSearch",
                searching(IMEI, extra=f"<comment>{S}</comment><comment>{S}</comment>"),
            )
        ),
        "MAX_OCCURS",
    ),
    (
        plan(one("accountSearch", searching(IMEI, extra=f'<comment a="{S}">x</comment>'))),
        "UNKNOWN_ATTRIBUTE",
    ),
    # Strict YAML, escapes and the schema
    (f'title: "{S}\\x41"\n', "YAML_ESCAPE"),
    (f"- {S}\n", "SCHEMA_NOT_MAPPING"),
    (yaml.safe_dump({"id": "RP-2026-003", "title": S}), "SCHEMA_MISSING_KEY"),
    (plan(one("getSystemStatus", "<request/>"), title=" "), "TEXT_EMPTY"),
    (plan(one("getSystemStatus", "<request/>"), title=f"{S}\u00a0x"), "TEXT_NOT_PLAIN"),
    (
        plan(one("getSystemStatus", "<request/>"), expires_at="2026-11-30T00:00:00+00:00"),
        "EXPIRES_AT_NOT_UTC",
    ),
    (plan(one("getSystemStatus", "<request/>"), max_calls=0), "MAX_CALLS_OUT_OF_RANGE"),
    (plan([]), "CALLS_EMPTY"),
    (
        plan(
            calls(("getSystemStatus", "<request/>"), ("getSystemStatus", "<request/>")), max_calls=1
        ),
        "CALLS_OVER_MAX",
    ),
    (
        plan(
            [
                {
                    "id": LOW,
                    "endpoint": "provisioning",
                    "operation": "getSystemStatus",
                    "request": "<request/>",
                }
                for _ in range(2)
            ]
        ),
        "CALL_ID_DUPLICATE",
    ),
    (plan(one("getSystemStatus", " ")), "REQUEST_EMPTY"),
    (
        plan(one("getSystemStatus", f"<request><x>{S}</x>{' ' * (64 * 1024)}</request>")),
        "REQUEST_TOO_LARGE",
    ),
    # Request shape
    (plan(one("accountSearch", f"<request><?{LOW} x?></request>")), "XML_PI"),
    (plan(one("accountSearch", f"{S}<request/>")), "REQUEST_TEXT_OUTSIDE_ELEMENT"),
    (plan(one("accountSearch", f"<getVessels><x>{S}</x></getVessels>")), "OPERATION_ROOT_MISMATCH"),
    # Limits and windows
    (
        plan(one("getEVoucherInventory", f"<request><Limit>5</Limit><x>{S}</x></request>")),
        "ELEMENT_NAME_CASE",
    ),
    (
        plan(one("getEVoucherInventory", f"<request><limit>5</limit><limit>{S}</limit></request>")),
        "LIMIT_DUPLICATE",
    ),
    (plan(one("getEVoucherInventory", f"<request><x>{S}</x></request>")), "LIMIT_MISSING"),
    (plan(one("getIwsRequests", IWS_LOG.format(dates="", S=S))), "WINDOW_MISSING"),
    (
        plan(
            one(
                "getIwsRequests",
                IWS_LOG.format(dates=f"<startDate>{S}</startDate><endDate>{S}</endDate>", S=S),
            )
        ),
        "WINDOW_INVALID",
    ),
    (
        plan(
            one(
                "getIwsRequests",
                IWS_LOG.format(
                    dates="<startDate>2026-10-01T00:00:00Z</startDate>"
                    "<endDate>2026-10-03T00:00:00Z</endDate>",
                    S=S,
                ),
            )
        ),
        "WINDOW_TOO_LONG",
    ),
    (
        plan(
            one(
                "accountSearch",
                f"<request><filterType>IMEI</filterType><limit>5</limit><status>{S}</status></request>",
            )
        ),
        "SEARCH_INPUT_REQUIRED",
    ),
    # References
    (
        plan(
            one(
                "getSubscriberAccount",
                f"<request><accountNo>${{item}}</accountNo><x>{S}</x></request>",
            )
        ),
        "ITEM_WITHOUT_FOR_EACH",
    ),
    (
        plan(
            list(
                reversed(
                    chain(
                        "${search.accountNumber[0:2]}",
                        "<request><accountNo>${item}</accountNo></request>",
                    )
                )
            )
        ),
        "REFERENCE_FORWARD",
    ),
    (
        plan(
            chain(
                "${search.accountNumber[5:2]}", "<request><accountNo>${item}</accountNo></request>"
            )
        ),
        "REFERENCE_SLICE_INVALID",
    ),
    (
        plan(
            chain(
                "${search.accountStatus[0:2]}", "<request><accountNo>${item}</accountNo></request>"
            )
        ),
        "REFERENCE_SOURCE_NOT_IDENTIFIER",
    ),
    (
        plan(chain("${search.imei[0:2]}", "<request><accountNo>${item}</accountNo></request>")),
        "REFERENCE_TYPE_MISMATCH",
    ),
    (
        plan(
            chain(
                "${search.accountNumber[0:2]}",
                f"<request><filterType>{S}</filterType><filterValue>${{item}}</filterValue>"
                "<limit>5</limit></request>",
                "accountSearch",
            )
        ),
        "REFERENCE_TYPING_UNKNOWN",
    ),
    (
        plan(
            chain(
                "${search.accountNumber[0:2]}",
                "<request><filterType>ACCOUNT_NUMBER</filterType><filterValue>${item}</filterValue>"
                f"<limit>5</limit><status>{S}</status><comment>${{item}}</comment></request>",
                "accountSearch",
            )
        ),
        "REFERENCE_NOT_IDENTIFIER_FIELD",
    ),
    # Element paths built from plan-controlled names and xsi:type values (_target_kind)
    (
        plan(
            chain(
                "${search.accountNumber[0:2]}",
                f'<request {XSI} xsi:type="t:{S}"><accountNo>${{item}}</accountNo></request>',
            )
        ),
        "UNKNOWN_ELEMENT",
    ),
    (
        plan(
            chain(
                "${search.accountNumber[0:2]}",
                f'<request {XSI}><accountNo xsi:type="t:{S}">${{item}}</accountNo></request>',
            )
        ),
        "UNKNOWN_ELEMENT",
    ),
    (
        plan(
            chain(
                "${search.accountNumber[0:2]}",
                f"<request><{S}>${{item}}</{S}></request>",
            )
        ),
        "UNKNOWN_ELEMENT",
    ),
    (
        plan(
            one(
                "getSubscriberAccount",
                f'<request {XSI}><accountNo xsi:type="t:{S}">{CONTRACT}</accountNo></request>',
            )
        ),
        "UNKNOWN_XSI_TYPE",
    ),
    # Search inputs of a read
    (
        plan(one("accountSearch", searching(IMEI, extra=f"<comment>{S}</comment>"))),
        "FREE_TEXT_IN_SEARCH_INPUT",
    ),
    (
        plan(one("getRechargeHistory", "<request><msisdn> </msisdn><limit>5</limit></request>")),
        "IDENTIFIER_BLANK",
    ),
    # Codes from named constants and allowlist rules
    (
        plan(
            one(
                "accountSearch",
                searching(IMEI, filter_type="SMART", extra=f"<comment>{S}</comment>"),
            )
        ),
        "FILTER_SMART_REFUSED",
    ),
    # Codes passed through from the masker's request parse and check
    (plan(one("accountSearch", searching(IMEI, extra=S))), "MIXED_CONTENT"),
    (
        plan(one("accountSearch", searching(IMEI, extra=f"<comment><x>{S}</x></comment>"))),
        "UNEXPECTED_CHILDREN",
    ),
    (
        plan(one("accountSearch", searching(IMEI, extra=f"<comment><![CDATA[{S}]]></comment>"))),
        "XML_CDATA",
    ),
    (plan(one("accountSearch", f"<!DOCTYPE {S}>" + searching(IMEI))), "XML_DTD"),
    (
        plan(one("accountSearch", searching(IMEI, extra=f"<comment>\x00{S}</comment>"))),
        "XML_ENCODING",
    ),
    (
        plan(
            one(
                "accountSearch",
                searching(IMEI, extra=f"<comment>{'<a>' * 70}{S}{'</a>' * 70}</comment>"),
            )
        ),
        "XML_TOO_DEEP",
    ),
    (
        plan(
            one(
                "getRechargeHistory",
                f'<request {XSI}><msisdn xsi:nil="{S}"/><limit>5</limit></request>',
            )
        ),
        "XSI_NIL_INVALID",
    ),
    (
        plan(
            one(
                "getRechargeHistory",
                f'<request {XSI}><msisdn xsi:type="{S}:{S}:x">1</msisdn><limit>5</limit></request>',
            )
        ),
        "XSI_TYPE_INVALID",
    ),
    (
        plan(
            one(
                "getRechargeHistory",
                f'<request {XSI}><msisdn xsi:nil="true"/><limit>5</limit><x>{S}</x></request>',
            )
        ),
        "NIL_NOT_ALLOWED",
    ),
    (
        plan(one("getPrepaidAccountDetail", f"<request><spAccount>{S}</spAccount></request>")),
        "CONSTANT_UNKNOWN",
    ),
    (
        plan(one("getPrepaidAccountDetail", f"<request><ownerName>{S}</ownerName></request>")),
        "NOT_REVERSIBLE",
    ),
    (
        plan(one("getPrepaidAccountDetail", f"<request><note>{S}</note></request>")),
        "UNCLASSIFIED_ELEMENT",
    ),
    (plan(one("getModels", f"<request><x>{S}</x></request>")), "OPERATION_NOT_IN_FIELD_MAP"),
]

# Refusals about the file itself rather than its text; see test_file_refusals_print_no_value.
FILE_CASES: Final = frozenset({"PLAN_NOT_REGULAR_FILE", "PLAN_TOO_LARGE", "PLAN_UNREADABLE"})
# Refusal codes no plan can reach today, each with the reason. A new code must be added to
# CASES (or here, with its reason), so every refusal path runs with the sentinel.
UNREACHABLE: Final = {
    # A read on its own endpoint passes the hard blocks, and any other known method is a
    # write (WRITES_NOT_SUPPORTED) or refused by name first.
    "OPERATION_NOT_ALLOWLISTED": "the hard blocks refuse every such operation first",
    # The CLI decodes strict UTF-8 and escapes are refused, so no lone surrogate reaches a
    # request.
    "REQUEST_NOT_UTF8": "no lone surrogate can reach a request",
    # Masker codes that the request check cannot raise.
    "D_NEEDS_SENTINEL": "D is applied to responses only; a D request field is NOT_REVERSIBLE",
    "D_ON_ROOT": "D is applied to responses only; a D request field is NOT_REVERSIBLE",
    "MASKING_TIMEOUT": "a request within MAX_REQUEST_BYTES is walked well inside the budget",
    "OPERATION_NOT_ALLOWED": "raised by start_call, which recorder check never calls",
    "VAULT_UNAVAILABLE": "raised by unmask_request, which recorder check never calls",
    "XML_ENTITY": "no DTD can declare an entity (XML_DTD), so an entity is XML_PARSE",
    "XML_NODE": "the hard blocks parse the request inside a wrapper, so it has no siblings",
    "XML_TOO_LARGE": "REQUEST_TOO_LARGE refuses a request over MAX_REQUEST_BYTES first",
    "YAML_TOO_LARGE": "PLAN_TOO_LARGE refuses a plan over MAX_PLAN_BYTES first",
}


@pytest.mark.parametrize(("text", "code"), CASES, ids=[code for _, code in CASES])
def test_no_plan_value_reaches_the_output(
    run: Run, capsys: pytest.CaptureFixture[str], text: str | bytes, code: str
) -> None:
    status, out = run(text)
    captured = capsys.readouterr()
    assert status == 1
    assert out.split()[2] == code
    for printed in (out, captured.out, captured.err):
        assert SENTINEL not in printed
        assert LOW not in printed.lower()
        assert REAL_IMEI not in printed


_CODE: Final = re.compile(r"[A-Z][A-Z0-9_]+")


def _callee(node: ast.Call) -> str:
    func = node.func
    return func.id if isinstance(func, ast.Name) else getattr(func, "attr", "")


def _code(node: ast.AST) -> str | None:
    value: object = node.value if isinstance(node, ast.Constant) else None
    return value if isinstance(value, str) and _CODE.fullmatch(value) else None


def _refusal_codes() -> set[str]:
    """Return every refusal code a plan could meet, as written in the source.

    In the recorder: the literals in a ``PlanRefusedError(...)``, the module-level code
    constants (``DEACTIVE`` and the like) and each ``EnumRule``'s code. In the masker's
    request parse and check, which the recorder passes through: the literal codes given to
    ``error(...)``, ``walk.error(...)``, ``RequestRefusedError(...)`` and ``RequestRefusal``;
    and in the strict YAML loader, which ``load_plan`` passes through, ``StrictYamlError(...)``.
    """
    codes: set[str] = set()
    for source in Path(cli.__file__).parent.rglob("*.py"):
        for node in ast.walk(ast.parse(source.read_text(encoding="utf-8"))):
            if isinstance(node, ast.Call) and _callee(node) == "PlanRefusedError" and node.args:
                codes |= {c for n in ast.walk(node.args[0]) if (c := _code(n))}
            elif isinstance(node, ast.Call) and _callee(node) == "EnumRule" and len(node.args) > 1:
                codes |= {c for c in [_code(node.args[1])] if c}
            elif isinstance(node, ast.AnnAssign) and node.value is not None:
                codes |= {c for c in [_code(node.value)] if c}
    masker = Path(xmlsafe.__file__).parent
    request_side = {"error", "RequestRefusedError", "RequestRefusal", "StrictYamlError"}
    for source in (
        masker / "xmlsafe.py",
        masker / "engine.py",
        masker / "fieldmap" / "strict_yaml.py",
    ):
        for node in ast.walk(ast.parse(source.read_text(encoding="utf-8"))):
            if isinstance(node, ast.Call) and _callee(node) in request_side and node.args:
                codes |= {c for c in [_code(node.args[0])] if c}
    return codes


def test_the_sentinel_cases_cover_every_refusal_path() -> None:
    codes = _refusal_codes()
    assert len(codes) > 80
    assert {"ALWAYS_REFUSED_DEACTIVE", "FILTER_COND_REFUSED", "XML_CDATA"} <= codes
    covered = {code for _, code in CASES} | FILE_CASES
    assert codes - covered == set(UNREACHABLE)
    assert SPECS["IMEI"].is_surrogate_shape(IMEI)
    assert SPECS["IMO"].is_surrogate_shape(IMO)


def test_file_refusals_print_no_value(
    texts: tuple[str, str],
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.chdir(tmp_path)
    Path("target.yaml").write_text(plan(one("getSystemStatus", "<request/>")), encoding="utf-8")
    Path("link.yaml").symlink_to("target.yaml")
    Path("large.yaml").write_text(f"title: {S}\n" * 20000, encoding="utf-8")
    out = io.StringIO()
    status = main(
        ["check", "link.yaml", "large.yaml", "absent.yaml"],
        out=out,
        now=lambda: NOW,
        field_map_source=lambda: texts,
    )
    assert status == 1
    assert [line.split()[2] for line in out.getvalue().splitlines()] == [
        "PLAN_NOT_REGULAR_FILE",
        "PLAN_TOO_LARGE",
        "PLAN_UNREADABLE",
    ]
    captured = capsys.readouterr()
    for printed in (out.getvalue(), captured.out, captured.err):
        assert SENTINEL not in printed


def test_no_plan_value_reaches_the_output_without_a_field_map(
    run: Run, capsys: pytest.CaptureFixture[str]
) -> None:
    status, out = run(plan(one("getSystemStatus", "<request/>")), field_map=False)
    assert (status, out.split()[2]) == (1, "FIELD_MAP_MISSING")
    assert SENTINEL not in out + capsys.readouterr().err


# ---------------------------------------------------------------- the real entry point


def test_python_dash_m(tmp_path: Path, build: Build) -> None:
    # The subprocess reads the real clock, so the plan expires a month from now.
    expires = (datetime.now(UTC) + timedelta(days=30)).strftime("%Y-%m-%dT%H:%M:%SZ")
    (tmp_path / "plan.yaml").write_text(build(expires_at=expires), encoding="utf-8")
    command = [sys.executable, "-m", "airtimesat_platform.recorder"]
    # A fixed program and arguments built by this test.
    checked = subprocess.run(  # noqa: S603
        [*command, "check", "plan.yaml"],
        capture_output=True,
        text=True,
        check=False,
        cwd=tmp_path,
    )
    assert checked.returncode == 1
    assert checked.stdout == "REFUSED plan.yaml FIELD_MAP_MISSING\n"
    assert checked.stderr == ""
    usage = subprocess.run(command, capture_output=True, text=True, check=False)  # noqa: S603 - as above
    assert usage.returncode == 2
    assert usage.stdout == ""
