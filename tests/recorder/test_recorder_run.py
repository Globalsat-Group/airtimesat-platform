"""``recorder run`` against a fake SITEST port (design §5.1, §5.3, §5.5, §8.4, §8.5).

Real-format values are canaries built at run time; plans name reserved-prefix surrogates
the test issues first, as an earlier recording would have.
"""

import base64
import json
import shutil
import signal
import sqlite3
import subprocess
from collections.abc import Callable
from datetime import timedelta
from pathlib import Path
from typing import Any

import pytest

from airtimesat_platform.gateway.sitest_port import TransportTimeoutError
from airtimesat_platform.masker.detect.canary import canary
from airtimesat_platform.masker.engine import MaskingEngine
from airtimesat_platform.masker.errors import VaultError
from airtimesat_platform.masker.tokenize.surrogates import SPECS
from airtimesat_platform.recorder import run as run_module
from airtimesat_platform.recorder.output import Staging, tool_scan
from airtimesat_platform.recorder.store import Incident, LogRow, SqliteStore, open_store, utc_text

Harness = Any  # tests/conftest.py's Harness (test modules cannot import conftest)


def answer(h: Harness, operation: str, reply: Callable[[str], bytes | BaseException]) -> None:
    """Set the fake port's reply to ``operation``."""
    h.port.replies[operation] = reply


SEARCH = (
    "<request><filterType>IMEI</filterType><filterValue>{imei}</filterValue>"
    "<filterCond>EQUALS</filterCond><limit>5</limit></request>"
)
ACCOUNT = "<request><accountNo>${item}</accountNo></request>"
LOG = (
    "<request><iwsOperation>accountSearch</iwsOperation><startDate>2026-10-21T00:00:00Z"
    "</startDate><endDate>2026-10-21T10:00:00Z</endDate><limit>10</limit></request>"
)
NS = 'xmlns:ns="urn:example:iws"'
IMEI = canary("IMEI", 61)
CONTRACTS = [canary("CONTRACT", 61 + n) for n in range(3)]


def two_call_plan(h: Harness, *, push: bool = True) -> Path:
    surrogate = h.issue("IMEI", IMEI)
    return h.plan(
        h.plan_yaml(
            h.plan_call("search", "accountSearch", SEARCH.format(imei=surrogate)),
            h.plan_call("account", "getSubscriberAccount", ACCOUNT, "search.accountNumber[0:3]"),
        ),
        push=push,
    )


def answer_reads(h: Harness) -> None:
    rows = [(c, IMEI) for c in CONTRACTS[:2]]
    answer(h, "accountSearch", lambda _: h.search_reply(*rows))

    def account(request: str) -> bytes:
        contract = next(c for c in CONTRACTS if c in request)
        return h.account_reply(contract, IMEI)

    h.port.replies["getSubscriberAccount"] = account


def codes(out: str) -> list[str]:
    return [line.split()[0] for line in out.splitlines() if line and line[0].isupper()]


def incidents(h: Harness) -> list[tuple[Any, ...]]:
    return h.query("SELECT operation, code, path, detector, blocks_method FROM incidents")


# ---------------------------------------------------------------- a full read run


def test_a_full_read_run(harness: Harness) -> None:
    h = harness
    plan = two_call_plan(h)
    answer_reads(h)
    code, out = h.run(plan)
    assert code == 0, out
    assert codes(out)[:4] == ["RUN_START", "CALL_OK", "CALL_OK", "CALL_OK"]
    assert "RUN_DONE" in out
    assert "recorder backup" in out
    # The port saw real values, unmasked from the plan's surrogates and the masked search.
    sent = h.port.requests
    assert [r[1] for r in sent] == ["accountSearch", "getSubscriberAccount", "getSubscriberAccount"]
    assert IMEI in sent[0][2]
    assert CONTRACTS[0] in sent[1][2]
    assert CONTRACTS[1] in sent[2][2]
    assert {r[3] for r in sent} == {"rec.RP-2026-003"}
    # The staged files: masked requests and responses, and the manifest.
    names = [p.name for p in h.staged()]
    assert names == [
        "001-search.request.xml",
        "001-search.response.xml",
        "002-account.request.xml",
        "002-account.response.xml",
        "003-account.request.xml",
        "003-account.response.xml",
        "manifest.json",
    ]
    for path in h.staged():
        text = path.read_text(encoding="utf-8")
        assert IMEI not in text
        assert all(c not in text for c in CONTRACTS)
    request = (h.staged()[2]).read_text(encoding="utf-8")
    assert SPECS["CONTRACT"].is_surrogate_shape(request.split("<accountNo>")[1][:11])
    manifest = json.loads(h.staged()[-1].read_text(encoding="utf-8"))
    assert manifest["plan_id"] == "RP-2026-003"
    assert len(manifest["commit"]) == 40
    assert len(manifest["plan_digest"]) == 64
    assert manifest["stopped"] is None
    assert [c["operation"] for c in manifest["calls"]] == [
        "accountSearch",
        "getSubscriberAccount",
        "getSubscriberAccount",
    ]
    assert manifest["calls"][0]["surrogates_issued"] == 2
    assert manifest["calls"][0]["iws_duration_ms"] == 250
    assert manifest["in_canary_range"] == {"CONTRACT": 2, "IMEI": 1}
    assert manifest["in_prefix"] == {}
    # The run log: one row per call, masked fields only.
    rows = h.query(
        "SELECT call_id, decision, outcome, caller, dry_run, plan_digest FROM run_log ORDER BY id"
    )
    assert [r[:5] for r in rows] == [
        ("search", "sent", "ok", "rec.RP-2026-003", 0),
        ("account", "sent", "ok", "rec.RP-2026-003", 0),
        ("account", "sent", "ok", "rec.RP-2026-003", 0),
    ]
    assert rows[0][5] == manifest["plan_digest"]
    assert h.scanned == [h.staged()[0].parent]
    assert incidents(h) == []


# ---------------------------------------------------------------- refusals before any call


def refused(h: Harness, plan: Path, *, dry_run: bool = False, sitest: bool | None = None) -> str:
    code, out = h.run(plan, dry_run=dry_run, sitest=sitest)
    assert code == 1, out
    assert h.port.requests == []
    assert h.staged() == []
    line = out.splitlines()[-1]
    assert line.startswith("REFUSED code=")
    return line.removeprefix("REFUSED ")


def test_a_dirty_tree_is_refused(harness: Harness) -> None:
    plan = two_call_plan(harness)
    (harness.checkout / "stray.txt").write_text("x", encoding="utf-8")
    assert refused(harness, plan) == "code=CHECKOUT_NOT_CLEAN"
    assert refused(harness, plan, dry_run=True) == "code=CHECKOUT_NOT_CLEAN"


def test_a_head_not_on_origin_main_is_refused(harness: Harness) -> None:
    plan = two_call_plan(harness, push=False)
    assert refused(harness, plan) == "code=HEAD_NOT_ON_MAIN"
    assert refused(harness, plan, dry_run=True) == "code=HEAD_NOT_ON_MAIN"


def test_an_unmerged_plan_may_be_dry_run_only(harness: Harness) -> None:
    h = harness
    surrogate = h.issue("IMEI", IMEI)
    text = h.plan_yaml(h.plan_call("search", "accountSearch", SEARCH.format(imei=surrogate)))
    outside = h.tmp / "RP-2026-003.yaml"
    outside.write_text(text, encoding="utf-8")
    assert refused(h, outside) == "code=PLAN_NOT_IN_CHECKOUT"
    assert h.run(outside, dry_run=True)[0] == 0
    inside = h.checkout / "recording-plans" / "RP-2026-003.yaml"
    inside.parent.mkdir()
    inside.write_text(text, encoding="utf-8")
    assert refused(h, inside) == "code=CHECKOUT_NOT_CLEAN"
    # Only the plan itself is left out of the clean-tree check.
    assert h.run(inside, dry_run=True)[0] == 0
    assert refused(h, outside, dry_run=True) == "code=CHECKOUT_NOT_CLEAN"
    assert h.port.requests == []


def test_a_live_plan_must_be_tracked_in_head(harness: Harness) -> None:
    # An ignored plan file leaves the tree clean, but it is not part of the reviewed commit.
    h = harness
    (h.checkout / ".gitignore").write_text("recording-plans/\n", encoding="utf-8")
    h.commit("ignore plans")
    surrogate = h.issue("IMEI", IMEI)
    plan = h.checkout / "recording-plans" / "RP-2026-003.yaml"
    plan.parent.mkdir()
    plan.write_text(
        h.plan_yaml(h.plan_call("search", "accountSearch", SEARCH.format(imei=surrogate))),
        encoding="utf-8",
    )
    assert refused(h, plan) == "code=PLAN_NOT_MERGED"


def test_code_from_another_tree_is_refused(harness: Harness) -> None:
    # The recorder must run from the checkout it checks, not from a second clone or branch.
    plan = two_call_plan(harness)
    harness.code_file = harness.tmp / "other" / "src" / "airtimesat_platform" / "x.py"
    assert refused(harness, plan) == "code=CODE_NOT_FROM_CHECKOUT"
    assert refused(harness, plan, dry_run=True) == "code=CODE_NOT_FROM_CHECKOUT"


def test_a_live_plan_must_sit_in_recording_plans(harness: Harness) -> None:
    h = harness
    surrogate = h.issue("IMEI", IMEI)
    plan = h.checkout / "docs" / "RP-2026-003.yaml"
    plan.parent.mkdir()
    text = h.plan_yaml(h.plan_call("search", "accountSearch", SEARCH.format(imei=surrogate)))
    plan.write_text(text, encoding="utf-8")
    h.commit("plan outside recording-plans")
    assert refused(h, plan) == "code=PLAN_NOT_IN_PLANS_FOLDER"


def test_a_local_branch_named_origin_main_does_not_pass(harness: Harness) -> None:
    plan = two_call_plan(harness, push=False)
    git = ["git", "-C", str(harness.checkout)]
    subprocess.run([*git, "branch", "origin/main"], check=True)  # noqa: S603 - fixed program
    assert refused(harness, plan) == "code=HEAD_NOT_ON_MAIN"


def test_a_commit_from_a_merged_branch_is_not_on_main(harness: Harness) -> None:
    # Reachable from origin/main, but never one of main's own (first-parent) commits.
    h = harness
    plan = two_call_plan(h)

    def git(*args: str) -> None:
        command = ["git", "-C", str(h.checkout), *args]
        subprocess.run(command, check=True)  # noqa: S603 - fixed program, arguments from the test

    git("switch", "-q", "-c", "side")
    (h.checkout / "README.md").write_text("work in progress\n", encoding="utf-8")
    h.commit("WIP", push=False)
    git("switch", "-q", "main")
    git("merge", "-q", "--no-ff", "-m", "merge", "side")
    git("push", "-q", "origin", "HEAD:main")
    git("switch", "-q", "--detach", "side")
    assert refused(h, plan) == "code=HEAD_NOT_ON_MAIN"
    git("switch", "-q", "main")
    answer_reads(h)
    assert h.run(plan)[0] == 0


def test_an_assume_unchanged_edit_is_refused(harness: Harness) -> None:
    plan = two_call_plan(harness)
    git = ["git", "-C", str(harness.checkout)]
    subprocess.run([*git, "update-index", "--assume-unchanged", "README.md"], check=True)  # noqa: S603
    (harness.checkout / "README.md").write_text("edited\n", encoding="utf-8")
    assert refused(harness, plan) == "code=CHECKOUT_NOT_CLEAN"


def test_a_checkout_without_origin_is_refused(harness: Harness) -> None:
    plan = two_call_plan(harness)
    remove = ["git", "-C", str(harness.checkout), "remote", "remove", "origin"]
    subprocess.run(remove, check=True)  # noqa: S603 - fixed program, arguments from the test
    assert refused(harness, plan) == "code=GIT_FETCH_FAILED"


def test_an_expired_plan_is_refused(harness: Harness) -> None:
    plan = two_call_plan(harness)
    harness.now += timedelta(days=60)
    assert refused(harness, plan) == "code=EXPIRES_AT_PAST path=expires_at"


def test_guessed_surrogates_fail_before_any_call(harness: Harness) -> None:
    # Design §8.5 #6: well-formed surrogates in the reserved prefix that were never issued.
    h = harness
    guesses = [SPECS["IMEI"].render(bytes([n]) * 32, "") for n in range(3)]
    calls = [
        h.plan_call(f"guess-{n}", "accountSearch", SEARCH.format(imei=g))
        for n, g in enumerate(guesses)
    ]
    plan = h.plan(h.plan_yaml(*calls))
    assert refused(h, plan).startswith("code=IDENTIFIER_NOT_ISSUED path=calls[0]/")
    assert refused(h, plan, dry_run=True).startswith("code=IDENTIFIER_NOT_ISSUED")


def test_an_unissued_surrogate_behind_a_reference_is_caught_too(harness: Harness) -> None:
    h = harness
    surrogate = h.issue("IMEI", IMEI)
    account = "<request><accountNo>${item}</accountNo></request>"
    guessed = SPECS["IMEI"].render(bytes(32), "")
    search = SEARCH.format(imei=guessed)
    plan = h.plan(
        h.plan_yaml(
            h.plan_call("search", "accountSearch", SEARCH.format(imei=surrogate)),
            h.plan_call("account", "getSubscriberAccount", account, "search.accountNumber[0:2]"),
            h.plan_call("again", "accountSearch", search),
        )
    )
    assert (
        refused(h, plan)
        == "code=IDENTIFIER_NOT_ISSUED path=calls[2]/request/filterValue detector=IMEI"
    )


def test_an_open_incident_blocks_its_method(harness: Harness) -> None:
    plan = two_call_plan(harness)
    with open_store(harness.config.data_dir) as store:
        incident = store.add_incident(
            Incident("r", "RP-2026-001", "accountSearch", 0, "MASKING_BLOCKED", "", "", True),
            harness.now,
        )
        store.add_incident(
            Incident("r", "RP-2026-001", "getVessels", 0, "MASKING_BLOCKED"), harness.now
        )
    assert refused(harness, plan) == f"code=INCIDENT_OPEN path=incident:{incident}"
    with open_store(harness.config.data_dir) as store:
        store.clear_incident(incident, harness.now)
    answer_reads(harness)
    assert harness.run(plan)[0] == 0


def cooldown(store: SqliteStore, h: Harness, seconds: int) -> None:
    store.log(
        LogRow(
            run_utc="r",
            plan_id="RP-2026-001",
            commit_sha="0" * 40,
            plan_digest="0" * 64,
            dry_run=False,
            started_utc=utc_text(h.now),
            ended_utc=utc_text(h.now),
            decision="failed",
            cooldown_until=utc_text(h.now + timedelta(seconds=seconds)),
        )
    )


def test_a_pending_cooldown_refuses_a_live_run_only(harness: Harness) -> None:
    plan = two_call_plan(harness)
    with open_store(harness.config.data_dir) as store:
        cooldown(store, harness, 30)
    assert refused(harness, plan) == "code=COOLDOWN_PENDING"
    assert harness.run(plan, dry_run=True)[0] == 0
    harness.now += timedelta(seconds=31)
    answer_reads(harness)
    assert harness.run(plan)[0] == 0


@pytest.mark.parametrize(
    ("dry_run", "drop", "expected"),
    [
        (False, "sitest.secret_key", "code=SECRET_MISSING path=sitest.secret_key"),
        (False, "masker.vault_key", "code=SECRET_MISSING path=masker.vault_key"),
        (True, "masker.k_mask", "code=SECRET_MISSING path=masker.k_mask"),
        (True, "", "code=SITEST_SECRET_IN_DRY_RUN"),
    ],
)
def test_missing_or_unexpected_secrets(
    harness: Harness, dry_run: bool, drop: str, expected: str
) -> None:
    plan = two_call_plan(harness)
    harness.secrets.pop(drop, None)
    assert refused(harness, plan, dry_run=dry_run, sitest=not drop or None) == expected


def test_get_queue_entry_is_refused_until_w(harness: Harness) -> None:
    # Queue entry ids are not IWS request ids, and D2's reads create no queue entry.
    h = harness
    request = "<request><queueEntryId>q-1</queueEntryId></request>"
    plan = h.plan(h.plan_yaml(h.plan_call("entry", "getQueueEntry", request)))
    with open_store(h.config.data_dir) as store:
        store.add_recorder_requests(["q-1"], "RP-2026-003", "r")
    assert refused(h, plan) == "code=QUEUE_ENTRY_NOT_SUPPORTED path=calls[0]"
    assert refused(h, plan, dry_run=True) == "code=QUEUE_ENTRY_NOT_SUPPORTED path=calls[0]"


def test_reused_keys_and_a_missing_field_map(harness: Harness) -> None:
    plan = two_call_plan(harness)
    harness.secrets["masker.vault_key"] = harness.secrets["masker.k_mask"]
    assert refused(harness, plan) == "code=KEY_REUSED"
    harness.secrets["masker.vault_key"] = "b2" * 32
    harness.field_map = None
    assert refused(harness, plan) == "code=FIELD_MAP_MISSING"


# ---------------------------------------------------------------- the dry run


def test_a_dry_run_shows_each_masked_request_and_never_calls_iws(harness: Harness) -> None:
    h = harness
    plan = two_call_plan(h)
    code, out = h.run(plan, dry_run=True)
    assert code == 0, out
    assert h.port.requests == []
    assert h.staged() == []
    assert codes(out) == ["RUN_START", "DRY_RUN_CALL", "DRY_RUN_CALL", "DRY_RUN_DONE"]
    assert "<accountNo>${item}</accountNo>" in out
    assert IMEI not in out
    rows = h.query("SELECT call_id, decision, dry_run, plan_digest FROM run_log ORDER BY id")
    assert [r[:3] for r in rows] == [("search", "would_send", 1), ("account", "would_send", 1)]
    assert len(rows[0][3]) == 64


def test_the_dry_run_and_the_live_run_agree_on_a_constant(harness: Harness) -> None:
    # The SP constants come from the SITEST record, which a dry run never loads.
    h = harness
    request = "<request><spAccount>SP-0001</spAccount></request>"
    plan = h.plan(h.plan_yaml(h.plan_call("detail", "getPrepaidAccountDetail", request)))
    answer(
        h,
        "getPrepaidAccountDetail",
        lambda _: h.envelope(f"<ns:getPrepaidAccountDetailResponse {NS}/>"),
    )
    code, out = h.run(plan, dry_run=True)
    assert code == 0, out
    code, out = h.run(plan)
    assert code == 0, out
    assert "<spAccount>canary-sp-account-9</spAccount>" in h.port.requests[0][2]


# ---------------------------------------------------------------- fail closed (§8.5 #17)


def blocked(h: Harness, plan: Path, code: str) -> str:
    """Run, and assert the first call wrote nothing, recorded an incident and stopped."""
    status, out = h.run(plan)
    assert status == 1, out
    assert [r[1] for r in h.port.requests] == ["accountSearch"]
    assert h.staged() == []
    rows = incidents(h)
    assert [r[:2] for r in rows] == [("accountSearch", code)]
    log = h.query("SELECT call_id, decision, code FROM run_log")
    assert log[0][0] == "search"
    assert log[0][2] == code
    assert IMEI not in out
    assert all(c not in out for c in CONTRACTS)
    assert "CALL_BLOCKED" in out or "CALL_FAILED" in out
    return out


def test_an_html_error_page_blocks(harness: Harness) -> None:
    plan = two_call_plan(harness)
    answer(harness, "accountSearch", lambda _: f"<html><body>{IMEI}</body></html>".encode())
    blocked(harness, plan, "NON_SOAP_BODY")
    # A transient failure (an outage page) stops the run but leaves the method enabled.
    assert incidents(harness)[0][4] == 0
    # IWS answered: the run log keeps the outcome, duration and signed timestamp (§5.8).
    assert harness.query("SELECT outcome, iws_duration_ms, signed_ts FROM run_log") == [
        ("ok", 250, "2026-10-21T12:00:01Z")
    ]


def test_an_unknown_element_blocks_the_method(harness: Harness) -> None:
    plan = two_call_plan(harness)
    answer(
        harness,
        "accountSearch",
        lambda _: harness.envelope(
            f"<ns:accountSearchResponse {NS}><x>1</x></ns:accountSearchResponse>"
        ),
    )
    out = blocked(harness, plan, "UNKNOWN_ELEMENT")
    with open_store(harness.config.data_dir) as store:
        assert [op for _, op in store.open_incidents(["accountSearch"])] == ["accountSearch"]
    # IWS answered, so the block line says what kind of answer it was (an enum, never text).
    line = next(x for x in out.splitlines() if x.startswith("CALL_BLOCKED"))
    assert "outcome=ok" in line


def test_an_oversized_response_blocks(harness: Harness) -> None:
    plan = two_call_plan(harness)
    answer(harness, "accountSearch", lambda _: b"<x>" + b"a" * (5 * 1024 * 1024) + b"</x>")
    blocked(harness, plan, "XML_TOO_LARGE")


def test_more_rows_than_requested_block(harness: Harness) -> None:
    plan = two_call_plan(harness)
    rows = [(canary("CONTRACT", 70 + n), IMEI) for n in range(6)]
    answer(harness, "accountSearch", lambda _: harness.search_reply(*rows))
    blocked(harness, plan, "TOO_MANY_ROWS")


def test_an_exception_inside_masking_blocks(
    harness: Harness, monkeypatch: pytest.MonkeyPatch
) -> None:
    plan = two_call_plan(harness)
    answer_reads(harness)

    def broken(*_: object) -> None:
        raise RuntimeError(IMEI)

    monkeypatch.setattr(MaskingEngine, "_scan", broken)
    out = blocked(harness, plan, "MASKING_FAILED")
    assert "detector=RuntimeError" in out


def test_a_masking_timeout_blocks(harness: Harness) -> None:
    plan = two_call_plan(harness)
    answer_reads(harness)
    ticks = iter(range(10**6))

    def clock() -> float:
        # Time runs fast once the first call has been sent.
        return float(next(ticks)) if harness.port.requests else 0.0

    harness.monotonic = clock
    blocked(harness, plan, "MASKING_TIMEOUT")


@pytest.mark.parametrize(
    "code",
    ["VAULT_WRITE_FAILED", "VAULT_INTEGRITY", "COLLISION_LIMIT", "SURROGATE_SPACE_EXHAUSTED"],
)
def test_a_vault_failure_stops_the_run_but_not_the_method(
    harness: Harness, monkeypatch: pytest.MonkeyPatch, code: str
) -> None:
    # A wrong key or a full surrogate space is no fault of the method's field map (§8.4).
    plan = two_call_plan(harness)
    answer_reads(harness)

    def fail(*_: object) -> None:
        raise VaultError(code)

    monkeypatch.setattr(SqliteStore, "insert", fail)
    out = blocked(harness, plan, code)
    assert "CALL_FAILED" in out
    assert incidents(harness)[0][4] == 0


def test_a_timeout_records_a_cooldown_that_holds_across_runs(harness: Harness) -> None:
    h = harness
    plan = two_call_plan(h)
    answer(h, "accountSearch", lambda _: TransportTimeoutError("TRANSPORT_TIMEOUT"))
    status, out = h.run(plan)
    assert status == 1
    assert "code=TRANSPORT_TIMEOUT" in out
    # IWS never answered: no outcome to show.
    assert "outcome=" not in next(x for x in out.splitlines() if x.startswith("CALL_FAILED"))
    assert incidents(h) == [("accountSearch", "TRANSPORT_TIMEOUT", "", "", 0)]
    assert h.query("SELECT cooldown_until FROM run_log") == [
        (utc_text(h.now + timedelta(seconds=60)),)
    ]
    h.port.requests.clear()
    assert refused(h, plan) == "code=COOLDOWN_PENDING"


def test_a_failure_after_written_calls_keeps_them_and_scans(harness: Harness) -> None:
    h = harness
    plan = two_call_plan(h)
    answer_reads(h)
    answer(h, "getSubscriberAccount", lambda _: b"<html/>")
    status, out = h.run(plan)
    assert status == 1
    assert [p.name for p in h.staged()] == [
        "001-search.request.xml",
        "001-search.response.xml",
        "manifest.json",
    ]
    manifest = json.loads(h.staged()[-1].read_text(encoding="utf-8"))
    assert manifest["stopped"] == "NON_SOAP_BODY"
    assert [(c["call_id"], c["decision"], c.get("code")) for c in manifest["calls"]] == [
        ("search", "sent", None),
        ("account", "failed", "NON_SOAP_BODY"),
    ]
    # IWS answered the failed call: its outcome and duration, not its signed timestamp.
    assert manifest["calls"][1]["outcome"] == "ok"
    assert manifest["calls"][1]["iws_duration_ms"] == 250
    assert "signed_ts" not in manifest["calls"][1]
    assert len(h.scanned) == 1
    assert "RUN_STOPPED" in out


@pytest.mark.parametrize("failing", ["log", "write"])
def test_a_failure_after_masking_writes_nothing_for_that_call(
    harness: Harness, monkeypatch: pytest.MonkeyPatch, failing: str
) -> None:
    # Design §8.4: an exchange is written only once every stage, the run log included, passed;
    # and a call is reported and logged as sent only once its exchange is written.
    h = harness
    plan = two_call_plan(h)
    answer_reads(h)
    log, write = SqliteStore.log, Staging.write_exchange

    def failing_log(store: SqliteStore, row: LogRow) -> None:
        if row.call_id == "account" and row.decision == "sent":
            raise sqlite3.OperationalError("disk full")
        log(store, row)

    def failing_write(staging: Staging, seq: int, call_id: str, *body: bytes) -> Any:
        if call_id == "account":
            raise OSError
        return write(staging, seq, call_id, *body)

    if failing == "log":
        monkeypatch.setattr(SqliteStore, "log", failing_log)
    else:
        monkeypatch.setattr(Staging, "write_exchange", failing_write)
    status, out = h.run(plan)
    assert status == 1, out
    assert "CALL_FAILED call_id=account" in out
    assert "CALL_OK call_id=account" not in out
    assert h.query("SELECT call_id, decision FROM run_log ORDER BY id") == [
        ("search", "sent"),
        ("account", "failed"),
    ]
    assert [p.name for p in h.staged()] == [
        "001-search.request.xml",
        "001-search.response.xml",
        "manifest.json",
    ]


def test_an_interrupt_mid_call_deletes_the_staging_folder_and_keeps_the_cooldown(
    harness: Harness,
) -> None:
    # Ctrl-C while call 2 is in flight: the staged call 1 was never scanned, and IWS may
    # still be working on call 2 (§5.1 step 6, §5.8).
    h = harness
    plan = two_call_plan(h)
    answer_reads(h)
    answer(h, "getSubscriberAccount", lambda _: KeyboardInterrupt())
    with pytest.raises(KeyboardInterrupt):
        h.run(plan)
    assert h.staged() == []
    assert h.scanned == []
    assert incidents(h) == [("getSubscriberAccount", "RUN_INTERRUPTED", "", "", 0)]
    assert h.query("SELECT MAX(cooldown_until) FROM run_log") == [
        (utc_text(h.now + timedelta(seconds=60)),)
    ]
    h.port.requests.clear()
    assert refused(h, plan) == "code=COOLDOWN_PENDING"


@pytest.mark.parametrize("number", [signal.SIGTERM, signal.SIGHUP])
def test_sigterm_or_sighup_mid_call_takes_the_interrupt_path(
    harness: Harness, number: signal.Signals
) -> None:
    # Closing the terminal or a shutdown: the same clean-up as Ctrl-C (§5.1 step 6).
    h = harness
    plan = two_call_plan(h)
    answer_reads(h)
    before = signal.getsignal(number)
    ignored: list[bool] = []

    def deliver(_: str) -> bytes:
        handler = signal.getsignal(number)
        assert callable(handler)
        try:
            handler(number, None)
        finally:
            # A second signal (a closing terminal often sends one) must not cut the
            # clean-up short: from the first one on, both are ignored until the run ends.
            ignored.append(
                signal.getsignal(signal.SIGTERM) == signal.SIG_IGN
                and signal.getsignal(signal.SIGHUP) == signal.SIG_IGN
            )
        return b""

    answer(h, "getSubscriberAccount", deliver)
    with pytest.raises(SystemExit) as info:
        h.run(plan)
    assert info.value.code == 128 + number
    assert ignored == [True]
    assert signal.getsignal(number) == before
    assert h.staged() == []
    assert h.scanned == []
    assert incidents(h) == [("getSubscriberAccount", "RUN_INTERRUPTED", "", "", 0)]
    assert h.query("SELECT MAX(cooldown_until) FROM run_log") == [
        (utc_text(h.now + timedelta(seconds=60)),)
    ]


# ---------------------------------------------------------------- caps (§8.5 #18)


def test_the_record_cap_stops_the_run_cleanly(
    harness: Harness, monkeypatch: pytest.MonkeyPatch
) -> None:
    h = harness
    monkeypatch.setattr(run_module, "RECORD_CAP", 2)
    plan = two_call_plan(h)
    answer_reads(h)
    extra = canary("CONTRACT", 80)
    answer(h, "getSubscriberAccount", lambda _: h.account_reply(extra, IMEI))
    status, out = h.run(plan)
    assert status == 0, out
    assert "RUN_STOPPED call_id=account code=RECORD_CAP_REACHED" in out
    assert [p.name for p in h.staged()] == [
        "001-search.request.xml",
        "001-search.response.xml",
        "manifest.json",
    ]
    manifest = json.loads(h.staged()[-1].read_text(encoding="utf-8"))
    assert manifest["stopped"] == "RECORD_CAP_REACHED"
    assert manifest["calls"][1]["decision"] == "not_written"
    assert incidents(h) == []


# ---------------------------------------------------------------- the IWS log (§5.3, §8.5 #19)


def test_other_callers_never_reach_a_recording(harness: Harness) -> None:
    h = harness
    other_login = "other" + h.username
    plan = h.plan(
        h.plan_yaml(
            h.plan_call("log", "getIwsRequests", LOG),
            h.plan_call("one", "getIwsRequest", "<request><requestId>req-1</requestId></request>"),
        )
    )
    answer(
        h,
        "getIwsRequests",
        lambda _: h.log_reply(
            ("req-1", "accountSearch", "rec.RP-2026-003"),
            ("req-2", f"accountSearch {IMEI}", other_login),
        ),
    )
    answer(
        h,
        "getIwsRequest",
        lambda _: h.envelope(
            '<ns:getIwsRequestResponse xmlns:ns="urn:example:iws"><iwsLog><requestId>req-1'
            "</requestId><caller>rec.RP-2026-003</caller></iwsLog></ns:getIwsRequestResponse>"
        ),
    )
    status, out = h.run(plan)
    assert status == 0, out
    log = h.staged()[1].read_text(encoding="utf-8")
    assert "<caller>rec.RP-2026-003</caller>" in log
    assert other_login not in log
    assert IMEI not in log
    manifest = json.loads(h.staged()[-1].read_text(encoding="utf-8"))
    assert [c["filtered_log_entries"] for c in manifest["calls"]] == [1, 0]
    assert h.query("SELECT iws_request_id, plan_id FROM recorder_requests") == [
        ("req-1", "RP-2026-003")
    ]


def test_an_iws_request_id_no_recording_produced_is_refused(harness: Harness) -> None:
    h = harness
    plan = h.plan(
        h.plan_yaml(
            h.plan_call("one", "getIwsRequest", "<request><requestId>req-9</requestId></request>")
        )
    )
    status, out = h.run(plan)
    assert status == 1
    assert h.port.requests == []
    assert "code=REQUEST_ID_NOT_RECORDED" in out
    assert incidents(h) == [("getIwsRequest", "REQUEST_ID_NOT_RECORDED", "", "", 0)]


def test_more_log_entries_than_the_limit_block_before_filtering(harness: Harness) -> None:
    h = harness
    plan = h.plan(h.plan_yaml(h.plan_call("log", "getIwsRequests", LOG.replace(">10<", ">2<"))))
    answer(
        h,
        "getIwsRequests",
        lambda _: h.log_reply(
            ("req-1", "accountSearch", "rec.RP-2026-003"),
            ("req-2", "accountSearch", "someone"),
            ("req-3", "accountSearch", "someone"),
        ),
    )
    status, _ = h.run(plan)
    assert status == 1
    assert incidents(h) == [("getIwsRequests", "TOO_MANY_ROWS", "", "", 0)]


def test_queue_entries_are_asked_for_the_recorders_own(harness: Harness) -> None:
    h = harness
    request = "<request><Endpoint>PROVISIONING</Endpoint><status>PENDING</status></request>"
    plan = h.plan(h.plan_yaml(h.plan_call("queue", "getQueueEntries", request)))
    answer(
        h,
        "getQueueEntries",
        lambda _: h.envelope('<ns:getQueueEntriesResponse xmlns:ns="urn:example:iws"/>'),
    )
    status, out = h.run(plan)
    assert status == 0, out
    assert h.port.requests[0][2].endswith("<createdBy>rec.RP-2026-003</createdBy></request>")
    staged = h.staged()[0].read_text(encoding="utf-8")
    assert "createdBy" not in staged


# ---------------------------------------------------------------- before git


def test_a_scanner_hit_deletes_the_staging_folder(harness: Harness) -> None:
    h = harness
    plan = two_call_plan(h)
    answer_reads(h)
    h.scan_result = [("staged.xml:3", "leak_scan:IMEI"), ("staged.xml:4", "gitleaks:rule")]
    status, out = h.run(plan)
    assert status == 1
    # Where, for the CTO: file, line and detector, never the value.
    assert "SCAN_FINDING path=staged.xml:3 detector=leak_scan:IMEI" in out
    assert "SCAN_FINDING path=staged.xml:4 detector=gitleaks:rule" in out
    assert "RUN_FAILED code=STAGING_SCAN_HIT" in out
    assert h.staged() == []
    assert not h.scanned[0].exists()
    assert incidents(h) == [("", "STAGING_SCAN_HIT", "staged.xml:3", "leak_scan:IMEI", 1)]
    # A confirmed leak refuses every later run until the CTO clears it (§8.4).
    h.port.requests.clear()
    assert refused(h, plan).startswith("code=INCIDENT_OPEN")
    assert refused(h, plan, dry_run=True).startswith("code=INCIDENT_OPEN")


def test_a_scanner_that_cannot_run_deletes_the_folder_but_blocks_nothing(
    harness: Harness,
) -> None:
    h = harness
    plan = two_call_plan(h)
    answer_reads(h)
    h.scan_result = None
    status, out = h.run(plan)
    assert status == 1
    assert "RUN_FAILED code=SCANNER_UNAVAILABLE" in out
    assert "SCAN_FINDING" not in out
    assert h.staged() == []
    assert incidents(h) == [("", "SCANNER_UNAVAILABLE", "", "", 0)]
    h.scan_result = []
    assert h.run(plan)[0] == 0


def test_a_failed_staging_delete_is_reported(
    harness: Harness, monkeypatch: pytest.MonkeyPatch
) -> None:
    h = harness
    plan = two_call_plan(h)
    answer_reads(h)
    h.scan_result = [("staged.xml:3", "leak_scan:IMEI")]

    def broken(*_: object, **__: object) -> None:
        raise PermissionError

    monkeypatch.setattr(shutil, "rmtree", broken)
    status, out = h.run(plan)
    assert status == 1
    assert "STAGING_DELETE_FAILED" in out
    assert "RUN_FAILED code=STAGING_SCAN_HIT" in out


def test_a_planted_secret_deletes_the_staging_folder(harness: Harness) -> None:
    # A value the field map keeps, which no detector can recognize: only the secret scan can.
    h = harness
    plan = two_call_plan(h)
    answer_reads(h)
    answer(
        h,
        "getSubscriberAccount",
        lambda r: h.account_reply(next(c for c in CONTRACTS if c in r), IMEI, status=h.secret_key),
    )
    status, out = h.run(plan)
    assert status == 1
    assert "STAGING_SCAN_HIT" in out
    # Which file, and which secret by name: never the value.
    staged = "tests/fixtures/masked/recordings/RP-2026-003/20261021T120000Z"
    assert (
        f"SCAN_FINDING path={staged}/003-account.response.xml detector=secret:sitest.secret_key"
    ) in out
    assert h.staged() == []
    assert h.secret_key not in out


def test_a_planted_key_in_base64_is_found(harness: Harness) -> None:
    h = harness
    plan = two_call_plan(h)
    answer_reads(h)
    planted = base64.b64encode(bytes.fromhex(h.secrets["masker.vault_key"])).decode()
    answer(
        h,
        "accountSearch",
        lambda _: h.search_reply((CONTRACTS[0], IMEI)).replace(b"ACTIVE", planted.encode()),
    )
    status, _ = h.run(plan)
    assert status == 1
    assert h.staged() == []


def tool(folder: Path, name: str, exit_code: int, output: str = "") -> None:
    script = folder / name
    script.write_text(f"#!/bin/sh\nprintf '{output}'\nexit {exit_code}\n", encoding="utf-8")
    script.chmod(0o700)


STAGED = "tests/fixtures/masked/recordings/RP-2026-003/r/manifest.json"
GITLEAKS_OUT = (
    "Finding:     REDACTED\\nSecret:      REDACTED\\nRuleID:      generic-api-key\\n"
    "Entropy:     4.5\\nFile:        {checkout}/" + STAGED + "\\nLine:        2\\n"
)


@pytest.mark.parametrize(
    ("leak_scan", "gitleaks", "expected"),
    [
        ((0, ""), (0, ""), []),
        ((1, f"{STAGED}:1: IMEI"), (0, ""), [(f"{STAGED}:1", "leak_scan:IMEI")]),
        ((0, ""), (3, GITLEAKS_OUT), [(f"{STAGED}:2", "gitleaks:generic-api-key")]),
        ((0, ""), (3, ""), [(STAGED.rpartition("/")[0], "gitleaks")]),
        # A crash or a missing tool is not a finding.
        ((1, ""), (0, ""), None),
        ((0, ""), (1, ""), None),
        ((0, ""), None, None),
        # A finding from one scanner stands even if the other could not run.
        ((1, f"{STAGED}:1: IMEI"), None, [(f"{STAGED}:1", "leak_scan:IMEI")]),
    ],
)
def test_the_scanners_run_on_the_staged_files(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    leak_scan: tuple[int, str],
    gitleaks: tuple[int, str] | None,
    expected: list[tuple[str, str]] | None,
) -> None:
    checkout = tmp_path / "checkout"
    staging = checkout / "tests" / "fixtures" / "masked" / "recordings" / "RP-2026-003" / "r"
    staging.mkdir(parents=True)
    (staging / "manifest.json").write_text("{}", encoding="utf-8")
    (checkout / "scripts").mkdir()
    (checkout / "scripts" / "leak_scan.py").write_text(
        f"import sys\nassert sys.argv[1:] == ['{STAGED}']\n"
        f"print({leak_scan[1]!r}, end='')\nsys.exit({leak_scan[0]})\n",
        encoding="utf-8",
    )
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    if gitleaks is not None:
        tool(bin_dir, "gitleaks", gitleaks[0], gitleaks[1].format(checkout=checkout))
    monkeypatch.setenv("PATH", str(bin_dir))
    assert tool_scan(checkout, staging) == expected


# ---------------------------------------------------------------- retention at the start


def test_the_run_applies_retention_but_spares_the_plans_surrogates(harness: Harness) -> None:
    h = harness
    old = h.now - timedelta(days=120)
    h.now = old
    planned = h.issue("IMEI", IMEI)
    forgotten = h.issue("IMEI", canary("IMEI", 69))
    h.now = old + timedelta(days=120)
    plan = h.plan(h.plan_yaml(h.plan_call("search", "accountSearch", SEARCH.format(imei=planned))))
    h.run(plan, dry_run=True)
    rows = dict(h.query("SELECT surrogate, ciphertext IS NULL FROM vault"))
    assert rows == {planned: 0, forgotten: 1}
