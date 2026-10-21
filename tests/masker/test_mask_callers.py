"""The IWS log's caller filter, the recorder's caller keep, and the row limit (S2 PR D2).

Design §5.3 (only ``rec.`` entries reach masking), §13 #29 (the recorder's own ``caller`` is
kept), §8.4 (a list with more rows than requested is blocked). Every identifier is a canary.
"""

from collections.abc import Callable

import pytest
from lxml import etree

from airtimesat_platform.masker.detect.canary import canary
from airtimesat_platform.masker.engine import MaskingEngine
from airtimesat_platform.masker.errors import MaskingBlockedError
from airtimesat_platform.masker.fieldmap.loader import build_field_map
from airtimesat_platform.masker.iwslog import filter_callers, is_recorder_caller
from airtimesat_platform.masker.tokenize.surrogates import SPECS
from airtimesat_platform.masker.tokenize.vault import Vault

Envelope = Callable[..., bytes]
NS = 'xmlns:ns="urn:example:iws"'
OWN = "rec.RP-2026-003"
OTHER_LOGIN = "canary.login.7"
OTHER_IMEI = canary("IMEI", 7)


def log_entry(caller: str | None, n: int = 1, name: str = "iwsLog") -> str:
    caller_xml = "" if caller is None else f"<caller>{caller}</caller>"
    return (
        f"<{name}><requestId>{n}</requestId><requestedOperation>accountSearch"
        f"</requestedOperation>{caller_xml}<errorMessage>IMEI {OTHER_IMEI}</errorMessage></{name}>"
    )


def log_response(envelope: Envelope, *entries: str) -> bytes:
    return envelope(
        f"<ns:getIwsRequestsResponse {NS}>{''.join(entries)}</ns:getIwsRequestsResponse>"
    )


def callers(xml: bytes) -> list[str]:
    return [
        e.text or "" for e in etree.fromstring(xml).iter() if etree.QName(e).localname == "caller"
    ]


# ---------------------------------------------------------------- the caller filter


def test_only_entries_from_a_recorder_caller_survive(envelope: Envelope) -> None:
    body = log_response(
        envelope,
        log_entry(OWN, 1),
        log_entry(OTHER_LOGIN, 2),
        log_entry("rec.RP-2026-001", 3),
        log_entry(None, 4),
        log_entry(" rec.RP-2026-003", 5),
        log_entry("REC.RP-2026-003", 6),
    )
    result = filter_callers(body)
    assert (result.kept, result.removed) == (2, 4)
    assert callers(result.body) == [OWN, "rec.RP-2026-001"]
    assert OTHER_LOGIN.encode() not in result.body


def test_an_entry_with_two_callers_is_removed(envelope: Envelope) -> None:
    entry = log_entry(OWN).replace("</iwsLog>", f"<caller>{OTHER_LOGIN}</caller></iwsLog>")
    result = filter_callers(log_response(envelope, entry))
    assert (result.kept, result.removed) == (0, 1)
    assert OTHER_LOGIN.encode() not in result.body


def test_a_caller_outside_a_log_entry_blocks(envelope: Envelope) -> None:
    with pytest.raises(MaskingBlockedError) as info:
        filter_callers(log_response(envelope, log_entry(OWN, name="entry")))
    assert info.value.code == "CALLER_OUTSIDE_LOG_ENTRY"


def test_an_unparsable_log_blocks() -> None:
    with pytest.raises(MaskingBlockedError) as info:
        filter_callers(b"<html><body>Service unavailable</body>")
    assert info.value.code == "XML_PARSE"


def test_a_log_without_entries_passes_unchanged(envelope: Envelope) -> None:
    result = filter_callers(log_response(envelope))
    assert (result.kept, result.removed) == (0, 0)


# ---------------------------------------------------------------- the caller keep


@pytest.mark.parametrize(
    ("value", "kept"),
    [
        (OWN, True),
        ("rec.RP-2026-003x", False),
        ("rec.RP-26-003", False),
        ("rec.other", False),
        ("xrec.RP-2026-003", False),
        (OTHER_LOGIN, False),
    ],
)
def test_the_recorder_caller_pattern(value: str, kept: bool) -> None:
    assert is_recorder_caller("caller", value) is kept
    assert not is_recorder_caller("createdBy", value)


def test_the_recorder_caller_is_kept_and_other_callers_are_masked(
    engine: MaskingEngine, envelope: Envelope
) -> None:
    body = log_response(
        envelope,
        log_entry(OWN, 1, name="entry"),
        log_entry("rec.other", 2, name="entry"),
        log_entry(OTHER_LOGIN, 3, name="entry"),
    )
    masked = engine.mask_response(engine.start_call("getIwsRequests"), body).body
    own, other, login = callers(masked)
    assert own == OWN
    assert SPECS["USER"].is_surrogate_shape(other)
    assert SPECS["USER"].is_surrogate_shape(login)
    assert OTHER_LOGIN.encode() not in masked
    assert OTHER_IMEI.encode() not in masked


def test_the_keep_applies_only_to_caller_fields(engine: MaskingEngine, envelope: Envelope) -> None:
    account = (
        '<account xsi:type="ns:sbdSubscriberAccountImpl">'
        f"<accountNumber>{canary('CONTRACT', 7)}</accountNumber>"
        f"<createdBy>{OWN}</createdBy></account>"
    )
    body = envelope(
        f"<ns:getSubscriberAccountResponse {NS}>{account}</ns:getSubscriberAccountResponse>"
    )
    masked = engine.mask_response(engine.start_call("getSubscriberAccount"), body).body
    assert OWN.encode() not in masked


# ---------------------------------------------------------------- rows and placed surrogates


def test_more_rows_than_requested_block(engine: MaskingEngine, envelope: Envelope) -> None:
    body = log_response(envelope, *(log_entry(OWN, n, name="entry") for n in range(3)))
    with pytest.raises(MaskingBlockedError) as info:
        engine.mask_response(engine.start_call("getIwsRequests"), body, max_rows=2)
    assert info.value.code == "TOO_MANY_ROWS"
    assert engine.mask_response(engine.start_call("getIwsRequests"), body, max_rows=3).body


def test_repeated_children_inside_one_row_are_not_rows(
    map_texts: tuple[str, str], vault: Vault, envelope: Envelope
) -> None:
    # Design §8.4 blocks a list with more rows than requested, not a row with two services.
    generated, overrides = map_texts
    path = "accountSearchResponse/accounts/account/service"
    generated += (
        f"  - {{operation: accountSearch, direction: response, path: {path},"
        " xsd_type: string, min_occurs: 0, max_occurs: unbounded}\n"
    )
    overrides = overrides.replace(
        "templates:",
        f"  - {{operation: accountSearch, direction: response, path: {path},"
        ' treatment: KEEP, reason: "service names"}\ntemplates:',
    )
    field_map, templates = build_field_map(generated, overrides)
    engine = MaskingEngine(field_map, vault, templates=templates)

    def reply(rows: int) -> bytes:
        account = (
            f"<account><accountNumber>{canary('CONTRACT', 9)}</accountNumber>"
            "<service>SBD</service><service>VOICE</service></account>"
        )
        return envelope(
            f"<ns:accountSearchResponse {NS}><accounts>{account * rows}</accounts>"
            "</ns:accountSearchResponse>"
        )

    assert engine.mask_response(engine.start_call("accountSearch"), reply(1), max_rows=1).body
    with pytest.raises(MaskingBlockedError) as info:
        engine.mask_response(engine.start_call("accountSearch"), reply(2), max_rows=1)
    assert info.value.code == "TOO_MANY_ROWS"


def test_the_result_names_the_placed_surrogates(engine: MaskingEngine, envelope: Envelope) -> None:
    contract = canary("CONTRACT", 8)
    account = (
        '<account xsi:type="ns:sbdSubscriberAccountImpl">'
        f"<accountNumber>{contract}</accountNumber></account>"
    )
    body = envelope(
        f"<ns:getSubscriberAccountResponse {NS}>{account}</ns:getSubscriberAccountResponse>"
    )
    result = engine.mask_response(engine.start_call("getSubscriberAccount"), body)
    assert len(result.placed) == result.surrogates_placed == 1
    (placed,) = result.placed
    assert SPECS["CONTRACT"].is_surrogate_shape(placed)
    assert placed.encode() in result.body
