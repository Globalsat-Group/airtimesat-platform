"""Detectors of design §8.1, identifier variants of §8.5 #4, and exemptions."""

import base64
import string
import time

import pytest
from hypothesis import given
from hypothesis import strategies as st

from airtimesat_platform.masker.detect.canary import canary, in_canary_range, is_canary
from airtimesat_platform.masker.detect.patterns import (
    DEFAULT_OPTIONS,
    OPERATIONAL_SKIP,
    Boundary,
    Detector,
    Options,
    classify_digits,
    find_hits,
    normalize,
)
from airtimesat_platform.masker.detect.scan import (
    CallKnownValues,
    cross_call_hit,
    offline_exemption,
    placed_exemption,
    scan_value,
    token_around,
    word_sequences,
)
from airtimesat_platform.masker.tokenize.surrogates import SPECS, derive, luhn_check_digit

KEY = bytes(32)


def full_width(text: str) -> str:
    """Return ASCII letters and digits as their full-width forms (U+FF01 block)."""
    return "".join(chr(ord(c) + 0xFEE0) for c in text)


def detectors(text: str, options: Options = DEFAULT_OPTIONS) -> set[Detector]:
    return {hit.detector for hit in find_hits(text, options)}


def offline(text: str, allow_canary: bool = False) -> set[Detector]:
    return {hit.detector for hit in find_hits(text, Options(), offline_exemption(allow_canary))}


def surrogate(type_name: str, real: str) -> str:
    return SPECS[type_name].render(derive(KEY, type_name, real, 0), real)


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        (canary("IMEI", 1), {Detector.IMEI, Detector.IMSI, Detector.LONG_DIGITS}),
        (canary("ICCID", 1), {Detector.ICCID, Detector.VOUCHER_SERIAL, Detector.LONG_DIGITS}),
        (canary("MSISDN", 1), {Detector.MSISDN, Detector.LONG_DIGITS}),
        (canary("MMSI", 1), {Detector.MMSI, Detector.LONG_DIGITS}),
        (canary("IMO", 1), {Detector.IMO}),
        (canary("CONTRACT", 1), {Detector.CONTRACT}),
        (canary("EMAIL", 1), {Detector.EMAIL}),
        (canary("IPV4", 1), {Detector.IPV4}),
        (canary("IPV6", 1), {Detector.IPV6}),
    ],
)
def test_each_detector_fires_on_its_canary(value: str, expected: set[Detector]) -> None:
    assert expected <= detectors(value)


def test_contract_and_voucher_account_rules() -> None:
    assert Detector.CONTRACT in detectors(f"see {canary('CONTRACT', 2)} now")
    assert Detector.CONTRACT in detectors(canary("CONTRACT", 2).lower())
    assert Detector.CONTRACT in detectors(canary("VOUCHER_ACCOUNT", 2))
    assert Detector.CONTRACT not in detectors("SC-99")


@pytest.mark.parametrize(
    "variant",
    [
        "+" + canary("MSISDN", 3),
        "00" + canary("MSISDN", 3),
        " ".join([canary("IMEI", 3)[:5], canary("IMEI", 3)[5:10], canary("IMEI", 3)[10:]]),
        "-".join([canary("ICCID", 3)[:4], canary("ICCID", 3)[4:12], canary("ICCID", 3)[12:]]),
        ".".join([canary("MSISDN", 3)[:4], canary("MSISDN", 3)[4:8], canary("MSISDN", 3)[8:]]),
        canary("IMEI", 3) + "7",  # IMEISV, 16 digits
        canary("IMEI", 3)[:14],  # 14-digit IMEI without its check digit
        canary("IMEI", 3)[:14] + "1" if luhn_check_digit(canary("IMEI", 3)[:14]) != "1" else "",
        "0" + canary("IMEI", 3),  # a leading zero
        canary("ICCID", 3) + "0",  # a 20-digit ICCID-like run
        full_width(canary("IMEI", 3)),  # full-width digits
        "".join(chr(0x0660 + int(d)) for d in canary("IMEI", 3)),  # Arabic-Indic digits
        "99" + canary("OTHER_NUMBER", 3)[2:],  # 12 digits starting 99, not placed
        canary("EMAIL", 3).upper(),
        "Mail Person3@Canary.Test today",
        base64.b64encode(f"account {canary('IMEI', 3)} here".encode()).decode(),
        "3fff:0:0:0:0:0:0:3",
    ],
)
def test_identifier_variants_are_detected(variant: str) -> None:
    if not variant:
        pytest.skip("the check digit happens to be 1")
    assert detectors(variant), "no detector fired on a variant"


def test_an_sbd_imei_ending_in_zero_with_an_invalid_luhn_digit_is_detected() -> None:
    payload = canary("IMEI", 5)[:14]
    value = payload + "0"
    assert Detector.IMEI in detectors(value)


def test_classify_digits_rules() -> None:
    assert classify_digits("12345678") == []
    assert classify_digits(canary("MMSI", 1)) == [Detector.MMSI, Detector.LONG_DIGITS]
    assert Detector.ICCID in classify_digits(
        "89" + "0" * 15 + "1" + luhn_check_digit("89" + "0" * 15 + "1")
    )
    assert Detector.MSISDN in classify_digits("00" + canary("MSISDN", 1))


@pytest.mark.parametrize(
    "text",
    [
        "2026-10-20T10:00:00Z",
        "2026-10-20 10:00:00",
        "2026-10-20T10:00:00.123+02:00",
        "20-OCT-2026 10:00:00",
        "UnconfiguredSecretsProvider",
        "subscriberCallDataEntryImpl",
        "Unattended-Upgrade::Allowed-Origins",
        "count 12345678",
        "port 4000 and 10800",
        "ratio 1.5 and 3.25",
        "::1 and ::",
        "http://example.invalid/iws",
    ],
)
def test_no_false_positives_on_ordinary_text(text: str) -> None:
    assert detectors(text) == set()


def test_operational_fields_skip_the_noisy_rules() -> None:
    version = "10.2.0.1"
    assert Detector.IPV4 in detectors(version)
    assert detectors(version, Options(skip=OPERATIONAL_SKIP)) == set()
    assert detectors(canary("NUMERIC_ID", 1), Options(skip=OPERATIONAL_SKIP)) == set()
    # A 15-digit run in an operational field is still an IMEI hit.
    assert Detector.IMEI in detectors(canary("IMEI", 1), Options(skip=OPERATIONAL_SKIP))


def test_alnum_boundary_ignores_digits_inside_tokens() -> None:
    token = "a" + canary("IMEI", 1) + "f"
    assert detectors(token, Options(boundary=Boundary.ALNUM)) == set()
    assert Detector.IMEI in detectors(token, Options(boundary=Boundary.DIGIT))


def test_signature_rule() -> None:
    padded = base64.b64encode(bytes(range(20))).decode()
    assert len(padded) == 28
    assert Detector.SIGNATURE in detectors(padded)
    assert Detector.SIGNATURE in detectors(padded[:27])
    assert Detector.SIGNATURE not in detectors("abcdefghijklmnopqrstuvwxyza")


def test_placed_surrogates_are_exempt_but_lookalikes_are_not() -> None:
    placed = surrogate("IMEI", canary("IMEI", 1))
    lookalike = surrogate("IMEI", canary("IMEI", 2))
    exempt = placed_exemption({placed})
    text = f"device {placed} and {lookalike}"
    hits = find_hits(text, Options(), exempt)
    assert hits
    assert all(hit.text == lookalike for hit in hits)


def test_placed_contract_exempts_its_digits_too() -> None:
    placed = surrogate("CONTRACT", canary("CONTRACT", 1))
    assert find_hits(f"Account {placed}.", Options(), placed_exemption({placed})) == []


def test_offline_exemption_allows_reserved_shapes_only() -> None:
    for type_name in SPECS:
        value = surrogate(type_name, canary(type_name, 3))
        assert offline(f"x {value} y") == set(), type_name
    assert offline("mail someone@example.invalid or h-abc.example.invalid") == set()
    assert offline(canary("IMEI", 3))
    assert offline(canary("IMEI", 3), allow_canary=True) == set()
    assert offline("person@elsewhere.example.com")


def test_token_around() -> None:
    text = "Account SUB-9004217. done"
    start = text.index("9004217")
    assert token_around(text, start, start + 7) == "SUB-9004217"


def test_canary_helpers() -> None:
    for type_name in (
        "IMEI",
        "ICCID",
        "IMSI",
        "MSISDN",
        "CONTRACT",
        "IPV4",
        "IPV6",
        "EMAIL",
        "HOST",
    ):
        value = canary(type_name, 4)
        assert is_canary(value), type_name
        assert in_canary_range(type_name, value)
    assert not is_canary("not a canary")
    assert not is_canary("10.0.0.1")
    assert in_canary_range("VESSEL", "Canary Vessel 4")
    assert not in_canary_range("IMEI", "980001")


def test_normalize_maps_digits_one_for_one() -> None:
    assert normalize(full_width(string.digits)) == string.digits
    assert normalize(full_width("Abc")) == "Abc"


def test_call_known_values() -> None:
    known = CallKnownValues()
    known.add("Canary Vessel 9", "Vessel-abcdefgh")
    known.add("abc", "ignored")
    assert len(known) == 1
    assert known.found_in("the CANARY VESSEL 9 again")
    assert known.found_in(full_width("canary") + " vessel 9")
    assert not known.found_in("abc")
    assert known.replace_in("about canary vessel 9.") == "about Vessel-abcdefgh."


class _Index:
    def __init__(self, values: set[str]) -> None:
        self.values = values

    def is_known(self, value: str) -> bool:
        return value in self.values


def test_cross_call_word_sequences() -> None:
    index = _Index({"canary ocean star"})
    assert cross_call_hit("Vessel (Canary Ocean Star) offline", index)
    assert not cross_call_hit("Vessel Canary Ocean offline", index)
    assert "canary ocean star" in set(word_sequences("x Canary Ocean Star y"))
    assert (
        scan_value("Canary Ocean Star", Options(), offline_exemption(), None, index)
        == Detector.CROSS_CALL_VALUE
    )


def test_detectors_stay_fast_on_adversarial_input() -> None:
    nasty = ("1 " * 50_000) + ("a@" * 20_000) + ("A" * 50_000) + (":" * 20_000) + ("9." * 20_000)
    start = time.monotonic()
    find_hits(nasty)
    assert time.monotonic() - start < 5.0


@given(
    st.text(alphabet=string.digits, min_size=15, max_size=15),
    st.text(alphabet=" abc,;:()", max_size=5),
    st.text(alphabet=" abc,;:()", max_size=5),
)
def test_any_15_digit_run_is_an_imei_hit(digits: str, left: str, right: str) -> None:
    assert Detector.IMEI in detectors(f"{left} {digits} {right}")


@given(st.sampled_from(sorted(SPECS)), st.text(min_size=1, max_size=30))
def test_rendered_surrogates_never_hit_offline(type_name: str, real: str) -> None:
    value = surrogate(type_name, real)
    assert offline(f"value {value} end") == set()
