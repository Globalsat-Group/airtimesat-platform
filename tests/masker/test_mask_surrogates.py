"""Surrogate formats, derivation, check digits and reserved prefixes (design §4.2, §4.3)."""

import ipaddress
import string

import pytest
from hypothesis import given
from hypothesis import strategies as st

from airtimesat_platform.masker.detect.canary import canary
from airtimesat_platform.masker.tokenize.surrogates import (
    ONE_WAY_SPECS,
    SPECS,
    base32_from,
    derive,
    digits_from,
    imo_check_digit,
    imo_valid,
    is_reserved_surrogate,
    luhn_check_digit,
    luhn_valid,
    one_way,
)

KEY = bytes(range(32))
OTHER_KEY = bytes(range(1, 33))


def surrogate(type_name: str, real: str, counter: int = 0, key: bytes = KEY) -> str:
    return SPECS[type_name].render(derive(key, type_name, real, counter), real)


@pytest.mark.parametrize(
    ("type_name", "length", "prefix"),
    [
        ("IMEI", 15, "99"),
        ("ICCID", 19, "99"),
        ("IMSI", 15, "99"),
        ("MSISDN", 12, "99"),
        ("OTHER_NUMBER", 12, "99"),
        ("CAPCODE", 12, "99"),
        ("IMO", 7, "99"),
        ("MMSI", 9, "99"),
        ("SERIAL", 19, "99"),
        ("NUMERIC_ID", 9, "99"),
    ],
)
def test_digit_surrogates_have_fixed_length_and_reserved_prefix(
    type_name: str, length: int, prefix: str
) -> None:
    value = surrogate(type_name, canary(type_name, 7))
    assert len(value) == length
    assert value.isdigit()
    assert value.startswith(prefix)
    assert SPECS[type_name].is_surrogate_shape(value)


def test_luhn_types_carry_a_valid_check_digit() -> None:
    for type_name in ("IMEI", "ICCID"):
        for n in range(50):
            assert luhn_valid(surrogate(type_name, canary(type_name, n)))


def test_imo_surrogate_has_a_valid_imo_check_digit() -> None:
    for n in range(50):
        assert imo_valid(surrogate("IMO", canary("IMO", n)))


def test_real_check_digit_is_never_copied() -> None:
    # A real value with a wrong check digit still gets a valid one.
    real = canary("IMEI", 3)
    broken = real[:-1] + str((int(real[-1]) + 1) % 10)
    assert luhn_valid(surrogate("IMEI", broken))


def test_contract_and_voucher_formats() -> None:
    contract = surrogate("CONTRACT", canary("CONTRACT", 1))
    assert contract.startswith("SUB-9")
    assert len(contract) == len("SUB-9") + 6
    voucher_real = canary("VOUCHER_ACCOUNT", 1)
    voucher = surrogate("VOUCHER_ACCOUNT", voucher_real)
    assert voucher.startswith("SC-99")
    assert len(voucher) == len(voucher_real)


def test_address_surrogates_sit_in_reserved_ranges() -> None:
    v4 = ipaddress.ip_address(surrogate("IPV4", canary("IPV4", 1)))
    assert v4 in ipaddress.ip_network("240.0.0.0/4")
    assert str(v4) != "255.255.255.255"
    v6 = ipaddress.ip_address(surrogate("IPV6", canary("IPV6", 1)))
    assert v6 in ipaddress.ip_network("2001:db8::/32")
    assert surrogate("HOST", canary("HOST", 1)).endswith(".example.invalid")
    email = surrogate("EMAIL", canary("EMAIL", 1))
    assert email.startswith("u-")
    assert email.endswith("@example.invalid")


@pytest.mark.parametrize(
    ("type_name", "prefix"),
    [
        ("NAME", "Name-"),
        ("VESSEL", "Vessel-"),
        ("ORG", "Org-"),
        ("GROUP", "Group-"),
        ("USER", "user-"),
    ],
)
def test_label_surrogates(type_name: str, prefix: str) -> None:
    value = surrogate(type_name, "Canary Name 1")
    assert value.startswith(prefix)
    assert len(value) == len(prefix) + 8
    assert SPECS[type_name].is_surrogate_shape(value)


def test_derivation_is_deterministic_and_keyed() -> None:
    real = canary("IMEI", 9)
    assert surrogate("IMEI", real) == surrogate("IMEI", real)
    assert surrogate("IMEI", real) != surrogate("IMEI", real, key=OTHER_KEY)
    assert surrogate("IMEI", real, counter=0) != surrogate("IMEI", real, counter=1)


def test_types_are_derived_independently() -> None:
    digits = canary("IMEI", 4)
    assert derive(KEY, "IMEI", digits, 0) != derive(KEY, "IMSI", digits, 0)


def test_length_prefixed_fields_never_concatenate_to_the_same_input() -> None:
    assert derive(KEY, "ab", "c", 0) != derive(KEY, "a", "bc", 0)
    assert derive(KEY, "IMEI", "1", 23) != derive(KEY, "IMEI", "12", 3)


def test_luhn_and_imo_vectors() -> None:
    payload = "9800012345"
    check = luhn_check_digit(payload)
    assert luhn_valid(payload + check)
    assert not luhn_valid(payload + str((int(check) + 1) % 10))
    assert not luhn_valid("7")
    assert luhn_check_digit("7") == "5"
    assert luhn_check_digit("0") == "0"
    payload = "980012"
    assert imo_check_digit("980012") == str((9 * 7 + 8 * 6 + 1 * 3 + 2 * 2) % 10)
    assert imo_valid(payload + imo_check_digit(payload))
    assert not imo_valid("12345")


def test_digit_and_base32_helpers() -> None:
    h = bytes(32)
    assert digits_from(h, 5) == "00000"
    assert digits_from(h, 0) == ""
    assert base32_from(h) == "aaaaaaaa"
    assert base32_from(b"\xff" * 32) == "77777777"


def test_one_way_pseudonyms() -> None:
    first = one_way(KEY, "NAME", "Canary Person")
    assert first == one_way(KEY, "NAME", "Canary Person")
    assert first.startswith("Name-")
    assert one_way(KEY, "TEXT", "free text").startswith("Text-")
    number = one_way(KEY, "NUMERIC_ID", "12345")
    assert len(number) == 9
    assert number.startswith("99")
    # One-way and reversible derivations of the same value differ.
    assert first != surrogate("NAME", "Canary Person")


def test_reserved_space_detection() -> None:
    assert SPECS["IMEI"].in_reserved_space("990000000000000")
    assert not SPECS["IMEI"].in_reserved_space(canary("IMEI", 1))
    assert SPECS["CONTRACT"].in_reserved_space("SUB-9123456")
    assert not SPECS["CONTRACT"].in_reserved_space(canary("CONTRACT", 1))
    assert SPECS["IPV4"].in_reserved_space("240.1.2.3")
    assert SPECS["EMAIL"].in_reserved_space("someone@host.invalid")
    assert SPECS["VESSEL"].in_reserved_space("Vessel-abcdefgh")
    assert not SPECS["VESSEL"].in_reserved_space("Canary Vessel")


def test_surrogate_shapes_are_exact() -> None:
    good = surrogate("IMEI", canary("IMEI", 1))
    bad_check = good[:-1] + str((int(good[-1]) + 1) % 10)
    assert not SPECS["IMEI"].is_surrogate_shape(bad_check)
    assert not SPECS["IMEI"].is_surrogate_shape(good + "0")
    assert not SPECS["IMEI"].is_surrogate_shape(canary("IMEI", 1))
    assert not SPECS["IPV4"].is_surrogate_shape("240.0.0.01")
    assert not SPECS["IPV4"].is_surrogate_shape("not an address")
    assert not SPECS["VOUCHER_ACCOUNT"].is_surrogate_shape("SC-99")
    assert SPECS["VOUCHER_ACCOUNT"].is_surrogate_shape("SC-990001")


def test_is_reserved_surrogate_covers_every_format() -> None:
    for type_name in SPECS:
        assert is_reserved_surrogate(surrogate(type_name, canary(type_name, 2)))
    for label in ONE_WAY_SPECS:
        assert is_reserved_surrogate(one_way(KEY, label, "x"))
    assert not is_reserved_surrogate(canary("IMEI", 2))


@given(st.sampled_from(sorted(SPECS)), st.text(min_size=1, max_size=40), st.integers(0, 63))
def test_every_rendered_surrogate_has_its_shape(type_name: str, real: str, counter: int) -> None:
    value = surrogate(type_name, real, counter)
    assert SPECS[type_name].is_surrogate_shape(value)
    assert SPECS[type_name].in_reserved_space(value)
    assert is_reserved_surrogate(value)


@given(st.text(alphabet=string.digits, min_size=2, max_size=30))
def test_luhn_check_digit_always_validates(payload: str) -> None:
    assert luhn_valid(payload + luhn_check_digit(payload))
