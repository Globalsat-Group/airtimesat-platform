"""Offline signature vectors for IWS signing (ST-02, design §7.1, §9.3).

Every secret here is synthetic. The expected signatures were computed independently of this
code, with ``printf '%s%s' "$operation" "$timestamp" | openssl dgst -sha1 -hmac "$secret"
-binary | base64``.
"""

from datetime import UTC, datetime, timedelta, timezone

import pytest

from airtimesat_platform.common.secrets import SecretValue
from airtimesat_platform.gateway.errors import SigningError
from airtimesat_platform.gateway.signing import sign, utc_timestamp

FAKE_1 = SecretValue("fake-secret-not-real-0001")
FAKE_2 = SecretValue("fake-secret-not-real-0002")

VECTORS = [
    (FAKE_1, "authenticatedPing", "2026-10-20T12:00:00Z", "8W3YvwGizLO5+DJZ64hwBHqpWgs="),
    (FAKE_1, "accountSearch", "2026-10-20T12:00:00Z", "o3DXyBA+ArGZsEr8r9HxyT6QIHo="),
    (FAKE_1, "accountSearch", "2026-10-20T12:00:01Z", "xLzloVsZowYM/veg9N5ye+kUGGE="),
    (FAKE_2, "getSystemStatus", "2026-12-31T23:59:59Z", "L6PjH7z4A8ePJXfsbc78xBHWqL8="),
    (
        FAKE_2,
        "setSubscriberAccountStatus",
        "2027-01-01T00:00:00Z",
        "2s1z95UweI6q/8CEpHp1AOtIYTA=",
    ),
]


@pytest.mark.parametrize(("secret", "operation", "timestamp", "expected"), VECTORS)
def test_offline_vectors(
    secret: SecretValue, operation: str, timestamp: str, expected: str
) -> None:
    assert sign(secret, operation, timestamp) == expected


def test_operation_name_case_changes_the_signature() -> None:
    # The operation name is case-sensitive: a wrong-case name signs differently.
    assert sign(FAKE_1, "accountsearch", "2026-10-20T12:00:00Z") == "FnvfvdDV89uksMKv+agz/6myH7A="
    assert sign(FAKE_1, "accountsearch", "2026-10-20T12:00:00Z") != sign(
        FAKE_1, "accountSearch", "2026-10-20T12:00:00Z"
    )


def test_one_second_changes_the_signature() -> None:
    assert sign(FAKE_1, "accountSearch", "2026-10-20T12:00:00Z") != sign(
        FAKE_1, "accountSearch", "2026-10-20T12:00:01Z"
    )


def test_signature_has_hmac_sha1_base64_length() -> None:
    signature = sign(FAKE_1, "authenticatedPing", "2026-10-20T12:00:00Z")
    assert len(signature) == 28
    assert signature.endswith("=")


@pytest.mark.parametrize(
    ("now", "expected"),
    [
        (datetime(2026, 10, 20, 12, 0, 0, tzinfo=UTC), "2026-10-20T12:00:00Z"),
        # A host clock in another zone is converted, never labelled "Z" as is.
        (
            datetime(2026, 10, 20, 7, 0, 0, tzinfo=timezone(timedelta(hours=-5))),
            "2026-10-20T12:00:00Z",
        ),
        (
            datetime(2026, 10, 20, 17, 30, 0, tzinfo=timezone(timedelta(hours=5, minutes=30))),
            "2026-10-20T12:00:00Z",
        ),
        # Across midnight and the year boundary in both directions.
        (
            datetime(2026, 12, 31, 20, 59, 59, tzinfo=timezone(timedelta(hours=-3))),
            "2026-12-31T23:59:59Z",
        ),
        (
            datetime(2027, 1, 1, 9, 0, 0, tzinfo=timezone(timedelta(hours=9))),
            "2027-01-01T00:00:00Z",
        ),
        # Sub-second precision is truncated, never rounded up into the next second.
        (datetime(2026, 10, 20, 12, 0, 0, 999_999, tzinfo=UTC), "2026-10-20T12:00:00Z"),
    ],
)
def test_timestamp_is_explicit_utc(now: datetime, expected: str) -> None:
    assert utc_timestamp(now) == expected


def test_naive_datetime_is_refused() -> None:
    with pytest.raises(SigningError) as raised:
        utc_timestamp(datetime(2026, 10, 20, 12, 0, 0))
    assert raised.value.code == "TIMESTAMP_NOT_TIMEZONE_AWARE"


@pytest.mark.parametrize(
    "timestamp",
    [
        "2026-10-20T12:00:00",
        "2026-10-20T12:00:00+00:00",
        "2026-10-20 12:00:00Z",
        "2026-10-20T12:00:00.000Z",
        " 2026-10-20T12:00:00Z",
        "2026-10-20T12:00:00Z\n",
    ],
)
def test_timestamp_format_is_strict(timestamp: str) -> None:
    with pytest.raises(SigningError) as raised:
        sign(FAKE_1, "accountSearch", timestamp)
    assert raised.value.code == "TIMESTAMP_FORMAT_INVALID"


@pytest.mark.parametrize(
    "operation",
    ["", "account Search", "accountSearch\n", "irid:accountSearch", "1accountSearch", "ACCÖUNT"],
)
def test_operation_name_must_be_a_wsdl_name(operation: str) -> None:
    with pytest.raises(SigningError) as raised:
        sign(FAKE_1, operation, "2026-10-20T12:00:00Z")
    assert raised.value.code == "OPERATION_NAME_INVALID"


def test_empty_secret_is_refused() -> None:
    with pytest.raises(SigningError) as raised:
        sign(SecretValue(""), "accountSearch", "2026-10-20T12:00:00Z")
    assert raised.value.code == "SECRET_EMPTY"


def test_errors_carry_no_secret() -> None:
    with pytest.raises(SigningError) as raised:
        sign(FAKE_1, "bad name", "2026-10-20T12:00:00Z")
    assert "fake-secret" not in str(raised.value)
    assert "fake-secret" not in repr(raised.value)
