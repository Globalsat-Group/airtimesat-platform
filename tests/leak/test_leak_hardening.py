"""Regression tests for detector and leak-scan gaps found in the adversarial review of S2 PR B.

Every value is a canary or a surrogate (design §8.2).
"""

import base64
import codecs
import hashlib
import io
import logging
import sys
import threading
from pathlib import Path

import pytest

import leak_scan
from airtimesat_platform.masker.detect.canary import canary
from airtimesat_platform.masker.detect.patterns import DEFAULT_OPTIONS, Detector, find_hits
from airtimesat_platform.masker.detect.scan import CallKnownValues, offline_exemption
from airtimesat_platform.masker.logsafe import SafeLogFilter, install_excepthook

IMEI = canary("IMEI", 31)


def detectors(text: str) -> set[Detector]:
    return {hit.detector for hit in find_hits(text, DEFAULT_OPTIONS)}


def offline(text: str) -> set[Detector]:
    return {hit.detector for hit in find_hits(text, DEFAULT_OPTIONS, offline_exemption())}


# ---------------------------------------------------------------- normalization


@pytest.mark.parametrize(
    "separator",
    ["\u200b", "\u00ad", "\u2060", "\ufeff", "\u202e", "\u0301", "\u20e3", "\u2013", "\u2212"],
)
def test_invisible_characters_and_dashes_do_not_split_an_identifier(separator: str) -> None:
    assert Detector.IMEI in detectors(IMEI[:7] + separator + IMEI[7:])


# ---------------------------------------------------------------- detector shapes


@pytest.mark.parametrize(
    "text",
    [
        "person31\u00e9@canary.test",  # a non-ASCII letter right before "@"
        "person31@c\u00e1nary.test",  # an internationalized domain
    ],
)
def test_unicode_email_addresses_are_detected(text: str) -> None:
    assert Detector.EMAIL in detectors(text)


@pytest.mark.parametrize(
    "text", ["ip:3fff::1234", "at 3fff::1234: ok", "addr=3fff::1234:port", "[3fff::1234]:80"]
)
def test_ipv6_after_a_word_and_colon_or_before_a_colon_is_detected(text: str) -> None:
    assert Detector.IPV6 in detectors(text)


@pytest.mark.parametrize(
    "text",
    [
        "Class::Add",
        "Upgrade::Allowed",
        "std::cout",
        "Foo::Bar::Baz",
        "Name::dead::beef",
        "12:34:56",
    ],
)
def test_scope_operators_and_times_are_not_ipv6(text: str) -> None:
    assert Detector.IPV6 not in detectors(text)


@pytest.mark.parametrize(
    "encoded",
    [
        base64.b64encode(canary("MSISDN", 31).encode()).decode(),  # 16 characters
        base64.b64encode(canary("IMEI", 31).encode()).decode(),  # 20 characters
        base64.b64encode(canary("ICCID", 31).encode()).decode().rstrip("="),  # unpadded
    ],
)
def test_short_and_unpadded_base64_is_decoded(encoded: str) -> None:
    assert detectors(f"blob {encoded} end")


@pytest.mark.parametrize("separator", ["", "_", " "])
def test_contract_numbers_without_a_hyphen_are_detected(separator: str) -> None:
    digits = canary("CONTRACT", 31)[4:]
    assert Detector.CONTRACT in detectors(f"see SUB{separator}{digits} now")


# ---------------------------------------------------------------- offline exemption


@pytest.mark.parametrize(
    "text",
    [
        f"{IMEI}.example.invalid",
        f"{IMEI}@example.invalid",
        f"h-{IMEI}.example.invalid",
        f"{canary('EMAIL', 31)}.example.invalid",
        f"+{canary('MSISDN', 31)}.example.invalid",
        f"{canary('CONTRACT', 31)}.example.invalid",
        f"{canary('IPV4', 31)}.example.invalid",
    ],
)
def test_values_glued_to_the_reserved_domain_are_not_exempt(text: str) -> None:
    assert offline(text)


def test_reserved_addresses_and_surrogates_stay_exempt() -> None:
    assert offline("u-abcdefgh@example.invalid and someone@example.invalid") == set()
    assert offline("h-abcdefgh.example.invalid:4000 and 240.1.2.3") == set()


# ---------------------------------------------------------------- known values


def test_call_known_values_ignore_spacing() -> None:
    known = CallKnownValues()
    known.add("Canary  Vessel\tThirty", "Vessel-abcdefgh")
    assert known.found_in("seen canary vessel thirty today")
    assert known.found_in("seen CANARY\nVESSEL   THIRTY today")
    assert known.replace_in("x Canary\nVessel  Thirty y") == "x Vessel-abcdefgh y"


# ---------------------------------------------------------------- log filter and hooks


def test_log_values_glued_to_the_reserved_domain_trip() -> None:
    log_filter = SafeLogFilter()
    rec = logging.LogRecord("recorder", logging.INFO, __file__, 1, "CALL_DONE", None, None)
    rec.path = f"{IMEI}.example.invalid"
    assert not log_filter.filter(rec)
    assert log_filter.tripped == "LOG_DETECTOR_HIT"


def test_thread_and_unraisable_exceptions_print_type_only(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    stream = io.StringIO()
    monkeypatch.setattr(sys, "stderr", stream)
    monkeypatch.setattr(sys, "excepthook", sys.__excepthook__)
    monkeypatch.setattr(threading, "excepthook", threading.__excepthook__)
    monkeypatch.setattr(sys, "unraisablehook", sys.__unraisablehook__)
    install_excepthook()

    def fail() -> None:
        raise ValueError(IMEI)

    thread = threading.Thread(target=fail)
    thread.start()
    thread.join()
    assert stream.getvalue() == "UNCAUGHT ValueError\n"
    assert IMEI not in stream.getvalue()


# ---------------------------------------------------------------- leak scan

SCANNER = leak_scan.Scanner(frozenset())


def test_utf16_text_outside_strict_paths_is_scanned(tmp_path: Path) -> None:
    path = tmp_path / "notes.txt"
    path.write_bytes(codecs.BOM_UTF16_LE + f"imei {IMEI}\n".encode("utf-16-le"))
    text, problem = leak_scan.read_text_file(path, "docs/notes.txt")
    assert problem is None
    assert text is not None
    assert SCANNER.scan_text("docs/notes.txt", text)
    text, problem = leak_scan.read_text_file(path, "tests/fixtures/notes.txt")
    assert text is None
    assert problem is not None


def test_reserved_email_domains_allow_one_label_in_front() -> None:
    assert leak_scan.reserved_email_domain("a@canary.test")
    assert leak_scan.reserved_email_domain("a@example.invalid")
    assert leak_scan.reserved_email_domain("a@mail.example.com")
    assert not leak_scan.reserved_email_domain("a@other.canary.test")
    # Built at run time: the literal would be a finding of the repository scan itself.
    assert not leak_scan.reserved_email_domain("a@" + ".".join(["x", "mail", "example", "com"]))


def test_history_reads_quoted_paths() -> None:
    diff = (
        'diff --git "a/tests/fixtures/caf\\303\\251.xml" "b/tests/fixtures/caf\\303\\251.xml"\n'
        "--- /dev/null\n"
        '+++ "b/tests/fixtures/caf\\303\\251.xml"\n'
        "@@ -0,0 +1,1 @@\n"
        f"+imei {IMEI}\n"
        'Binary files /dev/null and "b/tests/fixtures/\\303\\251.bin" differ\n'
    )
    lines = list(leak_scan.added_lines(diff))
    assert ("tests/fixtures/caf\u00e9.xml", 1, f"imei {IMEI}") in lines
    assert ("tests/fixtures/\u00e9.bin", 0, "\0BINARY") in lines


def test_allow_list_tokens_use_the_normalized_line() -> None:
    address = canary("IPV4", 31)
    token = f"v{address}x"
    digest = hashlib.sha256(token.encode()).hexdigest()
    scanner = leak_scan.Scanner(
        frozenset({leak_scan.AllowEntry("tests/fixtures/a.txt", "IPV4", digest)})
    )
    # Two invisible characters shift every span of the normalized line.
    assert scanner.scan_line("tests/fixtures/a.txt", f"\u200b\u200b{token}") == []
