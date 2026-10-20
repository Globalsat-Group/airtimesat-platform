"""scripts/leak_scan.py: modes, refusals, allow-list and history (design §8.3)."""

import hashlib
import ipaddress
from pathlib import Path

import pytest

import leak_scan
from airtimesat_platform.masker.detect.canary import canary
from airtimesat_platform.masker.tokenize.surrogates import SPECS, derive

SCANNER = leak_scan.Scanner(frozenset())


def surrogate(type_name: str) -> str:
    real = canary(type_name, 1)
    return SPECS[type_name].render(derive(bytes(32), type_name, real, 0), real)


def test_canaries_are_findings_outside_the_test_folders() -> None:
    line = f"imei: {canary('IMEI', 1)}"
    assert "IMEI" in SCANNER.scan_line("tests/fixtures/masked/recordings/x/call.xml", line)
    assert "IMEI" in SCANNER.scan_line("recording-plans/RP-2026-001.yaml", line)
    assert "IMEI" in SCANNER.scan_line("docs/notes.md", line)
    assert SCANNER.scan_line("tests/leak/test_x.py", line) == []
    assert SCANNER.scan_line("tests/masker/test_x.py", line) == []


def test_surrogates_are_allowed_everywhere() -> None:
    for type_name in ("IMEI", "ICCID", "MSISDN", "CONTRACT", "EMAIL", "IPV4", "IPV6"):
        line = f"value: {surrogate(type_name)}"
        assert SCANNER.scan_line("recording-plans/RP-1.yaml", line) == [], type_name


def test_strict_and_standard_modes_differ() -> None:
    hashed = "sha256:ab" + canary("IMEI", 1) + "cd"
    assert SCANNER.scan_line("uv.lock", hashed) == []
    assert "IMEI" in SCANNER.scan_line("tests/fixtures/masked/x.txt", hashed)
    assert SCANNER.scan_line("Makefile", "--host 127.0.0.1") == []
    assert SCANNER.scan_line("infra/main.tf", 'cidr = "10.60.0.0/16"') == []
    assert SCANNER.scan_line("docs/a.md", "address 240.0.0.010") == []
    assert "IPV4" in SCANNER.scan_line("recording-plans/a.yaml", "address 10.60.0.1")
    assert SCANNER.scan_line("docs/a.md", "mail ops@example.com or a@b.test") == []
    assert "EMAIL" in SCANNER.scan_line("recording-plans/a.yaml", "mail ops@example.com")
    # The IMO rule is off in standard mode (one 7-digit number in ten passes its check).
    imo = canary("IMO", 1)
    assert SCANNER.scan_line("tests/fixtures/a.txt", f"imo {imo}") == ["IMO"]


# Global addresses built from integers, so this file itself carries no address literal.
GLOBAL_V4 = str(ipaddress.IPv4Address(0x08080404))
OTHER_GLOBAL_V4 = str(ipaddress.IPv4Address(0x08080808))
GLOBAL_V6 = str(ipaddress.IPv6Address((0x2606_4700 << 96) | 0x1111))


def test_global_addresses_count_in_standard_mode() -> None:
    line = f"host {GLOBAL_V4} and {GLOBAL_V6}"
    assert SCANNER.scan_line("docs/a.md", line) == ["IPV4", "IPV6"]
    assert leak_scan.standard_exempt("not-an-ip", leak_scan.Detector.IPV4) is False
    assert leak_scan.standard_exempt("zz::", leak_scan.Detector.IPV6) is False
    assert leak_scan.standard_exempt("x", leak_scan.Detector.PHONE) is False


def test_allow_list_entries_suppress_one_value_at_one_path(tmp_path: Path) -> None:
    value = GLOBAL_V4
    digest = hashlib.sha256(value.encode()).hexdigest()
    allow = tmp_path / "allow.toml"
    allow.write_text(
        f'[[allow]]\npath = "docs/a.md"\ndetector = "IPV4"\nsha256 = "{digest}"\nreason = "test"\n'
    )
    scanner = leak_scan.Scanner(leak_scan.load_allowlist(allow))
    assert scanner.scan_line("docs/a.md", f"dns {value}") == []
    assert scanner.scan_line("docs/b.md", f"dns {value}") == ["IPV4"]
    assert scanner.scan_line("docs/a.md", f"dns {OTHER_GLOBAL_V4}") == ["IPV4"]


@pytest.mark.parametrize(
    "body",
    [
        '[[allow]]\npath = "a"\ndetector = "IPV4"\nsha256 = "00"\nreason = "r"\n',
        '[[allow]]\npath = "a"\ndetector = "IPV4"\nsha256 = "' + "0" * 64 + '"\n',
        '[[allow]]\npath = ""\ndetector = "IPV4"\nsha256 = "' + "0" * 64 + '"\nreason = "r"\n',
    ],
)
def test_allow_list_entries_are_validated(tmp_path: Path, body: str) -> None:
    allow = tmp_path / "allow.toml"
    allow.write_text(body)
    with pytest.raises(ValueError, match="allow"):
        leak_scan.load_allowlist(allow)


def test_missing_allow_list_is_empty(tmp_path: Path) -> None:
    assert leak_scan.load_allowlist(tmp_path / "none.toml") == frozenset()


def test_repository_allow_list_loads() -> None:
    assert leak_scan.load_allowlist(leak_scan.DEFAULT_ALLOWLIST)


def test_strict_paths_refuse_binary_compressed_and_non_utf8(tmp_path: Path) -> None:
    cases = {
        "a.bin": b"\x00\x01binary",
        "a.gz": b"anything",
        "a.txt": "café".encode("latin-1"),
    }
    codes: list[str] = []
    for name, data in cases.items():
        path = tmp_path / name
        path.write_bytes(data)
        text, problem = leak_scan.read_text_file(path, f"tests/fixtures/{name}")
        assert text is None
        assert problem is not None
        codes.append(problem.detector)
        text, problem = leak_scan.read_text_file(path, f"docs/{name}")
        assert text is None
        assert problem is None
    assert codes == ["BINARY_FILE", "COMPRESSED_FILE", "NOT_UTF8"]


def test_findings_never_show_the_value() -> None:
    findings = SCANNER.scan_text("docs/a.md", f"line one\nnumber {canary('IMEI', 1)}\n")
    assert [f.render() for f in findings] == [
        "docs/a.md:2: IMEI",
        "docs/a.md:2: IMSI",
        "docs/a.md:2: LONG_DIGITS",
    ]
    assert leak_scan.Finding("p", 1, "IMEI", "a" * 40).render() == "aaaaaaaaaaaa p:1: IMEI"


def test_main_scans_given_files(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(leak_scan, "REPO_ROOT", tmp_path)
    clean = tmp_path / "clean.md"
    clean.write_text("nothing to see\n")
    dirty = tmp_path / "recording-plans" / "plan.yaml"
    dirty.parent.mkdir()
    dirty.write_text(f"value: {canary('MSISDN', 1)}\n")
    assert leak_scan.main([str(clean), "--allowlist", str(tmp_path / "none.toml")]) == 0
    assert leak_scan.main([str(clean), str(dirty), str(tmp_path / "gone.md")]) == 1
    out = capsys.readouterr()
    assert "recording-plans/plan.yaml:1: MSISDN" in out.out
    assert canary("MSISDN", 1) not in out.out + out.err


def test_main_scans_the_repository_file_list(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(leak_scan, "REPO_ROOT", tmp_path)
    (tmp_path / "a.bin").write_bytes(b"\x00")
    monkeypatch.setattr(leak_scan, "repository_files", lambda: ["a.bin"])
    assert leak_scan.main([]) == 0


DIFF = """diff --git a/docs/a.md b/docs/a.md
--- a/docs/a.md
+++ b/docs/a.md
@@ -1,0 +1,2 @@
+safe line
+imei {imei}
diff --git a/recording-plans/p.yaml b/recording-plans/p.yaml
--- /dev/null
+++ b/recording-plans/p.yaml
@@ -0,0 +5,3 @@
+id: RP-1
 context
+value: 1
diff --git a/old.md b/old.md
--- a/old.md
+++ /dev/null
@@ -1 +0,0 @@
-gone
Binary files /dev/null and b/tests/fixtures/blob.bin differ
Binary files /dev/null and b/docs/logo.png differ
"""


def test_added_lines_parse_a_unified_diff() -> None:
    lines = list(leak_scan.added_lines(DIFF.format(imei="x")))
    assert ("docs/a.md", 2, "imei x") in lines
    assert ("recording-plans/p.yaml", 7, "value: 1") in lines
    assert ("tests/fixtures/blob.bin", 0, "\0BINARY") in lines
    assert all(path != "old.md" for path, _, _ in lines)


def test_history_scans_every_commit(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    calls: list[tuple[str, ...]] = []

    def fake_git(*args: str) -> str:
        calls.append(args)
        if args[0] == "rev-list":
            return "c1\nc2\n"
        return DIFF.format(imei=canary("IMEI", 1)) if args[-1] == "c1" else ""

    monkeypatch.setattr(leak_scan, "git", fake_git)
    assert leak_scan.main(["--history", "base..head"]) == 1
    out = capsys.readouterr().out
    assert "c1 docs/a.md:2: IMEI" in out
    assert "c1 tests/fixtures/blob.bin:0: BINARY_FILE" in out
    assert "logo.png" not in out
    assert calls[0] == ("rev-list", "--reverse", "base..head")
    with pytest.raises(SystemExit):
        leak_scan.main(["--history", "a..b", "c..d"])


def test_git_helper_runs_in_the_repository() -> None:
    assert leak_scan.git("rev-parse", "--is-inside-work-tree").strip() == "true"
    assert "Makefile" in leak_scan.repository_files()
