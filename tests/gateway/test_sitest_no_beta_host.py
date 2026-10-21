"""Beta and production stay unreachable from the code (design §7.1 layer 1, §8.5 #9).

This test names no Beta or production host. It allows exactly one Iridium host name under
``src/``, the SITEST one, and only in ``gateway/endpoints_sitest.py`` and in the harvested
SITEST WSDL snapshot under ``gateway/wsdl/sitest/`` (runbook ``01``), whose addresses and
imports name SITEST and nothing else. The one other allowed
string is the IWS XML namespace URI, ``"http://www.iridium.com"``, exactly and in quotes: a
name, never contacted. Any other host under ``iridium.com``, the bare domain, or a fragment
such as ``".iridium.com"`` (which could be joined to another name) fails it. In Python files
the check also runs on every string constant as Python reads it, so a name split across
adjacent literals (``"x.iridium" ".com"``) or written with escape sequences is caught. A
name assembled at run time is not; the CTO's review and the transport's pinned host are the
controls for that. From S4 the production endpoint module will be the one reviewed exception
(§7.3).
"""

import ast
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SRC = ROOT / "src"
GATEWAY = SRC / "airtimesat_platform" / "gateway"
SITEST_HOST = "iwstraining.iridium.com"
ENDPOINTS_FILE = GATEWAY / "endpoints_sitest.py"
# The harvested SITEST WSDL snapshot: the WSDLs and XSDs as fetched, never edited.
WSDL_DIR = GATEWAY / "wsdl" / "sitest"

# The registered domain, however it is split or cased.
_DOMAIN = re.compile(r"iridium\s*\.\s*com", re.IGNORECASE)
# What may stand right before an allowed occurrence: the SITEST label, after a character that
# cannot be part of a host name.
_ALLOWED_PREFIX = re.compile(r"(?:^|[^A-Za-z0-9.-])iwstraining\.$")
# The XML namespace of IWS operations: the exact URI, closed by a quote.
_NAMESPACE_BEFORE = re.compile(r"[\"']http://www\.$")
_NAMESPACE_AFTER = re.compile(r"\A[\"']")


def _source_files() -> list[Path]:
    return sorted(path for path in SRC.rglob("*") if path.is_file() and path.suffix != ".pyc")


def _text_violations(text: str) -> list[int]:
    lines: list[int] = []
    for match in _DOMAIN.finditer(text):
        before = text[max(0, match.start() - 64) : match.start()]
        after = text[match.end() : match.end() + 1]
        exact = match.group(0) == "iridium.com"
        sitest = exact and _ALLOWED_PREFIX.search(before)
        namespace = exact and _NAMESPACE_BEFORE.search(before) and _NAMESPACE_AFTER.match(after)
        if not (sitest or namespace):
            lines.append(text.count("\n", 0, match.start()) + 1)
    return lines


def _constant_violations(text: str) -> list[int]:
    # Python joins adjacent literals and decodes escapes into one constant; each constant is
    # checked as a quoted string, so the namespace URI passes only as the whole constant.
    lines: list[int] = []
    for node in ast.walk(ast.parse(text)):
        if isinstance(node, ast.Constant) and isinstance(node.value, str | bytes):
            value = node.value
            decoded = value.decode("latin-1") if isinstance(value, bytes) else value
            if _text_violations(f'"{decoded}"'):
                lines.append(node.lineno)
    return lines


def _violations(path: Path) -> list[int]:
    text = path.read_text(encoding="utf-8", errors="replace")
    lines = _text_violations(text)
    if path.suffix == ".py":
        lines += _constant_violations(text)
    return sorted(set(lines))


def test_no_iridium_host_but_sitest_under_src() -> None:
    found = {
        str(path.relative_to(ROOT)): lines
        for path in _source_files()
        if (lines := _violations(path))
    }
    assert found == {}, f"non-SITEST Iridium host names under src/: {found}"


def _may_name_sitest(path: Path) -> bool:
    return path == ENDPOINTS_FILE or WSDL_DIR in path.parents


def test_the_sitest_host_is_named_only_in_the_endpoints_module_and_the_snapshot() -> None:
    naming = [
        path
        for path in _source_files()
        if SITEST_HOST in path.read_text(encoding="utf-8", errors="replace").lower()
    ]
    assert ENDPOINTS_FILE in naming
    outside = sorted(str(path.relative_to(ROOT)) for path in naming if not _may_name_sitest(path))
    assert outside == []


def test_only_the_snapshot_folder_may_name_sitest() -> None:
    assert _may_name_sitest(WSDL_DIR / "provisioning.wsdl")
    assert _may_name_sitest(WSDL_DIR / "xsd" / "types.xsd")
    assert not _may_name_sitest(WSDL_DIR.parent / "other.wsdl")
    assert not _may_name_sitest(WSDL_DIR.parent / "sitest-copy" / "provisioning.wsdl")
    assert not _may_name_sitest(GATEWAY / "transport.py")


def test_the_check_catches_other_hosts(tmp_path: Path) -> None:
    # The detector itself, on synthetic text with made-up host labels.
    samples = {
        "a.py": 'URL = "https://example-env.iridium.com:8443/x"\n',
        "b.py": 'HOST = "iwstraining" ".iridium.com"\n',
        "c.py": 'HOST = "IRIDIUM.COM"\n',
        "d.py": "# see xiwstraining.iridium.com\n",
        "e.py": 'H = "iwstraining.iridium . com"\n',
        "f.py": 'U = "https://www.iridium.com:8443/x"\n',
        "g.py": 'U = "http://www.iridium.com/x"\n',
        "h.py": 'H = "example-env.iridium" ".com"\n',
        "i.py": 'H = ("example-env.iri"\n     "dium.com")\n',
        "j.py": 'H = "example-env.iridium\\x2ecom"\n',
        "k.py": 'U = b"https://example-env.iridium\\056com"\n',
        "l.py": 'U = "http://www.iridium.com" ":8443/x"\n',
    }
    for name, text in samples.items():
        path = tmp_path / name
        path.write_text(text, encoding="utf-8")
        assert _violations(path), name
    ok = tmp_path / "ok.py"
    ok.write_text(
        'SITEST_HOST = "iwstraining.iridium.com"\nNS = "http://www.iridium.com"\n', encoding="utf-8"
    )
    assert _violations(ok) == []


def test_gateway_package_init_imports_nothing() -> None:
    # Importing the package must not pull in the transport, the signer or any library: the
    # console imports gateway.api, and Python imports gateway/__init__.py on the way.
    tree = ast.parse((GATEWAY / "__init__.py").read_text(encoding="utf-8"))
    imports = [node for node in ast.walk(tree) if isinstance(node, ast.Import | ast.ImportFrom)]
    assert imports == []
    statements = [
        node
        for node in tree.body
        if not (isinstance(node, ast.Expr) and isinstance(node.value, ast.Constant))
    ]
    assert statements == []


def test_importing_gateway_api_loads_no_transport() -> None:
    code = (
        "import sys, airtimesat_platform.gateway.api as api\n"
        "gw = 'airtimesat_platform.gateway.'\n"
        "loaded = sorted(m for m in sys.modules if m.split('.')[0] in {'aiohttp', 'lxml'}"
        " or m.startswith(gw) and m != api.__name__)\n"
        "print(','.join(loaded))\n"
    )
    result = subprocess.run(  # noqa: S603
        [sys.executable, "-I", "-c", code], capture_output=True, text=True, check=True, cwd=ROOT
    )
    assert result.stdout.strip() == ""
