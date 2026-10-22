"""No secret in clear on disk or on the terminal from ``recorder init``, ``rekey`` or a run.

``recorder init``, ``recorder rekey`` and ``recorder run`` (standard input a terminal) run
with fake ``age`` and ``age-keygen`` (``fake_tools``), whose "ciphertext" is an XOR.
Afterwards no file under the test folder (the retired files included), and nothing written
to the terminal (standard output and standard error at the file-descriptor level, so the
age children's output too), holds the SITEST username or secret key, a masking key or
either identity, in clear.
"""

import io
import json
import re
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

from airtimesat_platform.masker.detect.canary import canary
from airtimesat_platform.recorder.config import load_config
from airtimesat_platform.recorder.init import init, rekey

Harness = Any  # tests/conftest.py's Harness
Tools = Any  # tests/conftest.py's FakeTools

SEARCH = (
    "<request><filterType>IMEI</filterType><filterValue>{imei}</filterValue>"
    "<filterCond>EQUALS</filterCond><limit>5</limit></request>"
)


def clear_secrets(h: Harness, tools: Tools, data: Path) -> list[bytes]:
    """Return the SITEST values, the four keys and the identity line ``init`` stored."""
    keys = json.loads(tools.decrypt(data / "masker-keys.json.age"))
    identity = tools.decrypt(data / "recorder-identity.age")
    secret_line = re.search(rb"AGE-SECRET-KEY-1\S+", identity)
    assert secret_line is not None
    values = [h.username, h.secret_key, *keys.values()]
    return [v.encode() for v in values] + [secret_line[0]]


def files_in_clear(root: Path, needles: list[bytes]) -> list[str]:
    return [
        p.name for p in root.rglob("*") if p.is_file() and any(n in p.read_bytes() for n in needles)
    ]


def test_init_and_a_run_leave_no_secret_in_clear(
    harness: Harness, fake_tools: Tools, capfd: pytest.CaptureFixture[str]
) -> None:
    h = harness
    data = h.tmp / "data"
    out = io.StringIO()
    replies = {
        "SITEST username: ": h.username,
        "SITEST secret key: ": h.secret_key,
        "SP account number (Enter if none): ": "",
    }
    config_path = h.tmp / "config" / "recorder.toml"
    init(
        data,
        h.tmp / "backups",
        config_path=config_path,
        out=out,
        prompt=fake_tools.prompt(replies),
        code=h.code_file,
    )
    needles = clear_secrets(h, fake_tools, data)
    # An exposed passphrase: a new identity for both files (runbook 06 case 7).
    now = datetime(2026, 10, 22, 12, 0, tzinfo=UTC)
    rekey(config_path, out=out, now=now, code=h.code_file)
    needles += clear_secrets(h, fake_tools, data)
    assert [p.name for p in data.iterdir() if p.name.startswith(".")] == []
    # The run reads the files init made: the configuration's recipient, init's keys.
    h.config = load_config(config_path)
    h.secrets = json.loads(fake_tools.decrypt(data / "masker-keys.json.age")) | {
        "sitest.iws_username": h.username,
        "sitest.secret_key": h.secret_key,
    }
    imei = canary("IMEI", 81)
    surrogate = h.issue("IMEI", imei)

    def reply(_: str) -> bytes:
        return h.search_reply((canary("CONTRACT", 81), imei))

    h.port.replies["accountSearch"] = reply
    plan = h.plan(
        h.plan_yaml(h.plan_call("search", "accountSearch", SEARCH.format(imei=surrogate)))
    )
    dry_code, dry_out = h.run(plan, dry_run=True, terminal=True)
    live_code, live_out = h.run(plan, terminal=True)
    assert (dry_code, live_code) == (0, 0), live_out
    captured = capfd.readouterr()
    printed = "".join([out.getvalue(), dry_out, live_out, captured.out, captured.err]).encode()
    assert [n for n in needles if n in printed] == []
    assert files_in_clear(h.tmp, needles) == []
