"""Runbook 07's SoapUI scripts stay in step with the gateway (runbook 07, design §13 #36).

The two scripts in ``docs/runbooks/soapui/`` run in SoapUI on the trusted machine for one
manual call. They cannot import the gateway, so this test reads them as text and checks what
they copy from it:
- the endpoint;
- the signing self-test;
- the request's elements, order and namespaces;
- the outcome codes.

It passes before and after PR #21: the scripts always send ``callerPassword`` empty, and the
recorder's envelope either omits it or sends it the same way. Synthetic values only.
"""

import re
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path

import pytest
from lxml import etree

from airtimesat_platform.common.secrets import SecretValue
from airtimesat_platform.gateway.endpoints_sitest import Endpoint, endpoint_url
from airtimesat_platform.gateway.envelope import (
    AUTH_FIELDS,
    IWS_NS,
    SOAP12_NS,
    AuthFields,
    build_envelope,
)
from airtimesat_platform.gateway.faults import ERROR_CODES
from airtimesat_platform.gateway.signing import TIMESTAMP_FORMAT, sign

ROOT = Path(__file__).resolve().parents[2]
SCRIPTS = ROOT / "docs" / "runbooks" / "soapui"
SIGN = (SCRIPTS / "sign.groovy").read_text(encoding="utf-8")
TEARDOWN = (SCRIPTS / "teardown.groovy").read_text(encoding="utf-8")

VALUES = {
    "iwsUsername": "user-fake0001",
    "signature": "synthetic-signature",
    "spAccount": "SP-0001",
    "timestamp": "2026-10-20T12:00:00Z",
}


def _constant(name: str) -> str:
    match = re.search(rf'^String {name} = "([^"]*)"$', SIGN, re.MULTILINE)
    assert match is not None, name
    return match.group(1)


def _soapui_request(with_sp: bool) -> list[tuple[str, str]]:
    """Rebuild the script's envelope() output, fill the placeholders, return the request."""
    pattern = r"String envelope\(String caller, boolean withSp\) \{\n(.*?)\n\}\n"
    match = re.search(pattern, SIGN, re.DOTALL)
    assert match is not None
    lines: list[str] = []
    for source in match.group(1).splitlines():
        fragments = re.findall(r"'([^']*)'", source)
        if not fragments or ("serviceProviderAccountNumber" in source and not with_sp):
            continue
        caller_line = "+ caller +" in source
        lines.append(_constant("CALLER").join(fragments) if caller_line else fragments[0])
    xml = re.sub(r"\$\{#TestCase#(\w+)\}", lambda m: VALUES[m.group(1)], "\n".join(lines))
    root = etree.fromstring(xml.encode("utf-8"))
    assert root.tag == f"{{{SOAP12_NS}}}Envelope"
    assert [child.tag for child in root] == [f"{{{SOAP12_NS}}}Body"]
    assert [child.tag for child in root[0]] == [f"{{{IWS_NS}}}getSystemStatus"]
    request = root[0][0][0]
    assert request.tag == "request"
    assert len(root[0][0]) == 1
    return [(str(child.tag), child.text or "") for child in request]


def _recorder_request(with_sp: bool) -> list[tuple[str, str]]:
    def auth(_operation: str) -> AuthFields:
        return AuthFields(
            iws_username=SecretValue(VALUES["iwsUsername"]),
            timestamp=VALUES["timestamp"],
            caller=_constant("CALLER"),
            service_provider_account_number=(SecretValue(VALUES["spAccount"]) if with_sp else None),
            signature=VALUES["signature"],
        )

    factory: Callable[[str], AuthFields] = auth
    root = etree.fromstring(build_envelope("getSystemStatus", "<request/>", factory))
    return [(str(child.tag), child.text or "") for child in root[0][0][0]]


def test_endpoint_is_sitest_provisioning() -> None:
    assert _constant("ENDPOINT") == endpoint_url(Endpoint.PROVISIONING)


def test_caller_is_the_recorders_with_a_manual_prefix() -> None:
    caller = _constant("CALLER")
    assert caller == "cto.RP-2026-001"
    assert not caller.startswith(("rec.", "agent.", "gs."))


def test_signing_self_test_matches_the_gateway() -> None:
    vector = re.search(
        r'hmacSha1Base64\("([^"]+)"\.toCharArray\(\), "(getSystemStatus)([0-9TZ:-]+)"\)'
        r'\s*!= "([^"]+)"',
        SIGN,
    )
    assert vector is not None
    secret, operation, timestamp, expected = vector.groups()
    assert sign(SecretValue(secret), operation, timestamp) == expected
    clock = re.search(r'format\.format\(new Date\((\d+)L\)\) != "([^"]+)"', SIGN)
    assert clock is not None
    when = datetime.fromtimestamp(int(clock.group(1)) / 1000, UTC)
    assert when.strftime(TIMESTAMP_FORMAT) == clock.group(2)
    assert clock.group(2) == timestamp


@pytest.mark.parametrize("with_sp", [True, False])
def test_request_matches_the_recorders_envelope(with_sp: bool) -> None:
    soapui = _soapui_request(with_sp)
    expected_order = [
        name for name in AUTH_FIELDS if with_sp or name != "serviceProviderAccountNumber"
    ]
    assert [name for name, _ in soapui] == expected_order
    assert dict(soapui)["callerPassword"] == ""
    recorder = _recorder_request(with_sp)
    recorder_names = {name for name, _ in recorder}
    # Every element the recorder sends is in the script's request, with the same text and order.
    assert [pair for pair in soapui if pair[0] in recorder_names] == recorder
    # The only possible difference: the recorder without PR #21 omits callerPassword.
    assert {name for name, _ in soapui} - recorder_names <= {"callerPassword"}


def test_teardown_matches_the_sign_check_and_the_gateway() -> None:
    first = "// Teardown of the getSystemStatus manual check"
    last = "log.info(result)"
    assert TEARDOWN.startswith(first)
    assert TEARDOWN.rstrip().endswith(last)
    assert f'tearDown.startsWith("{first}")' in SIGN
    assert f'tearDown.endsWith("{last}")' in SIGN
    fields = re.search(r"List<String> AUTH_FIELDS = \[(.*?)\]", TEARDOWN)
    codes = re.search(r"List<String> ERROR_CODES = \[(.*?)\]", TEARDOWN)
    assert fields is not None
    assert codes is not None
    assert re.findall(r'"(\w+)"', fields.group(1)) == list(AUTH_FIELDS)
    assert set(re.findall(r'"(\w+)"', codes.group(1))) == set(ERROR_CODES)
    assert f'String SOAP12 = "{SOAP12_NS}"' in TEARDOWN
    assert '"airtimesat.manualCheck.sent"' in SIGN
    assert '"airtimesat.manualCheck.sent"' in TEARDOWN
