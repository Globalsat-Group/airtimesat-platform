# 02. Pin the SITEST address

| | |
|---|---|
| **Purpose** | Pin SITEST's address in `SITEST_PINNED_ADDRESSES`, so the recorder connects only there; re-pin when SITEST moves |
| **When** | After the record of [`01`](01_wsdl_harvest_and_sitest_record.md) merges, and whenever SITEST moves |
| **Who** | The CTO only |
| **Design** | [§7.1](../design/s2-recorder-masker.md#71-signer-core-and-beta-unreachability) item 2 |
| **Status** | Draft for CTO review |

The transport never asks DNS for SITEST: it connects only to an address in [`gateway/endpoints_sitest.py`](../../src/airtimesat_platform/gateway/endpoints_sitest.py) and checks the certificate for the SITEST name. While the tuple is empty, every send is refused.

**Before the first pin:** ask the agents for a reviewed PR that fixes two tests that assume an empty tuple. Once an address is pinned, `test_without_a_pinned_address_nothing_is_sent` ([`tests/gateway/test_sitest_port.py`](../../tests/gateway/test_sitest_port.py)) would send a request to SITEST from CI and from every agent session, which breaks "agents never call SITEST". It must set the tuple to `()` with `monkeypatch`. `test_the_pinned_address_is_empty_until_the_cto_pins_it` ([`tests/gateway/test_sitest_transport.py`](../../tests/gateway/test_sitest_transport.py)) must be replaced, for example by a check that each pinned value is an IP address. Merge that PR first.

## Steps

1. Take the addresses from the merged record. Each must have shown the recorded certificate in `01` step 3.
2. Repeat the Beta DNS lookup (`01` step 4). A pinned address must not be a Beta address. If one is and the merged record says "shared address: no", stop and ask Iridium [FILL: contact]; never change the record to "yes" on your own. Only a first record that already said "yes" allows it (design §7.1 item 2). Never pin an address because it "works": with a wildcard certificate a Beta address passes the TLS check too.
3. On a branch from your checked `main`, change only the tuple, for example `("192.0.2.10",)` (a placeholder), and add one leak-scan allow-list entry per address, with path `src/airtimesat_platform/gateway/endpoints_sitest.py`, as in `01` step 7.
4. Commit, push and open the PR. Do not run `make` on the branch on the trusted machine; CI tests it. The PR names no Beta host or address.
5. Review it line by line (`gateway/` and the allow-list are on your list) and merge it.

Done when `main` holds the reviewed addresses and CI is green.

## When SITEST moves

Calls fail at connect or TLS (`TRANSPORT_TIMEOUT`, `TRANSPORT_FAILED`, `TLS_FAILED`) and the run stops. That is the intended failure: the code never follows DNS.

1. Run `dig "$H" A; dig "$H" AAAA` twice, a few minutes apart. Same answers as the record: SITEST is down, not moved. Wait.
2. New answers: redo `01` steps 3 to 5 first. A new SITEST address among Beta's answers while the merged record says "shared address: no": stop, and ask Iridium before you record or pin anything [FILL: contact].
3. Otherwise redo `01` steps 6 and 7 (move the old table to "Previous records"), then the steps above. Remove the allow-list entries of addresses that leave the code.

Done when the new pin is merged and the next run connects.
