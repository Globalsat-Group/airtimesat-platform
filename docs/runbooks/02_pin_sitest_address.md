# 02. Pin the SITEST address

| | |
|---|---|
| **Purpose** | Pin SITEST's reviewed address in `SITEST_PINNED_ADDRESSES`, so the transport connects only there; re-pin when SITEST moves |
| **When** | After [`01`](01_wsdl_harvest_and_sitest_record.md) steps 3 to 8 (the record) and the test change below. Again whenever SITEST moves |
| **Who** | The CTO only |
| **Design sections** | [§7.1](../design/s2-recorder-masker.md#71-signer-core-and-beta-unreachability) item 2 |
| **Status** | Draft for CTO review |

The transport never asks DNS for SITEST. It connects only to an address in `SITEST_PINNED_ADDRESSES` in [`gateway/endpoints_sitest.py`](../../src/airtimesat_platform/gateway/endpoints_sitest.py), sends SNI and `Host` for the SITEST name, and verifies the certificate for it ([`gateway/transport.py`](../../src/airtimesat_platform/gateway/transport.py)). While the tuple is empty, every send is refused (`SITEST_ADDRESS_NOT_PINNED`).

## Before you start

A reviewed agent PR must be merged on `main` before you open the pin PR. Today two tests depend on the empty tuple:

- `test_the_pinned_address_is_empty_until_the_cto_pins_it` ([`tests/gateway/test_sitest_transport.py`](../../tests/gateway/test_sitest_transport.py)) fails as soon as an address is pinned, and step 8 leaves you no allowed fix in the pin PR.
- `test_without_a_pinned_address_nothing_is_sent` ([`tests/gateway/test_sitest_port.py`](../../tests/gateway/test_sitest_port.py)) relies on the real constant. Once an address is pinned, it builds the real transport and sends a signed request (fake credentials) to the pinned SITEST address: from CI, and from every agent session that runs the tests. That breaks "agents never call SITEST" (`CLAUDE.md`).

Ask the agents for a PR that (a) sets the tuple to `()` with `monkeypatch` in the second test, as `test_no_pinned_address_refuses_to_build` already does; (b) replaces the first test, for example with one that checks each pinned address parses as an IP address; (c) preferably blocks outbound sockets for the whole test suite. Review it line by line and merge it. Do not open the pin PR until it is on `main`.

## Steps

1. **Take the addresses from the record.** Use the IPv4 and IPv6 addresses of [`sitest_endpoint_record.md`](sitest_endpoint_record.md). Pin every address SITEST answered with [confirm: if DNS rotates through more addresses than you saw, pin all you saw and expect a re-pin].
2. **Check each address against the record.** It appears in the record draft in the manual-call folder and in your Keeper notes (never only in a record copy inside a PR), and `01` step 4 showed it serving the recorded certificate fingerprint for the SITEST name.
3. **Check each address against the Beta lookup.** Repeat `01` step 5 today, DNS only. The address must not be a Beta address. If it is (the shared-address case of `01` step 6), the address cannot separate the two: write that in the PR, and rely on the SNI, `Host` and certificate name as the design says. Never pin an address only because it "works": with a wildcard certificate, a Beta address also passes the TLS check.

   This fresh lookup, with the answers kept in Keeper notes, stands in for the design's "runbook's record of Beta's addresses" (§7.1 item 2): Beta addresses never go into git ([`sitest_endpoint_record.md`](sitest_endpoint_record.md), "Departure from the design").
4. **Make the change.** In the trusted checkout, create a branch from your local `main`, checked under [`03`](03_trusted_machine_setup.md) Part C (never from an unchecked `origin/main` tip), and change only the tuple, for example:

   ```python
   SITEST_PINNED_ADDRESSES: Final[tuple[str, ...]] = ("192.0.2.10",)  # placeholder: use the record
   ```

5. **Add the leak-scan entries.** A global address trips the leak scan's IP detector. For each address, add an entry to `scripts/leak_scan_allow.toml`: path `src/airtimesat_platform/gateway/endpoints_sitest.py`, detector `IPV4` or `IPV6`, the SHA-256 of the address text (`printf '%s' '<address>' | shasum -a 256`), and the reason "SITEST pinned address, design §7.1, record of <date>". Include the record in this PR if it is not merged yet, with its own entries.
6. **Commit and push.** Do not run `make check` on this branch on the trusted machine: it changes gateway code, and unmerged branches are tested in CI, never run there (design §6.5). The pre-commit hook still runs at commit; the branch leaves the hook and the scanner unchanged, so that is `main`'s code. Right after the push, note the pushed SHA (`git rev-parse HEAD`) in your log in the manual-call folder. Then `git switch main && git branch -D <branch>`, and check `git status` shows a clean `main`. Never pull or fetch the branch back; redo any change locally from your checked `main` (`03` Part A step 6).
7. **Open the PR.** The text names the record and the shared-address answer. It names no Beta host and no Beta address.
8. **Review line by line.** The PR touches `gateway/` and gate configuration (`scripts/leak_scan_allow.toml`), so both are on the CTO's line-by-line list. Confirm the diff changes the tuple, the allow-list entries and, if included, the record only. Compare each pinned address with the record draft in the manual-call folder and your Keeper notes, not with the record inside the PR.
9. **Check the head, then merge.** Confirm the PR has exactly one commit and its head SHA equals the SHA you noted in step 6 (on GitHub, or `gh pr merge --match-head-commit <sha>` if you use `gh`). On any mismatch: close the PR, do not merge, and follow [`06`](06_incidents.md) case 6. GitHub will not let you approve your own PR, so it shows as blocked: merge through the step-7 bypass, only when all seven checks are green and you have reviewed every line (`docs/SETUP_CHECKLIST.md`, step 7).
10. **After the merge**, before the next run, do the before-each-run check of [`03`](03_trusted_machine_setup.md) Part C, then sync the checkout.

Done when `main` holds the reviewed addresses, CI is green, and the checkout is back on a clean `main`.

## When SITEST moves

1. **What you see.** Calls fail at connect or TLS: the transport reports `TRANSPORT_TIMEOUT` (an old address that drops packets; the next call then waits 60 s), `TRANSPORT_FAILED` or `TLS_FAILED`, and the run stops. This is the intended failure: the code never follows DNS to a new address. Calls keep working if the old address still serves a valid certificate for the SITEST name (for example a wildcard), so a working call proves nothing; the DNS re-check of `03` Part C before each run catches that case.
2. **Moved or down?** Run `dig "$H" A; dig "$H" AAAA` twice, a few minutes apart, and compare with the record. Unchanged answers: SITEST is down, not moved. Wait, and do not re-pin.
3. **Do not edit the constant locally**, and do not run a build with a new address before it merges.
4. First, in [`sitest_endpoint_record.md`](sitest_endpoint_record.md) in the checkout, move the current table to "Previous records" with its date (keep its allow-list entries). This change goes into the same PR as the new record.
5. Repeat `01` steps 3 to 8 (SITEST addresses, certificate, Beta lookup, comparison, TLS check, record).
6. Repeat this runbook from step 1 with the new addresses. Remove the leak-scan entries of addresses that leave the code.

Done when the new pin is merged and the next run connects.
