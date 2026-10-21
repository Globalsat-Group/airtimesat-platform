# SITEST endpoint record

| | |
|---|---|
| **Purpose** | The SITEST facts that go into git: addresses, port, certificate, and the shared-address answer. Template, filled in by step 8 of [`01`](01_wsdl_harvest_and_sitest_record.md) |
| **When** | After the first live step, and again after every re-record ([`02`](02_pin_sitest_address.md), "When SITEST moves") |
| **Who** | The CTO only |
| **Design sections** | [§7.1](../design/s2-recorder-masker.md#71-signer-core-and-beta-unreachability) item 2, [§10.1](../design/s2-recorder-masker.md#101-exit-criteria) item 4, [§10.2](../design/s2-recorder-masker.md#102-first-live-steps-the-cto-personally-in-order) step 1 |
| **Status** | Draft for CTO review (template, not yet filled) |

**What never goes here.** The Beta host name, Beta addresses, Beta DNS answers, the production host name, any credential, and any raw IWS output. Those stay in the CTO's Keeper notes. Three fields hold names copied from `dig` and `openssl` output, so never paste that output whole: in the CNAME chain, the certificate subject and the SAN list, write only the SITEST name and wildcard entries, and replace every other name with `[other name N, in Keeper notes]`.

**Departure from the design.** Design §7.1 item 1 puts the Beta and production host names in a runbook, and §7.1 item 2 and §10.1 item 4 put Beta's addresses (and certificates) there. These runbooks keep Beta names and addresses in Keeper notes only, and production host names out of git (README rule 3), and `02` step 3 checks each pin against a fresh Beta lookup. This record holds the date of the Beta lookup and the yes or no answers below, which meets the intent of §10.1 item 4. Follow-up: amend the design wording and the `endpoints_sitest.py` docstring in a reviewed PR.

**Leak scan.** A real SITEST address is a global IP address, so `scripts/leak_scan.py` reports it here. Each address needs a reviewed entry in `scripts/leak_scan_allow.toml` in the same PR: this file's path, the detector (`IPV4` or `IPV6`), the SHA-256 of the address text (`printf '%s' '<address>' | shasum -a 256`) and a reason. Write the fingerprint with colons, as `openssl` prints it.

## Current record

| Field | Value |
|---|---|
| Recorded on (UTC date) | [FILL] |
| Host | `iwstraining.iridium.com` (from `gateway/endpoints_sitest.py`) |
| CNAME chain, if any | [FILL: SITEST name and wildcard entries only; any other name as `[other name N, in Keeper notes]`] |
| IPv4 addresses | [FILL] |
| IPv6 addresses | [FILL, or "none"] |
| Answers stable across two lookups | [FILL: yes or no] |
| DNS TTL | [FILL] |
| Port that answered the TLS handshake | [FILL: 8443 expected] |
| Port 8843 tried on SITEST | [FILL: not tried, answered or no answer] |
| Scheme, port and path in the WSDLs' `soap:address` (`01` step 1 item 3) | [FILL: as expected, or what differs; host `$H` only] |
| Certificate subject | [FILL: as printed if it names SITEST or a wildcard; otherwise `[other name, in Keeper notes]`] |
| Certificate SAN list | [FILL: the SITEST name and wildcard entries as printed, then `[n other names, in Keeper notes]`] |
| Certificate issuer | [FILL] |
| Valid from / valid to | [FILL] |
| SHA-256 fingerprint | [FILL] |
| Every SITEST address serves this certificate | [FILL: yes or no] |
| Python TLS check (`01` step 7) | [FILL: OK with the default trust store, or the CA bundle chosen] |
| Beta lookup done (DNS only; details in Keeper notes) | [FILL: yes, on UTC date] |
| **Shared address with Beta** | [FILL: yes or no] |
| **SITEST certificate covers the Beta name** | [FILL: yes (exact or wildcard) or no] |
| What separates SITEST from Beta | [FILL: from `01` step 6] |

## Previous records

When you re-record, move the current table here with its date. Keep its leak-scan entries while the addresses stay in the file.

None yet.
