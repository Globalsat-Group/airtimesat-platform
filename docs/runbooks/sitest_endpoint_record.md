# SITEST endpoint record

| | |
|---|---|
| **Purpose** | The SITEST facts kept in git, for the pin and the Beta separation check |
| **When** | Filled in by [`01`](01_wsdl_harvest_and_sitest_record.md) step 7; again after every re-record ([`02`](02_pin_sitest_address.md)) |
| **Who** | The CTO only |
| **Design** | [§7.1](../design/s2-recorder-masker.md#71-signer-core-and-beta-unreachability) item 2, [§10.1](../design/s2-recorder-masker.md#101-exit-criteria) item 4 |
| **Status** | Template, not yet filled |

**Never here:** the Beta or production host name, Beta addresses, credentials, raw IWS output. In the subject and SAN list, write the SITEST name and wildcard entries only; note any other name as `[other name, in Keeper notes]`. Each address needs a leak-scan allow-list entry (`01` step 7).

## Current record

| Field | Value |
|---|---|
| Recorded on (UTC) | [FILL] |
| Host and port | `iwstraining.iridium.com`, [FILL: 8443 expected] |
| IPv4 / IPv6 addresses | [FILL] |
| Certificate subject and SAN list | [FILL: SITEST name and wildcards only] |
| Issuer, valid from / to | [FILL] |
| SHA-256 fingerprint | [FILL] |
| Python TLS check | [FILL: OK with the default trust store, or the bundle chosen] |
| Beta DNS lookup done (details in Keeper notes) | [FILL: UTC date] |
| **Shared address with Beta** | [FILL: yes or no] |
| **Certificate covers the Beta name** | [FILL: yes or no] |

## Previous records

On a re-record, move the current table here with its date. None yet.
