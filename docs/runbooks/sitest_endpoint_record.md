# SITEST endpoint record

| | |
|---|---|
| **Purpose** | The SITEST facts kept in git, for the pin and the Beta separation check |
| **When** | Filled in by [`01`](01_wsdl_harvest_and_sitest_record.md) step 7; again after every re-record ([`02`](02_pin_sitest_address.md)) |
| **Who** | The CTO only |
| **Design** | [§7.1](../design/s2-recorder-masker.md#71-signer-core-and-beta-unreachability) item 2, [§10.1](../design/s2-recorder-masker.md#101-exit-criteria) item 4 |
| **Status** | Filled on 2026-10-21 |

**Never here:** the Beta or production host name, Beta addresses, credentials, raw IWS output. In the subject and SAN list, write the SITEST name and wildcard entries only; note any other name as `[other name, in Keeper notes]`. Each address needs a leak-scan allow-list entry (`01` step 7).

## Current record

| Field | Value |
|---|---|
| Recorded on (UTC) | 2026-10-21 |
| Host and port | `iwstraining.iridium.com`, 8443 (both WSDLs' `soap12:address` say the same) |
| IPv4 / IPv6 addresses | `174.68.1.46` / none (one answer each time) |
| Certificate subject and SAN list | `CN=*.iridium.com, O=Iridium Satellite LLC, L=McLean, ST=Virginia, C=US`; SAN `*.iridium.com`, `iridium.com` |
| Issuer, valid from / to | DigiCert Global G2 TLS RSA SHA256 2020 CA1 (a public CA); 2026-09-14 to 2027-03-31 |
| SHA-256 fingerprint | `AE:CC:14:A4:1D:D1:6B:91:92:44:C8:91:83:AD:2B:A8:CF:89:08:B8:6F:9F:36:5D:76:D1:5E:35:84:68:ED:C7` (changes when the certificate is renewed, before 2027-03-31) |
| Python TLS check | OK with the default trust store on the trusted machine (macOS), TLS 1.2 |
| Beta DNS lookup done (details in Keeper notes) | 2026-10-21, DNS only; one IPv4 answer, in the same /24 as SITEST |
| **Shared address with Beta** | no |
| **Certificate covers the Beta name** | yes (the wildcard `*.iridium.com`) |

So the pinned address, not the TLS name check, separates SITEST from Beta. Beta is a neighbour in the same /24, so check every re-pin against your own lookup digit by digit.

## Previous records

On a re-record, move the current table here with its date. None yet.
