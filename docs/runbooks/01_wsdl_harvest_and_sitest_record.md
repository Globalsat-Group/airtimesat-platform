# 01. WSDL harvest and SITEST record

| | |
|---|---|
| **Purpose** | Harvest both SITEST WSDLs, record SITEST's address and certificate, look up Beta by DNS only, check Python's TLS trust, and commit the WSDL snapshot |
| **When** | The first live step of S2 (design §10.2 step 1), after `03` Part A |
| **Who** | The CTO only, on the trusted machine |
| **Design** | [§7.1](../design/s2-recorder-masker.md#71-signer-core-and-beta-unreachability), [§6.5](../design/s2-recorder-masker.md#65-the-trusted-machine) "Manual calls", [§13](../design/s2-recorder-masker.md#13-decisions-and-open-items) #9, #23, #24 |
| **Status** | Draft for CTO review |

From [`gateway/endpoints_sitest.py`](../../src/airtimesat_platform/gateway/endpoints_sitest.py): host `iwstraining.iridium.com`, port `8443`, paths `/iws-current/iws` (provisioning) and `/iwsReport-current/iws-report` (reporting). Work in the manual-call folder, and set once per shell:

```sh
H=iwstraining.iridium.com; P=8443
```

**Before step 8:** ask the agents for a reviewed change to [`tests/gateway/test_sitest_no_beta_host.py`](../../tests/gateway/test_sitest_no_beta_host.py). Today it allows the SITEST host only in `endpoints_sitest.py`, so a WSDL snapshot that names it fails `make check`. The change should allow the SITEST host and the IWS namespace URI under `gateway/wsdl/sitest/` only, and still fail every other Iridium host [confirm the scope in that PR's review]. It loosens a Beta control, so review it line by line.

## SoapUI calls

These rules apply to every signed manual call: the optional ping of step 2, the DEACTIVE of [`05`](05_manual_deactive.md), and a raw reproduction in [`06`](06_incidents.md).

1. **One endpoint.** Keep one project with exactly one endpoint, `https://$H:$P/iws-current/iws` (or the reporting path). Read the endpoint field before every send.
2. **No redirects.** Set "Follow Redirects" to false on the request [confirm the name in your SoapUI version]; otherwise SoapUI resends the signed request wherever a 3xx points.
3. **UTC timestamp.** The IWS guide's SoapUI sample formats the timestamp in local time with a literal `Z` (IWS plan Annex D §2.3). Set the formatter's time zone to UTC in its Groovy step, and sign the exact operation name followed by the timestamp, as [`gateway/signing.py`](../../src/airtimesat_platform/gateway/signing.py) does [confirm against the sample].
4. **No secret in a file.** Turn auto-save off, clear the secret, signature and account properties before closing, and answer No to save prompts. Copy the secret from Keeper with clipboard auto-clear on, and with no clipboard history tool running, including the OS's own: it saves the clipboard to disk. Send `caller` = [FILL: your manual-call value, never starting `rec.`, `agent.` or `gs.`].
5. **One call, then clean up.** No retry. Clear SoapUI's request and response history and lock Keeper.

## Steps

### 1. Harvest the WSDLs (no credential)

```sh
curl --fail --silent --show-error --proto '=https' --max-redirs 0 -o provisioning.wsdl "https://$H:$P/iws-current/iws?wsdl"
curl --fail --silent --show-error --proto '=https' --max-redirs 0 -o reporting.wsdl "https://$H:$P/iwsReport-current/iws-report?wsdl"
```

The `?wsdl` form is inferred [confirm]. Go on only if each file starts with an XML declaration or `wsdl:definitions` (`head -c 200 provisioning.wsdl`). Otherwise stop; do not fall back to the WSDL Explorer (README rule 1). In zsh, run `setopt null_glob` first, so the `*.xsd` globs below do not abort when there are no XSDs. Then fetch each imported XSD (`grep -n 'schemaLocation=' *.wsdl`) the same way, **only if its host is `$H`**, and repeat for imports inside the XSDs. Write the hashes: `shasum -a 256 *.wsdl *.xsd > SHA256SUMS`.

Done when both WSDLs and every SITEST-hosted import are saved with their hashes.

### 2. Check the hosts before any tool loads the files

```sh
grep -n -i -o -E '[a-z0-9.-]*iridium[.]com' *.wsdl *.xsd | sort -u
```

Only `$H` and the IWS namespace URI (`http://www.iridium.com`) may appear. Any other Iridium host: stop. Do not load the files into SoapUI, and do not commit them; settle it in a reviewed change first.

Optional: one `authenticatedPing` from SoapUI, under "SoapUI calls" and `03` Part C, to confirm the credential works. Record only "ok" or the fault code.

Done when no file names a host but `$H` and the namespace URI.

### 3. Record SITEST's addresses and certificate

```sh
dig "$H" A; dig "$H" AAAA
openssl s_client -connect "$H:$P" -servername "$H" </dev/null 2>/dev/null \
  | openssl x509 -noout -subject -issuer -dates -fingerprint -sha256 -ext subjectAltName
```

On macOS's LibreSSL use `-text` instead of `-ext` [confirm]. The issuer must be a public CA; a corporate or security-product issuer means something inspects TLS: stop. Then check that each address serves the same certificate:

```sh
openssl s_client -connect "<each SITEST address>:$P" -servername "$H" </dev/null 2>/dev/null \
  | openssl x509 -noout -fingerprint -sha256      # use [<address>] for IPv6
```

Done when the addresses, subject, SAN list, issuer, dates and SHA-256 fingerprint are noted, and every address gave the same fingerprint.

### 4. Look up the Beta name, by DNS only

```sh
B='BETA_HOST_FROM_YOUR_RECORDS'   # from your own records, never from an agent or a PR
dig "$B" A; dig "$B" AAAA
```

No other tool touches Beta. Keep the name and the answers in your Keeper notes only.

Done when the Beta answers are in your Keeper notes.

### 5. Compare SITEST and Beta

- **Shared address?** Does any Beta address equal a SITEST address?
- **Certificate covers Beta?** Does SITEST's SAN list cover the Beta name, exactly or by a wildcard?

No shared address: the pinned address separates them. Shared address: only the SNI, `Host` and certificate name check separate them (design §7.1 item 2); note it plainly. On a re-record, if the merged record says "shared address: no" and you now find one: stop, commit nothing, and ask Iridium [FILL: contact].

Done when you know both answers.

### 6. Check Python's TLS trust

The transport uses `ssl.create_default_context` ([`gateway/transport.py`](../../src/airtimesat_platform/gateway/transport.py)). A uv-managed Python on macOS may not find the system trust store. From the checkout of `main`:

```sh
uv run --locked python - <<'EOF'
import socket
from airtimesat_platform.gateway.endpoints_sitest import SITEST_HOST, SITEST_PORT
from airtimesat_platform.gateway.transport import tls_context
with socket.create_connection((SITEST_HOST, SITEST_PORT), timeout=15) as raw:
    with tls_context().wrap_socket(raw, server_hostname=SITEST_HOST) as tls:
        print("TLS OK", tls.version())
EOF
```

This is a handshake with SITEST only; it sends no request. On a certificate error, install a bundle of public CAs only [FILL: which bundle and how] and note the choice. Any code change, such as a trust-store library, is a reviewed PR.

Done when it prints `TLS OK`.

### 7. Commit the record

Fill in [`sitest_endpoint_record.md`](sitest_endpoint_record.md) (SITEST facts only) on a branch from your checked `main`. Each SITEST address trips the leak scan, so add an entry per address to `scripts/leak_scan_allow.toml`: path `docs/runbooks/sitest_endpoint_record.md`, detector `IPV4` or `IPV6`, the SHA-256 of the address (`printf '%s' '<address>' | shasum -a 256`) and a reason. Commit, push, open the PR, review it and merge it.

Done when the record is merged.

### 8. Commit the WSDL snapshot

Once the test change above is merged:

1. Copy the files, unchanged, to `src/airtimesat_platform/gateway/wsdl/sitest/` (both WSDLs, the XSDs, `SHA256SUMS`) on a branch from your checked `main` [confirm the names with PR W].
2. Scan them: `uv run --locked python scripts/leak_scan.py src/airtimesat_platform/gateway/wsdl/sitest/*` and `gitleaks dir src/airtimesat_platform/gateway/wsdl/sitest --redact --no-banner`. A hit: stop. Never edit the WSDL bytes to pass.
3. Commit, push, open the PR. Its text quotes no file content. Review it line by line (it is under `gateway/`) and merge it.
4. Delete the raw harvest from the manual-call folder.

Interim confidentiality rule (design §13 #9, #23): private repository, under `gateway/` only.

Done when the snapshot is merged and the raw harvest is deleted.
