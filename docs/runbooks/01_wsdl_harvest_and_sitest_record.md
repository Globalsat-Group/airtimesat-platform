# 01. WSDL harvest and SITEST record

| | |
|---|---|
| **Purpose** | Harvest both SITEST WSDLs, record SITEST's address, port and certificate, look up the Beta name by DNS only, check Python's TLS trust, and commit the WSDL snapshot |
| **When** | First live step of S2, mandatory, after Part A of [`03`](03_trusted_machine_setup.md). Repeat steps 3 to 8 whenever SITEST may have moved ([`02`](02_pin_sitest_address.md)) |
| **Who** | The CTO only, on the trusted machine |
| **Design sections** | [§7.1](../design/s2-recorder-masker.md#71-signer-core-and-beta-unreachability), [§6.5](../design/s2-recorder-masker.md#65-the-trusted-machine) "Manual calls", [§10.2](../design/s2-recorder-masker.md#102-first-live-steps-the-cto-personally-in-order) step 1, [§13](../design/s2-recorder-masker.md#13-decisions-and-open-items) #9, #23, #24 |
| **Status** | Draft for CTO review |

The SITEST host, port and paths come from [`gateway/endpoints_sitest.py`](../../src/airtimesat_platform/gateway/endpoints_sitest.py): host `iwstraining.iridium.com`, port `8443`, provisioning path `/iws-current/iws`, reporting path `/iwsReport-current/iws-report`. Below, `$H` is that host and `$P` that port. Set them once per shell:

```sh
H=iwstraining.iridium.com; P=8443
```

## Before you start

1. Part A of [`03`](03_trusted_machine_setup.md) is done: disk encryption, the folders, the first merge check, the clean checkout of `main`, `uv sync --frozen`, the hook and the tools (gitleaks 8.21.2 on `PATH`).
2. The run-time rules of [`03`](03_trusted_machine_setup.md) Part C, "During a run or a manual call", hold: AI features that send screen, terminal or clipboard content are off, clipboard sync is off, and no screen share, screen recording or remote-desktop session is active (quit meeting apps). Take no screenshots or photos while Keeper is unlocked, the secret is in SoapUI, or raw output is on screen.
3. Work in the manual-call folder: `cd [FILL: manual-call folder]`. Keep the values of steps 3 to 7 in a draft of the record (`record-draft.md`) in that folder until step 8. Beta facts go to Keeper notes only, never into the draft.
4. Step 9 needs a reviewed change to [`tests/gateway/test_sitest_no_beta_host.py`](../../tests/gateway/test_sitest_no_beta_host.py), merged first: today it allows the SITEST host only in `endpoints_sitest.py`, so a snapshot that names `$H` (almost certain, for example in its address) fails `make check`. Ask the agents for it as soon as step 1 shows what the files name. Proposed scope: allow `$H` and the IWS namespace URI under `gateway/wsdl/sitest/` only, and still fail every other Iridium host [confirm the scope in that PR's review]. Review that PR line by line: it changes a Beta-unreachability control (design §7.1 items 1 and 4), and the PR must give a written reason for loosening it. The test must still fail any Iridium host but `$H`, and `$H` anywhere outside `endpoints_sitest.py` and `gateway/wsdl/sitest/`. Follow-up: add the test to `.github/CODEOWNERS` in a reviewed PR.

## Signed manual calls

These rules hold for every signed manual call: the ping of step 2, the DEACTIVE of [`05`](05_manual_deactive.md) and a read reproduction of [`06`](06_incidents.md) case 1.

1. **One signing path.** Sign only in SoapUI, in the Groovy step of the IWS guide's SoapUI sample. Use the WSDL Explorer only to view WSDLs without a credential, and only under rule 4 [confirm whether it can sign a request itself; until then, never send a signed call from it]. Never compute the signature anywhere else, except the offline check of rule 3, which uses a synthetic test-vector secret only.
2. **The secret never leaves Keeper and SoapUI.** Never pass it as a command-line argument or an environment variable, never type it into a terminal (no `openssl dgst -hmac`), and never put it into an online tool. This repository's test vectors were made with `openssl` from synthetic secrets only.
3. **Fix the sample's signature bugs** (IWS plan Annex D §2.3, Phase 1 plan risk #7). The sample formats the timestamp in the JVM's local time zone with a literal `Z`, and mixes `method` and `methodName`. Otherwise an auth fault may say nothing about the credential. The reference is [`gateway/signing.py`](../../src/airtimesat_platform/gateway/signing.py): the timestamp is UTC, `yyyy-MM-dd'T'HH:mm:ss'Z'`; the signed string is the exact WSDL operation name followed by that timestamp, with no separator; the `timestamp` sent is that same string.
   - In the Groovy step, set the date formatter's time zone to UTC (`setTimeZone(TimeZone.getTimeZone("UTC"))`, standard JDK API), and build the signed string from the property that holds the exact operation name. Starting SoapUI with `TZ=UTC` is a fallback [confirm].
   - **Offline check, before the first call of each SoapUI session** (step 2, [`05`](05_manual_deactive.md), [`06`](06_incidents.md) case 1). With Keeper locked, put the synthetic secret `fake-secret-not-real-0001` from [`tests/gateway/test_signing.py`](../../tests/gateway/test_signing.py) into `secretKey` and set the operation name to `authenticatedPing`. Run only the Groovy step, never the request. Check the `timeStamp` it produced against `date -u +%Y-%m-%dT%H:%M:%SZ` (same second, `Z` suffix). Then compute the reference signature for that timestamp in the checkout: `uv run --locked python -c 'import sys; from airtimesat_platform.common.secrets import SecretValue; from airtimesat_platform.gateway.signing import sign; print(sign(SecretValue("fake-secret-not-real-0001"), "authenticatedPing", sys.argv[1]))' '<the timeStamp>'`, and compare it with the step's `signature`. This carve-out from rules 1 and 2 covers that synthetic secret only. Then clear `secretKey`, `signature` and `timeStamp`. A mismatch: fix the Groovy step and check again; never call with it.
4. **The endpoint.** Create the SoapUI project only from WSDLs that step 1 found to name no host but `$H`. After the snapshot merges (step 9), build it from the merged files under `src/airtimesat_platform/gateway/wsdl/sitest/` on your checked `main`, copied into the manual-call folder (or re-run step 1, with its checks). Keep one endpoint, `https://$H:$P/iws-current/iws` (or `https://$H:$P/iwsReport-current/iws-report` for a reporting call), and delete every other. Read the endpoint field before each send; never send to a default you have not read. Never reuse a project that ever held another environment.
   - **No redirects.** On every request, set SoapUI's "Follow Redirects" property to false before sending [confirm the property name in your SoapUI version]. It is on by default, and the project is not saved (rule 5), so set it again each session. With it on, SoapUI resends the whole signed request to whatever host a 3xx names. A 3xx reply: stop, record only its code, never the `Location` URL.
   - **The WSDL Explorer.** [confirm: whether opening the Explorer, or its default selection, already loads a Beta WSDL. Until that is answered by a source other than opening the page, do not open it.] Once it may be opened: use a private browser window with browser sync and password saving off, first confirm the selected entry is "SITEST - External" or "SITEST Report - External" and the target host is `$H`, and close the window afterwards (design §6.5 "Manual calls").
5. **No secret in a SoapUI file.** The sample keeps `secretKey`, `iwsUserId`, `AcctNum`, `signature`, `caller` and `callerPw` as properties, and SoapUI writes properties into the project file on save.
   - Send `caller` = [FILL: your manual-call value, with its own prefix, never `rec.`, `agent.` or `gs.`, design §5.3, §13 #22]. Leave `callerPw` empty and delete the `<callerPassword>` element from the request, so no SPNet password is sent or saved [confirm that an absent element is accepted].
   - Keep any SoapUI project, its workspace file and its backup folder in the manual-call folder only.
   - Set auto-save to `0` (off) and turn project backups off, or point them at the manual-call folder [confirm in SoapUI's preferences].
   - Before any save or close, clear the values of `secretKey`, `iwsUserId`, `AcctNum`, `signature`, `caller` and `callerPw`. Otherwise answer No to every save prompt.
   - SoapUI's settings and log files in your home folder [confirm paths]: add them to the exclusions of `03` Part A step 4, and check they hold no secret without ever typing it. Search by name: `grep -l -E 'secretKey|callerPw|AcctNum|iwsUserId|<signature>|<iwsUsername>' <files>`, then open each hit and confirm no value follows the name. A name search misses a value logged without its label; for that, feed the value from the Keeper CLI as a pattern, `grep -l -F -f <(<Keeper CLI command that prints the secret field>) <files>` [confirm with Keeper Commander docs], which prints file names only.
6. **Clipboard.** Copy the secret from Keeper with clipboard auto-clear on [confirm with Keeper], with no clipboard history tool running (including the OS's own). Clear the clipboard after the call.
7. **One call, then clean up.** Unlock Keeper only for the call. Make one call, no retry. Then clear SoapUI's request and response history, and lock Keeper.

## Steps

### 1. Harvest the WSDLs (no credential)

1. Fetch each WSDL from SITEST. The URL form `<endpoint>?wsdl` is inferred in Annex D [confirm]. If curl does not get both WSDLs, stop: the other source, the IWS WSDL Explorer (address in Annex E of the IWS plan, `Globalsat-Group/IWS`), is not opened until rule 4's [confirm] is answered. Once it may be used: entries "SITEST - External" and "SITEST Report - External" only, never a Beta entry, under rule 4; set the browser to ask where to save, save into the manual-call folder as `provisioning.wsdl` and `reporting.wsdl`, run items 1 (content check) to 5 on the saved files, and delete any copy that landed elsewhere (for example `~/Downloads`).

   ```sh
   curl -q --fail --show-error --silent --proto '=https' --max-redirs 0 \
     -w '%{http_code} %{content_type}\n' -o provisioning.wsdl "https://$H:$P/iws-current/iws?wsdl"
   curl -q --fail --show-error --silent --proto '=https' --max-redirs 0 \
     -w '%{http_code} %{content_type}\n' -o reporting.wsdl "https://$H:$P/iwsReport-current/iws-report?wsdl"
   ```

   `-q` must come first: curl then skips `~/.curlrc`, which could turn on redirects, a proxy or insecure TLS. No `-L` and `--max-redirs 0`: curl never follows a redirect. Go on only if each command prints `200` with an XML content type, and each file starts with an XML declaration or a `wsdl:definitions` element (`head -c 200 provisioning.wsdl`). A 3xx, an HTML page or anything else: stop [confirm what SITEST returns].
2. List every import and address in each file:

   ```sh
   grep -n -E 'schemaLocation=|location=' provisioning.wsdl reporting.wsdl
   ```

3. **Check every host now, before any other tool loads the files.**

   ```sh
   grep -n -i -o -E '[a-z0-9.-]*iridium[.]com' provisioning.wsdl reporting.wsdl | sort -u
   ```

   Each `soap:address` or `soap12:address` `location` must be `https://$H:$P` plus the path of `endpoints_sitest.py`, and each absolute `schemaLocation` must name `$H`. The IWS namespace URI (`http://www.iridium.com`, exactly) is a name, never contacted, and is allowed. Same host `$H` with another scheme, port or path: note it in the record draft (a port answers part of §13 #24), keep the bytes as harvested, and go on; rule 4's endpoint applies to calls. Any other host: stop. Note it in your Keeper notes only, do not load the files into SoapUI or any other tool, do not commit them, and settle it in a reviewed change first [confirm].
4. Fetch each imported XSD, one at a time, **only if its URL host is `$H`**. Resolve a relative `schemaLocation` against the WSDL URL. Save each one as `<last path segment, or the query value such as xsd1>.xsd`, and write the URL-to-file mapping into `IMPORTS.txt` next to it:

   ```sh
   curl -q --fail --show-error --silent --proto '=https' --max-redirs 0 \
     -w '%{http_code} %{content_type}\n' -o '<name>.xsd' "https://$H:$P/<path and query>"
   ```

   Use double quotes, so `$H` and `$P` expand; if the URL names another port on `$H`, write that port. The same checks as item 1 apply. Repeat items 2 to 4 for imports inside each XSD.
5. Write the SHA-256 of each file, listed by name (under zsh an unmatched `*.xsd` aborts the command): `shasum -a 256 provisioning.wsdl reporting.wsdl <each saved XSD> > SHA256SUMS` (`sha256sum` on Linux).

Done when both WSDLs and every SITEST-hosted import are in the manual-call folder with their hashes, every fetch printed `200`, and no file names a host but `$H` and the namespace URI.

### 2. Optional: one `authenticatedPing` on SITEST

1. Follow "Signed manual calls" above, in SoapUI, including the offline check of rule 3.
2. Make one call. Record only "ok" or the fault code. An auth fault may come from the sample's timestamp bug (rule 3), not the credential.

Done when you know whether the credential works, no SoapUI file holds the secret, and the history and clipboard are cleared.

### 3. Record SITEST's addresses and port

```sh
dig "$H" A; dig "$H" AAAA       # note any CNAME chain, every address, the TTL
```

Run it twice a few minutes apart. Note whether the answers change. Record the port that answers a TLS handshake in step 4 (`$P`). Optionally repeat step 4 on port 8843, SITEST only, to answer §13 #24 for SITEST.

Done when every address, the TTL, any CNAME chain and whether the answers changed are in the record draft.

### 4. Record SITEST's TLS certificate

```sh
openssl s_client -connect "$H:$P" -servername "$H" </dev/null 2>/dev/null \
  | openssl x509 -noout -subject -issuer -dates -fingerprint -sha256 -ext subjectAltName
```

If your `openssl` rejects `-ext` (LibreSSL on macOS), use `-text` and read "Subject Alternative Name" [confirm]. Then check each address from step 3 serves the same certificate:

```sh
openssl s_client -connect "<SITEST address>:$P" -servername "$H" </dev/null 2>/dev/null \
  | openssl x509 -noout -fingerprint -sha256      # use [<address>] for IPv6
```

Done when you have the subject, SAN list, issuer, validity dates and SHA-256 fingerprint, and every address gives the same fingerprint.

### 5. Look up the Beta name, by DNS only

1. Take the Beta host name from your own records: [the Beta host name, from the CTO's own records]. Do not take it from an agent, a plan or a PR.
2. Look it up. `dig` asks your resolver, never Beta. Replace the placeholder before you run it:

   ```sh
   B='BETA_HOST_FROM_YOUR_RECORDS'
   dig "$B" A; dig "$B" AAAA
   ```

3. No connection of any kind: no `curl`, `openssl`, `ping`, `traceroute`, `nc`, browser, SoapUI or WSDL Explorer entry for Beta.
4. Keep the name, the answers and the date in your Keeper notes only. Never in git, a PR, the record draft or an agent chat.

Done when the Beta answers and the date are in your Keeper notes only, and nothing connected to Beta.

### 6. Compare SITEST and Beta

| Check | How |
|---|---|
| Shared address | Does any Beta address from step 5 equal a SITEST address from step 3? Do both names have a CNAME to the same target? |
| Shared certificate | Does SITEST's SAN list cover the Beta name, exactly or by a wildcard? Read it from step 4. No Beta connection needed |

What each answer means for the pin (design §7.1 item 2):

- **No shared address, and the certificate does not cover Beta.** The pinned address and the TLS name check both separate SITEST from Beta.
- **No shared address, but the certificate covers Beta (wildcard).** A Beta address would pass the TLS check. The pinned address is the separation, so every pin and re-pin, and every recording run, is checked against the Beta lookup ([`02`](02_pin_sitest_address.md); [`03`](03_trusted_machine_setup.md) Part C).
- **Shared address.** The address cannot separate them. The SNI and `Host` constant and the certificate name check are the separation. Record it plainly.

Done when the record draft says "shared address: yes or no" and "certificate covers the Beta name: yes or no".

### 7. Check Python's TLS trust on this machine

The transport uses `ssl.create_default_context` with the system trust store ([`gateway/transport.py`](../../src/airtimesat_platform/gateway/transport.py), `tls_context`). A uv-managed Python on macOS may not find the system trust store. From the clean checkout of `main` (`cd [FILL: checkout]`):

1. Show the default verify paths:

   ```sh
   uv run --locked python -c "import ssl; print(ssl.get_default_verify_paths())"
   ```

2. Handshake with SITEST only, verifying the certificate for the SITEST name with the transport's own context. This sends no HTTP request:

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

3. If it fails with a certificate error, install a CA bundle you trust [FILL: which bundle and how], and record the choice in your Keeper notes and in the record draft. Any code change, such as a trust-store library, is a reviewed PR, never a local edit.

Done when the check prints `TLS OK`.

### 8. Fill in the record

1. Copy the record draft into [`sitest_endpoint_record.md`](sitest_endpoint_record.md) in the checkout. Follow its redaction rules for the CNAME chain, the subject and the SAN list: the SITEST name and wildcard entries only, every other name in Keeper notes.
2. Before committing, read the filled record: the only full host name in it is the SITEST name, apart from wildcard entries. No Beta name, no production name, no Beta address.
3. For each address in the record, add an entry to `scripts/leak_scan_allow.toml`: path `docs/runbooks/sitest_endpoint_record.md`, detector `IPV4` or `IPV6`, the SHA-256 of the address text, and a reason, as in [`02`](02_pin_sitest_address.md) step 5. The allow-list is gate configuration, on your line-by-line list. Without these entries the pre-commit hook blocks the commit.
4. Commit it by PR, alone or with the pin PR of [`02`](02_pin_sitest_address.md), as in step 9 items 5 to 7 (own branch from your checked `main`, the pushed SHA noted, back to `main` after the push, the head SHA checked before the merge).

Done when the record PR is open, and the record names no host but SITEST and wildcard entries.

### 9. Commit the WSDL snapshot

Interim confidentiality rule (design §13 #9, #23): private repository, under `src/airtimesat_platform/gateway/` only. Keep the bytes as harvested; the "no catalog descriptions" rule of §13 #23 is for recordings. The test change of "Before you start" item 4 is merged.

1. Name the files so PR W can find them [confirm with PR W]:

   ```text
   src/airtimesat_platform/gateway/wsdl/sitest/provisioning.wsdl
   src/airtimesat_platform/gateway/wsdl/sitest/reporting.wsdl
   src/airtimesat_platform/gateway/wsdl/sitest/<each imported XSD, named as in step 1>
   src/airtimesat_platform/gateway/wsdl/sitest/IMPORTS.txt
   src/airtimesat_platform/gateway/wsdl/sitest/SHA256SUMS
   ```

   Keep the bytes as harvested. Do not edit imports or addresses.
2. Check the files carry no credential, account number or identifier. Element names such as `iwsUsername` are expected; values are not. In the manual-call folder:

   ```sh
   cd [FILL: manual-call folder]
   grep -n -E "(default|fixed)=[\"'][^\"']+" provisioning.wsdl reporting.wsdl <each saved XSD>
   grep -n -i -E '<[a-z0-9]*:?(documentation|appinfo)' provisioning.wsdl reporting.wsdl <each saved XSD>
   grep -n -E '[0-9]{6,}' provisioning.wsdl reporting.wsdl <each saved XSD>
   ```

   These search for values, not element names; identifiers and secrets are also caught by the leak scan and gitleaks in item 4. Read every hit, and for a documentation or appinfo hit read the whole annotation block. Any real value: stop, do not commit. A "No such file" or "no matches found" error means you are in the wrong folder, not that there were no hits.
3. Check for Iridium hosts again, in the same folder:

   ```sh
   grep -n -i -o -E '[a-z0-9.-]*iridium[.]com' provisioning.wsdl reporting.wsdl <each saved XSD> | sort -u
   ```

   Only `$H` and the exact namespace URI may appear (step 1 item 3). Any other host under `iridium.com` must not go into git: stop. If `make check` would still fail on the files, do not edit them or the test to pass; settle it in a reviewed change first.
4. In the checkout, copy the files to the paths of item 1, still uncommitted, and scan them with `main`'s tools:

   ```sh
   cd [FILL: checkout]
   uv run --locked python scripts/leak_scan.py src/airtimesat_platform/gateway/wsdl/sitest/*
   gitleaks dir src/airtimesat_platform/gateway/wsdl/sitest --redact --no-banner --verbose
   ```

   A hit: stop. A false positive needs a reviewed entry in `scripts/leak_scan_allow.toml` with a reason.
5. Create a branch from your local `main`, checked under `03` Part C (never from an unchecked `origin/main` tip). Commit only these files (the pre-commit hook scans again), push, open the PR. The branch adds data files only, so the hook and scans that run are `main`'s code. The PR text names no host but SITEST and quotes no file content.
6. Right after the push, note the pushed SHA (`git rev-parse HEAD`) in your log in the manual-call folder. Then `git switch main && git branch -D <branch>`, and check `git status` shows a clean `main`. Never pull or fetch that branch back. If CI or review needs a change, redo it locally on a new branch from your checked `main` ([`03`](03_trusted_machine_setup.md) Part A step 6).
7. Review the PR line by line (it is under `gateway/`). Before merging, confirm the PR has exactly one commit and its head SHA equals the SHA you noted (on GitHub, or `gh pr merge --match-head-commit <sha>` if you use `gh`). After the merge, compare the merged files' hashes with the `SHA256SUMS` in the manual-call folder. On any mismatch: close the PR, do not merge, and follow [`06`](06_incidents.md) case 6. GitHub will not let you approve your own PR, so it shows as blocked: merge through the step-7 bypass, only when all seven checks are green and you have reviewed every line (`docs/SETUP_CHECKLIST.md`, step 7).

Done when the snapshot is merged on `main`, the record PR is open or merged, the checkout is back on a clean `main`, and the raw harvest stays only in the manual-call folder until the snapshot merges ([`03`](03_trusted_machine_setup.md) Part A step 3).
