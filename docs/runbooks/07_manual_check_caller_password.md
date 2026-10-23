# 07. Manual check: one `getSystemStatus` with an empty `callerPassword`

| | |
|---|---|
| **Purpose** | One signed `getSystemStatus` call to SITEST provisioning with `<callerPassword></callerPassword>`, built like the recorder's request with PR #21. It tests design §13 #36, proposed in PR #21 ("to be confirmed by one manual SoapUI call with an empty `callerPassword`"), before #21 merges |
| **When** | Once, after this runbook and its two scripts are merged and before PR #21 merges |
| **Who** | The CTO only, on the trusted machine, every part. Parts B to D run in Terminal and SoapUI with no AI tool open on the screen. Read this file and open the scripts from your checkout in TextEdit (or another viewer with no AI feature), never from an AI chat |
| **Design** | [§6.5](../design/s2-recorder-masker.md#65-the-trusted-machine) "Manual calls", [§7.1](../design/s2-recorder-masker.md#71-signer-core-and-beta-unreachability); README rules 1, 3 and 5; [`01`](01_wsdl_harvest_and_sitest_record.md) "SoapUI calls"; [`03`](03_trusted_machine_setup.md) Part C |
| **Status** | Draft for CTO review |

The two scripts are [`soapui/sign.groovy`](soapui/sign.groovy) (the TestCase's first step) and [`soapui/teardown.groovy`](soapui/teardown.groovy) (its TearDown Script). They run inside SoapUI with the SITEST secret, so use only the copies in your checkout on `main` (README rule 5). `tests/gateway/test_runbook_soapui.py` keeps them in step with the gateway: the endpoint, the signing self-test, the request's elements and the outcome codes.

No `R` command runs except the read-only `R doctor` of `03` Part C. Incident 1 stays open, and the vault and the plans are untouched. The first time takes about 40 minutes. Afterwards you share only the one `RESULT …` line: codes, WSDL field names and `sp=with` or `sp=without`. Never share a value, the request or the response.

## Read first: four facts that shape the steps

1. **SoapUI accepts any server certificate and any host name** (its `SoapUISSLSocketFactory` trusts every certificate). SITEST's certificate is the `*.iridium.com` wildcard, which also covers Beta ([`sitest_endpoint_record.md`](sitest_endpoint_record.md)). So for SoapUI, only name resolution keeps the call on SITEST. Part B step 6 pins SITEST's recorded address in `/etc/hosts` before SoapUI starts, as the recorder pins it in code, and Part D step 2 removes the pin after SoapUI quits.
2. **SoapUI starts with its proxy on, in Automatic mode.** Through a proxy, the proxy resolves the name, and the pin no longer applies. Part C step 2 turns the proxy off, and the sign script stops with `PROXY` if it is on.
3. **SoapUI follows redirects unless the request says otherwise.** The sign script turns redirects off, keeps empty elements, sets a 120 s timeout, and checks all three before anything is signed.
4. **The app's name includes its version:** `/Applications/SoapUI-5.9.1.app`. Homebrew's uninstall moves files to the Trash rather than deleting them, so Part D deletes SoapUI's own files with `rm` first.

Rules for this check (README rules 1 and 3, `01` "SoapUI calls", `03` Part C):
- One call and no retry.
- Never Beta and never DEACTIVE.
- SITEST values go from the Keeper app only into the script's hidden fields, and in Part D step 3 into the value search, which reads them from the clipboard without showing them. Never into a file, a property you type, a terminal command line or a chat.
- Never save the SoapUI project.
- You may look at the Raw views, the TestCase log and the http log yourself. Never use Copy, Export or Save in them, and never share them. Quit SoapUI right after recording the `RESULT` line.

## Part A. Install SoapUI (Terminal; no secret, no Iridium host)

**Recommended source:** SmartBear's own installer, SoapUI 5.9.1 from `dl.eviware.com`, through Homebrew.
- `dl.eviware.com` is SmartBear's download host; soapui.org's download page links to it.
- The Homebrew cask pins the installer's SHA-256 for both Apple silicon and Intel.
- soapui.org's page itself offers 5.10.0, but only for Apple silicon and without a published checksum.

Approving the source is your call. These steps assume the Homebrew 5.9.1 route. If a value differs from the expected one, stop. You may tell an agent which field differed, never the output.

1. **Check the cask before anything is downloaded:**

   ```zsh
   brew update
   brew info --cask --json=v2 soapui | jq -r '.casks[0] | .version, .url, .sha256, "deprecated=\(.deprecated) disabled=\(.disabled)"'
   ```

   Expected, exactly four lines:
   - `5.9.1`
   - `https://dl.eviware.com/soapuios/5.9.1/SoapUI-arm64-5.9.1.dmg` (Intel Mac: `https://dl.eviware.com/soapuios/5.9.1/SoapUI-x64-5.9.1.dmg`)
   - `8fd400d40bebfa0260d2f7a8ccead22742a08b6c0b33ef321def7b2f19022969` (Intel Mac: `1c95a58c88151b20adb7fc76cfbe22f3a429d2306cd7e20496a5dce7e5b16eec`)
   - `deprecated=false disabled=false`
2. **Download, and check the installer before it runs:**

   ```zsh
   brew fetch --cask soapui
   DMG="$(brew --cache --cask soapui)"; shasum -a 256 "$DMG"
   MNT="$(hdiutil attach -nobrowse -readonly "$DMG" | awk -F'\t' '/\/Volumes\//{print $NF}')"; print -r -- "$MNT"
   codesign --verify --deep --strict "$MNT/SoapUI 5.9.1 Installer.app" && echo INSTALLER_SIGNATURE_OK
   codesign -d --verbose=4 "$MNT/SoapUI 5.9.1 Installer.app" 2>&1 | grep -E '^(Authority|TeamIdentifier)='
   spctl --assess --type execute -vv "$MNT/SoapUI 5.9.1 Installer.app"
   hdiutil detach "$MNT"
   ```

   Expected:
   - the same hash as in step 1;
   - a `/Volumes/…` path;
   - `INSTALLER_SIGNATURE_OK`;
   - `Authority=Developer ID Application: SmartBear …`, then `Authority=Developer ID Certification Authority` and `Authority=Apple Root CA`, and a `TeamIdentifier=` line;
   - `accepted`, with `source=Notarized Developer ID` and an `origin=Developer ID Application: SmartBear …` line.

   Anything else: stop, and delete the download with `rm -f "$DMG"`.
3. **Install:** `brew install --cask soapui`. It runs the installer you just checked, from the same cached file, and creates `/Applications/SoapUI-5.9.1.app`. The installer writes into the app after signing, so the installed app is not re-checked; step 2 is the check.

Done when the installer's hash, signature and notarization matched and the app is installed.

## Part B. Before the session (Terminal, no AI tool)

In each command, replace `<CHECKOUT>` and `<MANUAL_DIR>` with your folders from `03`, written in full from `/Users/…`, never with `~`.

1. **`03` Part C steps 1 to 3:**
   - the merge check;
   - `git merge --ff-only origin/main` and `uv sync --frozen`;
   - `R doctor` with no `FIX`.

   The checkout stays on `main`: Part C loads the reviewed WSDL and the two scripts from it.
2. **Run-time rules** (`03` Part C step 4), for the whole session:
   - no AI tool in any window of the terminal app;
   - AI features that send screen, terminal or clipboard content to a cloud service are off;
   - Handoff is off: System Settings > General > AirDrop & Handoff (macOS 15) or AirDrop & Continuity (macOS 26 and later), "Allow Handoff between this Mac and your iCloud devices";
   - no clipboard history tool runs, including the OS's own: on macOS 26 and later, Spotlight's clipboard history is off (System Settings > Spotlight, "Results from Clipboard") [confirm the label]. If it was on, turn it off and clear it now, and clear it again in Part D step 5;
   - no screen sharing, and no screen-recording or screen-history tool;
   - Secure Keyboard Entry is on in Terminal;
   - the Keeper app's clipboard auto-clear is on, and Keeper is unlocked only for Part C step 9 and Part D step 3;
   - Time Machine backs up manually for the session (System Settings > General > Time Machine > Options > Back up frequency: Manually). Skip this if Time Machine is not set up.
3. **Clock.**
   - System Settings > General > Date & Time: "Set time and date automatically" is on.
   - `sntp time.apple.com` shows an offset under 1 second.
4. **DNS against the record:**

   ```zsh
   dig +short iwstraining.iridium.com A; dig +short iwstraining.iridium.com AAAA
   ```

   Expected: exactly `174.68.1.46`, then nothing. Anything else: stop. SITEST may have moved, so follow `02` first.
5. **Certificate against the record** (a TLS handshake with SITEST's address only, as in `01` step 3):

   ```zsh
   openssl s_client -connect 174.68.1.46:8443 -servername iwstraining.iridium.com </dev/null 2>/dev/null | openssl x509 -noout -fingerprint -sha256
   ```

   Expected: `AE:CC:14:A4:1D:D1:6B:91:92:44:C8:91:83:AD:2B:A8:CF:89:08:B8:6F:9F:36:5D:76:D1:5E:35:84:68:ED:C7`. A different fingerprint means the certificate was renewed: stop, and re-record through `01` step 3 first.
6. **Pin the address** (it asks for your macOS password):

   ```zsh
   grep -n iridium /etc/hosts
   printf '\n%s\n' '174.68.1.46 iwstraining.iridium.com # airtimesat-manual-check' | sudo tee -a /etc/hosts >/dev/null
   sudo dscacheutil -flushcache; sudo killall -HUP mDNSResponder
   grep -c -x '174\.68\.1\.46 iwstraining\.iridium\.com # airtimesat-manual-check' /etc/hosts
   dscacheutil -q host -a name iwstraining.iridium.com
   ```

   Expected:
   - nothing from the first `grep`. If it prints a line, stop and remove that line first;
   - `1` from the second `grep`: the pin is a line of its own. The leading newline keeps it off the previous line; a blank line is harmless in `/etc/hosts`;
   - only `ip_address: 174.68.1.46` from `dscacheutil`. DNS gives the same address, so this shows only that nothing else answers.
7. **Marker,** so Part D step 3 can list every file SoapUI writes:

   ```zsh
   touch '/Users/<you>/<MANUAL_DIR>/soapui-start.marker' && ls -l '/Users/<you>/<MANUAL_DIR>/soapui-start.marker'
   ```

Done when `R doctor` is clean, the run-time rules hold, DNS and the certificate match the record, the pin is in, and the marker exists.

## Part C. The SoapUI session

1. **Start SoapUI** after the pin: `open /Applications/SoapUI-5.9.1.app`.
   - Decline any offer to send usage statistics.
   - Close the starter page.
2. **Preferences** (the Preferences toolbar button, or File > Preferences):
   - Proxy Settings: select **None**. The toolbar's Proxy button must be off too.
   - UI Settings: set the auto-save interval to 0 (off) [confirm the label].
3. **Project from the reviewed WSDL.**
   - File > New SOAP Project. Name it `manual-check`.
   - Initial WSDL: `<CHECKOUT>/src/airtimesat_platform/gateway/wsdl/sitest/provisioning.wsdl`. This is the reviewed snapshot: it has no imports, so nothing is fetched, and its only address is SITEST's (enforced by `tests/gateway/test_sitest_no_beta_host.py`).
   - Untick "Create Requests" and "Create TestSuite" if offered. OK.
4. **Test case**, from the navigator tree on the left:
   - right-click the project > New TestSuite (any name);
   - right-click the suite > New TestCase (any name). Its window opens.
5. **Step 1, the sign script.**
   - In the navigator, right-click the TestCase > Add Step > Groovy Script, named `sign`.
   - Open `<CHECKOUT>/docs/runbooks/soapui/sign.groovy` in TextEdit, then Cmd+A and Cmd+C. Click in the `sign` editor, then Cmd+V.
   - Do not edit it. Its `CALLER` is `cto.RP-2026-001`: the recorder's caller with `cto.` in place of `rec.`, which `01` rule 4 forbids for manual calls.
   - **Never press the script editor's own green Run arrow, and never press Option+Return in the editor.** Both run the script with a mock runner; it stops with `STOP RUNNER`.
6. **Step 2, the request.**
   - In the navigator again, right-click the TestCase > Add Step > SOAP Request, named `getSystemStatus`. The navigator adds the step at the end. The TestCase window's own Add Step button would insert it above the selected step.
   - Pick the operation `iwsSoapBinding` > `getSystemStatus`.
   - In the next dialog, untick every assertion and "Create optional elements".
   - **Never press this step's own green Run arrow.** It would send without signing.
7. **Teardown.** In the TestCase window, open "TearDown Script" (bottom of the window). Paste the whole of `<CHECKOUT>/docs/runbooks/soapui/teardown.groovy` the same way.
8. **Check before the run,** in the TestCase window:
   - it lists exactly two steps: `sign` first, then `getSystemStatus`;
   - TestCase Options: "Abort on Error" is ticked. It is ticked by default, and clicking a ticked box unticks it. The script also sets it;
   - the toolbar's Loop button is off.
9. **Run once.** Unlock Keeper. Press the TestCase window's green Run button (the test case's, not a step's).
   - The script first checks, before asking for anything:
     - how it was started, and that the TearDown Script is in place and compiles;
     - that no call was made yet in this SoapUI session;
     - the UTC timestamp and the HMAC-SHA1 signature, against the synthetic vector of `tests/gateway/test_signing.py`;
     - two steps in this order, the operation and the endpoint;
     - redirects off, empty elements kept, a 120 s timeout, and the proxy off.
   - Then it opens three hidden fields, one at a time. Each OK empties the clipboard, so press Keeper's copy button before every field. Click in the field, paste (Cmd+V), then OK. One dot appears per character, never the value. If no dots appear, click in the field and paste again before OK.
     1. `SITEST username`
     2. `SITEST secret key`
     3. `SP account number`: answer as you did at `R init` (`03` Part D step 1). Paste the number if you pasted one there; otherwise leave the field empty (no dots) and press OK. If you are not sure the paste worked, press Cancel (`STOP CANCELLED`, nothing is sent) and Run again.
   - Only after the last field does it stamp the UTC time, sign, and let the request go once.
10. **Read the log.** It is in the script log tab at the bottom of the SoapUI window. Expect:

    ```text
    OK self-tests: UTC timestamp, HMAC-SHA1 Base64
    OK test case: teardown, endpoint, operation, redirects off, proxy off, empty content kept
    OK signed getSystemStatus at <UTC> UTC, with|without serviceProviderAccountNumber, callerPassword empty; sending now
    OK cleared the test case properties and the request text; the sent request stays in SoapUI's memory until you quit
    RESULT …
    ```

    A `STOP …` line instead means the script stopped. The `RESULT` line says whether anything was sent. See [STOP codes](#stop-codes) and Part E.
11. **Clipboard and Keeper.** In Terminal, run `pbcopy < /dev/null`. Lock Keeper.
12. **Record.** Write the `RESULT` line and the UTC time from `OK signed` in your manual-call log in `<MANUAL_DIR>` [FILL: file name]. Then go straight to Part D.

Done when you have one `RESULT` line.

## Part D. Clean up (always, whatever the result)

Any `zsh: no matches found` or `command not found` line means that command did not run: stop, and fix it before going on.

1. **Quit SoapUI** (SoapUI > Quit). Answer **No** to every save prompt, for the project and the workspace.
2. **Remove the pin:**

   ```zsh
   sudo sed -i '' '/ # airtimesat-manual-check$/d' /etc/hosts
   sudo dscacheutil -flushcache; sudo killall -HUP mDNSResponder
   grep -c iridium /etc/hosts
   ```

   Expected: `0`.
3. **Search what SoapUI wrote for the SITEST values,** without showing them. Use one Terminal window for all of this step.
   1. List the files SoapUI wrote. If macOS asks for access to a folder or to other apps' data, choose Don't Allow.

      ```zsh
      M='/Users/<you>/<MANUAL_DIR>/soapui-start.marker'
      [[ -f $M ]] && print MARKER_OK || print NO_MARKER
      F=(${(f)"$(find "$HOME" "${TMPDIR:-/tmp}" /Applications/SoapUI-5.9.1.app -xdev \( -path "$HOME/Desktop" -o -path "$HOME/Documents" -o -path "$HOME/Downloads" -o -path "$HOME/Pictures" -o -path "$HOME/Movies" -o -path "$HOME/Music" -o -path "$HOME/Library/Containers" -o -path "$HOME/Library/Group Containers" -o -path "$HOME/Library/Mobile Documents" -o -path "$HOME/Library/Mail" -o -path "$HOME/Library/Messages" -o -path "$HOME/Library/Safari" -o -path "$HOME/.Trash" \) -prune -o -type f -newer "$M" \( -ipath '*soapui*' -o -ipath '*smartbear*' -o -name 'hs_err_pid*' \) -print 2>/dev/null)"})
      print -l -- $F; print "FILES ${#F}"
      ```

      Expected: `MARKER_OK`, the file names, then `FILES <n>` with n of at least 1. SoapUI writes `~/.soapuios/logs/soapui.log` at every start. On `NO_MARKER` or `FILES 0`, stop: the list is not valid.
   2. Paste this once into the same window. It defines the search; it does not run it yet.

      ```zsh
      HITS=()
      scan() {
        if (( ${#F} == 0 )); then print NO_FILE_LIST
        elif (( $(pbpaste | wc -c) == 0 )); then print CLIPBOARD_EMPTY
        elif [[ "$(pbpaste)" == scan ]] || pbpaste | grep -qF -e pbpaste -e 'grep '; then print CLIPBOARD_IS_A_COMMAND
        else H=(${(f)"$(pbpaste | grep -lF -f - -- $F /dev/null)"}); (( ${#H} )) && print -l -- $H; HITS+=($H); print SCAN_DONE
        fi
        pbcopy </dev/null
      }
      ```
   3. Unlock Keeper. For each value in turn (the secret key, the username, then the SP account number if you have one):
      1. press the copy button in Keeper;
      2. type `scan` by hand (do not paste it);
      3. press Return.

      Lock Keeper afterwards.

   Expected for each value: `SCAN_DONE` alone.
   - `CLIPBOARD_EMPTY` or `CLIPBOARD_IS_A_COMMAND`: that value was not searched. Copy it again and type `scan` again.
   - `NO_FILE_LIST`: run sub-step 1 again in this window.
   - File names before `SCAN_DONE`: that value is in those files, in clear. Step 4 deletes them. If it was the secret key, it is [`06`](06_incidents.md) case 3 (Sev1): record your decision on rotation. The copy never left this FileVault disk. Tell an agent only that a file matched, never its content.
4. **Remove SoapUI and its files:**

   ```zsh
   rm -rf -- ~/.soapuios ~/soapui-settings.xml ~/default-soapui-workspace.xml ~/Library/Application\ Support/SoapUI-*(N)
   (( ${#HITS} )) && rm -f -- $HITS
   brew uninstall --zap --cask soapui
   for f in ~/.soapuios(N) ~/soapui-settings.xml(N) ~/default-soapui-workspace.xml(N) ~/Library/Application\ Support/SoapUI-*(N) /Applications/SoapUI-5.9.1.app(N) $HITS; do [[ -e $f ]] && print "LEFT: $f"; done; print CHECK_DONE
   ```

   - `rm` deletes SoapUI's own files and every file `scan` matched.
   - `brew` then moves the app to the Trash; it holds no SITEST value.
   - Expected: `CHECK_DONE` and no `LEFT:` line.
   - Reinstalling next time is Part A again.
5. **Finish.**
   - Run `rm '/Users/<you>/<MANUAL_DIR>/soapui-start.marker'`.
   - If Spotlight's clipboard history was on during the session, clear it.
   - Set Time Machine back to automatic.
   - Keeper is locked.

Done when the pin is gone, each value search printed `SCAN_DONE`, `CHECK_DONE` printed no `LEFT:`, and Time Machine is back to automatic.

## Part E. What the result means, and what happens next

Share only the `RESULT` line.

For every result except `outcome=ok`:
- **#21 stays a draft:** do not merge it.
- Its CI change (the one `checks` job) moves to its own PR, together with the ruleset update.

| `RESULT` | Meaning | Next |
|---|---|---|
| `outcome=ok` | IWS accepts the empty `callerPassword`. The caller differs from the recorder's only in its prefix. Design #36 holds; the live run confirms the `rec.` caller | 1. Update the `main` ruleset to `checks`, `tests` and `recorder-check` (`docs/SETUP_CHECKLIST.md`). 2. Review #21 line by line, note the `RESULT` line and its date in its description, then mark it ready and merge it. 3. `03` Part C (merge check, `uv sync --frozen`, `R doctor`), then `R incident clear 1`. 4. `04` from "Before" step 2: `R check recording-plans/RP-2026-001.yaml`, the dry run, the live run, the PR, the backup |
| `outcome=FIELD` with `auth_fields_named` including `callerPassword`, or `mentions_password=yes` | An empty value is not enough; IWS likely wants an SPNet password | Design #36 reopens: an SPNet password is your decision. Send the line. No retry |
| `outcome=FIELD` with `auth_fields_named=none` and `mentions_password=no` | The same code as the first run's fault, and the field is unknown. The empty `callerPassword` did not clear it | Design #36 is not confirmed and reopens. Send the line. No retry |
| `outcome=FIELD` naming only other fields | IWS refuses another field (for `caller`, its format) | Send the line. No retry |
| `outcome=AUTH` | IWS refused the credential or the signature | No retry (lockout risk). Send the line; next session, check the Keeper values against `R init` |
| `outcome=SYS`, `CONFIG` or `unknown` (including `not_soap12`, `not_xml`, `no_fault_no_answer`) | The reply cannot be classified from codes | Send the line. No retry |
| `unreadable: …` | The call was signed and may have been sent. The reply could not be classified | Send the line. No retry |
| `redirect_not_followed` | SITEST answered with a redirect. The signed request was not resent | Never resend. Send the line; `02` may apply |
| `no_response` | No HTTP response: a connection or TLS error, a timeout after sending, or Cancel. IWS may have received and processed the call: treat it as made | Send the line. No second attempt in this session. Only you decide on one, after Part D, in a new session (Parts A to C again) |
| `sent_unsigned` | A request went out before or without the sign step (wrong step order, or Abort on Error off). It carried no SITEST value | Never resend. Go to Part D and send the line |
| `already_sent` | A repeat run. It sent nothing | Report the first `RESULT` line, then go to Part D |
| `not_sent` | The script stopped before signing. Nothing was sent | Fix the `STOP` code and press Run again, in the same session |

## STOP codes

With the steps in order, every `STOP` comes before the request. The `RESULT` line says whether anything was sent. Each code names a check or a field, never a value.

| Code | Fix |
|---|---|
| `RUNNER` | You ran the script from its editor (Run arrow or Option+Return). Nothing was signed or sent. Press the TestCase window's Run button |
| `TEARDOWN` | The TearDown Script is missing or incomplete. Paste the whole of `teardown.groovy` again (Part C step 7), then Run |
| `ALREADY_SENT` | One call per SoapUI session, and it has been made. Go to Part D |
| `SELF_TEST_TIMESTAMP`, `SELF_TEST_SIGNATURE` | The script changed while pasting. Paste it again, whole |
| `STEPS` | The test case must hold exactly two steps, in this order: `sign`, then the SOAP request. Fix the order in the navigator, then Run |
| `OPERATION` | The request step is not `getSystemStatus`. Delete it and add it again (Part C step 6) |
| `ENDPOINT` | The request's endpoint is not exactly `https://iwstraining.iridium.com:8443/iws-current/iws`. Pick that one in the request's endpoint field; never type another host |
| `REQUEST_SETTINGS` | SoapUI did not take the settings. Select the request step. In its properties panel (bottom left), set "Follow Redirects" to false, "Remove Empty Content" to false and "Timeout" to 120000, then Run |
| `PROXY` | SoapUI's proxy is on. Set Preferences > Proxy Settings to None, make sure the toolbar's Proxy button is off, then Run |
| `CANCELLED` | You pressed Cancel in a field |
| `EMPTY`, `SPACE` or `INVALID` + a field name | The pasted value was empty, started or ended with a space, held a control character, or (username or SP account number) held `<`, `>` or `&`. Copy it again from Keeper, then Run. If it persists, stop and tell an agent the code |
| `SAME_VALUE` + field names | Two fields got the same paste. Press Keeper's copy button before each field, then Run |

## How the scripts were checked

All offline, with synthetic values only, before this runbook's PR:

- **Inside SoapUI 5.9.1's own code** (its release jar and its dependencies, Groovy 3.0.19), in a network namespace with no outside network. `/etc/hosts` there sent the SITEST name to a local HTTPS stand-in.
  - The real TestCase run sent one request. It had the six fields in the WSDL's order, `callerPassword` empty, a valid signature, and the Content-Type `application/soap+xml;charset=UTF-8;action="getSystemStatus"`. The secret key never went over the wire.
  - A second run, and a new TestCase in the same session, sent nothing.
  - A 302 was not followed.
  - The editor's mock runner, a missing teardown and an active proxy each stopped before any prompt.
  - A request step placed first was reported as `sent_unsigned`.
  - SoapUI's own log files under `~/.soapuios/logs` held none of the three values.
- **The hidden field,** on a virtual display: focus starts in the field, a paste lands without a click, and the clipboard is empty after OK. Tested on Groovy 2.4, 3.0 and 4.0.
- **Every `STOP` code and `RESULT` row,** against fake SoapUI objects on Groovy 2.4, 3.0 and 4.0 (32 checks).
- **The Part D commands** in zsh 5.9 on a synthetic home folder. They cover an empty clipboard, the command text on the clipboard, a missing marker, a match, and a value that is absent.
- **In CI:** `tests/gateway/test_runbook_soapui.py`.
- **Not checked:**
  - the macOS screens and their labels (marked [confirm]);
  - the real installer's signature and notarization (Part A step 2 checks them);
  - the macOS-only commands (`dscacheutil`, `sntp`, BSD `sed`);
  - Keeper's own behaviour.
