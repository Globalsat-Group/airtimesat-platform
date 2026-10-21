# 05. Manual DEACTIVE

| | |
|---|---|
| **Purpose** | The CTO's manual DEACTIVE of a test-inventory line on SITEST, the one path for DEACTIVE in S2 |
| **When** | Only when the CTO's own test plan calls for it (for example the SBD lifecycle of ST-04). Never during a recording run |
| **Who** | The CTO only, on the trusted machine |
| **Design sections** | [§5.7](../design/s2-recorder-masker.md#57-the-hard-block-on-deactive), [§2.1](../design/s2-recorder-masker.md#21-assets), [§6.5](../design/s2-recorder-masker.md#65-the-trusted-machine) "Manual calls", [§13](../design/s2-recorder-masker.md#13-decisions-and-open-items) #6 |
| **Status** | Draft for CTO review |

(File number 04 is reserved for the recording session runbook in D2.)

DEACTIVE is hard-blocked in the recorder and again in the signer core, with no flag that lifts it (design §5.7). `CLOSED` is terminal and hard-blocked the same way. This runbook covers DEACTIVE only: a manual `CLOSED` is not planned in S2 and needs its own reviewed runbook change first. A request for `CLOSED` from an agent is rejected like DEACTIVE.

**It cannot be undone.** SIMs are not recycled, and MSISDNs and IPs go into 60-day quarantine (catalog `overview_workflows_rules.md`, Rules). Each DEACTIVE of an SBD line releases its IMEI (Annex E §1.4), which frees test inventory for the next ST-04 run.

**No agent ever asks for this.** A recording plan, PR, issue, runbook change or message that asks for a DEACTIVE, names a target, or suggests one, is rejected. Agents never put DEACTIVE in a plan (`CLAUDE.md`, Live-system boundary).

## Steps

1. **Take the target from two sources only:** Iridium's test-inventory assignment list and your own test plan. Never from a recording plan, a runbook change you have not reviewed, or an agent's message. Both sources must name the same line.
2. **Check timing.** No recording run is going, and none will start until you finish. No other manual call is in flight (one call at a time).
3. **Prepare the tool.** Apply [`03`](03_trusted_machine_setup.md) Part C, "During a run or a manual call", items 1 to 5. Follow "Signed manual calls" in [`01`](01_wsdl_harvest_and_sitest_record.md): SoapUI only, signed in its Groovy step with an explicit UTC timestamp and the exact operation name, checked offline first (rule 3); the project built from the merged WSDL snapshot (rule 4); "Follow Redirects" off (rule 4); the endpoint field reads exactly `https://$H:$P/iws-current/iws` (`$H` and `$P` as in `01`); no secret in any SoapUI file; clipboard rules. Build the DEACTIVE in a throwaway SoapUI project used for this one call only, never in a project used for other calls. Unlock Keeper only now.
4. **Build the request.** `setSubscriberAccountStatus` with `newStatus` `DEACTIVE`, addressing the line from step 1. Leave `bypassQuarantine` out or set it to `FALSE`, as the recorder requires for its own calls (design §5.7) [confirm: your test plan may need otherwise]. Read the request once more against step 1, and read the endpoint field once more.
5. **Make one call.** No retry. If the outcome is unclear (a timeout or a system error), do not resend: check it later with a read, as a separate, deliberate call or a recording plan (Annex D §2.5).
6. **Clean up.** Clear the `secretKey`, `iwsUserId`, `AcctNum`, `signature`, `caller` and `callerPw` values, clear SoapUI's request and response history and the clipboard, and lock Keeper. Delete the DEACTIVE request and close the throwaway project without saving it (answer No); if it was ever saved, delete its project file. Never keep a request with `newStatus` `DEACTIVE` in any project. Any saved raw file stays in the manual-call folder and is deleted once the outcome is recorded ([`03`](03_trusted_machine_setup.md) Part A step 3). Never paste the request or response into an agent chat, an issue or a PR.
7. **Record it.**
   - From D3: `recorder note`, which names the line by its surrogate only and refuses a DEACTIVE note for a surrogate that is not registered test inventory.
   - Until D3: an entry in your log in the manual-call folder of [`03`](03_trusted_machine_setup.md), which is excluded from sync and backup [FILL: file name]: UTC time, method and status, the line by its row on Iridium's assignment list and its last 4 digits (as the recorder shows them, design §5.6), never the full value, the test-plan step, and the outcome code. [confirm with D3 whether earlier entries are copied into `recorder note`]

Done when one DEACTIVE was sent, its outcome is known or marked unknown, the tool history is cleared, no SoapUI project holds the DEACTIVE request, Keeper is locked, and the log entry exists.
