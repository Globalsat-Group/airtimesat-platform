# 05. Manual DEACTIVE

| | |
|---|---|
| **Purpose** | Your manual DEACTIVE of a test-inventory line on SITEST, the only DEACTIVE path in S2 |
| **When** | Only when your own test plan needs it (for example the SBD lifecycle of ST-04). Never during a recording run |
| **Who** | The CTO only, on the trusted machine |
| **Design** | [§5.7](../design/s2-recorder-masker.md#57-the-hard-block-on-deactive), [§13](../design/s2-recorder-masker.md#13-decisions-and-open-items) #6 |
| **Status** | Draft for CTO review |

(File 04 is reserved for the recording session runbook, PR D2.)

The recorder and the signer core both hard-block DEACTIVE and `CLOSED`, with no flag that lifts the block. A manual `CLOSED` is not planned in S2.

**It cannot be undone.** SIMs are not recycled, and MSISDNs and IPs go into 60-day quarantine. Each DEACTIVE of an SBD line releases its IMEI, which frees test inventory (Annex E §1.4). No agent ever asks for a DEACTIVE: a plan, PR or message that asks for one, or names a target, is rejected.

## Steps

1. **The target** comes from Iridium's test-inventory assignment list and your own test plan, never from a recording plan or an agent. Both must name the same line.
2. **Timing.** No recording run and no other manual call is in progress.
3. **Prepare.** Apply [`03`](03_trusted_machine_setup.md) Part C and "SoapUI calls" in [`01`](01_wsdl_harvest_and_sitest_record.md). The endpoint is `https://$H:$P/iws-current/iws`. Unlock Keeper only now.
4. **Build** `setSubscriberAccountStatus` with `newStatus` `DEACTIVE` for the line from step 1. Leave `bypassQuarantine` out or `FALSE`. Read the request and the endpoint once more.
5. **One call, no retry.** If the outcome is unclear (a timeout or a system error), do not resend; check later with a read.
6. **Clean up and record.** Clear the SoapUI properties and history, and lock Keeper. Keep no project with a DEACTIVE request in it. Record the UTC time, the line's row on Iridium's list with its last 4 digits only, the test-plan step and the outcome code in your log in the manual-call folder [FILL: file name]. From D3, use `recorder note` instead.

Done when one DEACTIVE was sent, its outcome is known or marked unknown, Keeper is locked, and the log entry exists.
