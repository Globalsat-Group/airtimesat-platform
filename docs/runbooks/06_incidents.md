# 06. Incidents

| | |
|---|---|
| **Purpose** | What to do when the recorder blocks, a leak is caught, a secret or key may be compromised, an unreviewed merge reaches `main`, or a call reaches the wrong environment |
| **When** | As soon as a case below happens |
| **Who** | The CTO only |
| **Design** | [§8.3](../design/s2-recorder-masker.md#83-scanning-before-git), [§8.4](../design/s2-recorder-masker.md#84-runtime-detector-block-and-stop), [§6.2](../design/s2-recorder-masker.md#62-keys-and-the-secret), [§2.1](../design/s2-recorder-masker.md#21-assets) |
| **Status** | Draft for CTO review |

Who to tell: a second person for any Sev1 [FILL], Legal for personal data exposure [FILL], Iridium for a secret rotation or a wrong-environment write [FILL: contact and channel], GitHub Support for a purge [FILL].

What an agent may get: the refusal code, the call id, the detector id and the element path. Never a value, raw output, the secret or a key.

**If the trusted machine or Keeper may itself be compromised, start here.** From a clean device, change the Keeper master password and end its other sessions. Revoke the GitHub tokens and SSH keys the laptop held. Wipe the laptop, or move to a clean device, and redo `03` Parts A and B. Only then store new secrets or keys (cases 3 and 4).

## 1. `MASKING_BLOCKED` or another block

1. The run stops and writes nothing for that call. The terminal shows `CALL_BLOCKED` with the code, the call id and the detector id.
2. The method stays refused until the fix merges and you run `recorder incident clear <id>` ([`04`](04_recording_session.md)). After `STAGING_SCAN_HIT`, every run stays refused until you clear it. A `CALL_FAILED` (a refusal, a timeout, an outage page, a disk error) refuses nothing: fix the cause and run again.
3. Give the agents the code, call id, detector id and element path; they propose the fix in a PR.
4. If you need the raw response, reproduce it by hand (SoapUI, under `01` "SoapUI calls"), for a read only, in the manual-call folder. Delete the raw file once the fix is verified. Never reproduce a write or a refused call.

Done when the fix is merged, the incident is cleared, and a new run passes.

## 2. A leak caught in CI: Sev1

CI runs after the push, so the data is already at GitHub (design §8.3). A leak caught before the push (the recorder's own scan or the hook) is not a Sev1: unstage and delete the file, and fix the cause as in case 1.

1. Stop all runs. Tell the people above.
2. Remove the bad commit from every branch that holds it: close the PR and delete the branch, or rewrite and force-push it. If it reached `main`, lift the force-push block only for the rewrite [confirm the ruleset steps], then restore it, and re-clone the trusted checkout.
3. Delete the workflow logs of the affected runs.
4. Once no branch holds the commit, ask GitHub Support to purge cached views.
5. Treat agent transcripts that read the file as exposed; tell Legal. If gitleaks found a secret, also do case 3.

Done when no branch holds the commit, GitHub confirmed the purge, and the cause is fixed.

## 3. Suspected SITEST secret leak: Sev1

The same credential works on Beta, so this is also a Beta leak.

1. Stop all runs and manual calls.
2. Remove the exposed copy without printing it.
3. Ask Iridium to rotate the secret (procedure and lead time unknown, re-plan §11.1 Q4). Never use `resetIWSUserPassword`.
4. Store the new secret in its Keeper record only.

Done when Iridium confirms the old secret no longer works.

## 4. Suspected vault or `K_mask` compromise: Sev1

Committed recordings could then be de-pseudonymized (design §2.1).

1. Stop all runs. Tell the people above and Legal.
2. Generate new keys (`recorder keys init`, `03` Part D), start a new vault (move `vault.sqlite` out of `data_dir`; the next run creates a new one), replace the escrow, and take the recordings again (design §6.2).
3. Delete the old vault and its backups once Legal confirms nothing must be kept.

Done when new keys are in Keeper and escrow, and the recordings agents need are taken again.

## 5. An unreviewed merge on `main`

The merge check of `03` Part C lists a merge that is not a PR you reviewed and merged.

1. Do not sync, run or commit from it. Stay on your last checked SHA.
2. Revert it from GitHub (the PR's Revert button), review the revert, and merge it.
3. Find in the GitHub audit log who merged it, and revoke that access.
4. If any of its code ran on the trusted machine, follow "start here" above, then cases 3 and 4.

Done when the merge is reverted, the access revoked, and the checkout synced past the revert.

## 6. A call reached Beta or production by mistake

1. Stop all calls and runs. Note the UTC time, the method, and read or write, in Keeper notes only.
2. A write is a Sev1: tell the people above and Iridium. Do not resend or undo anything on your own.
3. Fix the cause in a reviewed change to these runbooks before the next manual call.

Done when the call is recorded, a write is reported, and the cause is fixed.
