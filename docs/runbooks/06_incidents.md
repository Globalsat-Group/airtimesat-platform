# 06. Incidents

| | |
|---|---|
| **Purpose** | What the CTO does when the recorder refuses or blocks, when a leak is caught, when the SITEST secret, the vault or `K_mask` may be compromised, when an unreviewed merge reaches `main`, and when a call reaches Beta or production by mistake |
| **When** | As soon as one of the cases below happens |
| **Who** | The CTO only |
| **Design sections** | [§8.4](../design/s2-recorder-masker.md#84-runtime-detector-block-and-stop), [§8.3](../design/s2-recorder-masker.md#83-scanning-before-git), [§6.2](../design/s2-recorder-masker.md#62-keys-and-the-secret), [§2.1](../design/s2-recorder-masker.md#21-assets), [§5.1](../design/s2-recorder-masker.md#51-how-a-run-works) |
| **Status** | Draft for CTO review |

## Who to tell

| Case | Tell |
|---|---|
| Any Sev1 below | [FILL: deputy or second person, if any] |
| Personal data exposure | [FILL: Legal or data-protection contact] |
| SITEST secret rotation | [FILL: Iridium contact and channel for rotation] |
| A write that reached the wrong environment | [FILL: Iridium contact] |
| GitHub purge | [FILL: GitHub Support route for the organization] |

What you may tell an agent: the refusal code, the call id, the detector id and the element path. Never a value, raw output, the secret or a key.

## 1. `MASKING_BLOCKED` and other refusals

1. **What you see.** The run stops. The terminal shows `MASKING_BLOCKED`, the call id and the detector id (a detector hit or an unknown element). Nothing was written for that call, and the raw bytes were discarded. An incident row holds the element path and detector id, never the value.
2. **Other stops.** A hard block (`ALWAYS_REFUSED_DEACTIVE`, `ALWAYS_REFUSED_BULK`), a transport or reply error (for example `TLS_FAILED`, `TRANSPORT_TIMEOUT`, `CLOCK_SKEW`, or `TOO_MANY_CONNECTIONS`, IWS's "Too many connections!") or any failure inside masking also stops the run and writes nothing for that call. Earlier calls of the run may already have reached SITEST. An unissued surrogate (`IDENTIFIER_NOT_ISSUED`) refuses the whole plan before any IWS call (design §5.5): no call was sent. A plan with a blocked call fails `recorder check` in CI (design §5.7), so a hard block at run time means the plan got past that check: do not run it again until you know how.
3. **The method stays refused** in later runs until the fix merges (for example a new override or message template) and you run `recorder incident clear <id>` (D2).
4. Give the agents the code, call id, detector id and element path. They propose the fix in a PR, and you review it.
5. If you need the raw response to understand it, reproduce it **by hand only**, outside the recorder, and **only for a read method**: one call, no retry, with [`01`](01_wsdl_harvest_and_sitest_record.md) "Signed manual calls" (rule 4 picks the provisioning or reporting endpoint by method), [`03`](03_trusted_machine_setup.md) Part C "During a run or a manual call", [`05`](05_manual_deactive.md) steps 2 and 6, and the manual-call folder. Take the target from your own records: no tool unmasks a surrogate. Never reproduce a write, nor any refused or hard-blocked call: for a write, check the resulting state with a read instead. A write's free-text fault message (for a message template, design §4.4) cannot be read this way; that needs a new decision or a reviewed plan, never a resend. There is no raw mode and no debug flag. Delete the raw file once the fix is verified ([`03`](03_trusted_machine_setup.md) Part A step 3). Verify the fix through the recorder afterwards.

Done when the fix is merged, the incident is cleared, and a new run passes.

## 2. A leak caught before git

The recorder's end-of-run scan, the pre-commit hook or your own reading finds a real value or a key in a staged or masked file.

1. Do not commit or push. The recorder already deletes that run's staging folder on a hit. Otherwise unstage the file first (`git restore --staged <path>`, or `git rm --cached <path>`), then delete it, and check `git status` shows nothing staged. Deleting the file alone leaves it in the index, where `git commit --no-verify` would record it. If you already committed it locally and did not push, delete that branch (`git switch main && git branch -D <branch>`). Then, optionally, drop the leftover copy from `.git`: `git reflog expire --expire-unreachable=now --all && git gc --prune=now`. Run it after the branch deletion: the reflog keeps a deleted commit, and plain `gc` keeps what the reflog reaches. It also drops reflog recovery of every other unreachable commit.
2. Treat it as a masking defect: give the agents the file path, line and detector id (never the value), and fix it as in case 1.

Done when nothing is staged or committed with the value, the file is gone, and the fix PR is open.

## 3. A leak caught in CI: Sev1

CI runs after the push, so the data is already at GitHub (design §8.3).

1. Stop all runs. Tell the people above. If the file reached `main`, also stop every agent session and suspend the bot's write access (`docs/SETUP_CHECKLIST.md`, step 9) for the whole window; otherwise stop agent work on the affected branches.
2. Remove the file from GitHub's history:
   - **Find every branch that holds it.** After `git fetch origin`, list every remote branch that contains the bad commit: `git branch -r --contains <sha>`. Each one keeps the file reachable at GitHub, so GitHub's purge cannot remove it.
   - **On PR branches only** (the usual case: CI catches it before merge). For each listed branch, close its PR and delete the branch, or rewrite the branch and force-push; the `main` rulesets do not cover PR branches.
   - **Merged on `main`** (rare). `main`'s ruleset blocks force pushes, and your bypass is for pull requests only, so a force-push to `main` is rejected even for you (`docs/SETUP_CHECKLIST.md`, steps 7 and 7b). Turn off "Block force pushes" in the `main` ruleset, and Restrict updates in `main-humans-merge` if it blocks the push, for the rewrite only [confirm the exact settings]. Rewrite the history to remove the file from every commit [confirm the tool, for example `git filter-repo`] and force-push. Then restore both rulesets exactly as in steps 7 and 7b and re-run their Done-when checks. Delete or rewrite every other listed branch and close its PR.
   - **Your trusted checkout after a rewrite of `main`.** Its local `main` and any branch cut from it still hold the file, and pushing any of them uploads it again. Once the rulesets are restored, clone the repository into a new folder, delete the old checkout, redo [`03`](03_trusted_machine_setup.md) Part A steps 6 to 8 (first merge check, `uv sync --frozen`, hook), and record a new last checked SHA. Never pull or merge the old history.
   - **Agents.** Tell them to discard every clone made before the rewrite, and to rebase or close every PR opened before it.
3. Only when no remote branch contains the bad commit any more, ask GitHub Support to purge cached views and pull-request references (`refs/pull/<n>`).
4. Agent sessions may have read the file: treat their transcripts as exposed, and tell Legal.
5. If gitleaks found a secret, also follow case 4.
6. Fix the cause as in case 1 before the next run.

Done when no branch at GitHub contains the bad commit, both rulesets are restored and checked, the bot's access is back, the trusted checkout is a fresh clone (if `main` was rewritten), GitHub has confirmed the purge, and the cause is fixed.

## 4. Suspected SITEST secret leak: Sev1

The same credential works on Beta, so a SITEST leak is also a Beta leak (design §2.1, §6.2).

1. Stop all recording runs and manual calls.
2. Ask Iridium to rotate the secret. The procedure and lead time are unknown (re-plan §11.1 Q4) [FILL: the channel, once known].
3. Never use `resetIWSUserPassword`. It is always refused, for the recorder and for agents (design §5.4).
4. When Iridium issues the new secret, store it in its Keeper record only.
5. If the leak came through Keeper or the trusted machine, also follow case 5.

Done when Iridium confirms the old secret no longer works.

## 5. Suspected vault or `K_mask` compromise: Sev1

A `K_mask` compromise equals a vault compromise for numeric types, which can be rebuilt by brute force (design §2.1). The masked recordings at GitHub and in agent transcripts could then be de-pseudonymized: a personal data exposure, which is a Sev1 (re-plan §8.1).

1. Stop all runs. Tell the people above.
2. Generate new keys (`recorder keys init`, D2), start a new vault, and take the recordings again (design §6.2). Replace the "masker keys" record; do not add a second set beside it [confirm with D2]. Old surrogates can no longer be named in plans.
3. If Keeper or the machine was the route, also replace the age backup key ([`03`](03_trusted_machine_setup.md) Part B step 2) and its recipient in the recorder configuration.
4. Update the escrow with the new keys, made as in `03` Part B step 3, and destroy the old escrow copies.
5. Tell Legal: committed recordings were pseudonymized under the compromised keys.
6. Once Legal confirms no copy must be kept, delete the old vault file and the old backup attachments in Keeper: they still decrypt real values under the old keys.
7. If Keeper or the machine was the route, also follow case 4.

Done when new keys (and, if needed, a new backup key) are in Keeper and the escrow, the old vault and backups are handled as Legal decided, and the recordings agents need are taken again.

## 6. An unreviewed merge on `main`

The check of [`03`](03_trusted_machine_setup.md) Part C (or Part A step 6) lists a merge that is not a PR you reviewed and merged, or one of your own PRs holds a commit you did not push (`01` step 9, `02` step 9). `main` is trusted only as far as only you merge into it (design §6.5).

1. Do not sync, run or commit from it. Stay on your last checked SHA.
2. Revert it by a PR you review and merge. For one of your own PRs that is not merged: close it, and redo the change on a new branch from your checked `main`.
3. Check the GitHub audit log for who merged it, and revoke the session, token or app access that did [FILL: where the organization's audit log is].
4. If any code from it ran on the trusted machine (a sync, a hook, a run), treat the machine as compromised: follow case 4 and case 5. Rebuild the virtual environment and reinstall the hook from a checked commit [confirm what else to check].

Done when the merge is reverted, the access that made it is revoked, and, if its code ran, cases 4 and 5 are done.

## 7. A call reached Beta or production by mistake

For example a SoapUI endpoint or a WSDL Explorer entry that was not SITEST's. The shared credential works on Beta, so such a call may succeed.

1. Stop all calls and runs.
2. Note the UTC time, the method, and whether it was a read or a write, in your Keeper notes only. No host name in git, an issue or an agent chat.
3. A write is a Sev1 (re-plan §8.1, wrong or unintended IWS write). Tell the people above and Iridium, and agree with Iridium how the state is checked [confirm]. Do not resend or undo anything on your own.
4. Find why the endpoint check failed ([`01`](01_wsdl_harvest_and_sitest_record.md) "Signed manual calls", rule 4), and fix the runbook or the setup in a reviewed PR before the next manual call.

Done when the call is recorded in Keeper notes, a write is reported and checked, and the cause is fixed.
