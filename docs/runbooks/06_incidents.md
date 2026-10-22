# 06. Incidents

| | |
|---|---|
| **Purpose** | What to do when the recorder blocks, a leak is caught, a secret, key, age passphrase or `.age` file may be compromised or lost, an unreviewed merge reaches `main`, or a call reaches the wrong environment |
| **When** | As soon as a case below happens |
| **Who** | The CTO only |
| **Design** | [§8.3](../design/s2-recorder-masker.md#83-scanning-before-git), [§8.4](../design/s2-recorder-masker.md#84-runtime-detector-block-and-stop), [§6.2](../design/s2-recorder-masker.md#62-keys-and-the-secret), [§2.1](../design/s2-recorder-masker.md#21-assets) |
| **Status** | Draft for CTO review |

Who to tell: a second person for any Sev1 [FILL], Legal for personal data exposure [FILL], Iridium for a secret rotation or a wrong-environment write [FILL: contact and channel], GitHub Support for a purge [FILL].

What an agent may get: the refusal code, the call id, the detector id and the element path. Never a value, raw output, the secret or a key.

**If the trusted machine or Keeper may itself be compromised, start here.** From a clean device, change the Keeper master password and end its other sessions. Revoke the GitHub tokens and SSH keys the laptop held. Wipe the laptop, or move to a clean device, and redo `03` Parts A and B with a new age passphrase. Then follow cases 3 and 4, and `03` Part D, which makes a new identity under the new passphrase.

## 1. `MASKING_BLOCKED` or another block

1. The run stops and writes nothing for that call. The terminal shows `CALL_BLOCKED` with the code, the call id, the element path, the detector id and, when IWS answered, `outcome=`: `ok`, or for a SOAP fault its error code (`AUTH`, `CONFIG`, `FIELD`, `SYS`) or `unknown`. The outcome is an enum, never text, so you can share it. For a block recorded before the terminal showed it, read it from the run log, read-only (this prints no secret):

   ```zsh
   sqlite3 -readonly <DATA_DIR>/vault.sqlite "SELECT call_id, decision, code, outcome FROM run_log ORDER BY id DESC LIMIT 3;"
   ```
2. The method stays refused until the fix merges and you run `recorder incident clear <id>` ([`04`](04_recording_session.md)). After `STAGING_SCAN_HIT`, every run stays refused until you clear it. A `CALL_FAILED` (a refusal, a timeout, an outage page, a disk error) refuses nothing: fix the cause and run again.
3. Give the agents the code, call id, detector id, element path and outcome; they propose the fix in a PR. A block on a SOAP fault means two things to fix: the masking of that fault, and whatever made IWS answer with a fault (the outcome says what kind).
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
4. Store the new secret in its Keeper record. Then `rm <DATA_DIR>/sitest.json.age` and run `R init` with the same arguments: it asks only for the SITEST values, from the new record (`03` Part D, "To redo the SITEST file").

Done when Iridium confirms the old secret no longer works and only the new `sitest.json.age` exists.

## 4. Suspected vault or `K_mask` compromise: Sev1

Committed recordings could then be de-pseudonymized (design §2.1).

1. Stop all runs. Tell the people above and Legal.
2. Move `masker-keys.json.age` and `vault.sqlite` into a new folder inside `data_dir` (`mkdir -m 700 <DATA_DIR>/retired-<UTC>`), which stays out of sync and backup (the recorder reads only `data_dir/vault.sqlite`). Run `R init --new-keys` with the same arguments: with no vault and no keys file, it makes new keys (the next run creates a new vault). `--new-keys` is for this step only. Note the new `MASKER_KEYS_SHA256`, replace the Keeper and escrow copies of `masker-keys.json.age`, and take the recordings again (design §6.2). If the identity's passphrase may be exposed too, follow case 7 first.
3. Delete the old vault, the old keys file and the old backups once Legal confirms nothing must be kept.

Done when the new `masker-keys.json.age` is in Keeper and escrow, and the recordings agents need are taken again.

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

## 7. The age passphrase or an `.age` file exposed or lost

1. **Lost** (a deleted file, a dead disk). Restore in this order, and run `R init` only at step 1.3:
   1. **The configuration**, if missing: `mkdir -m 700 ~/.config/airtimesat` if needed, then create `~/.config/airtimesat/recorder.toml` (mode 600) with exactly these four lines, the recipient from the notes of the "Recorder age files" Keeper record (`03` Part D step 2):

      ```toml
      data_dir = "<DATA_DIR>"
      checkout = "<CHECKOUT>"
      backup_recipient = "<age1… from the Keeper record>"
      backup_dir = "<BACKUP_DIR>"
      ```

      A wrong recipient is refused at the next run with `IDENTITY_RECIPIENT_MISMATCH`. After correcting it, `rm <DATA_DIR>/sitest.json.age` if step 1.3 made it under the wrong recipient, and run `R init` again.
   2. **`recorder-identity.age` and `masker-keys.json.age`**, if missing: copy them back into `data_dir` from the "Recorder age files" Keeper record or from escrow. The passphrase: from its Keeper record or escrow.
   3. **`R init`** with the same arguments. It makes `sitest.json.age` again from the SITEST record if it is missing, and must print `EXISTS` for the other files and the `MASKER_KEYS_SHA256` you noted. `INIT_KEYS_MISSING`: step 1.2 is not done; never add `--new-keys` here. Another digest: stop; the keys file is not the one the vault and the recordings use.
   4. **The vault**, if `data_dir` has no `vault.sqlite`: put the newest `vault-<UTC>.sqlite.age` from the "Recorder vault backups" record into `<BACKUP_DIR>`, then run the one `age -d` that rule 4 of `03` allows:

      ```zsh
      age -d -i <DATA_DIR>/recorder-identity.age -o <DATA_DIR>/vault.sqlite <BACKUP_DIR>/vault-<UTC>.sqlite.age
      ```

      age asks once, `Enter passphrase for identity file`. The output goes to the file (`-o`), never the screen, and the vault's values are themselves encrypted. This is also the restore test of the S2 exit (design §6.3).
   5. `R doctor` prints no `FIX`, and `R run <plan> --dry-run` passes.

   **Every copy of `recorder-identity.age` lost** (data folder, Keeper, escrow): `masker-keys.json.age`, `sitest.json.age` and every vault backup can no longer be opened, and the keys are lost. `mkdir -m 700 <DATA_DIR>/retired-<UTC>` and move into it whichever of `~/.config/airtimesat/recorder.toml`, `masker-keys.json.age`, `sitest.json.age` and `vault.sqlite` exist. Run `R init --data-dir <DATA_DIR> --backup-dir <BACKUP_DIR>`: it asks for the SITEST values and a new passphrase, and makes a new identity, configuration, keys and SITEST file. Note the new `RECIPIENT` and `MASKER_KEYS_SHA256` (`03` Part D step 2), replace the Keeper and escrow copies, delete the old vault backups (they cannot be opened), and take the recordings again, as in case 4 (design §6.2).
2. **Exposed passphrase** (typed into the wrong window, seen, pasted): stop all runs. Create the new passphrase in a new Keeper record, and keep the old record until this step is done. Then, in the session shell, after `03` Part C:

   ```zsh
   R rekey
   ```

   It asks for the old passphrase once, then for the new one twice: wait for each prompt before typing. It decrypts both secrets files into its memory, makes a new identity under the new passphrase, encrypts both files to it (the keys and the SITEST values stay the same), moves the three old files into `data_dir/retired-<UTC>` with a copy of the configuration, and points the configuration at the new recipient. It prints `RETIRED`, `RECIPIENT` and `MASKER_KEYS_SHA256`: note the new recipient and digest in the "Recorder age files" record (`03` Part D step 2). If age printed an autogenerated passphrase, follow rule 3 of `03` before anything else. Then:
   1. `R doctor` prints no `FIX`, and `R run <plan> --dry-run` opens with the new passphrase.
   2. `R backup`, and attach the new backup to the "Recorder vault backups" record. Older backups are encrypted to the old identity: delete them from Keeper and `backup_dir`.
   3. Replace the Keeper and escrow copies of `recorder-identity.age` and `masker-keys.json.age`.
   4. Only then delete the `retired-<UTC>` folder and the old passphrase record.

   `REKEY_FAILED` or `REKEY_IN_PROGRESS`: nothing was moved; fix the cause (for example a full disk, or a `.rekey-<UTC>` folder left from an earlier attempt, which you delete) and run `R rekey` again. `REKEY_INCOMPLETE retired-<UTC>`: the swap stopped halfway. Put the old set back, then run `R rekey` again:

   ```zsh
   for f in <DATA_DIR>/retired-<UTC>/*.age; do mv -f "$f" <DATA_DIR>/; done
   cp <DATA_DIR>/retired-<UTC>/recorder.toml ~/.config/airtimesat/recorder.toml
   rm -r <DATA_DIR>/.rekey-<UTC> <DATA_DIR>/retired-<UTC>
   ```
3. **Exposed passphrase and a copy of the files taken** (or the files leaked together with the passphrase): also follow case 3 (the SITEST secret) and case 4 (the keys and the vault).

Done when only files under an unexposed passphrase exist, in `data_dir`, Keeper and escrow.
