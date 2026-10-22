# 04. Recording session

| | |
|---|---|
| **Purpose** | Run a reviewed recording plan's reads against SITEST and turn the masked output into a PR |
| **When** | For each merged plan you decide to run. Writes, `inventory add` and `note` come with PR D3 |
| **Who** | The CTO only, on the trusted machine |
| **Design** | [§5.1](../design/s2-recorder-masker.md#51-how-a-run-works), [§6.2](../design/s2-recorder-masker.md#62-keys-and-the-secret), [§6.3](../design/s2-recorder-masker.md#63-backup-and-recovery), [§8.4](../design/s2-recorder-masker.md#84-runtime-detector-block-and-stop) |
| **Status** | Draft for CTO review |

Every command runs in the session shell of [`03`](03_trusted_machine_setup.md) (`umask 077` and `R`), in the checkout. `run`, `backup` and `incident clear` read `~/.config/airtimesat/recorder.toml`, which `R init` wrote (`03` Part D); `--config` names another file.

## Before

1. [`03`](03_trusted_machine_setup.md) Part C: the merge check, `uv sync --frozen`, then `R doctor` with no `FIX`. A staged recording you have not committed makes the tree dirty, and the recorder refuses.
2. The plan is merged on `main`, and `R check recording-plans/<plan>.yaml` prints `OK`. Note the digest.
3. No manual IWS call is running, and none will start until the run ends.

## Run

1. **Unlock Keeper** only now.
2. **Dry run:**

   ```zsh
   R run recording-plans/<plan>.yaml --dry-run
   ```

   The recorder checks the checkout, then asks for the age passphrase once: type it by hand from the Keeper record. It decrypts the masking keys only (never `sitest.json.age`), checks the plan again, unmasks every request against the vault and prints `RUN_START plan_id=<id> run_utc=<utc> decision=dry_run`, then per call `DRY_RUN_CALL call_id=<id> operation=<op>` and the masked request, then `DRY_RUN_DONE plan_id=<id> count=<n>`. Nothing is sent. The first dry run creates the vault. Any `REFUSED` line: stop and see below.
3. **Live run:**

   ```zsh
   R run recording-plans/<plan>.yaml
   ```

   Again one passphrase prompt; the recorder decrypts the masking keys and the SITEST file into its memory only. It prints `RUN_START ... decision=live`, then calls run one at a time; each prints `CALL_OK` with its outcome, duration and counts. At the end, `RUN_DONE plan_id=<id> run_utc=<utc> count=<n>` and the reminder to run `recorder backup`.
4. **Lock Keeper** as soon as the run ends.

A wrong passphrase prints `incorrect passphrase` from age, then `REFUSED code=SECRETS_DECRYPT_FAILED path=recorder-identity.age`: nothing was sent; run again. `SECRETS_FILE_MISSING path=<file>`: run `R init` (`03` Part D), or restore the file (`06` case 7). `IDENTITY_RECIPIENT_MISMATCH`: the configuration's `backup_recipient` is not the identity's; correct the configuration from the `RECIPIENT` noted in Keeper (`06` case 7, "Lost").

## Read the output

1. The staging folder is `tests/fixtures/masked/recordings/<plan-id>/<run-utc>/`: per call, the masked request and response, then `manifest.json`.
2. Read the manifest: the commit and plan digest you expected, each call's outcome, the elements dropped, the surrogates issued, the IWS log entries filtered, and `in_prefix` and `in_canary_range` (both should be empty; anything else goes to the design owner before the next run).
3. Skim the masked responses. Every identifier should be a reserved-prefix surrogate (`99…`, `SUB-9…`, `*.example.invalid`, `240.…`, `2001:db8:…`).

## Commit and PR

1. `git switch -c recording/<plan-id>-<run-utc>`, `git add` the staging folder, commit. The pre-commit hook scans again.
2. `git push -u origin HEAD`, then `gh pr create --base main`. The PR text names no identifier and quotes no file content. CI scans the range again; merge once it is green, as in design §5.1 step 6.
3. `git switch main`.

## Backup

1. `R backup` writes `vault-<UTC>.sqlite.age` to `backup_dir`, encrypted to the configured age recipient, and deletes backups there older than 30 days. It refuses with `VAULT_MISSING` if `data_dir` holds no vault: check the configuration.
2. Attach the new file to the "Recorder vault backups" record by hand in the Keeper app, and delete the record's attachments older than 30 days (design §6.4). Then clear the clipboard (`pbcopy < /dev/null`) and lock Keeper.

## When the run stops

- **`REFUSED code=<CODE> [path=...]` before any call** (`CHECKOUT_NOT_CLEAN`, `HEAD_NOT_ON_MAIN`, `GIT_FETCH_FAILED`, `CODE_NOT_FROM_CHECKOUT` when `R` runs from another clone, `PLAN_NOT_IN_PLANS_FOLDER`, an expired plan, `IDENTIFIER_NOT_ISSUED`, `INCIDENT_OPEN`, `COOLDOWN_PENDING`, `SECRETS_FILE_MISSING`, `SECRETS_DECRYPT_FAILED` after a wrong passphrase, `SECRET_MISSING` or `SECRETS_UNREADABLE` for a damaged file, `QUEUE_ENTRY_NOT_SUPPORTED` until the recorder records the queue entry ids of its own writes): nothing was sent. Fix the cause; for `COOLDOWN_PENDING` wait 60 s after the last timeout or interrupted call.
- **`CALL_BLOCKED`** (`MASKING_BLOCKED`, an unknown or unclassified element, or another field-map mismatch): nothing was written for that call and the method stays refused. Follow [`06`](06_incidents.md) case 1; once the fix is merged, `R incident clear <id>` prints the method it re-enables. When IWS answered, the line ends in `outcome=` (`ok`, or a fault's `AUTH`, `CONFIG`, `FIELD`, `SYS` or `unknown`): share it with the code and path.
- **`CALL_FAILED`** (a refusal, a timeout, a gateway error, a transient masking failure: `NON_SOAP_BODY`, `XML_PARSE`, `XML_TOO_LARGE`, `MASKING_TIMEOUT`, `MASKING_FAILED`, `TOO_MANY_ROWS`; or a vault or key failure: `VAULT_WRITE_FAILED`, `VAULT_INTEGRITY`, `COLLISION_LIMIT`, `SURROGATE_SPACE_EXHAUSTED`): nothing was written for that call and no method is refused. Calls already written stay staged and scanned; commit them or delete the folder. Fix the cause and run again: wait out an outage; for `TOO_MANY_ROWS` (IWS returned more rows than the request asked for), give the agents the call id; for `VAULT_INTEGRITY`, check first that `shasum -a 256 <DATA_DIR>/masker-keys.json.age` prints the `MASKER_KEYS_SHA256` noted in `03` Part D step 2 (read-only; never delete the file here), and if it matches, stop and tell the design owner, as for `COLLISION_LIMIT` and `SURROGATE_SPACE_EXHAUSTED`.
- **`RUN_FAILED code=STAGING_SCAN_HIT`:** the scans found something and the staging folder is deleted. Each `SCAN_FINDING` line before it names the file, the line and the check (`leak_scan:<detector>`, `gitleaks:<rule>`, or `secret:<name>` for the SITEST secret or a key), never the value. The incident refuses every run until you clear it. Treat it as [`06`](06_incidents.md) case 1, give the agents the `SCAN_FINDING` lines, and treat it as case 3 too if the check is `secret:` or `gitleaks:`. A `STAGING_DELETE_FAILED` line means part of the folder remains: delete it by hand before anything else.
- **`RUN_FAILED code=SCANNER_UNAVAILABLE`:** a scanner could not run (gitleaks missing from `PATH`, a crash, a timeout) and found nothing; the staging folder is deleted and no run is refused. Fix the tool (runbook [`03`](03_trusted_machine_setup.md)) and run again.
- **`RUN_FAILED code=RUN_INTERRUPTED`** (Ctrl-C, a closed terminal or a shutdown, or an uncaught error that also prints `UNCAUGHT <type>`): the staging folder is deleted unscanned. If a call was in flight, the 60 s cooldown holds. Give the agents the error type if it repeats, then run again. If the recorder was killed outright (power loss, `kill -9`), a staging folder without `manifest.json` may remain: delete it unscanned, never commit it.
- **`RUN_STOPPED code=RECORD_CAP_REACHED`:** the run reached 500 distinct subscriber records; what was written is complete. Ask for a smaller plan.

Done when the recording PR is open (or the staging folder deleted), the backup is attached, and Keeper is locked.
