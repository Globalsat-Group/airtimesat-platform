# 04. Recording session

| | |
|---|---|
| **Purpose** | Run a reviewed recording plan's reads against SITEST and turn the masked output into a PR |
| **When** | For each merged plan you decide to run. Writes, `inventory add` and `note` come with PR D3. Until PR W adds the generated field map, `R check` and `R run` refuse every plan with `FIELD_MAP_MISSING` |
| **Who** | The CTO only, on the trusted machine |
| **Design** | [§5.1](../design/s2-recorder-masker.md#51-how-a-run-works), [§6.2](../design/s2-recorder-masker.md#62-keys-and-the-secret), [§6.3](../design/s2-recorder-masker.md#63-backup-and-recovery), [§8.4](../design/s2-recorder-masker.md#84-runtime-detector-block-and-stop) |
| **Status** | Draft for CTO review |

`R` below is `uv run --frozen python -m airtimesat_platform.recorder`, run in the checkout. `run`, `backup` and `incident clear` read `~/.config/airtimesat/recorder.toml` (`03` Part D); `--config` names another file.

## Before

1. [`03`](03_trusted_machine_setup.md) Part C: the merge check, then `git status` is clean. A staged recording you have not committed makes the tree dirty, and the recorder refuses.
2. The plan is merged on `main`, and `R check recording-plans/<plan>.yaml` prints `OK`. Note the digest.
3. No manual IWS call is running, and none will start until the run ends.

## The secrets, on standard input only

The recorder reads one JSON object of name-to-value pairs from standard input, never from a file, an argument or an environment variable. A dry run takes the masker-keys record only (it refuses the SITEST fields); a live run takes both records:

- `masker.k_mask`, `masker.vault_key`, `masker.known_value_key`, `masker.inventory_key`;
- `sitest.iws_username`, `sitest.secret_key` and, if the record has it, `sitest.sp_account_number`.

Shape of the pipe [confirm the Keeper Commander commands and the jq filter; record names are not secrets]:

```sh
keeper get "<masker keys record>" --format json \
  | jq -c '<map the record fields to the names above>' \
  | R run recording-plans/<plan>.yaml --dry-run
```

For a live run, combine both records into one object in the same pipe, never through a file.

## Run

1. **Unlock Keeper** only now.
2. **Dry run:** `... | R run recording-plans/<plan>.yaml --dry-run`. It checks the plan again, unmasks every request against the vault and prints each masked request with `DRY_RUN_CALL`. Nothing is sent. Any `REFUSED` line: stop and see below.
3. **Live run:** the same pipe with both records and without `--dry-run`. Calls run one at a time; each prints `CALL_OK` with its outcome, duration and counts.
4. **Lock Keeper** as soon as the run ends.

## Read the output

1. The staging folder is `tests/fixtures/masked/recordings/<plan-id>/<run-utc>/`: per call, the masked request and response, then `manifest.json`.
2. Read the manifest: the commit and plan digest you expected, each call's outcome, the elements dropped, the surrogates issued, the IWS log entries filtered, and `in_prefix` and `in_canary_range` (both should be empty; anything else goes to the design owner before the next run).
3. Skim the masked responses. Every identifier should be a reserved-prefix surrogate (`99…`, `SUB-9…`, `*.example.invalid`, `240.…`, `2001:db8:…`).

## Commit and PR

1. `git switch -c recording/<plan-id>-<run-utc>`, `git add` the staging folder, commit. The pre-commit hook scans again.
2. Push and open the PR. CI scans the range again; merge once it is green, as in design §5.1 step 6.
3. `git switch main`.

## Backup

1. `R backup` writes `vault-<UTC>.sqlite.age` to `backup_dir`, encrypted to the configured age recipient, and deletes backups there older than 30 days. It refuses with `VAULT_MISSING` if `data_dir` holds no vault: check the configuration.
2. Attach the new file to the Keeper backup record by hand, and delete the record's attachments older than 30 days (design §6.4) [confirm the Keeper steps]. Then lock Keeper.

## When the run stops

- **`REFUSED code=<CODE> [path=...]` before any call** (`CHECKOUT_NOT_CLEAN`, `HEAD_NOT_ON_MAIN`, `CODE_NOT_FROM_CHECKOUT` when `R` runs from another clone, `PLAN_NOT_IN_PLANS_FOLDER`, an expired plan, `IDENTIFIER_NOT_ISSUED`, `INCIDENT_OPEN`, `COOLDOWN_PENDING`, a missing secret, `QUEUE_ENTRY_NOT_SUPPORTED` until PR W): nothing was sent. Fix the cause; for `COOLDOWN_PENDING` wait 60 s after the last timeout or interrupted call.
- **`CALL_BLOCKED`** (`MASKING_BLOCKED`, an unknown or unclassified element, or another field-map mismatch): nothing was written for that call and the method stays refused. Follow [`06`](06_incidents.md) case 1; once the fix is merged, `R incident clear <id>` prints the method it re-enables.
- **`CALL_FAILED`** (a refusal, a timeout, a gateway error, or a transient masking failure: `NON_SOAP_BODY`, `XML_PARSE`, `XML_TOO_LARGE`, `MASKING_TIMEOUT`, `MASKING_FAILED`, `VAULT_WRITE_FAILED`, `TOO_MANY_ROWS`): nothing was written for that call and no method is refused. Calls already written stay staged and scanned; commit them or delete the folder. Fix the cause (wait out an outage, ask for a smaller limit) and run again.
- **`RUN_FAILED code=STAGING_SCAN_HIT`:** the scans found something and the staging folder is deleted. The incident refuses every run until you clear it. Treat it as [`06`](06_incidents.md) case 1, and as case 3 if a secret may have leaked. A `STAGING_DELETE_FAILED` line means part of the folder remains: delete it by hand before anything else.
- **`RUN_FAILED code=RUN_INTERRUPTED`** (Ctrl-C, or an uncaught error that also prints `UNCAUGHT <type>`): the staging folder is deleted unscanned. If a call was in flight, the 60 s cooldown holds. Give the agents the error type if it repeats, then run again.
- **`RUN_STOPPED code=RECORD_CAP_REACHED`:** the run reached 500 distinct subscriber records; what was written is complete. Ask for a smaller plan.

Done when the recording PR is open (or the staging folder deleted), the backup is attached, and Keeper is locked.
