# 03. Trusted machine setup

| | |
|---|---|
| **Purpose** | Set up the one device that runs the recorder and your manual IWS calls, and holds raw data, the vault and keys |
| **When** | Part A before any IWS call. Part B before the first recording. Part C before every run and every manual call. Part D once, before the first recording |
| **Who** | The CTO only |
| **Design** | [§6.5](../design/s2-recorder-masker.md#65-the-trusted-machine), [§6.2](../design/s2-recorder-masker.md#62-keys-and-the-secret), [§6.3](../design/s2-recorder-masker.md#63-backup-and-recovery), [§13](../design/s2-recorder-masker.md#13-decisions-and-open-items) #19, #20 |
| **Status** | Draft for CTO review |

The decided setup (design §13 #19, risk accepted): your laptop, your normal OS user, your normal Keeper; AI tools may run on the same user. The controls are the merge check of Part C, running only reviewed code from `main`, and the run-time rules. Device: [FILL: device and OS].

## Part A. The machine

1. **Disk encryption** that also covers swap and hibernation (macOS: FileVault). Automatic OS updates and a screen lock.
2. **Three folders**, outside every other git working tree: the git checkout [FILL: path], the recorder data folder for the vault and run log [FILL: path; it goes into the configuration, Part D], and the manual-call folder for raw files [FILL: path]. Keep all three, and SoapUI's settings and logs, out of cloud sync and online backup (on macOS: not under iCloud Drive's Desktop or Documents; `tmutil addexclusion -p <path>` for Time Machine). Never start an AI tool's session in these folders.
3. **Core dumps off:** `ulimit -c 0` in your shell profile; on macOS also `sudo sysctl -w kern.coredump=0`, made persistent [confirm on your macOS version].
4. **The checkout.** Clone the repository and stay on `main`. Before any code runs, check `git log --first-parent --oneline origin/main`: each entry is a PR you reviewed and merged. Note `HEAD`'s SHA as your last checked SHA, in [FILL: your log in the manual-call folder, or a Keeper note].
5. **Environment and hook.** `uv sync --frozen`, then install the pre-commit hook (repository `README.md`). It runs the leak scan and gitleaks before each commit (design §8.3).
6. **Tools:** git, uv, gitleaks 8.21.2, age, curl, OpenSSL, `dig`, SoapUI [confirm versions].
7. **No TLS inspection** (proxy, VPN or endpoint security) applies to traffic to SITEST [confirm with whoever manages the laptop].

Done when the disk is encrypted, the folders are out of sync and backup, core dumps are off, the merge check passed, and the hook and tools are installed.

## Part B. Keeper and the backup key

Exact Keeper CLI (Keeper Commander) syntax comes from its docs [confirm with Keeper Commander docs].

1. **Keeper CLI** with persistent login off; log out after each use. Keep its configuration folder out of sync and backup.
2. **The SITEST credential** lives in its Keeper record only. Delete the delivery e-mail and any attachment.
3. **The age backup key.** Generate it with `age-keygen` piped straight into a new Keeper record, never to a file or the terminal. Note its public recipient (`age1…`); the recorder configuration takes it (Part D). If the Keeper CLI cannot read a field from standard input, stop and decide another path in a reviewed change.
4. **Escrow** the backup key now, and `K_mask` and the vault key after Part D: [FILL: sealed copy or Keeper break-glass record], custodian [FILL: name]. The escrow must not expose the SITEST record or the rest of your vault.
5. **Backup target:** a Keeper file attachment holding the age-encrypted backup (design §13 #20). Optional: a second, passphrase layer you keep outside Keeper [FILL: yes or no].

Done when the backup key is in Keeper and in escrow, its recipient is noted, and the credential lives only in Keeper.

## Part C. Before every run and every manual call

1. `git fetch origin main`, then `git log --first-parent --oneline <last-checked-sha>..origin/main`. Open each merge on GitHub and confirm it is a PR you reviewed and merged. Any other merge: stop, and follow [`06`](06_incidents.md) case 5.
2. Only then `git merge --ff-only origin/main` and `uv sync --frozen`, and note the new last checked SHA.
3. `git status` is clean.
4. During the run or call:
   - no AI tool in that terminal session;
   - AI features that send screen, terminal or clipboard content to a cloud service are off;
   - clipboard sync to other devices (Handoff) is off;
   - no screen sharing;
   - Keeper is unlocked only for the run and locked right after.

Done when every merge since your last checked SHA is one you reviewed, and the run-time rules hold.

## Part D. Masking keys and recorder configuration

`R` is `uv run --frozen python -m airtimesat_platform.recorder`, run in the checkout.

1. **Masking keys, once.** `R keys init` writes four new 256-bit keys (`masker.k_mask`, `masker.vault_key`, `masker.known_value_key`, `masker.inventory_key`, hex) as one JSON object to standard output. It writes only to a pipe, never to a terminal or a file, so pipe it straight into the Keeper CLI as one new "masker keys" record [confirm the Keeper Commander command]. Never run it again unless [`06`](06_incidents.md) case 4 says so: new keys change every surrogate. Then escrow `K_mask` and the vault key (Part B step 4).
2. **Configuration.** Create `~/.config/airtimesat/recorder.toml` with exactly these keys (absolute paths; unknown keys are refused; no secret ever goes here):

   ```toml
   data_dir = "<the recorder data folder of Part A step 2>"
   checkout = "<the git checkout of Part A step 2>"
   backup_recipient = "<the age1... recipient of Part B step 3>"
   backup_dir = "<a folder outside the checkout for the encrypted backups>"
   ```

   `data_dir` and `backup_dir` must be outside the checkout. The first run creates the vault there as `vault.sqlite`, mode 0600; `backup` and `incident clear` never create one (`VAULT_MISSING`).
3. **Secrets for a run** are piped as one JSON object of name-to-value pairs ([`common/secrets_stdin.py`](../../src/airtimesat_platform/common/secrets_stdin.py)): the masker-keys record for a dry run, plus the SITEST record for a live run. [`04`](04_recording_session.md) gives the command shape. Never a file, an argument or an environment variable.

Done when the masker keys are in Keeper and escrow, and the configuration file exists.

## Optional hardening

Extra guards that review proposed. They are not needed to start; add any you want with a reviewed change to this file.

- Before each signed SoapUI call, check SITEST's DNS answers against the record, because SoapUI follows DNS, not the pin.
- Before each SoapUI session, check the Groovy step offline with the synthetic secret of [`tests/gateway/test_signing.py`](../../tests/gateway/test_signing.py) against `gateway/signing.py`.
- Before each run, check `git config --list --show-origin` and `.git/hooks/` for entries you did not set, and rebuild `.venv` from scratch.
- Note the SHA you pushed for your own PRs, and merge only if the PR head still equals it.
- Search SoapUI's settings and log files for the secret, by name and by value.
- Run the recorder from a separate `uv sync --frozen --no-dev` environment (design §6.5, "A minimal environment").
- If the record says the certificate covers the Beta name: before each run, `dig` SITEST and the Beta name (DNS only). A pinned address missing from SITEST's answers, or found in Beta's: stop and re-pin through [`02`](02_pin_sitest_address.md). Without this check, a run on a stale pin may not fail at TLS.
