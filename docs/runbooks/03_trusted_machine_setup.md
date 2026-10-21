# 03. Trusted machine setup

| | |
|---|---|
| **Purpose** | Set up the one device that runs the recorder and the CTO's manual IWS calls, and holds raw data, the vault and key material |
| **When** | Part A before any IWS call. Part B before the first recording. Part C before every sync of a new `main` commit, every run and every manual call. Part D when PR D2 merges |
| **Who** | The CTO only |
| **Design sections** | [§6.5](../design/s2-recorder-masker.md#65-the-trusted-machine), [§6.2](../design/s2-recorder-masker.md#62-keys-and-the-secret), [§6.3](../design/s2-recorder-masker.md#63-backup-and-recovery), [§5.1](../design/s2-recorder-masker.md#51-how-a-run-works), [§10.2](../design/s2-recorder-masker.md#102-first-live-steps-the-cto-personally-in-order) step 2, [§13](../design/s2-recorder-masker.md#13-decisions-and-open-items) #14, #19, #20 |
| **Status** | Draft for CTO review |

**The decided setup** (design §13 #19, risk accepted). The trusted machine is the CTO's laptop, under the CTO's normal OS user, with the CTO's normal Keeper. AI tools may run on the same user. Accepted risk: while Keeper is unlocked for a run, an AI tool or a malicious dependency running as that user could read the keys, the vault key and the SITEST secret (and so reach Beta). The controls are the before-each-run check (Part C), the rule that no branch code runs on this laptop (Part A step 6), and the run-time rules below. Design §13 #14 still says "no AI agent under the OS user that holds Keeper or as an administrator"; that clause predates §13 #19 and §6.5, which replace it. Follow-up: amend §13 #14 and the §2.2 threat row in a reviewed design PR.

Device: [FILL: device name and OS].

## Part A. Before any IWS call

1. **Disk encryption.** Turn on full-disk encryption that also covers swap and hibernation. macOS: FileVault (`fdesetup status`; `sysctl vm.swapusage` shows "encrypted"). Linux: LUKS with encrypted swap, and hibernation only to encrypted swap. [confirm for the device's OS]
2. **Updates and lock.** Turn on automatic OS updates and a screen lock with a short timeout.
3. **Folders.** Create three folders, each outside every other git working tree:
   - the git checkout: [FILL: path];
   - the recorder data folder (vault, run log), readable by your user only: [FILL: path] [confirm with D2, which sets where the recorder looks];
   - the manual-call folder, the one place raw files live (WSDL harvest, manual calls, raw reproductions, SoapUI project files) and your interim logs: [FILL: path].

   Delete raw files once they have served their purpose: a raw reproduction or manual-call response once its fix is verified or its outcome is recorded, and the WSDL harvest once its snapshot merges. Never start an AI tool's session in the trusted checkout, the manual-call folder, the recorder data folder or any folder above them, and deny AI tools read access to them where the tool allows it (for example a deny rule in its settings) [confirm per tool]. AI tools run as your user, so file permissions do not stop them.
4. **No cloud sync, no online backup** for: the recorder data folder, the run log, the git checkout (with its staging folder), the manual-call folder (with your interim logs and any SoapUI project), SoapUI's settings and log files [FILL: paths, confirm for the SoapUI version], and your shell history file. The Keeper CLI configuration folder is excluded once it exists (Part B step 1). On macOS keep them out of iCloud Drive's Desktop and Documents, and exclude them from Time Machine (`tmutil addexclusion -p <path>`, needs admin). Check every other sync or backup client on the device. Only the encrypted vault backup leaves the machine (Part B).
5. **Core dumps off.**
   - Shell: add `ulimit -c 0` to your shell profile, open a new shell, and check `ulimit -c` prints `0`.
   - OS, where possible. Linux: a `hard core 0` entry in `/etc/security/limits.conf`, `Storage=none` in `/etc/systemd/coredump.conf` if systemd-coredump is used, and `fs.suid_dumpable=0`. macOS: `sudo sysctl -w kern.coredump=0`, made persistent [confirm on the device's macOS version].
6. **Clean checkout of `main` only.** Clone the repository into the checkout folder and stay on `main`.
   - **First merge check, before any code runs.** Before item 7, list `main`'s history with `git log --first-parent --oneline origin/main` and open each entry on GitHub. Each must be a PR you reviewed and merged; the root "Initial commit" is the repository's own start. Any other entry: stop, do not sync ([`06`](06_incidents.md) case 6). Then record `HEAD`'s SHA as your first last checked SHA (Part C step 5).
   - **No branch code anywhere on this laptop.** No person and no AI tool runs `make`, tests, `uv sync` or hooks from an unmerged branch of this repository, in any folder: not in the trusted checkout, not in a second clone (design §6.5). Agent work that runs branch code stays in cloud sessions. Never start an AI tool's session in the trusted checkout. Never check out, build or run a branch you did not write (agent PRs).
   - The one exception (design §5.1 step 6): your own branches that change only data files or the pinned-address constant (`01` steps 8 and 9, `02`, masked recordings). Cut them from your local `main` checked under Part C. Commit through the hook, which is `main`'s code because the branch leaves it unchanged. Never run `make` or tests on them. Right after the push, `git switch main && git branch -D <branch>`. Never pull or fetch such a branch back from GitHub: an agent with access to it could have pushed to it. Redo any follow-up change locally on a new branch from your checked `main`.
7. **Locked environment.** In the checkout, after the first merge check: `uv sync --frozen`.
8. **Pre-commit hook.** In the checkout: `uvx pre-commit@[FILL: reviewed version] install` (repository `README.md`). It runs ruff, the leak scan and gitleaks before each commit (design §8.3). `pre-commit` is not in `uv.lock`, so pin at least its version; its dependencies are still fetched without hash checks. [confirm: move `pre-commit` into the locked dev group and use `uv run --frozen pre-commit install`, in a separate gate-configuration PR, since `pyproject.toml` and `uv.lock` are on the review list]
9. **Tools.** Install, and check each version:
   - git; uv 0.11.32 (repository `README.md` tool table);
   - gitleaks 8.21.2 on `PATH` (the pre-commit hook builds its own copy, which is not on `PATH`). Verify the download against the checksum for your platform's asset in the release's `gitleaks_8.21.2_checksums.txt` (for `linux_x64` it equals `GITLEAKS_SHA256` in `.github/workflows/ci.yml`);
   - age and age-keygen (Part B); curl and OpenSSL (`01`); `dig` (on Linux in dnsutils or bind-utils); SoapUI (`01` "Signed manual calls") [confirm versions].

   Check: `git --version; uv --version; gitleaks version; age --version`.

Done when the disk is encrypted with swap, updates and the screen lock are on, the three folders exist outside sync and backup, `ulimit -c` is `0`, the first merge check passed and its SHA is recorded, the checkout is clean on `main` with `uv sync --frozen` done, the hook is installed, and the tools print their versions. Python's TLS trust is checked in `01` step 7.

## Part B. Keeper, the backup key and the escrow

For Keeper CLI (Keeper Commander) commands this runbook gives the intent. Take exact syntax from the Keeper Commander docs [confirm with Keeper Commander docs].

1. **Keeper CLI.** Install Keeper Commander. Turn persistent login off, so each use asks for your master password and nothing stays logged in [confirm with Keeper Commander docs]. Log out after each use. Exclude its configuration folder [FILL: path, confirm with Keeper Commander docs] from sync and backup as in Part A step 4.
2. **The age backup key.** Generate it so the private key goes straight into Keeper, never to a file, a command-line argument, an environment variable, a terminal or the clipboard:
   - `age-keygen` writes the identity to standard output when no `-o` is given. Pipe it into a Keeper CLI command that creates a new record "vault backup key" from standard input [confirm with Keeper Commander docs]. When standard output is not a terminal, `age-keygen` prints the public key on standard error [confirm with `man age-keygen`].
   - If the Keeper CLI cannot take a field from standard input, stop. Do not fall back to a file, an argument (such as `"secret=$(age-keygen)"`, which shows in the process list) or an environment variable. Decide the path in a reviewed change (for example, `recorder keys init` also generating the age identity in D2) [confirm].
   - Record the public recipient (`age1…`) in your Keeper notes. It goes into the recorder configuration in D2.
3. **The offline escrow.** Escrow the backup key now, and `K_mask` and the vault key after Part D: a sealed copy with a named custodian, or a Keeper break-glass record (design §6.3). The form must expose only the backup key, `K_mask` and the vault key: never the SITEST record or the rest of your vault. Keeper's account-wide emergency access hands over the whole vault, so it is not this form; a record shared with the custodian alone may be [confirm with Keeper docs]. Form: [FILL: sealed copy or break-glass record]. Custodian: [FILL: name and role]. Write down how a deputy would recover, without the values.
   - A sealed copy is made by hand. Never print it, screenshot it, photograph it or copy-paste it: print spools, screenshots and photos land in files and sync. The key never reaches a file, a terminal or the clipboard. The run-time rules of Part C hold while it is on screen. [FILL: sealed-copy procedure, if that form is chosen]
   - When keys are replaced ([`06`](06_incidents.md) case 5), the old escrow copies are destroyed.
4. **The off-machine backup target.** A Keeper file attachment holding the age-encrypted backup, ciphertext only (design §13 #20). Keeper also holds the vault key, so Keeper alone can decrypt it; that is accepted. Recommended hardening: also encrypt the backup to an age passphrase you keep outside Keeper. Decision: [FILL: passphrase layer yes or no; where the passphrase is kept]. `recorder backup` arrives with D2.

Done when the backup key is in Keeper and the escrow, its public recipient is noted, persistent login is off, the Keeper CLI configuration folder is outside sync and backup, and the backup target is decided.

## Part C. Before and during each run

Before syncing or running a new `main` commit:

1. `git fetch origin`
2. List the merges since your last checked SHA:

   ```sh
   git log --first-parent --oneline <last-checked-sha>..origin/main
   ```

   The first last checked SHA is the one recorded in Part A step 6. Keep it in one place only: [FILL: your log in the manual-call folder, or a Keeper note]. Never read it from a file in the checkout or from `origin`.
3. Open each merge on GitHub and confirm it is a PR you reviewed and merged. Any other merge: stop, do not sync, and follow [`06`](06_incidents.md) case 6.
4. Only then, on `main`: `git merge --ff-only origin/main` and `uv sync --frozen`.
5. Record `HEAD`'s SHA as your new last checked SHA, in the same place.

Before every run and every manual call that uses the checkout, even when `main` has not moved (defense in depth; it does not undo anything planted outside the checkout):

1. `git status --porcelain` prints nothing, and `git rev-parse HEAD` equals your last checked SHA.
2. Rebuild the environment: `rm -rf .venv && uv sync --frozen`. A plain `uv sync` keeps extra files in `.venv`.
3. `.git/hooks/` holds only the pre-commit hook, besides git's `*.sample` files.

Before each recording run, re-check the pinned address, by DNS only (`01` steps 3 and 5). Never connect to the pinned address with `openssl` or anything else to check it: it might now be Beta's.

1. Run `dig "$H" A; dig "$H" AAAA` (`$H` as in `01`) and the Beta lookup. Keep the answers in Keeper notes only.
2. If a pinned address is missing from SITEST's answers, run the lookup again a few minutes later (DNS may rotate).
3. Still missing: stop, and re-pin through [`02`](02_pin_sitest_address.md).
4. Found in Beta's answers, unless the record says "shared address: yes": stop, and re-pin through `02`.

Manual calls go to the SITEST name through DNS, not the pin, so this check is for recording runs. [confirm: certificate or public-key pinning in the transport would close this in code; a design follow-up]

During a run or a manual call:

1. No AI tool runs in the terminal session of the run.
2. AI features of the terminal, editor, browser or OS that send screen, terminal or clipboard content to a cloud service are off.
3. Clipboard sync to other devices is off (on macOS, Handoff).
4. Unlock Keeper only for the run, and lock it right after.
5. No screen share, screen recording or remote-desktop or support session is active: quit meeting apps. Take no screenshots or photos while Keeper is unlocked, the secret is in SoapUI, or raw output is on screen.

Done when every merge since your last checked SHA is one you reviewed, the new last checked SHA is recorded, the checkout and its environment match it, the pinned address still belongs to SITEST only, and the run-time rules hold.

## Part D. After PR D2

These steps need D2. They are described here so you can plan; D2 brings the exact commands.

1. **`recorder keys init`.** Run once. It generates the four 256-bit keys (`K_mask`, the vault key, the known-value hash key, the inventory key) and writes them to standard output for the Keeper CLI to store as one "masker keys" record, never to a file, a command-line argument, an environment variable or the terminal. It refuses to run when standard output is a terminal. Then add `K_mask` and the vault key to the escrow (Part B step 3).
2. **The recorder configuration.** It holds the backup key's public recipient (Part B step 2) [confirm with D2 what else it holds].
3. **Loading secrets for a run.** The recorder reads one JSON object of name-to-value pairs on standard input ([`common/secrets_stdin.py`](../../src/airtimesat_platform/common/secrets_stdin.py)). The masker-keys record and, for a live run, the SITEST record must be combined into that one object in the pipe (for example with `jq`), never in a file, a command-line argument, an environment variable or the terminal. Never use `--argjson "$(...)"`, which puts them on `jq`'s command line. Do not run two Keeper CLI commands at once (for example two `<(...)` process substitutions): with persistent login off, both prompt for the master password on the same terminal, and one prompt can echo the password in clear text. Read both records from one Keeper CLI login, or one after the other inside the pipe (for example `{ <first fetch>; <second fetch>; } | jq -s ...`) [confirm with Keeper Commander docs]. D2's combining command is reviewed for how its password prompt behaves as well as for `jq` errors. `jq` errors print the start of a value, so D2's combining command must be reviewed for this, and the combining step never runs with its output going to a terminal (test it only with the recorder at the end of the pipe). The SITEST names are `sitest.iws_username`, `sitest.secret_key` and the optional `sitest.sp_account_number` ([`gateway/sitest_port.py`](../../src/airtimesat_platform/gateway/sitest_port.py)). The masker-key names and the exact command come with D2. A dry run loads the masking keys only.

Done when the masker keys are in Keeper and the escrow, and the configuration holds the backup recipient.
