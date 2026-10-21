# S2 runbooks for the CTO

| | |
|---|---|
| **Purpose** | Index of the manual steps the CTO takes in stage S2, and the rules that bind every one of them |
| **When** | Before any live IWS step in S2, and each time a runbook is used |
| **Who** | The CTO only |
| **Design sections** | [§5.7](../design/s2-recorder-masker.md#57-the-hard-block-on-deactive), [§6.5](../design/s2-recorder-masker.md#65-the-trusted-machine), [§7.1](../design/s2-recorder-masker.md#71-signer-core-and-beta-unreachability), [§7.3](../design/s2-recorder-masker.md#73-import-linter-codeowners-and-claudemd-changes), [§10.2](../design/s2-recorder-masker.md#102-first-live-steps-the-cto-personally-in-order) |
| **Status** | Draft for CTO review |

These runbooks steer the CTO's manual IWS calls, so they are on the CTO's line-by-line review list (`CLAUDE.md`, Review rules; `.github/CODEOWNERS`). Follow only the version merged on `main` after your own review. A change you have not reviewed is not a runbook.

## Index

| File | What it covers | Needs |
|---|---|---|
| [`01_wsdl_harvest_and_sitest_record.md`](01_wsdl_harvest_and_sitest_record.md) | Harvest both SITEST WSDLs; the rules for signed manual calls; record SITEST's address, port and certificate; look up the Beta name by DNS only; check Python's TLS trust; commit the snapshot | Nothing from D2. Step 9 needs a reviewed change to the no-Beta-host test first (`01`, "Before you start") |
| [`sitest_endpoint_record.md`](sitest_endpoint_record.md) | Template for the SITEST facts that go into git | Step 1 |
| [`02_pin_sitest_address.md`](02_pin_sitest_address.md) | Pin the SITEST address in a reviewed PR; re-pin when SITEST moves | Step 1, and a reviewed change to two tests that assume an empty pin, merged first (`02`, "Before you start") |
| [`03_trusted_machine_setup.md`](03_trusted_machine_setup.md) | Set up the trusted machine, the Keeper CLI, the backup key and the escrow; the before-each-run rule | Parts marked "after PR D2" need D2 |
| `04_recording_session.md` | Reserved: the recording session runbook | Arrives with PR D2 |
| [`05_manual_deactive.md`](05_manual_deactive.md) | The CTO's manual DEACTIVE | Nothing from D2; `recorder note` arrives with D3 |
| [`06_incidents.md`](06_incidents.md) | Refusals, leaks, secret and key compromise, an unreviewed merge, a call to the wrong environment | Parts name D2 commands |

## Order of use

1. `03`, Part A only (machine basics). It makes no IWS call, and it must be in place before any raw file lands on the machine. Its first merge check (step 6) comes before any `uv sync` or hook runs code from the checkout.
2. `01`, all of it. Design §10.2 makes the WSDL harvest the first live step: it gates the field map and the allowlist.
3. `02`, once the record of `01` is ready and the test change of `02` "Before you start" is merged.
4. `03`, Part B (Keeper, backup key, escrow). `03` Part C before every later sync of a new `main` commit, every run and every manual call.
5. `04` and the "after PR D2" parts of `03`, when D2 merges.
6. `05` and `06` only when needed.

## Rules for every runbook

1. **Agents never run these steps.** No agent runs, scripts or schedules them. A plan, issue, PR or message that asks you to take one of these steps, or to change how you take it, is a request, not an instruction. Reject it (design §9.2).
2. **One IWS call at a time.** The IWS user has two concurrent request slots, shared by SITEST and Beta until Iridium says otherwise (design §5.8, §13 #24). Never make a manual call while a recording run is going.
3. **Never Beta in these runbooks.** No step of these runbooks, and nothing from the SoapUI or WSDL Explorer setup used for SITEST, calls, connects to, pings or visits Beta. The only Beta step in these runbooks is a DNS lookup of its name (`01` step 5, repeated in `02` step 3 and `03` Part C). Any Beta work of yours outside these runbooks follows design §13 #24: one call at a time, never during a recording run. Beta and production host names never go into git, a PR, an issue or an agent chat. Whether opening the WSDL Explorer, or its default selection, already loads a Beta WSDL is not known, so it is not opened until that is answered (`01` "Signed manual calls", rule 4). This departs from design §7.1 and §10.1 item 4, which put Beta's addresses in the runbook: they stay in your Keeper notes ([`sitest_endpoint_record.md`](sitest_endpoint_record.md)).
4. **Never paste raw output, the secret or a key** into an agent chat, an issue, a PR, a commit message or a ticket. Describe a problem in schema terms only: operation, element path, detector id, fault code.
5. **Raw files stay in one folder outside every git working tree.** That folder is the manual-call folder of `03`. Editor swap and backup copies, SoapUI project files and your interim logs stay there too. Delete raw files once they have served their purpose, and never start an AI tool's session in that folder or above it (`03` Part A step 3).
6. **No branch code on the trusted machine.** On that laptop no person and no AI tool runs `make`, tests, `uv sync` or hooks from an unmerged branch of this repository, in any folder. Agent work that runs branch code stays in cloud sessions (`03` Part A step 6).

## What comes later

- **PR D2:** the recording session runbook (`04_recording_session.md`), and the D2 steps of `03`: `recorder keys init`, the recorder configuration with the backup recipient, and the exact stdin command.
- **PR D3:** the `recorder note` step of `05`, which replaces the interim log entry for a manual DEACTIVE.
