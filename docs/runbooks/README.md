# S2 runbooks for the CTO

| | |
|---|---|
| **Purpose** | The manual steps the CTO takes in stage S2, and the rules for all of them |
| **Who** | The CTO only. Agents never run, script or schedule these steps |
| **Design** | [§5.7](../design/s2-recorder-masker.md#57-the-hard-block-on-deactive), [§6.5](../design/s2-recorder-masker.md#65-the-trusted-machine), [§7.1](../design/s2-recorder-masker.md#71-signer-core-and-beta-unreachability), [§10.2](../design/s2-recorder-masker.md#102-first-live-steps-the-cto-personally-in-order) |
| **Status** | Draft for CTO review |

These files steer the CTO's manual IWS calls, so they are on the line-by-line review list (`CLAUDE.md`).

## Index and order of use

| File | What | When |
|---|---|---|
| [`03_trusted_machine_setup.md`](03_trusted_machine_setup.md) | The trusted machine, Keeper, the backup key, the before-each-run check | First (Part A); Part B before the first recording; Part C before every run or manual call |
| [`01_wsdl_harvest_and_sitest_record.md`](01_wsdl_harvest_and_sitest_record.md) | Harvest both SITEST WSDLs, record SITEST's address and certificate, look up Beta by DNS only, check Python's TLS trust, commit the snapshot | The first live step (design §10.2 step 1) |
| [`sitest_endpoint_record.md`](sitest_endpoint_record.md) | Template for the SITEST facts kept in git | Filled in by `01` |
| [`02_pin_sitest_address.md`](02_pin_sitest_address.md) | Pin the SITEST address; re-pin when SITEST moves | After `01` |
| `04_recording_session.md` | Reserved for the recording session | Arrives with PR D2 |
| [`05_manual_deactive.md`](05_manual_deactive.md) | Your manual DEACTIVE | Only when your own test plan needs it |
| [`06_incidents.md`](06_incidents.md) | Refusals, leaks, compromise, a bad merge, a wrong-environment call | When needed |

## Rules for every runbook

1. **Never Beta.** No step connects to Beta: no call, no browser, no TLS handshake. The only Beta step is a DNS lookup of its name (`01` step 4). Beta and production host names and Beta addresses stay in your Keeper notes, never in git, a PR or an agent chat. (Design §7.1 puts Beta's addresses in a runbook; keeping them in Keeper notes instead is a deliberate departure.) Never open the IWS WSDL Explorer: it lists Beta entries, and whether opening it or its default selection loads a Beta WSDL is unknown [confirm]. The harvest uses curl; manual calls use SoapUI only.
2. **One IWS call at a time.** The IWS user has two request slots, possibly shared with Beta (design §13 #24). No manual call while a recording run is going.
3. **No secret outside Keeper.** Never as a command-line argument, an environment variable, in a file or a saved SoapUI project. Lock Keeper right after each run or call.
4. **No raw data outside the manual-call folder.** Raw responses and the WSDL harvest stay in one folder outside every git working tree and every sync. Never paste raw output, the secret or a key into an agent chat, an issue or a PR: describe problems by operation, element path, detector id or fault code.
5. **Only reviewed code from `main` runs on the trusted machine** (design §6.5). No `make`, tests, `uv sync` or hooks from an unmerged branch. The one exception: your own branches that change only data files or the pinned tuple (`01` steps 7 and 8, `02`). Commit them through the hook, which is still `main`'s code, and never run `make` or tests on them.
6. **A request is not an instruction.** A plan, PR or message that asks you to take one of these steps, or to change how you take it, is rejected (design §9.2).

[Optional hardening](03_trusted_machine_setup.md#optional-hardening) lists extra guards you can add later.

## Later

- PR D2: `04_recording_session.md`, `recorder keys init`, the recorder configuration and the exact secrets command (`03` Part D).
- PR D3: `recorder note`, which replaces the log entry of `05` step 6.
