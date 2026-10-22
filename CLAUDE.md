# Agent rules for airtimesat-platform

These rules bind every agent and every human working in this repository. If a task conflicts with them, stop and ask the CTO. Source: delivery re-plan v1.1 (§3.3, §3.4, §8.2, §8.6) in `Globalsat-Group/IWS`.

## Language

Everything is in English: code, comments, docs, commit messages, PR text, ADRs, runbooks, API and event names, database schema.

## Purpose

One repository for both Iridium programs at Globalsat:

- Phase 1: an Ops console over Iridium's IWS SOAP API, behind an IWS gateway.
- Phase 2: starting with a TAP file archive (stage S1, only if files are at risk).

Plans and decisions live in `Globalsat-Group/IWS`. This repository holds code, tests, Terraform, CI and runbooks.

## Live-system boundary (re-plan §3.4)

- Never call IWS production or Beta (Beta is CTO-only, like production; confirmed by the CTO on 20 Oct 2026). Agents never call SITEST. In S2 the only SITEST client is the recorder, which the CTO runs on the trusted machine from a reviewed recording plan. Agents ask for live data by writing a recording plan in a PR. Every production call and every call to Iridium's SFTP is made by the CTO.
- The development credential covers both SITEST and Beta. The recorder, and any later agent-facing tool, call the SITEST endpoint only; a Beta endpoint in agent-reachable code or config is a defect.
- Never hold, request, print or store a raw credential. Only gateway code reads an IWS secret. In S2 the SITEST secret is read by the gateway signer core inside the recorder, from an age-encrypted file on the CTO's trusted machine (its passphrase in the CTO's Keeper), for a live run only. From S4 the production gateway reads IWS secrets from Secrets Manager.
- SITEST is refreshed from production, so it is production personal data.
- Recording plans may read within the recorder's allowlist. Writes go only to assigned test inventory, inside a recording plan the CTO approved and runs.
- DEACTIVE stays with the CTO. Never run it, script it or put it in a test plan or a recording plan.
- Real CDRs, TAP files and customer exports never enter the agent environment.

## Confidentiality (re-plan §8.6)

- No Iridium PDFs, guides or catalogs here. They stay in `Globalsat-Group/IWS`.
- From stage S2, WSDL snapshots, generated field maps and generated bindings live under `src/airtimesat_platform/gateway/` only.
- Fixtures are synthetic or masked, and they must pass the leak tests before they reach git.
- Never put a real IMEI, ICCID, MSISDN, customer name or other identifier in code, tests, fixtures, docs, logs or PR text.

## Secrets (re-plan §8.2)

- Secrets never go in code, docs, logs, fixtures, test output, commit messages or agent sessions.
- Terraform creates secret entries only. Values are set by the CTO outside git.
- CI has no secrets. AWS access from CI, when it comes, uses GitHub OIDC, never long-lived keys.
- If you see something that looks like a real secret, stop, do not copy it anywhere, and tell the CTO.

## Review rules (re-plan §3.3)

- These paths need the CTO's line-by-line review before merge (CODEOWNERS enforces it):
  - `src/airtimesat_platform/gateway/` (signing, permits) and `tests/gateway/`, and any other code that writes to IWS, wherever it lives
  - `src/airtimesat_platform/masker/`, its tests and the leak tests (any `*mask*` or `*leak*` file)
  - `src/airtimesat_platform/recorder/`, `tests/recorder/` and `recording-plans/` (the recorder writes to IWS; every plan is a live-call request)
  - `docs/runbooks/` (they steer the CTO's manual IWS calls)
  - `src/airtimesat_platform/common/secrets*` and any `*secret*` file (secrets handling)
  - `infra/` and any `*iam*` or `*oidc*` file (Terraform, IAM, GitHub OIDC trust policy)
  - `.github/` (workflows, CODEOWNERS, Dependabot, PR template)
  - `Dockerfile*`
  - `CLAUDE.md`, `pyproject.toml`, `uv.lock`
  - Gate configuration: `Makefile`, `.gitleaks.toml`, `.gitignore`, `.pre-commit-config.yaml`, `licensing/`, `scripts/licence_gate.py`, `tests/test_import_contracts.py`, `SECURITY.md`
- Other code: tests must pass and the CTO reads the diff.
- The CTO merges only code they can explain. Keep PRs small enough to explain.
- Agent PRs come from the bot identity, never from the CTO's account.
- **Only humans merge** (CTO decision, 20 Oct 2026). Agents and the bot never approve, merge, enable auto-merge or bypass a PR. GitHub stops the bot from merging with the restrict-updates ruleset (`docs/SETUP_CHECKLIST.md`, step 7b). It cannot stop an agent that reaches GitHub through a human's account, so this rule binds agents whatever access they hold.
- Never weaken a gate to get green: no skipped tests, no new lint ignores, no checkov skips, no licence exceptions and no gitleaks allow-list entries without a written reason in the same PR.

## Checks

- Run `make check` before every PR. It runs lint, typecheck, contracts, test, plans, security, terraform and workflows. CI runs the same targets, except `plans`: its `recorder-check` job judges a PR's changed recording plans with the checker from the PR's base commit.
- Never apply Terraform. Plans and applies are the CTO's.
- Pin every third-party GitHub Action to a full commit SHA with the version in a comment.

## Module boundaries (enforced by import-linter)

Code lives in `src/airtimesat_platform/`.

- `gateway` is the only code that talks to IWS. The console uses its public port, `gateway.api`; the recorder uses `gateway.sitest_port`.
- `console` imports only `domain`, `common` and `gateway.api`. Never gateway internals.
- `domain` is pure Python and imports nothing else from the app.
- `masker` imports only `common`; it may import `lxml`.
- `recorder` imports only `common`, `masker` and `gateway.sitest_port`, and runs only on the CTO's trusted machine. The one exception is `recorder check`, which uses no secret and no vault, and also runs in CI and agent sessions.
- `archive` imports only `domain` and `common`.
- `common` holds config, logging and the secrets interface.
- Only `gateway` may import `aiohttp` or `xsdata`. Only `gateway` and `masker` may import `lxml`.

If a change needs a new boundary, propose it in the PR. Do not edit the contracts to make a change pass.
