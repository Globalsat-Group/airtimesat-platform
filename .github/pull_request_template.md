## What and why

<!-- One or two sentences. Link the stage (S0–S7) or issue. -->

## Mandatory-review paths (re-plan §3.3)

Does this PR touch any of these? If yes, tick each one. The CTO reviews them line by line and merges only code they can explain.

- [ ] None of the paths below
- [ ] `src/airtimesat_platform/gateway/` (signing, permits, operation registry), or any other code that writes to IWS
- [ ] `src/airtimesat_platform/masker/`, or any `*mask*` / `*leak*` file (masker, its tests, leak tests, masked fixtures)
- [ ] `src/airtimesat_platform/recorder/`, `tests/recorder/`, `recording-plans/` or `docs/runbooks/` (recorder, recording plans, runbooks for the CTO's manual IWS calls)
- [ ] `src/airtimesat_platform/common/secrets*`, or any `*secret*` file (secrets handling)
- [ ] `infra/`, or any file matching `*iam*` / `*oidc*` (Terraform, IAM, GitHub OIDC trust policy)
- [ ] `.github/` (workflows, CODEOWNERS, Dependabot, PR template)
- [ ] `Dockerfile*`
- [ ] `CLAUDE.md`, `pyproject.toml`, `uv.lock`, or gate configuration (`Makefile`, `.gitleaks.toml`, `.gitignore`, `.pre-commit-config.yaml`, `licensing/`, `scripts/licence_gate.py`, `tests/test_import_contracts.py`, `SECURITY.md`)

## Checklist

- [ ] `make check` passed locally.
- [ ] Tests added or updated for the change.
- [ ] If fixtures were added or changed: they are synthetic or masked, and the leak tests pass. No real IMEI, ICCID, MSISDN, names or other identifiers.
- [ ] No secrets, credentials, tokens or keys anywhere in the diff, the PR text or the logs.
- [ ] No Iridium PDFs, guides or catalog extracts (they stay in `Globalsat-Group/IWS`).
- [ ] No call to IWS production or Beta, and no DEACTIVE. No agent called SITEST: any SITEST call was made by the CTO through the recorder, from a merged recording plan, and any SITEST write was on assigned test inventory.

## Notes for the reviewer

<!-- Anything the CTO should look at first, open questions, follow-ups. -->
