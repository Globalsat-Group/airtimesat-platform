# airtimesat-platform

Globalsat's platform for both Iridium programs, in one repository:

- **Phase 1:** an Ops-only console over Iridium's IWS SOAP API, with an IWS gateway.
- **Phase 2:** starting with a TAP file archive (stage S1, only if files are at risk).

**Status:** foundations only (stage S0). No business logic yet. Nothing here talks to Iridium, SITEST or AWS, and the Terraform has never been applied.

The plans, decisions and stage definitions live in the documentation repository: <https://github.com/Globalsat-Group/IWS> (start with `docs/delivery/DELIVERY_REPLAN.md`).

Rules for agents and humans: [CLAUDE.md](CLAUDE.md). Reporting a vulnerability: [SECURITY.md](SECURITY.md). GitHub setup that only the CTO can do: [docs/SETUP_CHECKLIST.md](docs/SETUP_CHECKLIST.md).

## Layout

```text
src/airtimesat_platform/
  gateway/    The only code that talks to IWS. Public port: gateway/api.py. Built in stage S3.
  masker/     Recorder and masker: the only path from agents to SITEST. Stage S2.
  domain/     Normalized domain model (anti-corruption layer). Pure Python.
  console/    Ops console (FastAPI + Jinja2/HTMX). Only /healthz for now.
  archive/    Phase 2 TAP archive job. Stage S1.
  common/     Config, structured logging, secrets access interface.
tests/        Smoke tests per package and the import-contract test.
infra/terraform/
  modules/    kms, secrets, network, archive_bucket, budget, github_oidc
  envs/sandbox/  Composes the modules. Local backend. Never applied.
.github/      CI, Dependabot, CODEOWNERS, PR template.
docs/         Setup checklist and, later, ADRs and runbooks.
```

Module boundaries are enforced by import-linter. They are listed in words in [CLAUDE.md](CLAUDE.md#module-boundaries-enforced-by-import-linter).

## Run the checks

You need:

| Tool | Version | Used by |
| --- | --- | --- |
| Python | 3.12 | everything (uv installs it if missing) |
| uv | 0.11.32 | Python dependencies and commands |
| GNU make | any | entry point |
| terraform | 1.9.8 | `make terraform` |
| gitleaks | 8.21.2 | `make security` |
| actionlint | 1.7.4 | `make workflows` |
| checkov | 3.3.29 | `make terraform`, `make workflows` |

Then:

```sh
uv sync --locked   # install the locked dependencies into .venv
make check         # every gate CI runs
```

`make check` runs these targets, each also runnable on its own. CI runs one job per target, with the same name except `test`, whose job is `tests`:

| Target | What it runs | CI job |
| --- | --- | --- |
| `make lint` | `ruff check`, `ruff format --check` | `lint` |
| `make typecheck` | `pyright` (strict) | `typecheck` |
| `make contracts` | `lint-imports` | `contracts` |
| `make test` | `pytest` | `tests` |
| `make security` | gitleaks on the working tree, `pip-audit`, licence gate | `security` |
| `make terraform` | `terraform fmt -check`, `init -backend=false -lockfile=readonly` + `validate` for `envs/sandbox`, checkov | `terraform` |
| `make workflows` | `actionlint`, a check that bans `pull_request_target`, `workflow_run` and `issue_comment`, checkov on `.github/workflows` | `workflows` |

The CI `security` job also runs gitleaks over the full git history.

Optional local hooks (ruff and gitleaks): `uvx pre-commit install`.

## Contributing

- Work on a branch and open a PR to `main`. `main` is protected: one approval, Code Owner review, and all CI jobs green.
- Run `make check` before opening the PR and fill in the PR template.
- Agent PRs come from the bot identity; the CTO reviews and merges.
