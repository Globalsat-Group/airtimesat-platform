# GitHub setup checklist (CTO only)

What only the CTO can do in GitHub to finish S0 action 3.1 (`Globalsat-Group/IWS`, `docs/delivery/s0/README.md`). Do the steps in this order. Each step says why, where, and when it is done.

S0 action 3.1 is done when: the repository is private, `main` is protected, CI runs green on the first PR, and the bot identity's PRs need the CTO's approval.

## Required status checks

The CI workflow (`.github/workflows/ci.yml`, workflow name `CI`) has seven jobs. Their names are the required checks. Type them exactly, in lower case:

| Required check | What it gates |
| --- | --- |
| `lint` | `ruff check`, `ruff format --check` |
| `typecheck` | `pyright` strict |
| `contracts` | import-linter module boundaries |
| `tests` | `pytest` |
| `security` | gitleaks (working tree and git history), `pip-audit`, licence gate |
| `terraform` | `terraform fmt`, `validate`, checkov |
| `workflows` | actionlint, banned-trigger check, checkov on workflows |

The PR page shows them as `CI / lint (pull_request)` and so on, but the check name is the job name. If a job is ever renamed in `ci.yml`, update the ruleset in the same PR, or every merge is blocked.

## 1. Create the empty private repository

- **Why.** One private repository for both phases (CTO decision, 20 Oct 2026). Empty, so the first push is clean and there is no history to reconcile.
- **Where.** GitHub → Globalsat-Group → Repositories → New repository. Name `airtimesat-platform`. Visibility **Private**. Do **not** add a README, a licence or a `.gitignore`.
- **Done when.** `https://github.com/Globalsat-Group/airtimesat-platform` exists, is private and has no commits.

## 2. Restrict access to the CTO and the bot

- **Why.** Re-plan §8.6 interim rule: private repository with restricted access while Legal and the Channel Manager answer the cloud AI question.
- **Where.** Repository → Settings → Collaborators and teams. Remove every team and person except the CTO. Check Organization → Settings → Member privileges → Base permissions: if it is Read or higher, every org member can read this repository. Note who the organization owners are: they have admin on every repository.
- **Done when.** Collaborators and teams lists only the CTO (the bot is added in step 9). The org base permission is "No permission", or the exception is written down.

## 3. Confirm the CODEOWNERS handle

- **Why.** `.github/CODEOWNERS` names `@imtgsat` as owner of everything and of the mandatory-review paths (re-plan §3.3). A wrong handle, or one without write access, silently disables Code Owner review.
- **Where.** Confirm `@imtgsat` is the CTO's account. If not, change every line of `.github/CODEOWNERS` before the first push. After the push, open `.github/CODEOWNERS` on GitHub: it shows a warning if a line is invalid.
- **Done when.** The handle is confirmed and GitHub shows no CODEOWNERS errors.

## 4. Set Actions permissions

- **Why.** Before the first CI run, so no run ever has a write token. CI needs no secrets and only reads the repository.
- **Where.** Repository → Settings → Actions → General. Organization policies can override these; if a setting is greyed out, an org owner sets it at Organization → Settings → Actions.
  - Actions permissions: allow actions created by GitHub, plus selected actions: `astral-sh/setup-uv@*` and `hashicorp/setup-terraform@*`. If offered, turn on **Require actions to be pinned to a full-length commit SHA**.
  - Workflow permissions: **Read repository contents and packages permissions**. Leave **Allow GitHub Actions to create and approve pull requests** off: no workflow may approve a PR.
  - Fork pull request workflows: do not run workflows from forks. Require approval for all outside collaborators. Never send secrets or write tokens to fork PRs.
  - Organization → Settings → Secrets and variables (Actions, Dependabot, Codespaces): an org secret or variable with access "All repositories" reaches this repository's workflows, PR runs from its own branches included. Set every one to "Selected repositories" without this one.
- **Done when.** The settings are saved, no option is overridden by a more permissive org policy, and Repository → Settings → Secrets and variables → Actions lists no organization secret.

## 5. Turn on secret scanning, push protection and Dependabot

- **Why.** Push protection stops a secret before it lands in git. Dependabot alerts and security updates cover vulnerable dependencies between the monthly update PRs (re-plan §8.7).
- **Where.** Repository → Settings → Advanced Security (called "Code security" on some plans).
  - Dependency graph: Enable. Dependabot alerts: Enable. Dependabot security updates: Enable.
  - Secret Protection: Enable secret scanning and **push protection**. On private repositories this needs a GitHub Secret Protection licence. Without it, gitleaks in CI and the optional pre-commit hook are the only secret controls; write that down.
  - Private vulnerability reporting: enable it if available, so `SECURITY.md` can point to it.
- **Done when.** Each toggle is on, or the missing licence is recorded as a known gap.

## 6. First push

- **Why.** Publishes the reviewed foundations. It happens before the ruleset, because the ruleset blocks direct pushes to `main`.
- **Where.** On the CTO's machine, after reviewing the mandatory-review paths line by line (re-plan §3.3: `.github/workflows`, `infra/`, the GitHub OIDC trust policy, `CLAUDE.md`, `pyproject.toml`, `uv.lock`):

  ```sh
  git remote add origin git@github.com:Globalsat-Group/airtimesat-platform.git
  git push -u origin main
  ```

- **Done when.** The push succeeded and the `CI` run on `main` shows all seven jobs green under Actions.

## 7. Add the branch ruleset on `main`

- **Why.** Enforces the review rules: nothing reaches `main` without a PR, the CTO's approval as Code Owner, and green checks (re-plan §3.3).
- **Where.** Repository → Settings → Rules → Rulesets → New ruleset → New branch ruleset.
  - Name `main`. Enforcement status **Active**. Target branches: include the default branch.
  - Bypass list: only the Repository admin role, set to **For pull requests only**, for emergencies by the CTO. No bot, no team, no app. Organization owners also hold admin (step 2).
  - Restrict deletions: on. Block force pushes: on.
  - Require a pull request before merging: on.
    - Required approvals: **1**.
    - Dismiss stale pull request approvals when new commits are pushed: on.
    - Require review from Code Owners: on.
    - Require conversation resolution before merging: on (recommended).
    - Allowed merge methods: squash (recommended), so each PR is one commit on `main`.
  - Require status checks to pass: on.
    - Require branches to be up to date before merging: on.
    - Add the seven checks from the table above: `lint`, `typecheck`, `contracts`, `tests`, `security`, `terraform`, `workflows`. For each, set the source to **GitHub Actions**, so no other app can report a passing check with the same name.
  - Optional: require linear history; require signed commits.
- **Note.** GitHub does not let authors approve their own PRs. With the CTO as the only Code Owner, a PR opened from the CTO's own account can only merge through the bypass. Agent work comes from the bot (step 9), so this is the exception, not the rule.
- **Done when.** A direct push to `main` is rejected, and a test PR cannot merge until all seven checks pass and the CTO approves.

## 8. Confirm the first PR runs green

- **Why.** S0 action 3.1 exit criterion.
- **Where.** Open a small PR (for example filling a `[FILL]` in `SECURITY.md`). Watch Actions.
- **Done when.** All seven required checks pass on the PR and it merges only after the CTO's approval.

## 9. Create the bot identity for agent PRs

- **Why.** Agent PRs must come from a bot identity, never from the CTO's account, so the CTO can approve them and the history shows who wrote what (re-plan §3.3).
- **Where.** Organization → Settings → Developer settings → GitHub Apps → New GitHub App.
  - Name: [FILL: for example `globalsat-agents`]. Webhook: off.
  - Repository permissions: **Contents: Read and write**, **Pull requests: Read and write**. Metadata: Read (GitHub adds it). Nothing else: no Administration, no Actions, no Secrets, no Workflows.
  - Where can this app be installed: **Only on this account**.
  - Install it with **Only select repositories** → `airtimesat-platform`.
  - Generate the private key and store it in Keeper. It never goes into this repository, an agent session or a CI secret.
  - Without the Workflows permission, the bot cannot push changes under `.github/workflows/`; the CTO commits those, or grants that permission later as a recorded decision.
- **Done when.** A test PR opened by the bot shows the author as `<app-name>[bot]`, cannot merge without the CTO's approval, and the bot is in no bypass list.

## 10. Later steps (not needed for S0)

### AWS access from CI with OIDC

- **Why.** Re-plan §8.2: GitHub OIDC to AWS, no long-lived keys.
- **When.** After the AWS account exists (S0 action 3.2) and the CTO has reviewed `infra/terraform/modules/github_oidc` line by line.
- **Where.** The CTO applies the module. Store the role ARN as an Actions **variable** (not a secret). Add `permissions: id-token: write` only to the job that needs it. The trust policy accepts only the exact subject `repo:Globalsat-Group/airtimesat-platform:ref:refs/heads/main`. A job that sets `environment:` gets a different subject (`...:environment:<name>`), so using an environment means a reviewed change to that trust policy.
  - Every workflow that runs in the context of `main` gets that same subject, including `pull_request_target`, `workflow_run` and `issue_comment`, which a pull request or a comment can fire. `make workflows` rejects those three triggers; give `id-token: write` only to a job that runs on `push` to `main`.
  - If the landing zone already has the GitHub OIDC provider (NuageIT, item 5), check that none of its roles trusts a wildcard subject such as `repo:Globalsat-Group/*`: that role would accept this repository's tokens too.
- **Done when.** A job on `main` can assume the role, a job on a PR branch cannot, and no other role in the account trusts this repository.

### Environments with required reviewers

- **Why.** Production deployments are CTO-only (re-plan §3.2).
- **Where.** Repository → Settings → Environments → New environment `production`. Required reviewers: the CTO. Deployment branches and tags: `main` only. No environment secrets (use OIDC).
- **Done when.** A deployment job to `production` waits for the CTO's approval.

### Internal deputy

- **Why.** Re-plan §8.5: an internal deputy with read access to the repositories and second-admin rights on GitHub.
- **Where.** When the deputy is named: add them to the repository (Read, or Admin as second admin, as the CTO decides; Admin also holds the ruleset bypass of step 7). Keep the mandatory-review paths in `.github/CODEOWNERS` with the CTO.
- **Done when.** The deputy can read the repository and the runbooks, and CODEOWNERS still routes the mandatory-review paths to the CTO.
