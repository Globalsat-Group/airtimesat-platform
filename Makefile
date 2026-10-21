# One local entry point for every check. CI calls the same targets by name, except `plans`:
# CI's recorder-check job judges a pull request's changed plans with the base commit's checker.
# Tools come from PATH: uv, gitleaks, terraform, checkov, actionlint.
# Python tools run through uv from the locked environment.

SHELL := /bin/bash
.SHELLFLAGS := -eu -o pipefail -c
.DEFAULT_GOAL := help

UV_RUN := uv run --locked
TF_DIR := infra/terraform
TF_ENV := $(TF_DIR)/envs/sandbox

# checkov exits 0 when it cannot parse a file, and then checks nothing in it. Keep its exit
# code, and also fail unless at least one check passed and no file failed to parse.
CHECKOV = run_checkov() { rc=0; out="$$(checkov "$$@" --quiet --compact)" || rc=$$?; \
	printf '%s\n' "$$out"; [ "$$rc" -eq 0 ] || return "$$rc"; \
	if ! grep -q 'Passed checks: [1-9]' <<<"$$out" || grep -q 'Parsing errors' <<<"$$out"; then \
	echo "checkov: no checks ran or a file did not parse" >&2; return 1; fi; }; run_checkov

# Triggers that run with the main branch's token and OIDC subject but can be fired by a pull
# request or a comment.
BANNED_TRIGGERS := pull_request_target|workflow_run|issue_comment

.PHONY: help sync lint format typecheck contracts test plans security gitleaks leak-scan audit \
	licences terraform workflows check run

help: ## List targets
	@grep -E '^[a-z-]+:.*## ' $(MAKEFILE_LIST) | awk -F':.*## ' '{printf "  %-11s %s\n", $$1, $$2}'

sync: ## Install the locked environment (.venv)
	uv sync --locked

lint: ## ruff check and ruff format --check
	$(UV_RUN) ruff check .
	$(UV_RUN) ruff format --check .

format: ## Apply ruff fixes and formatting (local use only)
	$(UV_RUN) ruff check --fix .
	$(UV_RUN) ruff format .

typecheck: ## pyright in strict mode
	$(UV_RUN) pyright

contracts: ## import-linter module boundaries
	$(UV_RUN) lint-imports

test: ## pytest with coverage
	$(UV_RUN) pytest

# CI has no `plans` job: its recorder-check job judges a pull request's changed plans with the
# base commit's checker. This target judges, with the working tree's checker, the plans that
# differ from origin/main (committed or not, untracked included), so a merged plan that has
# expired, or that a later checker refuses, does not fail every later `make check`. Without
# origin/main it judges every plan. Anything under recording-plans/ that is neither a
# directory nor a regular file (a symlink, for example) fails.
plans: ## recorder check over the plans changed against origin/main (passes when there are none)
	@if [ ! -d recording-plans ]; then echo "plans: no recording plans"; exit 0; fi; \
	if [ -n "$$(find recording-plans ! -type d ! -type f -print -quit)" ]; then \
		echo "plans: recording-plans/ may hold only regular files" >&2; exit 1; fi; \
	list="$$(mktemp)"; trap 'rm -f "$$list"' EXIT; \
	if base="$$(git merge-base HEAD origin/main 2>/dev/null)"; then \
		{ git diff -z --name-only --no-renames --diff-filter=d "$$base" -- recording-plans/; \
			git ls-files -z --others --exclude-standard -- recording-plans/; } \
			| sort -zu > "$$list"; \
	else \
		find recording-plans ! -type d -print0 | sort -z > "$$list"; \
	fi; \
	if [ ! -s "$$list" ]; then echo "plans: no changed recording plans"; \
	else xargs -0 $(UV_RUN) python -m airtimesat_platform.recorder check -- < "$$list"; fi

security: gitleaks leak-scan audit licences ## gitleaks, leak scan, pip-audit and the licence gate

gitleaks: ## Scan the working tree for secrets
	gitleaks dir . --redact --no-banner --verbose

leak-scan: ## Scan the working tree for real identifiers (design s2-recorder-masker §8.3)
	$(UV_RUN) python scripts/leak_scan.py

audit: ## pip-audit over every locked dependency, dev group included
	@req="$$(mktemp)"; trap 'rm -f "$$req"' EXIT; \
	uv export --locked --all-groups --no-emit-project --format requirements-txt --quiet -o "$$req"; \
	$(UV_RUN) pip-audit --strict --progress-spinner off --disable-pip --require-hashes -r "$$req"

licences: ## Licence gate (licensing/allowlist.toml, licensing/exceptions.toml)
	$(UV_RUN) python scripts/licence_gate.py

terraform: ## terraform fmt, init -backend=false + validate (sandbox), checkov
	terraform fmt -check -recursive $(TF_DIR)
	terraform -chdir=$(TF_ENV) init -backend=false -input=false -lockfile=readonly
	terraform -chdir=$(TF_ENV) validate
	@echo "checkov --directory $(TF_DIR) --framework terraform"
	@$(CHECKOV) --directory $(TF_DIR) --framework terraform

workflows: ## actionlint, banned-trigger check and checkov over .github/workflows
	actionlint
	@if grep -rnwE '$(BANNED_TRIGGERS)' .github/workflows; then \
		echo "workflows: $(BANNED_TRIGGERS) are not allowed (docs/SETUP_CHECKLIST.md)" >&2; exit 1; fi
	@echo "checkov --directory .github/workflows --framework github_actions"
	@$(CHECKOV) --directory .github/workflows --framework github_actions

check: lint typecheck contracts test plans security terraform workflows ## Every CI check (plans: see above)

run: ## Start the console locally on http://127.0.0.1:8000
	$(UV_RUN) uvicorn --factory airtimesat_platform.console.app:create_app --host 127.0.0.1 --port 8000
