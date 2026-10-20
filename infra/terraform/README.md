# Terraform

AWS foundations for the IWS gateway, the recorder and masker, and the TAP archive. Written by agents, reviewed line by line by the CTO (re-plan §3.3), and **never applied by agents or CI**. The CTO applies `envs/sandbox` once the AWS account exists (S0 runbook 3.3).

## Layout

| Path | What it holds |
|---|---|
| `modules/kms` | One customer-managed key per purpose, rotation on |
| `modules/secrets` | Secrets Manager entries for the IWS credentials, one per environment; read-deny policy except listed roles; alarm on every read. Values are never in code |
| `modules/network` | Gateway VPC: private subnets, one NAT gateway with a fixed Elastic IP, no inbound, flow logs |
| `modules/archive_bucket` | TAP archive (S1): versioning, Object Lock in governance mode, SSE-KMS, public access block, TLS-only policy, lifecycle |
| `modules/budget` | Monthly AWS Budgets alarm |
| `modules/github_oidc` | CI role trusted only for `Globalsat-Group/airtimesat-platform` on `main`; no permissions yet |
| `envs/sandbox` | Composes the modules; local state; S3 backend block commented out |

## Checks

`make terraform` runs `terraform fmt -check`, `init -backend=false -lockfile=readonly` (providers must match `.terraform.lock.hcl`), `validate` and `checkov`, and fails if checkov parsed nothing. Every checkov skip has its reason next to it.

## Before the first apply (CTO)

1. Copy `envs/sandbox/terraform.tfvars.example` to `terraform.tfvars` (git-ignored) and fill each `[FILL]`.
2. Region, budget amount, archive on or off, and archive retention are open decisions: ST-15, the run cost, the G0 memo and Legal.
3. The secret-read alarm needs a CloudTrail trail that logs management events in the account.
4. Store IWS credential values by hand in the console or CLI. Never in Terraform, tfvars or state.
