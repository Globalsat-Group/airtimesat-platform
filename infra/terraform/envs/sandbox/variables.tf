variable "region" {
  description = "AWS region. Open until the ST-15 latency probe in the gateway spike (Annex F §7.2); candidates: us-east-1, us-east-2, sa-east-1 (Annex D). Data residency per country is part of the Legal task in S0."
  type        = string

  validation {
    condition     = contains(["us-east-1", "us-east-2", "sa-east-1"], var.region)
    error_message = "Use one of the ST-15 candidates: us-east-1, us-east-2, sa-east-1."
  }
}

variable "alert_emails" {
  description = "Email addresses for the budget alerts and the secret-read alarm (a shared mailbox and the deputy). Set them in a git-ignored tfvars file."
  type        = list(string)
}

variable "budget_monthly_limit_usd" {
  description = "Monthly AWS budget in US dollars. The run cost is open (re-plan §7, §12), so the CTO sets it; no default."
  type        = number
}

variable "iws_credential_environments" {
  description = "IWS environments with a credential entry in this account. Only SITEST by default: the CTO decides whether a sandbox account may hold anything else (AWS account request §3)."
  type        = set(string)
  default     = ["sitest"]
}

variable "vpc_cidr" {
  description = "Gateway VPC CIDR. Agree it with NuageIT so it does not overlap the landing zone."
  type        = string
  default     = "10.60.0.0/20"
}

variable "create_github_oidc_provider" {
  description = "Create the GitHub OIDC provider here. Set false if the landing zone already provides it."
  type        = bool
  default     = true
}

variable "enable_archive_bucket" {
  description = "Create the TAP archive bucket (stage S1). Only if the G0 memo finds TAP files at risk (re-plan §4 S1); no default."
  type        = bool
}

variable "archive_retention_days" {
  description = "Object Lock retention in days for the TAP archive, set by Legal. Required when enable_archive_bucket is true; null otherwise."
  type        = number
  nullable    = true

  validation {
    condition     = var.enable_archive_bucket ? var.archive_retention_days != null : true
    error_message = "Set archive_retention_days (from Legal) when enable_archive_bucket is true."
  }
}

variable "archive_governance_admin_role_arns" {
  description = "Full IAM role ARNs, path included, allowed to bypass the archive's governance retention or change its lock and bucket policy (break-glass, and the deploy role if Terraform must later change the archive policy, this list or archive_retention_days). Decide it before the first apply: afterwards only a listed role can change it. Empty means nobody, short of the account root user."
  type        = list(string)
  default     = []
}
