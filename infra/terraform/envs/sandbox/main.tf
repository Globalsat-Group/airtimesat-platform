# Sandbox composition. Never applied by agents or CI: the CTO applies it once the AWS account exists
# (S0 runbook 3.3), after the line-by-line review the re-plan requires for Terraform and IAM (§3.3).

data "aws_caller_identity" "current" {}

locals {
  environment = "sandbox"
  name        = "airtimesat-${local.environment}"
}

module "kms_secrets" {
  source = "../../modules/kms"

  alias       = "${local.name}-secrets"
  description = "Encrypts the IWS credential secrets (${local.environment})."
}

module "kms_ops" {
  source = "../../modules/kms"

  alias                 = "${local.name}-ops"
  description           = "Encrypts log groups and alarm topics (${local.environment})."
  allow_cloudwatch_logs = true
  allow_sns             = true
}

module "secrets" {
  source = "../../modules/secrets"

  name_prefix        = "airtimesat/${local.environment}"
  environments       = var.iws_credential_environments
  kms_key_arn        = module.kms_secrets.key_arn
  alerts_kms_key_arn = module.kms_ops.key_arn
  alert_emails       = toset(var.alert_emails)
}

module "network" {
  source = "../../modules/network"

  name             = "${local.name}-gateway"
  cidr_block       = var.vpc_cidr
  logs_kms_key_arn = module.kms_ops.key_arn
}

module "budget" {
  source = "../../modules/budget"

  name              = "${local.name}-monthly"
  monthly_limit_usd = var.budget_monthly_limit_usd
  alert_emails      = var.alert_emails
}

module "github_oidc" {
  source = "../../modules/github_oidc"

  role_name            = "${local.name}-ci"
  create_oidc_provider = var.create_github_oidc_provider
}

module "kms_archive" {
  source = "../../modules/kms"
  count  = var.enable_archive_bucket ? 1 : 0

  alias       = "${local.name}-tap-archive"
  description = "Encrypts the TAP file archive (${local.environment})."
}

module "archive_bucket" {
  source = "../../modules/archive_bucket"
  count  = var.enable_archive_bucket ? 1 : 0

  bucket_name    = "${local.name}-tap-archive-${data.aws_caller_identity.current.account_id}"
  retention_days = var.archive_retention_days
  kms_key_arn    = module.kms_archive[0].key_arn

  governance_admin_role_arns = var.archive_governance_admin_role_arns
}
