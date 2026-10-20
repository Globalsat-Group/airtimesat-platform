# Role for CI, assumed through GitHub OIDC with no long-lived keys (re-plan §8.2).
# Not used yet: it has no permissions attached. Its trust policy is on the mandatory-review list (re-plan §3.3).

data "aws_partition" "current" {}
data "aws_caller_identity" "current" {}

locals {
  oidc_host         = "token.actions.githubusercontent.com"
  oidc_provider_arn = var.create_oidc_provider ? aws_iam_openid_connect_provider.github[0].arn : "arn:${data.aws_partition.current.partition}:iam::${data.aws_caller_identity.current.account_id}:oidc-provider/${local.oidc_host}"
}

# The landing zone may already provide the GitHub OIDC provider (AWS account request, item 5). Create it here only if not.
resource "aws_iam_openid_connect_provider" "github" {
  count = var.create_oidc_provider ? 1 : 0

  url            = "https://${local.oidc_host}"
  client_id_list = ["sts.amazonaws.com"]
  tags           = var.tags
}

data "aws_iam_policy_document" "trust" {
  statement {
    sid     = "GitHubActionsOnMainOfThisRepository"
    effect  = "Allow"
    actions = ["sts:AssumeRoleWithWebIdentity"]

    principals {
      type        = "Federated"
      identifiers = [local.oidc_provider_arn]
    }

    condition {
      test     = "StringEquals"
      variable = "${local.oidc_host}:aud"
      values   = ["sts.amazonaws.com"]
    }

    # Exact match: only workflow runs on this repository's main branch. No wildcards.
    condition {
      test     = "StringEquals"
      variable = "${local.oidc_host}:sub"
      values   = ["repo:${var.github_repository}:ref:refs/heads/${var.branch}"]
    }
  }
}

resource "aws_iam_role" "ci" {
  name                 = var.role_name
  description          = "CI role for ${var.github_repository} on ${var.branch}, through GitHub OIDC. No permissions yet."
  assume_role_policy   = data.aws_iam_policy_document.trust.json
  max_session_duration = 3600
  tags                 = var.tags
}
