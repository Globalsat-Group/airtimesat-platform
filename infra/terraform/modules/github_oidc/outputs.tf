output "role_arn" {
  description = "ARN of the CI role (no permissions attached yet)."
  value       = aws_iam_role.ci.arn
}

output "oidc_provider_arn" {
  description = "ARN of the GitHub OIDC identity provider the role trusts."
  value       = local.oidc_provider_arn
}
