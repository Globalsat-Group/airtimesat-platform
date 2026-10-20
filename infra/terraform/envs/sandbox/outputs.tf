output "nat_egress_ip" {
  description = "Fixed egress IP for ST-15 and for Iridium's IP allowlist."
  value       = module.network.nat_egress_ip
}

output "iws_secret_arns" {
  description = "IWS credential secrets by environment. The CTO sets the values by hand."
  value       = module.secrets.secret_arns
}

output "ci_role_arn" {
  description = "CI role for GitHub OIDC (no permissions yet)."
  value       = module.github_oidc.role_arn
}

output "archive_bucket_name" {
  description = "TAP archive bucket, or null when the archive is not enabled."
  value       = var.enable_archive_bucket ? module.archive_bucket[0].bucket_name : null
}
