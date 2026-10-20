output "secret_arns" {
  description = "ARN of each IWS credential secret, keyed by environment."
  value       = { for env, secret in aws_secretsmanager_secret.iws : env => secret.arn }
}

output "secret_read_topic_arn" {
  description = "ARN of the SNS topic that receives an event on every secret read."
  value       = aws_sns_topic.secret_reads.arn
}
