# Monthly cost budget with email alerts (re-plan §4 S0: AWS account with a budget alarm).
# The amount has no default: the run cost (about US$150-300/month, inferred) is not approved yet (re-plan §7, §12).

resource "aws_budgets_budget" "monthly" {
  name         = var.name
  budget_type  = "COST"
  limit_amount = format("%.2f", var.monthly_limit_usd)
  limit_unit   = "USD"
  time_unit    = "MONTHLY"

  dynamic "notification" {
    for_each = var.actual_thresholds_percent

    content {
      comparison_operator        = "GREATER_THAN"
      notification_type          = "ACTUAL"
      threshold                  = notification.value
      threshold_type             = "PERCENTAGE"
      subscriber_email_addresses = var.alert_emails
    }
  }

  notification {
    comparison_operator        = "GREATER_THAN"
    notification_type          = "FORECASTED"
    threshold                  = 100
    threshold_type             = "PERCENTAGE"
    subscriber_email_addresses = var.alert_emails
  }

  tags = var.tags
}
