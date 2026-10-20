variable "name" {
  description = "Budget name."
  type        = string
}

variable "monthly_limit_usd" {
  description = "Monthly budget in US dollars. The CTO sets it; the run cost is still open (re-plan §7, §12), so there is no default."
  type        = number

  validation {
    condition     = var.monthly_limit_usd > 0
    error_message = "The budget must be greater than zero."
  }
}

variable "actual_thresholds_percent" {
  description = "Alert when actual spend passes these percentages of the budget."
  type        = set(number)
  default     = [50, 80, 100]
}

variable "alert_emails" {
  description = "Email addresses that receive budget alerts (1 to 10). Set them in a git-ignored tfvars file."
  type        = list(string)

  validation {
    condition     = length(var.alert_emails) >= 1 && length(var.alert_emails) <= 10
    error_message = "Give between 1 and 10 email addresses."
  }
}

variable "tags" {
  description = "Tags for the budget."
  type        = map(string)
  default     = {}
}
