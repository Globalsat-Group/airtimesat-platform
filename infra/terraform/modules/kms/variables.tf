variable "alias" {
  description = "Alias name without the \"alias/\" prefix, for example \"airtimesat-sandbox-secrets\"."
  type        = string

  validation {
    condition     = can(regex("^[a-zA-Z0-9/_-]+$", var.alias)) && !startswith(var.alias, "aws/")
    error_message = "Use letters, digits, \"/\", \"_\" or \"-\", and do not start with \"aws/\"."
  }
}

variable "description" {
  description = "What the key protects."
  type        = string
}

variable "deletion_window_in_days" {
  description = "Waiting period before a scheduled key deletion takes effect (7 to 30 days)."
  type        = number
  default     = 30

  validation {
    condition     = var.deletion_window_in_days >= 7 && var.deletion_window_in_days <= 30
    error_message = "The deletion window must be between 7 and 30 days."
  }
}

variable "allow_cloudwatch_logs" {
  description = "Let CloudWatch Logs in this account and region encrypt log groups with the key."
  type        = bool
  default     = false
}

variable "allow_sns" {
  description = "Let EventBridge rules in this account publish to SNS topics encrypted with the key."
  type        = bool
  default     = false
}

variable "tags" {
  description = "Tags for the key."
  type        = map(string)
  default     = {}
}
