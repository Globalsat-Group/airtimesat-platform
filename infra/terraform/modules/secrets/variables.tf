variable "name_prefix" {
  description = "Prefix for secret names, for example \"airtimesat/sandbox\". Secrets are named <prefix>/iws/<environment>."
  type        = string

  validation {
    condition     = can(regex("^[a-z0-9][a-z0-9/-]*[a-z0-9]$", var.name_prefix))
    error_message = "Use lower-case letters, digits, \"/\" and \"-\"."
  }
}

variable "environments" {
  description = "IWS environments that get a credential entry in this account: any of sitest, beta, production."
  type        = set(string)

  validation {
    condition     = length(var.environments) > 0 && alltrue([for e in var.environments : contains(["sitest", "beta", "production"], e)])
    error_message = "Use one or more of: sitest, beta, production."
  }
}

variable "reader_role_arns" {
  description = "IAM role ARNs allowed to read each environment's secret, keyed by environment. Only the gateway role belongs here, plus the masker role under sitest only (CTO decision, 20 Oct 2026). An environment with no entry cannot be read by anyone."
  type        = map(list(string))
  default     = {}
}

variable "kms_key_arn" {
  description = "ARN of the KMS key that encrypts the secrets."
  type        = string
}

variable "alerts_kms_key_arn" {
  description = "ARN of the KMS key that encrypts the secret-read alarm topic. The key must allow EventBridge to use it."
  type        = string
}

variable "alert_emails" {
  description = "Email addresses subscribed to the secret-read alarm. Set them in a git-ignored tfvars file."
  type        = set(string)
  default     = []
}

variable "tags" {
  description = "Tags for every resource."
  type        = map(string)
  default     = {}
}
