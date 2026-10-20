variable "bucket_name" {
  description = "Globally unique bucket name."
  type        = string

  validation {
    condition     = can(regex("^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$", var.bucket_name))
    error_message = "Use 3-63 lower-case letters, digits, dots or hyphens."
  }
}

variable "retention_days" {
  description = "Object Lock retention in days (governance mode). Legal sets it per country (re-plan §4 S0, §8.6); there is no default on purpose."
  type        = number

  validation {
    condition     = var.retention_days >= 1 && floor(var.retention_days) == var.retention_days
    error_message = "Retention must be a whole number of days, at least 1."
  }
}

variable "kms_key_arn" {
  description = "ARN of the KMS key that encrypts archived objects."
  type        = string
}

variable "tags" {
  description = "Tags for every resource."
  type        = map(string)
  default     = {}
}
