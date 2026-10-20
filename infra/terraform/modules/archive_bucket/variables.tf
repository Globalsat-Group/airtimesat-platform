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

variable "governance_admin_role_arns" {
  description = "Full IAM role ARNs, path included, that may bypass governance retention or change the Object Lock configuration and the bucket policy: a break-glass role, and the Terraform deploy role if it must later change the bucket policy, this list or the retention. Decide it before the first apply: afterwards only a listed role can change it. Empty means nobody, short of the account root user."
  type        = list(string)
  default     = []

  validation {
    condition     = alltrue([for arn in var.governance_admin_role_arns : can(regex("^arn:aws[a-z-]*:iam::[0-9]{12}:role/", arn))])
    error_message = "Each entry must be an IAM role ARN (arn:aws:iam::<account>:role/<name>)."
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
