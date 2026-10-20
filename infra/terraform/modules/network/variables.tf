variable "name" {
  description = "Name for the VPC and a prefix for its resources, for example \"airtimesat-sandbox-gateway\"."
  type        = string
}

variable "cidr_block" {
  description = "VPC CIDR block. Agree it with NuageIT so it does not overlap the landing zone."
  type        = string
  default     = "10.60.0.0/20"

  validation {
    condition     = can(cidrnetmask(var.cidr_block))
    error_message = "Give a valid IPv4 CIDR block."
  }
}

variable "private_subnet_count" {
  description = "Number of private subnets, one per availability zone (2 keeps a second zone ready for the database later)."
  type        = number
  default     = 2

  validation {
    condition     = var.private_subnet_count >= 1 && var.private_subnet_count <= 3
    error_message = "Use 1 to 3 private subnets."
  }
}

variable "logs_kms_key_arn" {
  description = "ARN of the KMS key for the flow-log group. The key must allow CloudWatch Logs to use it."
  type        = string
}

variable "flow_log_retention_days" {
  description = "Days to keep VPC flow logs."
  type        = number
  default     = 365
}

variable "tags" {
  description = "Tags for every resource."
  type        = map(string)
  default     = {}
}
