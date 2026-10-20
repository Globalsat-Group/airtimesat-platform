variable "github_repository" {
  description = "GitHub repository allowed to assume the role, as owner/name."
  type        = string
  default     = "Globalsat-Group/airtimesat-platform"

  validation {
    condition     = can(regex("^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$", var.github_repository))
    error_message = "Use owner/name, with no wildcards."
  }
}

variable "branch" {
  description = "Branch whose workflow runs may assume the role."
  type        = string
  default     = "main"

  validation {
    condition     = can(regex("^[A-Za-z0-9_./-]+$", var.branch))
    error_message = "Give one branch name, with no wildcards."
  }
}

variable "role_name" {
  description = "Name of the CI role."
  type        = string
}

variable "create_oidc_provider" {
  description = "Create the GitHub OIDC identity provider in this account. Set false if the landing zone already has one."
  type        = bool
  default     = true
}

variable "tags" {
  description = "Tags for every resource."
  type        = map(string)
  default     = {}
}
