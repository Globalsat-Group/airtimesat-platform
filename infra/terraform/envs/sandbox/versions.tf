terraform {
  # A floor, not a pin: CI installs exactly TERRAFORM_VERSION (.github/workflows/ci.yml).
  # An exact pin made Dependabot's newer Terraform refuse to init, so it could never
  # propose provider updates.
  required_version = ">= 1.9.8, < 2.0.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "6.66.0"
    }
  }

  # Local state only until the AWS account exists. Never applied from CI.
  # When the account exists, the CTO creates the state bucket by hand, then replaces this comment
  # with the block below and runs `terraform init -migrate-state`.
  #
  # backend "s3" {
  #   bucket       = "[FILL: state bucket name]"
  #   key          = "airtimesat-platform/sandbox/terraform.tfstate"
  #   region       = "[FILL: region decided after ST-15]"
  #   encrypt      = true
  #   kms_key_id   = "[FILL: state KMS key ARN]"
  #   use_lockfile = true
  # }
}
