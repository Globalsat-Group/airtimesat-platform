provider "aws" {
  region = var.region

  default_tags {
    tags = {
      project     = "airtimesat-platform"
      environment = local.environment
      managed_by  = "terraform"
      repository  = "Globalsat-Group/airtimesat-platform"
    }
  }
}
