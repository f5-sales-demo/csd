terraform {
  required_version = ">= 1.14.0"

  backend "s3" {
    bucket       = "terraform-tfstate-xc"
    key          = "f5-sales-demo/client-side-defense.tfstate"
    region       = "us-east-1"
    use_lockfile = true
    encrypt      = true
  }

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 6.0, < 7.0"
    }

    xcsh = {
      source  = "f5-sales-demo/xcsh"
      version = "9.5.1"
    }
  }
}

provider "aws" {
  profile = var.aws_profile
  region  = var.aws_region

  default_tags {
    tags = var.tags
  }
}

provider "xcsh" {}
