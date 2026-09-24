variable "expected_aws_account_id" {
  description = "AWS account that is authorized to own this stack."
  type        = string
  default     = "280469140135"

  validation {
    condition     = var.expected_aws_account_id == "280469140135"
    error_message = "This stack is restricted to AWS account 280469140135."
  }
}

variable "aws_profile" {
  description = "Local AWS shared-configuration profile."
  type        = string
  default     = "Users-280469140135"

  validation {
    condition     = var.aws_profile == "Users-280469140135"
    error_message = "Use the approved Users-280469140135 profile."
  }
}

variable "aws_region" {
  description = "AWS region for the application origin."
  type        = string
  default     = "us-east-1"

  validation {
    condition     = var.aws_region == "us-east-1"
    error_message = "This stack is restricted to us-east-1."
  }
}

variable "namespace" {
  description = "F5 Distributed Cloud namespace."
  type        = string
  default     = "client-side-defense"

  validation {
    condition     = var.namespace == "client-side-defense"
    error_message = "This stack is restricted to the client-side-defense namespace."
  }
}

variable "domain" {
  description = "Public application domain protected by F5 Distributed Cloud."
  type        = string
  default     = "client-side-defense.f5-sales-demo.com"

  validation {
    condition     = var.domain == "client-side-defense.f5-sales-demo.com"
    error_message = "This stack is restricted to client-side-defense.f5-sales-demo.com."
  }
}

variable "vpc_cidr" {
  description = "CIDR for the dedicated CSD application VPC."
  type        = string
  default     = "10.43.0.0/16"

  validation {
    condition     = var.vpc_cidr == "10.43.0.0/16"
    error_message = "The reviewed dedicated VPC CIDR is 10.43.0.0/16."
  }
}

variable "public_subnet_cidrs" {
  description = "CIDRs for public ALB subnets in us-east-1a and us-east-1b."
  type        = list(string)
  default     = ["10.43.0.0/24", "10.43.1.0/24"]

  validation {
    condition     = tolist(var.public_subnet_cidrs) == tolist(["10.43.0.0/24", "10.43.1.0/24"])
    error_message = "Public subnet CIDRs must retain the reviewed two-AZ layout."
  }
}

variable "private_subnet_cidrs" {
  description = "CIDRs for private Fargate subnets in us-east-1a and us-east-1b."
  type        = list(string)
  default     = ["10.43.10.0/24", "10.43.11.0/24"]

  validation {
    condition     = tolist(var.private_subnet_cidrs) == tolist(["10.43.10.0/24", "10.43.11.0/24"])
    error_message = "Private subnet CIDRs must retain the reviewed two-AZ layout."
  }
}


variable "tags" {
  description = "Tags applied to supported AWS resources."
  type        = map(string)
  default = {
    application = "client-side-defense"
    managed-by  = "terraform"
    repository  = "f5-sales-demo/csd"
  }
}
