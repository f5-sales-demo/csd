variable "name" {
  description = "DNS-safe prefix used for AWS resource names."
  type        = string

  validation {
    condition     = length(var.name) >= 2 && length(var.name) <= 32 && can(regex("^[a-z][a-z0-9-]*[a-z0-9]$", var.name))
    error_message = "name must be 2-32 characters, start with a lowercase letter, end with a lowercase letter or digit, and contain only lowercase letters, digits, and hyphens."
  }
}

variable "vpc_id" {
  description = "ID of the caller-managed VPC."
  type        = string

  validation {
    condition     = can(regex("^vpc-[0-9a-f]+$", var.vpc_id))
    error_message = "vpc_id must be an AWS VPC ID."
  }
}

variable "alb_subnet_ids" {
  description = "At least two caller-managed subnet IDs for ALB placement in the declared VPC and distinct Availability Zones."
  type        = list(string)

  validation {
    condition     = length(distinct(var.alb_subnet_ids)) >= 2 && alltrue([for id in var.alb_subnet_ids : can(regex("^subnet-[0-9a-f]+$", id))])
    error_message = "alb_subnet_ids must contain at least two distinct AWS subnet IDs."
  }
}

variable "task_subnet_ids" {
  description = "Caller-managed private subnet IDs for Fargate tasks. They must provide NAT/proxy egress for Docker Hub and AWS Logs, or equivalent endpoints and egress."
  type        = list(string)

  validation {
    condition     = length(var.task_subnet_ids) > 0 && alltrue([for id in var.task_subnet_ids : can(regex("^subnet-[0-9a-f]+$", id))])
    error_message = "task_subnet_ids must contain at least one valid AWS subnet ID."
  }
}

variable "public_exposure" {
  description = "Explicitly create an internet-facing rather than internal ALB. Use only for authorized demo infrastructure."
  type        = bool
  default     = false
}

variable "allowed_ingress_cidrs" {
  description = "Non-empty set of authorized IPv4 CIDRs allowed to reach HTTP. World-open ingress requires public_exposure=true."
  type        = set(string)
  default     = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]

  validation {
    condition     = length(var.allowed_ingress_cidrs) > 0 && alltrue([for cidr in var.allowed_ingress_cidrs : can(cidrnetmask(cidr)) && !strcontains(cidr, ":")]) && (var.public_exposure || !contains(var.allowed_ingress_cidrs, "0.0.0.0/0"))
    error_message = "allowed_ingress_cidrs must contain valid IPv4 CIDRs; 0.0.0.0/0 is allowed only when public_exposure is true."
  }
}

variable "container_image" {
  description = "OWASP Juice Shop OCI image reference pinned by immutable sha256 digest."
  type        = string
  default     = "docker.io/bkimminich/juice-shop@sha256:9e437b456e444ff001d1663e4f6f05c796fe02f1058dd2651d6791a15b43dfeb"

  validation {
    condition     = can(regex("^[^@]+@sha256:[0-9a-f]{64}$", var.container_image))
    error_message = "container_image must be an immutable image reference ending in @sha256:<64 lowercase hexadecimal characters>."
  }
}

variable "container_port" {
  description = "TCP port exposed by the Juice Shop container."
  type        = number
  default     = 3000

  validation {
    condition     = var.container_port >= 1024 && var.container_port <= 65535
    error_message = "container_port must be between 1024 and 65535."
  }
}

variable "desired_count" {
  description = "Number of Fargate tasks to run."
  type        = number
  default     = 1

  validation {
    condition     = var.desired_count >= 1 && floor(var.desired_count) == var.desired_count
    error_message = "desired_count must be a positive integer."
  }
}

variable "cpu" {
  description = "Fargate task CPU units."
  type        = number
  default     = 512

  validation {
    condition     = contains([256, 512, 1024, 2048, 4096, 8192, 16384], var.cpu)
    error_message = "cpu must be a supported Fargate CPU value."
  }
}

variable "memory" {
  description = "Fargate task memory in MiB."
  type        = number
  default     = 1024

  validation {
    condition = (
      var.cpu == 256 ? contains([512, 1024, 2048], var.memory) :
      var.cpu == 512 ? contains([1024, 2048, 3072, 4096], var.memory) :
      var.cpu == 1024 ? var.memory >= 2048 && var.memory <= 8192 && var.memory % 1024 == 0 :
      var.cpu == 2048 ? var.memory >= 4096 && var.memory <= 16384 && var.memory % 1024 == 0 :
      var.cpu == 4096 ? var.memory >= 8192 && var.memory <= 30720 && var.memory % 1024 == 0 :
      var.cpu == 8192 ? var.memory >= 16384 && var.memory <= 61440 && var.memory % 4096 == 0 :
      var.cpu == 16384 ? var.memory >= 32768 && var.memory <= 122880 && var.memory % 8192 == 0 : false
    )
    error_message = "memory must be a valid Fargate memory value for the selected cpu."
  }
}

variable "cloudwatch_log_retention_days" {
  description = "CloudWatch Logs retention in days. The security baseline requires at least one year."
  type        = number
  default     = 365

  validation {
    condition     = var.cloudwatch_log_retention_days >= 365
    error_message = "cloudwatch_log_retention_days must be at least 365."
  }
}

variable "cloudwatch_logs_kms_key_arn" {
  description = "ARN of a caller-managed symmetric KMS key whose policy permits the regional CloudWatch Logs service to use it."
  type        = string

  validation {
    condition     = can(regex("^arn:(aws|aws-us-gov|aws-cn):kms:[a-z0-9-]+:[0-9]{12}:key/[0-9a-fA-F-]{36}$", var.cloudwatch_logs_kms_key_arn))
    error_message = "cloudwatch_logs_kms_key_arn must be a valid KMS key ARN."
  }
}

variable "alb_access_logs_bucket" {
  description = "Name of a caller-managed S3 bucket configured to accept ALB access logs with the required regional delivery policy."
  type        = string

  validation {
    condition     = length(var.alb_access_logs_bucket) >= 3 && length(var.alb_access_logs_bucket) <= 63
    error_message = "alb_access_logs_bucket must be a valid 3-63 character S3 bucket name."
  }
}

variable "alb_access_logs_prefix" {
  description = "Optional S3 key prefix for ALB access logs."
  type        = string
  default     = "juice-shop"

  validation {
    condition     = !startswith(var.alb_access_logs_prefix, "/") && !endswith(var.alb_access_logs_prefix, "/") && !strcontains(var.alb_access_logs_prefix, "AWSLogs")
    error_message = "alb_access_logs_prefix must not start or end with a slash or contain AWSLogs."
  }
}

variable "tags" {
  description = "Additional tags applied to supported resources."
  type        = map(string)
  default     = {}
}
