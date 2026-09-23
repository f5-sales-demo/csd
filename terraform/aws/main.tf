data "aws_caller_identity" "current" {}
data "aws_partition" "current" {}

data "xcsh_addon_service_activation_status" "csd" {
  addon_service = "f5xc-client-side-defense-standard"
}

locals {
  name                   = "csd-juice-shop"
  availability_zones     = ["us-east-1a", "us-east-1b"]
  alb_logs_bucket_prefix = "f5-sales-demo-csd-alb-logs-"
  alb_access_logs_prefix = "juice-shop"
}

resource "terraform_data" "require_csd" {
  lifecycle {
    precondition {
      condition     = data.xcsh_addon_service_activation_status.csd.state == "AS_SUBSCRIBED"
      error_message = "Client-Side Defense Standard must be subscribed before this stack can be planned or applied."
    }
  }
}

resource "aws_vpc" "csd" {
  cidr_block           = var.vpc_cidr
  enable_dns_hostnames = true
  enable_dns_support   = true

  tags = { Name = "${local.name}-vpc" }

  lifecycle {
    precondition {
      condition     = data.aws_caller_identity.current.account_id == var.expected_aws_account_id
      error_message = "Refusing to operate outside the approved AWS account."
    }
  }
}

resource "aws_default_security_group" "csd" {
  vpc_id = aws_vpc.csd.id

  tags = { Name = "${local.name}-default-deny-all" }
}


resource "aws_internet_gateway" "csd" {
  vpc_id = aws_vpc.csd.id
  tags   = { Name = "${local.name}-igw" }
}

resource "aws_subnet" "public" {
  count = 2

  vpc_id                  = aws_vpc.csd.id
  availability_zone       = local.availability_zones[count.index]
  cidr_block              = var.public_subnet_cidrs[count.index]
  map_public_ip_on_launch = false

  tags = { Name = "${local.name}-public-${count.index + 1}" }
}

resource "aws_subnet" "private" {
  count = 2

  vpc_id            = aws_vpc.csd.id
  availability_zone = local.availability_zones[count.index]
  cidr_block        = var.private_subnet_cidrs[count.index]

  tags = { Name = "${local.name}-private-${count.index + 1}" }
}

resource "aws_route_table" "public" {
  vpc_id = aws_vpc.csd.id
  tags   = { Name = "${local.name}-public" }
}

resource "aws_route" "public_internet" {
  route_table_id         = aws_route_table.public.id
  destination_cidr_block = "0.0.0.0/0"
  gateway_id             = aws_internet_gateway.csd.id
}

resource "aws_route_table_association" "public" {
  count = 2

  subnet_id      = aws_subnet.public[count.index].id
  route_table_id = aws_route_table.public.id
}

# One NAT Gateway limits demo cost. It is intentionally a single-AZ egress dependency;
# production resilience would require one NAT Gateway and route table per AZ.
resource "aws_eip" "nat" {
  domain = "vpc"
  tags   = { Name = "${local.name}-nat" }

  depends_on = [aws_internet_gateway.csd]
}

resource "aws_nat_gateway" "csd" {
  count = 1

  allocation_id = aws_eip.nat.id
  subnet_id     = aws_subnet.public[0].id
  tags          = { Name = "${local.name}-nat" }
}

resource "aws_route_table" "private" {
  vpc_id = aws_vpc.csd.id
  tags   = { Name = "${local.name}-private" }
}

resource "aws_route" "private_egress" {
  route_table_id         = aws_route_table.private.id
  destination_cidr_block = "0.0.0.0/0"
  nat_gateway_id         = aws_nat_gateway.csd[0].id
}

resource "aws_route_table_association" "private" {
  count = 2

  subnet_id      = aws_subnet.private[count.index].id
  route_table_id = aws_route_table.private.id
}

resource "aws_kms_key" "logs" {
  description             = "Encrypt CSD Juice Shop CloudWatch logs"
  deletion_window_in_days = 30
  enable_key_rotation     = true

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "AccountAdministration"
        Effect    = "Allow"
        Principal = { AWS = "arn:${data.aws_partition.current.partition}:iam::${data.aws_caller_identity.current.account_id}:root" }
        Action    = "kms:*"
        Resource  = "*"
      },
      {
        Sid       = "CloudWatchLogsUse"
        Effect    = "Allow"
        Principal = { Service = "logs.${var.aws_region}.amazonaws.com" }
        Action = [
          "kms:Decrypt",
          "kms:Encrypt",
          "kms:GenerateDataKey*",
          "kms:ReEncrypt*",
          "kms:DescribeKey"
        ]
        Resource = "*"
        Condition = {
          ArnLike = {
            "kms:EncryptionContext:aws:logs:arn" = [
              "arn:${data.aws_partition.current.partition}:logs:${var.aws_region}:${data.aws_caller_identity.current.account_id}:log-group:/ecs/${local.name}*",
              "arn:${data.aws_partition.current.partition}:logs:${var.aws_region}:${data.aws_caller_identity.current.account_id}:log-group:/aws/vpc/${local.name}*",
            ]
          }
        }
      }
    ]
  })

  tags = { Name = "${local.name}-logs" }
}

resource "aws_kms_alias" "logs" {
  name          = "alias/${local.name}-logs"
  target_key_id = aws_kms_key.logs.key_id
}

resource "aws_cloudwatch_log_group" "vpc_flow" {
  name              = "/aws/vpc/${local.name}"
  retention_in_days = 365
  kms_key_id        = aws_kms_key.logs.arn

  tags = { Name = "${local.name}-vpc-flow" }
}

resource "aws_iam_role" "vpc_flow" {
  name = "${local.name}-vpc-flow"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "vpc-flow-logs.amazonaws.com" }
      Action    = "sts:AssumeRole"
      Condition = {
        StringEquals = { "aws:SourceAccount" = data.aws_caller_identity.current.account_id }
        ArnLike = {
          "aws:SourceArn" = "arn:${data.aws_partition.current.partition}:ec2:${var.aws_region}:${data.aws_caller_identity.current.account_id}:vpc-flow-log/*"
        }
      }
    }]
  })
}

resource "aws_iam_role_policy" "vpc_flow" {
  name = "${local.name}-vpc-flow-delivery"
  role = aws_iam_role.vpc_flow.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "logs:CreateLogStream",
          "logs:PutLogEvents",
          "logs:DescribeLogStreams",
        ]
        Resource = "${aws_cloudwatch_log_group.vpc_flow.arn}:*"
      },
      {
        Effect   = "Allow"
        Action   = "logs:DescribeLogGroups"
        Resource = "*"
      },
    ]
  })
}

resource "aws_flow_log" "csd" {
  vpc_id               = aws_vpc.csd.id
  traffic_type         = "ALL"
  log_destination_type = "cloud-watch-logs"
  log_destination      = aws_cloudwatch_log_group.vpc_flow.arn
  iam_role_arn         = aws_iam_role.vpc_flow.arn

  tags = { Name = "${local.name}-vpc-flow" }
}


resource "aws_s3_bucket" "alb_logs" {
  # checkov:skip=CKV2_AWS_62:Dedicated ALB access-log sink has no event consumer; notifications would add an unused delivery path.
  # checkov:skip=CKV_AWS_18:Server access logging to this same dedicated log sink would recurse; no separate durable audit bucket is part of this ephemeral demo stack.
  # checkov:skip=CKV_AWS_144:Cross-region replication conflicts with same-state ephemeral teardown and is not required for this disposable ALB log sink.
  # checkov:skip=CKV_AWS_145:ALB access-log delivery supports only Amazon S3-managed encryption keys (SSE-S3), not SSE-KMS.

  bucket_prefix = local.alb_logs_bucket_prefix
  force_destroy = true
}

resource "aws_s3_bucket_versioning" "alb_logs" {
  bucket = aws_s3_bucket.alb_logs.id

  versioning_configuration {
    status = "Enabled"
  }
}


resource "aws_s3_bucket_public_access_block" "alb_logs" {
  bucket = aws_s3_bucket.alb_logs.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "alb_logs" {
  bucket = aws_s3_bucket.alb_logs.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "alb_logs" {
  bucket = aws_s3_bucket.alb_logs.id

  rule {
    id     = "expire-alb-logs"
    status = "Enabled"

    filter {}

    expiration {
      days = 90
    }

    noncurrent_version_expiration {
      noncurrent_days = 90
    }

    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }
  }
}

resource "aws_s3_bucket_policy" "alb_logs" {
  bucket = aws_s3_bucket.alb_logs.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "AllowELBLogDelivery"
        Effect    = "Allow"
        Principal = { Service = "logdelivery.elasticloadbalancing.amazonaws.com" }
        Action    = "s3:PutObject"
        Resource  = "${aws_s3_bucket.alb_logs.arn}/${local.alb_access_logs_prefix}/AWSLogs/${data.aws_caller_identity.current.account_id}/*"
        Condition = {
          StringEquals = {
            "aws:SourceAccount" = data.aws_caller_identity.current.account_id
          }
        }
      },
      {
        Sid       = "AllowELBGetBucketAcl"
        Effect    = "Allow"
        Principal = { Service = "logdelivery.elasticloadbalancing.amazonaws.com" }
        Action    = "s3:GetBucketAcl"
        Resource  = aws_s3_bucket.alb_logs.arn
        Condition = {
          StringEquals = {
            "aws:SourceAccount" = data.aws_caller_identity.current.account_id
          }
        }
      }
    ]
  })
}

# Vendored from f5-sales-demo/origin-server commit d6384bb0621c4c1eceb38d55a6b63e7b9cc7083a.
module "origin" {
  source = "./vendor/aws-juice-shop"

  name                        = local.name
  vpc_id                      = aws_vpc.csd.id
  alb_subnet_ids              = aws_subnet.public[*].id
  task_subnet_ids             = aws_subnet.private[*].id
  public_exposure             = true
  allowed_ingress_cidrs       = var.origin_ingress_cidrs
  cloudwatch_logs_kms_key_arn = aws_kms_key.logs.arn
  alb_access_logs_bucket      = aws_s3_bucket.alb_logs.id
  alb_access_logs_prefix      = local.alb_access_logs_prefix
  tags                        = var.tags

  depends_on = [
    aws_route.public_internet,
    aws_route.private_egress,
    aws_route_table_association.public,
    aws_route_table_association.private,
    aws_s3_bucket_policy.alb_logs,
    aws_s3_bucket_server_side_encryption_configuration.alb_logs,
  ]
}

resource "xcsh_namespace" "csd" {
  name = var.namespace
}

resource "xcsh_protected_domain" "csd" {
  name             = "client-side-defense"
  namespace        = var.namespace
  protected_domain = "f5-sales-demo.com"

  depends_on = [xcsh_namespace.csd, terraform_data.require_csd]
}

resource "xcsh_origin_pool" "origin" {
  name      = "csd-juice-shop"
  namespace = var.namespace
  port      = 80

  origin_servers {
    public_name {
      dns_name = module.origin.origin_hostname
    }
  }

  no_tls                = {}
  same_as_endpoint_port = {}

  depends_on = [xcsh_namespace.csd, terraform_data.require_csd]
}

resource "xcsh_http_loadbalancer" "csd" {
  name      = "client-side-defense"
  namespace = var.namespace
  domains   = [var.domain]

  https_auto_cert {
    http_redirect = true
  }

  advertise_on_public_default_vip = {}

  default_route_pools {
    pool {
      name      = xcsh_origin_pool.origin.name
      namespace = var.namespace
    }
    weight   = 1
    priority = 1
  }

  client_side_defense {
    policy {
      js_insert_all_pages = {}
    }
  }

  depends_on = [xcsh_namespace.csd, xcsh_protected_domain.csd, terraform_data.require_csd]
}
