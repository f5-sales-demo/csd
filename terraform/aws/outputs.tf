output "aws_account_id" {
  description = "AWS account containing the CSD origin stack."
  value       = data.aws_caller_identity.current.account_id
}

output "aws_region" {
  description = "AWS region containing the CSD origin stack."
  value       = var.aws_region
}

output "vpc_id" {
  description = "Dedicated application VPC identifier."
  value       = aws_vpc.csd.id
}

output "origin_hostname" {
  description = "Public ALB hostname consumed by the F5 Distributed Cloud origin pool."
  value       = module.origin.origin_hostname
}

output "origin_url" {
  description = "Direct HTTP origin URL for restricted operational diagnostics."
  value       = module.origin.origin_url
}

output "application_url" {
  description = "F5 Distributed Cloud protected application URL."
  value       = "https://${var.domain}"
}

output "xc_namespace" {
  description = "F5 Distributed Cloud namespace containing application resources."
  value       = var.namespace
}

output "xc_protected_domain_name" {
  description = "Managed F5 Distributed Cloud protected-domain resource name."
  value       = xcsh_protected_domain.csd.name
}

output "xc_origin_pool_name" {
  description = "Managed F5 Distributed Cloud origin-pool resource name."
  value       = xcsh_origin_pool.origin.name
}

output "xc_http_loadbalancer_name" {
  description = "Managed F5 Distributed Cloud HTTP load balancer resource name."
  value       = xcsh_http_loadbalancer.csd.name
}

output "alb_access_logs_bucket" {
  description = "S3 bucket receiving Application Load Balancer access logs."
  value       = aws_s3_bucket.alb_logs.id
}


output "alb_arn" {
  description = "Application Load Balancer ARN."
  value       = module.origin.load_balancer_arn
}

output "target_group_arn" {
  description = "Application target group ARN."
  value       = module.origin.target_group_arn
}

output "listener_port" {
  description = "Public origin HTTP listener port."
  value       = module.origin.listener_port
}

output "health_check_port" {
  description = "Application target health-check port."
  value       = 3000
}

output "public_subnet_ids" {
  description = "Selected public ALB subnet IDs."
  value       = module.origin.alb_subnet_ids
}

output "private_subnet_ids" {
  description = "Selected private Fargate subnet IDs."
  value       = module.origin.task_subnet_ids
}

output "cloudwatch_logs_kms_key_arn" {
  description = "KMS key ARN used to encrypt application CloudWatch logs."
  value       = aws_kms_key.logs.arn
}

output "alb_access_logs_prefix" {
  description = "S3 object prefix used for ALB access logs."
  value       = local.alb_access_logs_prefix
}
