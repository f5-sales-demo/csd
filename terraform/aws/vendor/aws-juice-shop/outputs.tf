output "origin_hostname" {
  description = "ALB DNS hostname for the origin."
  value       = aws_lb.this.dns_name
}

output "origin_url" {
  description = "HTTP URL for the origin."
  value       = "http://${aws_lb.this.dns_name}"
}

output "listener_port" {
  description = "HTTP listener port."
  value       = aws_lb_listener.http.port
}

output "listener_protocol" {
  description = "Listener protocol."
  value       = aws_lb_listener.http.protocol
}

output "ecs_cluster_id" {
  description = "ECS cluster identifier."
  value       = aws_ecs_cluster.this.id
}

output "ecs_service_id" {
  description = "ECS service identifier."
  value       = aws_ecs_service.this.id
}

output "task_definition_arn" {
  description = "ECS task definition ARN."
  value       = aws_ecs_task_definition.this.arn
}

output "load_balancer_arn" {
  description = "Application Load Balancer ARN."
  value       = aws_lb.this.arn
}

output "target_group_arn" {
  description = "Target group ARN."
  value       = aws_lb_target_group.this.arn
}

output "alb_security_group_id" {
  description = "Security group protecting the ALB."
  value       = aws_security_group.alb.id
}

output "task_security_group_id" {
  description = "Security group protecting the Fargate tasks."
  value       = aws_security_group.task.id
}

output "vpc_id" {
  description = "Caller-provided VPC ID."
  value       = var.vpc_id
}

output "alb_subnet_ids" {
  description = "Caller-provided ALB subnet IDs."
  value       = var.alb_subnet_ids
}

output "task_subnet_ids" {
  description = "Caller-provided Fargate task subnet IDs."
  value       = var.task_subnet_ids
}

output "container_image" {
  description = "Immutable image reference used by the task definition."
  value       = var.container_image
}

output "page_tamper_path" {
  description = "Dedicated CSD Page Tamper payment path, or null when disabled."
  value       = var.enable_page_tamper_endpoint ? local.page_tamper_path : null
}

output "page_tamper_url" {
  description = "Direct HTTP URL for the dedicated CSD Page Tamper payment endpoint, or null when disabled."
  value       = var.enable_page_tamper_endpoint ? "http://${aws_lb.this.dns_name}${local.page_tamper_path}" : null
}

output "page_tamper_target_group_arn" {
  description = "Dedicated CSD Page Tamper target group ARN, or null when disabled."
  value       = var.enable_page_tamper_endpoint ? one(aws_lb_target_group.page_tamper).arn : null
}
