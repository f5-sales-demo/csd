locals {
  tags = merge(var.tags, {
    Name = var.name
  })
}


resource "aws_iam_role" "task_execution" {
  name = "${var.name}-execution"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Action    = "sts:AssumeRole"
      Principal = { Service = "ecs-tasks.amazonaws.com" }
    }]
  })
  tags = local.tags
}

resource "aws_iam_role_policy" "task_execution" {
  name = "${var.name}-logs"
  role = aws_iam_role.task_execution.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["logs:CreateLogStream", "logs:PutLogEvents"]
      Resource = "${aws_cloudwatch_log_group.this.arn}:*"
    }]
  })
}

resource "aws_cloudwatch_log_group" "this" {
  name              = "/ecs/${var.name}"
  retention_in_days = var.cloudwatch_log_retention_days
  kms_key_id        = var.cloudwatch_logs_kms_key_arn
  tags              = local.tags
}

resource "aws_ecs_cluster" "this" {
  name = var.name

  setting {
    name  = "containerInsights"
    value = "enabled"
  }

  tags = local.tags
}

resource "aws_security_group" "alb" {
  name_prefix = "${var.name}-alb-"
  description = "Caller-scoped HTTP ingress to the Juice Shop ALB"
  vpc_id      = var.vpc_id
  tags        = local.tags

  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_vpc_security_group_ingress_rule" "alb" {
  for_each = var.allowed_ingress_cidrs

  security_group_id = aws_security_group.alb.id
  description       = "HTTP from ${each.value}"
  cidr_ipv4         = each.value
  from_port         = 80
  to_port           = 80
  ip_protocol       = "tcp"
}

resource "aws_vpc_security_group_egress_rule" "alb" {
  security_group_id            = aws_security_group.alb.id
  description                  = "Juice Shop traffic to Fargate tasks"
  referenced_security_group_id = aws_security_group.task.id
  from_port                    = var.container_port
  to_port                      = var.container_port
  ip_protocol                  = "tcp"
}

resource "aws_security_group" "task" {
  name_prefix = "${var.name}-task-"
  description = "Juice Shop tasks reachable only from the ALB"
  vpc_id      = var.vpc_id
  tags        = local.tags

  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_vpc_security_group_ingress_rule" "task" {
  security_group_id            = aws_security_group.task.id
  description                  = "Juice Shop traffic from the ALB"
  referenced_security_group_id = aws_security_group.alb.id
  from_port                    = var.container_port
  to_port                      = var.container_port
  ip_protocol                  = "tcp"
}

resource "aws_vpc_security_group_egress_rule" "task" {
  security_group_id = aws_security_group.task.id
  description       = "HTTPS egress for image pulls and AWS service access"
  cidr_ipv4         = "0.0.0.0/0"
  from_port         = 443
  to_port           = 443
  ip_protocol       = "tcp"
}

data "aws_subnet" "alb" {
  for_each = { for index, id in var.alb_subnet_ids : tostring(index) => id }
  id       = each.value
}

data "aws_subnet" "task" {
  for_each = { for index, id in var.task_subnet_ids : tostring(index) => id }
  id       = each.value
}

check "task_subnet_placement" {
  assert {
    condition     = alltrue([for subnet in data.aws_subnet.task : subnet.vpc_id == var.vpc_id])
    error_message = "task_subnet_ids must all belong to vpc_id."
  }
}

check "alb_subnet_placement" {
  assert {
    condition     = alltrue([for subnet in data.aws_subnet.alb : subnet.vpc_id == var.vpc_id]) && length(distinct([for subnet in data.aws_subnet.alb : subnet.availability_zone])) >= 2
    error_message = "alb_subnet_ids must all belong to vpc_id and span at least two distinct Availability Zones."
  }
}

resource "aws_lb" "this" {
  # checkov:skip=CKV_AWS_150:Deletion protection is intentionally disabled so this ephemeral authorized demo origin can be destroyed immediately after use.
  # checkov:skip=CKV2_AWS_28:F5 Distributed Cloud CSD and edge security are the enforcement point; an AWS WAF would duplicate controls on this dedicated origin.
  # checkov:skip=CKV2_AWS_20:F5 Distributed Cloud owns the HTTPS redirect; this CIDR-scoped origin ALB intentionally forwards HTTP.
  name                       = var.name
  internal                   = !var.public_exposure
  load_balancer_type         = "application"
  security_groups            = [aws_security_group.alb.id]
  subnets                    = var.alb_subnet_ids
  drop_invalid_header_fields = true
  enable_deletion_protection = false

  access_logs {
    bucket  = var.alb_access_logs_bucket
    prefix  = var.alb_access_logs_prefix
    enabled = true
  }

  tags = local.tags
}

resource "aws_lb_target_group" "this" {
  # checkov:skip=CKV_AWS_378:Private Fargate tasks accept Juice Shop's native HTTP only from the ALB security group.
  name        = var.name
  port        = var.container_port
  protocol    = "HTTP"
  target_type = "ip"
  vpc_id      = var.vpc_id

  health_check {
    enabled             = true
    path                = "/"
    matcher             = "200-399"
    interval            = 30
    timeout             = 10
    healthy_threshold   = 2
    unhealthy_threshold = 5
  }

  tags = local.tags
}

resource "aws_lb_listener" "http" {
  # checkov:skip=CKV_AWS_2:F5 Distributed Cloud terminates public TLS and uses this CIDR-scoped HTTP listener only as the demo origin hop.
  # checkov:skip=CKV_AWS_103:F5 Distributed Cloud owns public TLS; this listener is a CIDR-scoped HTTP origin hop.
  load_balancer_arn = aws_lb.this.arn
  port              = 80
  protocol          = "HTTP"

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.this.arn
  }
}

resource "aws_ecs_task_definition" "this" {
  family                   = var.name
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  cpu                      = tostring(var.cpu)
  memory                   = tostring(var.memory)
  execution_role_arn       = aws_iam_role.task_execution.arn

  container_definitions = jsonencode([{
    name      = "juice-shop"
    image     = var.container_image
    essential = true
    portMappings = [{
      containerPort = var.container_port
      hostPort      = var.container_port
      protocol      = "tcp"
    }]
    logConfiguration = {
      logDriver = "awslogs"
      options = {
        awslogs-group         = aws_cloudwatch_log_group.this.name
        awslogs-region        = data.aws_region.current.region
        awslogs-stream-prefix = "juice-shop"
      }
    }
  }])

  tags = local.tags
}

data "aws_region" "current" {}

resource "aws_ecs_service" "this" {
  name            = var.name
  cluster         = aws_ecs_cluster.this.id
  task_definition = aws_ecs_task_definition.this.arn
  desired_count   = var.desired_count
  launch_type     = "FARGATE"

  network_configuration {
    subnets          = var.task_subnet_ids
    security_groups  = [aws_security_group.task.id]
    assign_public_ip = false
  }

  deployment_circuit_breaker {
    enable   = true
    rollback = true
  }

  load_balancer {
    target_group_arn = aws_lb_target_group.this.arn
    container_name   = "juice-shop"
    container_port   = var.container_port
  }

  health_check_grace_period_seconds = 120

  depends_on = [aws_lb_listener.http]
  tags       = local.tags
}
