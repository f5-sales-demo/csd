locals {
  tags = merge(var.tags, {
    Name = var.name
  })

  page_tamper_path  = "/csd-page-tamper/payment"
  page_tamper_port  = 8080
  page_tamper_image = "docker.io/library/nginx@sha256:30f1c0d78e0ad60901648be663a710bdadf19e4c10ac6782c235200619158284"

  page_tamper_html = <<-HTML
    <!doctype html>
    <html lang="en">
    <head>
      <meta charset="utf-8">
      <meta name="viewport" content="width=device-width, initial-scale=1">
      <title>Synthetic Payment</title>
    </head>
    <body>
      <main>
        <h1>Synthetic payment</h1>
        <p>Authorized security-control validation only. No payment data is submitted or stored.</p>
        <form id="synthetic-payment" onsubmit="return false">
          <label>Cardholder name <input name="cardholder_name" value="" autocomplete="off"></label>
          <label>Card number <input name="card_number" value="" autocomplete="off" inputmode="numeric"></label>
          <label>Expiry <input name="expiry" value="" autocomplete="off"></label>
          <label>CVV <input name="cvv" value="" autocomplete="off" inputmode="numeric"></label>
          <label>Billing postal code <input name="billing_postal_code" value="" autocomplete="off"></label>
        </form>
      </main>
    </body>
    </html>
  HTML

  page_tamper_nginx_config = <<-NGINX
    worker_processes auto;
    error_log /dev/stderr notice;
    pid /tmp/nginx.pid;

    events {
      worker_connections 1024;
    }

    http {
      access_log /dev/stdout;
      client_body_temp_path /tmp/client_temp;
      proxy_temp_path /tmp/proxy_temp;
      fastcgi_temp_path /tmp/fastcgi_temp;
      uwsgi_temp_path /tmp/uwsgi_temp;
      scgi_temp_path /tmp/scgi_temp;

      map $http_x_csd_page_tamper $selector_valid {
        "" 1;
        "cache-control" 1;
        "clear-site-data" 1;
        "content-security-policy" 1;
        "cross-origin-embedder-policy" 1;
        "cross-origin-opener-policy" 1;
        "cross-origin-resource-policy" 1;
        "permissions-policy" 1;
        "referrer-policy" 1;
        "strict-transport-security" 1;
        "x-content-type-options" 1;
        "x-frame-options" 1;
        "x-permitted-cross-domain-policies" 1;
        ~.*,.* 0;
        default 0;
      }

      map $http_x_csd_page_tamper $cache_control { default "no-store, max-age=0"; "cache-control" ""; }
      map $http_x_csd_page_tamper $clear_site_data { default "\"cache\""; "clear-site-data" ""; }
      map $http_x_csd_page_tamper $content_security_policy { default "default-src 'self' https://*.zeronaught.com; script-src 'self' https://*.zeronaught.com; connect-src 'self' https://*.zeronaught.com https://csd.zeronaught.com; style-src 'self' 'unsafe-inline'; img-src 'self' data:; object-src 'none'; base-uri 'self'; frame-ancestors 'none'"; "content-security-policy" ""; }
      map $http_x_csd_page_tamper $cross_origin_embedder_policy { default "credentialless"; "cross-origin-embedder-policy" ""; }
      map $http_x_csd_page_tamper $cross_origin_opener_policy { default "same-origin"; "cross-origin-opener-policy" ""; }
      map $http_x_csd_page_tamper $cross_origin_resource_policy { default "same-origin"; "cross-origin-resource-policy" ""; }
      map $http_x_csd_page_tamper $permissions_policy { default "camera=(), geolocation=(), microphone=(), payment=(self)"; "permissions-policy" ""; }
      map $http_x_csd_page_tamper $referrer_policy { default "strict-origin-when-cross-origin"; "referrer-policy" ""; }
      map $http_x_csd_page_tamper $strict_transport_security { default "max-age=31536000; includeSubDomains"; "strict-transport-security" ""; }
      map $http_x_csd_page_tamper $x_content_type_options { default "nosniff"; "x-content-type-options" ""; }
      map $http_x_csd_page_tamper $x_frame_options { default "DENY"; "x-frame-options" ""; }
      map $http_x_csd_page_tamper $x_permitted_cross_domain_policies { default "none"; "x-permitted-cross-domain-policies" ""; }

      server {
        listen 8080;
        server_name _;

        location = /healthz {
          access_log off;
          default_type text/plain;
          return 200 "ok\n";
        }

        location = /csd-page-tamper/payment {
          if ($selector_valid = 0) { return 400; }

          default_type text/html;
          add_header Cache-Control $cache_control always;
          add_header Clear-Site-Data $clear_site_data always;
          add_header Content-Security-Policy $content_security_policy always;
          add_header Cross-Origin-Embedder-Policy $cross_origin_embedder_policy always;
          add_header Cross-Origin-Opener-Policy $cross_origin_opener_policy always;
          add_header Cross-Origin-Resource-Policy $cross_origin_resource_policy always;
          add_header Permissions-Policy $permissions_policy always;
          add_header Referrer-Policy $referrer_policy always;
          add_header Strict-Transport-Security $strict_transport_security always;
          add_header X-Content-Type-Options $x_content_type_options always;
          add_header X-Frame-Options $x_frame_options always;
          add_header X-Permitted-Cross-Domain-Policies $x_permitted_cross_domain_policies always;
          root /tmp/page-tamper;
          try_files /payment.html =404;
        }

        location / {
          return 404;
        }
      }
    }
  NGINX

  page_tamper_start_command = <<-SHELL
    mkdir -p /tmp/page-tamper
    cat > /tmp/nginx.conf <<'NGINX'
    ${local.page_tamper_nginx_config}
    NGINX
    cat > /tmp/page-tamper/payment.html <<'HTML'
    ${local.page_tamper_html}
    HTML
    exec nginx -c /tmp/nginx.conf -g 'daemon off;'
  SHELL
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

resource "aws_vpc_security_group_egress_rule" "alb_page_tamper" {
  count = var.enable_page_tamper_endpoint ? 1 : 0

  security_group_id            = aws_security_group.alb.id
  description                  = "Page Tamper traffic to Fargate tasks"
  referenced_security_group_id = aws_security_group.task.id
  from_port                    = local.page_tamper_port
  to_port                      = local.page_tamper_port
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

resource "aws_vpc_security_group_ingress_rule" "task_page_tamper" {
  count = var.enable_page_tamper_endpoint ? 1 : 0

  security_group_id            = aws_security_group.task.id
  description                  = "Page Tamper traffic from the ALB"
  referenced_security_group_id = aws_security_group.alb.id
  from_port                    = local.page_tamper_port
  to_port                      = local.page_tamper_port
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

resource "aws_lb_target_group" "page_tamper" {
  count = var.enable_page_tamper_endpoint ? 1 : 0

  # checkov:skip=CKV_AWS_378:Private Fargate tasks accept the dedicated HTTP endpoint only from the ALB security group.
  name        = "${substr(var.name, 0, 20)}-page-tamper"
  port        = local.page_tamper_port
  protocol    = "HTTP"
  target_type = "ip"
  vpc_id      = var.vpc_id

  health_check {
    enabled             = true
    path                = "/healthz"
    matcher             = "200"
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

resource "aws_lb_listener_rule" "page_tamper" {
  count = var.enable_page_tamper_endpoint ? 1 : 0

  listener_arn = aws_lb_listener.http.arn
  priority     = 10

  action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.page_tamper[0].arn
  }

  condition {
    path_pattern {
      values = [local.page_tamper_path]
    }
  }
}

resource "aws_ecs_task_definition" "this" {
  family                   = var.name
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  cpu                      = tostring(var.cpu)
  memory                   = tostring(var.memory)
  execution_role_arn       = aws_iam_role.task_execution.arn

  container_definitions = jsonencode(concat([{
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
    },
    ], var.enable_page_tamper_endpoint ? [{
      name       = "page-tamper"
      image      = local.page_tamper_image
      essential  = true
      entryPoint = ["/bin/sh", "-c"]
      command    = [local.page_tamper_start_command]
      portMappings = [{
        containerPort = local.page_tamper_port
        hostPort      = local.page_tamper_port
        protocol      = "tcp"
      }]
      logConfiguration = {
        logDriver = "awslogs"
        options = {
          awslogs-group         = aws_cloudwatch_log_group.this.name
          awslogs-region        = data.aws_region.current.region
          awslogs-stream-prefix = "page-tamper"
        }
      }
  }] : []))

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

  dynamic "load_balancer" {
    for_each = var.enable_page_tamper_endpoint ? [1] : []

    content {
      target_group_arn = aws_lb_target_group.page_tamper[0].arn
      container_name   = "page-tamper"
      container_port   = local.page_tamper_port
    }
  }

  health_check_grace_period_seconds = 120

  depends_on = [aws_lb_listener.http, aws_lb_listener_rule.page_tamper]
  tags       = local.tags
}
