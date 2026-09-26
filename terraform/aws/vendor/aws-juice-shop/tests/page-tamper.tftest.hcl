mock_provider "aws" {
  mock_resource "aws_lb" {
    defaults = {
      arn      = "arn:aws:elasticloadbalancing:us-east-1:111111111111:loadbalancer/app/csd-page-tamper/0000000000000000"
      dns_name = "origin.example.com"
    }
  }

  mock_resource "aws_lb_target_group" {
    defaults = {
      arn = "arn:aws:elasticloadbalancing:us-east-1:111111111111:targetgroup/csd-page-tamper/0000000000000000"
    }
  }

  mock_resource "aws_lb_listener" {
    defaults = {
      arn = "arn:aws:elasticloadbalancing:us-east-1:111111111111:listener/app/csd-page-tamper/0000000000000000/0000000000000000"
    }
  }

  mock_resource "aws_iam_role" {
    defaults = {
      arn = "arn:aws:iam::111111111111:role/csd-page-tamper-test-execution"
    }
  }
}

variables {
  name                        = "csd-page-tamper-test"
  vpc_id                      = "vpc-0123456789abcdef0"
  alb_subnet_ids              = ["subnet-0123456789abcdef0", "subnet-1123456789abcdef0"]
  task_subnet_ids             = ["subnet-2123456789abcdef0", "subnet-3123456789abcdef0"]
  cloudwatch_logs_kms_key_arn = "arn:aws:kms:us-east-1:111111111111:key/00000000-0000-0000-0000-000000000000"
  alb_access_logs_bucket      = "csd-page-tamper-test-logs"
}

override_data {
  target = data.aws_region.current
  values = {
    region = "us-east-1"
  }
}

override_data {
  target = data.aws_subnet.alb["0"]
  values = {
    vpc_id            = "vpc-0123456789abcdef0"
    availability_zone = "us-east-1a"
  }
}

override_data {
  target = data.aws_subnet.alb["1"]
  values = {
    vpc_id            = "vpc-0123456789abcdef0"
    availability_zone = "us-east-1b"
  }
}

override_data {
  target = data.aws_subnet.task["0"]
  values = {
    vpc_id = "vpc-0123456789abcdef0"
  }
}

override_data {
  target = data.aws_subnet.task["1"]
  values = {
    vpc_id = "vpc-0123456789abcdef0"
  }
}

run "disabled_by_default" {
  command = apply

  assert {
    condition     = var.enable_page_tamper_endpoint == false
    error_message = "The reusable origin module must keep the Page Tamper endpoint disabled by default."
  }

  assert {
    condition     = length(aws_lb_target_group.page_tamper) == 0 && length(aws_lb_listener_rule.page_tamper) == 0
    error_message = "Disabled mode must not create Page Tamper routing resources."
  }

  assert {
    condition     = length(aws_vpc_security_group_ingress_rule.task_page_tamper) == 0 && length(aws_vpc_security_group_egress_rule.alb_page_tamper) == 0
    error_message = "Disabled mode must not open Page Tamper security-group paths."
  }

  assert {
    condition     = output.page_tamper_path == null && output.page_tamper_url == null && output.page_tamper_target_group_arn == null
    error_message = "Disabled mode must expose null Page Tamper outputs."
  }

  assert {
    condition     = one(aws_lb_listener.http.default_action).target_group_arn == aws_lb_target_group.this.arn
    error_message = "The ordinary Juice Shop default route must remain isolated from Page Tamper routing."
  }

  assert {
    condition     = length(regexall("depends_on\\s*=\\s*\\[aws_lb_listener\\.http,\\s*aws_lb_listener_rule\\.page_tamper\\]", file("${path.module}/main.tf"))) == 1
    error_message = "The ECS service must depend on the listener and the complete conditional Page Tamper listener-rule resource, including disabled mode where its count is zero."
  }
}

run "enabled_contract" {
  command = apply

  variables {
    enable_page_tamper_endpoint = true
  }

  assert {
    condition     = length(aws_lb_target_group.page_tamper) == 1 && one(aws_lb_target_group.page_tamper).port == 8080 && one(aws_lb_target_group.page_tamper).protocol == "HTTP" && one(aws_lb_target_group.page_tamper).target_type == "ip"
    error_message = "Enabled mode must create one HTTP/IP Page Tamper target group on port 8080."
  }

  assert {
    condition     = one(one(aws_lb_target_group.page_tamper).health_check).path == "/healthz"
    error_message = "The Page Tamper target group must use /healthz."
  }

  assert {
    condition     = one(aws_lb_listener_rule.page_tamper).priority == 10
    error_message = "Page Tamper routing must use listener priority 10."
  }

  assert {
    condition     = length(regexall("(?s)resource\\s+\"aws_lb_listener_rule\"\\s+\"page_tamper\".*?priority\\s*=\\s*10.*?values\\s*=\\s*\\[local\\.page_tamper_path\\]", file("${path.module}/main.tf"))) == 1
    error_message = "Page Tamper routing must match only the dedicated payment path local."
  }

  assert {
    condition     = one(aws_vpc_security_group_ingress_rule.task_page_tamper).from_port == 8080 && one(aws_vpc_security_group_ingress_rule.task_page_tamper).to_port == 8080 && one(aws_vpc_security_group_ingress_rule.task_page_tamper).referenced_security_group_id == aws_security_group.alb.id
    error_message = "Task ingress on 8080 must be sourced only from the ALB security group."
  }

  assert {
    condition     = one(aws_vpc_security_group_egress_rule.alb_page_tamper).from_port == 8080 && one(aws_vpc_security_group_egress_rule.alb_page_tamper).to_port == 8080 && one(aws_vpc_security_group_egress_rule.alb_page_tamper).referenced_security_group_id == aws_security_group.task.id
    error_message = "ALB egress on 8080 must target only the task security group."
  }

  assert {
    condition     = one(aws_lb_listener.http.default_action).target_group_arn == aws_lb_target_group.this.arn
    error_message = "Enabling Page Tamper must not change the ordinary Juice Shop default target group."
  }

  assert {
    condition     = output.page_tamper_path == "/csd-page-tamper/payment" && output.page_tamper_url == "http://${aws_lb.this.dns_name}/csd-page-tamper/payment"
    error_message = "Enabled mode must publish the canonical path and direct origin URL."
  }

  assert {
    condition     = output.page_tamper_target_group_arn == one(aws_lb_target_group.page_tamper).arn
    error_message = "Enabled mode must publish the dedicated Page Tamper target-group ARN for readiness checks."
  }

  assert {
    condition = alltrue([
      for selector in [
        "cache-control",
        "clear-site-data",
        "content-security-policy",
        "cross-origin-embedder-policy",
        "cross-origin-opener-policy",
        "cross-origin-resource-policy",
        "permissions-policy",
        "referrer-policy",
        "strict-transport-security",
        "x-content-type-options",
        "x-frame-options",
        "x-permitted-cross-domain-policies",
      ] : strcontains(local.page_tamper_nginx_config, "\"${selector}\" 1;")
    ]) && strcontains(local.page_tamper_nginx_config, "\"\" 1;") && strcontains(local.page_tamper_nginx_config, "~.*,.* 0;") && strcontains(local.page_tamper_nginx_config, "default 0;")
    error_message = "Selector validation must preserve absent-header baseline, allow only the 12 exact selector IDs, explicitly reject comma-joined values, and reject every other nonempty value through default 0."
  }

  assert {
    condition     = length(regexall("location\\s+=\\s+/healthz", file("${path.module}/main.tf"))) == 1 && length(regexall("values\\s*=\\s*\\[local\\.page_tamper_path\\]", file("${path.module}/main.tf"))) == 1 && !strcontains(local.page_tamper_path, "healthz")
    error_message = "The ALB listener rule must expose only the payment path; /healthz remains target-group-only."
  }

  assert {
    condition = alltrue([
      for container in jsondecode(aws_ecs_task_definition.this.container_definitions) :
      container.image == "docker.io/library/nginx@sha256:30f1c0d78e0ad60901648be663a710bdadf19e4c10ac6782c235200619158284" &&
      one(container.portMappings).containerPort == 8080 &&
      one(container.portMappings).hostPort == 8080 &&
      container.logConfiguration.options["awslogs-stream-prefix"] == "page-tamper"
      if container.name == "page-tamper"
      ]) && length([
      for container in jsondecode(aws_ecs_task_definition.this.container_definitions) : container
      if container.name == "page-tamper"
    ]) == 1
    error_message = "The enabled task must contain one digest-pinned NGINX sidecar on 8080 using the page-tamper log prefix."
  }

  assert {
    condition = alltrue([
      for token in [
        "cache-control",
        "clear-site-data",
        "content-security-policy",
        "cross-origin-embedder-policy",
        "cross-origin-opener-policy",
        "cross-origin-resource-policy",
        "permissions-policy",
        "referrer-policy",
        "strict-transport-security",
        "x-content-type-options",
        "x-frame-options",
        "x-permitted-cross-domain-policies",
        "x_csd_page_tamper",
        "no-store, max-age=0",
        "credentialless",
        "camera=(), geolocation=(), microphone=(), payment=(self)",
        "max-age=31536000; includeSubDomains",
        "nosniff",
        "DENY",
        ] : strcontains(one([
          for container in jsondecode(aws_ecs_task_definition.this.container_definitions) : one(container.command)
          if container.name == "page-tamper"
      ]), token)
    ])
    error_message = "The sidecar command must encode all canonical selector IDs, request selector, and baseline header values."
  }
}
