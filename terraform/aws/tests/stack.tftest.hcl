mock_provider "aws" {
  mock_resource "aws_cloudwatch_log_group" {
    defaults = {
      arn = "arn:aws:logs:us-east-1:280469140135:log-group:/aws/vpc/csd-juice-shop"
    }
  }

  mock_resource "aws_iam_role" {
    defaults = {
      arn = "arn:aws:iam::280469140135:role/csd-juice-shop-vpc-flow"
    }
  }
}
mock_provider "xcsh" {}

override_data {
  target = data.aws_caller_identity.current
  values = {
    account_id = "280469140135"
  }
}

override_data {
  target = data.xcsh_addon_service_activation_status.csd
  values = {
    state = "AS_SUBSCRIBED"
  }
}

override_module {
  target = module.origin
  outputs = {
    origin_hostname   = "origin.example.com"
    origin_url        = "http://origin.example.com"
    listener_port     = 80
    load_balancer_arn = "arn:aws:elasticloadbalancing:us-east-1:280469140135:loadbalancer/app/csd/0000000000000000"
    target_group_arn  = "arn:aws:elasticloadbalancing:us-east-1:280469140135:targetgroup/csd/0000000000000000"
    alb_subnet_ids    = ["subnet-public-a", "subnet-public-b"]
    task_subnet_ids   = ["subnet-private-a", "subnet-private-b"]
  }
}

run "stack_contract" {
  command = apply

  assert {
    condition     = length(regexall("allowed_account_ids\\s*=\\s*\\[\\s*var\\.expected_aws_account_id\\s*\\]", file("${path.module}/versions.tf"))) == 1
    error_message = "The AWS provider must enforce the approved account from expected_aws_account_id at provider initialization."
  }

  assert {
    condition     = length(regexall("(?s)module\\s+\"origin\"\\s*\\{.*?depends_on\\s*=\\s*\\[\\s*aws_route\\.public_internet,\\s*aws_route\\.private_egress,\\s*aws_route_table_association\\.public,\\s*aws_route_table_association\\.private,\\s*aws_s3_bucket_policy\\.alb_logs,\\s*aws_s3_bucket_server_side_encryption_configuration\\.alb_logs,\\s*\\]", file("${path.module}/main.tf"))) == 1
    error_message = "The origin module must wait for both default routes, both route-table association sets, and the existing log-bucket dependencies."
  }

  assert {
    condition     = aws_vpc.csd.cidr_block == "10.43.0.0/16"
    error_message = "The CSD stack must use the reviewed non-overlapping VPC CIDR."
  }

  assert {
    condition     = toset(var.public_subnet_cidrs) == toset(["10.43.0.0/24", "10.43.1.0/24"]) && toset(var.private_subnet_cidrs) == toset(["10.43.10.0/24", "10.43.11.0/24"])
    error_message = "The CSD subnets must use the reviewed non-overlapping two-AZ layout."
  }

  assert {
    condition = var.origin_ingress_cidrs == toset([
      "5.182.215.0/25",
      "84.54.61.0/25",
      "23.158.32.0/25",
      "84.54.62.0/25",
      "185.94.143.0/25",
      "185.94.142.0/24",
      "159.60.190.0/24",
      "159.60.168.0/24",
      "159.60.180.0/24",
      "159.60.174.0/24",
      "159.60.175.0/24",
      "159.60.176.0/24",
      "159.60.177.0/24",
      "159.60.179.0/24",
      "159.60.181.0/24",
      "159.60.183.0/24",
    ]) && !contains(var.origin_ingress_cidrs, "0.0.0.0/0")
    error_message = "The public origin must allow only the documented Americas Regional Edge CIDRs by default."
  }

  assert {
    condition     = aws_s3_bucket.alb_logs.bucket_prefix == "f5-sales-demo-csd-alb-logs-" && aws_s3_bucket.alb_logs.force_destroy
    error_message = "The ALB log bucket must use a generated name and allow complete demo teardown."
  }

  assert {
    condition     = aws_s3_bucket_versioning.alb_logs.versioning_configuration[0].status == "Enabled"
    error_message = "The ALB access-log bucket must retain recoverable object versions."
  }

  assert {
    condition = anytrue([
      for statement in jsondecode(aws_iam_role_policy.vpc_flow.policy).Statement :
      statement.Effect == "Allow" && try(toset(statement.Action), toset([statement.Action])) == toset(["logs:DescribeLogGroups"]) && statement.Resource == "*"
    ])
    error_message = "The VPC flow-log role must allow DescribeLogGroups in a separate wildcard-scoped statement."
  }

  assert {
    condition = anytrue([
      for statement in jsondecode(aws_iam_role_policy.vpc_flow.policy).Statement :
      statement.Effect == "Allow" && contains(try(toset(statement.Action), toset([statement.Action])), "logs:PutLogEvents") && statement.Resource == "${aws_cloudwatch_log_group.vpc_flow.arn}:*" && !contains(try(toset(statement.Action), toset([statement.Action])), "logs:DescribeLogGroups")
    ])
    error_message = "Restrictable VPC flow-log write actions must remain scoped to the log-group ARN and separate from DescribeLogGroups."
  }

  assert {
    condition     = one(aws_s3_bucket_lifecycle_configuration.alb_logs.rule).expiration[0].days == 90 && one(aws_s3_bucket_lifecycle_configuration.alb_logs.rule).noncurrent_version_expiration[0].noncurrent_days == 90 && one(aws_s3_bucket_lifecycle_configuration.alb_logs.rule).abort_incomplete_multipart_upload[0].days_after_initiation == 7
    error_message = "The ALB log lifecycle must expire current and noncurrent versions after 90 days while preserving multipart cleanup."
  }

  assert {
    condition     = aws_flow_log.csd.traffic_type == "ALL" && aws_flow_log.csd.log_destination_type == "cloud-watch-logs"
    error_message = "The dedicated VPC must publish all flow records to CloudWatch Logs."
  }

  assert {
    condition     = aws_cloudwatch_log_group.vpc_flow.name == "/aws/vpc/csd-juice-shop" && aws_cloudwatch_log_group.vpc_flow.retention_in_days == 365
    error_message = "VPC flow logging must use the dedicated one-year-retention CloudWatch log group."
  }

  assert {
    condition     = strcontains(aws_kms_key.logs.policy, "log-group:/aws/vpc/csd-juice-shop*")
    error_message = "The CloudWatch Logs KMS policy must authorize the VPC flow-log namespace."
  }

  assert {
    condition     = length(aws_default_security_group.csd.ingress) == 0 && length(aws_default_security_group.csd.egress) == 0
    error_message = "The VPC default security group must be explicitly managed with no ingress or egress rules."
  }

  assert {
    condition     = output.alb_arn == module.origin.load_balancer_arn && output.target_group_arn == module.origin.target_group_arn
    error_message = "The stack must re-export the ALB and target group ARNs."
  }

  assert {
    condition     = output.listener_port == 80 && output.health_check_port == 3000
    error_message = "The stack must re-export the origin listener and target health-check ports."
  }

  assert {
    condition     = output.public_subnet_ids == module.origin.alb_subnet_ids && output.private_subnet_ids == module.origin.task_subnet_ids
    error_message = "The stack must re-export the selected public and private subnet IDs."
  }

  assert {
    condition     = output.alb_access_logs_prefix == "juice-shop"
    error_message = "The stack must re-export the ALB access-log prefix."
  }

  assert {
    condition     = length(aws_subnet.public) == 2 && length(aws_subnet.private) == 2
    error_message = "The dedicated VPC must have two public and two private subnets."
  }

  assert {
    condition     = length(aws_nat_gateway.csd) == 1
    error_message = "The stack must use the documented single NAT Gateway topology."
  }


  assert {
    condition     = xcsh_protected_domain.csd.namespace == "client-side-defense" && xcsh_protected_domain.csd.protected_domain == "f5-sales-demo.com"
    error_message = "The protected-domain prerequisite must use the guarded namespace and registrable parent domain."
  }

  assert {
    condition     = xcsh_origin_pool.origin.port == 80 && one(xcsh_origin_pool.origin.origin_servers).public_name.dns_name == module.origin.origin_hostname
    error_message = "The origin pool must target the module ALB hostname over HTTP port 80."
  }

  assert {
    condition     = toset(xcsh_http_loadbalancer.csd.domains) == toset(["client-side-defense.f5-sales-demo.com"])
    error_message = "The load balancer must use the guarded CSD domain."
  }

  assert {
    condition     = xcsh_http_loadbalancer.csd.https_auto_cert.http_redirect == true
    error_message = "The load balancer must use auto-cert with HTTP redirect."
  }

  assert {
    condition     = xcsh_http_loadbalancer.csd.advertise_on_public_default_vip != null
    error_message = "The load balancer must advertise on the public default VIP."
  }

  assert {
    condition     = xcsh_http_loadbalancer.csd.client_side_defense.policy.js_insert_all_pages != null
    error_message = "Client-Side Defense JavaScript injection must cover all pages."
  }

  assert {
    condition     = one(xcsh_http_loadbalancer.csd.default_route_pools).pool.name == xcsh_origin_pool.origin.name
    error_message = "The default route must reference the managed origin pool."
  }
}


run "reject_wrong_aws_account" {
  command = plan

  override_data {
    target = data.aws_caller_identity.current
    values = {
      account_id = "111111111111"
    }
  }

  expect_failures = [aws_vpc.csd]
}

run "reject_missing_csd_entitlement" {
  command = plan

  override_data {
    target = data.xcsh_addon_service_activation_status.csd
    values = {
      state = "AS_NOT_SUBSCRIBED"
    }
  }

  expect_failures = [terraform_data.require_csd]
}
