# AWS Juice Shop origin module

Deploys the intentionally vulnerable OWASP Juice Shop container on private AWS Fargate tasks behind an Application Load Balancer (ALB). Use only in authorized demo infrastructure.

## Architecture and authorization

The caller owns the VPC, ALB subnets, private task subnets, routing, provider authentication,
CloudWatch Logs KMS key, and ALB access-log S3 bucket. The module creates an ALB/listener/target
group, ECS cluster/service/task definition, security groups, an execution role with log-only
permissions, and a KMS-encrypted CloudWatch log group retained for at least 365 days. It creates no
SSH access, credentials, VPC, NAT gateway, KMS key, S3 bucket, or Terraform state backend.

`public_exposure` defaults to `false`, producing an internal ALB. Internet-facing exposure requires
`public_exposure = true`. Even then, restrict `allowed_ingress_cidrs` to approved source networks.
`0.0.0.0/0` is accepted only with explicit public exposure and is not recommended.

## Trust boundary

F5 Distributed Cloud is the public HTTPS termination and security enforcement point for this
origin design. Client-Side Defense and other configured edge controls run there; the module does
not create an AWS WAF because that would duplicate the enforcement point and expand the reusable
origin module's responsibility.

Traffic from F5 Distributed Cloud to the ALB intentionally uses HTTP. The ALB security group limits
port 80 ingress to `allowed_ingress_cidrs`, which operators must set to the approved F5 Distributed
Cloud egress or connected-network CIDRs. This hop is not encrypted, so its routing domain must be
trusted and protected from interception; use a different origin design if that trust cannot be
established.

The Juice Shop target natively serves HTTP. Fargate tasks have no public IP address and run in
caller-managed private subnets. Their security group accepts the container port only from the ALB
security group, so neither F5 Distributed Cloud nor arbitrary VPC sources connect directly to a
task. These controls are part of the exception rationale and must not be relaxed.

Deletion protection is intentionally disabled: this is ephemeral authorized demo infrastructure and must support prompt Terraform teardown after use.

## Prerequisites and routing

- Terraform >= 1.7 and AWS provider 6.x.
- Caller authorization to create ALB, ECS, IAM role/policy, CloudWatch Logs, and security-group resources.
- Two or more ALB subnets in `vpc_id`, spanning at least two Availability Zones. The module validates this with `aws_subnet` data.
- One or more caller-managed private task subnets in `vpc_id`. The module validates VPC membership but does not require multiple task Availability Zones when `desired_count = 1`.
- Task-subnet egress through NAT or an approved proxy for the Docker Hub image, plus AWS Logs connectivity; equivalent private endpoints and egress controls are acceptable. The module does not claim that private tasks can pull the image without this connectivity.
- ALB subnet routes appropriate to the chosen internal or internet-facing mode.
- A caller-managed symmetric KMS key. Its key policy must permit the CloudWatch Logs service principal for the deployment region to encrypt and decrypt the log group.
- A caller-managed S3 bucket for ALB access logs. The caller owns bucket encryption, retention/lifecycle, public-access blocking, and the regional Elastic Load Balancing log-delivery bucket policy.

## Immutable consumption

Downstream repositories should pin a released module version rather than a branch:

```hcl
module "juice_shop" {
  source = "git::https://github.com/f5-sales-demo/origin-server.git//terraform/modules/aws-juice-shop?ref=vX.Y.Z"
  # inputs omitted
}
```

Replace `vX.Y.Z` with an actual published release tag. The local example intentionally uses `source = "../.."` so repository validation does not require network access.

## Inputs

| Name | Required | Default | Description |
| --- | --- | --- | --- |
| `name` | yes | — | 2-32 character resource prefix; leaves room for generated suffixes and AWS ALB/target-group limits. |
| `vpc_id` | yes | — | Caller-managed VPC. |
| `alb_subnet_ids` | yes | — | At least two subnets in the VPC and distinct AZs. |
| `task_subnet_ids` | yes | — | Private Fargate subnets with required egress/endpoints. |
| `public_exposure` | no | `false` | Makes the ALB internet-facing when true. |
| `allowed_ingress_cidrs` | no | RFC1918 ranges | Authorized IPv4 listener sources. |
| `container_image` | no | digest-pinned Juice Shop image | Immutable OCI image reference. |
| `container_port` | no | `3000` | Container and target port. |
| `desired_count` | no | `1` | Fargate task count. |
| `cpu` / `memory` | no | `512` / `1024` | Valid Fargate sizing pair. |
| `cloudwatch_log_retention_days` | no | `365` | Log retention; values below 365 are rejected. |
| `cloudwatch_logs_kms_key_arn` | yes | — | Caller-managed KMS key ARN for CloudWatch Logs encryption. |
| `alb_access_logs_bucket` | yes | — | Caller-managed S3 bucket with an ALB log-delivery policy. |
| `alb_access_logs_prefix` | no | `juice-shop` | S3 key prefix for ALB access logs. |
| `tags` | no | `{}` | Additional resource tags. |

## Outputs

The module returns the ALB hostname and URL, listener attributes, ECS identifiers, load-balancer and target-group ARNs, security-group IDs, VPC/subnet inputs, and selected image. The hostname may resolve only inside connected networks when the ALB is internal.

## Deploy and verify

```bash
install -d -m 700 .artifacts
terraform init
terraform plan -out=.artifacts/tfplan
terraform apply .artifacts/tfplan
terraform output origin_url
```

Saved plans can contain sensitive configuration and state-derived values. Keep `.artifacts/` private, ignored, and out of logs or plan-JSON exports; remove saved plans when they are no longer needed.

Verify the ECS service reaches steady state, target health is healthy, CloudWatch receives container logs, and the URL is reachable only from an approved source. Re-run `terraform plan`; a stable deployment should show no changes.

## Image upgrades

Resolve and review a new image digest, update `container_image`, then plan and apply. The ECS deployment circuit breaker automatically rolls back a failed deployment. Never replace the digest with a mutable tag such as `latest`.

## Costs and destroy

ALB hourly/capacity charges, Fargate compute, Container Insights metrics, CloudWatch Logs storage/KMS requests, S3 access-log storage, data transfer, and caller-managed NAT gateway/endpoints can incur costs. Destroy when the demo is finished:

```bash
install -d -m 700 .artifacts
terraform plan -destroy -out=.artifacts/destroy.tfplan
terraform apply .artifacts/destroy.tfplan
```

Caller-owned VPC, subnet, NAT, proxy, endpoint, and routing resources are not destroyed.

## Troubleshooting

- **ALB subnet check fails:** confirm every ALB subnet belongs to `vpc_id` and the set spans two AZs.
- **Task subnet check fails:** confirm every task subnet belongs to `vpc_id`; multiple task Availability Zones are optional for a single desired task.

- **Tasks cannot start / image pull fails:** verify task-subnet routes, NAT/proxy policy, DNS, and Docker Hub reachability.
- **Log initialization fails:** verify network reachability to AWS Logs, the KMS key ARN and regional CloudWatch Logs key policy, and caller permissions to create the module resources.
- **ALB access logs are absent:** verify the bucket is in the supported region and its policy permits regional Elastic Load Balancing log delivery to the configured prefix.
- **Targets stay unhealthy:** inspect ECS events and CloudWatch logs; confirm the container listens on `container_port` and task security-group ingress references the ALB security group.
- **Internal URL is unreachable:** connect through the VPC, VPN, Direct Connect, or another authorized routed network; do not make the ALB public merely to bypass missing routing.
