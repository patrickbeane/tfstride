# tfSTRIDE Threat Model Report

- Analyzed file: `sample_aws_alb_ec2_rds_plan.json`
- Provider: `aws`
- Normalized resources: `19`
- Unsupported resources: `0`

## Summary

This run identified **4 trust boundaries** and **4 findings** across **19 normalized resources**.

- High severity findings: `0`
- Medium severity findings: `3`
- Low severity findings: `1`

## Analysis Coverage

- Terraform resources seen: `19`
- Provider resources considered: `19`
- Normalized resources: `19`
- Unsupported resources: `0`
- Registered rules: `204`
- Enabled rules: `204`
- Disabled rules: `0`
- Severity overrides: `0`
- Unresolved in-plan references: `0`
- Findings by rule:
  - `aws-public-alb-waf-missing`: `1`
  - `aws-rds-cloudwatch-log-exports-missing`: `1`
  - `aws-vpc-flow-logs-not-configured`: `1`
  - `aws-private-data-transitive-exposure`: `1`

## Discovered Trust Boundaries

### `internet-to-service`

- Source: `internet`
- Target: `aws_lb.web`
- Description: Traffic can cross from the public internet to aws_lb.web.
- Rationale: The resource is directly reachable or intentionally exposed to unauthenticated network clients.

### `public-subnet-to-private-subnet`

- Source: `aws_subnet.public_edge`
- Target: `aws_subnet.private_app`
- Description: Traffic can move from aws_subnet.public_edge toward aws_subnet.private_app.
- Rationale: The VPC contains both publicly routable and private network segments that should be treated as separate trust zones.

### `public-subnet-to-private-subnet`

- Source: `aws_subnet.public_edge`
- Target: `aws_subnet.private_data`
- Description: Traffic can move from aws_subnet.public_edge toward aws_subnet.private_data.
- Rationale: The VPC contains both publicly routable and private network segments that should be treated as separate trust zones.

### `workload-to-data-store`

- Source: `aws_instance.app`
- Target: `aws_db_instance.app`
- Description: aws_instance.app can interact with aws_db_instance.app.
- Rationale: Application or function workloads cross into a higher-sensitivity data plane when database ingress security groups explicitly trust the workload security group.

## Findings

### High

No findings in this severity band.

### Medium

#### Public Application Load Balancer is not associated with a WAF Web ACL

- STRIDE category: Tampering
- Affected resources: `aws_lb.web`
- Trust boundary: `not-applicable`
- Severity reasoning: internet_exposure +2, privilege_breadth +0, data_sensitivity +0, lateral_movement +1, blast_radius +1, final_score 4 => medium
- Rationale: aws_lb.web is an internet-facing Application Load Balancer, but the Terraform plan does not show a deterministic AWS WAFv2 Web ACL association targeting it. Public edge traffic can reach the ALB without a modeled WAF or edge protection policy.
- Recommended mitigation: Associate an AWS WAFv2 Web ACL with internet-facing Application Load Balancers and keep the association modeled in Terraform so public edge protection is reviewable before deployment.
- Evidence:
  - target load balancer: address=aws_lb.web; type=aws_lb; arn=arn:aws:elasticloadbalancing:us-east-1:333344445555:loadbalancer/app/web-prod/123456; load_balancer_type=application; public_exposure=true; load balancer is internet-facing and attached security groups allow internet ingress
  - waf association coverage: target_resource_arn=arn:aws:elasticloadbalancing:us-east-1:333344445555:loadbalancer/app/web-prod/123456; resolved_web_acl_association_count=0; modeled_web_acl_association_count=0

#### Sensitive data tier is transitively reachable from an internet-exposed path

- STRIDE category: Information Disclosure
- Affected resources: `aws_lb.web`, `aws_instance.app`, `aws_db_instance.app`, `aws_security_group.app`
- Trust boundary: `workload-to-data-store:aws_instance.app->aws_db_instance.app`
- Severity reasoning: internet_exposure +0, privilege_breadth +0, data_sensitivity +2, lateral_movement +2, blast_radius +1, final_score 5 => medium
- Rationale: aws_db_instance.app is not directly public, but internet traffic can first reach aws_lb.web, move through aws_lb.web can reach aws_instance.app, and then cross into the private data tier through aws_instance.app. That creates a quieter transitive exposure path than a directly public data store.
- Recommended mitigation: Keep internet-adjacent entry points from chaining into workloads that retain database or secret access, narrow edge-to-workload and workload-to-workload trust, and isolate sensitive data access behind more deliberate service boundaries.
- Evidence:
  - network path: internet reaches aws_lb.web; aws_lb.web reaches aws_instance.app; aws_instance.app reaches aws_db_instance.app
  - security group rules: aws_security_group.app ingress tcp 8080 from sg-web-lb-001 (Application traffic from the ALB)
  - subnet posture: aws_lb.web sits in public subnet aws_subnet.public_edge with an internet route; aws_instance.app sits in private subnet aws_subnet.private_app with NAT-backed egress
  - data tier posture: aws_db_instance.app is not directly public; database has no direct internet ingress path
  - boundary rationale: Application or function workloads cross into a higher-sensitivity data plane when database ingress security groups explicitly trust the workload security group.

#### VPC Flow Logs are not configured for a modeled VPC

- STRIDE category: Repudiation
- Affected resources: `aws_vpc.main`
- Trust boundary: `not-applicable`
- Severity reasoning: internet_exposure +0, privilege_breadth +0, data_sensitivity +0, lateral_movement +1, blast_radius +2, final_score 3 => medium
- Rationale: aws_vpc.main does not have a resolved aws_flow_log targeting the VPC in this Terraform plan. Network traffic metadata for incident response, threat hunting, and segmentation review may be unavailable unless Flow Logs are configured elsewhere.
- Recommended mitigation: Enable VPC Flow Logs for production VPCs, route them to a retained CloudWatch Logs, S3, or Firehose destination, and manage Flow Log resources in Terraform so network telemetry posture is reviewable.
- Evidence:
  - target vpc: address=aws_vpc.main; type=aws_vpc; identifier=vpc-web-001; cidr_block=10.20.0.0/16
  - flow log coverage: target_vpc_id=vpc-web-001; resolved_vpc_flow_log_count=0; aws_flow_log resources are not modeled

### Low

#### RDS database does not export engine CloudWatch logs

- STRIDE category: Repudiation
- Affected resources: `aws_db_instance.app`
- Trust boundary: `not-applicable`
- Severity reasoning: internet_exposure +0, privilege_breadth +0, data_sensitivity +1, lateral_movement +0, blast_radius +1, final_score 2 => low
- Rationale: aws_db_instance.app (engine `postgres`) does not export any of the baseline CloudWatch Logs expected for its engine family (postgresql). Without these log exports the database lacks the basic observability posture needed to investigate errors, slow queries, and audit activity from CloudWatch.
- Recommended mitigation: Enable the CloudWatch Logs exports expected for the RDS engine family (for example `postgresql` for PostgreSQL, `error` and `slowquery` for MySQL/MariaDB) so errors, slow queries, and audit activity are captured for investigation.
- Evidence:
  - target resource: address=aws_db_instance.app; type=aws_db_instance; identifier=db-web-001; engine=postgres
  - log export posture: enabled_cloudwatch_logs_exports=[]; expected_log_exports=['postgresql']; engine-family baseline log exports are absent

## Controls Observed

### RDS instance is private and storage encrypted

- Category: `data-protection`
- Affected resources: `aws_db_instance.app`
- Rationale: aws_db_instance.app is kept off direct internet paths and has storage encryption enabled, which reduces straightforward data exposure risk.
- Evidence:
  - database posture: publicly_accessible is false; storage_encrypted is true; no attached security group allows internet ingress; engine is postgres

## Limitations / Unsupported Resources

- AWS support is intentionally limited to a curated v1 resource set rather than the full Terraform AWS provider.
- Subnet public/private classification prefers explicit route table associations and NAT or internet routes when present, but it does not model main-route-table inheritance or every routing edge case.
- IAM analysis resolves inline role policies, customer-managed role-policy attachments, and EC2 instance profiles present in the plan, but it does not expand AWS-managed policy documents that are not materialized in Terraform state.
- Resource-policy analysis focuses on explicit policy documents and Lambda permission resources present in the plan; it does not model every service-specific condition key or every downstream runtime authorization path.
- The engine reasons over Terraform planned values only and does not validate runtime drift, CloudTrail evidence, or post-deploy control-plane activity.
