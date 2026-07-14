# tfSTRIDE Threat Model Report

- Analyzed file: `sample_aws_plan.json`
- Provider: `aws`
- Normalized resources: `23`
- Unsupported resources: `1`

## Summary

This run identified **9 trust boundaries** and **15 findings** across **23 normalized resources**.

- High severity findings: `4`
- Medium severity findings: `10`
- Low severity findings: `1`

## Analysis Coverage

- Terraform resources seen: `24`
- Provider resources considered: `24`
- Normalized resources: `23`
- Unsupported resources: `1`
- Registered rules: `218`
- Enabled rules: `218`
- Disabled rules: `0`
- Severity overrides: `0`
- Unresolved in-plan references: `0`
- Unsupported resource types:
  - `aws_cloudwatch_log_group`: `1`
- Findings by rule:
  - `aws-public-compute-broad-ingress`: `1`
  - `aws-public-alb-waf-missing`: `1`
  - `aws-database-permissive-ingress`: `1`
  - `aws-rds-cloudwatch-log-exports-missing`: `1`
  - `aws-s3-public-access`: `1`
  - `aws-workload-kms-vpc-endpoint-missing`: `1`
  - `aws-workload-s3-vpc-endpoint-missing`: `1`
  - `aws-vpc-flow-logs-not-configured`: `1`
  - `aws-iam-wildcard-permissions`: `2`
  - `aws-iam-privileged-role-assignment`: `1`
  - `aws-workload-role-sensitive-permissions`: `1`
  - `aws-missing-tier-segmentation`: `1`
  - `aws-role-trust-expansion`: `1`
  - `aws-role-trust-missing-narrowing`: `1`

## Discovered Trust Boundaries

### `internet-to-service`

- Source: `internet`
- Target: `aws_lb.web`
- Description: Traffic can cross from the public internet to aws_lb.web.
- Rationale: The resource is directly reachable or intentionally exposed to unauthenticated network clients.

### `internet-to-service`

- Source: `internet`
- Target: `aws_instance.app`
- Description: Traffic can cross from the public internet to aws_instance.app.
- Rationale: The resource is directly reachable or intentionally exposed to unauthenticated network clients.

### `internet-to-service`

- Source: `internet`
- Target: `aws_s3_bucket.assets`
- Description: Traffic can cross from the public internet to aws_s3_bucket.assets.
- Rationale: The resource is directly reachable or intentionally exposed to unauthenticated network clients.

### `public-subnet-to-private-subnet`

- Source: `aws_subnet.public_app`
- Target: `aws_subnet.private_data`
- Description: Traffic can move from aws_subnet.public_app toward aws_subnet.private_data.
- Rationale: The VPC contains both publicly routable and private network segments that should be treated as separate trust zones.

### `workload-to-data-store`

- Source: `aws_instance.app`
- Target: `aws_db_instance.app`
- Description: aws_instance.app can interact with aws_db_instance.app.
- Rationale: Application or function workloads cross into a higher-sensitivity data plane when database ingress security groups explicitly trust the workload security group.

### `workload-to-data-store`

- Source: `aws_lambda_function.processor`
- Target: `aws_db_instance.app`
- Description: aws_lambda_function.processor can interact with aws_db_instance.app.
- Rationale: Application or function workloads cross into a higher-sensitivity data plane when database ingress security groups explicitly trust the workload security group.

### `workload-to-data-store`

- Source: `aws_lambda_function.processor`
- Target: `aws_s3_bucket.assets`
- Description: aws_lambda_function.processor can interact with aws_s3_bucket.assets.
- Rationale: Application or function workloads cross into a higher-sensitivity data plane when their attached role allows S3 actions such as s3:*.

### `admin-to-workload-plane`

- Source: `aws_iam_role.workload`
- Target: `aws_lambda_function.processor`
- Description: aws_iam_role.workload governs actions performed by aws_lambda_function.processor.
- Rationale: IAM configuration acts as a control-plane boundary because the workload inherits whatever privileges the role carries.

### `cross-account-or-role-access`

- Source: `arn:aws:iam::999988887777:root`
- Target: `aws_iam_role.workload`
- Description: aws_iam_role.workload trusts arn:aws:iam::999988887777:root.
- Rationale: A foreign AWS account can cross into this role's trust boundary.

## Findings

### High

#### Database is reachable from overly permissive sources

- STRIDE category: Information Disclosure
- Affected resources: `aws_db_instance.app`, `aws_security_group.db`
- Trust boundary: `workload-to-data-store:aws_instance.app->aws_db_instance.app`
- Severity reasoning: internet_exposure +2, privilege_breadth +0, data_sensitivity +2, lateral_movement +1, blast_radius +1, final_score 6 => high
- Rationale: aws_db_instance.app is a sensitive data store, but database is not marked directly internet reachable, but its security groups allow internet-origin ingress, and database trusts security groups attached to internet-exposed workloads. That weakens the expected separation between the workload tier and the data tier.
- Recommended mitigation: Keep databases off public paths, allow ingress only from narrowly scoped application security groups, and enforce authentication plus encryption independently of network policy.
- Evidence:
  - security group rules: aws_security_group.db ingress tcp 5432 from 0.0.0.0/0 (Postgres from internet); aws_security_group.db ingress tcp 5432 from sg-app-001 (Postgres from public app tier)
  - network path: database is not marked directly internet reachable, but its security groups allow internet-origin ingress; database trusts security groups attached to internet-exposed workloads; aws_security_group.db allows sg-app-001 attached to aws_instance.app, aws_lb.web
  - subnet posture: aws_instance.app sits in public subnet aws_subnet.public_app with an internet route; aws_lb.web sits in public subnet aws_subnet.public_app with an internet route

#### IAM role has privileged assignment posture

- STRIDE category: Elevation of Privilege
- Affected resources: `aws_iam_role.workload`, `aws_iam_policy.admin_like`
- Trust boundary: `not-applicable`
- Severity reasoning: internet_exposure +0, privilege_breadth +3, data_sensitivity +2, lateral_movement +2, blast_radius +3, final_score 10 => high
- Rationale: aws_iam_role.workload has deterministic privileged IAM assignment posture: compute-admin, data-admin, iam-admin, key-admin, privilege-escalation. If this role is attached to a workload or assumable by a control-plane principal, those privileges increase blast radius.
- Recommended mitigation: Review high-impact IAM role permissions, split administrative and runtime duties, scope resources to named ARNs, and avoid attaching broad IAM, role-passing, secrets, KMS, data, network, or audit administration permissions to general workload roles.
- Evidence:
  - iam role: address=aws_iam_role.workload; type=aws_iam_role; arn=arn:aws:iam::111122223333:role/workload-role; identifier=workload-role
  - privileged access: grant_1=categories=[data-admin, key-admin, privilege-escalation]; scope=account; confidence=high; grant_2=categories=[compute-admin, iam-admin]; scope=account; confidence=high
  - privilege categories: compute-admin; data-admin; iam-admin; key-admin; privilege-escalation
  - permission patterns: s3:*; iam:PassRole; sts:AssumeRole; ec2:*; iam:*
  - grant scopes: scope_kind=account; scope_value=*
  - grant confidence: high
  - attached policies: attached_policy_arn=arn:aws:iam::111122223333:policy/admin-like; attached_policy_address=aws_iam_policy.admin_like
  - inline policy sources: inline_policy_name=workload-inline

#### Private data tier directly trusts the public application tier

- STRIDE category: Tampering
- Affected resources: `aws_db_instance.app`, `aws_instance.app`, `aws_lb.web`, `aws_security_group.db`
- Trust boundary: `public-subnet-to-private-subnet:aws_subnet.public_app->aws_subnet.private_data`
- Severity reasoning: internet_exposure +2, privilege_breadth +0, data_sensitivity +2, lateral_movement +2, blast_radius +1, final_score 7 => high
- Rationale: aws_db_instance.app accepts traffic from security groups attached to internet-facing workloads. A compromise of the public tier can therefore move laterally into the private data tier.
- Recommended mitigation: Introduce tighter tier segmentation with dedicated security groups, narrow ingress to specific services and ports, and keep the data tier reachable only through controlled application paths.
- Evidence:
  - security group rules: aws_security_group.db ingress tcp 5432 from sg-app-001 (Postgres from public app tier)
  - network path: aws_security_group.db allows sg-app-001 attached to aws_instance.app, aws_lb.web
  - subnet posture: aws_instance.app sits in public subnet aws_subnet.public_app with an internet route; aws_lb.web sits in public subnet aws_subnet.public_app with an internet route

#### Workload role carries sensitive permissions

- STRIDE category: Elevation of Privilege
- Affected resources: `aws_lambda_function.processor`, `aws_iam_role.workload`
- Trust boundary: `admin-to-workload-plane:aws_iam_role.workload->aws_lambda_function.processor`
- Severity reasoning: internet_exposure +0, privilege_breadth +2, data_sensitivity +1, lateral_movement +1, blast_radius +2, final_score 6 => high
- Rationale: aws_lambda_function.processor inherits sensitive privileges from aws_iam_role.workload, including iam:PassRole, kms:Decrypt, s3:*, sts:AssumeRole. If the workload is compromised, those credentials can be reused for privilege escalation, data access, or role chaining.
- Recommended mitigation: Split high-privilege actions into separate roles, scope permissions to named resources, and remove role-passing or cross-role permissions from general application identities.
- Evidence:
  - iam actions: iam:PassRole; kms:Decrypt; s3:*; sts:AssumeRole
  - policy statements: Allow actions=[s3:*, kms:Decrypt, iam:PassRole, sts:AssumeRole] resources=[*]

### Medium

#### Cross-account or broad role trust lacks narrowing conditions

- STRIDE category: Elevation of Privilege
- Affected resources: `aws_iam_role.workload`
- Trust boundary: `cross-account-or-role-access:arn:aws:iam::999988887777:root->aws_iam_role.workload`
- Severity reasoning: internet_exposure +0, privilege_breadth +2, data_sensitivity +0, lateral_movement +1, blast_radius +2, final_score 5 => medium
- Rationale: aws_iam_role.workload trusts arn:aws:iam::999988887777:root without supported narrowing conditions such as `sts:ExternalId`, `aws:SourceArn`, or `aws:SourceAccount`. That leaves the assume-role path dependent on the trusted principal match alone.
- Recommended mitigation: Keep the trusted principal as specific as possible and add supported assume-role conditions such as `ExternalId`, `SourceArn`, `SourceAccount`, `SAML:aud`, or provider-specific OIDC `aud` and `sub` checks when crossing accounts or trusting broad or federated principals.
- Evidence:
  - trust principals: arn:aws:iam::999988887777:root
  - trust scope: principal is foreign account root 999988887777
  - trust narrowing: supported narrowing conditions present: false; supported narrowing condition keys: none

#### IAM policy grants wildcard privileges

- STRIDE category: Elevation of Privilege
- Affected resources: `aws_iam_role.workload`
- Trust boundary: `not-applicable`
- Severity reasoning: internet_exposure +0, privilege_breadth +2, data_sensitivity +0, lateral_movement +1, blast_radius +2, final_score 5 => medium
- Rationale: aws_iam_role.workload contains allow statements with wildcard actions or resources. That makes the resulting access difficult to reason about and expands blast radius.
- Recommended mitigation: Replace wildcard actions and resources with narrowly scoped permissions tied to the exact services, APIs, and ARNs required by the workload.
- Evidence:
  - iam actions: ec2:*; iam:*; s3:*
  - iam resources: *
  - policy statements: Allow actions=[s3:*, kms:Decrypt, iam:PassRole, sts:AssumeRole] resources=[*]; Allow actions=[ec2:*, iam:*] resources=[*]

#### IAM policy grants wildcard privileges

- STRIDE category: Elevation of Privilege
- Affected resources: `aws_iam_policy.admin_like`
- Trust boundary: `not-applicable`
- Severity reasoning: internet_exposure +0, privilege_breadth +2, data_sensitivity +0, lateral_movement +1, blast_radius +2, final_score 5 => medium
- Rationale: aws_iam_policy.admin_like contains allow statements with wildcard actions or resources. That makes the resulting access difficult to reason about and expands blast radius.
- Recommended mitigation: Replace wildcard actions and resources with narrowly scoped permissions tied to the exact services, APIs, and ARNs required by the workload.
- Evidence:
  - iam actions: ec2:*; iam:*
  - iam resources: *
  - policy statements: Allow actions=[ec2:*, iam:*] resources=[*]

#### Internet-exposed compute service permits overly broad ingress

- STRIDE category: Spoofing
- Affected resources: `aws_instance.app`, `aws_security_group.app`
- Trust boundary: `internet-to-service:internet->aws_instance.app`
- Severity reasoning: internet_exposure +2, privilege_breadth +0, data_sensitivity +0, lateral_movement +1, blast_radius +1, final_score 4 => medium
- Rationale: aws_instance.app is reachable from the internet and at least one attached security group allows administrative access or all ports from 0.0.0.0/0. That broad ingress raises the chance of unauthenticated probing and credential attacks.
- Recommended mitigation: Restrict ingress to expected client ports, remove direct administrative exposure, and place management access behind a controlled bastion, VPN, or SSM Session Manager.
- Evidence:
  - security group rules: aws_security_group.app ingress tcp 22 from 0.0.0.0/0 (SSH from internet)
  - public exposure reasons: instance has a public IP path and attached security groups allow internet ingress
  - subnet posture: aws_instance.app sits in public subnet aws_subnet.public_app with an internet route

#### Object storage is publicly accessible

- STRIDE category: Information Disclosure
- Affected resources: `aws_s3_bucket.assets`
- Trust boundary: `internet-to-service:internet->aws_s3_bucket.assets`
- Severity reasoning: internet_exposure +2, privilege_breadth +0, data_sensitivity +2, lateral_movement +0, blast_radius +1, final_score 5 => medium
- Rationale: aws_s3_bucket.assets appears to be public through ACLs or bucket policy. Public object access is a common source of unintended data disclosure.
- Recommended mitigation: Remove public ACL or bucket policy access, enable an S3 public access block, and serve content through a controlled CDN or origin access pattern when public distribution is required.
- Evidence:
  - public exposure reasons: bucket ACL `public-read` grants public access; bucket policy allows anonymous access

#### Public Application Load Balancer is not associated with a WAF Web ACL

- STRIDE category: Tampering
- Affected resources: `aws_lb.web`
- Trust boundary: `not-applicable`
- Severity reasoning: internet_exposure +2, privilege_breadth +0, data_sensitivity +0, lateral_movement +1, blast_radius +1, final_score 4 => medium
- Rationale: aws_lb.web is an internet-facing Application Load Balancer, but the Terraform plan does not show a deterministic AWS WAFv2 Web ACL association targeting it. Public edge traffic can reach the ALB without a modeled WAF or edge protection policy.
- Recommended mitigation: Associate an AWS WAFv2 Web ACL with internet-facing Application Load Balancers and keep the association modeled in Terraform so public edge protection is reviewable before deployment.
- Evidence:
  - target load balancer: address=aws_lb.web; type=aws_lb; arn=arn:aws:elasticloadbalancing:us-east-1:111122223333:loadbalancer/app/web/123456; load_balancer_type=application; public_exposure=true; load balancer is internet-facing and attached security groups allow internet ingress
  - waf association coverage: target_resource_arn=arn:aws:elasticloadbalancing:us-east-1:111122223333:loadbalancer/app/web/123456; resolved_web_acl_association_count=0; modeled_web_acl_association_count=0

#### Role trust relationship expands blast radius

- STRIDE category: Elevation of Privilege
- Affected resources: `aws_iam_role.workload`
- Trust boundary: `cross-account-or-role-access:arn:aws:iam::999988887777:root->aws_iam_role.workload`
- Severity reasoning: internet_exposure +0, privilege_breadth +1, data_sensitivity +0, lateral_movement +2, blast_radius +2, final_score 5 => medium
- Rationale: aws_iam_role.workload can be assumed by arn:aws:iam::999988887777:root. Broad or foreign-account trust relationships increase the chance that compromise in one identity domain spills into another.
- Recommended mitigation: Limit trust policies to the exact service principals or roles required, prefer role ARNs over account root where possible, and add conditions such as `ExternalId`, source ARN, SAML audience, or OIDC audience and subject checks.
- Evidence:
  - trust principals: arn:aws:iam::999988887777:root
  - trust path: trust principal belongs to foreign account 999988887777

#### VPC Flow Logs are not configured for a modeled VPC

- STRIDE category: Repudiation
- Affected resources: `aws_vpc.main`
- Trust boundary: `not-applicable`
- Severity reasoning: internet_exposure +0, privilege_breadth +0, data_sensitivity +0, lateral_movement +1, blast_radius +2, final_score 3 => medium
- Rationale: aws_vpc.main does not have a resolved aws_flow_log targeting the VPC in this Terraform plan. Network traffic metadata for incident response, threat hunting, and segmentation review may be unavailable unless Flow Logs are configured elsewhere.
- Recommended mitigation: Enable VPC Flow Logs for production VPCs, route them to a retained CloudWatch Logs, S3, or Firehose destination, and manage Flow Log resources in Terraform so network telemetry posture is reviewable.
- Evidence:
  - target vpc: address=aws_vpc.main; type=aws_vpc; identifier=vpc-001; cidr_block=10.0.0.0/16
  - flow log coverage: target_vpc_id=vpc-001; resolved_vpc_flow_log_count=0; aws_flow_log resources are not modeled

#### Workload uses KMS without a VPC endpoint

- STRIDE category: Information Disclosure
- Affected resources: `aws_lambda_function.processor`, `aws_iam_role.workload`
- Trust boundary: `not-applicable`
- Severity reasoning: internet_exposure +0, privilege_breadth +1, data_sensitivity +1, lateral_movement +1, blast_radius +1, final_score 4 => medium
- Rationale: aws_lambda_function.processor runs in VPC `vpc-001` and inherits KMS cryptographic key access from aws_iam_role.workload, but the Terraform plan does not show a KMS interface VPC endpoint for that VPC. Calls to the sensitive service may therefore depend on public AWS service endpoints, NAT, or another egress path.
- Recommended mitigation: Add a KMS interface VPC endpoint with private DNS enabled for VPC workloads that perform key operations, and narrow endpoint policies where possible.
- Evidence:
  - target workload: address=aws_lambda_function.processor; type=aws_lambda_function; vpc_id=vpc-001; subnet_ids=[subnet-private-001]; security_group_ids=[sg-app-001]
  - sensitive service dependency: service=kms; role=aws_iam_role.workload; actions=[kms:Decrypt]; resources=[*]
  - vpc endpoint coverage: vpc_id=vpc-001; service=kms; expected_endpoint_type=interface; vpc_endpoint_coverage=missing
  - policy statements: Allow actions=[s3:*, kms:Decrypt, iam:PassRole, sts:AssumeRole] resources=[*]

#### Workload uses S3 without a VPC endpoint

- STRIDE category: Information Disclosure
- Affected resources: `aws_lambda_function.processor`, `aws_iam_role.workload`
- Trust boundary: `not-applicable`
- Severity reasoning: internet_exposure +0, privilege_breadth +1, data_sensitivity +1, lateral_movement +1, blast_radius +1, final_score 4 => medium
- Rationale: aws_lambda_function.processor runs in VPC `vpc-001` and inherits S3 data-plane permissions from aws_iam_role.workload, but the Terraform plan does not show an S3 VPC endpoint for that VPC. S3 access may therefore depend on public AWS service endpoints, NAT, or another egress path; this does not imply the bucket itself is public.
- Recommended mitigation: Add an S3 gateway or interface VPC endpoint for VPC workloads that access S3, route expected private subnets through it, and use endpoint policies where possible.
- Evidence:
  - target workload: address=aws_lambda_function.processor; type=aws_lambda_function; vpc_id=vpc-001; subnet_ids=[subnet-private-001]; security_group_ids=[sg-app-001]
  - sensitive service dependency: service=s3; role=aws_iam_role.workload; actions=[s3:*]; resources=[*]
  - vpc endpoint coverage: vpc_id=vpc-001; service=s3; expected_endpoint_type=gateway_or_interface; vpc_endpoint_coverage=missing
  - policy statements: Allow actions=[s3:*, kms:Decrypt, iam:PassRole, sts:AssumeRole] resources=[*]

### Low

#### RDS database does not export engine CloudWatch logs

- STRIDE category: Repudiation
- Affected resources: `aws_db_instance.app`
- Trust boundary: `not-applicable`
- Severity reasoning: internet_exposure +0, privilege_breadth +0, data_sensitivity +1, lateral_movement +0, blast_radius +1, final_score 2 => low
- Rationale: aws_db_instance.app (engine `postgres`) does not export any of the baseline CloudWatch Logs expected for its engine family (postgresql). Without these log exports the database lacks the basic observability posture needed to investigate errors, slow queries, and audit activity from CloudWatch.
- Recommended mitigation: Enable the CloudWatch Logs exports expected for the RDS engine family (for example `postgresql` for PostgreSQL, `error` and `slowquery` for MySQL/MariaDB) so errors, slow queries, and audit activity are captured for investigation.
- Evidence:
  - target resource: address=aws_db_instance.app; type=aws_db_instance; identifier=db-001; engine=postgres
  - log export posture: enabled_cloudwatch_logs_exports=[]; expected_log_exports=['postgresql']; engine-family baseline log exports are absent

## Limitations / Unsupported Resources

- AWS support is intentionally limited to a curated v1 resource set rather than the full Terraform AWS provider.
- Subnet public/private classification prefers explicit route table associations and NAT or internet routes when present, but it does not model main-route-table inheritance or every routing edge case.
- IAM analysis resolves inline role policies, customer-managed role-policy attachments, and EC2 instance profiles present in the plan, but it does not expand AWS-managed policy documents that are not materialized in Terraform state.
- Resource-policy analysis focuses on explicit policy documents and Lambda permission resources present in the plan; it does not model every service-specific condition key or every downstream runtime authorization path.
- The engine reasons over Terraform planned values only and does not validate runtime drift, CloudTrail evidence, or post-deploy control-plane activity.
- Unsupported resource skipped: `aws_cloudwatch_log_group.processor`
