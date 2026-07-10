# tfSTRIDE Threat Model Report

- Analyzed file: `sample_aws_lambda_deploy_role_plan.json`
- Provider: `aws`
- Normalized resources: `13`
- Unsupported resources: `0`

## Summary

This run identified **4 trust boundaries** and **6 findings** across **13 normalized resources**.

- High severity findings: `0`
- Medium severity findings: `6`
- Low severity findings: `0`

## Analysis Coverage

- Terraform resources seen: `13`
- Provider resources considered: `13`
- Normalized resources: `13`
- Unsupported resources: `0`
- Registered rules: `182`
- Enabled rules: `182`
- Disabled rules: `0`
- Severity overrides: `0`
- Unresolved in-plan references: `0`
- Findings by rule:
  - `aws-workload-s3-vpc-endpoint-missing`: `1`
  - `aws-vpc-flow-logs-not-configured`: `1`
  - `aws-iam-privileged-role-assignment`: `1`
  - `aws-workload-role-sensitive-permissions`: `1`
  - `aws-role-trust-expansion`: `1`
  - `aws-role-trust-missing-narrowing`: `1`

## Discovered Trust Boundaries

### `public-subnet-to-private-subnet`

- Source: `aws_subnet.public_edge`
- Target: `aws_subnet.private_app`
- Description: Traffic can move from aws_subnet.public_edge toward aws_subnet.private_app.
- Rationale: The VPC contains both publicly routable and private network segments that should be treated as separate trust zones.

### `workload-to-data-store`

- Source: `aws_lambda_function.deployer`
- Target: `aws_s3_bucket.artifacts`
- Description: aws_lambda_function.deployer can interact with aws_s3_bucket.artifacts.
- Rationale: Application or function workloads cross into a higher-sensitivity data plane when their attached role allows S3 actions such as s3:GetObject.

### `admin-to-workload-plane`

- Source: `aws_iam_role.deployer`
- Target: `aws_lambda_function.deployer`
- Description: aws_iam_role.deployer governs actions performed by aws_lambda_function.deployer.
- Rationale: IAM configuration acts as a control-plane boundary because the workload inherits whatever privileges the role carries.

### `cross-account-or-role-access`

- Source: `arn:aws:iam::777788889999:role/ci-deployer`
- Target: `aws_iam_role.deployer`
- Description: aws_iam_role.deployer trusts arn:aws:iam::777788889999:role/ci-deployer.
- Rationale: A foreign AWS account can cross into this role's trust boundary.

## Findings

### High

No findings in this severity band.

### Medium

#### Cross-account or broad role trust lacks narrowing conditions

- STRIDE category: Elevation of Privilege
- Affected resources: `aws_iam_role.deployer`
- Trust boundary: `cross-account-or-role-access:arn:aws:iam::777788889999:role/ci-deployer->aws_iam_role.deployer`
- Severity reasoning: internet_exposure +0, privilege_breadth +1, data_sensitivity +0, lateral_movement +1, blast_radius +2, final_score 4 => medium
- Rationale: aws_iam_role.deployer trusts arn:aws:iam::777788889999:role/ci-deployer without supported narrowing conditions such as `sts:ExternalId`, `aws:SourceArn`, or `aws:SourceAccount`. That leaves the assume-role path dependent on the trusted principal match alone.
- Recommended mitigation: Keep the trusted principal as specific as possible and add supported assume-role conditions such as `ExternalId`, `SourceArn`, `SourceAccount`, `SAML:aud`, or provider-specific OIDC `aud` and `sub` checks when crossing accounts or trusting broad or federated principals.
- Evidence:
  - trust principals: arn:aws:iam::777788889999:role/ci-deployer
  - trust scope: principal belongs to foreign account 777788889999
  - trust narrowing: supported narrowing conditions present: false; supported narrowing condition keys: none

#### IAM role has privileged assignment posture

- STRIDE category: Elevation of Privilege
- Affected resources: `aws_iam_role.deployer`
- Trust boundary: `not-applicable`
- Severity reasoning: internet_exposure +0, privilege_breadth +2, data_sensitivity +0, lateral_movement +2, blast_radius +1, final_score 5 => medium
- Rationale: aws_iam_role.deployer has deterministic privileged IAM assignment posture: privilege-escalation. If this role is attached to a workload or assumable by a control-plane principal, those privileges increase blast radius.
- Recommended mitigation: Review high-impact IAM role permissions, split administrative and runtime duties, scope resources to named ARNs, and avoid attaching broad IAM, role-passing, secrets, KMS, data, network, or audit administration permissions to general workload roles.
- Evidence:
  - iam role: address=aws_iam_role.deployer; type=aws_iam_role; arn=arn:aws:iam::333344445555:role/lambda-deployer-role; identifier=lambda-deployer-role
  - privileged access: grant_1=categories=[privilege-escalation]; scope=resource; confidence=medium
  - privilege categories: privilege-escalation
  - permission patterns: iam:PassRole
  - grant scopes: scope_kind=resource; scope_value=arn:aws:iam::333344445555:role/lambda-runtime-role,arn:aws:lambda:us-east-1:333344445555:function:release-deployer,arn:aws:s3:::lambda-deploy-artifacts/*
  - grant confidence: medium
  - inline policy sources: inline_policy_name=lambda-deployer-inline

#### Role trust relationship expands blast radius

- STRIDE category: Elevation of Privilege
- Affected resources: `aws_iam_role.deployer`
- Trust boundary: `cross-account-or-role-access:arn:aws:iam::777788889999:role/ci-deployer->aws_iam_role.deployer`
- Severity reasoning: internet_exposure +0, privilege_breadth +1, data_sensitivity +0, lateral_movement +2, blast_radius +2, final_score 5 => medium
- Rationale: aws_iam_role.deployer can be assumed by arn:aws:iam::777788889999:role/ci-deployer. Broad or foreign-account trust relationships increase the chance that compromise in one identity domain spills into another.
- Recommended mitigation: Limit trust policies to the exact service principals or roles required, prefer role ARNs over account root where possible, and add conditions such as `ExternalId`, source ARN, SAML audience, or OIDC audience and subject checks.
- Evidence:
  - trust principals: arn:aws:iam::777788889999:role/ci-deployer
  - trust path: trust principal belongs to foreign account 777788889999

#### VPC Flow Logs are not configured for a modeled VPC

- STRIDE category: Repudiation
- Affected resources: `aws_vpc.main`
- Trust boundary: `not-applicable`
- Severity reasoning: internet_exposure +0, privilege_breadth +0, data_sensitivity +0, lateral_movement +1, blast_radius +2, final_score 3 => medium
- Rationale: aws_vpc.main does not have a resolved aws_flow_log targeting the VPC in this Terraform plan. Network traffic metadata for incident response, threat hunting, and segmentation review may be unavailable unless Flow Logs are configured elsewhere.
- Recommended mitigation: Enable VPC Flow Logs for production VPCs, route them to a retained CloudWatch Logs, S3, or Firehose destination, and manage Flow Log resources in Terraform so network telemetry posture is reviewable.
- Evidence:
  - target vpc: address=aws_vpc.main; type=aws_vpc; identifier=vpc-lambda-001; cidr_block=10.30.0.0/16
  - flow log coverage: target_vpc_id=vpc-lambda-001; resolved_vpc_flow_log_count=0; aws_flow_log resources are not modeled

#### Workload role carries sensitive permissions

- STRIDE category: Elevation of Privilege
- Affected resources: `aws_lambda_function.deployer`, `aws_iam_role.deployer`
- Trust boundary: `admin-to-workload-plane:aws_iam_role.deployer->aws_lambda_function.deployer`
- Severity reasoning: internet_exposure +0, privilege_breadth +1, data_sensitivity +1, lateral_movement +1, blast_radius +2, final_score 5 => medium
- Rationale: aws_lambda_function.deployer inherits sensitive privileges from aws_iam_role.deployer, including iam:PassRole. If the workload is compromised, those credentials can be reused for privilege escalation, data access, or role chaining.
- Recommended mitigation: Split high-privilege actions into separate roles, scope permissions to named resources, and remove role-passing or cross-role permissions from general application identities.
- Evidence:
  - iam actions: iam:PassRole
  - policy statements: Allow actions=[lambda:UpdateFunctionCode, lambda:UpdateAlias, iam:PassRole, s3:GetObject] resources=[arn:aws:lambda:us-east-1:333344445555:function:release-deployer, arn:aws:iam::333344445555:role/lambda-runtime-role, arn:aws:s3:::lambda-deploy-artifacts/*]

#### Workload uses S3 without a VPC endpoint

- STRIDE category: Information Disclosure
- Affected resources: `aws_lambda_function.deployer`, `aws_iam_role.deployer`
- Trust boundary: `not-applicable`
- Severity reasoning: internet_exposure +0, privilege_breadth +1, data_sensitivity +1, lateral_movement +1, blast_radius +1, final_score 4 => medium
- Rationale: aws_lambda_function.deployer runs in VPC `vpc-lambda-001` and inherits S3 data-plane permissions from aws_iam_role.deployer, but the Terraform plan does not show an S3 VPC endpoint for that VPC. S3 access may therefore depend on public AWS service endpoints, NAT, or another egress path; this does not imply the bucket itself is public.
- Recommended mitigation: Add an S3 gateway or interface VPC endpoint for VPC workloads that access S3, route expected private subnets through it, and use endpoint policies where possible.
- Evidence:
  - target workload: address=aws_lambda_function.deployer; type=aws_lambda_function; vpc_id=vpc-lambda-001; subnet_ids=[subnet-lambda-private-app-001]; security_group_ids=[sg-lambda-app-001]
  - sensitive service dependency: service=s3; role=aws_iam_role.deployer; actions=[s3:GetObject]; resources=[arn:aws:lambda:us-east-1:333344445555:function:release-deployer, arn:aws:iam::333344445555:role/lambda-runtime-role, arn:aws:s3:::lambda-deploy-artifacts/*]
  - vpc endpoint coverage: vpc_id=vpc-lambda-001; service=s3; expected_endpoint_type=gateway_or_interface; vpc_endpoint_coverage=missing
  - policy statements: Allow actions=[lambda:UpdateFunctionCode, lambda:UpdateAlias, iam:PassRole, s3:GetObject] resources=[arn:aws:lambda:us-east-1:333344445555:function:release-deployer, arn:aws:iam::333344445555:role/lambda-runtime-role, arn:aws:s3:::lambda-deploy-artifacts/*]

### Low

No findings in this severity band.

## Limitations / Unsupported Resources

- AWS support is intentionally limited to a curated v1 resource set rather than the full Terraform AWS provider.
- Subnet public/private classification prefers explicit route table associations and NAT or internet routes when present, but it does not model main-route-table inheritance or every routing edge case.
- IAM analysis resolves inline role policies, customer-managed role-policy attachments, and EC2 instance profiles present in the plan, but it does not expand AWS-managed policy documents that are not materialized in Terraform state.
- Resource-policy analysis focuses on explicit policy documents and Lambda permission resources present in the plan; it does not model every service-specific condition key or every downstream runtime authorization path.
- The engine reasons over Terraform planned values only and does not validate runtime drift, CloudTrail evidence, or post-deploy control-plane activity.
