# tfSTRIDE Threat Model Report

- Analyzed file: `sample_aws_lambda_deploy_role_plan.json`
- Provider: `aws`
- Normalized resources: `13`
- Unsupported resources: `0`

## Summary

This run identified **4 trust boundaries** and **3 findings** across **13 normalized resources**.

- High severity findings: `0`
- Medium severity findings: `3`
- Low severity findings: `0`

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
- Rationale: aws_iam_role.deployer trusts arn:aws:iam::777788889999:role/ci-deployer without supported narrowing conditions such as `sts:ExternalId`, `aws:SourceArn`, or `aws:SourceAccount`. That leaves the assume-role path dependent on a broad or external principal match alone.
- Recommended mitigation: Keep the trusted principal as specific as possible and add supported assume-role conditions such as `ExternalId`, `SourceArn`, or `SourceAccount` when crossing accounts or trusting broad principals.
- Evidence:
  - trust principals: arn:aws:iam::777788889999:role/ci-deployer
  - trust scope: principal belongs to foreign account 777788889999
  - trust narrowing: supported narrowing conditions present: false; supported narrowing condition keys: none

#### Role trust relationship expands blast radius

- STRIDE category: Elevation of Privilege
- Affected resources: `aws_iam_role.deployer`
- Trust boundary: `cross-account-or-role-access:arn:aws:iam::777788889999:role/ci-deployer->aws_iam_role.deployer`
- Severity reasoning: internet_exposure +0, privilege_breadth +1, data_sensitivity +0, lateral_movement +2, blast_radius +2, final_score 5 => medium
- Rationale: aws_iam_role.deployer can be assumed by arn:aws:iam::777788889999:role/ci-deployer. Broad or foreign-account trust relationships increase the chance that compromise in one identity domain spills into another.
- Recommended mitigation: Limit trust policies to the exact service principals or roles required, prefer role ARNs over account root where possible, and add conditions such as `ExternalId` or source ARN checks.
- Evidence:
  - trust principals: arn:aws:iam::777788889999:role/ci-deployer
  - trust path: trust principal belongs to foreign account 777788889999

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

### Low

No findings in this severity band.

## Limitations / Unsupported Resources

- AWS support is intentionally limited to a curated v1 resource set rather than the full Terraform AWS provider.
- Subnet public/private classification prefers explicit route table associations and NAT or internet routes when present, but it does not model main-route-table inheritance or every routing edge case.
- IAM analysis resolves inline role policies, customer-managed role-policy attachments, and EC2 instance profiles present in the plan, but it does not expand AWS-managed policy documents that are not materialized in Terraform state.
- Resource-policy analysis focuses on explicit policy documents and Lambda permission resources present in the plan; it does not model every service-specific condition key or every downstream runtime authorization path.
- The engine reasons over Terraform planned values only and does not validate runtime drift, CloudTrail evidence, or post-deploy control-plane activity.
