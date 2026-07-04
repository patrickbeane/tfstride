# tfSTRIDE Threat Model Report

- Analyzed file: `sample_aws_cross_account_trust_unconstrained_plan.json`
- Provider: `aws`
- Normalized resources: `2`
- Unsupported resources: `0`

## Summary

This run identified **2 trust boundaries** and **2 findings** across **2 normalized resources**.

- High severity findings: `0`
- Medium severity findings: `2`
- Low severity findings: `0`

## Analysis Coverage

- Terraform resources seen: `2`
- Provider resources considered: `2`
- Normalized resources: `2`
- Unsupported resources: `0`
- Registered rules: `146`
- Enabled rules: `146`
- Disabled rules: `0`
- Severity overrides: `0`
- Unresolved in-plan references: `0`
- Findings by rule:
  - `aws-role-trust-expansion`: `1`
  - `aws-role-trust-missing-narrowing`: `1`

## Discovered Trust Boundaries

### `admin-to-workload-plane`

- Source: `aws_iam_role.deployer`
- Target: `aws_lambda_function.deployer`
- Description: aws_iam_role.deployer governs actions performed by aws_lambda_function.deployer.
- Rationale: IAM configuration acts as a control-plane boundary because the workload inherits whatever privileges the role carries.

### `cross-account-or-role-access`

- Source: `arn:aws:iam::444455556666:role/github-actions-deployer`
- Target: `aws_iam_role.deployer`
- Description: aws_iam_role.deployer trusts arn:aws:iam::444455556666:role/github-actions-deployer.
- Rationale: A foreign AWS account can cross into this role's trust boundary.

## Findings

### High

No findings in this severity band.

### Medium

#### Cross-account or broad role trust lacks narrowing conditions

- STRIDE category: Elevation of Privilege
- Affected resources: `aws_iam_role.deployer`
- Trust boundary: `cross-account-or-role-access:arn:aws:iam::444455556666:role/github-actions-deployer->aws_iam_role.deployer`
- Severity reasoning: internet_exposure +0, privilege_breadth +1, data_sensitivity +0, lateral_movement +1, blast_radius +2, final_score 4 => medium
- Rationale: aws_iam_role.deployer trusts arn:aws:iam::444455556666:role/github-actions-deployer without supported narrowing conditions such as `sts:ExternalId`, `aws:SourceArn`, or `aws:SourceAccount`. That leaves the assume-role path dependent on the trusted principal match alone.
- Recommended mitigation: Keep the trusted principal as specific as possible and add supported assume-role conditions such as `ExternalId`, `SourceArn`, `SourceAccount`, `SAML:aud`, or provider-specific OIDC `aud` and `sub` checks when crossing accounts or trusting broad or federated principals.
- Evidence:
  - trust principals: arn:aws:iam::444455556666:role/github-actions-deployer
  - trust scope: principal belongs to foreign account 444455556666
  - trust narrowing: supported narrowing conditions present: false; supported narrowing condition keys: none

#### Role trust relationship expands blast radius

- STRIDE category: Elevation of Privilege
- Affected resources: `aws_iam_role.deployer`
- Trust boundary: `cross-account-or-role-access:arn:aws:iam::444455556666:role/github-actions-deployer->aws_iam_role.deployer`
- Severity reasoning: internet_exposure +0, privilege_breadth +1, data_sensitivity +0, lateral_movement +2, blast_radius +2, final_score 5 => medium
- Rationale: aws_iam_role.deployer can be assumed by arn:aws:iam::444455556666:role/github-actions-deployer. Broad or foreign-account trust relationships increase the chance that compromise in one identity domain spills into another.
- Recommended mitigation: Limit trust policies to the exact service principals or roles required, prefer role ARNs over account root where possible, and add conditions such as `ExternalId`, source ARN, SAML audience, or OIDC audience and subject checks.
- Evidence:
  - trust principals: arn:aws:iam::444455556666:role/github-actions-deployer
  - trust path: trust principal belongs to foreign account 444455556666

### Low

No findings in this severity band.

## Limitations / Unsupported Resources

- AWS support is intentionally limited to a curated v1 resource set rather than the full Terraform AWS provider.
- Subnet public/private classification prefers explicit route table associations and NAT or internet routes when present, but it does not model main-route-table inheritance or every routing edge case.
- IAM analysis resolves inline role policies, customer-managed role-policy attachments, and EC2 instance profiles present in the plan, but it does not expand AWS-managed policy documents that are not materialized in Terraform state.
- Resource-policy analysis focuses on explicit policy documents and Lambda permission resources present in the plan; it does not model every service-specific condition key or every downstream runtime authorization path.
- The engine reasons over Terraform planned values only and does not validate runtime drift, CloudTrail evidence, or post-deploy control-plane activity.
