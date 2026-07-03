# tfSTRIDE Threat Model Report

- Analyzed file: `sample_aws_cross_account_trust_constrained_plan.json`
- Provider: `aws`
- Normalized resources: `2`
- Unsupported resources: `0`

## Summary

This run identified **2 trust boundaries** and **0 findings** across **2 normalized resources**.

- High severity findings: `0`
- Medium severity findings: `0`
- Low severity findings: `0`

## Analysis Coverage

- Terraform resources seen: `2`
- Provider resources considered: `2`
- Normalized resources: `2`
- Unsupported resources: `0`
- Registered rules: `131`
- Enabled rules: `131`
- Disabled rules: `0`
- Severity overrides: `0`
- Unresolved in-plan references: `0`

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

No findings in this severity band.

### Low

No findings in this severity band.

## Controls Observed

### Cross-account or broad role trust is narrowed by assume-role conditions

- Category: `iam`
- Affected resources: `aws_iam_role.deployer`
- Rationale: aws_iam_role.deployer trusts arn:aws:iam::444455556666:role/github-actions-deployer, but supported assume-role conditions narrow when that trust can be exercised.
- Evidence:
  - trust principals: arn:aws:iam::444455556666:role/github-actions-deployer
  - trust scope: principal belongs to foreign account 444455556666
  - trust narrowing: supported narrowing conditions present: true; supported narrowing condition keys: aws:SourceAccount, aws:SourceArn, sts:ExternalId

## Limitations / Unsupported Resources

- AWS support is intentionally limited to a curated v1 resource set rather than the full Terraform AWS provider.
- Subnet public/private classification prefers explicit route table associations and NAT or internet routes when present, but it does not model main-route-table inheritance or every routing edge case.
- IAM analysis resolves inline role policies, customer-managed role-policy attachments, and EC2 instance profiles present in the plan, but it does not expand AWS-managed policy documents that are not materialized in Terraform state.
- Resource-policy analysis focuses on explicit policy documents and Lambda permission resources present in the plan; it does not model every service-specific condition key or every downstream runtime authorization path.
- The engine reasons over Terraform planned values only and does not validate runtime drift, CloudTrail evidence, or post-deploy control-plane activity.
