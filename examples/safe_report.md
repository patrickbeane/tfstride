# Cloud Threat Model Report

- Analyzed file: `sample_aws_safe_plan.json`
- Provider: `aws`
- Normalized resources: `26`
- Unsupported resources: `0`

## Summary

This run identified **7 trust boundaries** and **1 findings** across **26 normalized resources**.

- High severity findings: `0`
- Medium severity findings: `1`
- Low severity findings: `0`

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

### `workload-to-data-store`

- Source: `aws_lambda_function.processor`
- Target: `aws_db_instance.app`
- Description: aws_lambda_function.processor can interact with aws_db_instance.app.
- Rationale: Application or function workloads cross into a higher-sensitivity data plane when database ingress security groups explicitly trust the workload security group.

### `workload-to-data-store`

- Source: `aws_lambda_function.processor`
- Target: `aws_s3_bucket.artifacts`
- Description: aws_lambda_function.processor can interact with aws_s3_bucket.artifacts.
- Rationale: Application or function workloads cross into a higher-sensitivity data plane when their attached role allows S3 actions such as s3:GetObject.

### `admin-to-workload-plane`

- Source: `aws_iam_role.workload`
- Target: `aws_lambda_function.processor`
- Description: aws_iam_role.workload governs actions performed by aws_lambda_function.processor.
- Rationale: IAM configuration acts as a control-plane boundary because the workload inherits whatever privileges the role carries.

## Findings

### High

No findings in this severity band.

### Medium

#### IAM policy grants wildcard privileges

- STRIDE category: Elevation of Privilege
- Affected resources: `aws_iam_policy.observability`
- Trust boundary: `not-applicable`
- Severity reasoning: internet_exposure +0, privilege_breadth +2, data_sensitivity +0, lateral_movement +1, blast_radius +2, final_score 5 => medium
- Rationale: aws_iam_policy.observability contains allow statements with wildcard actions or resources. That makes the resulting access difficult to reason about and expands blast radius.
- Recommended mitigation: Replace wildcard actions and resources with narrowly scoped permissions tied to the exact services, APIs, and ARNs required by the workload.
- Evidence:
  - iam actions: logs:*
  - iam resources: *
  - policy statements: Allow actions=[logs:*] resources=[*]

### Low

No findings in this severity band.

## Controls Observed

### RDS instance is private and storage encrypted

- Category: `data-protection`
- Affected resources: `aws_db_instance.app`
- Rationale: aws_db_instance.app is kept off direct internet paths and has storage encryption enabled, which reduces straightforward data exposure risk.
- Evidence:
  - database posture: publicly_accessible is false; storage_encrypted is true; no attached security group allows internet ingress; engine is postgres

### S3 public access is reduced by a public access block

- Category: `data-protection`
- Affected resources: `aws_s3_bucket.artifacts`, `aws_s3_bucket_public_access_block.artifacts`
- Rationale: aws_s3_bucket.artifacts includes public-looking ACL or policy signals, but an attached public access block materially reduces that exposure.
- Evidence:
  - mitigated public access: bucket ACL `public-read` would otherwise grant public access; bucket policy would otherwise allow anonymous access
  - control posture: block_public_acls is true; block_public_policy is true; ignore_public_acls is true; restrict_public_buckets is true

## Limitations / Unsupported Resources

- AWS support is intentionally limited to a curated v1 resource set rather than the full Terraform AWS provider.
- Subnet public/private classification prefers explicit route table associations and NAT or internet routes when present, but it does not model main-route-table inheritance or every routing edge case.
- IAM analysis resolves inline role policies, customer-managed role-policy attachments, and EC2 instance profiles present in the plan, but it does not expand AWS-managed policy documents that are not materialized in Terraform state.
- Resource-policy analysis focuses on explicit policy documents and Lambda permission resources present in the plan; it does not model every service-specific condition key or every downstream runtime authorization path.
- The engine reasons over Terraform planned values only and does not validate runtime drift, CloudTrail evidence, or post-deploy control-plane activity.
