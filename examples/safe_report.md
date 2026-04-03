# Cloud Threat Model Report

- Analyzed file: `sample_aws_safe_plan.json`
- Provider: `aws`
- Normalized resources: `16`
- Unsupported resources: `0`

## Summary

This run identified **7 trust boundaries** and **1 findings** across **16 normalized resources**.

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
- Rationale: Application or function workloads cross into a higher-sensitivity data plane when they reach databases or object storage.

### `workload-to-data-store`

- Source: `aws_lambda_function.processor`
- Target: `aws_db_instance.app`
- Description: aws_lambda_function.processor can interact with aws_db_instance.app.
- Rationale: Application or function workloads cross into a higher-sensitivity data plane when they reach databases or object storage.

### `workload-to-data-store`

- Source: `aws_lambda_function.processor`
- Target: `aws_s3_bucket.artifacts`
- Description: aws_lambda_function.processor can interact with aws_s3_bucket.artifacts.
- Rationale: Application or function workloads cross into a higher-sensitivity data plane when they reach databases or object storage.

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
- Rationale: aws_iam_policy.observability contains allow statements with wildcard actions or resources. That makes the resulting access difficult to reason about and expands blast radius.
- Recommended mitigation: Replace wildcard actions and resources with narrowly scoped permissions tied to the exact services, APIs, and ARNs required by the workload.

### Low

No findings in this severity band.

## Limitations / Unsupported Resources

- AWS support is intentionally limited to a curated v1 resource set rather than the full Terraform AWS provider.
- Subnet public/private classification uses Terraform plan attributes plus route-table heuristics and does not model every association resource.
- IAM analysis focuses on inline role policies, standalone policy documents, and trust policies; it does not yet build a full attachment graph.
- The engine reasons over Terraform planned values only and does not validate runtime drift, CloudTrail evidence, or resource-based policies beyond basic S3 checks.
