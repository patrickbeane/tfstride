# Cloud Threat Model Report

- Analyzed file: `sample_aws_alb_ec2_rds_plan.json`
- Provider: `aws`
- Normalized resources: `19`
- Unsupported resources: `0`

## Summary

This run identified **4 trust boundaries** and **0 findings** across **19 normalized resources**.

- High severity findings: `0`
- Medium severity findings: `0`
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

## Findings

### High

No findings in this severity band.

### Medium

No findings in this severity band.

### Low

No findings in this severity band.

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
