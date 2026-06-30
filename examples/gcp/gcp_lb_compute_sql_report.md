# tfSTRIDE Threat Model Report

- Analyzed file: `sample_gcp_lb_compute_sql_plan.json`
- Provider: `gcp`
- Normalized resources: `10`
- Unsupported resources: `0`

## Summary

This run identified **2 trust boundaries** and **0 findings** across **10 normalized resources**.

- High severity findings: `0`
- Medium severity findings: `0`
- Low severity findings: `0`

## Analysis Coverage

- Terraform resources seen: `10`
- Provider resources considered: `10`
- Normalized resources: `10`
- Unsupported resources: `0`
- Registered rules: `117`
- Enabled rules: `117`
- Disabled rules: `0`
- Severity overrides: `0`
- Unresolved in-plan references: `0`

## Discovered Trust Boundaries

### `internet-to-service`

- Source: `internet`
- Target: `google_compute_forwarding_rule.web`
- Description: Traffic can cross from the public internet to google_compute_forwarding_rule.web.
- Rationale: The resource is directly reachable or intentionally exposed to unauthenticated network clients.

### `workload-to-data-store`

- Source: `google_compute_instance.web`
- Target: `google_sql_database_instance.app`
- Description: google_compute_instance.web can interact with google_sql_database_instance.app.
- Rationale: Application or function workloads cross into a higher-sensitivity data plane when they share a VPC with the database and the plan does not provide tighter security-group evidence.

## Findings

### High

No findings in this severity band.

### Medium

No findings in this severity band.

### Low

No findings in this severity band.

## Limitations / Unsupported Resources

- GCP support currently provides initial inventory normalization, internet-to-service, route/NAT posture, and workload-to-sensitive-data trust-boundary detection for compute and serverless workloads, with limited GCP STRIDE rule coverage for compute, GCS posture, Cloud SQL posture, Secret Manager, Cloud KMS, and project IAM only; GCP control coverage is not implemented yet.
- The engine reasons over Terraform planned values only and does not validate runtime drift, CloudTrail evidence, or post-deploy control-plane activity.
