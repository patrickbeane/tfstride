# tfSTRIDE Threat Model Report

- Analyzed file: `sample_gcp_safe_plan.json`
- Provider: `gcp`
- Normalized resources: `9`
- Unsupported resources: `0`

## Summary

This run identified **1 trust boundary** and **0 findings** across **9 normalized resources**.

- High severity findings: `0`
- Medium severity findings: `0`
- Low severity findings: `0`

## Analysis Coverage

- Terraform resources seen: `9`
- Provider resources considered: `9`
- Normalized resources: `9`
- Unsupported resources: `0`
- Resources with plan-time unknown values: `0`
- Registered provider rules (GCP): `97`
- Enabled provider rules (GCP): `97`
- Disabled rules: `0`
- Severity overrides: `0`
- Configuration-reference resolution: `0 symbolic`, `0 ambiguous`, `0 unresolved`, `0 unsupported`
- Recorded unresolved modeled references: `0`

Sensitive resource labels are assumptions based on resource class. tfSTRIDE does not assess stored data contents from the plan.

## Discovered Trust Boundaries

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

- GCP support covers a curated set of compute, serverless, data, IAM, Kubernetes, networking, audit, private-connectivity, messaging, registry, and key-management resources. Analysis is plan-local and does not model every provider resource, runtime drift, or every organization-level control; provider-specific positive observations remain more limited than finding coverage.
- The engine reasons over Terraform planned values only and does not validate runtime drift, runtime audit evidence, or post-deployment control-plane activity.
