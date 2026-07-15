# tfSTRIDE Threat Model Report

- Analyzed file: `sample_gcp_lb_compute_sql_plan.json`
- Provider: `gcp`
- Normalized resources: `11`
- Unsupported resources: `0`

## Summary

This run identified **2 trust boundaries** and **2 findings** across **11 normalized resources**.

- High severity findings: `0`
- Medium severity findings: `2`
- Low severity findings: `0`

## Analysis Coverage

- Terraform resources seen: `11`
- Provider resources considered: `11`
- Normalized resources: `11`
- Unsupported resources: `0`
- Registered rules: `231`
- Enabled rules: `231`
- Disabled rules: `0`
- Severity overrides: `0`
- Unresolved in-plan references: `0`
- Findings by rule:
  - `gcp-cloud-sql-zonal-availability`: `1`
  - `gcp-subnetwork-flow-logs-not-configured`: `1`

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

#### Cloud SQL instance uses zonal availability

- STRIDE category: Denial of Service
- Affected resources: `google_sql_database_instance.app`
- Trust boundary: `not-applicable`
- Severity reasoning: internet_exposure +0, privilege_breadth +0, data_sensitivity +2, lateral_movement +0, blast_radius +1, final_score 3 => medium
- Rationale: google_sql_database_instance.app uses zonal Cloud SQL availability. A zonal failure or maintenance disruption can leave the database unavailable longer than a regional high-availability deployment.
- Recommended mitigation: Use `REGIONAL` availability for production Cloud SQL instances that require higher availability, then validate application failover behavior and recovery objectives.
- Evidence:
  - availability posture: availability_type=ZONAL; engine=POSTGRES_15

#### GCP subnetwork Flow Logs are not configured

- STRIDE category: Repudiation
- Affected resources: `google_compute_subnetwork.app`
- Trust boundary: `not-applicable`
- Severity reasoning: internet_exposure +0, privilege_breadth +0, data_sensitivity +0, lateral_movement +2, blast_radius +1, final_score 3 => medium
- Rationale: google_compute_subnetwork.app does not configure VPC Flow Logs in this Terraform plan. Without subnetwork flow telemetry, network investigation, lateral-movement review, and egress analysis can lack packet-flow evidence for workloads attached to this subnet.
- Recommended mitigation: Enable VPC Flow Logs on subnetworks that host workloads, keep the flow log configuration in Terraform, and export or retain those logs according to investigation and monitoring requirements.
- Evidence:
  - subnetwork flow log posture: address=google_compute_subnetwork.app; type=google_compute_subnetwork; name=app; identifier=tfstride-app; flow_log_state=not_configured; network=google_compute_network.main.id; project=tfstride-demo

### Low

No findings in this severity band.

## Limitations / Unsupported Resources

- GCP support currently provides initial inventory normalization, internet-to-service, route/NAT posture, and workload-to-sensitive-data trust-boundary detection for compute and serverless workloads, with limited GCP STRIDE rule coverage for compute, GCS posture, Cloud SQL posture, Secret Manager, Cloud KMS, and project IAM only; GCP control coverage is not implemented yet.
- The engine reasons over Terraform planned values only and does not validate runtime drift, CloudTrail evidence, or post-deploy control-plane activity.
