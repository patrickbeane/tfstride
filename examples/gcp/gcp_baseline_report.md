# tfSTRIDE Threat Model Report

- Analyzed file: `sample_gcp_baseline_plan.json`
- Provider: `gcp`
- Normalized resources: `9`
- Unsupported resources: `0`

## Summary

This run identified **1 trust boundaries** and **5 findings** across **9 normalized resources**.

- High severity findings: `2`
- Medium severity findings: `3`
- Low severity findings: `0`

## Analysis Coverage

- Terraform resources seen: `9`
- Provider resources considered: `9`
- Normalized resources: `9`
- Unsupported resources: `0`
- Registered rules: `236`
- Enabled rules: `236`
- Disabled rules: `0`
- Severity overrides: `0`
- Unresolved in-plan references: `0`
- Findings by rule:
  - `gcp-cloud-sql-point-in-time-recovery-disabled`: `1`
  - `gcp-cloud-sql-zonal-availability`: `1`
  - `gcp-subnetwork-flow-logs-not-configured`: `1`
  - `gcp-project-iam-privileged-role`: `1`
  - `gcp-inherited-iam-blast-radius`: `1`

## Discovered Trust Boundaries

### `workload-to-data-store`

- Source: `google_compute_instance.web`
- Target: `google_sql_database_instance.app`
- Description: google_compute_instance.web can interact with google_sql_database_instance.app.
- Rationale: Application or function workloads cross into a higher-sensitivity data plane when they share a VPC with the database and the plan does not provide tighter security-group evidence.

## Findings

### High

#### GCP project IAM binding grants a high-privilege role

- STRIDE category: Elevation of Privilege
- Affected resources: `google_project_iam_member.deploy_admin`
- Trust boundary: `not-applicable`
- Severity reasoning: internet_exposure +0, privilege_breadth +2, data_sensitivity +0, lateral_movement +2, blast_radius +2, final_score 6 => high
- Rationale: google_project_iam_member.deploy_admin grants the high-impact GCP role `projects/tfstride-demo/roles/deployAdmin` to `group:deploy@example.com` at project scope. That role enables custom role includes high-impact permissions: iam.serviceAccounts.actAs and can materially expand control-plane blast radius if the principal is compromised or mis-scoped.
- Recommended mitigation: Replace Owner, Editor, IAM admin, service-account impersonation, and admin-class project roles with narrowly scoped predefined or custom roles assigned to specific groups or service accounts.
- Evidence:
  - iam binding: member=group:deploy@example.com; role=projects/tfstride-demo/roles/deployAdmin
  - role risk: custom role includes high-impact permissions: iam.serviceAccounts.actAs
  - custom role permissions: iam.serviceAccounts.actAs

#### Inherited GCP IAM grant expands descendant blast radius

- STRIDE category: Elevation of Privilege
- Affected resources: `google_project_iam_member.deploy_admin`, `google_compute_instance.web`, `google_compute_network.main`, `google_compute_subnetwork.app`, `google_project_iam_custom_role.deploy_admin`, `google_service_account.web`, `google_sql_database_instance.app`, `google_storage_bucket.logs`
- Trust boundary: `not-applicable`
- Severity reasoning: internet_exposure +0, privilege_breadth +2, data_sensitivity +2, lateral_movement +2, blast_radius +2, final_score 8 => high
- Rationale: google_project_iam_member.deploy_admin grants `projects/tfstride-demo/roles/deployAdmin` to `group:deploy@example.com` at project scope `tfstride-demo`, and that inherited grant applies to 7 concrete descendant resource(s). A high-level IAM grant with broad, external, or high-impact access increases control-plane blast radius because compromise or misuse can affect resources below the inherited scope.
- Recommended mitigation: Avoid broad or high-impact IAM grants at organization, folder, and project scope when narrower resource-level or workload-specific bindings are possible; split inherited roles by service and review descendant resources before assigning public, external, or administrator principals.
- Evidence:
  - iam binding: source=google_project_iam_member.deploy_admin; scope=project:tfstride-demo; member=group:deploy@example.com; role=projects/tfstride-demo/roles/deployAdmin
  - role risk: custom role includes high-impact permissions: iam.serviceAccounts.actAs
  - descendant scope: scope=project:tfstride-demo; descendant_count=7; resource_type_count=7; projects=tfstride-demo
  - descendant resource types: google_compute_instance: 1; google_compute_network: 1; google_compute_subnetwork: 1; google_project_iam_custom_role: 1; google_service_account: 1; google_sql_database_instance: 1; google_storage_bucket: 1
  - descendant resources: google_compute_instance.web; google_compute_network.main; google_compute_subnetwork.app; google_project_iam_custom_role.deploy_admin; google_service_account.web; google_sql_database_instance.app; google_storage_bucket.logs
  - custom role permissions: iam.serviceAccounts.actAs

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

#### Cloud SQL point-in-time recovery is disabled

- STRIDE category: Denial of Service
- Affected resources: `google_sql_database_instance.app`
- Trust boundary: `not-applicable`
- Severity reasoning: internet_exposure +0, privilege_breadth +0, data_sensitivity +2, lateral_movement +0, blast_radius +1, final_score 3 => medium
- Rationale: google_sql_database_instance.app has automated backups enabled but point-in-time recovery disabled. That narrows recovery options after accidental writes, destructive migrations, or credential misuse.
- Recommended mitigation: Enable point-in-time recovery for Cloud SQL engines that support it, tune retention to recovery objectives, and test restore workflows for destructive-write scenarios.
- Evidence:
  - backup posture: backup_configuration.enabled is true; point_in_time_recovery_enabled is false; engine is POSTGRES_15

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
