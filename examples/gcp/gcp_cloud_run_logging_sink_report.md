# tfSTRIDE Threat Model Report

- Analyzed file: `sample_gcp_cloud_run_logging_sink_plan.json`
- Provider: `gcp`
- Normalized resources: `6`
- Unsupported resources: `0`

## Summary

This run identified **1 trust boundary** and **5 findings** across **6 normalized resources**.

- High severity findings: `2`
- Medium severity findings: `3`
- Low severity findings: `0`

## Analysis Coverage

- Terraform resources seen: `6`
- Provider resources considered: `6`
- Normalized resources: `6`
- Unsupported resources: `0`
- Resources with plan-time unknown values: `0`
- Registered provider rules (GCP): `97`
- Enabled provider rules (GCP): `97`
- Disabled rules: `0`
- Severity overrides: `0`
- Configuration-reference resolution: `0 symbolic`, `0 ambiguous`, `0 unresolved`, `0 unsupported`
- Recorded unresolved modeled references: `0`
- Findings by rule:
  - `gcp-logging-sink-audit-export-incomplete`: `1`
  - `gcp-cloud-run-public-invoker`: `1`
  - `gcp-public-cloud-run-logging-sink-disruption`: `1`
  - `gcp-project-iam-privileged-role`: `1`
  - `gcp-inherited-iam-blast-radius`: `1`

Sensitive resource labels are assumptions based on resource class. tfSTRIDE does not assess stored data contents from the plan.

## Discovered Trust Boundaries

### `internet-to-service`

- Source: `internet`
- Target: `google_cloud_run_v2_service.api`
- Description: Traffic can cross from the public internet to google_cloud_run_v2_service.api.
- Rationale: The resource is directly reachable or intentionally exposed to unauthenticated network clients.

## Findings

### High

#### GCP project IAM binding grants a high-privilege role

- STRIDE category: Elevation of Privilege
- Affected resources: `google_project_iam_member.run_logging_admin`
- Trust boundary: `not-applicable`
- Severity reasoning: internet_exposure +0, privilege_breadth +2, data_sensitivity +0, lateral_movement +2, blast_radius +2, final_score 6 => high
- Rationale: google_project_iam_member.run_logging_admin grants the high-impact GCP role `roles/logging.admin` to `serviceAccount:tfstride-run@tfstride-demo.iam.gserviceaccount.com` at project scope. That role enables admin-level control over a GCP service or project security surface and can materially expand control-plane blast radius if the principal is compromised or mis-scoped.
- Recommended mitigation: Replace Owner, Editor, IAM admin, service-account impersonation, and admin-class project roles with narrowly scoped predefined or custom roles assigned to specific groups or service accounts.
- Evidence:
  - iam binding: member=serviceAccount:tfstride-run@tfstride-demo.iam.gserviceaccount.com; role=roles/logging.admin
  - role risk: admin-level control over a GCP service or project security surface

#### Public Cloud Run identity can disrupt audit telemetry export

- STRIDE category: Repudiation
- Affected resources: `google_cloud_run_v2_service.api`, `google_cloud_run_v2_service_iam_member.public_invoker`, `google_logging_project_sink.audit`, `google_logging_project_sink.errors`, `google_project_iam_member.run_logging_admin`
- Trust boundary: `internet-to-service:internet->google_cloud_run_v2_service.api`
- Severity reasoning: internet_exposure +2, privilege_breadth +2, data_sensitivity +2, lateral_movement +1, blast_radius +2, final_score 9 => high
- Rationale: google_cloud_run_v2_service.api is publicly invokable and its Cloud Run runtime service account has current deterministic logging.sinks.delete authority over 2 exact active project logging sinks that export modeled audit/security telemetry to storage.googleapis.com/tfstride-audit-archive. A compromise of the public workload could request deletion of those modeled sink targets, disrupting future export or recording of the modeled audit/security telemetry and weakening auditability/accountability. This plan-local evidence does not establish a successful API call, sink deletion, deletion of retained source logs or logs already delivered to the destination, deletion of the destination resource, disruption of every project or out-of-plan sink, historical audit-log erasure, or recovery/restoration.
- Recommended mitigation: Restrict public invocation of the Cloud Run service and grant its runtime service account only the exact logging.sinks.delete permission and project logging-sink scope required. Keep audit sink administration on separate operational identities, and protect audit/security export paths from public workload credentials.
- Evidence:
  - public invoker bindings: source=google_cloud_run_v2_service_iam_member.public_invoker; role=roles/run.invoker; member=allUsers; condition=none
  - public exposure reasons: google_cloud_run_v2_service_iam_member.public_invoker grants roles/run.invoker to allUsers
  - runtime identity: service_account=tfstride-run@tfstride-demo.iam.gserviceaccount.com; member=serviceAccount:tfstride-run@tfstride-demo.iam.gserviceaccount.com; role=roles/logging.admin; identity_kind=cloud_run_service_account; credential_context=workload_runtime
  - logging sink audit telemetry disruption paths: sink_address=google_logging_project_sink.audit; sink_resource_name=projects/tfstride-demo/sinks/audit-export; sink_project=tfstride-demo; destination=storage.googleapis.com/tfstride-audit-archive; operation=logging.sinks.delete; operation_class=project_sink_deletion; target_granularity=project_logging_sink; target_scope=exact_project_logging_sink; scope_type=project; scope=tfstride-demo; resource_scope=logging_project; iam_resource=google_project_iam_member.run_logging_admin; iam_sources=google_project_iam_member.run_logging_admin; role=roles/logging.admin; role_kind=logging_admin; custom_role_permissions=none; matched_permissions=logging.sinks.delete; authorization_state=granted; operation_evaluation=deterministic_allowed; sink_address=google_logging_project_sink.errors; sink_resource_name=projects/tfstride-demo/sinks/error-export; sink_project=tfstride-demo; destination=storage.googleapis.com/tfstride-audit-archive; operation=logging.sinks.delete; operation_class=project_sink_deletion; target_granularity=project_logging_sink; target_scope=exact_project_logging_sink; scope_type=project; scope=tfstride-demo; resource_scope=logging_project; iam_resource=google_project_iam_member.run_logging_admin; iam_sources=google_project_iam_member.run_logging_admin; role=roles/logging.admin; role_kind=logging_admin; custom_role_permissions=none; matched_permissions=logging.sinks.delete; authorization_state=granted; operation_evaluation=deterministic_allowed
  - logging sink lifecycle evidence: sink_address=google_logging_project_sink.audit; sink_lifecycle_state=active; sink_disabled=false; disabled_configuration_state=configured; provider_default_applied=false; lifecycle_compatibility_state=compatible; uncertainties=none; sink_address=google_logging_project_sink.errors; sink_lifecycle_state=active; sink_disabled=false; disabled_configuration_state=configured; provider_default_applied=false; lifecycle_compatibility_state=compatible; uncertainties=none
  - logging sink deletion constraint evidence: sink_address=google_logging_project_sink.audit; sink_kind=user_managed; system_sink_name=unknown; api_deletion_supported=true; deletion_compatibility_state=compatible; uncertainties=none; sink_address=google_logging_project_sink.errors; sink_kind=user_managed; system_sink_name=unknown; api_deletion_supported=true; deletion_compatibility_state=compatible; uncertainties=none
  - logging sink audit telemetry relevance evidence: sink_address=google_logging_project_sink.audit; filter_state=configured; sink_filter=(logName="projects/tfstride-demo/logs/cloudaudit.googleapis.com%2Factivity" OR logName="projects/tfstride-demo/logs/cloudaudit.googleapis.com%2Fdata_access"); relevance_basis=audit_security_filter; matched_signals=cloudaudit.googleapis.com; audit_telemetry_relevance_state=established; uncertainties=none; sink_address=google_logging_project_sink.errors; filter_state=configured; sink_filter=logName:"cloudaudit.googleapis.com" AND severity>=ERROR; relevance_basis=narrowed_audit_security_filter; matched_signals=cloudaudit.googleapis.com; audit_telemetry_relevance_state=established; uncertainties=none
  - logging sink outcome evidence: sink_address=google_logging_project_sink.audit; successful_operation_observed=false; historical_log_entry_deletion_observed=false; destination_resource_deletion_observed=false; all_project_audit_sinks_evaluated=false; out_of_plan_sinks_evaluated=false; telemetry_recovery_state=not_established_by_modeled_gcp_logging_sink_evidence; restoration_observed=false; sink_address=google_logging_project_sink.errors; successful_operation_observed=false; historical_log_entry_deletion_observed=false; destination_resource_deletion_observed=false; all_project_audit_sinks_evaluated=false; out_of_plan_sinks_evaluated=false; telemetry_recovery_state=not_established_by_modeled_gcp_logging_sink_evidence; restoration_observed=false
  - assessment scope: establishes=Repudiation risk from deterministic logging.sinks.delete authority over exact active project logging sinks that export modeled audit/security telemetry; effect=compromise of the public workload could disrupt future export or recording of the modeled audit/security telemetry to the modeled destination, weakening auditability/accountability; does_not_establish=successful API operation, sink deletion, retained or delivered log deletion, destination deletion, disruption of every or out-of-plan sink, historical audit-log erasure, or recovery/restoration

### Medium

#### Cloud Run service is publicly invokable

- STRIDE category: Spoofing
- Affected resources: `google_cloud_run_v2_service.api`, `google_cloud_run_v2_service_iam_member.public_invoker`
- Trust boundary: `internet-to-service:internet->google_cloud_run_v2_service.api`
- Severity reasoning: internet_exposure +2, privilege_breadth +0, data_sensitivity +0, lateral_movement +0, blast_radius +1, final_score 3 => medium
- Rationale: google_cloud_run_v2_service.api allows public ingress and grants Cloud Run invoke permission to public GCP principals. Unauthenticated internet clients can reach the service entry point without an organization-owned identity boundary.
- Recommended mitigation: Remove `allUsers` and `allAuthenticatedUsers` from Cloud Run invoker bindings unless anonymous access is intentional, and front public services with authentication, IAP, API Gateway, or a controlled edge policy.
- Evidence:
  - public invoker bindings: source=google_cloud_run_v2_service_iam_member.public_invoker; role=roles/run.invoker; member=allUsers
  - public access reasons: google_cloud_run_v2_service_iam_member.public_invoker grants roles/run.invoker to allUsers
  - public exposure reasons: google_cloud_run_v2_service_iam_member.public_invoker grants roles/run.invoker to allUsers

#### Inherited GCP IAM grant expands descendant blast radius

- STRIDE category: Elevation of Privilege
- Affected resources: `google_project_iam_member.run_logging_admin`, `google_cloud_run_v2_service.api`, `google_logging_project_sink.audit`, `google_logging_project_sink.errors`, `google_logging_project_sink.negated`
- Trust boundary: `not-applicable`
- Severity reasoning: internet_exposure +0, privilege_breadth +2, data_sensitivity +0, lateral_movement +2, blast_radius +1, final_score 5 => medium
- Rationale: google_project_iam_member.run_logging_admin grants `roles/logging.admin` to `serviceAccount:tfstride-run@tfstride-demo.iam.gserviceaccount.com` at project scope `tfstride-demo`, and that inherited grant applies to 4 concrete descendant resource(s). A high-level IAM grant with broad, external, or high-impact access increases control-plane blast radius because compromise or misuse can affect resources below the inherited scope.
- Recommended mitigation: Avoid broad or high-impact IAM grants at organization, folder, and project scope when narrower resource-level or workload-specific bindings are possible; split inherited roles by service and review descendant resources before assigning public, external, or administrator principals.
- Evidence:
  - iam binding: source=google_project_iam_member.run_logging_admin; scope=project:tfstride-demo; member=serviceAccount:tfstride-run@tfstride-demo.iam.gserviceaccount.com; role=roles/logging.admin
  - role risk: admin-level control over a GCP service or project security surface
  - descendant scope: scope=project:tfstride-demo; descendant_count=4; resource_type_count=2; projects=tfstride-demo
  - descendant resource types: google_cloud_run_v2_service: 1; google_logging_project_sink: 3
  - descendant resources: google_cloud_run_v2_service.api; google_logging_project_sink.audit; google_logging_project_sink.errors; google_logging_project_sink.negated

#### Logging sink audit export is incomplete

- STRIDE category: Repudiation
- Affected resources: `google_logging_project_sink.negated`
- Trust boundary: `not-applicable`
- Severity reasoning: internet_exposure +0, privilege_breadth +0, data_sensitivity +1, lateral_movement +1, blast_radius +1, final_score 3 => medium
- Rationale: google_logging_project_sink.negated does not clearly export audit or security logs to a retained destination. A modeled sink without a deterministic destination or with a narrow filter can leave investigation and alerting coverage incomplete.
- Recommended mitigation: Configure logging sinks with deterministic retained destinations and filters that include Cloud Audit Logs or other security-relevant streams. Leave the filter unset when the sink should export all logs from its scope.
- Evidence:
  - logging sink: address=google_logging_project_sink.negated; type=google_logging_project_sink; name=app-export; identifier=projects/tfstride-demo/sinks/app-export; destination=storage.googleapis.com/tfstride-app-logs; filter=NOT logName:"cloudaudit.googleapis.com"; scope_type=project; scope=tfstride-demo; writer_identity=serviceAccount:logging-tfstride-demo@gcp-sa-logging.iam.gserviceaccount.com; unique_writer_identity=true
  - audit export posture: filter excludes audit or security log streams

### Low

No findings in this severity band.

## Limitations / Unsupported Resources

- GCP support covers a curated set of compute, serverless, data, IAM, Kubernetes, networking, audit, private-connectivity, messaging, registry, and key-management resources. Analysis is plan-local and does not model every provider resource, runtime drift, or every organization-level control; provider-specific positive observations remain more limited than finding coverage.
- The engine reasons over Terraform planned values only and does not validate runtime drift, runtime audit evidence, or post-deployment control-plane activity.
