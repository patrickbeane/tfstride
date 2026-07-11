# tfSTRIDE Threat Model Report

- Analyzed file: `sample_gcp_serverless_plan.json`
- Provider: `gcp`
- Normalized resources: `11`
- Unsupported resources: `0`

## Summary

This run identified **4 trust boundaries** and **5 findings** across **11 normalized resources**.

- High severity findings: `2`
- Medium severity findings: `3`
- Low severity findings: `0`

## Analysis Coverage

- Terraform resources seen: `11`
- Provider resources considered: `11`
- Normalized resources: `11`
- Unsupported resources: `0`
- Registered rules: `187`
- Enabled rules: `187`
- Disabled rules: `0`
- Severity overrides: `0`
- Unresolved in-plan references: `0`
- Findings by rule:
  - `gcp-public-workload-sensitive-data-access`: `2`
  - `gcp-subnetwork-flow-logs-not-configured`: `1`
  - `gcp-cloud-run-public-invoker`: `1`
  - `gcp-cloud-functions-public-invoker`: `1`

## Discovered Trust Boundaries

### `internet-to-service`

- Source: `internet`
- Target: `google_cloud_run_v2_service.api`
- Description: Traffic can cross from the public internet to google_cloud_run_v2_service.api.
- Rationale: The resource is directly reachable or intentionally exposed to unauthenticated network clients.

### `internet-to-service`

- Source: `internet`
- Target: `google_cloudfunctions_function.worker`
- Description: Traffic can cross from the public internet to google_cloudfunctions_function.worker.
- Rationale: The resource is directly reachable or intentionally exposed to unauthenticated network clients.

### `workload-to-data-store`

- Source: `google_cloud_run_v2_service.api`
- Target: `google_secret_manager_secret.api_key`
- Description: google_cloud_run_v2_service.api can interact with google_secret_manager_secret.api_key.
- Rationale: GCP workloads cross into a higher-sensitivity data plane when their attached service account is granted data access through IAM: google_secret_manager_secret_iam_member.run_accessor grants roles/secretmanager.secretAccessor to serviceAccount:tfstride-run@tfstride-demo.iam.gserviceaccount.com.

### `workload-to-data-store`

- Source: `google_cloudfunctions_function.worker`
- Target: `google_secret_manager_secret.api_key`
- Description: google_cloudfunctions_function.worker can interact with google_secret_manager_secret.api_key.
- Rationale: GCP workloads cross into a higher-sensitivity data plane when their attached service account is granted data access through IAM: google_secret_manager_secret_iam_member.function_accessor grants roles/secretmanager.secretAccessor to serviceAccount:tfstride-fn@tfstride-demo.iam.gserviceaccount.com.

## Findings

### High

#### Internet-exposed GCP workload can access sensitive data services

- STRIDE category: Information Disclosure
- Affected resources: `google_cloud_run_v2_service.api`, `google_secret_manager_secret.api_key`, `google_secret_manager_secret_iam_member.run_accessor`, `google_secret_manager_secret_iam_member.function_accessor`
- Trust boundary: `workload-to-data-store:google_cloud_run_v2_service.api->google_secret_manager_secret.api_key`
- Severity reasoning: internet_exposure +2, privilege_breadth +1, data_sensitivity +2, lateral_movement +1, blast_radius +1, final_score 7 => high
- Rationale: google_cloud_run_v2_service.api is internet-exposed and runs with GCP workload identity serviceAccount:tfstride-run@tfstride-demo.iam.gserviceaccount.com. That identity can access google_secret_manager_secret.api_key. A compromise of the public workload can therefore become direct access to sensitive GCP data services.
- Recommended mitigation: Run public GCP workloads with narrowly scoped service accounts, remove direct Secret Manager, Cloud KMS, GCS, or Cloud SQL grants from internet-facing instances, and broker sensitive data access through private services where possible.
- Evidence:
  - public exposure reasons: google_cloud_run_v2_service_iam_member.public_invoker grants roles/run.invoker to allUsers
  - workload identity: serviceAccount:tfstride-run@tfstride-demo.iam.gserviceaccount.com
  - data access path: google_cloud_run_v2_service.api reaches google_secret_manager_secret.api_key
  - boundary rationale: GCP workloads cross into a higher-sensitivity data plane when their attached service account is granted data access through IAM: google_secret_manager_secret_iam_member.run_accessor grants roles/secretmanager.secretAccessor to serviceAccount:tfstride-run@tfstride-demo.iam.gserviceaccount.com.
  - resource policy sources: google_secret_manager_secret_iam_member.run_accessor; google_secret_manager_secret_iam_member.function_accessor

#### Internet-exposed GCP workload can access sensitive data services

- STRIDE category: Information Disclosure
- Affected resources: `google_cloudfunctions_function.worker`, `google_secret_manager_secret.api_key`, `google_secret_manager_secret_iam_member.run_accessor`, `google_secret_manager_secret_iam_member.function_accessor`
- Trust boundary: `workload-to-data-store:google_cloudfunctions_function.worker->google_secret_manager_secret.api_key`
- Severity reasoning: internet_exposure +2, privilege_breadth +1, data_sensitivity +2, lateral_movement +1, blast_radius +1, final_score 7 => high
- Rationale: google_cloudfunctions_function.worker is internet-exposed and runs with GCP workload identity serviceAccount:tfstride-fn@tfstride-demo.iam.gserviceaccount.com. That identity can access google_secret_manager_secret.api_key. A compromise of the public workload can therefore become direct access to sensitive GCP data services.
- Recommended mitigation: Run public GCP workloads with narrowly scoped service accounts, remove direct Secret Manager, Cloud KMS, GCS, or Cloud SQL grants from internet-facing instances, and broker sensitive data access through private services where possible.
- Evidence:
  - public exposure reasons: google_cloudfunctions_function_iam_member.public_invoker grants roles/cloudfunctions.invoker to allAuthenticatedUsers
  - workload identity: serviceAccount:tfstride-fn@tfstride-demo.iam.gserviceaccount.com
  - data access path: google_cloudfunctions_function.worker reaches google_secret_manager_secret.api_key
  - boundary rationale: GCP workloads cross into a higher-sensitivity data plane when their attached service account is granted data access through IAM: google_secret_manager_secret_iam_member.function_accessor grants roles/secretmanager.secretAccessor to serviceAccount:tfstride-fn@tfstride-demo.iam.gserviceaccount.com.
  - resource policy sources: google_secret_manager_secret_iam_member.run_accessor; google_secret_manager_secret_iam_member.function_accessor

### Medium

#### Cloud Functions function is publicly invokable

- STRIDE category: Spoofing
- Affected resources: `google_cloudfunctions_function.worker`, `google_cloudfunctions_function_iam_member.public_invoker`
- Trust boundary: `internet-to-service:internet->google_cloudfunctions_function.worker`
- Severity reasoning: internet_exposure +2, privilege_breadth +0, data_sensitivity +0, lateral_movement +0, blast_radius +1, final_score 3 => medium
- Rationale: google_cloudfunctions_function.worker allows public HTTP access and grants Cloud Functions invoke permission to public GCP principals. Unauthenticated internet clients can reach the function entry point without an organization-owned identity boundary.
- Recommended mitigation: Remove `allUsers` and `allAuthenticatedUsers` from Cloud Functions invoker bindings unless anonymous access is intentional, and require authentication, IAP, API Gateway, or a controlled edge policy for public HTTP functions.
- Evidence:
  - public invoker bindings: source=google_cloudfunctions_function_iam_member.public_invoker; role=roles/cloudfunctions.invoker; member=allAuthenticatedUsers
  - public access reasons: google_cloudfunctions_function_iam_member.public_invoker grants roles/cloudfunctions.invoker to allAuthenticatedUsers
  - public exposure reasons: google_cloudfunctions_function_iam_member.public_invoker grants roles/cloudfunctions.invoker to allAuthenticatedUsers

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
