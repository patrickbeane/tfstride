# tfSTRIDE Threat Model Report

- Analyzed file: `sample_gcp_cross_project_iam_plan.json`
- Provider: `gcp`
- Normalized resources: `8`
- Unsupported resources: `0`

## Summary

This run identified **0 trust boundaries** and **5 findings** across **8 normalized resources**.

- High severity findings: `3`
- Medium severity findings: `2`
- Low severity findings: `0`

## Analysis Coverage

- Terraform resources seen: `8`
- Provider resources considered: `8`
- Normalized resources: `8`
- Unsupported resources: `0`
- Registered rules: `91`
- Enabled rules: `91`
- Disabled rules: `0`
- Severity overrides: `0`
- Unresolved in-plan references: `0`
- Findings by rule:
  - `gcp-sensitive-resource-iam-external-access`: `2`
  - `gcp-project-iam-privileged-role`: `1`
  - `gcp-inherited-iam-sensitive-resource-access`: `1`
  - `gcp-inherited-iam-blast-radius`: `1`

## Discovered Trust Boundaries

No trust boundaries were discovered.

## Findings

### High

#### GCP project IAM binding grants a high-privilege role

- STRIDE category: Elevation of Privilege
- Affected resources: `google_project_iam_member.partner_editor`
- Trust boundary: `not-applicable`
- Severity reasoning: internet_exposure +0, privilege_breadth +2, data_sensitivity +0, lateral_movement +2, blast_radius +2, final_score 6 => high
- Rationale: google_project_iam_member.partner_editor grants the high-impact GCP role `roles/editor` to `serviceAccount:deployer@partner-project.iam.gserviceaccount.com` at project scope. That role enables broad write access across most project services and can materially expand control-plane blast radius if the principal is compromised or mis-scoped.
- Recommended mitigation: Replace Owner, Editor, IAM admin, service-account impersonation, and admin-class project roles with narrowly scoped predefined or custom roles assigned to specific groups or service accounts.
- Evidence:
  - iam binding: member=serviceAccount:deployer@partner-project.iam.gserviceaccount.com; role=roles/editor
  - role risk: broad write access across most project services

#### Inherited GCP IAM grant expands descendant blast radius

- STRIDE category: Elevation of Privilege
- Affected resources: `google_project_iam_member.partner_editor`, `google_compute_network.main`, `google_compute_subnetwork.app`, `google_kms_crypto_key.customer`, `google_secret_manager_secret.api_key`, `google_service_account.web`
- Trust boundary: `not-applicable`
- Severity reasoning: internet_exposure +0, privilege_breadth +2, data_sensitivity +2, lateral_movement +2, blast_radius +2, final_score 8 => high
- Rationale: google_project_iam_member.partner_editor grants `roles/editor` to `serviceAccount:deployer@partner-project.iam.gserviceaccount.com` at project scope `tfstride-demo`, and that inherited grant applies to 5 concrete descendant resource(s). A high-level IAM grant with broad, external, or high-impact access increases control-plane blast radius because compromise or misuse can affect resources below the inherited scope.
- Recommended mitigation: Avoid broad or high-impact IAM grants at organization, folder, and project scope when narrower resource-level or workload-specific bindings are possible; split inherited roles by service and review descendant resources before assigning public, external, or administrator principals.
- Evidence:
  - iam binding: source=google_project_iam_member.partner_editor; scope=project:tfstride-demo; member=serviceAccount:deployer@partner-project.iam.gserviceaccount.com; role=roles/editor
  - role risk: broad write access across most project services
  - trust scope: service account belongs to project `partner-project`, outside resource project `tfstride-demo`
  - descendant scope: scope=project:tfstride-demo; descendant_count=5; resource_type_count=5; projects=tfstride-demo
  - descendant resource types: google_compute_network: 1; google_compute_subnetwork: 1; google_kms_crypto_key: 1; google_secret_manager_secret: 1; google_service_account: 1
  - descendant resources: google_compute_network.main; google_compute_subnetwork.app; google_kms_crypto_key.customer; google_secret_manager_secret.api_key; google_service_account.web

#### Inherited GCP IAM grant reaches sensitive resources

- STRIDE category: Information Disclosure
- Affected resources: `google_project_iam_member.partner_editor`, `google_kms_crypto_key.customer`, `google_secret_manager_secret.api_key`
- Trust boundary: `not-applicable`
- Severity reasoning: internet_exposure +0, privilege_breadth +2, data_sensitivity +2, lateral_movement +1, blast_radius +2, final_score 7 => high
- Rationale: google_project_iam_member.partner_editor grants `roles/editor` to `serviceAccount:deployer@partner-project.iam.gserviceaccount.com` at project scope `tfstride-demo`, and that inherited grant reaches 2 sensitive GCP descendant resource(s). Project, folder, and organization IAM applies below the grant scope, so a single ancestor binding can expose data resources beyond their local IAM boundary.
- Recommended mitigation: Move sensitive data access off organization, folder, and project-level IAM where possible; grant Secret Manager, KMS, GCS, Cloud SQL, BigQuery, and Pub/Sub permissions at the narrowest resource scope with reviewed principals and custom roles.
- Evidence:
  - iam binding: source=google_project_iam_member.partner_editor; scope=project:tfstride-demo; member=serviceAccount:deployer@partner-project.iam.gserviceaccount.com; role=roles/editor
  - sensitive descendants: resource=google_kms_crypto_key.customer; type=google_kms_crypto_key; risk=Cloud KMS cryptographic key access through roles/editor; resource=google_secret_manager_secret.api_key; type=google_secret_manager_secret; risk=Secret Manager secret access through roles/editor
  - trust scope: service account belongs to project `partner-project`, outside resource project `tfstride-demo`

### Medium

#### Sensitive GCP resource IAM binding allows broad or external access

- STRIDE category: Information Disclosure
- Affected resources: `google_secret_manager_secret.api_key`, `google_secret_manager_secret_iam_member.partner_accessor`
- Trust boundary: `not-applicable`
- Severity reasoning: internet_exposure +0, privilege_breadth +1, data_sensitivity +2, lateral_movement +1, blast_radius +1, final_score 5 => medium
- Rationale: google_secret_manager_secret.api_key grants `roles/secretmanager.secretAccessor` to `serviceAccount:reader@partner-project.iam.gserviceaccount.com` through GCP IAM. Public, broad-domain, or foreign-project principals can access sensitive secrets or cryptographic key operations outside the expected project trust boundary.
- Recommended mitigation: Grant Secret Manager and Cloud KMS IAM roles only to specific in-project service accounts or groups, remove public principals, and require explicit cross-project access reviews for partner identities.
- Evidence:
  - iam binding: source=google_secret_manager_secret_iam_member.partner_accessor; role=roles/secretmanager.secretAccessor; member=serviceAccount:reader@partner-project.iam.gserviceaccount.com
  - trust scope: service account belongs to project `partner-project`, outside resource project `tfstride-demo`
  - resource policy sources: google_secret_manager_secret_iam_member.partner_accessor

#### Sensitive GCP resource IAM binding allows broad or external access

- STRIDE category: Information Disclosure
- Affected resources: `google_kms_crypto_key.customer`, `google_kms_crypto_key_iam_member.partner_decrypter`
- Trust boundary: `not-applicable`
- Severity reasoning: internet_exposure +0, privilege_breadth +1, data_sensitivity +2, lateral_movement +1, blast_radius +1, final_score 5 => medium
- Rationale: google_kms_crypto_key.customer grants `roles/cloudkms.cryptoKeyDecrypter` to `serviceAccount:decryptor@partner-project.iam.gserviceaccount.com` through GCP IAM. Public, broad-domain, or foreign-project principals can access sensitive secrets or cryptographic key operations outside the expected project trust boundary.
- Recommended mitigation: Grant Secret Manager and Cloud KMS IAM roles only to specific in-project service accounts or groups, remove public principals, and require explicit cross-project access reviews for partner identities.
- Evidence:
  - iam binding: source=google_kms_crypto_key_iam_member.partner_decrypter; role=roles/cloudkms.cryptoKeyDecrypter; member=serviceAccount:decryptor@partner-project.iam.gserviceaccount.com
  - trust scope: service account belongs to project `partner-project`, outside resource project `tfstride-demo`
  - resource policy sources: google_kms_crypto_key_iam_member.partner_decrypter

### Low

No findings in this severity band.

## Limitations / Unsupported Resources

- GCP support currently provides initial inventory normalization, internet-to-service, route/NAT posture, and workload-to-sensitive-data trust-boundary detection for compute and serverless workloads, with limited GCP STRIDE rule coverage for compute, GCS posture, Cloud SQL posture, Secret Manager, Cloud KMS, and project IAM only; GCP control coverage is not implemented yet.
- The engine reasons over Terraform planned values only and does not validate runtime drift, CloudTrail evidence, or post-deploy control-plane activity.
