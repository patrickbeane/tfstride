# tfSTRIDE Threat Model Report

- Analyzed file: `sample_gcp_plan.json`
- Provider: `gcp`
- Normalized resources: `14`
- Unsupported resources: `0`

## Summary

This run identified **3 trust boundaries** and **6 findings** across **14 normalized resources**.

- High severity findings: `2`
- Medium severity findings: `4`
- Low severity findings: `0`

## Analysis Coverage

- Terraform resources seen: `14`
- Provider resources considered: `14`
- Normalized resources: `14`
- Unsupported resources: `0`
- Registered rules: `20`
- Enabled rules: `20`
- Disabled rules: `0`
- Severity overrides: `0`
- Unresolved in-plan references: `0`
- Findings by rule:
  - `gcp-sensitive-resource-iam-external-access`: `2`
  - `gcp-cloud-sql-public-authorized-network`: `1`
  - `gcp-cloud-sql-backup-disabled`: `1`
  - `gcp-gcs-public-access`: `1`
  - `gcp-public-compute-broad-ingress`: `1`

## Discovered Trust Boundaries

### `internet-to-service`

- Source: `internet`
- Target: `google_compute_instance.web`
- Description: Traffic can cross from the public internet to google_compute_instance.web.
- Rationale: The resource is directly reachable or intentionally exposed to unauthenticated network clients.

### `internet-to-service`

- Source: `internet`
- Target: `google_sql_database_instance.app`
- Description: Traffic can cross from the public internet to google_sql_database_instance.app.
- Rationale: The resource is directly reachable or intentionally exposed to unauthenticated network clients.

### `internet-to-service`

- Source: `internet`
- Target: `google_storage_bucket.logs`
- Description: Traffic can cross from the public internet to google_storage_bucket.logs.
- Rationale: The resource is directly reachable or intentionally exposed to unauthenticated network clients.

## Findings

### High

#### Cloud SQL instance accepts public authorized network access

- STRIDE category: Information Disclosure
- Affected resources: `google_sql_database_instance.app`
- Trust boundary: `internet-to-service:internet->google_sql_database_instance.app`
- Severity reasoning: internet_exposure +2, privilege_breadth +0, data_sensitivity +2, lateral_movement +1, blast_radius +1, final_score 6 => high
- Rationale: google_sql_database_instance.app has a public Cloud SQL IPv4 endpoint and an authorized network that allows internet-wide client sources. That weakens the database trust boundary even when database authentication is still required.
- Recommended mitigation: Disable public IPv4 access where possible, use private IP connectivity or the Cloud SQL Auth Proxy, and restrict authorized networks to narrow CIDRs when public client access is required.
- Evidence:
  - authorized networks: anywhere (0.0.0.0/0)
  - public exposure reasons: authorized network `anywhere` allows 0.0.0.0/0

#### Sensitive GCP resource IAM binding allows broad or external access

- STRIDE category: Information Disclosure
- Affected resources: `google_secret_manager_secret.api_key`, `google_secret_manager_secret_iam_member.public_accessor`
- Trust boundary: `not-applicable`
- Severity reasoning: internet_exposure +2, privilege_breadth +2, data_sensitivity +2, lateral_movement +1, blast_radius +2, final_score 9 => high
- Rationale: google_secret_manager_secret.api_key grants `roles/secretmanager.secretAccessor` to `allAuthenticatedUsers` through GCP IAM. Public, broad-domain, or foreign-project principals can access sensitive secrets or cryptographic key operations outside the expected project trust boundary.
- Recommended mitigation: Grant Secret Manager and Cloud KMS IAM roles only to specific in-project service accounts or groups, remove public principals, and require explicit cross-project access reviews for partner identities.
- Evidence:
  - iam binding: source=google_secret_manager_secret_iam_member.public_accessor; role=roles/secretmanager.secretAccessor; member=allAuthenticatedUsers
  - trust scope: member is public GCP principal `allAuthenticatedUsers`
  - resource policy sources: google_secret_manager_secret_iam_member.public_accessor

### Medium

#### Cloud SQL automated backups are disabled

- STRIDE category: Denial of Service
- Affected resources: `google_sql_database_instance.app`
- Trust boundary: `not-applicable`
- Severity reasoning: internet_exposure +0, privilege_breadth +0, data_sensitivity +2, lateral_movement +0, blast_radius +1, final_score 3 => medium
- Rationale: google_sql_database_instance.app does not have Cloud SQL automated backups enabled. A destructive change, operator error, or data corruption event would have fewer managed recovery points.
- Recommended mitigation: Enable automated backups for Cloud SQL instances, configure retention appropriate to the workload, and enable point-in-time recovery where supported.
- Evidence:
  - backup posture: backup_configuration.enabled is false; point_in_time_recovery_enabled is false; engine is POSTGRES_15

#### GCS bucket is publicly accessible

- STRIDE category: Information Disclosure
- Affected resources: `google_storage_bucket.logs`
- Trust boundary: `internet-to-service:internet->google_storage_bucket.logs`
- Severity reasoning: internet_exposure +2, privilege_breadth +0, data_sensitivity +2, lateral_movement +0, blast_radius +1, final_score 5 => medium
- Rationale: google_storage_bucket.logs is publicly reachable through GCS IAM grants. Public bucket access is a common source of unintended object disclosure.
- Recommended mitigation: Remove `allUsers` and `allAuthenticatedUsers` from bucket-level IAM grants, enforce GCS Public Access Prevention, and use signed URLs, CDN origins, or narrow identities when objects must be distributed.
- Evidence:
  - public exposure reasons: google_storage_bucket_iam_member.public_logs_reader grants roles/storage.objectViewer to allUsers

#### Internet-exposed GCP compute instance permits broad ingress

- STRIDE category: Spoofing
- Affected resources: `google_compute_instance.web`, `google_compute_firewall.public_ssh`
- Trust boundary: `internet-to-service:internet->google_compute_instance.web`
- Severity reasoning: internet_exposure +2, privilege_breadth +0, data_sensitivity +0, lateral_movement +1, blast_radius +1, final_score 4 => medium
- Rationale: google_compute_instance.web has an external access config and matching GCP firewall rules allow administrative access or all ports from the public internet. That broad ingress raises the chance of unauthenticated probing and credential attacks.
- Recommended mitigation: Restrict GCP firewall source ranges and exposed ports, remove external IP access where possible, and use Identity-Aware Proxy, VPN, or a controlled bastion for administration.
- Evidence:
  - firewall rules: google_compute_firewall.public_ssh ingress tcp 22 from 0.0.0.0/0
  - network tags: web
  - public exposure reasons: compute instance has an external access config and matching firewall rules allow internet ingress

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

- GCP support currently provides initial inventory normalization, internet-to-service trust-boundary detection, and limited GCP STRIDE rule coverage for compute, GCS, Cloud SQL, Secret Manager, Cloud KMS, and project IAM only; GCP control coverage is not implemented yet.
- The engine reasons over Terraform planned values only and does not validate runtime drift, CloudTrail evidence, or post-deploy control-plane activity.
