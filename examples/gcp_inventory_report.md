# tfSTRIDE Threat Model Report

- Analyzed file: `sample_gcp_plan.json`
- Provider: `gcp`
- Normalized resources: `18`
- Unsupported resources: `0`

## Summary

This run identified **4 trust boundaries** and **19 findings** across **18 normalized resources**.

- High severity findings: `5`
- Medium severity findings: `14`
- Low severity findings: `0`

## Analysis Coverage

- Terraform resources seen: `18`
- Provider resources considered: `18`
- Normalized resources: `18`
- Unsupported resources: `0`
- Registered rules: `41`
- Enabled rules: `41`
- Disabled rules: `0`
- Severity overrides: `0`
- Unresolved in-plan references: `0`
- Findings by rule:
  - `gcp-sensitive-resource-iam-external-access`: `2`
  - `gcp-cloud-sql-public-authorized-network`: `1`
  - `gcp-cloud-sql-backup-disabled`: `1`
  - `gcp-cloud-sql-public-ip-without-private-network`: `1`
  - `gcp-cloud-sql-ssl-not-required`: `1`
  - `gcp-cloud-sql-deletion-protection-disabled`: `1`
  - `gcp-gcs-public-access`: `1`
  - `gcp-gcs-public-access-prevention-not-enforced`: `1`
  - `gcp-gcs-versioning-disabled`: `1`
  - `gcp-gcs-customer-managed-encryption-missing`: `1`
  - `gcp-public-compute-broad-ingress`: `1`
  - `gcp-gke-public-control-plane`: `1`
  - `gcp-gke-broad-authorized-networks`: `1`
  - `gcp-gke-workload-identity-disabled`: `1`
  - `gcp-gke-legacy-metadata-endpoints-enabled`: `1`
  - `gcp-gke-broad-node-service-account`: `1`
  - `gcp-org-folder-iam-broad-principal`: `1`
  - `gcp-org-folder-iam-privileged-role`: `1`

## Discovered Trust Boundaries

### `internet-to-service`

- Source: `internet`
- Target: `google_compute_instance.web`
- Description: Traffic can cross from the public internet to google_compute_instance.web.
- Rationale: The resource is directly reachable or intentionally exposed to unauthenticated network clients.

### `internet-to-service`

- Source: `internet`
- Target: `google_container_cluster.app`
- Description: Traffic can cross from the public internet to google_container_cluster.app.
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

#### GCP organization or folder IAM grants a high-privilege role

- STRIDE category: Elevation of Privilege
- Affected resources: `google_folder_iam_member.folder_admin`
- Trust boundary: `not-applicable`
- Severity reasoning: internet_exposure +0, privilege_breadth +2, data_sensitivity +0, lateral_movement +2, blast_radius +2, final_score 6 => high
- Rationale: google_folder_iam_member.folder_admin grants the high-impact GCP role `roles/resourcemanager.folderAdmin` to `group:folder-admins@example.com` at folder scope `folders/12345`. That role enables folder hierarchy administration across a high-level resource boundary and can materially expand blast radius if the principal is compromised.
- Recommended mitigation: Replace high-impact organization and folder roles with narrowly scoped custom or predefined roles, assign them only to controlled break-glass or platform groups, and review descendant project blast radius.
- Evidence:
  - iam binding: member=group:folder-admins@example.com; role=roles/resourcemanager.folderAdmin
  - scope: folder scope `folders/12345`
  - role risk: folder hierarchy administration

#### GCP organization or folder IAM grants access to broad principals

- STRIDE category: Elevation of Privilege
- Affected resources: `google_organization_iam_binding.domain_viewer`
- Trust boundary: `not-applicable`
- Severity reasoning: internet_exposure +0, privilege_breadth +2, data_sensitivity +0, lateral_movement +2, blast_radius +2, final_score 6 => high
- Rationale: google_organization_iam_binding.domain_viewer grants `roles/viewer` to `domain:example.com` at organization scope `1234567890`. Public or broad-domain principals at organization or folder scope can expand access across many descendant projects and workloads.
- Recommended mitigation: Remove public and broad-domain principals from organization and folder IAM, grant high-level access only to tightly controlled groups, and prefer project- or resource-scoped bindings where possible.
- Evidence:
  - iam binding: member=domain:example.com; role=roles/viewer
  - scope: organization scope `1234567890`
  - trust scope: member grants a whole Google Workspace domain

#### GKE node pool uses broad node identity settings

- STRIDE category: Elevation of Privilege
- Affected resources: `google_container_node_pool.app`
- Trust boundary: `not-applicable`
- Severity reasoning: internet_exposure +0, privilege_breadth +2, data_sensitivity +0, lateral_movement +2, blast_radius +2, final_score 6 => high
- Rationale: google_container_node_pool.app uses broad GKE node identity settings. Default or broadly scoped node service accounts can turn a node or pod compromise into wider GCP API access.
- Recommended mitigation: Attach a dedicated least-privilege node service account, remove cloud-platform or full-control OAuth scopes, and shift workload permissions to Workload Identity bindings.
- Evidence:
  - node identity risks: node service account uses default Compute Engine identity `123456789-compute@developer.gserviceaccount.com`; node OAuth scope is broad: https://www.googleapis.com/auth/cloud-platform
  - node service account: 123456789-compute@developer.gserviceaccount.com
  - oauth scopes: https://www.googleapis.com/auth/cloud-platform

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

#### Cloud SQL deletion protection is disabled

- STRIDE category: Denial of Service
- Affected resources: `google_sql_database_instance.app`
- Trust boundary: `not-applicable`
- Severity reasoning: internet_exposure +0, privilege_breadth +0, data_sensitivity +2, lateral_movement +0, blast_radius +1, final_score 3 => medium
- Rationale: google_sql_database_instance.app has Cloud SQL deletion protection disabled. Accidental or unauthorized infrastructure changes could destroy the managed database instance without this provider-level guardrail.
- Recommended mitigation: Enable Cloud SQL deletion protection for persistent environments and require explicit review before disabling it during planned database retirement.
- Evidence:
  - lifecycle posture: deletion_protection is false

#### Cloud SQL public IPv4 is enabled without private network access

- STRIDE category: Information Disclosure
- Affected resources: `google_sql_database_instance.app`
- Trust boundary: `internet-to-service:internet->google_sql_database_instance.app`
- Severity reasoning: internet_exposure +2, privilege_breadth +0, data_sensitivity +2, lateral_movement +1, blast_radius +0, final_score 5 => medium
- Rationale: google_sql_database_instance.app has Cloud SQL public IPv4 enabled without a private network attachment. That keeps database client access on a public endpoint instead of an internal VPC path.
- Recommended mitigation: Disable public IPv4 where possible, attach the instance to a private network, and route clients through private IP, the Cloud SQL Auth Proxy, or tightly controlled connectivity paths.
- Evidence:
  - network posture: ipv4_enabled is true; private_network is unset; authorized_networks configured: 1
  - public access reasons: Cloud SQL public IPv4 access is enabled

#### Cloud SQL public client access does not require SSL

- STRIDE category: Information Disclosure
- Affected resources: `google_sql_database_instance.app`
- Trust boundary: `internet-to-service:internet->google_sql_database_instance.app`
- Severity reasoning: internet_exposure +2, privilege_breadth +0, data_sensitivity +2, lateral_movement +1, blast_radius +0, final_score 5 => medium
- Rationale: google_sql_database_instance.app allows Cloud SQL public IPv4 client access without requiring encrypted client connections. Credentials and database traffic should not depend on client-side optional TLS behavior.
- Recommended mitigation: Require encrypted Cloud SQL client connections with `require_ssl` or an enforcing `ssl_mode`, and prefer private IP or the Cloud SQL Auth Proxy for application connectivity.
- Evidence:
  - ssl posture: require_ssl is false; ssl_mode is unset; ipv4_enabled is true

#### GCS bucket does not enforce Public Access Prevention

- STRIDE category: Information Disclosure
- Affected resources: `google_storage_bucket.logs`
- Trust boundary: `internet-to-service:internet->google_storage_bucket.logs`
- Severity reasoning: internet_exposure +2, privilege_breadth +0, data_sensitivity +2, lateral_movement +0, blast_radius +1, final_score 5 => medium
- Rationale: google_storage_bucket.logs does not enforce GCS Public Access Prevention. Public principals can still be introduced through bucket IAM unless an organization-level policy blocks them.
- Recommended mitigation: Set GCS Public Access Prevention to `enforced` on sensitive buckets and rely on explicit non-public identities or signed access patterns when objects must be shared.
- Evidence:
  - access control posture: public_access_prevention is unset
  - public exposure reasons: google_storage_bucket_iam_member.public_logs_reader grants roles/storage.objectViewer to allUsers

#### GCS bucket is publicly accessible

- STRIDE category: Information Disclosure
- Affected resources: `google_storage_bucket.logs`
- Trust boundary: `internet-to-service:internet->google_storage_bucket.logs`
- Severity reasoning: internet_exposure +2, privilege_breadth +0, data_sensitivity +2, lateral_movement +0, blast_radius +1, final_score 5 => medium
- Rationale: google_storage_bucket.logs is publicly reachable through GCS IAM grants. Public bucket access is a common source of unintended object disclosure.
- Recommended mitigation: Remove `allUsers` and `allAuthenticatedUsers` from bucket-level IAM grants, enforce GCS Public Access Prevention, and use signed URLs, CDN origins, or narrow identities when objects must be distributed.
- Evidence:
  - public exposure reasons: google_storage_bucket_iam_member.public_logs_reader grants roles/storage.objectViewer to allUsers

#### GCS sensitive bucket does not use customer-managed encryption

- STRIDE category: Information Disclosure
- Affected resources: `google_storage_bucket.logs`
- Trust boundary: `not-applicable`
- Severity reasoning: internet_exposure +0, privilege_breadth +0, data_sensitivity +2, lateral_movement +0, blast_radius +1, final_score 3 => medium
- Rationale: google_storage_bucket.logs relies on default GCS encryption rather than a customer-managed KMS key. Sensitive buckets lose key ownership, rotation, and separation-of-duties controls that a CMEK can provide.
- Recommended mitigation: Configure a Cloud KMS customer-managed key for sensitive GCS buckets, assign the GCS service agent only the key roles it needs, and manage key rotation separately from bucket IAM.
- Evidence:
  - encryption posture: default_kms_key_name is unset; customer_managed_encryption is false

#### GCS sensitive bucket versioning is disabled

- STRIDE category: Denial of Service
- Affected resources: `google_storage_bucket.logs`
- Trust boundary: `not-applicable`
- Severity reasoning: internet_exposure +0, privilege_breadth +0, data_sensitivity +2, lateral_movement +0, blast_radius +1, final_score 3 => medium
- Rationale: google_storage_bucket.logs stores sensitive GCS data without bucket versioning. Accidental overwrites, deletes, or destructive changes have fewer object-level recovery options.
- Recommended mitigation: Enable bucket versioning for sensitive GCS buckets and pair it with lifecycle retention rules that match recovery objectives and storage cost constraints.
- Evidence:
  - data protection posture: versioning.enabled is false; data_sensitivity is sensitive

#### GKE cluster does not enable Workload Identity

- STRIDE category: Elevation of Privilege
- Affected resources: `google_container_cluster.app`
- Trust boundary: `not-applicable`
- Severity reasoning: internet_exposure +2, privilege_breadth +1, data_sensitivity +0, lateral_movement +1, blast_radius +1, final_score 5 => medium
- Rationale: google_container_cluster.app does not enable GKE Workload Identity. Pods are more likely to depend on node service-account credentials, which weakens workload-level identity boundaries and can expand blast radius after pod compromise.
- Recommended mitigation: Enable GKE Workload Identity, bind Kubernetes service accounts to narrow Google service accounts, and avoid relying on node service-account credentials for pod-level cloud API access.
- Evidence:
  - workload identity posture: workload_identity_enabled is false; workload_pool is unset

#### GKE cluster exposes a public control plane

- STRIDE category: Spoofing
- Affected resources: `google_container_cluster.app`
- Trust boundary: `internet-to-service:internet->google_container_cluster.app`
- Severity reasoning: internet_exposure +2, privilege_breadth +0, data_sensitivity +0, lateral_movement +1, blast_radius +1, final_score 4 => medium
- Rationale: google_container_cluster.app exposes a public GKE control-plane endpoint. Public API server reachability increases dependence on IAM, Kubernetes RBAC, and authorized network configuration to protect cluster administration.
- Recommended mitigation: Use private GKE control-plane endpoints where possible, or restrict master authorized networks to narrow administrator CIDRs and enforce IAM plus Kubernetes RBAC for cluster administration.
- Evidence:
  - control plane endpoint: 35.4.5.6
  - public access reasons: GKE control plane endpoint is public
  - public exposure reasons: authorized network `anywhere` allows 0.0.0.0/0

#### GKE control plane allows broad authorized networks

- STRIDE category: Spoofing
- Affected resources: `google_container_cluster.app`
- Trust boundary: `internet-to-service:internet->google_container_cluster.app`
- Severity reasoning: internet_exposure +2, privilege_breadth +0, data_sensitivity +0, lateral_movement +2, blast_radius +1, final_score 5 => medium
- Rationale: google_container_cluster.app exposes the GKE control plane without narrow master authorized networks. Internet-wide or unset CIDR controls leave the Kubernetes API server reachable from untrusted client networks.
- Recommended mitigation: Configure GKE master authorized networks with narrow trusted CIDRs, avoid internet-wide ranges, and prefer private control-plane access for administrative paths.
- Evidence:
  - authorized networks: anywhere (0.0.0.0/0)
  - configured authorized network count: 1
  - public exposure reasons: authorized network `anywhere` allows 0.0.0.0/0

#### GKE node metadata exposure is not hardened

- STRIDE category: Elevation of Privilege
- Affected resources: `google_container_node_pool.app`
- Trust boundary: `not-applicable`
- Severity reasoning: internet_exposure +0, privilege_breadth +1, data_sensitivity +0, lateral_movement +1, blast_radius +1, final_score 3 => medium
- Rationale: google_container_node_pool.app allows legacy or broad node metadata exposure. Workloads on the node may be able to reach metadata credentials outside the intended GKE metadata server controls.
- Recommended mitigation: Disable legacy metadata endpoints, use GKE metadata server or Workload Identity controls, and prevent pods from reaching broad node credentials.
- Evidence:
  - node metadata posture: legacy metadata endpoints are enabled; metadata mode is GCE_METADATA

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
  - internet ingress reasons: google_compute_firewall.public_ssh ingress tcp 22 from 0.0.0.0/0
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

- GCP support currently provides initial inventory normalization, internet-to-service, route/NAT posture, and workload-to-sensitive-data trust-boundary detection for compute and serverless workloads, with limited GCP STRIDE rule coverage for compute, GCS posture, Cloud SQL posture, Secret Manager, Cloud KMS, and project IAM only; GCP control coverage is not implemented yet.
- The engine reasons over Terraform planned values only and does not validate runtime drift, CloudTrail evidence, or post-deploy control-plane activity.
