# tfSTRIDE Threat Model Report

- Analyzed file: `sample_gcp_plan.json`
- Provider: `gcp`
- Normalized resources: `23`
- Unsupported resources: `0`

## Summary

This run identified **4 trust boundaries** and **26 findings** across **23 normalized resources**.

- High severity findings: `6`
- Medium severity findings: `20`
- Low severity findings: `0`

## Analysis Coverage

- Terraform resources seen: `23`
- Provider resources considered: `23`
- Normalized resources: `23`
- Unsupported resources: `0`
- Registered rules: `212`
- Enabled rules: `212`
- Disabled rules: `0`
- Severity overrides: `0`
- Unresolved in-plan references: `0`
- Findings by rule:
  - `gcp-sensitive-resource-iam-external-access`: `2`
  - `gcp-pubsub-public-access`: `1`
  - `gcp-pubsub-topic-customer-managed-encryption-missing`: `1`
  - `gcp-pubsub-subscription-dead-letter-policy-missing`: `1`
  - `gcp-bigquery-public-access`: `1`
  - `gcp-public-workload-sensitive-data-access`: `1`
  - `gcp-cloud-sql-public-authorized-network`: `1`
  - `gcp-cloud-sql-backup-disabled`: `1`
  - `gcp-cloud-sql-public-ip-without-private-network`: `1`
  - `gcp-cloud-sql-ssl-not-required`: `1`
  - `gcp-cloud-sql-deletion-protection-disabled`: `1`
  - `gcp-cloud-sql-zonal-availability`: `1`
  - `gcp-gcs-public-access`: `1`
  - `gcp-gcs-public-access-prevention-not-enforced`: `1`
  - `gcp-gcs-versioning-disabled`: `1`
  - `gcp-gcs-customer-managed-encryption-missing`: `1`
  - `gcp-gcs-retention-policy-insufficient`: `1`
  - `gcp-secret-manager-customer-managed-encryption-missing`: `1`
  - `gcp-secret-manager-lifecycle-posture-incomplete`: `1`
  - `gcp-public-compute-broad-ingress`: `1`
  - `gcp-compute-os-login-disabled`: `1`
  - `gcp-subnetwork-flow-logs-not-configured`: `1`
  - `gcp-service-account-key-hygiene`: `1`
  - `gcp-service-account-key-effective-access`: `1`
  - `gcp-inherited-iam-blast-radius`: `1`

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

### `workload-to-data-store`

- Source: `google_compute_instance.web`
- Target: `google_bigquery_dataset.analytics`
- Description: google_compute_instance.web can interact with google_bigquery_dataset.analytics.
- Rationale: GCP workloads cross into a higher-sensitivity data plane when their attached service account is granted data access through IAM: google_bigquery_dataset_iam_binding.analytics_viewers grants roles/bigquery.dataViewer to serviceAccount:tfstride-web@example.iam.gserviceaccount.com.

## Findings

### High

#### BigQuery IAM binding allows public or broad data access

- STRIDE category: Information Disclosure
- Affected resources: `google_bigquery_dataset.analytics`, `google_bigquery_dataset_iam_binding.analytics_viewers`
- Trust boundary: `not-applicable`
- Severity reasoning: internet_exposure +2, privilege_breadth +2, data_sensitivity +2, lateral_movement +1, blast_radius +2, final_score 9 => high
- Rationale: google_bigquery_dataset.analytics grants `roles/bigquery.dataViewer` to `allUsers` through BigQuery IAM. Public or broad principals can read or modify analytical data outside the expected project trust boundary.
- Recommended mitigation: Grant BigQuery dataset and table access only to specific in-project identities or reviewed analytics groups, remove public principals, and prefer least-privilege data roles.
- Evidence:
  - iam binding: source=google_bigquery_dataset_iam_binding.analytics_viewers; role=roles/bigquery.dataViewer; member=allUsers
  - trust scope: member is public GCP principal `allUsers`
  - resource policy sources: google_bigquery_dataset_iam_binding.analytics_viewers

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

#### GCP service account key can exercise sensitive or privileged access

- STRIDE category: Elevation of Privilege
- Affected resources: `google_service_account.web`, `google_service_account_key.web`, `google_bigquery_dataset.analytics`, `google_bigquery_dataset_iam_binding.analytics_viewers`
- Trust boundary: `not-applicable`
- Severity reasoning: internet_exposure +0, privilege_breadth +1, data_sensitivity +2, lateral_movement +1, blast_radius +2, final_score 6 => high
- Rationale: google_service_account_key.web creates portable credentials for `google_service_account.web`, and that service account has sensitive data access or high-impact IAM grants. A copied key can exercise those effective permissions outside the intended workload boundary.
- Recommended mitigation: Remove sensitive data and high-impact IAM grants from service accounts that still have user-managed keys, replace keys with workload identity or service-account impersonation, and revoke or rotate existing keys after privilege reduction.
- Evidence:
  - key context: source=google_service_account_key.web; service_account_reference=google_service_account.web.email; resolved_service_account=google_service_account.web
  - service account principals: serviceAccount:tfstride-web@example.iam.gserviceaccount.com; tfstride-web@example.iam.gserviceaccount.com
  - effective access: resource=google_bigquery_dataset.analytics; source=google_bigquery_dataset_iam_binding.analytics_viewers; scope=BigQuery dataset IAM; role=roles/bigquery.dataViewer; member=serviceAccount:tfstride-web@example.iam.gserviceaccount.com; risk=BigQuery dataset IAM grants roles/bigquery.dataViewer

#### Internet-exposed GCP workload can access sensitive data services

- STRIDE category: Information Disclosure
- Affected resources: `google_compute_instance.web`, `google_bigquery_dataset.analytics`, `google_bigquery_dataset_iam_binding.analytics_viewers`
- Trust boundary: `workload-to-data-store:google_compute_instance.web->google_bigquery_dataset.analytics`
- Severity reasoning: internet_exposure +2, privilege_breadth +1, data_sensitivity +2, lateral_movement +1, blast_radius +1, final_score 7 => high
- Rationale: google_compute_instance.web is internet-exposed and runs with GCP workload identity serviceAccount:tfstride-web@example.iam.gserviceaccount.com. That identity can access google_bigquery_dataset.analytics. A compromise of the public workload can therefore become direct access to sensitive GCP data services.
- Recommended mitigation: Run public GCP workloads with narrowly scoped service accounts, remove direct Secret Manager, Cloud KMS, GCS, or Cloud SQL grants from internet-facing instances, and broker sensitive data access through private services where possible.
- Evidence:
  - public exposure reasons: compute instance has an external access config and matching firewall rules allow internet ingress
  - workload identity: serviceAccount:tfstride-web@example.iam.gserviceaccount.com
  - workload identity scopes: cloud-platform
  - data access path: google_compute_instance.web reaches google_bigquery_dataset.analytics
  - boundary rationale: GCP workloads cross into a higher-sensitivity data plane when their attached service account is granted data access through IAM: google_bigquery_dataset_iam_binding.analytics_viewers grants roles/bigquery.dataViewer to serviceAccount:tfstride-web@example.iam.gserviceaccount.com.
  - resource policy sources: google_bigquery_dataset_iam_binding.analytics_viewers

#### Pub/Sub IAM binding allows public or broad data access

- STRIDE category: Information Disclosure
- Affected resources: `google_pubsub_topic.events`, `google_pubsub_topic_iam_member.public_publisher`
- Trust boundary: `not-applicable`
- Severity reasoning: internet_exposure +2, privilege_breadth +2, data_sensitivity +1, lateral_movement +1, blast_radius +1, final_score 7 => high
- Rationale: google_pubsub_topic.events grants `roles/pubsub.publisher` to `allAuthenticatedUsers` through Pub/Sub IAM. Public or broad principals can publish, consume, or administer event streams outside the expected service boundary.
- Recommended mitigation: Grant Pub/Sub publisher and subscriber roles only to specific service accounts or groups, remove public principals, and separate publish and consume permissions by workload.
- Evidence:
  - iam binding: source=google_pubsub_topic_iam_member.public_publisher; role=roles/pubsub.publisher; member=allAuthenticatedUsers
  - trust scope: member is public GCP principal `allAuthenticatedUsers`
  - resource policy sources: google_pubsub_topic_iam_member.public_publisher

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

#### Cloud SQL instance uses zonal availability

- STRIDE category: Denial of Service
- Affected resources: `google_sql_database_instance.app`
- Trust boundary: `not-applicable`
- Severity reasoning: internet_exposure +0, privilege_breadth +0, data_sensitivity +2, lateral_movement +0, blast_radius +1, final_score 3 => medium
- Rationale: google_sql_database_instance.app uses zonal Cloud SQL availability. A zonal failure or maintenance disruption can leave the database unavailable longer than a regional high-availability deployment.
- Recommended mitigation: Use `REGIONAL` availability for production Cloud SQL instances that require higher availability, then validate application failover behavior and recovery objectives.
- Evidence:
  - availability posture: availability_type=ZONAL; engine=POSTGRES_15

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

#### GCP compute instance disables OS Login

- STRIDE category: Elevation of Privilege
- Affected resources: `google_compute_instance.web`
- Trust boundary: `not-applicable`
- Severity reasoning: internet_exposure +2, privilege_breadth +1, data_sensitivity +0, lateral_movement +1, blast_radius +1, final_score 5 => medium
- Rationale: google_compute_instance.web explicitly disables OS Login. SSH access can therefore fall back to instance or project metadata keys instead of centralized IAM-backed login and audit controls.
- Recommended mitigation: Enable OS Login on GCE instances and manage SSH access through IAM roles, two-factor enforcement, and centralized audit logs instead of metadata SSH keys.
- Evidence:
  - os login posture: metadata.enable-oslogin is false
  - public exposure reasons: compute instance has an external access config and matching firewall rules allow internet ingress

#### GCP service account user-managed key lacks rotation hygiene

- STRIDE category: Spoofing
- Affected resources: `google_service_account.web`, `google_service_account_key.web`
- Trust boundary: `not-applicable`
- Severity reasoning: internet_exposure +0, privilege_breadth +1, data_sensitivity +0, lateral_movement +1, blast_radius +2, final_score 4 => medium
- Rationale: google_service_account_key.web creates a user-managed GCP service account key for `google_service_account.web`. User-managed service account keys are portable, long-lived credentials that can be copied outside GCP control, so they need explicit rotation controls or should be replaced with workload identity or impersonation flows.
- Recommended mitigation: Avoid user-managed service account keys where Workload Identity Federation, workload identity, or service-account impersonation can be used; when keys are unavoidable, keep lifetimes short, configure explicit rotation triggers, and store private material outside Terraform state.
- Evidence:
  - key context: source=google_service_account_key.web; service_account_reference=google_service_account.web.email; key_algorithm=KEY_ALG_RSA_2048; public_key_type=TYPE_X509_PEM_FILE
  - key risk: Terraform manages a user-created service-account key; validity window is 365 days and exceeds 180-day threshold; no Terraform keepers rotation trigger observed
  - validity window: valid_after=2026-01-01T00:00:00Z; valid_before=2027-01-01T00:00:00Z; validity_days=365
  - rotation control: no Terraform keepers rotation trigger observed

#### GCP subnetwork Flow Logs are not configured

- STRIDE category: Repudiation
- Affected resources: `google_compute_subnetwork.app`
- Trust boundary: `not-applicable`
- Severity reasoning: internet_exposure +0, privilege_breadth +0, data_sensitivity +0, lateral_movement +2, blast_radius +1, final_score 3 => medium
- Rationale: google_compute_subnetwork.app does not configure VPC Flow Logs in this Terraform plan. Without subnetwork flow telemetry, network investigation, lateral-movement review, and egress analysis can lack packet-flow evidence for workloads attached to this subnet.
- Recommended mitigation: Enable VPC Flow Logs on subnetworks that host workloads, keep the flow log configuration in Terraform, and export or retain those logs according to investigation and monitoring requirements.
- Evidence:
  - subnetwork flow log posture: address=google_compute_subnetwork.app; type=google_compute_subnetwork; name=app; identifier=tfstride-app; flow_log_state=not_configured; network=google_compute_network.main.id; project=tfstride-demo

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

#### GCS sensitive bucket retention policy is insufficient

- STRIDE category: Denial of Service
- Affected resources: `google_storage_bucket.logs`
- Trust boundary: `not-applicable`
- Severity reasoning: internet_exposure +0, privilege_breadth +0, data_sensitivity +2, lateral_movement +0, blast_radius +1, final_score 3 => medium
- Rationale: google_storage_bucket.logs does not have deterministic GCS retention posture that meets the minimum retention threshold and lock expectation. Retention policy and retention lock reduce destructive deletion or overwrite risk, but are distinct from soft-delete recovery controls.
- Recommended mitigation: Configure a GCS retention policy that meets recovery and compliance objectives, and lock the retention policy after operational validation. Treat retention lock as immutability posture, not as a replacement for object versioning or soft-delete recovery.
- Evidence:
  - retention policy issues: retention_policy is missing
  - retention policy posture: retention_policy.retention_period_state=missing; minimum_retention_period_days=7; minimum_retention_period_seconds=604800; retention_policy.is_locked is unset

#### GCS sensitive bucket versioning is disabled

- STRIDE category: Denial of Service
- Affected resources: `google_storage_bucket.logs`
- Trust boundary: `not-applicable`
- Severity reasoning: internet_exposure +0, privilege_breadth +0, data_sensitivity +2, lateral_movement +0, blast_radius +1, final_score 3 => medium
- Rationale: google_storage_bucket.logs stores sensitive GCS data without bucket versioning. Accidental overwrites, deletes, or destructive changes have fewer object-level recovery options.
- Recommended mitigation: Enable bucket versioning for sensitive GCS buckets and pair it with lifecycle retention rules that match recovery objectives and storage cost constraints.
- Evidence:
  - data protection posture: versioning.enabled is false; data_sensitivity is sensitive

#### Inherited GCP IAM grant expands descendant blast radius

- STRIDE category: Elevation of Privilege
- Affected resources: `google_project_iam_member.web_viewer`, `google_bigquery_dataset.analytics`, `google_bigquery_table.events`, `google_compute_firewall.public_app`, `google_compute_firewall.public_ssh`, `google_compute_instance.web`, `google_compute_network.main`, `google_compute_route.default_internet`, `google_compute_subnetwork.app`, `google_kms_crypto_key.customer`, `google_logging_project_sink.processor`, `google_pubsub_subscription.events`, `google_pubsub_topic.events`, `google_secret_manager_secret.api_key`, `google_service_account.web`, `google_service_account_key.web`, `google_sql_database_instance.app`, `google_storage_bucket.logs`
- Trust boundary: `not-applicable`
- Severity reasoning: internet_exposure +0, privilege_breadth +1, data_sensitivity +0, lateral_movement +1, blast_radius +2, final_score 4 => medium
- Rationale: google_project_iam_member.web_viewer grants `roles/viewer` to `serviceAccount:tfstride-web@example.iam.gserviceaccount.com` at project scope `tfstride-demo`, and that inherited grant applies to 17 concrete descendant resource(s). A high-level IAM grant with broad, external, or high-impact access increases control-plane blast radius because compromise or misuse can affect resources below the inherited scope.
- Recommended mitigation: Avoid broad or high-impact IAM grants at organization, folder, and project scope when narrower resource-level or workload-specific bindings are possible; split inherited roles by service and review descendant resources before assigning public, external, or administrator principals.
- Evidence:
  - iam binding: source=google_project_iam_member.web_viewer; scope=project:tfstride-demo; member=serviceAccount:tfstride-web@example.iam.gserviceaccount.com; role=roles/viewer
  - trust scope: service account belongs to project `example`, outside resource project `tfstride-demo`
  - descendant scope: scope=project:tfstride-demo; descendant_count=17; resource_type_count=16; projects=tfstride-demo
  - descendant resource types: google_bigquery_dataset: 1; google_bigquery_table: 1; google_compute_firewall: 2; google_compute_instance: 1; google_compute_network: 1; google_compute_route: 1; google_compute_subnetwork: 1; google_kms_crypto_key: 1; google_logging_project_sink: 1; google_pubsub_subscription: 1; google_pubsub_topic: 1; google_secret_manager_secret: 1; google_service_account: 1; google_service_account_key: 1; google_sql_database_instance: 1; google_storage_bucket: 1
  - descendant resources: google_bigquery_dataset.analytics; google_bigquery_table.events; google_compute_firewall.public_app; google_compute_firewall.public_ssh; google_compute_instance.web; google_compute_network.main; google_compute_route.default_internet; google_compute_subnetwork.app; google_kms_crypto_key.customer; google_logging_project_sink.processor; and 7 more descendant resources

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
  - internet ingress reasons: google_compute_firewall.public_ssh ingress tcp 22 from 0.0.0.0/0; google_compute_firewall.public_app ingress tcp 8080 from 0.0.0.0/0
  - public exposure reasons: compute instance has an external access config and matching firewall rules allow internet ingress

#### Pub/Sub subscription does not configure a dead-letter policy

- STRIDE category: Denial of Service
- Affected resources: `google_pubsub_subscription.events`
- Trust boundary: `not-applicable`
- Severity reasoning: internet_exposure +0, privilege_breadth +0, data_sensitivity +2, lateral_movement +0, blast_radius +1, final_score 3 => medium
- Rationale: google_pubsub_subscription.events does not configure a Pub/Sub dead-letter policy. Poison messages or repeated delivery failures can consume subscriber capacity and reduce recovery options for failed processing.
- Recommended mitigation: Configure a reviewed Pub/Sub dead-letter topic and delivery-attempt threshold for subscriptions where poison messages or repeated delivery failures could disrupt processing.
- Evidence:
  - target resource: address=google_pubsub_subscription.events; resource_type=google_pubsub_subscription
  - dead letter posture: dead_letter_policy_state=not_configured; dead_letter_topic=unset

#### Pub/Sub topic does not use customer-managed encryption

- STRIDE category: Information Disclosure
- Affected resources: `google_pubsub_topic.events`
- Trust boundary: `not-applicable`
- Severity reasoning: internet_exposure +0, privilege_breadth +0, data_sensitivity +2, lateral_movement +0, blast_radius +1, final_score 3 => medium
- Rationale: google_pubsub_topic.events relies on Google-managed Pub/Sub encryption rather than a customer-managed Cloud KMS key. Google-managed encryption still protects message data; this finding concerns key ownership, rotation, audit separation, and compliance posture.
- Recommended mitigation: Configure a customer-managed Cloud KMS key for sensitive Pub/Sub topics where key ownership, rotation, audit separation, or compliance requirements warrant it.
- Evidence:
  - target resource: address=google_pubsub_topic.events; resource_type=google_pubsub_topic
  - encryption ownership: cmek_state=not_configured; kms_key_name=unset

#### Secret Manager lifecycle posture is incomplete

- STRIDE category: Denial of Service
- Affected resources: `google_secret_manager_secret.api_key`
- Trust boundary: `not-applicable`
- Severity reasoning: internet_exposure +0, privilege_breadth +0, data_sensitivity +2, lateral_movement +0, blast_radius +1, final_score 3 => medium
- Rationale: google_secret_manager_secret.api_key does not show deterministic Secret Manager lifecycle posture for secret expiry or delayed version destruction. Expiry and version-destroy TTL controls reduce the lifetime of stale or accidentally destroyed secret material, but do not replace access review or rotation.
- Recommended mitigation: Configure Secret Manager `ttl` or `expire_time` where secret-level expiry is expected, and set `version_destroy_ttl` to a retention window that gives operators enough time to recover from accidental or malicious secret version destruction.
- Evidence:
  - target resource: address=google_secret_manager_secret.api_key; type=google_secret_manager_secret; identifier=projects/tfstride-demo/secrets/tfstride-api-key
  - lifecycle issues: secret has no ttl, expire_time, or version_destroy_ttl lifecycle guardrail; version_destroy_ttl is missing
  - lifecycle posture: ttl=unset; expire_time=unset; version_destroy_ttl=unset; minimum_version_destroy_ttl_days=7; minimum_version_destroy_ttl_seconds=604800

#### Secret Manager secret does not use customer-managed encryption

- STRIDE category: Information Disclosure
- Affected resources: `google_secret_manager_secret.api_key`
- Trust boundary: `not-applicable`
- Severity reasoning: internet_exposure +0, privilege_breadth +0, data_sensitivity +2, lateral_movement +0, blast_radius +1, final_score 3 => medium
- Rationale: google_secret_manager_secret.api_key relies on Google-managed Secret Manager encryption rather than a customer-managed Cloud KMS key. Google-managed encryption still applies; this finding concerns customer key ownership, rotation, audit separation, and compliance posture for sensitive secrets.
- Recommended mitigation: Configure Secret Manager replication with Cloud KMS customer-managed encryption for secrets that require customer key ownership, independent rotation, audit separation, or compliance controls.
- Evidence:
  - target resource: address=google_secret_manager_secret.api_key; type=google_secret_manager_secret; identifier=projects/tfstride-demo/secrets/tfstride-api-key
  - encryption ownership: customer_managed_encryption is false; secret_manager_replication_mode=automatic; secret_manager_kms_key_names is empty
  - replication posture: replication.mode=automatic

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
