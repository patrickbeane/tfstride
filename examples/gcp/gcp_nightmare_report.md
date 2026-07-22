# tfSTRIDE Threat Model Report

- Analyzed file: `sample_gcp_nightmare_plan.json`
- Provider: `gcp`
- Normalized resources: `31`
- Unsupported resources: `0`

## Summary

This run identified **9 trust boundaries** and **45 findings** across **31 normalized resources**.

- High severity findings: `14`
- Medium severity findings: `29`
- Low severity findings: `2`

## Analysis Coverage

- Terraform resources seen: `31`
- Provider resources considered: `31`
- Normalized resources: `31`
- Unsupported resources: `0`
- Registered rules: `251`
- Enabled rules: `251`
- Disabled rules: `0`
- Severity overrides: `0`
- Unresolved in-plan references: `0`
- Findings by rule:
  - `gcp-sensitive-resource-iam-external-access`: `2`
  - `gcp-pubsub-public-access`: `1`
  - `gcp-pubsub-topic-customer-managed-encryption-missing`: `1`
  - `gcp-pubsub-subscription-dead-letter-policy-missing`: `1`
  - `gcp-bigquery-public-access`: `1`
  - `gcp-public-workload-sensitive-data-access`: `3`
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
  - `gcp-gke-public-control-plane`: `1`
  - `gcp-gke-broad-authorized-networks`: `1`
  - `gcp-gke-workload-identity-disabled`: `1`
  - `gcp-gke-legacy-metadata-endpoints-enabled`: `1`
  - `gcp-gke-broad-node-service-account`: `1`
  - `gcp-gke-control-plane-logging-incomplete`: `1`
  - `gcp-subnetwork-flow-logs-not-configured`: `1`
  - `gcp-gke-network-policy-disabled`: `1`
  - `gcp-gke-secrets-encryption-not-configured`: `1`
  - `gcp-gke-legacy-abac-enabled-or-unknown`: `1`
  - `gcp-gke-shielded-nodes-disabled-or-unknown`: `1`
  - `gcp-cloud-run-public-invoker`: `1`
  - `gcp-cloud-functions-public-invoker`: `1`
  - `gcp-service-account-key-hygiene`: `1`
  - `gcp-service-account-key-effective-access`: `1`
  - `gcp-org-folder-iam-broad-principal`: `1`
  - `gcp-org-folder-iam-privileged-role`: `1`
  - `gcp-project-iam-broad-principal`: `1`
  - `gcp-project-iam-privileged-role`: `1`
  - `gcp-inherited-iam-sensitive-resource-access`: `1`
  - `gcp-inherited-iam-blast-radius`: `1`

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

- Source: `google_compute_instance.web`
- Target: `google_bigquery_dataset.analytics`
- Description: google_compute_instance.web can interact with google_bigquery_dataset.analytics.
- Rationale: GCP workloads cross into a higher-sensitivity data plane when their attached service account is granted data access through IAM: google_bigquery_dataset_iam_binding.analytics_viewers grants roles/bigquery.dataViewer to serviceAccount:tfstride-web@example.iam.gserviceaccount.com.

### `workload-to-data-store`

- Source: `google_cloud_run_v2_service.api`
- Target: `google_sql_database_instance.app`
- Description: google_cloud_run_v2_service.api can interact with google_sql_database_instance.app.
- Rationale: Application or function workloads cross into a higher-sensitivity data plane when a directly internet-reachable database is reachable from a workload subnet with general egress.

### `workload-to-data-store`

- Source: `google_cloudfunctions_function.worker`
- Target: `google_sql_database_instance.app`
- Description: google_cloudfunctions_function.worker can interact with google_sql_database_instance.app.
- Rationale: Application or function workloads cross into a higher-sensitivity data plane when a directly internet-reachable database is reachable from a workload subnet with general egress.

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

#### GCP project IAM binding grants a high-privilege role

- STRIDE category: Elevation of Privilege
- Affected resources: `google_project_iam_member.public_owner`
- Trust boundary: `not-applicable`
- Severity reasoning: internet_exposure +0, privilege_breadth +2, data_sensitivity +0, lateral_movement +2, blast_radius +2, final_score 6 => high
- Rationale: google_project_iam_member.public_owner grants the high-impact GCP role `roles/owner` to `allUsers` at project scope. That role enables full project administration and can materially expand control-plane blast radius if the principal is compromised or mis-scoped.
- Recommended mitigation: Replace Owner, Editor, IAM admin, service-account impersonation, and admin-class project roles with narrowly scoped predefined or custom roles assigned to specific groups or service accounts.
- Evidence:
  - iam binding: member=allUsers; role=roles/owner
  - role risk: full project administration

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

#### Inherited GCP IAM grant expands descendant blast radius

- STRIDE category: Elevation of Privilege
- Affected resources: `google_project_iam_member.public_owner`, `google_bigquery_dataset.analytics`, `google_bigquery_table.events`, `google_cloud_run_v2_service.api`, `google_cloudfunctions_function.worker`, `google_compute_firewall.public_admin`, `google_compute_firewall.public_all`, `google_compute_instance.web`, `google_compute_network.main`, `google_compute_route.default_internet`, `google_compute_subnetwork.app`, `google_container_cluster.app`, `google_container_node_pool.app`, `google_kms_crypto_key.customer`, `google_logging_project_sink.processor`, `google_pubsub_subscription.events`, `google_pubsub_topic.events`, `google_secret_manager_secret.api_key`, `google_service_account.web`, `google_service_account_key.web`, `google_sql_database_instance.app`, `google_storage_bucket.logs`
- Trust boundary: `not-applicable`
- Severity reasoning: internet_exposure +2, privilege_breadth +2, data_sensitivity +2, lateral_movement +2, blast_radius +2, final_score 10 => high
- Rationale: google_project_iam_member.public_owner grants `roles/owner` to `allUsers` at project scope `tfstride-demo`, and that inherited grant applies to 21 concrete descendant resource(s). A high-level IAM grant with broad, external, or high-impact access increases control-plane blast radius because compromise or misuse can affect resources below the inherited scope.
- Recommended mitigation: Avoid broad or high-impact IAM grants at organization, folder, and project scope when narrower resource-level or workload-specific bindings are possible; split inherited roles by service and review descendant resources before assigning public, external, or administrator principals.
- Evidence:
  - iam binding: source=google_project_iam_member.public_owner; scope=project:tfstride-demo; member=allUsers; role=roles/owner
  - role risk: full project administration
  - trust scope: member is public GCP principal `allUsers`
  - descendant scope: scope=project:tfstride-demo; descendant_count=21; resource_type_count=20; projects=tfstride-demo
  - descendant resource types: google_bigquery_dataset: 1; google_bigquery_table: 1; google_cloud_run_v2_service: 1; google_cloudfunctions_function: 1; google_compute_firewall: 2; google_compute_instance: 1; google_compute_network: 1; google_compute_route: 1; google_compute_subnetwork: 1; google_container_cluster: 1; google_container_node_pool: 1; google_kms_crypto_key: 1; google_logging_project_sink: 1; google_pubsub_subscription: 1; google_pubsub_topic: 1; google_secret_manager_secret: 1; google_service_account: 1; google_service_account_key: 1; google_sql_database_instance: 1; google_storage_bucket: 1
  - descendant resources: google_bigquery_dataset.analytics; google_bigquery_table.events; google_cloud_run_v2_service.api; google_cloudfunctions_function.worker; google_compute_firewall.public_admin; google_compute_firewall.public_all; google_compute_instance.web; google_compute_network.main; google_compute_route.default_internet; google_compute_subnetwork.app; and 11 more descendant resources

#### Inherited GCP IAM grant reaches sensitive resources

- STRIDE category: Information Disclosure
- Affected resources: `google_project_iam_member.public_owner`, `google_bigquery_dataset.analytics`, `google_bigquery_table.events`, `google_kms_crypto_key.customer`, `google_pubsub_subscription.events`, `google_pubsub_topic.events`, `google_secret_manager_secret.api_key`, `google_sql_database_instance.app`, `google_storage_bucket.logs`
- Trust boundary: `not-applicable`
- Severity reasoning: internet_exposure +2, privilege_breadth +2, data_sensitivity +2, lateral_movement +1, blast_radius +2, final_score 9 => high
- Rationale: google_project_iam_member.public_owner grants `roles/owner` to `allUsers` at project scope `tfstride-demo`, and that inherited grant reaches 8 sensitive GCP descendant resource(s). Project, folder, and organization IAM applies below the grant scope, so a single ancestor binding can expose data resources beyond their local IAM boundary.
- Recommended mitigation: Move sensitive data access off organization, folder, and project-level IAM where possible; grant Secret Manager, KMS, GCS, Cloud SQL, BigQuery, and Pub/Sub permissions at the narrowest resource scope with reviewed principals and custom roles.
- Evidence:
  - iam binding: source=google_project_iam_member.public_owner; scope=project:tfstride-demo; member=allUsers; role=roles/owner
  - sensitive descendants: resource=google_bigquery_dataset.analytics; type=google_bigquery_dataset; risk=BigQuery dataset data access through roles/owner; resource=google_bigquery_table.events; type=google_bigquery_table; risk=BigQuery table data access through roles/owner; resource=google_kms_crypto_key.customer; type=google_kms_crypto_key; risk=Cloud KMS cryptographic key access through roles/owner; resource=google_pubsub_subscription.events; type=google_pubsub_subscription; risk=Pub/Sub subscription data access through roles/owner; resource=google_pubsub_topic.events; type=google_pubsub_topic; risk=Pub/Sub topic data access through roles/owner; resource=google_secret_manager_secret.api_key; type=google_secret_manager_secret; risk=Secret Manager secret access through roles/owner; resource=google_sql_database_instance.app; type=google_sql_database_instance; risk=Cloud SQL client/admin access through roles/owner; resource=google_storage_bucket.logs; type=google_storage_bucket; risk=GCS object data access through roles/owner
  - trust scope: member is public GCP principal `allUsers`

#### Internet-exposed GCP workload can access sensitive data services

- STRIDE category: Information Disclosure
- Affected resources: `google_cloud_run_v2_service.api`, `google_sql_database_instance.app`
- Trust boundary: `workload-to-data-store:google_cloud_run_v2_service.api->google_sql_database_instance.app`
- Severity reasoning: internet_exposure +2, privilege_breadth +1, data_sensitivity +2, lateral_movement +1, blast_radius +1, final_score 7 => high
- Rationale: google_cloud_run_v2_service.api is internet-exposed and runs with GCP workload identity serviceAccount:tfstride-run@tfstride-demo.iam.gserviceaccount.com. That identity can access google_sql_database_instance.app. A compromise of the public workload can therefore become direct access to sensitive GCP data services.
- Recommended mitigation: Run public GCP workloads with narrowly scoped service accounts, remove direct Secret Manager, Cloud KMS, GCS, or Cloud SQL grants from internet-facing instances, and broker sensitive data access through private services where possible.
- Evidence:
  - public exposure reasons: google_cloud_run_v2_service_iam_member.public_invoker grants roles/run.invoker to allUsers
  - workload identity: serviceAccount:tfstride-run@tfstride-demo.iam.gserviceaccount.com
  - data access path: google_cloud_run_v2_service.api reaches google_sql_database_instance.app
  - boundary rationale: Application or function workloads cross into a higher-sensitivity data plane when a directly internet-reachable database is reachable from a workload subnet with general egress.

#### Internet-exposed GCP workload can access sensitive data services

- STRIDE category: Information Disclosure
- Affected resources: `google_cloudfunctions_function.worker`, `google_sql_database_instance.app`
- Trust boundary: `workload-to-data-store:google_cloudfunctions_function.worker->google_sql_database_instance.app`
- Severity reasoning: internet_exposure +2, privilege_breadth +1, data_sensitivity +2, lateral_movement +1, blast_radius +1, final_score 7 => high
- Rationale: google_cloudfunctions_function.worker is internet-exposed and runs with GCP workload identity serviceAccount:tfstride-fn@tfstride-demo.iam.gserviceaccount.com. That identity can access google_sql_database_instance.app. A compromise of the public workload can therefore become direct access to sensitive GCP data services.
- Recommended mitigation: Run public GCP workloads with narrowly scoped service accounts, remove direct Secret Manager, Cloud KMS, GCS, or Cloud SQL grants from internet-facing instances, and broker sensitive data access through private services where possible.
- Evidence:
  - public exposure reasons: google_cloudfunctions_function_iam_member.public_invoker grants roles/cloudfunctions.invoker to allAuthenticatedUsers
  - workload identity: serviceAccount:tfstride-fn@tfstride-demo.iam.gserviceaccount.com
  - data access path: google_cloudfunctions_function.worker reaches google_sql_database_instance.app
  - boundary rationale: Application or function workloads cross into a higher-sensitivity data plane when a directly internet-reachable database is reachable from a workload subnet with general egress.

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

#### GCP project IAM binding grants access to public principals

- STRIDE category: Elevation of Privilege
- Affected resources: `google_project_iam_member.public_owner`
- Trust boundary: `not-applicable`
- Severity reasoning: internet_exposure +2, privilege_breadth +1, data_sensitivity +0, lateral_movement +1, blast_radius +1, final_score 5 => medium
- Rationale: google_project_iam_member.public_owner grants `roles/owner` to `allUsers` at project scope. Public or broadly authenticated principals can cross into the control plane without an organization-owned identity boundary.
- Recommended mitigation: Remove `allUsers` and `allAuthenticatedUsers` from project-level IAM bindings, grant access to specific groups or service accounts, and scope permissions to the smallest project or resource needed.
- Evidence:
  - iam binding: member=allUsers; role=roles/owner

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

#### GKE control-plane logging is incomplete

- STRIDE category: Repudiation
- Affected resources: `google_container_cluster.app`
- Trust boundary: `not-applicable`
- Severity reasoning: internet_exposure +0, privilege_breadth +0, data_sensitivity +0, lateral_movement +2, blast_radius +1, final_score 3 => medium
- Rationale: google_container_cluster.app does not show deterministic GKE control-plane logging for key security components. Missing API server, scheduler, or controller manager logs can limit investigation of administrative and cluster-control activity.
- Recommended mitigation: Enable GKE control-plane logging for security-relevant components such as the API server, scheduler, and controller manager, and retain the logs in a monitored logging project.
- Evidence:
  - logging posture: control_plane_logging_state=not_configured; logging_service is not represented in planned values; logging_components are not represented in planned values; control-plane logging is not_configured

#### GKE network policy is not enabled

- STRIDE category: Tampering
- Affected resources: `google_container_cluster.app`
- Trust boundary: `not-applicable`
- Severity reasoning: internet_exposure +0, privilege_breadth +0, data_sensitivity +0, lateral_movement +2, blast_radius +1, final_score 3 => medium
- Rationale: google_container_cluster.app does not deterministically enable GKE network policy. Without a pod network policy provider, Kubernetes workloads have weaker pod-level traffic isolation and lateral-movement controls.
- Recommended mitigation: Enable a supported GKE network policy provider and define namespace or workload policies that restrict pod-to-pod and pod-to-service traffic paths.
- Evidence:
  - network policy posture: network_policy_state=not_configured; network_policy_provider is not represented in planned values

#### GKE node metadata exposure is not hardened

- STRIDE category: Elevation of Privilege
- Affected resources: `google_container_node_pool.app`
- Trust boundary: `not-applicable`
- Severity reasoning: internet_exposure +0, privilege_breadth +1, data_sensitivity +0, lateral_movement +1, blast_radius +1, final_score 3 => medium
- Rationale: google_container_node_pool.app allows legacy or broad node metadata exposure. Workloads on the node may be able to reach metadata credentials outside the intended GKE metadata server controls.
- Recommended mitigation: Disable legacy metadata endpoints, use GKE metadata server or Workload Identity controls, and prevent pods from reaching broad node credentials.
- Evidence:
  - node metadata posture: legacy metadata endpoints are enabled; metadata mode is GCE_METADATA

#### GKE secrets encryption is not configured

- STRIDE category: Information Disclosure
- Affected resources: `google_container_cluster.app`
- Trust boundary: `not-applicable`
- Severity reasoning: internet_exposure +0, privilege_breadth +0, data_sensitivity +2, lateral_movement +0, blast_radius +1, final_score 3 => medium
- Rationale: google_container_cluster.app does not show deterministic GKE application-layer secrets encryption with a Cloud KMS key. Kubernetes secrets may not have customer-controlled encryption key ownership represented in the Terraform plan.
- Recommended mitigation: Configure GKE application-layer secrets encryption with a Cloud KMS key where customer key ownership or stronger Kubernetes secret protection is required.
- Evidence:
  - secret encryption posture: secrets_encryption_state=disabled; database_encryption_state is not represented in planned values; database_encryption_key_name is not represented in planned values

#### Internet-exposed GCP compute instance permits broad ingress

- STRIDE category: Spoofing
- Affected resources: `google_compute_instance.web`, `google_compute_firewall.public_admin`
- Trust boundary: `internet-to-service:internet->google_compute_instance.web`
- Severity reasoning: internet_exposure +2, privilege_breadth +0, data_sensitivity +0, lateral_movement +1, blast_radius +1, final_score 4 => medium
- Rationale: google_compute_instance.web has an external access config and matching GCP firewall rules allow administrative access or all ports from the public internet. That broad ingress raises the chance of unauthenticated probing and credential attacks.
- Recommended mitigation: Restrict GCP firewall source ranges and exposed ports, remove external IP access where possible, and use Identity-Aware Proxy, VPN, or a controlled bastion for administration.
- Evidence:
  - firewall rules: google_compute_firewall.public_admin ingress tcp 22 from 0.0.0.0/0; google_compute_firewall.public_admin ingress tcp 3389 from 0.0.0.0/0
  - network tags: web
  - internet ingress reasons: google_compute_firewall.public_admin ingress tcp 22 from 0.0.0.0/0; google_compute_firewall.public_admin ingress tcp 3389 from 0.0.0.0/0; google_compute_firewall.public_all ingress tcp unspecified ports from 0.0.0.0/0
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

#### GKE Shielded Nodes is not enabled

- STRIDE category: Tampering
- Affected resources: `google_container_cluster.app`
- Trust boundary: `not-applicable`
- Severity reasoning: internet_exposure +0, privilege_breadth +0, data_sensitivity +0, lateral_movement +0, blast_radius +1, final_score 1 => low
- Rationale: google_container_cluster.app does not show GKE Shielded Nodes enabled. Shielded Nodes add node integrity protections that reduce the impact of boot-level tampering and host compromise paths.
- Recommended mitigation: Enable GKE Shielded Nodes to add node integrity protections against boot-level tampering and host compromise paths.
- Evidence:
  - shielded nodes posture: shielded_nodes_state=unknown; shielded nodes setting is not represented in planned values

#### GKE legacy ABAC is enabled or unknown

- STRIDE category: Elevation of Privilege
- Affected resources: `google_container_cluster.app`
- Trust boundary: `not-applicable`
- Severity reasoning: internet_exposure +0, privilege_breadth +0, data_sensitivity +0, lateral_movement +0, blast_radius +1, final_score 1 => low
- Rationale: google_container_cluster.app does not show legacy ABAC disabled. Legacy ABAC can bypass stronger IAM and Kubernetes RBAC expectations, and an unknown Terraform value should be reviewed before relying on RBAC-only authorization.
- Recommended mitigation: Disable legacy ABAC and rely on Kubernetes RBAC with centralized IAM-backed administration. Review unknown ABAC values before treating the cluster authorization posture as hardened.
- Evidence:
  - legacy abac posture: legacy_abac_state=unknown; enable_legacy_abac is not represented in planned values

## Limitations / Unsupported Resources

- GCP support covers a curated set of compute, serverless, data, IAM, Kubernetes, networking, audit, private-connectivity, messaging, registry, and key-management resources. Analysis is plan-local and does not model every provider resource, runtime drift, or every organization-level control; provider-specific positive observations remain more limited than finding coverage.
- The engine reasons over Terraform planned values only and does not validate runtime drift, CloudTrail evidence, or post-deploy control-plane activity.
