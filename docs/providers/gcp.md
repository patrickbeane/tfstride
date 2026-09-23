# GCP Provider Coverage

GCP is an actively supported provider, covering Compute Engine/Cloud Run/Cloud Functions edge exposure, workload-to-data paths, Cloud KMS CMEK-backed cryptographic paths, IAM/Workload Identity Federation, and organization-level audit/detection posture.

## Modeled Resources and Families

This is a concise coverage map. Repetitive IAM variants are grouped, and reports identify unsupported Google resource types encountered in each plan.

* `google_compute_instance`
* `google_container_cluster`
* `google_container_node_pool`
* `google_compute_network`
* `google_compute_subnetwork`
* `google_compute_firewall`
* GCP firewall policy, rule, and association resources
* `google_compute_route`
* `google_compute_router`
* `google_compute_router_nat`
* `google_compute_forwarding_rule`
* `google_compute_global_forwarding_rule`
* `google_compute_backend_service`
* `google_compute_region_backend_service`
* `google_compute_backend_bucket`
* Global and regional network endpoint group resources
* Global and regional Cloud Armor security policy resources
* `google_compute_url_map`
* `google_compute_region_url_map`
* `google_compute_target_http_proxy`
* `google_compute_target_https_proxy`
* `google_compute_region_target_http_proxy`
* `google_compute_region_target_https_proxy`
* `google_compute_ssl_policy`
* `google_compute_managed_ssl_certificate`
* `google_compute_service_attachment`
* `google_compute_global_address`
* `google_service_networking_connection`
* `google_network_connectivity_service_connection_policy`
* `google_cloud_run_service`
* `google_cloud_run_v2_service`
* `google_artifact_registry_repository`
* Artifact Registry repository IAM member, binding, and policy resources
* Cloud Run IAM member, binding, and policy resources
* `google_cloudfunctions_function`
* `google_cloudfunctions2_function`
* Cloud Functions IAM member, binding, and policy resources
* `google_project`
* `google_folder` parent links for hierarchical firewall policy ordering
* Organization, folder, and project IAM member, binding, and policy resources
* Organization, folder, and project organization-policy resources
* Project and organization custom IAM roles
* `google_service_account`
* `google_service_account_key`
* GCP service-account IAM member, binding, and policy resources
* `google_iam_workload_identity_pool`
* `google_iam_workload_identity_pool_provider`
* `google_pubsub_topic`
* `google_pubsub_subscription`
* Pub/Sub IAM member, binding, and policy resources
* `google_bigquery_dataset`
* `google_bigquery_table`
* BigQuery dataset and table IAM member, binding, and policy resources
* `google_sql_database_instance`
* `google_firestore_database`
* Firestore database IAM member, binding, and policy resources
* `google_secret_manager_secret`
* `google_secret_manager_secret_version`
* Secret Manager secret IAM member, binding, and policy resources
* `google_kms_key_ring`
* `google_kms_crypto_key`
* `google_kms_crypto_key_version`
* Cloud KMS crypto-key and key-ring IAM member, binding, and policy resources
* `google_storage_bucket`
* GCS bucket IAM member, binding, and policy resources
* `google_logging_project_sink`
* `google_logging_organization_sink`
* `google_logging_project_exclusion`
* `google_logging_organization_exclusion`
* `google_scc_organization_settings`

## Trust Boundaries

GCP trust-boundary coverage includes public compute, GKE control planes, Cloud Run, Cloud Functions, external forwarding rules, Cloud SQL, GCS buckets, Cloud NAT posture, and workload-to-sensitive-data paths through GCE, Cloud Run, and Cloud Functions service accounts.

Hierarchical firewall policies follow modeled attachment scopes and project/folder ancestry, with rule priorities compared only within each policy. The VPC's host project supplies ancestry for Shared VPC workloads. A policy's `parent` identifies its owner, and a rule's `target_resources` restricts its targets; neither establishes an attachment. Missing or ambiguous associations and ancestry remain explicit ingress uncertainty and cannot establish unrestricted fallback to VPC firewall rules.

Firewall policy actions apply to protocol/port subsets independently for IPv4 and IPv6. Allow and deny terminate only matching traffic; `goto_next` delegates only its matching traffic and skips the remaining rules of that policy for that traffic. Other traffic continues through the current policy, and only the surviving traffic reaches VPC rules. Partial or unresolved source-CIDR constraints remain conservative uncertainty for their possible protocol/port subsets; source-CIDR subtraction is not yet modeled.

## Rule Coverage

### Public exposure & edge
* Public compute ingress
* External load balancer HTTP/TLS, SSL-policy, and Cloud Armor edge-protection posture
* GKE public control-plane and authorized-network posture

### Container & image integrity
* Cloud Run images without digest pins
* Exact Artifact Registry mutable-tag correlation, and runtime service accounts with exact Artifact Registry write access to deployed image repositories
* Cloud Run literal sensitive environment values
* Artifact Registry mutable Docker tags, customer-managed encryption, and vulnerability-scanning posture

### Workload-to-data paths
* Exact public Cloud Run-to-Secret Manager, GCS, Pub/Sub, and Firestore read and mutation paths
* Exact public Cloud Run-to-Pub/Sub pull-subscription consume and acknowledgement paths with exact consumer-project and topic ancestry
* Public Cloud Run Pub/Sub topic and subscription topology-deletion paths with exact target and cross-project ancestry
* Public Cloud Run GCS logical-object and generation deletion paths with project/bucket scope and soft-delete/versioning evidence
* Public Cloud Run GCS bucket-topology disruption paths for exact `storage.buckets.delete` authority, with bucket emptiness left unestablished
* Public Cloud Run Firestore entity/bulk-entity deletion and database-topology disruption paths with project/database IAM scope, delete-protection, Terraform deletion policy, and point-in-time-recovery evidence
* Public Cloud Run secret-version tampering and secret/version disruption paths for runtime IAM authority
* Service-account access broader than consumed references
* External or explicitly denied Secret Manager paths stay quiet; condition-dependent, incomplete, ambiguous, or unresolved expected paths remain uncertainty where modeled

### Kubernetes (GKE)
* GKE Workload Identity posture
* Legacy metadata, node identity, control-plane logging, network policy, and secrets encryption posture
* Legacy ABAC, client-certificate auth, Shielded Nodes, and Binary Authorization posture

### Networking & telemetry
* Subnet Flow Logs coverage and capture-completeness posture
* Private Google Access posture for private workloads

### Data-store posture
* Cloud SQL exposure, private-service-access, recovery, zonal availability, Query Insights, and connector-enforcement posture
* Firestore customer-managed encryption, point-in-time recovery, and service delete-protection posture
* GCS public-access, encryption, versioning, soft-delete, and retention posture
* Pub/Sub customer-managed encryption, message retention, acknowledged-message replay, and dead-letter posture
* Secret Manager customer-managed encryption and lifecycle posture

### Cloud KMS & cryptographic paths
* Cloud KMS key and key-version lifecycle, exact key-ring/key ancestry, cryptographic capabilities, IAM source/scope, conditions, and unresolved-policy posture
* Exact CMEK encrypted-resource dependencies and version-aware downstream blast-radius enrichment
* Public Cloud Run decrypt, signing, and MAC-generation paths for compatible key purposes and granted IAM at project, key-ring, or CryptoKey scope
* Public Cloud Run Cloud KMS key-disruption and authorization-delegation paths for deterministic management authority at project, key-ring, or CryptoKey scope

### Audit & detection
* Security Command Center asset-discovery posture
* Logging exclusions that drop audit/security logs, logging sink destination/filter coverage, and central audit sink modeling
* Public Cloud Run service accounts with current `logging.sinks.delete` authority over an exact active, user-managed project sink whose effective export deterministically carries audit/security telemetry, reported as prospective Repudiation risk

### IAM & identity
* Workload Identity Federation provider-condition and principal narrowing
* Broad IAM access to sensitive services, and privileged IAM assignment posture
* Federated privileged service-account access
* Internet-exposed workloads with sensitive data access
* Broad organization/folder/project IAM principals, service-account key hygiene, and custom-role permission expansion

Cloud KMS and Secret Manager lifecycle posture, public workload cryptographic-operation paths, and public workload key or secret administration paths are plan-local and require modeled authorization. See [Public Workload Secret Integrity and Availability Paths](../analysis/secret-management-paths.md).

## Scope & Limitations

* GCP support is broad across core workload, data, Kubernetes, private-connectivity, public-edge TLS/protection, and audit/security-posture checks, but still has limited provider-specific positive observation records compared with its finding coverage.
* Identity-assignment analysis is deterministic and plan-local, focused on modeled IAM bindings/members, custom roles, and Workload Identity Federation pools/providers.
* Messaging findings establish modeled service-account authority, not successful payload retrieval, acknowledgement or topology deletion, replay, or recovery; see [Public Workload Messaging Disclosure and Disruption Paths](../analysis/messaging-paths.md).
* Logging-sink disruption findings establish current authority over an exact modeled sink, not successful deletion, retained/source or already-delivered log deletion, destination-resource deletion, project-wide or out-of-plan disruption, historical audit-log erasure, or recovery/restoration.

See [Cross-Provider Threat-Path Semantics](../analysis/path-semantics.md) for how these findings relate to the shared cross-provider evidence model.
