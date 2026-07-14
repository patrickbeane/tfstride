from __future__ import annotations

from tfstride.analysis.rule_registry import RuleMetadata
from tfstride.models import StrideCategory

GCP_RULE_METADATA = (
    RuleMetadata(
        rule_id="gcp-sensitive-resource-iam-external-access",
        title="Sensitive GCP resource IAM binding allows broad or external access",
        category=StrideCategory.INFORMATION_DISCLOSURE,
        recommended_mitigation=(
            "Grant Secret Manager and Cloud KMS IAM roles only to specific in-project service accounts or groups, "
            "remove public principals, and require explicit cross-project access reviews for partner identities."
        ),
        tags=("gcp", "iam", "secret-manager", "kms", "resource-policy"),
        severity_factors=("internet_exposure", "privilege_breadth", "data_sensitivity", "blast_radius"),
    ),
    RuleMetadata(
        rule_id="gcp-pubsub-public-access",
        title="Pub/Sub IAM binding allows public or broad data access",
        category=StrideCategory.INFORMATION_DISCLOSURE,
        recommended_mitigation=(
            "Grant Pub/Sub publisher and subscriber roles only to specific service accounts or groups, "
            "remove public principals, and separate publish and consume permissions by workload."
        ),
        tags=("gcp", "pubsub", "iam", "public-access"),
        severity_factors=("internet_exposure", "privilege_breadth", "data_sensitivity", "blast_radius"),
    ),
    RuleMetadata(
        rule_id="gcp-pubsub-topic-customer-managed-encryption-missing",
        title="Pub/Sub topic does not use customer-managed encryption",
        category=StrideCategory.INFORMATION_DISCLOSURE,
        recommended_mitigation=(
            "Configure a customer-managed Cloud KMS key for sensitive Pub/Sub topics where key ownership, "
            "rotation, audit separation, or compliance requirements warrant it."
        ),
        tags=("gcp", "pubsub", "encryption", "cmek"),
        severity_factors=("data_sensitivity", "blast_radius"),
    ),
    RuleMetadata(
        rule_id="gcp-pubsub-message-retention-insufficient",
        title="Pub/Sub message retention is below the recovery baseline",
        category=StrideCategory.DENIAL_OF_SERVICE,
        recommended_mitigation=(
            "Configure Pub/Sub topic or subscription message retention to meet the workload recovery objective, "
            "including enough time to replay messages after subscriber failures or destructive changes."
        ),
        tags=("gcp", "pubsub", "retention", "recovery"),
        severity_factors=("data_sensitivity", "blast_radius"),
    ),
    RuleMetadata(
        rule_id="gcp-pubsub-subscription-dead-letter-policy-missing",
        title="Pub/Sub subscription does not configure a dead-letter policy",
        category=StrideCategory.DENIAL_OF_SERVICE,
        recommended_mitigation=(
            "Configure a reviewed Pub/Sub dead-letter topic and delivery-attempt threshold for subscriptions "
            "where poison messages or repeated delivery failures could disrupt processing."
        ),
        tags=("gcp", "pubsub", "dead-letter", "recovery"),
        severity_factors=("data_sensitivity", "blast_radius"),
    ),
    RuleMetadata(
        rule_id="gcp-bigquery-public-access",
        title="BigQuery IAM binding allows public or broad data access",
        category=StrideCategory.INFORMATION_DISCLOSURE,
        recommended_mitigation=(
            "Grant BigQuery dataset and table access only to specific in-project identities or reviewed "
            "analytics groups, remove public principals, and prefer least-privilege data roles."
        ),
        tags=("gcp", "bigquery", "iam", "public-access"),
        severity_factors=("internet_exposure", "privilege_breadth", "data_sensitivity", "blast_radius"),
    ),
    RuleMetadata(
        rule_id="gcp-public-workload-sensitive-data-access",
        title="Internet-exposed GCP workload can access sensitive data services",
        category=StrideCategory.INFORMATION_DISCLOSURE,
        recommended_mitigation=(
            "Run public GCP workloads with narrowly scoped service accounts, remove direct Secret Manager, "
            "Cloud KMS, GCS, or Cloud SQL grants from internet-facing instances, and broker sensitive data "
            "access through private services where possible."
        ),
        tags=("gcp", "compute", "iam", "data", "transitive-path"),
        severity_factors=(
            "internet_exposure",
            "privilege_breadth",
            "data_sensitivity",
            "lateral_movement",
            "blast_radius",
        ),
    ),
    RuleMetadata(
        rule_id="gcp-cloud-sql-public-authorized-network",
        title="Cloud SQL instance accepts public authorized network access",
        category=StrideCategory.INFORMATION_DISCLOSURE,
        recommended_mitigation=(
            "Disable public IPv4 access where possible, use private IP connectivity or the Cloud SQL Auth Proxy, "
            "and restrict authorized networks to narrow CIDRs when public client access is required."
        ),
        tags=("gcp", "cloud-sql", "database", "network", "public-access"),
        severity_factors=("internet_exposure", "data_sensitivity", "lateral_movement", "blast_radius"),
    ),
    RuleMetadata(
        rule_id="gcp-cloud-sql-backup-disabled",
        title="Cloud SQL automated backups are disabled",
        category=StrideCategory.DENIAL_OF_SERVICE,
        recommended_mitigation=(
            "Enable automated backups for Cloud SQL instances, configure retention appropriate to the workload, "
            "and enable point-in-time recovery where supported."
        ),
        tags=("gcp", "cloud-sql", "database", "backup"),
        severity_factors=("data_sensitivity", "blast_radius"),
    ),
    RuleMetadata(
        rule_id="gcp-cloud-sql-public-ip-without-private-network",
        title="Cloud SQL public IPv4 is enabled without private network access",
        category=StrideCategory.INFORMATION_DISCLOSURE,
        recommended_mitigation=(
            "Disable public IPv4 where possible, attach the instance to a private network, and route clients "
            "through private IP, the Cloud SQL Auth Proxy, or tightly controlled connectivity paths."
        ),
        tags=("gcp", "cloud-sql", "database", "network", "public-access"),
        severity_factors=("internet_exposure", "data_sensitivity", "lateral_movement"),
    ),
    RuleMetadata(
        rule_id="gcp-cloud-sql-ssl-not-required",
        title="Cloud SQL public client access does not require SSL",
        category=StrideCategory.INFORMATION_DISCLOSURE,
        recommended_mitigation=(
            "Require encrypted Cloud SQL client connections with `require_ssl` or an enforcing `ssl_mode`, "
            "and prefer private IP or the Cloud SQL Auth Proxy for application connectivity."
        ),
        tags=("gcp", "cloud-sql", "database", "tls"),
        severity_factors=("internet_exposure", "data_sensitivity", "lateral_movement"),
    ),
    RuleMetadata(
        rule_id="gcp-cloud-sql-point-in-time-recovery-disabled",
        title="Cloud SQL point-in-time recovery is disabled",
        category=StrideCategory.DENIAL_OF_SERVICE,
        recommended_mitigation=(
            "Enable point-in-time recovery for Cloud SQL engines that support it, tune retention to recovery "
            "objectives, and test restore workflows for destructive-write scenarios."
        ),
        tags=("gcp", "cloud-sql", "database", "backup", "recovery"),
        severity_factors=("data_sensitivity", "blast_radius"),
    ),
    RuleMetadata(
        rule_id="gcp-cloud-sql-deletion-protection-disabled",
        title="Cloud SQL deletion protection is disabled",
        category=StrideCategory.DENIAL_OF_SERVICE,
        recommended_mitigation=(
            "Enable Cloud SQL deletion protection for persistent environments and require explicit review "
            "before disabling it during planned database retirement."
        ),
        tags=("gcp", "cloud-sql", "database", "lifecycle"),
        severity_factors=("data_sensitivity", "blast_radius"),
    ),
    RuleMetadata(
        rule_id="gcp-cloud-sql-zonal-availability",
        title="Cloud SQL instance uses zonal availability",
        category=StrideCategory.DENIAL_OF_SERVICE,
        recommended_mitigation=(
            "Use `REGIONAL` availability for production Cloud SQL instances that require higher availability, "
            "then validate application failover behavior and recovery objectives."
        ),
        tags=("gcp", "cloud-sql", "database", "availability", "resilience"),
        severity_factors=("data_sensitivity", "blast_radius"),
    ),
    RuleMetadata(
        rule_id="gcp-cloud-sql-query-insights-disabled",
        title="Cloud SQL Query Insights is disabled",
        category=StrideCategory.REPUDIATION,
        recommended_mitigation=(
            "Enable Cloud SQL Query Insights for production databases and retain query telemetry according to "
            "the organization's privacy, performance, and incident-response requirements."
        ),
        tags=("gcp", "cloud-sql", "database", "observability", "query-insights"),
        severity_factors=("data_sensitivity", "lateral_movement"),
    ),
    RuleMetadata(
        rule_id="gcp-cloud-sql-connector-enforcement-not-required",
        title="Cloud SQL does not require connector-based client access",
        category=StrideCategory.INFORMATION_DISCLOSURE,
        recommended_mitigation=(
            "Set Cloud SQL `connector_enforcement` to `REQUIRED` where workloads should use Cloud SQL connectors "
            "or the Auth Proxy, and combine it with private networking and narrowly scoped database identities."
        ),
        tags=("gcp", "cloud-sql", "database", "connectivity", "connectors"),
        severity_factors=("data_sensitivity", "lateral_movement"),
    ),
    RuleMetadata(
        rule_id="gcp-cloud-sql-private-connectivity-not-modeled",
        title="Cloud SQL private network lacks modeled private service access",
        category=StrideCategory.INFORMATION_DISCLOSURE,
        recommended_mitigation=(
            "Model the Private Service Access connection or Cloud SQL Private Service Connect policy for the "
            "Cloud SQL private network in Terraform, or attach review evidence showing that private connectivity "
            "is managed outside this plan. Disable public IPv4 where private connectivity should be mandatory."
        ),
        tags=("gcp", "cloud-sql", "database", "private-connectivity", "private-service-access"),
        severity_factors=("internet_exposure", "data_sensitivity", "lateral_movement"),
    ),
    RuleMetadata(
        rule_id="gcp-private-workload-private-google-access-disabled",
        title="Private GCP workload subnet disables Private Google Access",
        category=StrideCategory.INFORMATION_DISCLOSURE,
        recommended_mitigation=(
            "Enable Private Google Access on private subnets used by workloads that call Google APIs, or model "
            "Private Service Connect/Private Service Access coverage where applicable. Avoid relying on NAT or "
            "other public egress paths for sensitive Google API access unless that path is intentional and reviewed."
        ),
        tags=("gcp", "network", "private-google-access", "private-connectivity", "data-access"),
        severity_factors=("privilege_breadth", "data_sensitivity", "lateral_movement", "blast_radius"),
    ),
    RuleMetadata(
        rule_id="gcp-gcs-public-access",
        title="GCS bucket is publicly accessible",
        category=StrideCategory.INFORMATION_DISCLOSURE,
        recommended_mitigation=(
            "Remove `allUsers` and `allAuthenticatedUsers` from bucket-level IAM grants, enforce "
            "GCS Public Access Prevention, and use signed URLs, CDN origins, or narrow identities when "
            "objects must be distributed."
        ),
        tags=("gcp", "gcs", "storage", "public-access"),
        severity_factors=("internet_exposure", "data_sensitivity", "blast_radius"),
    ),
    RuleMetadata(
        rule_id="gcp-gcs-uniform-bucket-level-access-disabled",
        title="GCS bucket does not enforce uniform bucket-level access",
        category=StrideCategory.ELEVATION_OF_PRIVILEGE,
        recommended_mitigation=(
            "Enable uniform bucket-level access so object ACLs cannot bypass bucket IAM, and migrate "
            "legacy object ACL permissions into explicit bucket-level IAM bindings."
        ),
        tags=("gcp", "gcs", "storage", "iam"),
        severity_factors=("privilege_breadth", "data_sensitivity", "blast_radius"),
    ),
    RuleMetadata(
        rule_id="gcp-gcs-public-access-prevention-not-enforced",
        title="GCS bucket does not enforce Public Access Prevention",
        category=StrideCategory.INFORMATION_DISCLOSURE,
        recommended_mitigation=(
            "Set GCS Public Access Prevention to `enforced` on sensitive buckets and rely on explicit "
            "non-public identities or signed access patterns when objects must be shared."
        ),
        tags=("gcp", "gcs", "storage", "public-access"),
        severity_factors=("internet_exposure", "data_sensitivity", "blast_radius"),
    ),
    RuleMetadata(
        rule_id="gcp-gcs-versioning-disabled",
        title="GCS sensitive bucket versioning is disabled",
        category=StrideCategory.DENIAL_OF_SERVICE,
        recommended_mitigation=(
            "Enable bucket versioning for sensitive GCS buckets and pair it with lifecycle retention rules "
            "that match recovery objectives and storage cost constraints."
        ),
        tags=("gcp", "gcs", "storage", "recovery"),
        severity_factors=("data_sensitivity", "blast_radius"),
    ),
    RuleMetadata(
        rule_id="gcp-gcs-customer-managed-encryption-missing",
        title="GCS sensitive bucket does not use customer-managed encryption",
        category=StrideCategory.INFORMATION_DISCLOSURE,
        recommended_mitigation=(
            "Configure a Cloud KMS customer-managed key for sensitive GCS buckets, assign the GCS service "
            "agent only the key roles it needs, and manage key rotation separately from bucket IAM."
        ),
        tags=("gcp", "gcs", "storage", "kms", "encryption"),
        severity_factors=("data_sensitivity", "blast_radius"),
    ),
    RuleMetadata(
        rule_id="gcp-gcs-retention-policy-insufficient",
        title="GCS sensitive bucket retention policy is insufficient",
        category=StrideCategory.DENIAL_OF_SERVICE,
        recommended_mitigation=(
            "Configure a GCS retention policy that meets recovery and compliance objectives, and lock the "
            "retention policy after operational validation. Treat retention lock as immutability posture, not "
            "as a replacement for object versioning or soft-delete recovery."
        ),
        tags=("gcp", "gcs", "storage", "retention", "immutability"),
        severity_factors=("data_sensitivity", "blast_radius"),
    ),
    RuleMetadata(
        rule_id="gcp-secret-manager-customer-managed-encryption-missing",
        title="Secret Manager secret does not use customer-managed encryption",
        category=StrideCategory.INFORMATION_DISCLOSURE,
        recommended_mitigation=(
            "Configure Secret Manager replication with Cloud KMS customer-managed encryption for secrets that "
            "require customer key ownership, independent rotation, audit separation, or compliance controls."
        ),
        tags=("gcp", "secret-manager", "secrets", "kms", "encryption"),
        severity_factors=("data_sensitivity", "blast_radius"),
    ),
    RuleMetadata(
        rule_id="gcp-secret-manager-lifecycle-posture-incomplete",
        title="Secret Manager lifecycle posture is incomplete",
        category=StrideCategory.DENIAL_OF_SERVICE,
        recommended_mitigation=(
            "Configure Secret Manager `ttl` or `expire_time` where secret-level expiry is expected, and set "
            "`version_destroy_ttl` to a retention window that gives operators enough time to recover from accidental "
            "or malicious secret version destruction."
        ),
        tags=("gcp", "secret-manager", "secrets", "lifecycle", "recovery"),
        severity_factors=("data_sensitivity", "blast_radius"),
    ),
    RuleMetadata(
        rule_id="gcp-kms-key-rotation-not-configured-or-too-long",
        title="Cloud KMS key rotation is missing or too infrequent",
        category=StrideCategory.INFORMATION_DISCLOSURE,
        recommended_mitigation=(
            "Configure `rotation_period` for symmetric Cloud KMS crypto keys and keep the interval aligned to "
            "the organization key lifecycle policy, such as 90 days or less for keys protecting sensitive data."
        ),
        tags=("gcp", "kms", "encryption", "rotation", "lifecycle"),
        severity_factors=("data_sensitivity", "blast_radius"),
    ),
    RuleMetadata(
        rule_id="gcp-kms-key-destroy-scheduled-duration-too-short",
        title="Cloud KMS key-version destruction schedule is too short",
        category=StrideCategory.DENIAL_OF_SERVICE,
        recommended_mitigation=(
            "Configure `destroy_scheduled_duration` for Cloud KMS crypto keys to give operators enough "
            "time to cancel accidental or malicious key version destruction before it completes."
        ),
        tags=("gcp", "kms", "encryption", "recovery", "lifecycle"),
        severity_factors=("data_sensitivity", "blast_radius"),
    ),
    RuleMetadata(
        rule_id="gcp-public-compute-broad-ingress",
        title="Internet-exposed GCP compute instance permits broad ingress",
        category=StrideCategory.SPOOFING,
        recommended_mitigation=(
            "Restrict GCP firewall source ranges and exposed ports, remove external IP access where possible, "
            "and use Identity-Aware Proxy, VPN, or a controlled bastion for administration."
        ),
        tags=("gcp", "network", "compute", "internet"),
        severity_factors=("internet_exposure", "lateral_movement", "blast_radius"),
    ),
    RuleMetadata(
        rule_id="gcp-public-load-balanced-workload",
        title="GCP workload is exposed through a public load balancer",
        category=StrideCategory.SPOOFING,
        recommended_mitigation=(
            "Review public forwarding rules, URL maps, backend services, backend buckets, and NEGs that route "
            "to this resource. Require authentication or edge policy controls where public access is intended, "
            "and restrict or remove public load balancer frontends where it is not."
        ),
        tags=("gcp", "load-balancer", "compute", "serverless", "public-access"),
        severity_factors=("internet_exposure", "data_sensitivity", "lateral_movement", "blast_radius"),
    ),
    RuleMetadata(
        rule_id="gcp-load-balancer-http-public-proxy",
        title="Public GCP load balancer frontend uses plaintext HTTP",
        category=StrideCategory.INFORMATION_DISCLOSURE,
        recommended_mitigation=(
            "Terminate HTTPS on public GCP load balancer frontends, redirect HTTP to HTTPS where possible, "
            "and keep plaintext target proxies internal or behind another explicit TLS termination layer."
        ),
        tags=("gcp", "load-balancer", "tls", "http", "public-access"),
        severity_factors=("internet_exposure", "lateral_movement", "blast_radius"),
    ),
    RuleMetadata(
        rule_id="gcp-load-balancer-ssl-policy-missing-or-weak",
        title="Public GCP HTTPS load balancer has missing or weak SSL policy",
        category=StrideCategory.INFORMATION_DISCLOSURE,
        recommended_mitigation=(
            "Attach a GCP SSL policy to public HTTPS target proxies, require TLS 1.2 or newer, and keep the "
            "policy resource deterministic in Terraform so public edge TLS posture is reviewable."
        ),
        tags=("gcp", "load-balancer", "tls", "ssl-policy", "public-access"),
        severity_factors=("internet_exposure", "blast_radius"),
    ),
    RuleMetadata(
        rule_id="gcp-public-load-balancer-cloud-armor-missing",
        title="Public GCP load balancer backend lacks Cloud Armor policy",
        category=StrideCategory.TAMPERING,
        recommended_mitigation=(
            "Attach a Cloud Armor security policy or edge security policy to public GCP backend services and keep "
            "the policy reference deterministic in Terraform so public edge protection is reviewable."
        ),
        tags=("gcp", "load-balancer", "cloud-armor", "waf", "public-edge"),
        severity_factors=("internet_exposure", "lateral_movement", "blast_radius"),
    ),
    RuleMetadata(
        rule_id="gcp-compute-os-login-disabled",
        title="GCP compute instance disables OS Login",
        category=StrideCategory.ELEVATION_OF_PRIVILEGE,
        recommended_mitigation=(
            "Enable OS Login on GCE instances and manage SSH access through IAM roles, "
            "two-factor enforcement, and centralized audit logs instead of metadata SSH keys."
        ),
        tags=("gcp", "compute", "iam", "ssh"),
        severity_factors=("privilege_breadth", "lateral_movement", "blast_radius"),
    ),
    RuleMetadata(
        rule_id="gcp-gke-public-control-plane",
        title="GKE cluster exposes a public control plane",
        category=StrideCategory.SPOOFING,
        recommended_mitigation=(
            "Use private GKE control-plane endpoints where possible, or restrict master authorized networks "
            "to narrow administrator CIDRs and enforce IAM plus Kubernetes RBAC for cluster administration."
        ),
        tags=("gcp", "gke", "kubernetes", "public-access"),
        severity_factors=("internet_exposure", "lateral_movement", "blast_radius"),
    ),
    RuleMetadata(
        rule_id="gcp-gke-broad-authorized-networks",
        title="GKE control plane allows broad authorized networks",
        category=StrideCategory.SPOOFING,
        recommended_mitigation=(
            "Configure GKE master authorized networks with narrow trusted CIDRs, avoid internet-wide ranges, "
            "and prefer private control-plane access for administrative paths."
        ),
        tags=("gcp", "gke", "kubernetes", "network", "public-access"),
        severity_factors=("internet_exposure", "lateral_movement", "blast_radius"),
    ),
    RuleMetadata(
        rule_id="gcp-gke-workload-identity-disabled",
        title="GKE cluster does not enable Workload Identity",
        category=StrideCategory.ELEVATION_OF_PRIVILEGE,
        recommended_mitigation=(
            "Enable GKE Workload Identity, bind Kubernetes service accounts to narrow Google service accounts, "
            "and avoid relying on node service-account credentials for pod-level cloud API access."
        ),
        tags=("gcp", "gke", "kubernetes", "iam"),
        severity_factors=("privilege_breadth", "lateral_movement", "blast_radius"),
    ),
    RuleMetadata(
        rule_id="gcp-gke-legacy-metadata-endpoints-enabled",
        title="GKE node metadata exposure is not hardened",
        category=StrideCategory.ELEVATION_OF_PRIVILEGE,
        recommended_mitigation=(
            "Disable legacy metadata endpoints, use GKE metadata server or Workload Identity controls, "
            "and prevent pods from reaching broad node credentials."
        ),
        tags=("gcp", "gke", "kubernetes", "metadata", "iam"),
        severity_factors=("privilege_breadth", "lateral_movement", "blast_radius"),
    ),
    RuleMetadata(
        rule_id="gcp-gke-broad-node-service-account",
        title="GKE node pool uses broad node identity settings",
        category=StrideCategory.ELEVATION_OF_PRIVILEGE,
        recommended_mitigation=(
            "Attach a dedicated least-privilege node service account, remove cloud-platform or full-control "
            "OAuth scopes, and shift workload permissions to Workload Identity bindings."
        ),
        tags=("gcp", "gke", "kubernetes", "iam", "node-pool"),
        severity_factors=("privilege_breadth", "lateral_movement", "blast_radius"),
    ),
    RuleMetadata(
        rule_id="gcp-gke-control-plane-logging-incomplete",
        title="GKE control-plane logging is incomplete",
        category=StrideCategory.REPUDIATION,
        recommended_mitigation=(
            "Enable GKE control-plane logging for security-relevant components such as the API server, scheduler, "
            "and controller manager, and retain the logs in a monitored logging project."
        ),
        tags=("gcp", "gke", "kubernetes", "logging", "monitoring"),
        severity_factors=("lateral_movement", "blast_radius"),
    ),
    RuleMetadata(
        rule_id="gcp-scc-asset-discovery-disabled",
        title="Security Command Center asset discovery is disabled",
        category=StrideCategory.INFORMATION_DISCLOSURE,
        recommended_mitigation=(
            "Enable SCC asset discovery for the organization so Security Command Center can inventory assets, "
            "correlate findings, and support security posture review."
        ),
        tags=("gcp", "scc", "security-command-center", "asset-discovery", "monitoring"),
        severity_factors=("data_sensitivity", "lateral_movement", "blast_radius"),
    ),
    RuleMetadata(
        rule_id="gcp-logging-exclusion-drops-audit-security-logs",
        title="Logging exclusion drops audit or security logs",
        category=StrideCategory.REPUDIATION,
        recommended_mitigation=(
            "Disable or narrow logging exclusions that match Cloud Audit Logs, Security Command Center logs, "
            "or firewall/security records. Retain those streams in a monitored logging project or approved archive."
        ),
        tags=("gcp", "logging", "audit", "security-logs", "exclusion"),
        severity_factors=("data_sensitivity", "lateral_movement", "blast_radius"),
    ),
    RuleMetadata(
        rule_id="gcp-logging-sink-audit-export-incomplete",
        title="Logging sink audit export is incomplete",
        category=StrideCategory.REPUDIATION,
        recommended_mitigation=(
            "Configure logging sinks with deterministic retained destinations and filters that include Cloud Audit "
            "Logs or other security-relevant streams. Leave the filter unset when the sink should export all logs "
            "from its scope."
        ),
        tags=("gcp", "logging", "audit", "sink", "monitoring"),
        severity_factors=("data_sensitivity", "lateral_movement", "blast_radius"),
    ),
    RuleMetadata(
        rule_id="gcp-central-audit-sink-not-modeled",
        title="Central GCP audit logging sink is not modeled",
        category=StrideCategory.REPUDIATION,
        recommended_mitigation=(
            "Model a project or organization logging sink that exports audit and security logs to a retained "
            "destination, or attach review evidence showing that central log export is managed outside this plan."
        ),
        tags=("gcp", "logging", "audit", "sink", "monitoring"),
        severity_factors=("data_sensitivity", "lateral_movement", "blast_radius"),
    ),
    RuleMetadata(
        rule_id="gcp-subnetwork-flow-logs-not-configured",
        title="GCP subnetwork Flow Logs are not configured",
        category=StrideCategory.REPUDIATION,
        recommended_mitigation=(
            "Enable VPC Flow Logs on subnetworks that host workloads, keep the flow log configuration in "
            "Terraform, and export or retain those logs according to investigation and monitoring requirements."
        ),
        tags=("gcp", "network", "subnetwork", "flow-logs", "network-telemetry"),
        severity_factors=("lateral_movement", "blast_radius"),
    ),
    RuleMetadata(
        rule_id="gcp-subnetwork-flow-log-capture-incomplete",
        title="GCP subnetwork Flow Log capture is incomplete",
        category=StrideCategory.REPUDIATION,
        recommended_mitigation=(
            "Configure subnetwork VPC Flow Logs to capture the telemetry needed for investigations, avoid "
            "filters that exclude relevant traffic, and preserve metadata where workload attribution is required."
        ),
        tags=("gcp", "network", "subnetwork", "flow-logs", "network-telemetry"),
        severity_factors=("data_sensitivity", "lateral_movement", "blast_radius"),
    ),
    RuleMetadata(
        rule_id="gcp-gke-network-policy-disabled",
        title="GKE network policy is not enabled",
        category=StrideCategory.TAMPERING,
        recommended_mitigation=(
            "Enable a supported GKE network policy provider and define namespace or workload policies that restrict "
            "pod-to-pod and pod-to-service traffic paths."
        ),
        tags=("gcp", "gke", "kubernetes", "network-policy", "segmentation"),
        severity_factors=("lateral_movement", "blast_radius"),
    ),
    RuleMetadata(
        rule_id="gcp-gke-secrets-encryption-not-configured",
        title="GKE secrets encryption is not configured",
        category=StrideCategory.INFORMATION_DISCLOSURE,
        recommended_mitigation=(
            "Configure GKE application-layer secrets encryption with a Cloud KMS key where customer key ownership "
            "or stronger Kubernetes secret protection is required."
        ),
        tags=("gcp", "gke", "kubernetes", "secrets", "encryption", "kms"),
        severity_factors=("data_sensitivity", "blast_radius"),
    ),
    RuleMetadata(
        rule_id="gcp-gke-legacy-abac-enabled-or-unknown",
        title="GKE legacy ABAC is enabled or unknown",
        category=StrideCategory.ELEVATION_OF_PRIVILEGE,
        recommended_mitigation=(
            "Disable legacy ABAC and rely on Kubernetes RBAC with centralized IAM-backed administration. "
            "Review unknown ABAC values before treating the cluster authorization posture as hardened."
        ),
        tags=("gcp", "gke", "kubernetes", "auth", "rbac"),
        severity_factors=("privilege_breadth", "blast_radius"),
    ),
    RuleMetadata(
        rule_id="gcp-gke-client-certificate-auth-enabled-or-unknown",
        title="GKE client certificate authentication is enabled or unknown",
        category=StrideCategory.SPOOFING,
        recommended_mitigation=(
            "Disable client certificate authentication for GKE clusters and use centralized IAM and Kubernetes "
            "RBAC controls for administrative access."
        ),
        tags=("gcp", "gke", "kubernetes", "auth", "certificate"),
        severity_factors=("privilege_breadth", "lateral_movement", "blast_radius"),
    ),
    RuleMetadata(
        rule_id="gcp-gke-shielded-nodes-disabled-or-unknown",
        title="GKE Shielded Nodes is not enabled",
        category=StrideCategory.TAMPERING,
        recommended_mitigation=(
            "Enable GKE Shielded Nodes to add node integrity protections against boot-level tampering and host "
            "compromise paths."
        ),
        tags=("gcp", "gke", "kubernetes", "node", "hardening"),
        severity_factors=("lateral_movement", "blast_radius"),
    ),
    RuleMetadata(
        rule_id="gcp-gke-binary-authorization-not-enabled",
        title="GKE Binary Authorization is not enabled",
        category=StrideCategory.TAMPERING,
        recommended_mitigation=(
            "Enable GKE Binary Authorization or an equivalent admission policy so only trusted container images "
            "can be deployed to the cluster."
        ),
        tags=("gcp", "gke", "kubernetes", "binary-authorization", "admission-control"),
        severity_factors=("lateral_movement", "blast_radius"),
    ),
    RuleMetadata(
        rule_id="gcp-cloud-run-public-invoker",
        title="Cloud Run service is publicly invokable",
        category=StrideCategory.SPOOFING,
        recommended_mitigation=(
            "Remove `allUsers` and `allAuthenticatedUsers` from Cloud Run invoker bindings unless "
            "anonymous access is intentional, and front public services with authentication, IAP, "
            "API Gateway, or a controlled edge policy."
        ),
        tags=("gcp", "cloud-run", "serverless", "public-access"),
        severity_factors=("internet_exposure", "blast_radius"),
    ),
    RuleMetadata(
        rule_id="gcp-cloud-functions-public-invoker",
        title="Cloud Functions function is publicly invokable",
        category=StrideCategory.SPOOFING,
        recommended_mitigation=(
            "Remove `allUsers` and `allAuthenticatedUsers` from Cloud Functions invoker bindings unless "
            "anonymous access is intentional, and require authentication, IAP, API Gateway, or a controlled "
            "edge policy for public HTTP functions."
        ),
        tags=("gcp", "cloud-functions", "serverless", "public-access"),
        severity_factors=("internet_exposure", "blast_radius"),
    ),
    RuleMetadata(
        rule_id="gcp-service-account-iam-broad-principal",
        title="GCP service account IAM grants access to broad principals",
        category=StrideCategory.ELEVATION_OF_PRIVILEGE,
        recommended_mitigation=(
            "Remove `allUsers`, `allAuthenticatedUsers`, and broad domain grants from service-account IAM; "
            "grant impersonation roles only to narrowly scoped groups, workloads, or automation identities."
        ),
        tags=("gcp", "iam", "service-account", "public-access"),
        severity_factors=("internet_exposure", "privilege_breadth", "lateral_movement", "blast_radius"),
    ),
    RuleMetadata(
        rule_id="gcp-service-account-iam-privileged-role",
        title="GCP service account IAM grants a high-risk impersonation role",
        category=StrideCategory.ELEVATION_OF_PRIVILEGE,
        recommended_mitigation=(
            "Restrict service-account user, token creator, and admin roles to narrowly scoped principals, "
            "prefer workload-specific service accounts, and review impersonation paths before deployment."
        ),
        tags=("gcp", "iam", "service-account", "privilege"),
        severity_factors=("internet_exposure", "privilege_breadth", "lateral_movement", "blast_radius"),
    ),
    RuleMetadata(
        rule_id="gcp-service-account-key-hygiene",
        title="GCP service account user-managed key lacks rotation hygiene",
        category=StrideCategory.SPOOFING,
        recommended_mitigation=(
            "Avoid user-managed service account keys where Workload Identity Federation, workload identity, "
            "or service-account impersonation can be used; when keys are unavoidable, keep lifetimes short, "
            "configure explicit rotation triggers, and store private material outside Terraform state."
        ),
        tags=("gcp", "iam", "service-account", "credential"),
        severity_factors=("privilege_breadth", "lateral_movement", "blast_radius"),
    ),
    RuleMetadata(
        rule_id="gcp-service-account-key-effective-access",
        title="GCP service account key can exercise sensitive or privileged access",
        category=StrideCategory.ELEVATION_OF_PRIVILEGE,
        recommended_mitigation=(
            "Remove sensitive data and high-impact IAM grants from service accounts that still have "
            "user-managed keys, replace keys with workload identity or service-account impersonation, "
            "and revoke or rotate existing keys after privilege reduction."
        ),
        tags=("gcp", "iam", "service-account", "credential", "effective-access"),
        severity_factors=("privilege_breadth", "data_sensitivity", "lateral_movement", "blast_radius"),
    ),
    RuleMetadata(
        rule_id="gcp-org-folder-iam-broad-principal",
        title="GCP organization or folder IAM grants access to broad principals",
        category=StrideCategory.ELEVATION_OF_PRIVILEGE,
        recommended_mitigation=(
            "Remove public and broad-domain principals from organization and folder IAM, grant high-level "
            "access only to tightly controlled groups, and prefer project- or resource-scoped bindings where possible."
        ),
        tags=("gcp", "iam", "organization", "folder", "public-access"),
        severity_factors=("internet_exposure", "privilege_breadth", "lateral_movement", "blast_radius"),
    ),
    RuleMetadata(
        rule_id="gcp-org-folder-iam-privileged-role",
        title="GCP organization or folder IAM grants a high-privilege role",
        category=StrideCategory.ELEVATION_OF_PRIVILEGE,
        recommended_mitigation=(
            "Replace high-impact organization and folder roles with narrowly scoped custom or predefined roles, "
            "assign them only to controlled break-glass or platform groups, and review descendant project blast radius."
        ),
        tags=("gcp", "iam", "organization", "folder", "privilege"),
        severity_factors=("privilege_breadth", "lateral_movement", "blast_radius"),
    ),
    RuleMetadata(
        rule_id="gcp-project-iam-broad-principal",
        title="GCP project IAM binding grants access to public principals",
        category=StrideCategory.ELEVATION_OF_PRIVILEGE,
        recommended_mitigation=(
            "Remove `allUsers` and `allAuthenticatedUsers` from project-level IAM bindings, grant access to "
            "specific groups or service accounts, and scope permissions to the smallest project or resource needed."
        ),
        tags=("gcp", "iam", "public-access"),
        severity_factors=("internet_exposure", "privilege_breadth", "lateral_movement", "blast_radius"),
    ),
    RuleMetadata(
        rule_id="gcp-project-iam-privileged-role",
        title="GCP project IAM binding grants a high-privilege role",
        category=StrideCategory.ELEVATION_OF_PRIVILEGE,
        recommended_mitigation=(
            "Replace Owner, Editor, IAM admin, service-account impersonation, and admin-class project roles "
            "with narrowly scoped predefined or custom roles assigned to specific groups or service accounts."
        ),
        tags=("gcp", "iam", "privilege"),
        severity_factors=("privilege_breadth", "lateral_movement", "blast_radius"),
    ),
    RuleMetadata(
        rule_id="gcp-iam-privileged-assignment",
        title="GCP IAM assignment has privileged access posture",
        category=StrideCategory.ELEVATION_OF_PRIVILEGE,
        recommended_mitigation=(
            "Review high-impact GCP IAM assignments, replace owner/admin/service-account impersonation grants "
            "with narrowly scoped predefined or custom roles, and keep broad project, folder, and organization "
            "assignments limited to controlled break-glass or platform identities."
        ),
        tags=("gcp", "iam", "privileged-access", "role-assignment"),
        severity_factors=("privilege_breadth", "data_sensitivity", "lateral_movement", "blast_radius"),
    ),
    RuleMetadata(
        rule_id="gcp-inherited-iam-sensitive-resource-access",
        title="Inherited GCP IAM grant reaches sensitive resources",
        category=StrideCategory.INFORMATION_DISCLOSURE,
        recommended_mitigation=(
            "Move sensitive data access off organization, folder, and project-level IAM where possible; "
            "grant Secret Manager, KMS, GCS, Cloud SQL, BigQuery, and Pub/Sub permissions at the narrowest "
            "resource scope with reviewed principals and custom roles."
        ),
        tags=("gcp", "iam", "inheritance", "data"),
        severity_factors=(
            "internet_exposure",
            "privilege_breadth",
            "data_sensitivity",
            "lateral_movement",
            "blast_radius",
        ),
    ),
    RuleMetadata(
        rule_id="gcp-inherited-iam-blast-radius",
        title="Inherited GCP IAM grant expands descendant blast radius",
        category=StrideCategory.ELEVATION_OF_PRIVILEGE,
        recommended_mitigation=(
            "Avoid broad or high-impact IAM grants at organization, folder, and project scope when narrower "
            "resource-level or workload-specific bindings are possible; split inherited roles by service and "
            "review descendant resources before assigning public, external, or administrator principals."
        ),
        tags=("gcp", "iam", "inheritance", "blast-radius"),
        severity_factors=(
            "internet_exposure",
            "privilege_breadth",
            "data_sensitivity",
            "lateral_movement",
            "blast_radius",
        ),
    ),
)
