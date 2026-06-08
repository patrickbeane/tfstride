from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field, replace
from types import MappingProxyType

from tfstride.models import Finding, Severity, StrideCategory


@dataclass(frozen=True, slots=True)
class RuleMetadata:
    rule_id: str
    title: str
    category: StrideCategory
    recommended_mitigation: str
    tags: tuple[str, ...] = ()
    severity_factors: tuple[str, ...] = ()
    enabled_by_default: bool = True


@dataclass(frozen=True, slots=True)
class RulePolicy:
    enabled_rule_ids: frozenset[str] | None = None
    severity_overrides: Mapping[str, Severity] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "severity_overrides",
            MappingProxyType(dict(self.severity_overrides)),
        )

    def is_enabled(self, rule_id: str, registry: "RuleRegistry") -> bool:
        if self.enabled_rule_ids is None:
            return registry.get(rule_id).enabled_by_default
        return rule_id in self.enabled_rule_ids


class RuleRegistry:
    def __init__(self, rules: list[RuleMetadata]) -> None:
        self._rules = tuple(rules)
        self._rules_by_id = {rule.rule_id: rule for rule in self._rules}
        if len(self._rules_by_id) != len(rules):
            raise ValueError("Duplicate rule IDs are not allowed in the rule registry.")

    def get(self, rule_id: str) -> RuleMetadata:
        try:
            return self._rules_by_id[rule_id]
        except KeyError as exc:
            raise KeyError(f"Unknown rule ID `{rule_id}`.") from exc

    def known_rule_ids(self) -> set[str]:
        return set(self._rules_by_id)

    def default_enabled_rule_ids(self) -> set[str]:
        return {rule.rule_id for rule in self._rules_by_id.values() if rule.enabled_by_default}

    def rules(self) -> tuple[RuleMetadata, ...]:
        return self._rules


DEFAULT_RULE_METADATA = (
    RuleMetadata(
        rule_id="aws-public-compute-broad-ingress",
        title="Internet-exposed compute service permits overly broad ingress",
        category=StrideCategory.SPOOFING,
        recommended_mitigation=(
            "Restrict ingress to expected client ports, remove direct administrative exposure, "
            "and place management access behind a controlled bastion, VPN, or SSM Session Manager."
        ),
        tags=("aws", "network", "compute", "internet"),
        severity_factors=("internet_exposure", "lateral_movement", "blast_radius"),
    ),
    RuleMetadata(
        rule_id="aws-database-permissive-ingress",
        title="Database is reachable from overly permissive sources",
        category=StrideCategory.INFORMATION_DISCLOSURE,
        recommended_mitigation=(
            "Keep databases off public paths, allow ingress only from narrowly scoped application "
            "security groups, and enforce authentication plus encryption independently of network policy."
        ),
        tags=("aws", "network", "database"),
        severity_factors=("internet_exposure", "data_sensitivity", "lateral_movement", "blast_radius"),
    ),
    RuleMetadata(
        rule_id="aws-rds-storage-encryption-disabled",
        title="Database storage encryption is disabled",
        category=StrideCategory.INFORMATION_DISCLOSURE,
        recommended_mitigation=(
            "Enable RDS storage encryption with a managed KMS key, enforce encryption by default in "
            "database modules, and migrate plaintext instances to encrypted replacements where needed."
        ),
        tags=("aws", "database", "encryption"),
        severity_factors=("data_sensitivity", "blast_radius"),
    ),
    RuleMetadata(
        rule_id="aws-s3-public-access",
        title="Object storage is publicly accessible",
        category=StrideCategory.INFORMATION_DISCLOSURE,
        recommended_mitigation=(
            "Remove public ACL or bucket policy access, enable an S3 public access block, "
            "and serve content through a controlled CDN or origin access pattern when public distribution is required."
        ),
        tags=("aws", "storage", "public-access"),
        severity_factors=("internet_exposure", "privilege_breadth", "data_sensitivity", "blast_radius"),
    ),
    RuleMetadata(
        rule_id="aws-sensitive-resource-policy-external-access",
        title="Sensitive resource policy allows broad or cross-account access",
        category=StrideCategory.INFORMATION_DISCLOSURE,
        recommended_mitigation=(
            "Limit resource policies to exact service principals or workload roles, avoid wildcard "
            "foreign-account, and account-root principals where more specific identities are possible, "
            "and require source-account or source-ARN constraints where supported."
        ),
        tags=("aws", "resource-policy", "data"),
        severity_factors=(
            "internet_exposure",
            "privilege_breadth",
            "data_sensitivity",
            "lateral_movement",
            "blast_radius",
        ),
    ),
    RuleMetadata(
        rule_id="aws-service-resource-policy-external-access",
        title="Service resource policy allows broad or cross-account access",
        category=StrideCategory.ELEVATION_OF_PRIVILEGE,
        recommended_mitigation=(
            "Limit resource policies to exact service principals or workload roles, avoid wildcard "
            "foreign-account, and account-root principals where more specific identities are possible, "
            "and require source-account or source-ARN constraints where supported."
        ),
        tags=("aws", "resource-policy", "service"),
        severity_factors=("internet_exposure", "privilege_breadth", "lateral_movement", "blast_radius"),
    ),
    RuleMetadata(
        rule_id="aws-iam-wildcard-permissions",
        title="IAM policy grants wildcard privileges",
        category=StrideCategory.ELEVATION_OF_PRIVILEGE,
        recommended_mitigation=(
            "Replace wildcard actions and resources with narrowly scoped permissions tied to the exact "
            "services, APIs, and ARNs required by the workload."
        ),
        tags=("aws", "iam", "permissions"),
        severity_factors=("privilege_breadth", "lateral_movement", "blast_radius"),
    ),
    RuleMetadata(
        rule_id="aws-workload-role-sensitive-permissions",
        title="Workload role carries sensitive permissions",
        category=StrideCategory.ELEVATION_OF_PRIVILEGE,
        recommended_mitigation=(
            "Split high-privilege actions into separate roles, scope permissions to named resources, "
            "and remove role-passing or cross-role permissions from general application identities."
        ),
        tags=("aws", "iam", "workload"),
        severity_factors=("internet_exposure", "privilege_breadth", "lateral_movement", "blast_radius"),
    ),
    RuleMetadata(
        rule_id="aws-missing-tier-segmentation",
        title="Private data tier directly trusts the public application tier",
        category=StrideCategory.TAMPERING,
        recommended_mitigation=(
            "Introduce tighter tier segmentation with dedicated security groups, narrow ingress to "
            "specific services and ports, and keep the data tier reachable only through controlled application paths."
        ),
        tags=("aws", "network", "segmentation"),
        severity_factors=("internet_exposure", "data_sensitivity", "lateral_movement", "blast_radius"),
    ),
    RuleMetadata(
        rule_id="aws-private-data-transitive-exposure",
        title="Sensitive data tier is transitively reachable from an internet-exposed path",
        category=StrideCategory.INFORMATION_DISCLOSURE,
        recommended_mitigation=(
            "Keep internet-adjacent entry points from chaining into workloads that retain database or secret access, "
            "narrow edge-to-workload and workload-to-workload trust, and isolate sensitive data access behind more "
            "deliberate service boundaries."
        ),
        tags=("aws", "network", "segmentation", "transitive-path"),
        severity_factors=("data_sensitivity", "lateral_movement", "blast_radius"),
    ),
    RuleMetadata(
        rule_id="aws-control-plane-sensitive-workload-chain",
        title="Broad or cross-account control-plane path can influence a sensitive workload",
        category=StrideCategory.ELEVATION_OF_PRIVILEGE,
        recommended_mitigation=(
            "Keep external CI or deployment principals away from runtime workload roles, separate deployment "
            "and execution identities, require narrowing conditions on cross-account trust, and avoid giving "
            "data-bearing workloads broad secret or database access where a smaller brokered path would work."
        ),
        tags=("aws", "iam", "control-plane", "transitive-path"),
        severity_factors=("privilege_breadth", "data_sensitivity", "lateral_movement", "blast_radius"),
    ),
    RuleMetadata(
        rule_id="aws-role-trust-expansion",
        title="Role trust relationship expands blast radius",
        category=StrideCategory.ELEVATION_OF_PRIVILEGE,
        recommended_mitigation=(
            "Limit trust policies to the exact service principals or roles required, prefer role ARNs "
            "over account root where possible, and add conditions such as `ExternalId`, source ARN, "
            "SAML audience, or OIDC audience and subject checks."
        ),
        tags=("aws", "iam", "trust"),
        severity_factors=("privilege_breadth", "lateral_movement", "blast_radius"),
    ),
    RuleMetadata(
        rule_id="aws-role-trust-missing-narrowing",
        title="Cross-account or broad role trust lacks narrowing conditions",
        category=StrideCategory.ELEVATION_OF_PRIVILEGE,
        recommended_mitigation=(
            "Keep the trusted principal as specific as possible and add supported assume-role "
            "conditions such as `ExternalId`, `SourceArn`, `SourceAccount`, `SAML:aud`, or "
            "provider-specific OIDC `aud` and `sub` checks when crossing accounts or trusting "
            "broad or federated principals."
        ),
        tags=("aws", "iam", "trust", "cross-account"),
        severity_factors=("privilege_breadth", "lateral_movement", "blast_radius"),
    ),

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
)


DEFAULT_RULE_METADATA_BY_ID = {rule.rule_id: rule for rule in DEFAULT_RULE_METADATA}


def default_rule_registry() -> RuleRegistry:
    return RuleRegistry(list(DEFAULT_RULE_METADATA))


DEFAULT_RULE_REGISTRY = default_rule_registry()


def default_rule_metadata(rule_id: str) -> RuleMetadata:
    try:
        return DEFAULT_RULE_METADATA_BY_ID[rule_id]
    except KeyError as exc:
        raise KeyError(f"Unknown rule ID `{rule_id}`.") from exc


def apply_severity_overrides(
    findings: list[Finding],
    policy: RulePolicy | None,
) -> list[Finding]:
    if policy is None:
        return sort_findings(findings)

    adjusted_findings: list[Finding] = []
    for finding in findings:
        severity_override = policy.severity_overrides.get(finding.rule_id)
        if severity_override and severity_override != finding.severity:
            severity_reasoning = finding.severity_reasoning
            if severity_reasoning is not None:
                computed_severity = severity_reasoning.computed_severity or severity_reasoning.severity
                severity_reasoning = replace(
                    severity_reasoning,
                    severity=severity_override,
                    computed_severity=computed_severity,
                )
            finding = replace(
                finding,
                severity=severity_override,
                severity_reasoning=severity_reasoning,
            )
        adjusted_findings.append(finding)
    return sort_findings(adjusted_findings)


def sort_findings(findings: list[Finding]) -> list[Finding]:
    return sorted(findings, key=lambda finding: (Severity.sort_key(finding.severity), finding.title))