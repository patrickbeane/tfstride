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