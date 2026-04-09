from __future__ import annotations

from dataclasses import dataclass, field, replace

from cloud_threat_modeler.models import Finding, Severity, StrideCategory


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
    severity_overrides: dict[str, Severity] = field(default_factory=dict)

    def is_enabled(self, rule_id: str, registry: "RuleRegistry") -> bool:
        if self.enabled_rule_ids is None:
            return registry.get(rule_id).enabled_by_default
        return rule_id in self.enabled_rule_ids


class RuleRegistry:
    def __init__(self, rules: list[RuleMetadata]) -> None:
        self._rules_by_id = {rule.rule_id: rule for rule in rules}
        if len(self._rules_by_id) != len(rules):
            raise ValueError("Duplicate rule IDs are not allowed in the rule registry.")

    def get(self, rule_id: str) -> RuleMetadata:
        try:
            return self._rules_by_id[rule_id]
        except KeyError as exc:
            raise KeyError(f"Unknown rule ID `{rule_id}`.") from exc

    def all(self) -> list[RuleMetadata]:
        return list(self._rules_by_id.values())

    def known_rule_ids(self) -> set[str]:
        return set(self._rules_by_id)

    def default_enabled_rule_ids(self) -> set[str]:
        return {rule.rule_id for rule in self._rules_by_id.values() if rule.enabled_by_default}


DEFAULT_RULE_REGISTRY = RuleRegistry(
    [
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
            title="Sensitive resource policy allows public or cross-account access",
            category=StrideCategory.INFORMATION_DISCLOSURE,
            recommended_mitigation=(
                "Limit resource policies to exact service principals or workload roles, avoid wildcard "
                "and account-root principals, and require source-account or source-ARN constraints where supported."
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
            title="Service resource policy allows public or cross-account access",
            category=StrideCategory.ELEVATION_OF_PRIVILEGE,
            recommended_mitigation=(
                "Limit resource policies to exact service principals or workload roles, avoid wildcard "
                "and account-root principals, and require source-account or source-ARN constraints where supported."
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
            rule_id="aws-role-trust-expansion",
            title="Role trust relationship expands blast radius",
            category=StrideCategory.ELEVATION_OF_PRIVILEGE,
            recommended_mitigation=(
                "Limit trust policies to the exact service principals or roles required, prefer role ARNs "
                "over account root where possible, and add conditions such as `ExternalId` or source ARN checks."
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
                "conditions such as `ExternalId`, `SourceArn`, or `SourceAccount` when crossing "
                "accounts or trusting broad principals."
            ),
            tags=("aws", "iam", "trust", "cross-account"),
            severity_factors=("privilege_breadth", "lateral_movement", "blast_radius"),
        ),
    ]
)


def get_rule(rule_id: str) -> RuleMetadata:
    return DEFAULT_RULE_REGISTRY.get(rule_id)


def apply_rule_policy(
    findings: list[Finding],
    policy: RulePolicy | None,
    registry: RuleRegistry = DEFAULT_RULE_REGISTRY,
) -> list[Finding]:
    if policy is None:
        return sort_findings(findings)

    adjusted_findings: list[Finding] = []
    for finding in findings:
        if not policy.is_enabled(finding.rule_id, registry):
            continue
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
    severity_order = {Severity.HIGH: 0, Severity.MEDIUM: 1, Severity.LOW: 2}
    return sorted(findings, key=lambda finding: (severity_order[finding.severity], finding.title))
