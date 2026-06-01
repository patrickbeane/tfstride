from __future__ import annotations

from tfstride.analysis.finding_factory import FindingFactory
from tfstride.analysis.finding_helpers import build_severity_reasoning, collect_evidence, evidence_item
from tfstride.analysis.resource_facts import analysis_facts
from tfstride.analysis.rule_definitions import RuleEvaluationContext
from tfstride.models import BoundaryType, Finding, NormalizedResource, ResourceInventory, SecurityGroupRule
from tfstride.resource_helpers import describe_security_group_rule

_PRIVILEGED_GCP_PROJECT_ROLES: dict[str, str] = {
    "roles/owner": "full project administration",
    "roles/editor": "broad write access across most project services",
    "roles/iam.serviceAccountTokenCreator": "service account token minting and impersonation",
    "roles/iam.serviceAccountUser": "service account attachment and impersonation paths",
    "roles/iam.serviceAccountAdmin": "service account administration",
    "roles/iam.securityAdmin": "IAM policy and security-control administration",
    "roles/resourcemanager.projectIamAdmin": "project IAM policy administration",
}


class GcpRuleDetectors:
    def __init__(self, finding_factory: FindingFactory) -> None:
        self._finding_factory = finding_factory

    def detect_public_compute_broad_ingress(
        self,
        context: RuleEvaluationContext,
        rule_id: str,
    ) -> list[Finding]:
        if context.inventory.provider != "gcp":
            return []

        findings: list[Finding] = []
        inventory = context.inventory
        for instance in inventory.by_type("google_compute_instance"):
            if not instance.public_exposure:
                continue
            risky_rules = _risky_public_firewall_rules(instance, inventory)
            if not risky_rules:
                continue

            severity_reasoning = build_severity_reasoning(
                internet_exposure=True,
                privilege_breadth=0,
                data_sensitivity=0,
                lateral_movement=1,
                blast_radius=1,
            )
            boundary = context.boundary_index.get(
                (BoundaryType.INTERNET_TO_SERVICE, "internet", instance.address)
            )
            affected_resources = _dedupe_addresses(
                [instance.address, *[firewall.address for firewall, _ in risky_rules]]
            )
            findings.append(
                self._finding_factory.build(
                    rule_id=rule_id,
                    severity=severity_reasoning.severity,
                    affected_resources=affected_resources,
                    trust_boundary_id=boundary.identifier if boundary else None,
                    rationale=(
                        f"{instance.display_name} has an external access config and matching GCP firewall "
                        "rules allow administrative access or all ports from the public internet. That broad "
                        "ingress raises the chance of unauthenticated probing and credential attacks."
                    ),
                    evidence=collect_evidence(
                        evidence_item(
                            "firewall_rules",
                            [
                                describe_security_group_rule(firewall, rule)
                                for firewall, rule in risky_rules
                            ],
                        ),
                        evidence_item("network_tags", analysis_facts(instance).network_tags),
                        evidence_item("public_exposure_reasons", instance.public_exposure_reasons),
                    ),
                    severity_reasoning=severity_reasoning,
                )
            )
        return findings

    def detect_project_iam_broad_principal(
        self,
        context: RuleEvaluationContext,
        rule_id: str,
    ) -> list[Finding]:
        if context.inventory.provider != "gcp":
            return []

        findings: list[Finding] = []
        for binding in context.inventory.by_type("google_project_iam_member"):
            binding_facts = analysis_facts(binding)
            member = binding_facts.iam_member
            if member not in {"allUsers", "allAuthenticatedUsers"}:
                continue
            role = binding_facts.iam_role or "unknown role"
            severity_reasoning = build_severity_reasoning(
                internet_exposure=True,
                privilege_breadth=1,
                data_sensitivity=0,
                lateral_movement=1,
                blast_radius=1,
            )
            findings.append(
                self._finding_factory.build(
                    rule_id=rule_id,
                    severity=severity_reasoning.severity,
                    affected_resources=[binding.address],
                    trust_boundary_id=None,
                    rationale=(
                        f"{binding.display_name} grants `{role}` to `{member}` at project scope. Public "
                        "or broadly authenticated principals can cross into the control plane without an "
                        "organization-owned identity boundary."
                    ),
                    evidence=collect_evidence(
                        evidence_item("iam_binding", [f"member={member}", f"role={role}"]),
                    ),
                    severity_reasoning=severity_reasoning,
                )
            )
        return findings

    def detect_project_iam_privileged_role(
        self,
        context: RuleEvaluationContext,
        rule_id: str,
    ) -> list[Finding]:
        if context.inventory.provider != "gcp":
            return []

        findings: list[Finding] = []
        for binding in context.inventory.by_type("google_project_iam_member"):
            binding_facts = analysis_facts(binding)
            role = binding_facts.iam_role
            role_risk = _privileged_project_role_risk(role)
            if role_risk is None:
                continue
            member = binding_facts.iam_member or "unknown member"
            severity_reasoning = build_severity_reasoning(
                internet_exposure=False,
                privilege_breadth=2,
                data_sensitivity=0,
                lateral_movement=2,
                blast_radius=2,
            )
            findings.append(
                self._finding_factory.build(
                    rule_id=rule_id,
                    severity=severity_reasoning.severity,
                    affected_resources=[binding.address],
                    trust_boundary_id=None,
                    rationale=(
                        f"{binding.display_name} grants the high-impact GCP role `{role}` to `{member}` "
                        f"at project scope. That role enables {role_risk} and can materially expand "
                        "control-plane blast radius if the principal is compromised or mis-scoped."
                    ),
                    evidence=collect_evidence(
                        evidence_item("iam_binding", [f"member={member}", f"role={role}"]),
                        evidence_item("role_risk", [role_risk]),
                    ),
                    severity_reasoning=severity_reasoning,
                )
            )
        return findings

    def detect_gcs_public_access(
        self,
        context: RuleEvaluationContext,
        rule_id: str,
    ) -> list[Finding]:
        if context.inventory.provider != "gcp":
            return []

        findings: list[Finding] = []
        for bucket in context.inventory.by_type("google_storage_bucket"):
            if not bucket.public_exposure:
                continue
            boundary = context.boundary_index.get(
                (BoundaryType.INTERNET_TO_SERVICE, "internet", bucket.address)
            )
            severity_reasoning = build_severity_reasoning(
                internet_exposure=True,
                privilege_breadth=0,
                data_sensitivity=2,
                lateral_movement=0,
                blast_radius=1,
            )
            findings.append(
                self._finding_factory.build(
                    rule_id=rule_id,
                    severity=severity_reasoning.severity,
                    affected_resources=[bucket.address],
                    trust_boundary_id=boundary.identifier if boundary else None,
                    rationale=(
                        f"{bucket.display_name} is publicly reachable through GCS IAM grants. "
                        "Public bucket access is a common source of unintended object disclosure."
                    ),
                    evidence=collect_evidence(
                        evidence_item("public_exposure_reasons", bucket.public_exposure_reasons),
                    ),
                    severity_reasoning=severity_reasoning,
                )
            )
        return findings


def _risky_public_firewall_rules(
    instance: NormalizedResource,
    inventory: ResourceInventory,
) -> list[tuple[NormalizedResource, SecurityGroupRule]]:
    firewall_addresses = analysis_facts(instance).internet_ingress_firewalls
    risky_rules: list[tuple[NormalizedResource, SecurityGroupRule]] = []
    for firewall_address in firewall_addresses:
        firewall = inventory.get_by_address(firewall_address)
        if firewall is None:
            continue
        for rule in firewall.network_rules:
            if (
                rule.direction == "ingress"
                and rule.allows_internet()
                and (rule.is_administrative_access() or rule.is_all_ports())
            ):
                risky_rules.append((firewall, rule))
    return risky_rules


def _privileged_project_role_risk(role: str | None) -> str | None:
    if not role:
        return None
    normalized_role = role.strip()
    if normalized_role in _PRIVILEGED_GCP_PROJECT_ROLES:
        return _PRIVILEGED_GCP_PROJECT_ROLES[normalized_role]
    role_name = normalized_role.rsplit("/", 1)[-1].lower()
    if normalized_role.startswith("roles/") and "admin" in role_name:
        return "admin-level control over a GCP service or project security surface"
    return None


def _dedupe_addresses(addresses: list[str]) -> list[str]:
    deduped: list[str] = []
    seen: set[str] = set()
    for address in addresses:
        if address in seen:
            continue
        deduped.append(address)
        seen.add(address)
    return deduped