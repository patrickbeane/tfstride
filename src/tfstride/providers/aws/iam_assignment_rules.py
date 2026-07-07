from __future__ import annotations

from collections.abc import Iterable

from tfstride.analysis.finding_factory import FindingFactory
from tfstride.analysis.finding_helpers import build_severity_reasoning, collect_evidence, evidence_item
from tfstride.analysis.rule_definitions import RuleEvaluationContext
from tfstride.identity import PrivilegeCategory, PrivilegeConfidence, PrivilegedAccessGrant
from tfstride.models import Finding, NormalizedResource
from tfstride.providers.aws.resource_facts import aws_facts

_HIGH_IMPACT_CATEGORIES = frozenset(
    {
        PrivilegeCategory.FULL_ADMIN,
        PrivilegeCategory.IAM_ADMIN,
        PrivilegeCategory.POLICY_ADMIN,
        PrivilegeCategory.ROLE_ASSIGNMENT,
        PrivilegeCategory.PRIVILEGE_ESCALATION,
    }
)
_DATA_ACCESS_CATEGORIES = frozenset(
    {
        PrivilegeCategory.DATA_ADMIN,
        PrivilegeCategory.SECRETS_ADMIN,
        PrivilegeCategory.KEY_ADMIN,
    }
)
_CONTROL_PLANE_CATEGORIES = frozenset(
    {
        PrivilegeCategory.COMPUTE_ADMIN,
        PrivilegeCategory.NETWORK_ADMIN,
        PrivilegeCategory.AUDIT_ADMIN,
    }
)


class AwsIamAssignmentRuleDetectors:
    def __init__(self, finding_factory: FindingFactory) -> None:
        self._finding_factory = finding_factory

    def detect_privileged_role_assignment(
        self,
        context: RuleEvaluationContext,
        rule_id: str,
    ) -> list[Finding]:
        if context.inventory.provider != "aws":
            return []

        findings: list[Finding] = []
        for role in context.inventory.by_type("aws_iam_role"):
            facts = aws_facts(role)
            grants = facts.privileged_access_grants
            if not grants:
                continue
            severity_reasoning = _severity_for_grants(grants)
            findings.append(
                self._finding_factory.build(
                    rule_id=rule_id,
                    severity=severity_reasoning.severity,
                    affected_resources=_affected_resources(role),
                    trust_boundary_id=None,
                    rationale=(
                        f"{role.display_name} has deterministic privileged IAM assignment posture: "
                        f"{_grant_summary(grants)}. If this role is attached to a workload or assumable by a "
                        "control-plane principal, those privileges increase blast radius."
                    ),
                    evidence=collect_evidence(
                        evidence_item("iam_role", _role_evidence(role)),
                        evidence_item("privileged_access", _grant_evidence(grants)),
                        evidence_item("privilege_categories", _category_evidence(grants)),
                        evidence_item("permission_patterns", _permission_pattern_evidence(grants)),
                        evidence_item("grant_scopes", _scope_evidence(grants)),
                        evidence_item("grant_confidence", _confidence_evidence(grants)),
                        evidence_item("attached_policies", _attached_policy_evidence(role)),
                        evidence_item("inline_policy_sources", _inline_policy_evidence(role)),
                        evidence_item("unresolved_assignments", facts.iam_assignment_posture_uncertainties),
                    ),
                    severity_reasoning=severity_reasoning,
                )
            )
        return findings


def _severity_for_grants(grants: tuple[PrivilegedAccessGrant, ...]):
    categories = _grant_categories(grants)
    high_impact = bool(categories & _HIGH_IMPACT_CATEGORIES)
    data_access = bool(categories & _DATA_ACCESS_CATEGORIES)
    broad_scope = any(grant.has_broad_scope for grant in grants)
    high_confidence = any(grant.confidence == PrivilegeConfidence.HIGH for grant in grants)
    return build_severity_reasoning(
        internet_exposure=False,
        privilege_breadth=3 if high_impact and broad_scope and high_confidence else 2,
        data_sensitivity=2 if data_access else 0,
        lateral_movement=2 if high_impact else 1 if categories & _CONTROL_PLANE_CATEGORIES else 0,
        blast_radius=3 if broad_scope else 1,
    )


def _grant_summary(grants: tuple[PrivilegedAccessGrant, ...]) -> str:
    categories = ", ".join(
        category.value for category in sorted(_grant_categories(grants), key=lambda item: item.value)
    )
    if not categories:
        return "unknown privileged access"
    return categories


def _grant_categories(grants: tuple[PrivilegedAccessGrant, ...]) -> set[PrivilegeCategory]:
    return {category for grant in grants for category in grant.privilege_categories}


def _role_evidence(role: NormalizedResource) -> list[str]:
    values = [
        f"address={role.address}",
        f"type={role.resource_type}",
    ]
    if role.arn:
        values.append(f"arn={role.arn}")
    if role.identifier:
        values.append(f"identifier={role.identifier}")
    return values


def _grant_evidence(grants: tuple[PrivilegedAccessGrant, ...]) -> list[str]:
    values: list[str] = []
    for index, grant in enumerate(grants, start=1):
        categories = ", ".join(category.value for category in grant.privilege_categories)
        values.append(
            f"grant_{index}=categories=[{categories}]; scope={grant.assignment_scope.scope_kind.value}; "
            f"confidence={grant.confidence.value}"
        )
    return values


def _category_evidence(grants: tuple[PrivilegedAccessGrant, ...]) -> list[str]:
    return sorted(category.value for category in _grant_categories(grants))


def _permission_pattern_evidence(grants: tuple[PrivilegedAccessGrant, ...]) -> list[str]:
    return _dedupe(pattern for grant in grants for pattern in grant.permission_patterns)


def _scope_evidence(grants: tuple[PrivilegedAccessGrant, ...]) -> list[str]:
    values: list[str] = []
    for grant in grants:
        scope = grant.assignment_scope
        value = f"scope_kind={scope.scope_kind.value}"
        if scope.value:
            value = f"{value}; scope_value={scope.value}"
        values.append(value)
    return _dedupe(values)


def _confidence_evidence(grants: tuple[PrivilegedAccessGrant, ...]) -> list[str]:
    return _dedupe(grant.confidence.value for grant in grants)


def _attached_policy_evidence(role: NormalizedResource) -> list[str]:
    facts = aws_facts(role)
    values: list[str] = []
    values.extend(f"attached_policy_arn={arn}" for arn in facts.attached_policy_arns)
    values.extend(f"attached_policy_address={address}" for address in facts.attached_policy_addresses)
    return values


def _inline_policy_evidence(role: NormalizedResource) -> list[str]:
    facts = aws_facts(role)
    values: list[str] = []
    values.extend(f"inline_policy_name={name}" for name in facts.inline_policy_names)
    values.extend(f"inline_policy_source={address}" for address in facts.inline_policy_resource_addresses)
    return values


def _affected_resources(role: NormalizedResource) -> list[str]:
    facts = aws_facts(role)
    return _dedupe([role.address, *facts.attached_policy_addresses, *facts.inline_policy_resource_addresses])


def _dedupe(values: Iterable[str | None]) -> list[str]:
    seen: set[str] = set()
    deduped: list[str] = []
    for value in values:
        if value is None:
            continue
        normalized = str(value).strip()
        if not normalized or normalized in seen:
            continue
        seen.add(normalized)
        deduped.append(normalized)
    return deduped
