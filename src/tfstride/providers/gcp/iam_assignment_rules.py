from __future__ import annotations

from tfstride.analysis.finding_factory import FindingFactory
from tfstride.analysis.finding_helpers import build_severity_reasoning, collect_evidence, evidence_item
from tfstride.analysis.rule_definitions import RuleEvaluationContext
from tfstride.identity import PrincipalType, PrivilegeCategory, PrivilegeConfidence, PrivilegedAccessGrant
from tfstride.models import Finding, NormalizedResource
from tfstride.providers.coercion import dedupe_strings
from tfstride.providers.gcp.resource_facts import gcp_facts
from tfstride.providers.gcp.resource_types import (
    GCP_FOLDER_IAM_RESOURCE_TYPES,
    GCP_ORGANIZATION_IAM_RESOURCE_TYPES,
    GCP_PROJECT_IAM_RESOURCE_TYPES,
    GCP_SERVICE_ACCOUNT_IAM_RESOURCE_TYPES,
)

_LEGACY_SCOPED_IAM_RESOURCE_TYPES = (
    GCP_PROJECT_IAM_RESOURCE_TYPES
    | GCP_ORGANIZATION_IAM_RESOURCE_TYPES
    | GCP_FOLDER_IAM_RESOURCE_TYPES
    | GCP_SERVICE_ACCOUNT_IAM_RESOURCE_TYPES
)

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


class GcpIamAssignmentRuleDetectors:
    def __init__(self, finding_factory: FindingFactory) -> None:
        self._finding_factory = finding_factory

    def detect_privileged_assignment(
        self,
        context: RuleEvaluationContext,
        rule_id: str,
    ) -> list[Finding]:
        if context.inventory.provider != "gcp":
            return []

        findings: list[Finding] = []
        for resource in context.inventory.resources:
            if resource.resource_type in _LEGACY_SCOPED_IAM_RESOURCE_TYPES:
                continue
            facts = gcp_facts(resource)
            grants = facts.privileged_access_grants
            if not grants:
                continue
            severity_reasoning = _severity_for_grants(grants)
            findings.append(
                self._finding_factory.build(
                    rule_id=rule_id,
                    severity=severity_reasoning.severity,
                    affected_resources=_affected_resources(resource, grants),
                    trust_boundary_id=None,
                    rationale=(
                        f"{resource.display_name} has deterministic privileged GCP IAM assignment posture: "
                        f"{_grant_summary(grants)}. Those grants can expand control-plane, data-plane, or "
                        "impersonation blast radius if the assigned principal is compromised or mis-scoped."
                    ),
                    evidence=collect_evidence(
                        evidence_item("iam_assignment", _assignment_evidence(resource, grants)),
                        evidence_item("privileged_access", _grant_evidence(grants)),
                        evidence_item("privilege_categories", _category_evidence(grants)),
                        evidence_item("permission_patterns", _permission_pattern_evidence(grants)),
                        evidence_item("grant_principals", _principal_evidence(grants)),
                        evidence_item("grant_scopes", _scope_evidence(grants)),
                        evidence_item("grant_confidence", _confidence_evidence(grants)),
                        evidence_item("assignment_facts", _provider_fact_evidence(grants)),
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
    public_principal = any(grant.principal.principal_type == PrincipalType.ANY for grant in grants)
    return build_severity_reasoning(
        internet_exposure=public_principal,
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


def _assignment_evidence(resource: NormalizedResource, grants: tuple[PrivilegedAccessGrant, ...]) -> list[str]:
    values = [
        f"address={resource.address}",
        f"type={resource.resource_type}",
    ]
    values.extend(f"role={grant.role_name}" for grant in grants if grant.role_name)
    return dedupe_strings(values)


def _grant_evidence(grants: tuple[PrivilegedAccessGrant, ...]) -> list[str]:
    values: list[str] = []
    for index, grant in enumerate(grants, start=1):
        categories = ", ".join(category.value for category in grant.privilege_categories)
        principal = grant.principal.identifier or grant.principal.principal_type.value
        values.append(
            f"grant_{index}=principal={principal}; categories=[{categories}]; "
            f"scope={grant.assignment_scope.scope_kind.value}; confidence={grant.confidence.value}"
        )
    return values


def _category_evidence(grants: tuple[PrivilegedAccessGrant, ...]) -> list[str]:
    return sorted(category.value for category in _grant_categories(grants))


def _permission_pattern_evidence(grants: tuple[PrivilegedAccessGrant, ...]) -> list[str]:
    return dedupe_strings(pattern for grant in grants for pattern in grant.permission_patterns)


def _principal_evidence(grants: tuple[PrivilegedAccessGrant, ...]) -> list[str]:
    values: list[str] = []
    for grant in grants:
        value = f"principal_type={grant.principal.principal_type.value}"
        if grant.principal.identifier:
            value = f"{value}; principal={grant.principal.identifier}"
        values.append(value)
    return dedupe_strings(values)


def _scope_evidence(grants: tuple[PrivilegedAccessGrant, ...]) -> list[str]:
    values: list[str] = []
    for grant in grants:
        scope = grant.assignment_scope
        value = f"scope_kind={scope.scope_kind.value}"
        if scope.value:
            value = f"{value}; scope_value={scope.value}"
        values.append(value)
    return dedupe_strings(values)


def _confidence_evidence(grants: tuple[PrivilegedAccessGrant, ...]) -> list[str]:
    return dedupe_strings(grant.confidence.value for grant in grants)


def _provider_fact_evidence(grants: tuple[PrivilegedAccessGrant, ...]) -> list[str]:
    return dedupe_strings(value for grant in grants for value in grant.evidence)


def _affected_resources(resource: NormalizedResource, grants: tuple[PrivilegedAccessGrant, ...]) -> list[str]:
    return dedupe_strings([resource.address, *(grant.assignment_scope.source_address for grant in grants)])
