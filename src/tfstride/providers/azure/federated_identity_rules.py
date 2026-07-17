from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from tfstride.analysis.finding_factory import FindingFactory
from tfstride.analysis.finding_helpers import (
    build_severity_reasoning,
    collect_evidence,
    dedupe_addresses,
    evidence_item,
)
from tfstride.analysis.rule_definitions import RuleEvaluationContext
from tfstride.identity import (
    AssignmentScopeKind,
    PrincipalType,
    PrivilegeCategory,
    PrivilegeConfidence,
    PrivilegedAccessGrant,
)
from tfstride.models import Finding, NormalizedResource
from tfstride.providers.azure.resource_facts import azure_facts
from tfstride.providers.azure.resource_types import AzureResourceType
from tfstride.providers.coercion import dedupe_strings

_DATA_ACCESS_CATEGORIES = frozenset(
    {
        PrivilegeCategory.DATA_ADMIN,
        PrivilegeCategory.SECRETS_ADMIN,
        PrivilegeCategory.KEY_ADMIN,
    }
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
_CONTROL_PLANE_CATEGORIES = frozenset(
    {
        PrivilegeCategory.COMPUTE_ADMIN,
        PrivilegeCategory.NETWORK_ADMIN,
        PrivilegeCategory.AUDIT_ADMIN,
    }
)
_REPORTABLE_CATEGORIES = _HIGH_IMPACT_CATEGORIES | _DATA_ACCESS_CATEGORIES | _CONTROL_PLANE_CATEGORIES


class AzureFederatedIdentityRuleDetectors:
    def __init__(self, finding_factory: FindingFactory) -> None:
        self._finding_factory = finding_factory

    def detect_privileged_access(
        self,
        context: RuleEvaluationContext,
        rule_id: str,
    ) -> list[Finding]:
        if context.inventory.provider != "azure":
            return []

        findings: list[Finding] = []
        for identity in context.inventory.by_type(AzureResourceType.USER_ASSIGNED_IDENTITY):
            facts = azure_facts(identity)
            paths = _deterministic_trust_paths(identity)
            if not paths:
                continue
            grants = tuple(
                grant for grant in facts.privileged_access_grants if _reportable_identity_grant(identity, grant)
            )
            if not grants:
                continue

            severity_reasoning = _severity_for_grants(grants)
            findings.append(
                self._finding_factory.build(
                    rule_id=rule_id,
                    severity=severity_reasoning.severity,
                    affected_resources=_affected_resources(identity, paths, grants),
                    trust_boundary_id=None,
                    rationale=(
                        f"{identity.display_name} accepts deterministic external federated credentials and has "
                        f"privileged Azure RBAC access: {_grant_summary(grants)}. A subject admitted by the "
                        "represented issuer and audience can obtain the managed identity's assigned privileges."
                    ),
                    evidence=collect_evidence(
                        evidence_item("federated_trust", _federated_trust_evidence(paths)),
                        evidence_item("managed_identity", _managed_identity_evidence(identity)),
                        evidence_item("rbac_assignments", _rbac_assignment_evidence(grants)),
                        evidence_item("privilege_categories", _privilege_category_evidence(grants)),
                        evidence_item("permission_patterns", _permission_pattern_evidence(grants)),
                    ),
                    severity_reasoning=severity_reasoning,
                )
            )
        return findings


def _deterministic_trust_paths(identity: NormalizedResource) -> list[Mapping[str, Any]]:
    paths: list[Mapping[str, Any]] = []
    for path in azure_facts(identity).federated_managed_identity_trust_paths:
        identity_address = _known_path_string(path.get("identity_address"))
        credential_address = _known_path_string(path.get("credential_address"))
        issuer = _known_path_string(path.get("issuer"))
        subject = _known_path_string(path.get("subject"))
        audiences = _known_path_strings(path.get("audiences"))
        if (
            identity_address != identity.address
            or credential_address is None
            or issuer is None
            or subject is None
            or not audiences
        ):
            continue
        paths.append(path)
    return paths


def _reportable_identity_grant(
    identity: NormalizedResource,
    grant: PrivilegedAccessGrant,
) -> bool:
    facts = azure_facts(identity)
    if grant.confidence != PrivilegeConfidence.HIGH or grant.has_uncertainty:
        return False
    if grant.principal.principal_type != PrincipalType.MANAGED_IDENTITY:
        return False
    if grant.principal.source_address != identity.address:
        return False
    if facts.principal_id is None or grant.principal.identifier != facts.principal_id:
        return False
    if not grant.assignment_source_address or not (grant.role_name or grant.role_id):
        return False
    if grant.assignment_scope.scope_kind == AssignmentScopeKind.UNKNOWN or not grant.assignment_scope.value:
        return False
    return bool(set(grant.privilege_categories) & _REPORTABLE_CATEGORIES)


def _severity_for_grants(grants: tuple[PrivilegedAccessGrant, ...]):
    categories = _grant_categories(grants)
    high_impact = bool(categories & _HIGH_IMPACT_CATEGORIES)
    data_access = bool(categories & _DATA_ACCESS_CATEGORIES)
    control_plane = bool(categories & _CONTROL_PLANE_CATEGORIES)
    broad_scope = any(grant.has_broad_scope for grant in grants)
    return build_severity_reasoning(
        internet_exposure=False,
        privilege_breadth=3 if high_impact else 2,
        data_sensitivity=2 if data_access else 0,
        lateral_movement=2 if high_impact or control_plane else 1,
        blast_radius=3 if broad_scope else 1,
    )


def _affected_resources(
    identity: NormalizedResource,
    paths: list[Mapping[str, Any]],
    grants: tuple[PrivilegedAccessGrant, ...],
) -> list[str]:
    return dedupe_addresses(
        [
            identity.address,
            *(
                credential_address
                for path in paths
                if (credential_address := _known_path_string(path.get("credential_address")))
            ),
            *(grant.assignment_source_address or "" for grant in grants),
            *(grant.assignment_scope.source_address or "" for grant in grants),
        ]
    )


def _federated_trust_evidence(paths: list[Mapping[str, Any]]) -> list[str]:
    return dedupe_strings(
        f"credential={path.get('credential_address')}; issuer={path.get('issuer')}; "
        f"subject={path.get('subject')}; audiences=[{', '.join(_known_path_strings(path.get('audiences')))}]"
        for path in paths
    )


def _managed_identity_evidence(identity: NormalizedResource) -> list[str]:
    facts = azure_facts(identity)
    return [
        value
        for value in (
            f"address={identity.address}",
            f"principal_id={facts.principal_id}" if facts.principal_id else None,
            f"client_id={facts.client_id}" if facts.client_id else None,
        )
        if value
    ]


def _rbac_assignment_evidence(grants: tuple[PrivilegedAccessGrant, ...]) -> list[str]:
    return dedupe_strings(
        f"assignment={grant.assignment_source_address}; role={grant.role_name or grant.role_id}; "
        f"scope={grant.assignment_scope.value}; scope_kind={grant.assignment_scope.scope_kind.value}"
        for grant in grants
    )


def _grant_categories(grants: tuple[PrivilegedAccessGrant, ...]) -> set[PrivilegeCategory]:
    return {category for grant in grants for category in grant.privilege_categories}


def _privilege_category_evidence(grants: tuple[PrivilegedAccessGrant, ...]) -> list[str]:
    return sorted(category.value for category in _grant_categories(grants))


def _permission_pattern_evidence(grants: tuple[PrivilegedAccessGrant, ...]) -> list[str]:
    return dedupe_strings(pattern for grant in grants for pattern in grant.permission_patterns)


def _grant_summary(grants: tuple[PrivilegedAccessGrant, ...]) -> str:
    categories = _privilege_category_evidence(grants)
    return ", ".join(categories) if categories else "privileged access"


def _known_path_string(value: object) -> str | None:
    if value in (None, ""):
        return None
    normalized = str(value).strip()
    if not normalized or "$" + "{" in normalized or "}" in normalized:
        return None
    return normalized


def _known_path_strings(value: object) -> list[str]:
    if not isinstance(value, list | tuple):
        return []
    return [normalized for item in value if (normalized := _known_path_string(item)) is not None]
