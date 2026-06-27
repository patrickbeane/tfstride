from __future__ import annotations

from collections.abc import Callable, Iterable

from tfstride.analysis.finding_factory import FindingFactory
from tfstride.analysis.finding_helpers import build_severity_reasoning, collect_evidence, evidence_item
from tfstride.analysis.rule_definitions import RuleEvaluationContext
from tfstride.models import Finding, NormalizedResource
from tfstride.providers.azure.rbac_breadth import (
    COMPUTE_MANAGEMENT,
    KEY_VAULT_DATA_PLANE,
    NETWORK_MANAGEMENT,
    OWNER_LIKE_OR_WILDCARD,
    RESOURCE_GROUP_SUBSCRIPTION_WIDE_MANAGEMENT,
    ROLE_ASSIGNMENT_CAPABLE,
    STORAGE_DATA_PLANE,
    UNKNOWN_CUSTOM_WILDCARD,
)
from tfstride.providers.azure.resource_facts import AzureResourceFacts, azure_facts
from tfstride.providers.azure.resource_types import AzureResourceType

_MANAGEMENT_WILDCARD_SIGNALS = frozenset(
    {
        COMPUTE_MANAGEMENT,
        NETWORK_MANAGEMENT,
        RESOURCE_GROUP_SUBSCRIPTION_WIDE_MANAGEMENT,
        UNKNOWN_CUSTOM_WILDCARD,
    }
)
_DATA_PLANE_SIGNALS = frozenset({STORAGE_DATA_PLANE, KEY_VAULT_DATA_PLANE})
_SUBSCRIPTION_SCOPE_PREFIX = "/subscriptions/"
_RESOURCE_GROUP_SCOPE_MARKER = "/resourcegroups/"


class AzureCustomRoleRuleDetectors:
    def __init__(self, finding_factory: FindingFactory) -> None:
        self._finding_factory = finding_factory

    def detect_wildcard_management_plane(
        self,
        context: RuleEvaluationContext,
        rule_id: str,
    ) -> list[Finding]:
        return self._detect_custom_role_posture(
            context,
            rule_id,
            predicate=lambda facts: _has_exact_wildcard(facts.role_definition_actions),
            rationale=(
                "grants wildcard management-plane permissions. This custom role can authorize broad control-plane "
                "operations if assigned."
            ),
            evidence_key="management_actions",
            evidence_values=lambda facts: facts.role_definition_actions,
            privilege_breadth=3,
            data_sensitivity=0,
            lateral_movement=1,
        )

    def detect_authorization_management(
        self,
        context: RuleEvaluationContext,
        rule_id: str,
    ) -> list[Finding]:
        return self._detect_custom_role_posture(
            context,
            rule_id,
            predicate=lambda facts: ROLE_ASSIGNMENT_CAPABLE in facts.role_definition_breadth_signals,
            rationale=(
                "grants authorization-management permissions that can create or modify role assignments. This "
                "custom role can expand access paths if assigned."
            ),
            evidence_key="authorization_actions",
            evidence_values=_authorization_action_evidence,
            privilege_breadth=3,
            data_sensitivity=0,
            lateral_movement=1,
        )

    def detect_broad_management_plane(
        self,
        context: RuleEvaluationContext,
        rule_id: str,
    ) -> list[Finding]:
        return self._detect_custom_role_posture(
            context,
            rule_id,
            predicate=_has_broad_management_plane_wildcard,
            rationale=(
                "grants broad management-plane wildcard permissions. This custom role can modify Azure service "
                "configuration broadly if assigned."
            ),
            evidence_key="management_actions",
            evidence_values=_management_wildcard_action_evidence,
            privilege_breadth=2,
            data_sensitivity=0,
            lateral_movement=1,
        )

    def detect_broad_data_plane(
        self,
        context: RuleEvaluationContext,
        rule_id: str,
    ) -> list[Finding]:
        return self._detect_custom_role_posture(
            context,
            rule_id,
            predicate=_has_broad_data_plane_wildcard,
            rationale=(
                "grants broad storage or Key Vault data-plane permissions. This custom role can read or alter "
                "sensitive data-plane resources broadly if assigned."
            ),
            evidence_key="data_plane_actions",
            evidence_values=_data_plane_action_evidence,
            privilege_breadth=2,
            data_sensitivity=2,
            lateral_movement=0,
        )

    def detect_subscription_assignable_scope(
        self,
        context: RuleEvaluationContext,
        rule_id: str,
    ) -> list[Finding]:
        return self._detect_custom_role_posture(
            context,
            rule_id,
            predicate=lambda facts: _assignable_scope_kind(facts) == "subscription",
            rationale=(
                "is assignable at subscription scope. A subscription-wide assignable scope increases blast radius "
                "if this custom role is assigned later."
            ),
            evidence_key="scope_posture",
            evidence_values=lambda facts: ["custom role is assignable at subscription scope"],
            privilege_breadth=1,
            data_sensitivity=0,
            lateral_movement=0,
        )

    def detect_assigned_custom_role_blast_radius(
        self,
        context: RuleEvaluationContext,
        rule_id: str,
    ) -> list[Finding]:
        if context.inventory.provider != "azure":
            return []

        resources_by_address = {resource.address: resource for resource in context.inventory.resources}
        findings: list[Finding] = []
        for assignment in context.inventory.by_type(AzureResourceType.ROLE_ASSIGNMENT):
            assignment_facts = azure_facts(assignment)
            if not assignment_facts.principal_id:
                continue
            role = resources_by_address.get(assignment_facts.resolved_role_definition_address or "")
            if role is None or role.resource_type != AzureResourceType.ROLE_DEFINITION:
                continue
            role_facts = azure_facts(role)
            breadth_reasons = _assigned_custom_role_breadth_reasons(role_facts)
            if not breadth_reasons:
                continue
            principal = resources_by_address.get(assignment_facts.resolved_managed_identity_address or "")
            scope_kind = assignment_facts.role_assignment_scope_kind
            severity_reasoning = _assigned_custom_role_severity(
                role_facts=role_facts,
                assignment_facts=assignment_facts,
                principal=principal,
                breadth_reasons=breadth_reasons,
            )
            findings.append(
                self._finding_factory.build(
                    rule_id=rule_id,
                    severity=severity_reasoning.severity,
                    affected_resources=_assigned_custom_role_affected_resources(
                        role=role,
                        assignment=assignment,
                        assignment_facts=assignment_facts,
                        principal=principal,
                    ),
                    trust_boundary_id=None,
                    rationale=(
                        f"{_principal_subject(assignment_facts, principal)} is assigned {role.display_name}, "
                        f"a custom Azure role with {_assigned_custom_role_reason_summary(breadth_reasons)} "
                        f"at {_scope_label(scope_kind)} scope. This is active RBAC blast-radius evidence because "
                        "the role definition and role assignment resolve deterministically in the Terraform plan."
                    ),
                    evidence=collect_evidence(
                        evidence_item("custom_role", _custom_role_evidence(role, role_facts)),
                        evidence_item("role_assignment", _role_assignment_evidence(assignment, assignment_facts)),
                        evidence_item("assigned_principal", _assigned_principal_evidence(assignment_facts, principal)),
                        evidence_item("breadth_reasons", breadth_reasons),
                        evidence_item("role_breadth_signals", role_facts.role_definition_breadth_signals),
                        evidence_item("assignment_breadth_signals", assignment_facts.role_assignment_breadth_signals),
                        evidence_item("management_actions", _management_wildcard_action_evidence(role_facts)),
                        evidence_item("authorization_actions", _authorization_action_evidence(role_facts)),
                        evidence_item("data_plane_actions", _data_plane_action_evidence(role_facts)),
                        evidence_item("assignable_scopes", _assignable_scope_evidence(role_facts)),
                        evidence_item("mitigating_exclusions", role_facts.role_definition_breadth_mitigations),
                    ),
                    severity_reasoning=severity_reasoning,
                )
            )
        return findings

    def _detect_custom_role_posture(
        self,
        context: RuleEvaluationContext,
        rule_id: str,
        *,
        predicate: Callable[[AzureResourceFacts], bool],
        rationale: str,
        evidence_key: str,
        evidence_values: Callable[[AzureResourceFacts], list[str]],
        privilege_breadth: int,
        data_sensitivity: int,
        lateral_movement: int,
    ) -> list[Finding]:
        if context.inventory.provider != "azure":
            return []

        findings: list[Finding] = []
        for role in _custom_role_definitions(context.inventory.resources):
            facts = azure_facts(role)
            if not predicate(facts):
                continue
            scope_kind = _assignable_scope_kind(facts)
            adjusted_privilege_breadth = max(privilege_breadth, _scope_privilege_breadth(facts, privilege_breadth))
            severity_reasoning = build_severity_reasoning(
                internet_exposure=False,
                privilege_breadth=adjusted_privilege_breadth,
                data_sensitivity=data_sensitivity,
                lateral_movement=lateral_movement,
                blast_radius=_assignable_scope_blast_radius(scope_kind),
            )
            findings.append(
                self._finding_factory.build(
                    rule_id=rule_id,
                    severity=severity_reasoning.severity,
                    affected_resources=[role.address],
                    trust_boundary_id=None,
                    rationale=(
                        f"{role.display_name} {rationale} This is custom role-definition posture only; "
                        "tfSTRIDE is not asserting that any principal currently has this access from the role "
                        "definition alone."
                    ),
                    evidence=collect_evidence(
                        evidence_item("custom_role", _custom_role_evidence(role, facts)),
                        evidence_item(evidence_key, evidence_values(facts)),
                        evidence_item("assignable_scopes", _assignable_scope_evidence(facts)),
                        evidence_item("breadth_signals", facts.role_definition_breadth_signals),
                        evidence_item("mitigating_exclusions", facts.role_definition_breadth_mitigations),
                        evidence_item("uncertainties", facts.role_definition_uncertainties),
                    ),
                    severity_reasoning=severity_reasoning,
                )
            )
        return findings


def _assigned_custom_role_breadth_reasons(facts: AzureResourceFacts) -> list[str]:
    reasons: list[str] = []
    if _has_exact_wildcard(facts.role_definition_actions):
        reasons.append("wildcard_management_plane")
    if _has_exact_wildcard(facts.role_definition_data_actions):
        reasons.append("wildcard_data_plane")
    if ROLE_ASSIGNMENT_CAPABLE in facts.role_definition_breadth_signals:
        reasons.append("authorization_management")
    if _has_broad_management_plane_wildcard(facts):
        reasons.append("broad_management_plane")
    if not _has_exact_wildcard(facts.role_definition_data_actions) and _has_broad_data_plane_wildcard(facts):
        reasons.append("broad_data_plane")
    return list(dict.fromkeys(reasons))


def _assigned_custom_role_severity(
    *,
    role_facts: AzureResourceFacts,
    assignment_facts: AzureResourceFacts,
    principal: NormalizedResource | None,
    breadth_reasons: list[str],
):
    scope_kind = assignment_facts.role_assignment_scope_kind
    privilege_breadth = 3 if _assigned_custom_role_is_high_privilege(role_facts, breadth_reasons) else 2
    data_sensitivity = 2 if _assigned_custom_role_has_data_plane_breadth(breadth_reasons) else 0
    lateral_movement = 1 if principal is not None or _principal_type_is_service_identity(assignment_facts) else 0
    if "authorization_management" in breadth_reasons:
        lateral_movement = max(lateral_movement, 2 if scope_kind in {"subscription", "resource_group"} else 1)
    elif "broad_management_plane" in breadth_reasons:
        lateral_movement = max(lateral_movement, 1)
    return build_severity_reasoning(
        internet_exposure=False,
        privilege_breadth=privilege_breadth,
        data_sensitivity=data_sensitivity,
        lateral_movement=lateral_movement,
        blast_radius=_assignment_scope_blast_radius(scope_kind),
    )


def _principal_type_is_service_identity(facts: AzureResourceFacts) -> bool:
    principal_type = (facts.principal_type or "").replace("_", "").replace(" ", "").lower()
    return principal_type in {"serviceprincipal", "managedidentity"}


def _assigned_custom_role_is_high_privilege(facts: AzureResourceFacts, breadth_reasons: list[str]) -> bool:
    signals = set(facts.role_definition_breadth_signals)
    return bool(
        OWNER_LIKE_OR_WILDCARD in signals
        or ROLE_ASSIGNMENT_CAPABLE in signals
        or "wildcard_management_plane" in breadth_reasons
        or "wildcard_data_plane" in breadth_reasons
    )


def _assigned_custom_role_has_data_plane_breadth(breadth_reasons: list[str]) -> bool:
    return bool({"wildcard_data_plane", "broad_data_plane"} & set(breadth_reasons))


def _assignment_scope_blast_radius(scope_kind: str | None) -> int:
    if scope_kind == "subscription":
        return 2
    if scope_kind == "resource_group":
        return 1
    return 0


def _assigned_custom_role_affected_resources(
    *,
    role: NormalizedResource,
    assignment: NormalizedResource,
    assignment_facts: AzureResourceFacts,
    principal: NormalizedResource | None,
) -> list[str]:
    return _dedupe_strings(
        value
        for value in (
            principal.address if principal is not None else None,
            assignment.address,
            role.address,
            assignment_facts.role_assignment_target_resource_address,
        )
        if value
    )


def _role_assignment_evidence(assignment: NormalizedResource, facts: AzureResourceFacts) -> list[str]:
    return [
        value
        for value in (
            f"address={assignment.address}",
            f"scope={facts.role_assignment_scope}" if facts.role_assignment_scope else None,
            f"scope_kind={facts.role_assignment_scope_kind}" if facts.role_assignment_scope_kind else None,
            f"role_definition_id={facts.role_definition_id}" if facts.role_definition_id else None,
            f"resolved_role_definition={facts.resolved_role_definition_address}"
            if facts.resolved_role_definition_address
            else None,
            f"target_resource={facts.role_assignment_target_resource_address}"
            if facts.role_assignment_target_resource_address
            else None,
        )
        if value
    ]


def _assigned_principal_evidence(facts: AzureResourceFacts, principal: NormalizedResource | None) -> list[str]:
    return [
        value
        for value in (
            f"principal_id={facts.principal_id}" if facts.principal_id else None,
            f"principal_type={facts.principal_type}" if facts.principal_type else None,
            f"resolved_managed_identity={principal.address}" if principal is not None else None,
        )
        if value
    ]


def _principal_subject(facts: AzureResourceFacts, principal: NormalizedResource | None) -> str:
    if principal is not None:
        return principal.display_name
    if facts.principal_type and facts.principal_id:
        return f"Azure {facts.principal_type} principal `{facts.principal_id}`"
    if facts.principal_id:
        return f"Azure principal `{facts.principal_id}`"
    return "An Azure principal"


def _assigned_custom_role_reason_summary(reasons: list[str]) -> str:
    labels = {
        "wildcard_management_plane": "wildcard management-plane permissions",
        "wildcard_data_plane": "wildcard data-plane permissions",
        "authorization_management": "authorization-management permissions",
        "broad_management_plane": "broad management-plane permissions",
        "broad_data_plane": "broad data-plane permissions",
    }
    return ", ".join(labels.get(reason, reason) for reason in reasons)


def _scope_label(scope_kind: str | None) -> str:
    return scope_kind or "unknown"


def _dedupe_strings(values: Iterable[str]) -> list[str]:
    return list(dict.fromkeys(value for value in values if value))


def _custom_role_definitions(resources: Iterable[NormalizedResource]) -> list[NormalizedResource]:
    return [
        resource
        for resource in resources
        if resource.resource_type == AzureResourceType.ROLE_DEFINITION
        and azure_facts(resource).is_custom_role_definition
    ]


def _custom_role_evidence(role: NormalizedResource, facts: AzureResourceFacts) -> list[str]:
    return [
        value
        for value in (
            f"address={role.address}",
            f"name={facts.name}" if facts.name else None,
            f"role_definition_id={facts.role_definition_id}" if facts.role_definition_id else None,
            f"scope={facts.role_definition_scope}" if facts.role_definition_scope else None,
        )
        if value
    ]


def _assignable_scope_evidence(facts: AzureResourceFacts) -> list[str]:
    return facts.role_definition_assignable_scopes or ["assignable_scopes not captured"]


def _authorization_action_evidence(facts: AzureResourceFacts) -> list[str]:
    return [
        action
        for action in facts.role_definition_actions
        if _normalized_action(action).startswith("microsoft.authorization/")
    ]


def _management_wildcard_action_evidence(facts: AzureResourceFacts) -> list[str]:
    return [action for action in facts.role_definition_actions if "*" in action]


def _data_plane_action_evidence(facts: AzureResourceFacts) -> list[str]:
    return [
        *[action for action in facts.role_definition_actions if _is_data_plane_wildcard(action)],
        *[action for action in facts.role_definition_data_actions if _is_data_plane_wildcard(action) or action == "*"],
    ]


def _has_broad_management_plane_wildcard(facts: AzureResourceFacts) -> bool:
    if _has_exact_wildcard(facts.role_definition_actions):
        return False
    if not any("*" in action for action in facts.role_definition_actions):
        return False
    return bool(set(facts.role_definition_breadth_signals) & _MANAGEMENT_WILDCARD_SIGNALS)


def _has_broad_data_plane_wildcard(facts: AzureResourceFacts) -> bool:
    if _has_exact_wildcard(facts.role_definition_data_actions):
        return True
    if not bool(set(facts.role_definition_breadth_signals) & _DATA_PLANE_SIGNALS):
        return False
    return any(_is_data_plane_wildcard(action) for action in facts.role_definition_actions) or any(
        _is_data_plane_wildcard(action) for action in facts.role_definition_data_actions
    )


def _is_data_plane_wildcard(action: str) -> bool:
    normalized = _normalized_action(action)
    return "*" in normalized and (
        normalized.startswith("microsoft.storage/storageaccounts/")
        or normalized.startswith("microsoft.keyvault/vaults/")
    )


def _has_exact_wildcard(actions: Iterable[str]) -> bool:
    return any(action.strip() == "*" for action in actions)


def _assignable_scope_kind(facts: AzureResourceFacts) -> str | None:
    for scope in facts.role_definition_assignable_scopes:
        normalized = _normalized_scope(scope)
        if normalized.startswith(_SUBSCRIPTION_SCOPE_PREFIX) and _RESOURCE_GROUP_SCOPE_MARKER not in normalized:
            return "subscription"
    for scope in facts.role_definition_assignable_scopes:
        normalized = _normalized_scope(scope)
        if _RESOURCE_GROUP_SCOPE_MARKER in normalized:
            return "resource_group"
    return None


def _assignable_scope_blast_radius(scope_kind: str | None) -> int:
    if scope_kind == "subscription":
        return 2
    if scope_kind == "resource_group":
        return 1
    return 0


def _scope_privilege_breadth(facts: AzureResourceFacts, baseline: int) -> int:
    signals = set(facts.role_definition_breadth_signals)
    if OWNER_LIKE_OR_WILDCARD in signals or ROLE_ASSIGNMENT_CAPABLE in signals:
        return max(baseline, 3)
    if signals:
        return max(baseline, 2)
    return baseline


def _normalized_action(action: str) -> str:
    return action.strip().lower()


def _normalized_scope(scope: str) -> str:
    return scope.strip().lower()
