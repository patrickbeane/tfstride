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
