from __future__ import annotations

from tfstride.analysis.finding_factory import FindingFactory
from tfstride.analysis.finding_helpers import build_severity_reasoning, collect_evidence, evidence_item
from tfstride.analysis.rule_definitions import RuleEvaluationContext
from tfstride.models import Finding, NormalizedResource
from tfstride.providers.azure.public_network import (
    PUBLIC_NETWORK_FALLBACK_DISABLED,
    PUBLIC_NETWORK_FALLBACK_ENABLED,
    PUBLIC_NETWORK_FALLBACK_UNKNOWN,
)
from tfstride.providers.azure.resource_facts import AzureResourceFacts, azure_facts
from tfstride.providers.azure.resource_types import AzureResourceType
from tfstride.providers.coercion import STATE_CONFIGURED, STATE_UNKNOWN


class AzureContainerRegistryRuleDetectors:
    def __init__(self, finding_factory: FindingFactory) -> None:
        self._finding_factory = finding_factory

    def detect_public_network_access_not_disabled(
        self,
        context: RuleEvaluationContext,
        rule_id: str,
    ) -> list[Finding]:
        if context.inventory.provider != "azure":
            return []

        findings: list[Finding] = []
        for registry in context.inventory.by_type(AzureResourceType.CONTAINER_REGISTRY):
            facts = azure_facts(registry)
            if facts.public_network_fallback_state == PUBLIC_NETWORK_FALLBACK_DISABLED:
                continue
            severity_reasoning = _registry_severity(facts)
            findings.append(
                self._finding_factory.build(
                    rule_id=rule_id,
                    severity=severity_reasoning.severity,
                    affected_resources=[registry.address],
                    trust_boundary_id=None,
                    rationale=(
                        f"{registry.display_name} does not explicitly disable public network access. An effective "
                        "default-deny network rule can reduce exposure, but it does not prove that registry data-plane "
                        "access is private-only."
                    ),
                    evidence=collect_evidence(
                        evidence_item("target_resource", _target_resource_evidence(registry, facts)),
                        evidence_item("network_posture", _network_posture_evidence(facts)),
                        evidence_item("posture_uncertainty", _network_uncertainty_evidence(facts)),
                    ),
                    severity_reasoning=severity_reasoning,
                )
            )
        return findings

    def detect_admin_account_enabled(
        self,
        context: RuleEvaluationContext,
        rule_id: str,
    ) -> list[Finding]:
        if context.inventory.provider != "azure":
            return []

        findings: list[Finding] = []
        for registry in context.inventory.by_type(AzureResourceType.CONTAINER_REGISTRY):
            facts = azure_facts(registry)
            if facts.container_registry_admin_enabled is not True:
                continue
            severity_reasoning = _registry_severity(facts, privilege_breadth=1)
            findings.append(
                self._finding_factory.build(
                    rule_id=rule_id,
                    severity=severity_reasoning.severity,
                    affected_resources=[registry.address],
                    trust_boundary_id=None,
                    rationale=(
                        f"{registry.display_name} enables the Container Registry admin account. This permits shared "
                        "registry credentials outside Microsoft Entra ID and managed-identity authorization controls."
                    ),
                    evidence=collect_evidence(
                        evidence_item("target_resource", _target_resource_evidence(registry, facts)),
                        evidence_item("authorization_posture", ["admin_enabled is true"]),
                        evidence_item("network_posture", _network_posture_evidence(facts)),
                    ),
                    severity_reasoning=severity_reasoning,
                )
            )
        return findings

    def detect_anonymous_pull_enabled(
        self,
        context: RuleEvaluationContext,
        rule_id: str,
    ) -> list[Finding]:
        if context.inventory.provider != "azure":
            return []

        findings: list[Finding] = []
        for registry in context.inventory.by_type(AzureResourceType.CONTAINER_REGISTRY):
            facts = azure_facts(registry)
            if facts.container_registry_anonymous_pull_enabled is not True:
                continue
            severity_reasoning = _registry_severity(facts, data_sensitivity=2)
            findings.append(
                self._finding_factory.build(
                    rule_id=rule_id,
                    severity=severity_reasoning.severity,
                    affected_resources=[registry.address],
                    trust_boundary_id=None,
                    rationale=(
                        f"{registry.display_name} permits anonymous image pulls. Repository content can be read "
                        "without registry authentication where network access permits it."
                    ),
                    evidence=collect_evidence(
                        evidence_item("target_resource", _target_resource_evidence(registry, facts)),
                        evidence_item("authorization_posture", ["anonymous_pull_enabled is true"]),
                        evidence_item("network_posture", _network_posture_evidence(facts)),
                    ),
                    severity_reasoning=severity_reasoning,
                )
            )
        return findings

    def detect_customer_managed_key_missing(
        self,
        context: RuleEvaluationContext,
        rule_id: str,
    ) -> list[Finding]:
        if context.inventory.provider != "azure":
            return []

        findings: list[Finding] = []
        for registry in context.inventory.by_type(AzureResourceType.CONTAINER_REGISTRY):
            facts = azure_facts(registry)
            if facts.container_registry_is_premium is not True:
                continue
            cmk_state = facts.container_registry_customer_managed_key_state
            if cmk_state == STATE_CONFIGURED:
                continue
            unknown = cmk_state in (None, STATE_UNKNOWN)
            severity_reasoning = build_severity_reasoning(
                internet_exposure=False,
                privilege_breadth=0,
                data_sensitivity=1 if unknown else 2,
                lateral_movement=0,
                blast_radius=0 if unknown else 1,
            )
            findings.append(
                self._finding_factory.build(
                    rule_id=rule_id,
                    severity=severity_reasoning.severity,
                    affected_resources=[registry.address],
                    trust_boundary_id=None,
                    rationale=(
                        f"{registry.display_name} does not show configured customer-managed key control. Azure "
                        "Container Registry encryption at rest remains in place; this finding concerns customer key "
                        "ownership, rotation, and separation-of-duties controls."
                    ),
                    evidence=collect_evidence(
                        evidence_item("target_resource", _target_resource_evidence(registry, facts)),
                        evidence_item("encryption_ownership", _customer_managed_key_evidence(facts)),
                        evidence_item("posture_uncertainty", _cmk_uncertainty_evidence(facts)),
                    ),
                    severity_reasoning=severity_reasoning,
                )
            )
        return findings


def _registry_severity(
    facts: AzureResourceFacts,
    *,
    privilege_breadth: int = 0,
    data_sensitivity: int = 1,
):
    public_enabled = facts.public_network_fallback_state == PUBLIC_NETWORK_FALLBACK_ENABLED
    default_deny = _network_default_action_is_deny(facts.network_default_action)
    return build_severity_reasoning(
        internet_exposure=public_enabled and not default_deny,
        privilege_breadth=privilege_breadth,
        data_sensitivity=data_sensitivity,
        lateral_movement=0,
        blast_radius=1 if public_enabled and not default_deny else 0,
    )


def _target_resource_evidence(resource: NormalizedResource, facts: AzureResourceFacts) -> list[str]:
    values = [f"address={resource.address}", f"type={resource.resource_type}"]
    if facts.container_registry_sku:
        values.append(f"sku={facts.container_registry_sku}")
    if facts.container_registry_login_server:
        values.append(f"login_server={facts.container_registry_login_server}")
    return values


def _network_posture_evidence(facts: AzureResourceFacts) -> list[str]:
    values = [f"public_network_fallback_state={facts.public_network_fallback_state}"]
    if facts.public_network_access_enabled is True:
        values.append("public_network_access_enabled is true")
    elif facts.public_network_access_enabled is False:
        values.append("public_network_access_enabled is false")
    else:
        values.append("public_network_access_enabled is unknown")
    if facts.network_default_action:
        values.append(f"effective default_action is {facts.network_default_action}")
    if facts.network_rule_source_address:
        values.append(f"network rule source is {facts.network_rule_source_address}")
    return values


def _network_uncertainty_evidence(facts: AzureResourceFacts) -> list[str]:
    if facts.public_network_fallback_state != PUBLIC_NETWORK_FALLBACK_UNKNOWN:
        return []
    uncertainties = [
        uncertainty
        for uncertainty in facts.container_registry_posture_uncertainties
        if "public_network_access_enabled" in uncertainty
    ]
    return uncertainties or ["public_network_access_enabled is not represented in planned values"]


def _customer_managed_key_evidence(facts: AzureResourceFacts) -> list[str]:
    values = [f"customer_managed_key_state={facts.container_registry_customer_managed_key_state or 'unknown'}"]
    if facts.container_registry_key_vault_key_id:
        values.append(f"key_vault_key_id={facts.container_registry_key_vault_key_id}")
    else:
        values.append("key_vault_key_id is unset")
    if facts.container_registry_encryption_identity_client_id:
        values.append(f"encryption_identity_client_id={facts.container_registry_encryption_identity_client_id}")
    values.append(
        "Azure Container Registry encryption at rest remains in place; this finding concerns customer key control"
    )
    return values


def _cmk_uncertainty_evidence(facts: AzureResourceFacts) -> list[str]:
    return [
        uncertainty
        for uncertainty in facts.container_registry_posture_uncertainties
        if "encryption" in uncertainty or "key_vault_key_id" in uncertainty
    ]


def _network_default_action_is_deny(default_action: str | None) -> bool:
    return bool(default_action and default_action.strip().lower() == "deny")
