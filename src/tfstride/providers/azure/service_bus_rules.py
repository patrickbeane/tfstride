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
from tfstride.providers.azure.resource_utils import tls_version_below_1_2
from tfstride.providers.coercion import STATE_CONFIGURED


class AzureServiceBusRuleDetectors:
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
        for namespace in context.inventory.by_type(AzureResourceType.SERVICE_BUS_NAMESPACE):
            facts = azure_facts(namespace)
            if facts.public_network_fallback_state == PUBLIC_NETWORK_FALLBACK_DISABLED:
                continue
            public_enabled = facts.public_network_access_enabled is True
            default_deny = _network_default_action_is_deny(facts.network_default_action)
            severity_reasoning = build_severity_reasoning(
                internet_exposure=public_enabled and not default_deny,
                privilege_breadth=0,
                data_sensitivity=1,
                lateral_movement=0,
                blast_radius=1 if public_enabled and not default_deny else 0,
            )
            findings.append(
                self._finding_factory.build(
                    rule_id=rule_id,
                    severity=severity_reasoning.severity,
                    affected_resources=[namespace.address],
                    trust_boundary_id=None,
                    rationale=(
                        f"{namespace.display_name} does not explicitly disable public network access. An effective "
                        "default-deny network rule can reduce exposure, but it does not prove Service Bus is "
                        "reachable only through private connectivity."
                    ),
                    evidence=collect_evidence(
                        evidence_item("target_resource", _target_resource_evidence(namespace, facts)),
                        evidence_item("network_posture", _network_posture_evidence(facts)),
                        evidence_item("posture_uncertainty", _network_uncertainty_evidence(facts)),
                    ),
                    severity_reasoning=severity_reasoning,
                )
            )
        return findings

    def detect_minimum_tls_below_1_2(
        self,
        context: RuleEvaluationContext,
        rule_id: str,
    ) -> list[Finding]:
        if context.inventory.provider != "azure":
            return []

        findings: list[Finding] = []
        for namespace in context.inventory.by_type(AzureResourceType.SERVICE_BUS_NAMESPACE):
            facts = azure_facts(namespace)
            tls_version = facts.min_tls_version
            if not tls_version_below_1_2(tls_version):
                continue
            severity_reasoning = _service_bus_severity(facts)
            findings.append(
                self._finding_factory.build(
                    rule_id=rule_id,
                    severity=severity_reasoning.severity,
                    affected_resources=[namespace.address],
                    trust_boundary_id=None,
                    rationale=(
                        f"{namespace.display_name} accepts `{tls_version}` as its minimum TLS version. "
                        "Deprecated TLS versions weaken transport protection for Service Bus client connections."
                    ),
                    evidence=collect_evidence(
                        evidence_item("target_resource", _target_resource_evidence(namespace, facts)),
                        evidence_item("transport_posture", [f"minimum_tls_version is {tls_version}"]),
                        evidence_item("network_posture", _network_posture_evidence(facts)),
                    ),
                    severity_reasoning=severity_reasoning,
                )
            )
        return findings

    def detect_minimum_tls_unknown(
        self,
        context: RuleEvaluationContext,
        rule_id: str,
    ) -> list[Finding]:
        if context.inventory.provider != "azure":
            return []

        findings: list[Finding] = []
        for namespace in context.inventory.by_type(AzureResourceType.SERVICE_BUS_NAMESPACE):
            facts = azure_facts(namespace)
            if facts.min_tls_version is not None:
                continue
            severity_reasoning = _service_bus_severity(facts)
            findings.append(
                self._finding_factory.build(
                    rule_id=rule_id,
                    severity=severity_reasoning.severity,
                    affected_resources=[namespace.address],
                    trust_boundary_id=None,
                    rationale=(
                        f"{namespace.display_name} does not expose a deterministic minimum TLS version in the "
                        "Terraform plan. tfSTRIDE cannot prove that Service Bus client connections require TLS 1.2 "
                        "or newer from the available data."
                    ),
                    evidence=collect_evidence(
                        evidence_item("target_resource", _target_resource_evidence(namespace, facts)),
                        evidence_item("transport_posture", _tls_unknown_evidence(facts)),
                        evidence_item("network_posture", _network_posture_evidence(facts)),
                        evidence_item("posture_uncertainty", _tls_uncertainty_evidence(facts)),
                    ),
                    severity_reasoning=severity_reasoning,
                )
            )
        return findings

    def detect_local_auth_enabled(
        self,
        context: RuleEvaluationContext,
        rule_id: str,
    ) -> list[Finding]:
        if context.inventory.provider != "azure":
            return []

        findings: list[Finding] = []
        for namespace in context.inventory.by_type(AzureResourceType.SERVICE_BUS_NAMESPACE):
            facts = azure_facts(namespace)
            if facts.service_bus_local_auth_enabled is not True:
                continue
            severity_reasoning = _service_bus_severity(facts, privilege_breadth=1)
            findings.append(
                self._finding_factory.build(
                    rule_id=rule_id,
                    severity=severity_reasoning.severity,
                    affected_resources=[namespace.address],
                    trust_boundary_id=None,
                    rationale=(
                        f"{namespace.display_name} permits local/SAS authorization. This does not prove shared "
                        "access signatures are currently used, but it permits credentials that bypass Microsoft "
                        "Entra ID authorization controls."
                    ),
                    evidence=collect_evidence(
                        evidence_item("target_resource", _target_resource_evidence(namespace, facts)),
                        evidence_item("authorization_posture", ["local_auth_enabled is true"]),
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
        for namespace in context.inventory.by_type(AzureResourceType.SERVICE_BUS_NAMESPACE):
            facts = azure_facts(namespace)
            if not facts.service_bus_is_premium_tier:
                continue
            cmk_state = facts.service_bus_customer_managed_key_state
            if cmk_state == STATE_CONFIGURED:
                continue
            unknown = cmk_state is None or cmk_state == "unknown"
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
                    affected_resources=[namespace.address],
                    trust_boundary_id=None,
                    rationale=(
                        f"{namespace.display_name} does not show configured customer-managed key control. Azure "
                        "Service Bus encryption at rest remains in place; this finding concerns customer key "
                        "ownership, rotation, and separation-of-duties controls."
                    ),
                    evidence=collect_evidence(
                        evidence_item("target_resource", _target_resource_evidence(namespace, facts)),
                        evidence_item("encryption_ownership", _customer_managed_key_evidence(facts, cmk_state)),
                        evidence_item("posture_uncertainty", _cmk_uncertainty_evidence(facts)),
                    ),
                    severity_reasoning=severity_reasoning,
                )
            )
        return findings


def _service_bus_severity(
    facts: AzureResourceFacts,
    *,
    privilege_breadth: int = 0,
):
    public_enabled = facts.public_network_fallback_state == PUBLIC_NETWORK_FALLBACK_ENABLED
    default_deny = _network_default_action_is_deny(facts.network_default_action)
    return build_severity_reasoning(
        internet_exposure=public_enabled and not default_deny,
        privilege_breadth=privilege_breadth,
        data_sensitivity=1,
        lateral_movement=0,
        blast_radius=1 if public_enabled and not default_deny else 0,
    )


def _target_resource_evidence(resource: NormalizedResource, facts: AzureResourceFacts) -> list[str]:
    values = [f"address={resource.address}", f"type={resource.resource_type}"]
    if facts.service_bus_sku:
        values.append(f"sku={facts.service_bus_sku}")
    if facts.service_bus_tier:
        values.append(f"tier={facts.service_bus_tier}")
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
    source_address = facts.service_bus_network_rule_source_address or facts.network_rule_source_address
    if source_address:
        values.append(f"network rule source is {source_address}")
    return values


def _network_uncertainty_evidence(facts: AzureResourceFacts) -> list[str]:
    if facts.public_network_fallback_state != PUBLIC_NETWORK_FALLBACK_UNKNOWN:
        return []
    uncertainties = [
        uncertainty
        for uncertainty in facts.service_bus_posture_uncertainties
        if "public_network_access_enabled" in uncertainty
    ]
    return uncertainties or ["public_network_access_enabled is not represented in planned values"]


def _tls_unknown_evidence(facts: AzureResourceFacts) -> list[str]:
    if _tls_uncertainty_evidence(facts):
        return ["minimum_tls_version is unknown"]
    return ["minimum_tls_version is not represented in planned values"]


def _tls_uncertainty_evidence(facts: AzureResourceFacts) -> list[str]:
    return [
        uncertainty for uncertainty in facts.service_bus_posture_uncertainties if "minimum_tls_version" in uncertainty
    ]


def _customer_managed_key_evidence(
    facts: AzureResourceFacts,
    cmk_state: str | None,
) -> list[str]:
    values = [f"customer_managed_key_state={cmk_state or 'unknown'}"]
    if facts.service_bus_key_vault_key_id:
        values.append(f"key_vault_key_id={facts.service_bus_key_vault_key_id}")
    else:
        values.append("key_vault_key_id is unset")
    if facts.service_bus_customer_managed_key_source_address:
        values.append(f"cmk source is {facts.service_bus_customer_managed_key_source_address}")
    values.append("Azure Service Bus encryption at rest remains in place; this finding concerns customer key control")
    return values


def _cmk_uncertainty_evidence(facts: AzureResourceFacts) -> list[str]:
    return [
        uncertainty
        for uncertainty in facts.service_bus_posture_uncertainties
        if "customer_managed_key" in uncertainty or "key_vault_key_id" in uncertainty
    ]


def _network_default_action_is_deny(default_action: str | None) -> bool:
    return bool(default_action and default_action.strip().lower() == "deny")
