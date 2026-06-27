from __future__ import annotations

from tfstride.analysis.finding_factory import FindingFactory
from tfstride.analysis.finding_helpers import build_severity_reasoning, collect_evidence, evidence_item
from tfstride.analysis.rule_definitions import RuleEvaluationContext
from tfstride.models import Finding
from tfstride.providers.azure.public_network import PUBLIC_NETWORK_FALLBACK_DISABLED
from tfstride.providers.azure.resource_facts import AzureResourceFacts, azure_facts
from tfstride.providers.azure.resource_types import AZURE_APP_SERVICE_RESOURCE_TYPES


class AzureAppServiceRuleDetectors:
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
        for app in context.inventory.by_type(*AZURE_APP_SERVICE_RESOURCE_TYPES):
            facts = azure_facts(app)
            if facts.public_network_fallback_state == PUBLIC_NETWORK_FALLBACK_DISABLED:
                continue
            public_enabled = facts.public_network_access_enabled is True
            severity_reasoning = build_severity_reasoning(
                internet_exposure=public_enabled,
                privilege_breadth=0,
                data_sensitivity=0,
                lateral_movement=0,
                blast_radius=1,
            )
            findings.append(
                self._finding_factory.build(
                    rule_id=rule_id,
                    severity=severity_reasoning.severity,
                    affected_resources=[app.address],
                    trust_boundary_id=None,
                    rationale=(
                        f"{app.display_name} does not explicitly disable public network access. App Service "
                        "public endpoint reachability depends on this setting and any additional platform access "
                        "controls; leave it disabled unless the app intentionally accepts public traffic."
                    ),
                    evidence=collect_evidence(
                        evidence_item("target_resource", _target_resource_evidence(app)),
                        evidence_item("network_posture", _public_network_evidence(facts)),
                        evidence_item("posture_uncertainty", _public_network_uncertainty_evidence(facts)),
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
        for app in context.inventory.by_type(*AZURE_APP_SERVICE_RESOURCE_TYPES):
            facts = azure_facts(app)
            tls_version = facts.min_tls_version
            if not _tls_version_below_1_2(tls_version):
                continue
            public_enabled = facts.public_network_access_enabled is True
            severity_reasoning = build_severity_reasoning(
                internet_exposure=public_enabled,
                privilege_breadth=0,
                data_sensitivity=0,
                lateral_movement=0,
                blast_radius=1,
            )
            findings.append(
                self._finding_factory.build(
                    rule_id=rule_id,
                    severity=severity_reasoning.severity,
                    affected_resources=[app.address],
                    trust_boundary_id=None,
                    rationale=(
                        f"{app.display_name} accepts `{tls_version}` as its minimum TLS version. Deprecated TLS "
                        "versions weaken transport protection for App Service and Function App endpoint traffic."
                    ),
                    evidence=collect_evidence(
                        evidence_item("target_resource", _target_resource_evidence(app)),
                        evidence_item("transport_posture", [f"minimum_tls_version is {tls_version}"]),
                        evidence_item("network_posture", _public_network_evidence(facts)),
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
        for app in context.inventory.by_type(*AZURE_APP_SERVICE_RESOURCE_TYPES):
            facts = azure_facts(app)
            if facts.min_tls_version is not None:
                continue
            public_enabled = facts.public_network_access_enabled is True
            severity_reasoning = build_severity_reasoning(
                internet_exposure=public_enabled,
                privilege_breadth=0,
                data_sensitivity=0,
                lateral_movement=0,
                blast_radius=1,
            )
            findings.append(
                self._finding_factory.build(
                    rule_id=rule_id,
                    severity=severity_reasoning.severity,
                    affected_resources=[app.address],
                    trust_boundary_id=None,
                    rationale=(
                        f"{app.display_name} does not expose a deterministic minimum TLS version in the Terraform "
                        "plan. tfSTRIDE cannot prove the app enforces TLS 1.2 or newer from the available data."
                    ),
                    evidence=collect_evidence(
                        evidence_item("target_resource", _target_resource_evidence(app)),
                        evidence_item("transport_posture", _tls_unknown_evidence(facts)),
                        evidence_item("network_posture", _public_network_evidence(facts)),
                        evidence_item("posture_uncertainty", _tls_uncertainty_evidence(facts)),
                    ),
                    severity_reasoning=severity_reasoning,
                )
            )
        return findings

    def detect_managed_identity_missing(
        self,
        context: RuleEvaluationContext,
        rule_id: str,
    ) -> list[Finding]:
        if context.inventory.provider != "azure":
            return []

        findings: list[Finding] = []
        for app in context.inventory.by_type(*AZURE_APP_SERVICE_RESOURCE_TYPES):
            facts = azure_facts(app)
            if facts.has_system_assigned_identity or facts.has_user_assigned_identity:
                continue
            if _identity_is_unknown(facts):
                continue
            public_enabled = facts.public_network_access_enabled is True
            severity_reasoning = build_severity_reasoning(
                internet_exposure=public_enabled,
                privilege_breadth=1,
                data_sensitivity=0,
                lateral_movement=0,
                blast_radius=1,
            )
            findings.append(
                self._finding_factory.build(
                    rule_id=rule_id,
                    severity=severity_reasoning.severity,
                    affected_resources=[app.address],
                    trust_boundary_id=None,
                    rationale=(
                        f"{app.display_name} does not configure a managed identity. App Service workloads without "
                        "managed identity commonly fall back to static credentials or deployment-time secrets for "
                        "Azure resource access."
                    ),
                    evidence=collect_evidence(
                        evidence_item("target_resource", _target_resource_evidence(app)),
                        evidence_item("identity_posture", _identity_posture_evidence(facts)),
                        evidence_item("network_posture", _public_network_evidence(facts)),
                    ),
                    severity_reasoning=severity_reasoning,
                )
            )
        return findings

    def detect_vnet_integration_missing(
        self,
        context: RuleEvaluationContext,
        rule_id: str,
    ) -> list[Finding]:
        if context.inventory.provider != "azure":
            return []

        findings: list[Finding] = []
        for app in context.inventory.by_type(*AZURE_APP_SERVICE_RESOURCE_TYPES):
            facts = azure_facts(app)
            if facts.app_service_vnet_integration_subnet_id:
                continue
            if _vnet_integration_is_unknown(facts):
                continue
            public_enabled = facts.public_network_access_enabled is True
            severity_reasoning = build_severity_reasoning(
                internet_exposure=public_enabled,
                privilege_breadth=0,
                data_sensitivity=1,
                lateral_movement=0,
                blast_radius=1,
            )
            findings.append(
                self._finding_factory.build(
                    rule_id=rule_id,
                    severity=severity_reasoning.severity,
                    affected_resources=[app.address],
                    trust_boundary_id=None,
                    rationale=(
                        f"{app.display_name} does not have VNet integration configured, so outbound access to "
                        "private Azure resources may rely on public endpoints or service-level firewall exceptions."
                    ),
                    evidence=collect_evidence(
                        evidence_item("target_resource", _target_resource_evidence(app)),
                        evidence_item("vnet_integration", _vnet_integration_evidence(facts)),
                        evidence_item("network_posture", _public_network_evidence(facts)),
                    ),
                    severity_reasoning=severity_reasoning,
                )
            )
        return findings


def _target_resource_evidence(app) -> list[str]:
    return [f"address={app.address}", f"type={app.resource_type}"]


def _public_network_evidence(facts: AzureResourceFacts) -> list[str]:
    values = [f"public_network_fallback_state={facts.public_network_fallback_state}"]
    if facts.public_network_access_enabled is True:
        values.append("public_network_access_enabled is true")
    elif facts.public_network_access_enabled is False:
        values.append("public_network_access_enabled is false")
    else:
        values.append("public_network_access_enabled is unknown")
    return values


def _public_network_uncertainty_evidence(facts: AzureResourceFacts) -> list[str]:
    if facts.public_network_access_enabled is not None:
        return []
    uncertainties = [
        uncertainty
        for uncertainty in facts.app_service_posture_uncertainties
        if "public_network_access_enabled" in uncertainty
    ]
    return uncertainties or ["public_network_access_enabled is not represented in planned values"]


def _tls_unknown_evidence(facts: AzureResourceFacts) -> list[str]:
    uncertainties = _tls_uncertainty_evidence(facts)
    if uncertainties:
        return ["minimum_tls_version is unknown"]
    return ["minimum_tls_version is not represented in planned values"]


def _tls_uncertainty_evidence(facts: AzureResourceFacts) -> list[str]:
    return [
        uncertainty
        for uncertainty in facts.app_service_posture_uncertainties
        if "minimum_tls_version" in uncertainty or "site_config is unknown" in uncertainty
    ]


def _identity_posture_evidence(facts: AzureResourceFacts) -> list[str]:
    if facts.identity_type:
        return [f"identity_type is {facts.identity_type}"]
    return ["identity block is absent"]


def _identity_is_unknown(facts: AzureResourceFacts) -> bool:
    return any("identity" in uncertainty for uncertainty in facts.managed_identity_uncertainties)


def _vnet_integration_evidence(facts: AzureResourceFacts) -> list[str]:
    if facts.app_service_vnet_integration_subnet_id:
        return [f"virtual_network_subnet_id is {facts.app_service_vnet_integration_subnet_id}"]
    return ["virtual_network_subnet_id is not configured"]


def _vnet_integration_is_unknown(facts: AzureResourceFacts) -> bool:
    return any("virtual_network_subnet_id" in uncertainty for uncertainty in facts.app_service_posture_uncertainties)


def _tls_version_below_1_2(value: str | None) -> bool:
    if value is None:
        return False
    normalized = value.strip().lower().replace(".", "_").replace("-", "_")
    return normalized in {"tls1_0", "tls1_1", "tlsv1", "tlsv1_0", "tlsv1_1", "1_0", "1_1"}
