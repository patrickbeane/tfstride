from __future__ import annotations

from collections.abc import Iterable

from tfstride.analysis.finding_factory import FindingFactory
from tfstride.analysis.finding_helpers import (
    build_severity_reasoning,
    collect_evidence,
    evidence_item,
)
from tfstride.analysis.rule_definitions import RuleEvaluationContext
from tfstride.models import Finding, NormalizedResource
from tfstride.providers.azure.diagnostic_index import (
    AzureDiagnosticSettingCoverage,
    build_azure_diagnostic_setting_index,
)
from tfstride.providers.azure.resource_facts import AzureResourceFacts, azure_facts
from tfstride.providers.azure.resource_types import AzureResourceType

_DIAGNOSTIC_TARGET_TYPES = (
    AzureResourceType.STORAGE_ACCOUNT,
    AzureResourceType.KEY_VAULT,
    AzureResourceType.MSSQL_SERVER,
    AzureResourceType.POSTGRESQL_FLEXIBLE_SERVER,
    AzureResourceType.KUBERNETES_CLUSTER,
    AzureResourceType.LINUX_WEB_APP,
    AzureResourceType.WINDOWS_WEB_APP,
    AzureResourceType.FUNCTION_APP,
    AzureResourceType.LINUX_FUNCTION_APP,
    AzureResourceType.WINDOWS_FUNCTION_APP,
)
_DATA_PLANE_DIAGNOSTIC_TARGET_TYPES = {
    AzureResourceType.STORAGE_ACCOUNT,
    AzureResourceType.KEY_VAULT,
    AzureResourceType.MSSQL_SERVER,
    AzureResourceType.POSTGRESQL_FLEXIBLE_SERVER,
}
_STATE_DISABLED = "disabled"

_DIAGNOSTIC_DESTINATION_FIELDS = (
    "log_analytics_workspace_id",
    "storage_account_id",
    "eventhub_authorization_rule_id",
    "marketplace_partner_resource_id",
)
_DIAGNOSTIC_CATEGORY_FIELDS = ("enabled_log", "log", "category", "category_group")
_AUDIT_SECURITY_CATEGORY_GROUPS = frozenset({"audit", "alllogs"})


class AzureAuditRuleDetectors:
    def __init__(self, finding_factory: FindingFactory) -> None:
        self._finding_factory = finding_factory

    def detect_missing_diagnostic_settings(
        self,
        context: RuleEvaluationContext,
        rule_id: str,
    ) -> list[Finding]:
        if context.inventory.provider != "azure":
            return []

        diagnostic_index = build_azure_diagnostic_setting_index(context.inventory)
        findings: list[Finding] = []
        for resource in context.inventory.by_type(*_DIAGNOSTIC_TARGET_TYPES):
            coverage = diagnostic_index.coverage_for(resource)
            if coverage.has_diagnostic_settings:
                continue

            facts = azure_facts(resource)
            severity_reasoning = _diagnostic_coverage_severity(resource)
            findings.append(
                self._finding_factory.build(
                    rule_id=rule_id,
                    severity=severity_reasoning.severity,
                    affected_resources=[resource.address],
                    trust_boundary_id=None,
                    rationale=(
                        f"{resource.display_name} has no resolved Azure Monitor diagnostic setting in this "
                        "Terraform plan. Security-relevant data-plane, control-plane, or platform logs may not be "
                        "routed to a retained logging destination for investigation and alerting."
                    ),
                    evidence=collect_evidence(
                        evidence_item("target_resource", _target_resource_evidence(resource, facts)),
                        evidence_item(
                            "diagnostic_coverage",
                            ["no resolved azurerm_monitor_diagnostic_setting targets this resource"],
                        ),
                    ),
                    severity_reasoning=severity_reasoning,
                )
            )
        return findings

    def detect_diagnostic_setting_no_log_destination(
        self,
        context: RuleEvaluationContext,
        rule_id: str,
    ) -> list[Finding]:
        if context.inventory.provider != "azure":
            return []

        findings: list[Finding] = []
        for setting in context.inventory.by_type(AzureResourceType.MONITOR_DIAGNOSTIC_SETTING):
            facts = azure_facts(setting)
            if _has_delivery_destination(facts) or _destination_fields_unknown(facts):
                continue

            severity_reasoning = _audit_detection_severity()
            findings.append(
                self._finding_factory.build(
                    rule_id=rule_id,
                    severity=severity_reasoning.severity,
                    affected_resources=[setting.address],
                    trust_boundary_id=None,
                    rationale=(
                        f"{setting.display_name} enables diagnostic collection but does not configure a deterministic "
                        "Log Analytics, storage, Event Hub authorization rule, or marketplace partner destination. "
                        "Logs and metrics may not leave the resource for retained audit review."
                    ),
                    evidence=collect_evidence(
                        evidence_item("diagnostic_setting", _diagnostic_setting_evidence(setting, facts)),
                        evidence_item("diagnostic_categories", _diagnostic_category_evidence(facts)),
                        evidence_item("destination_posture", _diagnostic_destination_evidence(facts)),
                    ),
                    severity_reasoning=severity_reasoning,
                )
            )
        return findings

    def detect_diagnostic_setting_audit_logs_incomplete(
        self,
        context: RuleEvaluationContext,
        rule_id: str,
    ) -> list[Finding]:
        if context.inventory.provider != "azure":
            return []

        diagnostic_index = build_azure_diagnostic_setting_index(context.inventory)
        findings: list[Finding] = []
        for resource in context.inventory.by_type(*_DIAGNOSTIC_TARGET_TYPES):
            coverage = diagnostic_index.coverage_for(resource)
            if not coverage.has_diagnostic_settings or _has_audit_or_security_log_coverage(coverage):
                continue

            facts = azure_facts(resource)
            severity_reasoning = _diagnostic_coverage_severity(resource)
            findings.append(
                self._finding_factory.build(
                    rule_id=rule_id,
                    severity=severity_reasoning.severity,
                    affected_resources=[resource.address],
                    trust_boundary_id=None,
                    rationale=(
                        f"{resource.display_name} has resolved Azure Monitor diagnostic settings, but none clearly "
                        "enable audit or security log categories or category groups. Metrics-only or incomplete "
                        "diagnostics can leave security-relevant activity without retained audit logs."
                    ),
                    evidence=collect_evidence(
                        evidence_item("target_resource", _target_resource_evidence(resource, facts)),
                        evidence_item("diagnostic_settings", _diagnostic_setting_coverage_evidence(coverage)),
                        evidence_item("diagnostic_categories", _diagnostic_coverage_category_evidence(coverage)),
                        evidence_item("audit_log_posture", _audit_security_log_posture_evidence(coverage)),
                    ),
                    severity_reasoning=severity_reasoning,
                )
            )
        return findings

    def detect_defender_pricing_tier_not_standard(
        self,
        context: RuleEvaluationContext,
        rule_id: str,
    ) -> list[Finding]:
        if context.inventory.provider != "azure":
            return []

        findings: list[Finding] = []
        for pricing in context.inventory.by_type(AzureResourceType.SECURITY_CENTER_SUBSCRIPTION_PRICING):
            facts = azure_facts(pricing)
            tier = facts.defender_pricing_tier
            if tier is None or tier.strip().lower() == "standard":
                continue

            severity_reasoning = _audit_detection_severity()
            findings.append(
                self._finding_factory.build(
                    rule_id=rule_id,
                    severity=severity_reasoning.severity,
                    affected_resources=[pricing.address],
                    trust_boundary_id=None,
                    rationale=(
                        f"{pricing.display_name} configures Microsoft Defender for Cloud pricing tier `{tier}`. "
                        "Plans below Standard can leave modeled Azure services without the expected threat detection "
                        "and security posture management coverage."
                    ),
                    evidence=collect_evidence(
                        evidence_item("defender_plan", _defender_pricing_evidence(pricing, facts)),
                    ),
                    severity_reasoning=severity_reasoning,
                )
            )
        return findings

    def detect_security_center_auto_provisioning_disabled(
        self,
        context: RuleEvaluationContext,
        rule_id: str,
    ) -> list[Finding]:
        if context.inventory.provider != "azure":
            return []

        findings: list[Finding] = []
        for setting in context.inventory.by_type(AzureResourceType.SECURITY_CENTER_AUTO_PROVISIONING):
            facts = azure_facts(setting)
            if facts.security_center_auto_provisioning_state != _STATE_DISABLED:
                continue

            severity_reasoning = _audit_detection_severity()
            findings.append(
                self._finding_factory.build(
                    rule_id=rule_id,
                    severity=severity_reasoning.severity,
                    affected_resources=[setting.address],
                    trust_boundary_id=None,
                    rationale=(
                        f"{setting.display_name} disables Security Center auto-provisioning. Supported security "
                        "agents may not be deployed automatically for monitored workloads represented by the plan."
                    ),
                    evidence=collect_evidence(
                        evidence_item("auto_provisioning_posture", _auto_provisioning_evidence(setting, facts)),
                    ),
                    severity_reasoning=severity_reasoning,
                )
            )
        return findings


def _diagnostic_coverage_severity(resource: NormalizedResource):
    return build_severity_reasoning(
        internet_exposure=resource.public_access_configured or resource.direct_internet_reachable,
        privilege_breadth=0,
        data_sensitivity=2 if resource.resource_type in _DATA_PLANE_DIAGNOSTIC_TARGET_TYPES else 1,
        lateral_movement=1 if resource.resource_type == AzureResourceType.KUBERNETES_CLUSTER else 0,
        blast_radius=1,
    )


def _audit_detection_severity():
    return build_severity_reasoning(
        internet_exposure=False,
        privilege_breadth=0,
        data_sensitivity=1,
        lateral_movement=1,
        blast_radius=1,
    )


def _has_delivery_destination(facts: AzureResourceFacts) -> bool:
    return any(getattr(facts, f"diagnostic_{field}") for field in _DIAGNOSTIC_DESTINATION_FIELDS)


def _destination_fields_unknown(facts: AzureResourceFacts) -> bool:
    return bool(_matching_uncertainties(facts.azure_security_posture_uncertainties, _DIAGNOSTIC_DESTINATION_FIELDS))


def _target_resource_evidence(resource: NormalizedResource, facts: AzureResourceFacts) -> list[str]:
    values = [f"address={resource.address}", f"type={resource.resource_type}"]
    name = facts.name or resource.name
    if name:
        values.append(f"name={name}")
    if resource.identifier:
        values.append(f"identifier={resource.identifier}")
    return values


def _diagnostic_setting_evidence(resource: NormalizedResource, facts: AzureResourceFacts) -> list[str]:
    values = _target_resource_evidence(resource, facts)
    if facts.diagnostic_target_resource_id:
        values.append(f"target_resource_id={facts.diagnostic_target_resource_id}")
    if facts.diagnostic_setting_id:
        values.append(f"diagnostic_setting_id={facts.diagnostic_setting_id}")
    return values


def _diagnostic_category_evidence(facts: AzureResourceFacts) -> list[str]:
    values: list[str] = []
    values.extend(f"log_category={category}" for category in facts.diagnostic_enabled_log_categories)
    values.extend(f"log_category_group={group}" for group in facts.diagnostic_enabled_log_category_groups)
    values.extend(f"metric_category={category}" for category in facts.diagnostic_metric_categories)
    if not values:
        values.append("no enabled log or metric categories were modeled")
    return values


def _diagnostic_destination_evidence(facts: AzureResourceFacts) -> list[str]:
    values = [
        "log_analytics_workspace_id=not_configured",
        "storage_account_id=not_configured",
        "eventhub_authorization_rule_id=not_configured",
        "marketplace_partner_resource_id=not_configured",
    ]
    if facts.diagnostic_eventhub_name:
        values.append(f"eventhub_name={facts.diagnostic_eventhub_name}")
        values.append("eventhub_name without eventhub_authorization_rule_id is not treated as a log destination")
    values.extend(_uncertainty_evidence(facts.azure_security_posture_uncertainties, _DIAGNOSTIC_DESTINATION_FIELDS))
    return values


def _has_audit_or_security_log_coverage(coverage: AzureDiagnosticSettingCoverage) -> bool:
    return any(_is_audit_or_security_log_category(category) for category in coverage.enabled_log_categories) or any(
        _is_audit_or_security_log_category_group(group) for group in coverage.enabled_log_category_groups
    )


def _is_audit_or_security_log_category(value: str) -> bool:
    normalized = _normalized_category_token(value)
    return "audit" in normalized or "security" in normalized


def _is_audit_or_security_log_category_group(value: str) -> bool:
    normalized = _normalized_category_token(value)
    return normalized in _AUDIT_SECURITY_CATEGORY_GROUPS or "audit" in normalized or "security" in normalized


def _normalized_category_token(value: str) -> str:
    return "".join(character for character in value.strip().lower() if character.isalnum())


def _diagnostic_setting_coverage_evidence(coverage: AzureDiagnosticSettingCoverage) -> list[str]:
    values = [f"diagnostic_setting={address}" for address in coverage.diagnostic_setting_addresses]
    values.extend(f"destination={destination}" for destination in coverage.destinations)
    if not coverage.destinations:
        values.append("destination=not_configured")
    return values


def _diagnostic_coverage_category_evidence(coverage: AzureDiagnosticSettingCoverage) -> list[str]:
    values: list[str] = []
    values.extend(f"log_category={category}" for category in coverage.enabled_log_categories)
    values.extend(f"log_category_group={group}" for group in coverage.enabled_log_category_groups)
    values.extend(f"metric_category={category}" for category in coverage.metric_categories)
    if not values:
        values.append("no enabled log or metric categories were modeled")
    return values


def _audit_security_log_posture_evidence(coverage: AzureDiagnosticSettingCoverage) -> list[str]:
    values = ["audit_or_security_log_category=not_confirmed"]
    category_uncertainties = _uncertainty_evidence(coverage.uncertainties, _DIAGNOSTIC_CATEGORY_FIELDS)
    if category_uncertainties:
        values.extend(category_uncertainties)
    else:
        values.append("no audit or security log category/group is enabled")
    return values


def _defender_pricing_evidence(resource: NormalizedResource, facts: AzureResourceFacts) -> list[str]:
    values = _target_resource_evidence(resource, facts)
    values.append(f"pricing_tier={facts.defender_pricing_tier or 'unknown'}")
    if facts.defender_resource_type:
        values.append(f"resource_type={facts.defender_resource_type}")
    if facts.defender_subplan:
        values.append(f"subplan={facts.defender_subplan}")
    values.extend(f"extension={name}" for name in facts.defender_extension_names)
    values.extend(_uncertainty_evidence(facts.azure_security_posture_uncertainties, ("tier", "resource_type")))
    return values


def _auto_provisioning_evidence(resource: NormalizedResource, facts: AzureResourceFacts) -> list[str]:
    values = _target_resource_evidence(resource, facts)
    values.append(f"auto_provisioning_state={facts.security_center_auto_provisioning_state or 'unknown'}")
    values.extend(_uncertainty_evidence(facts.azure_security_posture_uncertainties, ("auto_provision",)))
    return values


def _uncertainty_evidence(uncertainties: Iterable[str], fields: tuple[str, ...]) -> list[str]:
    return [f"uncertainty={uncertainty}" for uncertainty in _matching_uncertainties(uncertainties, fields)]


def _matching_uncertainties(uncertainties: Iterable[str], fields: tuple[str, ...]) -> list[str]:
    return [uncertainty for uncertainty in uncertainties if any(field in uncertainty for field in fields)]
