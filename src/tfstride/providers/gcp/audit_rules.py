from __future__ import annotations

from collections.abc import Iterable

from tfstride.analysis.finding_factory import FindingFactory
from tfstride.analysis.finding_helpers import (
    build_severity_reasoning,
    collect_evidence,
    dedupe_addresses,
    evidence_item,
)
from tfstride.analysis.rule_definitions import RuleEvaluationContext
from tfstride.models import Finding, NormalizedResource
from tfstride.providers.coercion import STATE_DISABLED
from tfstride.providers.gcp.resource_facts import GcpResourceFacts, gcp_facts
from tfstride.providers.gcp.resource_types import GcpResourceType

_LOGGING_SINK_TYPES = (
    GcpResourceType.LOGGING_PROJECT_SINK,
    GcpResourceType.LOGGING_ORGANIZATION_SINK,
)
_LOGGING_EXCLUSION_TYPES = (
    GcpResourceType.LOGGING_PROJECT_EXCLUSION,
    GcpResourceType.LOGGING_ORGANIZATION_EXCLUSION,
)
_MODELED_AUDIT_SECURITY_TYPES = (
    GcpResourceType.LOGGING_PROJECT_EXCLUSION,
    GcpResourceType.LOGGING_ORGANIZATION_EXCLUSION,
    GcpResourceType.SCC_ORGANIZATION_SETTINGS,
)
_AUDIT_SECURITY_FILTER_SIGNALS = (
    ("cloudaudit.googleapis.com", "matches Cloud Audit Logs"),
    ("google.cloud.audit.auditlog", "matches AuditLog proto payloads"),
    ("protopayload.@type", "matches protoPayload audit log records"),
    ("protopayload.servicename", "matches service audit payloads"),
    ("securitycenter.googleapis.com", "matches Security Command Center logs"),
    ("security_command_center", "matches Security Command Center logs"),
    ("securitycenter", "matches security center logs"),
    ('resource.type="gce_firewall_rule"', "matches firewall rule logs"),
    ("resource.type=gce_firewall_rule", "matches firewall rule logs"),
)


class GcpAuditRuleDetectors:
    def __init__(self, finding_factory: FindingFactory) -> None:
        self._finding_factory = finding_factory

    def detect_scc_asset_discovery_disabled(
        self,
        context: RuleEvaluationContext,
        rule_id: str,
    ) -> list[Finding]:
        if context.inventory.provider != "gcp":
            return []

        findings: list[Finding] = []
        for setting in context.inventory.by_type(GcpResourceType.SCC_ORGANIZATION_SETTINGS):
            facts = gcp_facts(setting)
            if facts.scc_enable_asset_discovery is not False and facts.scc_asset_discovery_state != STATE_DISABLED:
                continue

            severity_reasoning = _audit_detection_severity()
            findings.append(
                self._finding_factory.build(
                    rule_id=rule_id,
                    severity=severity_reasoning.severity,
                    affected_resources=[setting.address],
                    trust_boundary_id=None,
                    rationale=(
                        f"{setting.display_name} disables Security Command Center asset discovery. SCC may not "
                        "inventory organization assets for security posture review and finding correlation."
                    ),
                    evidence=collect_evidence(
                        evidence_item("scc_asset_discovery", _scc_asset_discovery_evidence(setting, facts)),
                    ),
                    severity_reasoning=severity_reasoning,
                )
            )
        return findings

    def detect_logging_exclusion_drops_audit_security_logs(
        self,
        context: RuleEvaluationContext,
        rule_id: str,
    ) -> list[Finding]:
        if context.inventory.provider != "gcp":
            return []

        findings: list[Finding] = []
        for exclusion in context.inventory.by_type(*_LOGGING_EXCLUSION_TYPES):
            facts = gcp_facts(exclusion)
            if not _is_active_logging_exclusion(facts):
                continue
            matched_signals = _audit_security_filter_signals(facts.logging_exclusion_filter)
            if not matched_signals:
                continue

            severity_reasoning = _audit_detection_severity()
            findings.append(
                self._finding_factory.build(
                    rule_id=rule_id,
                    severity=severity_reasoning.severity,
                    affected_resources=[exclusion.address],
                    trust_boundary_id=None,
                    rationale=(
                        f"{exclusion.display_name} is an active logging exclusion whose filter matches audit or "
                        "security log streams. Excluding those logs can remove evidence needed for investigation, "
                        "alerting, and security posture review."
                    ),
                    evidence=collect_evidence(
                        evidence_item("logging_exclusion", _logging_exclusion_evidence(exclusion, facts)),
                        evidence_item("matched_log_streams", matched_signals),
                    ),
                    severity_reasoning=severity_reasoning,
                )
            )
        return findings

    def detect_logging_sink_audit_export_incomplete(
        self,
        context: RuleEvaluationContext,
        rule_id: str,
    ) -> list[Finding]:
        if context.inventory.provider != "gcp":
            return []

        findings: list[Finding] = []
        for sink in context.inventory.by_type(*_LOGGING_SINK_TYPES):
            facts = gcp_facts(sink)
            posture_issues = _logging_sink_audit_export_issues(facts)
            if not posture_issues:
                continue

            severity_reasoning = _audit_detection_severity()
            findings.append(
                self._finding_factory.build(
                    rule_id=rule_id,
                    severity=severity_reasoning.severity,
                    affected_resources=[sink.address],
                    trust_boundary_id=None,
                    rationale=(
                        f"{sink.display_name} does not clearly export audit or security logs to a retained "
                        "destination. A modeled sink without a deterministic destination or with a narrow filter "
                        "can leave investigation and alerting coverage incomplete."
                    ),
                    evidence=collect_evidence(
                        evidence_item("logging_sink", _logging_sink_evidence(sink, facts)),
                        evidence_item("audit_export_posture", posture_issues),
                    ),
                    severity_reasoning=severity_reasoning,
                )
            )
        return findings

    def detect_central_audit_sink_not_modeled(
        self,
        context: RuleEvaluationContext,
        rule_id: str,
    ) -> list[Finding]:
        if context.inventory.provider != "gcp":
            return []
        if context.inventory.by_type(*_LOGGING_SINK_TYPES):
            return []

        modeled_audit_resources = _modeled_audit_security_resources(context.inventory.resources)
        if not modeled_audit_resources:
            return []

        severity_reasoning = _audit_detection_severity()
        return [
            self._finding_factory.build(
                rule_id=rule_id,
                severity=severity_reasoning.severity,
                affected_resources=dedupe_addresses([resource.address for resource in modeled_audit_resources]),
                trust_boundary_id=None,
                rationale=(
                    "The Terraform plan models GCP audit or security posture resources, but no project or "
                    "organization logging sink is present. tfSTRIDE cannot confirm that audit/security logs are "
                    "centrally exported or retained from this plan."
                ),
                evidence=collect_evidence(
                    evidence_item("missing_control", ["no google_logging_project_sink or organization sink modeled"]),
                    evidence_item(
                        "modeled_audit_security_resources", _modeled_resource_evidence(modeled_audit_resources)
                    ),
                ),
                severity_reasoning=severity_reasoning,
            )
        ]


def _audit_detection_severity():
    return build_severity_reasoning(
        internet_exposure=False,
        privilege_breadth=0,
        data_sensitivity=1,
        lateral_movement=1,
        blast_radius=1,
    )


def _is_active_logging_exclusion(facts: GcpResourceFacts) -> bool:
    if facts.logging_exclusion_disabled is True:
        return False
    if _matching_uncertainties(facts.audit_security_posture_uncertainties, ("disabled",)):
        return False
    return bool(facts.logging_exclusion_filter)


def _audit_security_filter_signals(filter_text: str | None) -> list[str]:
    if not filter_text:
        return []
    normalized = _normalized_filter(filter_text)
    return [description for signal, description in _AUDIT_SECURITY_FILTER_SIGNALS if signal in normalized]


def _normalized_filter(filter_text: str) -> str:
    return " ".join(filter_text.lower().replace(chr(39), chr(34)).split())


def _modeled_audit_security_resources(resources: Iterable[NormalizedResource]) -> list[NormalizedResource]:
    return [resource for resource in resources if resource.resource_type in _MODELED_AUDIT_SECURITY_TYPES]


def _scc_asset_discovery_evidence(resource: NormalizedResource, facts: GcpResourceFacts) -> list[str]:
    values = _target_resource_evidence(resource, facts)
    asset_discovery_state = facts.scc_asset_discovery_state or "unknown"
    values.append(f"asset_discovery_state={asset_discovery_state}")
    if facts.scc_organization:
        values.append(f"organization={facts.scc_organization}")
    if facts.scc_asset_discovery_inclusion_mode:
        values.append(f"inclusion_mode={facts.scc_asset_discovery_inclusion_mode}")
    values.extend(_uncertainty_evidence(facts.audit_security_posture_uncertainties, ("enable_asset_discovery",)))
    return values


def _logging_sink_audit_export_issues(facts: GcpResourceFacts) -> list[str]:
    issues: list[str] = []
    destination_uncertainties = _matching_uncertainties(facts.audit_security_posture_uncertainties, ("destination",))
    filter_uncertainties = _matching_uncertainties(facts.audit_security_posture_uncertainties, ("filter",))

    if not facts.logging_sink_destination:
        if destination_uncertainties:
            issues.extend(f"destination uncertainty: {uncertainty}" for uncertainty in destination_uncertainties)
        else:
            issues.append("destination is not configured")

    if filter_uncertainties:
        issues.extend(f"filter uncertainty: {uncertainty}" for uncertainty in filter_uncertainties)
    elif facts.logging_sink_filter and not _audit_security_filter_signals(facts.logging_sink_filter):
        issues.append("filter does not clearly include audit or security log streams")

    return issues


def _logging_sink_evidence(resource: NormalizedResource, facts: GcpResourceFacts) -> list[str]:
    values = _target_resource_evidence(resource, facts)
    destination = facts.logging_sink_destination or "not_configured"
    sink_filter = facts.logging_sink_filter or "not_configured"
    values.append(f"destination={destination}")
    values.append(f"filter={sink_filter}")
    if facts.logging_sink_scope_type:
        values.append(f"scope_type={facts.logging_sink_scope_type}")
    if facts.logging_sink_scope:
        values.append(f"scope={facts.logging_sink_scope}")
    if facts.logging_sink_writer_identity:
        values.append(f"writer_identity={facts.logging_sink_writer_identity}")
    if facts.logging_sink_include_children is not None:
        values.append(f"include_children={_bool_status(facts.logging_sink_include_children)}")
    if facts.logging_sink_unique_writer_identity is not None:
        values.append(f"unique_writer_identity={_bool_status(facts.logging_sink_unique_writer_identity)}")
    values.extend(_uncertainty_evidence(facts.audit_security_posture_uncertainties, ("destination", "filter")))
    return values


def _logging_exclusion_evidence(resource: NormalizedResource, facts: GcpResourceFacts) -> list[str]:
    values = _target_resource_evidence(resource, facts)
    values.append(f"disabled={_bool_status(facts.logging_exclusion_disabled)}")
    if facts.logging_exclusion_filter:
        values.append(f"filter={facts.logging_exclusion_filter}")
    if facts.logging_exclusion_scope_type:
        values.append(f"scope_type={facts.logging_exclusion_scope_type}")
    if facts.logging_exclusion_scope:
        values.append(f"scope={facts.logging_exclusion_scope}")
    values.extend(_uncertainty_evidence(facts.audit_security_posture_uncertainties, ("filter", "disabled")))
    return values


def _target_resource_evidence(resource: NormalizedResource, facts: GcpResourceFacts) -> list[str]:
    values = [f"address={resource.address}", f"type={resource.resource_type}"]
    name = facts.resource_name or resource.name
    if name:
        values.append(f"name={name}")
    if resource.identifier:
        values.append(f"identifier={resource.identifier}")
    return values


def _modeled_resource_evidence(resources: Iterable[NormalizedResource]) -> list[str]:
    return [f"{resource.address} ({resource.resource_type})" for resource in resources]


def _uncertainty_evidence(uncertainties: Iterable[str], fields: tuple[str, ...]) -> list[str]:
    return [f"uncertainty={uncertainty}" for uncertainty in _matching_uncertainties(uncertainties, fields)]


def _matching_uncertainties(uncertainties: Iterable[str], fields: tuple[str, ...]) -> list[str]:
    return [uncertainty for uncertainty in uncertainties if any(field in uncertainty for field in fields)]


def _bool_status(value: bool | None) -> str:
    if value is True:
        return "true"
    if value is False:
        return "false"
    return "not_configured"
