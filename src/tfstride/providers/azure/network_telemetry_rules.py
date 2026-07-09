from __future__ import annotations

from collections.abc import Iterable

from tfstride.analysis.finding_factory import FindingFactory
from tfstride.analysis.finding_helpers import build_severity_reasoning, collect_evidence, evidence_item
from tfstride.analysis.rule_definitions import RuleEvaluationContext
from tfstride.models import Finding, NormalizedResource
from tfstride.providers.azure.resource_facts import AzureResourceFacts, azure_facts
from tfstride.providers.azure.resource_types import AzureResourceType

_STATE_ENABLED = "enabled"
_STATE_DISABLED = "disabled"
_STATE_UNKNOWN = "unknown"
_MIN_FLOW_LOG_RETENTION_DAYS = 7


class AzureNetworkTelemetryRuleDetectors:
    def __init__(self, finding_factory: FindingFactory) -> None:
        self._finding_factory = finding_factory

    def detect_nsg_flow_logs_not_configured(
        self,
        context: RuleEvaluationContext,
        rule_id: str,
    ) -> list[Finding]:
        if context.inventory.provider != "azure":
            return []

        flow_logs = context.inventory.by_type(AzureResourceType.NETWORK_WATCHER_FLOW_LOG)
        resolved_flow_logs = _resolved_nsg_flow_logs(flow_logs)
        unresolved_flow_logs = _unresolved_target_flow_logs(flow_logs)
        findings: list[Finding] = []
        for network_security_group in context.inventory.by_type(AzureResourceType.NETWORK_SECURITY_GROUP):
            nsg_ids = _network_security_group_identifiers(network_security_group)
            if not nsg_ids or nsg_ids & resolved_flow_logs.keys():
                continue
            if unresolved_flow_logs:
                continue

            severity_reasoning = build_severity_reasoning(
                internet_exposure=False,
                privilege_breadth=0,
                data_sensitivity=0,
                lateral_movement=2,
                blast_radius=1,
            )
            findings.append(
                self._finding_factory.build(
                    rule_id=rule_id,
                    severity=severity_reasoning.severity,
                    affected_resources=[network_security_group.address],
                    trust_boundary_id=None,
                    rationale=(
                        f"{network_security_group.display_name} does not have a resolved "
                        "azurerm_network_watcher_flow_log targeting the NSG in this Terraform plan. Network "
                        "traffic metadata for incident response, threat hunting, and segmentation review may be "
                        "unavailable unless NSG flow logs are configured elsewhere."
                    ),
                    evidence=collect_evidence(
                        evidence_item("target_network_security_group", _nsg_evidence(network_security_group)),
                        evidence_item(
                            "flow_log_coverage",
                            _missing_nsg_flow_log_evidence(sorted(nsg_ids), flow_logs),
                        ),
                    ),
                    severity_reasoning=severity_reasoning,
                )
            )
        return findings

    def detect_flow_log_disabled(
        self,
        context: RuleEvaluationContext,
        rule_id: str,
    ) -> list[Finding]:
        if context.inventory.provider != "azure":
            return []

        findings: list[Finding] = []
        for flow_log in context.inventory.by_type(AzureResourceType.NETWORK_WATCHER_FLOW_LOG):
            facts = azure_facts(flow_log)
            if facts.network_flow_log_state == _STATE_ENABLED:
                continue

            unknown_state = facts.network_flow_log_state in (None, _STATE_UNKNOWN)
            severity_reasoning = build_severity_reasoning(
                internet_exposure=False,
                privilege_breadth=0,
                data_sensitivity=0,
                lateral_movement=1 if unknown_state else 2,
                blast_radius=0 if unknown_state else 1,
            )
            findings.append(
                self._finding_factory.build(
                    rule_id=rule_id,
                    severity=severity_reasoning.severity,
                    affected_resources=[flow_log.address],
                    trust_boundary_id=None,
                    rationale=_disabled_flow_log_rationale(flow_log, facts, unknown_state),
                    evidence=collect_evidence(
                        evidence_item("target_flow_log", _flow_log_target_evidence(flow_log, facts)),
                        evidence_item("flow_log_state", _flow_log_state_evidence(facts)),
                        evidence_item("posture_uncertainty", _uncertainty_evidence(facts, "enabled")),
                    ),
                    severity_reasoning=severity_reasoning,
                )
            )
        return findings

    def detect_flow_log_destination_missing(
        self,
        context: RuleEvaluationContext,
        rule_id: str,
    ) -> list[Finding]:
        if context.inventory.provider != "azure":
            return []

        findings: list[Finding] = []
        for flow_log in context.inventory.by_type(AzureResourceType.NETWORK_WATCHER_FLOW_LOG):
            facts = azure_facts(flow_log)
            if facts.network_flow_log_storage_account_id:
                continue

            destination_unknown = bool(_uncertainty_evidence(facts, "storage_account_id"))
            severity_reasoning = build_severity_reasoning(
                internet_exposure=False,
                privilege_breadth=0,
                data_sensitivity=0,
                lateral_movement=1,
                blast_radius=0 if destination_unknown else 2,
            )
            findings.append(
                self._finding_factory.build(
                    rule_id=rule_id,
                    severity=severity_reasoning.severity,
                    affected_resources=[flow_log.address],
                    trust_boundary_id=None,
                    rationale=_destination_rationale(flow_log, destination_unknown),
                    evidence=collect_evidence(
                        evidence_item("target_flow_log", _flow_log_target_evidence(flow_log, facts)),
                        evidence_item("log_destination", _destination_evidence(facts)),
                        evidence_item("posture_uncertainty", _uncertainty_evidence(facts, "storage_account_id")),
                    ),
                    severity_reasoning=severity_reasoning,
                )
            )
        return findings

    def detect_flow_log_retention_insufficient(
        self,
        context: RuleEvaluationContext,
        rule_id: str,
    ) -> list[Finding]:
        if context.inventory.provider != "azure":
            return []

        findings: list[Finding] = []
        for flow_log in context.inventory.by_type(AzureResourceType.NETWORK_WATCHER_FLOW_LOG):
            facts = azure_facts(flow_log)
            retention_issue = _retention_issue(facts)
            if retention_issue is None:
                continue

            unknown_retention = retention_issue.startswith("unknown")
            severity_reasoning = build_severity_reasoning(
                internet_exposure=False,
                privilege_breadth=0,
                data_sensitivity=0,
                lateral_movement=1,
                blast_radius=0 if unknown_retention else 1,
            )
            findings.append(
                self._finding_factory.build(
                    rule_id=rule_id,
                    severity=severity_reasoning.severity,
                    affected_resources=[flow_log.address],
                    trust_boundary_id=None,
                    rationale=_retention_rationale(flow_log, retention_issue),
                    evidence=collect_evidence(
                        evidence_item("target_flow_log", _flow_log_target_evidence(flow_log, facts)),
                        evidence_item("retention_posture", _retention_evidence(facts, retention_issue)),
                        evidence_item(
                            "posture_uncertainty",
                            _uncertainty_evidence(facts, "retention_policy", "retention_policy.enabled", "days"),
                        ),
                    ),
                    severity_reasoning=severity_reasoning,
                )
            )
        return findings


def _resolved_nsg_flow_logs(flow_logs: Iterable[NormalizedResource]) -> dict[str, list[NormalizedResource]]:
    resolved: dict[str, list[NormalizedResource]] = {}
    for flow_log in flow_logs:
        target_id = azure_facts(flow_log).network_flow_log_target_resource_id
        if not target_id:
            continue
        resolved.setdefault(_normalized_reference(target_id), []).append(flow_log)
    return resolved


def _unresolved_target_flow_logs(flow_logs: Iterable[NormalizedResource]) -> list[NormalizedResource]:
    return [
        flow_log
        for flow_log in flow_logs
        if not azure_facts(flow_log).network_flow_log_target_resource_id
        and _uncertainty_evidence(azure_facts(flow_log), "network_security_group_id", "target_resource_id")
    ]


def _network_security_group_identifiers(resource: NormalizedResource) -> set[str]:
    facts = azure_facts(resource)
    identifiers = {resource.address, f"{resource.address}.id"}
    if resource.identifier:
        identifiers.add(resource.identifier)
    if facts.name:
        identifiers.add(facts.name)
    return {_normalized_reference(identifier) for identifier in identifiers if identifier}


def _normalized_reference(value: str) -> str:
    return str(value).strip().lower()


def _nsg_evidence(resource: NormalizedResource) -> list[str]:
    facts = azure_facts(resource)
    values = [f"address={resource.address}", f"resource_type={resource.resource_type}"]
    if resource.identifier:
        values.append(f"identifier={resource.identifier}")
    if facts.name:
        values.append(f"name={facts.name}")
    return values


def _missing_nsg_flow_log_evidence(nsg_ids: list[str], flow_logs: list[NormalizedResource]) -> list[str]:
    values = [f"target_nsg_identifier={identifier}" for identifier in nsg_ids]
    values.append("resolved_nsg_flow_log_count=0")
    if not flow_logs:
        values.append("azurerm_network_watcher_flow_log resources are not modeled")
        return values
    values.append(f"modeled_flow_log_count={len(flow_logs)}")
    for flow_log in flow_logs:
        facts = azure_facts(flow_log)
        values.append(
            f"flow_log={flow_log.address}; target_resource_id="
            f"{facts.network_flow_log_target_resource_id or 'unknown'}; "
            f"state={facts.network_flow_log_state or 'unknown'}"
        )
    return values


def _flow_log_target_evidence(flow_log: NormalizedResource, facts: AzureResourceFacts) -> list[str]:
    values = [f"address={flow_log.address}", f"resource_type={flow_log.resource_type}"]
    if facts.network_flow_log_id:
        values.append(f"flow_log_id={facts.network_flow_log_id}")
    if facts.network_flow_log_name:
        values.append(f"name={facts.network_flow_log_name}")
    if facts.network_flow_log_target_resource_id:
        values.append(f"target_resource_id={facts.network_flow_log_target_resource_id}")
    if facts.network_flow_log_network_security_group_id:
        values.append(f"network_security_group_id={facts.network_flow_log_network_security_group_id}")
    if facts.network_flow_log_network_watcher_name:
        values.append(f"network_watcher_name={facts.network_flow_log_network_watcher_name}")
    if facts.network_flow_log_resource_group_name:
        values.append(f"resource_group_name={facts.network_flow_log_resource_group_name}")
    if facts.network_flow_log_version is not None:
        values.append(f"version={facts.network_flow_log_version}")
    return values


def _flow_log_state_evidence(facts: AzureResourceFacts) -> list[str]:
    return [f"flow_log_state={facts.network_flow_log_state or 'unknown'}"]


def _destination_evidence(facts: AzureResourceFacts) -> list[str]:
    values = []
    if facts.network_flow_log_storage_account_id:
        values.append(f"storage_account_id={facts.network_flow_log_storage_account_id}")
    else:
        values.append("storage_account_id is unset")
    if facts.network_flow_log_traffic_analytics_state:
        values.append(f"traffic_analytics_state={facts.network_flow_log_traffic_analytics_state}")
    if facts.network_flow_log_traffic_analytics_workspace_id:
        values.append(f"traffic_analytics_workspace_id={facts.network_flow_log_traffic_analytics_workspace_id}")
    return values


def _retention_issue(facts: AzureResourceFacts) -> str | None:
    state = facts.network_flow_log_retention_state or _STATE_UNKNOWN
    if state != _STATE_ENABLED:
        return f"{state}_retention"
    days = facts.network_flow_log_retention_days
    if days is None:
        return "unknown_retention_days"
    if days < _MIN_FLOW_LOG_RETENTION_DAYS:
        return "short_retention"
    return None


def _retention_evidence(facts: AzureResourceFacts, issue: str) -> list[str]:
    values = [
        f"retention_state={facts.network_flow_log_retention_state or 'unknown'}",
        f"minimum_retention_days={_MIN_FLOW_LOG_RETENTION_DAYS}",
        f"retention_issue={issue}",
    ]
    if facts.network_flow_log_retention_days is not None:
        values.append(f"retention_days={facts.network_flow_log_retention_days}")
    if facts.network_flow_log_retention_policy:
        values.append(f"retention_policy={facts.network_flow_log_retention_policy}")
    return values


def _uncertainty_evidence(facts: AzureResourceFacts, *field_paths: str) -> list[str]:
    return [
        f"uncertainty={uncertainty}"
        for uncertainty in facts.network_telemetry_posture_uncertainties
        if any(field_path in uncertainty for field_path in field_paths)
    ]


def _disabled_flow_log_rationale(
    flow_log: NormalizedResource,
    facts: AzureResourceFacts,
    unknown_state: bool,
) -> str:
    if unknown_state:
        return (
            f"{flow_log.display_name} does not show a deterministic Network Watcher flow-log enabled state in "
            "the Terraform plan. tfSTRIDE cannot confirm that NSG flow telemetry will be collected."
        )
    return (
        f"{flow_log.display_name} has enabled={facts.network_flow_log_state}. Network Watcher flow logs will not "
        "collect traffic records for the targeted NSG while the flow log is disabled."
    )


def _destination_rationale(flow_log: NormalizedResource, destination_unknown: bool) -> str:
    if destination_unknown:
        return (
            f"{flow_log.display_name} does not show a deterministic storage_account_id for Network Watcher flow "
            "logs in the Terraform plan. tfSTRIDE cannot confirm where NSG flow telemetry will be retained."
        )
    return (
        f"{flow_log.display_name} does not configure a storage_account_id destination for Network Watcher flow "
        "logs. NSG flow telemetry may not be delivered to durable storage for investigation and retention."
    )


def _retention_rationale(flow_log: NormalizedResource, issue: str) -> str:
    if issue.startswith("unknown"):
        return (
            f"{flow_log.display_name} has unknown Network Watcher flow-log retention posture after planning. "
            "tfSTRIDE cannot confirm the retention period for NSG flow telemetry."
        )
    if issue == "short_retention":
        return (
            f"{flow_log.display_name} configures Network Watcher flow-log retention below "
            f"{_MIN_FLOW_LOG_RETENTION_DAYS} days. Short retention can reduce investigation coverage for delayed "
            "detection or incident response."
        )
    return (
        f"{flow_log.display_name} does not enable Network Watcher flow-log retention. NSG flow telemetry may age "
        "out or fail to meet investigation and retention requirements."
    )
