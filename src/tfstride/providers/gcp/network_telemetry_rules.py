from __future__ import annotations

from tfstride.analysis.finding_factory import FindingFactory
from tfstride.analysis.finding_helpers import build_severity_reasoning, collect_evidence, evidence_item
from tfstride.analysis.rule_definitions import RuleEvaluationContext
from tfstride.models import Finding, NormalizedResource
from tfstride.providers.gcp.resource_facts import GcpResourceFacts, gcp_facts
from tfstride.providers.gcp.resource_types import GcpResourceType

_SUBNETWORK_FLOW_LOG_ENABLED = "enabled"
_SUBNETWORK_FLOW_LOG_NOT_CONFIGURED = "not_configured"
_SUBNETWORK_FLOW_LOG_UNKNOWN = "unknown"


class GcpNetworkTelemetryRuleDetectors:
    def __init__(self, finding_factory: FindingFactory) -> None:
        self._finding_factory = finding_factory

    def detect_subnetwork_flow_logs_not_configured(
        self,
        context: RuleEvaluationContext,
        rule_id: str,
    ) -> list[Finding]:
        if context.inventory.provider != "gcp":
            return []

        findings: list[Finding] = []
        for subnetwork in context.inventory.by_type(GcpResourceType.COMPUTE_SUBNETWORK):
            facts = gcp_facts(subnetwork)
            state = facts.subnetwork_flow_log_state or _SUBNETWORK_FLOW_LOG_UNKNOWN
            if state == _SUBNETWORK_FLOW_LOG_ENABLED:
                continue

            explicit_gap = state == _SUBNETWORK_FLOW_LOG_NOT_CONFIGURED
            severity_reasoning = build_severity_reasoning(
                internet_exposure=False,
                privilege_breadth=0,
                data_sensitivity=0,
                lateral_movement=2 if explicit_gap else 1,
                blast_radius=1 if explicit_gap else 0,
            )
            findings.append(
                self._finding_factory.build(
                    rule_id=rule_id,
                    severity=severity_reasoning.severity,
                    affected_resources=[subnetwork.address],
                    trust_boundary_id=None,
                    rationale=_missing_flow_log_rationale(subnetwork, state),
                    evidence=collect_evidence(
                        evidence_item("subnetwork_flow_log_posture", _flow_log_posture_evidence(subnetwork, facts)),
                        evidence_item(
                            "posture_uncertainty",
                            _uncertainty_evidence(facts, "log_config"),
                        ),
                    ),
                    severity_reasoning=severity_reasoning,
                )
            )
        return findings

    def detect_subnetwork_flow_log_capture_incomplete(
        self,
        context: RuleEvaluationContext,
        rule_id: str,
    ) -> list[Finding]:
        if context.inventory.provider != "gcp":
            return []

        findings: list[Finding] = []
        for subnetwork in context.inventory.by_type(GcpResourceType.COMPUTE_SUBNETWORK):
            facts = gcp_facts(subnetwork)
            if facts.subnetwork_flow_log_state != _SUBNETWORK_FLOW_LOG_ENABLED:
                continue

            issues = _flow_log_capture_issues(facts)
            if not issues:
                continue

            explicit_gap = any(not issue.startswith("uncertainty=") for issue in issues)
            severity_reasoning = build_severity_reasoning(
                internet_exposure=False,
                privilege_breadth=0,
                data_sensitivity=1 if explicit_gap else 0,
                lateral_movement=1,
                blast_radius=1 if explicit_gap else 0,
            )
            findings.append(
                self._finding_factory.build(
                    rule_id=rule_id,
                    severity=severity_reasoning.severity,
                    affected_resources=[subnetwork.address],
                    trust_boundary_id=None,
                    rationale=(
                        f"{subnetwork.display_name} enables VPC Flow Logs, but the modeled log_config does not "
                        "clearly capture complete network telemetry. Sampling, filters, or omitted metadata can "
                        "reduce investigation detail for workload traffic on this subnetwork."
                    ),
                    evidence=collect_evidence(
                        evidence_item("subnetwork_flow_log_posture", _flow_log_posture_evidence(subnetwork, facts)),
                        evidence_item("capture_posture", issues),
                    ),
                    severity_reasoning=severity_reasoning,
                )
            )
        return findings


def _missing_flow_log_rationale(resource: NormalizedResource, state: str) -> str:
    if state == _SUBNETWORK_FLOW_LOG_NOT_CONFIGURED:
        return (
            f"{resource.display_name} does not configure VPC Flow Logs in this Terraform plan. Without subnetwork "
            "flow telemetry, network investigation, lateral-movement review, and egress analysis can lack packet-flow "
            "evidence for workloads attached to this subnet."
        )
    return (
        f"{resource.display_name} has an unknown VPC Flow Logs configuration after planning. tfSTRIDE cannot "
        "confirm whether network telemetry will be captured for this subnetwork."
    )


def _flow_log_capture_issues(facts: GcpResourceFacts) -> list[str]:
    issues: list[str] = []

    sampling = _parse_sampling(facts.subnetwork_flow_log_sampling)
    if sampling is not None and sampling < 1.0:
        issues.append(f"flow_sampling={facts.subnetwork_flow_log_sampling} captures a sampled subset of flows")
    elif facts.subnetwork_flow_log_sampling and sampling is None:
        issues.append(f"flow_sampling={facts.subnetwork_flow_log_sampling} is not a recognized numeric value")

    metadata = facts.subnetwork_flow_log_metadata
    if metadata and metadata.strip().upper() == "EXCLUDE_ALL_METADATA":
        issues.append("metadata=EXCLUDE_ALL_METADATA omits flow metadata used for investigation context")

    if facts.subnetwork_flow_log_filter_expr:
        issues.append(f"filter_expr={facts.subnetwork_flow_log_filter_expr} may exclude matching flow records")

    issues.extend(
        f"uncertainty={uncertainty}"
        for uncertainty in facts.network_telemetry_posture_uncertainties
        if _matches_any(uncertainty, ("flow_sampling", "metadata", "metadata_fields", "filter_expr"))
    )
    return issues


def _flow_log_posture_evidence(resource: NormalizedResource, facts: GcpResourceFacts) -> list[str]:
    values = [
        f"address={resource.address}",
        f"type={resource.resource_type}",
        f"name={resource.name}",
        f"identifier={resource.identifier or resource.address}",
        f"flow_log_state={facts.subnetwork_flow_log_state or 'unknown'}",
    ]
    if resource.vpc_id:
        values.append(f"network={resource.vpc_id}")
    if facts.project:
        values.append(f"project={facts.project}")
    if facts.subnetwork_flow_log_aggregation_interval:
        values.append(f"aggregation_interval={facts.subnetwork_flow_log_aggregation_interval}")
    if facts.subnetwork_flow_log_sampling:
        values.append(f"flow_sampling={facts.subnetwork_flow_log_sampling}")
    if facts.subnetwork_flow_log_metadata:
        values.append(f"metadata={facts.subnetwork_flow_log_metadata}")
    if facts.subnetwork_flow_log_metadata_fields:
        values.append(f"metadata_fields={', '.join(facts.subnetwork_flow_log_metadata_fields)}")
    if facts.subnetwork_flow_log_filter_expr:
        values.append(f"filter_expr={facts.subnetwork_flow_log_filter_expr}")
    values.extend(f"uncertainty={uncertainty}" for uncertainty in facts.network_telemetry_posture_uncertainties)
    return values


def _uncertainty_evidence(facts: GcpResourceFacts, *field_paths: str) -> list[str]:
    return [
        uncertainty
        for uncertainty in facts.network_telemetry_posture_uncertainties
        if _matches_any(uncertainty, field_paths)
    ]


def _matches_any(value: str, needles: tuple[str, ...]) -> bool:
    normalized = value.lower()
    return any(needle.lower() in normalized for needle in needles)


def _parse_sampling(value: str | None) -> float | None:
    if value is None:
        return None
    try:
        return float(value)
    except ValueError:
        return None
