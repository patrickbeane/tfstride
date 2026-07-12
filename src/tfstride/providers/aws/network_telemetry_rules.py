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
from tfstride.providers.aws.resource_facts import AwsResourceFacts, aws_facts

_AWS_VPC = "aws_vpc"
_AWS_FLOW_LOG = "aws_flow_log"
_TRAFFIC_TYPE_ALL = "all"
_CLOUDWATCH_DESTINATION_TYPES = frozenset({"cloud-watch-logs", "cloudwatch", "cloudwatch-logs"})


class AwsNetworkTelemetryRuleDetectors:
    def __init__(self, finding_factory: FindingFactory) -> None:
        self._finding_factory = finding_factory

    def detect_vpc_flow_logs_not_configured(
        self,
        context: RuleEvaluationContext,
        rule_id: str,
    ) -> list[Finding]:
        if context.inventory.provider != "aws":
            return []

        flow_logs = context.inventory.by_type(_AWS_FLOW_LOG)
        resolved_vpc_flow_logs = _resolved_vpc_flow_logs(flow_logs)
        unresolved_flow_logs = _unresolved_target_flow_logs(flow_logs)
        findings: list[Finding] = []
        for vpc in context.inventory.by_type(_AWS_VPC):
            vpc_id = _vpc_identifier(vpc)
            if not vpc_id or vpc_id in resolved_vpc_flow_logs:
                continue
            if unresolved_flow_logs:
                continue

            severity_reasoning = build_severity_reasoning(
                internet_exposure=False,
                privilege_breadth=0,
                data_sensitivity=0,
                lateral_movement=1,
                blast_radius=2,
            )
            findings.append(
                self._finding_factory.build(
                    rule_id=rule_id,
                    severity=severity_reasoning.severity,
                    affected_resources=[vpc.address],
                    trust_boundary_id=None,
                    rationale=(
                        f"{vpc.display_name} does not have a resolved aws_flow_log targeting the VPC in this "
                        "Terraform plan. Network traffic metadata for incident response, threat hunting, and "
                        "segmentation review may be unavailable unless Flow Logs are configured elsewhere."
                    ),
                    evidence=collect_evidence(
                        evidence_item("target_vpc", _vpc_target_evidence(vpc)),
                        evidence_item("flow_log_coverage", _missing_vpc_flow_log_evidence(vpc_id, flow_logs)),
                    ),
                    severity_reasoning=severity_reasoning,
                )
            )
        return findings

    def detect_flow_log_traffic_type_incomplete(
        self,
        context: RuleEvaluationContext,
        rule_id: str,
    ) -> list[Finding]:
        if context.inventory.provider != "aws":
            return []

        findings: list[Finding] = []
        for flow_log in context.inventory.by_type(_AWS_FLOW_LOG):
            facts = aws_facts(flow_log)
            traffic_type = _normalized_traffic_type(facts)
            if traffic_type == _TRAFFIC_TYPE_ALL:
                continue

            traffic_type_unknown = traffic_type is None
            severity_reasoning = build_severity_reasoning(
                internet_exposure=False,
                privilege_breadth=0,
                data_sensitivity=0,
                lateral_movement=1,
                blast_radius=1 if traffic_type_unknown else 2,
            )
            findings.append(
                self._finding_factory.build(
                    rule_id=rule_id,
                    severity=severity_reasoning.severity,
                    affected_resources=[flow_log.address],
                    trust_boundary_id=None,
                    rationale=_traffic_type_rationale(flow_log.display_name, facts, traffic_type_unknown),
                    evidence=collect_evidence(
                        evidence_item("target_flow_log", _flow_log_target_evidence(flow_log, facts)),
                        evidence_item("traffic_capture", _traffic_capture_evidence(facts)),
                        evidence_item("posture_uncertainty", _flow_log_uncertainty_evidence(facts, "traffic_type")),
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
        if context.inventory.provider != "aws":
            return []

        findings: list[Finding] = []
        for flow_log in context.inventory.by_type(_AWS_FLOW_LOG):
            facts = aws_facts(flow_log)
            if _has_deterministic_destination(facts):
                continue

            destination_unknown = bool(
                _flow_log_uncertainty_evidence(facts, "log_destination")
                or _flow_log_uncertainty_evidence(facts, "log_group_name")
                or _flow_log_uncertainty_evidence(facts, "log_destination_type")
            )
            severity_reasoning = build_severity_reasoning(
                internet_exposure=False,
                privilege_breadth=0,
                data_sensitivity=0,
                lateral_movement=1,
                blast_radius=1 if destination_unknown else 2,
            )
            findings.append(
                self._finding_factory.build(
                    rule_id=rule_id,
                    severity=severity_reasoning.severity,
                    affected_resources=[flow_log.address],
                    trust_boundary_id=None,
                    rationale=_destination_rationale(flow_log.display_name, destination_unknown),
                    evidence=collect_evidence(
                        evidence_item("target_flow_log", _flow_log_target_evidence(flow_log, facts)),
                        evidence_item("log_destination", _destination_evidence(facts)),
                        evidence_item(
                            "posture_uncertainty",
                            _flow_log_uncertainty_evidence(
                                facts,
                                "log_destination",
                                "log_group_name",
                                "log_destination_type",
                            ),
                        ),
                    ),
                    severity_reasoning=severity_reasoning,
                )
            )
        return findings


def _resolved_vpc_flow_logs(flow_logs: Iterable[NormalizedResource]) -> dict[str, list[NormalizedResource]]:
    resolved: dict[str, list[NormalizedResource]] = {}
    for flow_log in flow_logs:
        facts = aws_facts(flow_log)
        if facts.flow_log_target_type != "vpc" or not facts.flow_log_target_id:
            continue
        resolved.setdefault(facts.flow_log_target_id, []).append(flow_log)
    return resolved


def _unresolved_target_flow_logs(flow_logs: Iterable[NormalizedResource]) -> list[NormalizedResource]:
    unresolved: list[NormalizedResource] = []
    for flow_log in flow_logs:
        facts = aws_facts(flow_log)
        if facts.flow_log_target_type or facts.flow_log_target_id:
            continue
        if _flow_log_uncertainty_evidence(
            facts,
            "vpc_id",
            "subnet_id",
            "eni_id",
            "transit_gateway_id",
            "transit_gateway_attachment_id",
        ):
            unresolved.append(flow_log)
    return unresolved


def _vpc_identifier(vpc: NormalizedResource) -> str | None:
    return vpc.identifier.strip() if isinstance(vpc.identifier, str) and vpc.identifier.strip() else None


def _normalized_traffic_type(facts: AwsResourceFacts) -> str | None:
    return facts.flow_log_traffic_type.strip().lower() if facts.flow_log_traffic_type else None


def _has_deterministic_destination(facts: AwsResourceFacts) -> bool:
    if facts.flow_log_destination:
        return True
    destination_type = facts.flow_log_destination_type.strip().lower() if facts.flow_log_destination_type else None
    return destination_type in _CLOUDWATCH_DESTINATION_TYPES and bool(facts.flow_log_log_group_name)


def _vpc_target_evidence(vpc: NormalizedResource) -> list[str]:
    values = [f"address={vpc.address}", f"type={vpc.resource_type}"]
    if vpc.identifier:
        values.append(f"identifier={vpc.identifier}")
    if vpc.vpc_id:
        values.append(f"vpc_id={vpc.vpc_id}")
    cidr_block = aws_facts(vpc).cidr_block
    if cidr_block:
        values.append(f"cidr_block={cidr_block}")
    return values


def _missing_vpc_flow_log_evidence(vpc_id: str, flow_logs: list[NormalizedResource]) -> list[str]:
    values = [f"target_vpc_id={vpc_id}", "resolved_vpc_flow_log_count=0"]
    if not flow_logs:
        values.append("aws_flow_log resources are not modeled")
        return values
    values.append(f"modeled_flow_log_count={len(flow_logs)}")
    for flow_log in flow_logs:
        facts = aws_facts(flow_log)
        values.append(
            f"flow_log={flow_log.address}; target_type={facts.flow_log_target_type or 'unknown'}; "
            f"target_id={facts.flow_log_target_id or 'unknown'}"
        )
    return values


def _flow_log_target_evidence(flow_log: NormalizedResource, facts: AwsResourceFacts) -> list[str]:
    values = [f"address={flow_log.address}", f"type={flow_log.resource_type}"]
    if facts.flow_log_id:
        values.append(f"flow_log_id={facts.flow_log_id}")
    if facts.flow_log_target_type:
        values.append(f"target_type={facts.flow_log_target_type}")
    if facts.flow_log_target_id:
        values.append(f"target_id={facts.flow_log_target_id}")
    return values


def _traffic_capture_evidence(facts: AwsResourceFacts) -> list[str]:
    traffic_type = facts.flow_log_traffic_type or "unknown"
    values = [f"traffic_type={traffic_type}"]
    if _normalized_traffic_type(facts) == _TRAFFIC_TYPE_ALL:
        values.append("Flow Log captures ACCEPT and REJECT traffic")
    elif facts.flow_log_traffic_type:
        values.append("Flow Log does not capture both ACCEPT and REJECT traffic")
    else:
        values.append("Flow Log traffic_type is unknown")
    return values


def _destination_evidence(facts: AwsResourceFacts) -> list[str]:
    values = [f"destination_type={facts.flow_log_destination_type or 'unknown'}"]
    if facts.flow_log_destination:
        values.append(f"log_destination={facts.flow_log_destination}")
    else:
        values.append("log_destination is unset")
    if facts.flow_log_log_group_name:
        values.append(f"log_group_name={facts.flow_log_log_group_name}")
    else:
        values.append("log_group_name is unset")
    if facts.flow_log_iam_role_arn:
        values.append(f"iam_role_arn={facts.flow_log_iam_role_arn}")
    if facts.flow_log_max_aggregation_interval is not None:
        values.append(f"max_aggregation_interval={facts.flow_log_max_aggregation_interval}")
    return values


def _flow_log_uncertainty_evidence(facts: AwsResourceFacts, *field_paths: str) -> list[str]:
    return [
        f"uncertainty={uncertainty}"
        for uncertainty in facts.flow_log_posture_uncertainties
        if any(field_path in uncertainty for field_path in field_paths)
    ]


def _traffic_type_rationale(display_name: str, facts: AwsResourceFacts, traffic_type_unknown: bool) -> str:
    if traffic_type_unknown:
        return (
            f"{display_name} does not show a deterministic VPC Flow Log traffic_type in the Terraform plan. "
            "tfSTRIDE cannot confirm the Flow Log captures both accepted and rejected network traffic."
        )
    return (
        f"{display_name} captures traffic_type={facts.flow_log_traffic_type}, not ALL. That can leave either "
        "accepted or rejected network flows outside the modeled telemetry stream, reducing investigation and "
        "segmentation-review coverage."
    )


def _destination_rationale(display_name: str, destination_unknown: bool) -> str:
    if destination_unknown:
        return (
            f"{display_name} does not show a deterministic VPC Flow Log destination in the Terraform plan. "
            "tfSTRIDE cannot confirm where network telemetry will be delivered for retention and review."
        )
    return (
        f"{display_name} does not model a CloudWatch log group, S3, or Firehose destination for VPC Flow Logs. "
        "Network telemetry may not be delivered to a durable review location."
    )
