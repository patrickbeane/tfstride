from __future__ import annotations

from tfstride.analysis.finding_factory import FindingFactory
from tfstride.analysis.finding_helpers import (
    build_severity_reasoning,
    collect_evidence,
    dedupe_addresses,
    evidence_item,
)
from tfstride.analysis.rule_definitions import RuleEvaluationContext
from tfstride.models import Finding, NormalizedResource
from tfstride.providers.aws.resource_facts import aws_facts

_AWS_LOAD_BALANCER = "aws_lb"
_AWS_WAFV2_WEB_ACL_ASSOCIATION = "aws_wafv2_web_acl_association"
_APPLICATION_LOAD_BALANCER = "application"


class AwsEdgeProtectionRuleDetectors:
    def __init__(self, finding_factory: FindingFactory) -> None:
        self._finding_factory = finding_factory

    def detect_public_alb_waf_missing(
        self,
        context: RuleEvaluationContext,
        rule_id: str,
    ) -> list[Finding]:
        if context.inventory.provider != "aws":
            return []

        associations = list(context.inventory.by_type(_AWS_WAFV2_WEB_ACL_ASSOCIATION))
        associated_resource_arns = _associated_resource_arns(associations)
        if _has_unresolved_association_target(associations):
            return []

        findings: list[Finding] = []
        for load_balancer in context.inventory.by_type(_AWS_LOAD_BALANCER):
            if not _is_public_application_load_balancer(load_balancer):
                continue
            if load_balancer.arn and _normalized_arn(load_balancer.arn) in associated_resource_arns:
                continue
            severity_reasoning = build_severity_reasoning(
                internet_exposure=True,
                privilege_breadth=0,
                data_sensitivity=0,
                lateral_movement=1,
                blast_radius=1,
            )
            findings.append(
                self._finding_factory.build(
                    rule_id=rule_id,
                    severity=severity_reasoning.severity,
                    affected_resources=dedupe_addresses([load_balancer.address]),
                    trust_boundary_id=None,
                    rationale=(
                        f"{load_balancer.display_name} is an internet-facing Application Load Balancer, but the "
                        "Terraform plan does not show a deterministic AWS WAFv2 Web ACL association targeting it. "
                        "Public edge traffic can reach the ALB without a modeled WAF or edge protection policy."
                    ),
                    evidence=collect_evidence(
                        evidence_item("target_load_balancer", _load_balancer_evidence(load_balancer)),
                        evidence_item(
                            "waf_association_coverage",
                            _waf_association_coverage_evidence(load_balancer, associations),
                        ),
                    ),
                    severity_reasoning=severity_reasoning,
                )
            )
        return findings


def _is_public_application_load_balancer(load_balancer: NormalizedResource) -> bool:
    return (
        load_balancer.resource_type == _AWS_LOAD_BALANCER
        and load_balancer.public_exposure
        and _load_balancer_type(load_balancer) == _APPLICATION_LOAD_BALANCER
        and bool(load_balancer.arn)
    )


def _load_balancer_type(load_balancer: NormalizedResource) -> str | None:
    value = load_balancer.metadata.get("load_balancer_type")
    return value.strip().lower() if isinstance(value, str) and value.strip() else None


def _associated_resource_arns(associations: list[NormalizedResource]) -> frozenset[str]:
    return frozenset(
        _normalized_arn(resource_arn)
        for association in associations
        if (resource_arn := aws_facts(association).web_acl_association_resource_arn)
    )


def _has_unresolved_association_target(associations: list[NormalizedResource]) -> bool:
    return any(
        aws_facts(association).web_acl_association_resource_arn is None
        and any(
            "resource_arn" in uncertainty
            for uncertainty in aws_facts(association).edge_protection_posture_uncertainties
        )
        for association in associations
    )


def _normalized_arn(value: str) -> str:
    return value.strip()


def _load_balancer_evidence(load_balancer: NormalizedResource) -> list[str]:
    values = [f"address={load_balancer.address}", f"type={load_balancer.resource_type}"]
    if load_balancer.arn:
        values.append(f"arn={load_balancer.arn}")
    if load_balancer.metadata.get("load_balancer_type"):
        values.append(f"load_balancer_type={load_balancer.metadata['load_balancer_type']}")
    values.append("public_exposure=true")
    values.extend(load_balancer.public_exposure_reasons)
    return values


def _waf_association_coverage_evidence(
    load_balancer: NormalizedResource,
    associations: list[NormalizedResource],
) -> list[str]:
    values = [f"target_resource_arn={load_balancer.arn}", "resolved_web_acl_association_count=0"]
    if associations:
        values.append(f"modeled_web_acl_association_count={len(associations)}")
        nonmatching_targets = sorted(
            resource_arn
            for association in associations
            if (resource_arn := aws_facts(association).web_acl_association_resource_arn)
            and _normalized_arn(resource_arn) != _normalized_arn(str(load_balancer.arn))
        )
        values.extend(f"nonmatching_association_target={resource_arn}" for resource_arn in nonmatching_targets)
    else:
        values.append("modeled_web_acl_association_count=0")
    return values
