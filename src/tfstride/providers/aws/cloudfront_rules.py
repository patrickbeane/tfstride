from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from tfstride.analysis.finding_factory import FindingFactory
from tfstride.analysis.finding_helpers import (
    build_severity_reasoning,
    collect_evidence,
    dedupe_addresses,
    evidence_item,
)
from tfstride.analysis.rule_definitions import RuleEvaluationContext
from tfstride.models import Finding, NormalizedResource
from tfstride.providers.aws.resource_facts import AwsResourceFacts, aws_facts

_AWS_CLOUDFRONT_DISTRIBUTION = "aws_cloudfront_distribution"
_ALLOW_ALL_VIEWER_PROTOCOL_POLICY = "allow-all"
_CONFIGURED_TLS_STATE = "configured"
_WEAK_TLS_POLICY_NAMES = frozenset(
    {
        "sslv3",
        "tlsv1",
        "tlsv1_2016",
        "tlsv1_1",
        "tlsv1_1_2016",
    }
)


class AwsCloudFrontRuleDetectors:
    def __init__(self, finding_factory: FindingFactory) -> None:
        self._finding_factory = finding_factory

    def detect_viewer_http_allowed(
        self,
        context: RuleEvaluationContext,
        rule_id: str,
    ) -> list[Finding]:
        if context.inventory.provider != "aws":
            return []

        findings: list[Finding] = []
        for distribution in _enabled_cloudfront_distributions(context):
            facts = aws_facts(distribution)
            policy_evidence = _viewer_http_policy_evidence(facts)
            if not policy_evidence:
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
                    affected_resources=dedupe_addresses([distribution.address]),
                    trust_boundary_id=None,
                    rationale=(
                        f"{distribution.display_name} allows viewers to use plaintext HTTP for at least one "
                        "CloudFront cache behavior. Public distributions should use redirect-to-https or "
                        "https-only viewer protocol policies so clients do not rely on cleartext transport."
                    ),
                    evidence=collect_evidence(
                        evidence_item("target_distribution", _distribution_evidence(distribution, facts)),
                        evidence_item("viewer_protocol_policy", policy_evidence),
                    ),
                    severity_reasoning=severity_reasoning,
                )
            )
        return findings

    def detect_viewer_tls_policy_weak_or_unknown(
        self,
        context: RuleEvaluationContext,
        rule_id: str,
    ) -> list[Finding]:
        if context.inventory.provider != "aws":
            return []

        findings: list[Finding] = []
        for distribution in _enabled_cloudfront_distributions(context):
            facts = aws_facts(distribution)
            tls_state = _viewer_tls_policy_state(facts)
            if tls_state == _CONFIGURED_TLS_STATE:
                continue
            severity_reasoning = build_severity_reasoning(
                internet_exposure=True,
                privilege_breadth=0,
                data_sensitivity=0,
                lateral_movement=0,
                blast_radius=1,
            )
            findings.append(
                self._finding_factory.build(
                    rule_id=rule_id,
                    severity=severity_reasoning.severity,
                    affected_resources=dedupe_addresses([distribution.address]),
                    trust_boundary_id=None,
                    rationale=_viewer_tls_rationale(distribution, facts, tls_state),
                    evidence=collect_evidence(
                        evidence_item("target_distribution", _distribution_evidence(distribution, facts)),
                        evidence_item("viewer_tls_policy", _viewer_tls_evidence(facts, tls_state)),
                        evidence_item(
                            "posture_uncertainty",
                            _cloudfront_uncertainty_evidence(facts, "minimum_protocol_version"),
                        ),
                    ),
                    severity_reasoning=severity_reasoning,
                )
            )
        return findings

    def detect_access_logging_not_configured(
        self,
        context: RuleEvaluationContext,
        rule_id: str,
    ) -> list[Finding]:
        if context.inventory.provider != "aws":
            return []

        findings: list[Finding] = []
        for distribution in _enabled_cloudfront_distributions(context):
            facts = aws_facts(distribution)
            if facts.cloudfront_logging_state != "not_configured":
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
                    affected_resources=dedupe_addresses([distribution.address]),
                    trust_boundary_id=None,
                    rationale=(
                        f"{distribution.display_name} is an enabled public CloudFront distribution, but the "
                        "Terraform plan does not configure a standard access-log destination through "
                        "logging_config. Requests may lack durable CloudFront access records unless separate "
                        "real-time logging or external telemetry is configured outside this resource."
                    ),
                    evidence=collect_evidence(
                        evidence_item("target_distribution", _distribution_evidence(distribution, facts)),
                        evidence_item("access_logging", _access_logging_evidence(facts)),
                    ),
                    severity_reasoning=severity_reasoning,
                )
            )
        return findings

    def detect_web_acl_missing(
        self,
        context: RuleEvaluationContext,
        rule_id: str,
    ) -> list[Finding]:
        if context.inventory.provider != "aws":
            return []

        findings: list[Finding] = []
        for distribution in _enabled_cloudfront_distributions(context):
            facts = aws_facts(distribution)
            edge_protection_state = _cloudfront_edge_protection_state(facts)
            if edge_protection_state in {"configured", "unknown"}:
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
                    affected_resources=dedupe_addresses([distribution.address]),
                    trust_boundary_id=None,
                    rationale=(
                        f"{distribution.display_name} is an enabled public CloudFront distribution, but the "
                        "Terraform plan does not show a deterministic Web ACL attached through web_acl_id. "
                        "Public edge traffic can reach the distribution without a modeled AWS WAF policy."
                    ),
                    evidence=collect_evidence(
                        evidence_item("target_distribution", _distribution_evidence(distribution, facts)),
                        evidence_item(
                            "edge_protection_policy", _edge_protection_evidence(facts, edge_protection_state)
                        ),
                        evidence_item("posture_uncertainty", _cloudfront_uncertainty_evidence(facts, "web_acl_id")),
                    ),
                    severity_reasoning=severity_reasoning,
                )
            )
        return findings


def _enabled_cloudfront_distributions(context: RuleEvaluationContext) -> list[NormalizedResource]:
    return [
        distribution
        for distribution in context.inventory.by_type(_AWS_CLOUDFRONT_DISTRIBUTION)
        if distribution.public_exposure and aws_facts(distribution).cloudfront_enabled is True
    ]


def _viewer_http_policy_evidence(facts: AwsResourceFacts) -> list[str]:
    evidence: list[str] = []
    if _normalized_policy(facts.cloudfront_default_viewer_protocol_policy) == _ALLOW_ALL_VIEWER_PROTOCOL_POLICY:
        evidence.append("default_cache_behavior viewer_protocol_policy=allow-all")
    for behavior in facts.cloudfront_ordered_cache_behaviors:
        if not isinstance(behavior, Mapping):
            continue
        policy = _normalized_policy(behavior.get("viewer_protocol_policy"))
        if policy != _ALLOW_ALL_VIEWER_PROTOCOL_POLICY:
            continue
        values = ["ordered_cache_behavior", "viewer_protocol_policy=allow-all"]
        if behavior.get("path_pattern"):
            values.insert(1, f"path_pattern={behavior['path_pattern']}")
        evidence.append(" ".join(str(value) for value in values))
    return evidence


def _viewer_tls_policy_state(facts: AwsResourceFacts) -> str:
    minimum_protocol_version = facts.cloudfront_minimum_protocol_version
    if minimum_protocol_version:
        return "weak" if _cloudfront_tls_policy_is_weak(minimum_protocol_version) else _CONFIGURED_TLS_STATE
    if _cloudfront_field_unknown(facts, "minimum_protocol_version"):
        return "unknown"
    if facts.cloudfront_aliases and facts.cloudfront_viewer_certificate:
        return "unknown"
    return _CONFIGURED_TLS_STATE


def _cloudfront_tls_policy_is_weak(policy: str) -> bool:
    normalized = policy.strip().lower().replace(".", "_").replace("-", "_")
    return normalized in _WEAK_TLS_POLICY_NAMES


def _cloudfront_edge_protection_state(facts: AwsResourceFacts) -> str:
    if facts.cloudfront_web_acl_id:
        return "configured"
    if _cloudfront_field_unknown(facts, "web_acl_id"):
        return "unknown"
    return "missing"


def _distribution_evidence(distribution: NormalizedResource, facts: AwsResourceFacts) -> list[str]:
    values = [f"address={distribution.address}", f"type={distribution.resource_type}"]
    if distribution.identifier:
        values.append(f"identifier={distribution.identifier}")
    if distribution.arn:
        values.append(f"arn={distribution.arn}")
    if facts.cloudfront_domain_name:
        values.append(f"domain_name={facts.cloudfront_domain_name}")
    if facts.cloudfront_aliases:
        values.append("aliases=" + ",".join(facts.cloudfront_aliases))
    values.append(f"enabled_state={facts.cloudfront_enabled_state or 'unknown'}")
    values.append("public_exposure=true")
    values.extend(distribution.public_exposure_reasons)
    return values


def _viewer_tls_evidence(facts: AwsResourceFacts, tls_state: str) -> list[str]:
    evidence = [f"minimum_protocol_version_state={tls_state}"]
    if facts.cloudfront_minimum_protocol_version:
        evidence.append(f"minimum_protocol_version={facts.cloudfront_minimum_protocol_version}")
    else:
        evidence.append("minimum_protocol_version is unset or unknown")
    if facts.cloudfront_viewer_certificate_source:
        evidence.append(f"certificate_source={facts.cloudfront_viewer_certificate_source}")
    if facts.cloudfront_default_certificate_state:
        evidence.append(f"cloudfront_default_certificate_state={facts.cloudfront_default_certificate_state}")
    if facts.cloudfront_acm_certificate_arn:
        evidence.append(f"acm_certificate_arn={facts.cloudfront_acm_certificate_arn}")
    if facts.cloudfront_iam_certificate_id:
        evidence.append(f"iam_certificate_id={facts.cloudfront_iam_certificate_id}")
    if facts.cloudfront_aliases:
        evidence.append("aliases=" + ",".join(facts.cloudfront_aliases))
    return evidence


def _access_logging_evidence(facts: AwsResourceFacts) -> list[str]:
    values = [f"cloudfront_logging_state={facts.cloudfront_logging_state or 'unknown'}"]
    if facts.cloudfront_logging_bucket:
        values.append(f"bucket={facts.cloudfront_logging_bucket}")
    else:
        values.append("logging_config.bucket is not configured")
    if facts.cloudfront_logging_prefix:
        values.append(f"prefix={facts.cloudfront_logging_prefix}")
    return values


def _edge_protection_evidence(facts: AwsResourceFacts, edge_protection_state: str) -> list[str]:
    evidence = [f"edge_protection_state={edge_protection_state}"]
    if facts.cloudfront_web_acl_id:
        evidence.append(f"web_acl_id={facts.cloudfront_web_acl_id}")
    else:
        evidence.append("web_acl_id is unset")
    return evidence


def _viewer_tls_rationale(distribution: NormalizedResource, facts: AwsResourceFacts, tls_state: str) -> str:
    if tls_state == "weak" and facts.cloudfront_minimum_protocol_version:
        return (
            f"{distribution.display_name} uses {facts.cloudfront_minimum_protocol_version} as its CloudFront "
            "viewer TLS minimum protocol version. Public distributions should require TLS 1.2 or newer."
        )
    return (
        f"{distribution.display_name} is an enabled CloudFront distribution, but the Terraform plan does not show "
        "a deterministic modern viewer TLS minimum protocol version. tfSTRIDE cannot prove the distribution "
        "requires TLS 1.2 or newer from the available data."
    )


def _normalized_policy(value: Any) -> str | None:
    if not isinstance(value, str) or not value.strip():
        return None
    return value.strip().lower()


def _cloudfront_field_unknown(facts: AwsResourceFacts, field_name: str) -> bool:
    return any(field_name in uncertainty for uncertainty in facts.cloudfront_posture_uncertainties)


def _cloudfront_uncertainty_evidence(facts: AwsResourceFacts, field_name: str) -> list[str]:
    return [uncertainty for uncertainty in facts.cloudfront_posture_uncertainties if field_name in uncertainty]
