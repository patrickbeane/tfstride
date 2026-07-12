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
from tfstride.providers.aws.resource_facts import AwsResourceFacts, aws_facts
from tfstride.providers.aws.resource_index import AwsResourceIndexBuilder

_AWS_LOAD_BALANCER = "aws_lb"
_AWS_LOAD_BALANCER_LISTENER = "aws_lb_listener"
_HTTP_PROTOCOL = "http"
_TLS_PROTOCOLS = frozenset({"https", "tls"})
_WEAK_SSL_POLICY_MARKERS = frozenset(
    {
        "ssl",
        "tls-1-0",
        "tls-1-1",
        "tls10",
        "tls11",
        "tlsv1-0",
        "tlsv1-1",
        "2015-05",
        "2016-08",
    }
)


class AwsLoadBalancerRuleDetectors:
    def __init__(self, finding_factory: FindingFactory) -> None:
        self._finding_factory = finding_factory

    def detect_public_http_listener(
        self,
        context: RuleEvaluationContext,
        rule_id: str,
    ) -> list[Finding]:
        if context.inventory.provider != "aws":
            return []

        findings: list[Finding] = []
        public_load_balancers_by_listener = _public_load_balancers_by_listener(context)
        for listener, load_balancer in public_load_balancers_by_listener:
            facts = aws_facts(listener)
            if _normalized_protocol(facts) != _HTTP_PROTOCOL:
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
                    affected_resources=dedupe_addresses([listener.address, load_balancer.address]),
                    trust_boundary_id=None,
                    rationale=(
                        f"{listener.display_name} accepts plaintext HTTP traffic on an internet-facing "
                        "AWS load balancer. Public listeners should terminate HTTPS or redirect HTTP to HTTPS "
                        "so clients do not rely on cleartext transport."
                    ),
                    evidence=collect_evidence(
                        evidence_item("target_listener", _listener_target_evidence(listener, facts)),
                        evidence_item("listener_transport", _listener_transport_evidence(facts)),
                        evidence_item("load_balancer_exposure", _load_balancer_exposure_evidence(load_balancer)),
                    ),
                    severity_reasoning=severity_reasoning,
                )
            )
        return findings

    def detect_tls_certificate_missing(
        self,
        context: RuleEvaluationContext,
        rule_id: str,
    ) -> list[Finding]:
        if context.inventory.provider != "aws":
            return []

        findings: list[Finding] = []
        public_load_balancers_by_listener = _public_load_balancers_by_listener(context)
        for listener, load_balancer in public_load_balancers_by_listener:
            facts = aws_facts(listener)
            if _normalized_protocol(facts) not in _TLS_PROTOCOLS or facts.load_balancer_listener_certificate_arn:
                continue
            certificate_unknown = _field_unknown(facts, "certificate_arn")
            severity_reasoning = build_severity_reasoning(
                internet_exposure=True,
                privilege_breadth=0,
                data_sensitivity=0,
                lateral_movement=0,
                blast_radius=1 if not certificate_unknown else 0,
            )
            findings.append(
                self._finding_factory.build(
                    rule_id=rule_id,
                    severity=severity_reasoning.severity,
                    affected_resources=dedupe_addresses([listener.address, load_balancer.address]),
                    trust_boundary_id=None,
                    rationale=(
                        f"{listener.display_name} is a public TLS listener but the Terraform plan does not "
                        "show a deterministic certificate ARN. tfSTRIDE cannot prove the listener presents an "
                        "expected managed certificate from the available plan data."
                    ),
                    evidence=collect_evidence(
                        evidence_item("target_listener", _listener_target_evidence(listener, facts)),
                        evidence_item("certificate_posture", _certificate_evidence(facts)),
                        evidence_item("load_balancer_exposure", _load_balancer_exposure_evidence(load_balancer)),
                        evidence_item("posture_uncertainty", _uncertainty_evidence(facts, "certificate_arn")),
                    ),
                    severity_reasoning=severity_reasoning,
                )
            )
        return findings

    def detect_ssl_policy_weak_or_unknown(
        self,
        context: RuleEvaluationContext,
        rule_id: str,
    ) -> list[Finding]:
        if context.inventory.provider != "aws":
            return []

        findings: list[Finding] = []
        public_load_balancers_by_listener = _public_load_balancers_by_listener(context)
        for listener, load_balancer in public_load_balancers_by_listener:
            facts = aws_facts(listener)
            if _normalized_protocol(facts) not in _TLS_PROTOCOLS:
                continue
            policy_state = _ssl_policy_state(facts)
            if policy_state == "configured":
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
                    affected_resources=dedupe_addresses([listener.address, load_balancer.address]),
                    trust_boundary_id=None,
                    rationale=_ssl_policy_rationale(listener.display_name, facts, policy_state),
                    evidence=collect_evidence(
                        evidence_item("target_listener", _listener_target_evidence(listener, facts)),
                        evidence_item("ssl_policy_posture", _ssl_policy_evidence(facts, policy_state)),
                        evidence_item("load_balancer_exposure", _load_balancer_exposure_evidence(load_balancer)),
                        evidence_item("posture_uncertainty", _uncertainty_evidence(facts, "ssl_policy")),
                    ),
                    severity_reasoning=severity_reasoning,
                )
            )
        return findings


def _public_load_balancers_by_listener(
    context: RuleEvaluationContext,
) -> list[tuple[NormalizedResource, NormalizedResource]]:
    index = AwsResourceIndexBuilder().build(context.inventory.resources)
    public_load_balancers_by_listener: list[tuple[NormalizedResource, NormalizedResource]] = []
    for listener in context.inventory.by_type(_AWS_LOAD_BALANCER_LISTENER):
        load_balancer = index.load_balancers.get(aws_facts(listener).load_balancer_arn or "")
        if _is_public_load_balancer(load_balancer):
            public_load_balancers_by_listener.append((listener, load_balancer))
    return public_load_balancers_by_listener


def _is_public_load_balancer(resource: NormalizedResource | None) -> bool:
    return resource is not None and resource.resource_type == _AWS_LOAD_BALANCER and resource.public_exposure


def _normalized_protocol(facts: AwsResourceFacts) -> str | None:
    protocol = facts.load_balancer_listener_protocol
    return protocol.strip().lower() if protocol else None


def _ssl_policy_state(facts: AwsResourceFacts) -> str:
    policy = facts.load_balancer_listener_ssl_policy
    if not policy:
        return "unknown"
    return "weak" if _ssl_policy_is_weak(policy) else "configured"


def _ssl_policy_is_weak(policy: str) -> bool:
    normalized = policy.strip().lower().replace("_", "-")
    return any(marker in normalized for marker in _WEAK_SSL_POLICY_MARKERS)


def _field_unknown(facts: AwsResourceFacts, field_name: str) -> bool:
    return any(field_name in uncertainty for uncertainty in facts.load_balancer_listener_tls_uncertainties)


def _listener_target_evidence(listener: NormalizedResource, facts: AwsResourceFacts) -> list[str]:
    values = [f"address={listener.address}", f"type={listener.resource_type}"]
    if listener.identifier:
        values.append(f"identifier={listener.identifier}")
    if listener.arn:
        values.append(f"arn={listener.arn}")
    if facts.load_balancer_listener_protocol:
        values.append(f"protocol={facts.load_balancer_listener_protocol}")
    return values


def _listener_transport_evidence(facts: AwsResourceFacts) -> list[str]:
    protocol = facts.load_balancer_listener_protocol or "unknown"
    values = [f"protocol={protocol}"]
    if _normalized_protocol(facts) == _HTTP_PROTOCOL:
        values.append("HTTP listener does not terminate TLS")
    return values


def _certificate_evidence(facts: AwsResourceFacts) -> list[str]:
    values = [
        f"certificate_arn={facts.load_balancer_listener_certificate_arn}"
        if facts.load_balancer_listener_certificate_arn
        else "certificate_arn is unset"
    ]
    if _field_unknown(facts, "certificate_arn"):
        values.append("certificate_arn is unknown after planning")
    return values


def _ssl_policy_evidence(facts: AwsResourceFacts, policy_state: str) -> list[str]:
    values = [f"ssl_policy_state={policy_state}"]
    if facts.load_balancer_listener_ssl_policy:
        values.append(f"ssl_policy={facts.load_balancer_listener_ssl_policy}")
    else:
        values.append("ssl_policy is unset or unknown")
    if _field_unknown(facts, "ssl_policy"):
        values.append("ssl_policy is unknown after planning")
    return values


def _load_balancer_exposure_evidence(load_balancer: NormalizedResource) -> list[str]:
    values = [f"address={load_balancer.address}", f"type={load_balancer.resource_type}"]
    if load_balancer.arn:
        values.append(f"arn={load_balancer.arn}")
    values.append("public_exposure=true")
    values.extend(load_balancer.public_exposure_reasons)
    return values


def _uncertainty_evidence(facts: AwsResourceFacts, field_name: str) -> list[str]:
    return [uncertainty for uncertainty in facts.load_balancer_listener_tls_uncertainties if field_name in uncertainty]


def _ssl_policy_rationale(display_name: str, facts: AwsResourceFacts, policy_state: str) -> str:
    if policy_state == "weak":
        return (
            f"{display_name} uses `{facts.load_balancer_listener_ssl_policy}` as its public listener SSL policy. "
            "That policy name indicates legacy SSL or pre-TLS-1.2 compatibility and weakens transport posture."
        )
    return (
        f"{display_name} is a public TLS listener but the Terraform plan does not show a deterministic "
        "SSL policy. tfSTRIDE cannot prove the listener enforces a modern TLS policy from the available data."
    )
