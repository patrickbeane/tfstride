from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from tfstride.analysis.finding_factory import FindingFactory
from tfstride.analysis.finding_helpers import build_severity_reasoning, collect_evidence, evidence_item
from tfstride.analysis.rule_definitions import RuleEvaluationContext
from tfstride.models import Finding, NormalizedResource
from tfstride.providers.azure.resource_facts import AzureResourceFacts, azure_facts
from tfstride.providers.azure.resource_types import AzureResourceType

_EXPOSURE_PUBLIC = "public"


class AzureLoadBalancerRuleDetectors:
    def __init__(self, finding_factory: FindingFactory) -> None:
        self._finding_factory = finding_factory

    def detect_public_load_balancer_frontend(
        self,
        context: RuleEvaluationContext,
        rule_id: str,
    ) -> list[Finding]:
        if context.inventory.provider != "azure":
            return []

        findings: list[Finding] = []
        for load_balancer in context.inventory.by_type(AzureResourceType.LOAD_BALANCER):
            facts = azure_facts(load_balancer)
            if facts.load_balancer_exposure_state != _EXPOSURE_PUBLIC:
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
                    affected_resources=[load_balancer.address],
                    trust_boundary_id=None,
                    rationale=(
                        f"{load_balancer.display_name} has a public Load Balancer frontend configured. "
                        "This exposes an Azure edge endpoint; actual backend reachability still depends on "
                        "load-balancing or NAT rules, backend membership, and NSG decisions."
                    ),
                    evidence=collect_evidence(
                        evidence_item("target_resource", _target_resource_evidence(load_balancer)),
                        evidence_item("frontend_exposure", _load_balancer_frontend_evidence(facts)),
                        evidence_item("posture_uncertainty", facts.load_balancer_posture_uncertainties),
                    ),
                    severity_reasoning=severity_reasoning,
                )
            )
        return findings

    def detect_public_application_gateway_listener(
        self,
        context: RuleEvaluationContext,
        rule_id: str,
    ) -> list[Finding]:
        if context.inventory.provider != "azure":
            return []

        findings: list[Finding] = []
        for gateway in context.inventory.by_type(AzureResourceType.APPLICATION_GATEWAY):
            facts = azure_facts(gateway)
            public_listener_records = _public_application_gateway_listeners(facts)
            if facts.application_gateway_exposure_state != _EXPOSURE_PUBLIC or not public_listener_records:
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
                    affected_resources=[gateway.address],
                    trust_boundary_id=None,
                    rationale=(
                        f"{gateway.display_name} has an Application Gateway listener attached to a public "
                        "frontend IP configuration. This creates an internet-facing application edge; WAF, "
                        "listener authentication, routing, backend, and NSG posture must be reviewed separately."
                    ),
                    evidence=collect_evidence(
                        evidence_item("target_resource", _target_resource_evidence(gateway)),
                        evidence_item("frontend_exposure", _application_gateway_frontend_evidence(facts)),
                        evidence_item("public_listeners", _listener_evidence(public_listener_records)),
                        evidence_item("routing_rules", _routing_rule_evidence(facts, public_listener_records)),
                        evidence_item("posture_uncertainty", facts.application_gateway_posture_uncertainties),
                    ),
                    severity_reasoning=severity_reasoning,
                )
            )
        return findings

    def detect_public_application_gateway_waf_missing(
        self,
        context: RuleEvaluationContext,
        rule_id: str,
    ) -> list[Finding]:
        if context.inventory.provider != "azure":
            return []

        findings: list[Finding] = []
        for gateway in context.inventory.by_type(AzureResourceType.APPLICATION_GATEWAY):
            facts = azure_facts(gateway)
            public_listener_records = _public_application_gateway_listeners(facts)
            if facts.application_gateway_exposure_state != _EXPOSURE_PUBLIC or not public_listener_records:
                continue
            edge_protection_state = _application_gateway_edge_protection_state(facts)
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
                    affected_resources=[gateway.address],
                    trust_boundary_id=None,
                    rationale=(
                        f"{gateway.display_name} has an Application Gateway listener attached to a public "
                        "frontend, but the Terraform plan does not show a deterministic firewall policy or enabled "
                        "WAF configuration. Public edge traffic can reach the listener without a modeled WAF policy."
                    ),
                    evidence=collect_evidence(
                        evidence_item("target_resource", _target_resource_evidence(gateway)),
                        evidence_item("frontend_exposure", _application_gateway_frontend_evidence(facts)),
                        evidence_item("public_listeners", _listener_evidence(public_listener_records)),
                        evidence_item("routing_rules", _routing_rule_evidence(facts, public_listener_records)),
                        evidence_item(
                            "edge_protection_policy",
                            _application_gateway_edge_protection_evidence(facts, edge_protection_state),
                        ),
                        evidence_item("posture_uncertainty", facts.application_gateway_posture_uncertainties),
                    ),
                    severity_reasoning=severity_reasoning,
                )
            )
        return findings


def _application_gateway_edge_protection_state(facts: AzureResourceFacts) -> str:
    return facts.application_gateway_edge_protection_state or "not_configured"


def _application_gateway_edge_protection_evidence(
    facts: AzureResourceFacts,
    edge_protection_state: str,
) -> list[str]:
    evidence = [f"edge_protection_state={edge_protection_state}"]
    if facts.application_gateway_firewall_policy_id:
        evidence.append(f"firewall_policy_id={facts.application_gateway_firewall_policy_id}")
    else:
        evidence.append("firewall_policy_id is unset")
    waf_enabled_state = facts.application_gateway_waf_enabled_state or "not_configured"
    evidence.append(f"waf_enabled_state={waf_enabled_state}")
    if facts.application_gateway_waf_mode:
        evidence.append(f"waf_mode={facts.application_gateway_waf_mode}")
    rule_set = _application_gateway_waf_rule_set(facts)
    if rule_set:
        evidence.append(f"waf_rule_set={rule_set}")
    evidence.extend(_waf_configuration_evidence(facts.application_gateway_waf_configurations))
    return evidence


def _application_gateway_waf_rule_set(facts: AzureResourceFacts) -> str | None:
    rule_set_type = facts.application_gateway_waf_rule_set_type
    rule_set_version = facts.application_gateway_waf_rule_set_version
    if rule_set_type and rule_set_version:
        return f"{rule_set_type}/{rule_set_version}"
    return rule_set_type or rule_set_version


def _waf_configuration_evidence(records: list[dict]) -> list[str]:
    evidence: list[str] = []
    for record in records:
        if not isinstance(record, Mapping):
            continue
        values = []
        enabled_state = record.get("enabled_state")
        if enabled_state:
            values.append(f"enabled_state={enabled_state}")
        firewall_mode = record.get("firewall_mode")
        if firewall_mode:
            values.append(f"mode={firewall_mode}")
        rule_set_type = record.get("rule_set_type") or "unknown"
        rule_set_version = record.get("rule_set_version") or "unknown"
        if record.get("rule_set_type") or record.get("rule_set_version"):
            values.append(f"rule_set={rule_set_type}/{rule_set_version}")
        if values:
            evidence.append("waf_configuration " + " ".join(values))
    return evidence


def _target_resource_evidence(resource: NormalizedResource) -> list[str]:
    return [f"address={resource.address}", f"resource_type={resource.resource_type}"]


def _load_balancer_frontend_evidence(facts: AzureResourceFacts) -> list[str]:
    evidence = [f"load_balancer_exposure_state={facts.load_balancer_exposure_state}"]
    evidence.extend(f"public_ip_address_id={reference}" for reference in facts.load_balancer_public_ip_references)
    evidence.extend(f"public_ip_prefix_id={reference}" for reference in facts.load_balancer_public_ip_prefix_references)
    evidence.extend(_frontend_record_evidence(facts.load_balancer_frontends, public_prefix=True))
    return evidence


def _application_gateway_frontend_evidence(facts: AzureResourceFacts) -> list[str]:
    evidence = [f"application_gateway_exposure_state={facts.application_gateway_exposure_state}"]
    evidence.extend(f"public_ip_address_id={reference}" for reference in facts.application_gateway_public_ip_references)
    evidence.extend(_frontend_record_evidence(facts.application_gateway_frontends, public_prefix=False))
    return evidence


def _frontend_record_evidence(records: list[dict], *, public_prefix: bool) -> list[str]:
    evidence: list[str] = []
    for record in records:
        if not isinstance(record, Mapping):
            continue
        public_ip_reference = record.get("public_ip_address_id")
        public_ip_prefix_reference = record.get("public_ip_prefix_id") if public_prefix else None
        if not public_ip_reference and not public_ip_prefix_reference:
            continue
        name = str(record.get("name") or "<unnamed>")
        if public_ip_reference:
            evidence.append(f"frontend {name} uses public_ip_address_id={public_ip_reference}")
        if public_ip_prefix_reference:
            evidence.append(f"frontend {name} uses public_ip_prefix_id={public_ip_prefix_reference}")
    return evidence


def _public_application_gateway_listeners(facts: AzureResourceFacts) -> list[dict[str, Any]]:
    public_frontend_names = {
        str(frontend.get("name"))
        for frontend in facts.application_gateway_frontends
        if isinstance(frontend, Mapping) and frontend.get("name") and frontend.get("public_ip_address_id")
    }
    if not public_frontend_names:
        return []
    return [
        dict(listener)
        for listener in facts.application_gateway_http_listeners
        if isinstance(listener, Mapping) and listener.get("frontend_ip_configuration_name") in public_frontend_names
    ]


def _listener_evidence(listeners: list[dict[str, Any]]) -> list[str]:
    evidence: list[str] = []
    for listener in listeners:
        name = listener.get("name") or "<unnamed>"
        frontend = listener.get("frontend_ip_configuration_name") or "<unknown-frontend>"
        protocol = listener.get("protocol") or "<unknown-protocol>"
        host_names = listener.get("host_names") or []
        host_values = ",".join(str(host) for host in host_names)
        host_text = f" host_names={host_values}" if host_values else ""
        evidence.append(f"listener {name} uses frontend={frontend} protocol={protocol}{host_text}")
    return evidence


def _routing_rule_evidence(facts: AzureResourceFacts, listeners: list[dict[str, Any]]) -> list[str]:
    listener_names = {str(listener.get("name")) for listener in listeners if listener.get("name")}
    if not listener_names:
        return []
    evidence: list[str] = []
    for rule in facts.application_gateway_routing_rules:
        if not isinstance(rule, Mapping) or rule.get("http_listener_name") not in listener_names:
            continue
        name = rule.get("name") or "<unnamed>"
        listener_name = rule.get("http_listener_name") or "<unknown-listener>"
        backend_pool = rule.get("backend_address_pool_name") or "<unknown-backend-pool>"
        rule_type = rule.get("rule_type") or "<unknown-rule-type>"
        evidence.append(f"routing_rule {name} type={rule_type} listener={listener_name} backend_pool={backend_pool}")
    return evidence
