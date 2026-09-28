"""Verify ALB listener and awsvpc backend traffic before public-path consumers run."""

from __future__ import annotations

import json
import re
from copy import deepcopy
from dataclasses import dataclass
from typing import Any

from tfstride.analysis.relationships import (
    RelationshipAssessment,
    RelationshipEvidenceSource,
    RelationshipKind,
    RelationshipOutcome,
    RelationshipPrerequisite,
    RelationshipReferenceResolution,
    RelationshipResourceScope,
    RelationshipTrafficScope,
)
from tfstride.models import NormalizedResource
from tfstride.providers.aws.resource_decoration.ecs import evaluate_ecs_forwarding
from tfstride.providers.aws.resource_facts import aws_facts
from tfstride.providers.aws.resource_index import AwsDecorationContext, AwsResourceIndex, resolve_aws_network_reference
from tfstride.providers.aws.security_group_traffic import (
    AwsSecurityGroupTrafficIndex,
    TrafficDecision,
    traffic_decision,
)

_INTERNET_VERSIONS: dict[str, tuple[int, ...]] = {
    "ipv4": (4,),
    "dualstack": (4, 6),
    "dualstack-without-public-ipv4": (6,),
}


@dataclass(frozen=True, slots=True)
class AwsEcsPublicIngressAssessment:
    """Typed relationship plus the provider record used by existing reports."""

    relationship: RelationshipAssessment
    _provider_record: dict[str, Any]

    def provider_record(self) -> dict[str, Any]:
        return deepcopy(self._provider_record)


class DeriveEcsPublicIngressStage:
    name = "derive_ecs_public_ingress"

    def apply(self, resources: list[NormalizedResource], context: AwsDecorationContext) -> None:
        services = [resource for resource in resources if resource.resource_type == "aws_ecs_service"]
        if not services:
            return
        traffic = AwsSecurityGroupTrafficIndex(context.index)
        for service in services:
            facts = aws_facts(service)
            assessments = evaluate_ecs_public_ingress(
                service, facts.ecs_forwarding_associations, context.index, traffic
            )
            decisions = [assessment.provider_record() for assessment in assessments]
            uncertainties = [
                reason
                for assessment in assessments
                if assessment.relationship.outcome == RelationshipOutcome.UNKNOWN
                for reason in assessment.relationship.uncertainties
            ]
            uncertainties.extend(facts.ecs_forwarding_uncertainties)
            facts.set_ecs_public_ingress(decisions, uncertainties)


def current_ecs_public_ingress(
    index: AwsResourceIndex,
) -> dict[str, tuple[AwsEcsPublicIngressAssessment, ...]]:
    """Prepare ingress once per analysis from current inputs, not cached path metadata.

    Analysis indexes describe a completed inventory snapshot. Rebuilding them also
    revalidates listener rules, bindings and SG permissions without mutating the
    independently useful workload-to-data authorization facts.
    """
    forwarding = evaluate_ecs_forwarding(index)
    if not forwarding:
        return {}
    traffic = AwsSecurityGroupTrafficIndex(index)
    return {
        service.address: tuple(
            assessment
            for assessment in evaluate_ecs_public_ingress(service, associations, index, traffic)
            if assessment.relationship.outcome == RelationshipOutcome.ESTABLISHED
        )
        for service, associations, _ in forwarding
    }


def evaluate_ecs_public_ingress(
    service: NormalizedResource,
    associations: list[dict[str, Any]],
    index: AwsResourceIndex,
    traffic: AwsSecurityGroupTrafficIndex,
) -> list[AwsEcsPublicIngressAssessment]:
    return [_evaluate_association(service, association, index, traffic) for association in associations]


def _evaluate_association(
    service: NormalizedResource,
    association: dict[str, Any],
    index: AwsResourceIndex,
    traffic: AwsSecurityGroupTrafficIndex,
) -> AwsEcsPublicIngressAssessment:
    result: dict[str, Any] = {
        **association,
        "service_address": service.address,
        "state": "unknown",
        "checks": {},
        "reasons": [],
        "evaluation_scope": "modeled_listener_container_and_security_group_permissions",
    }
    prerequisites = [
        RelationshipPrerequisite(
            name="forwarding_association",
            outcome=RelationshipOutcome.ESTABLISHED,
            evidence=_address_evidence(
                association,
                (
                    ("listener_address", "load_balancer_listener"),
                    ("action_source_address", "forwarding_action"),
                    ("target_group_address", "load_balancer_target_group"),
                ),
            ),
        )
    ]

    def finish() -> AwsEcsPublicIngressAssessment:
        return _typed_assessment(service, association, result, prerequisites, index)

    load_balancer = index.resources_by_address.get(association["load_balancer_address"])
    listener = index.resources_by_address.get(association["listener_address"])
    target = index.resources_by_address.get(association["target_group_address"])
    if load_balancer is None or listener is None or target is None:
        result["reasons"] = ["forwarding association resources are no longer resolved"]
        prerequisites.append(_unknown_prerequisite("forwarding_resources", result["reasons"]))
        return finish()
    prerequisites.append(
        RelationshipPrerequisite(
            name="forwarding_resources",
            outcome=RelationshipOutcome.ESTABLISHED,
            evidence=(
                RelationshipEvidenceSource(load_balancer.address, "load_balancer"),
                RelationshipEvidenceSource(listener.address, "load_balancer_listener"),
                RelationshipEvidenceSource(target.address, "load_balancer_target_group"),
            ),
        )
    )
    lb_facts, listener_facts, target_facts = aws_facts(load_balancer), aws_facts(listener), aws_facts(target)
    if lb_facts.load_balancer_type != "application" or not load_balancer.public_access_configured:
        result["reasons"] = ["an internet-facing application load balancer is not established"]
        prerequisites.append(_unknown_prerequisite("public_application_load_balancer", result["reasons"]))
        return finish()
    prerequisites.append(
        RelationshipPrerequisite(
            name="public_application_load_balancer",
            outcome=RelationshipOutcome.ESTABLISHED,
            evidence=(RelationshipEvidenceSource(load_balancer.address, "load_balancer"),),
        )
    )
    listener_port = listener_facts.load_balancer_listener_port
    if listener_port is None or listener_facts.load_balancer_listener_protocol not in {"HTTP", "HTTPS"}:
        result["reasons"] = [f"{listener.address}: listener protocol/port is unknown or unsupported"]
        prerequisites.append(_unknown_prerequisite("supported_listener", result["reasons"]))
        return finish()
    prerequisites.append(
        RelationshipPrerequisite(
            name="supported_listener",
            outcome=RelationshipOutcome.ESTABLISHED,
            evidence=(RelationshipEvidenceSource(listener.address, "load_balancer_listener"),),
        )
    )
    versions = _INTERNET_VERSIONS.get(lb_facts.load_balancer_ip_address_type or "")
    if versions is None:
        result["reasons"] = [f"{load_balancer.address}: public IP address family is unknown or unsupported"]
        prerequisites.append(_unknown_prerequisite("public_address_family", result["reasons"]))
        return finish()
    prerequisites.append(
        RelationshipPrerequisite(
            name="public_address_family",
            outcome=RelationshipOutcome.ESTABLISHED,
            evidence=(RelationshipEvidenceSource(load_balancer.address, "load_balancer"),),
        )
    )
    backend_port = association["container_port"]
    mapping = _container_binding(service, association, index)
    if (
        target_facts.load_balancer_target_type != "ip"
        or target_facts.load_balancer_target_protocol not in {"HTTP", "HTTPS"}
        or target_facts.load_balancer_target_ip_address_type != "ipv4"
    ):
        mapping = traffic_decision("unknown", f"{target.address}: an HTTP/HTTPS IPv4 IP target is not established")
    checks: dict[str, TrafficDecision] = {
        "container_binding": mapping,
        "listener_ingress": traffic.permission(load_balancer, "ingress", listener_port, internet_versions=versions),
        "load_balancer_egress": traffic.permission(load_balancer, "egress", backend_port, peer=service),
        "service_ingress": traffic.permission(service, "ingress", backend_port, peer=load_balancer),
    }
    # Backend permissions are evaluated at the ECS registration port, which can
    # differ both from the listener port and the target group's default port.
    result.update(
        listener_port=listener_port,
        listener_protocol=listener_facts.load_balancer_listener_protocol,
        backend_port=backend_port,
        backend_protocol=target_facts.load_balancer_target_protocol,
        transport_protocol="tcp",
        checks=checks,
    )
    if mapping["state"] != "allowed":
        result["state"] = "unknown"
    elif any(check["state"] == "blocked" for check in checks.values()):
        result["state"] = "blocked"
    elif all(check["state"] == "allowed" for check in checks.values()):
        result["state"] = "allowed"
    result["reasons"] = sorted({f"{name}: {reason}" for name, check in checks.items() for reason in check["reasons"]})
    prerequisites.extend(
        RelationshipPrerequisite(
            name=name,
            outcome=_relationship_outcome(check["state"]),
            evidence=_traffic_evidence(name, check),
            uncertainties=tuple(check["reasons"]) if check["state"] == "unknown" else (),
        )
        for name, check in checks.items()
    )
    return finish()


def _typed_assessment(
    service: NormalizedResource,
    association: dict[str, Any],
    result: dict[str, Any],
    prerequisites: list[RelationshipPrerequisite],
    index: AwsResourceIndex,
) -> AwsEcsPublicIngressAssessment:
    state = result["state"]
    evidence = _relationship_evidence(service, association, result)
    resource_addresses = tuple(sorted({item.address for item in evidence if item.address != "internet"}))
    traffic_scope: tuple[RelationshipTrafficScope, ...] = ()
    listener_port = result.get("listener_port")
    backend_port = result.get("backend_port")
    if type(listener_port) is int and type(backend_port) is int:
        listener_source_cidrs = tuple(
            sorted(
                {
                    proof["cidr"]
                    for proof in result["checks"]["listener_ingress"]["evidence"]
                    if isinstance(proof.get("cidr"), str)
                }
            )
        )
        traffic_scope = (
            RelationshipTrafficScope(
                name="internet_to_load_balancer",
                transport_protocol="tcp",
                application_protocol=result.get("listener_protocol"),
                from_port=listener_port,
                to_port=listener_port,
                source_addresses=("internet",),
                source_cidrs=listener_source_cidrs,
            ),
            RelationshipTrafficScope(
                name="load_balancer_to_service",
                transport_protocol="tcp",
                application_protocol=result.get("backend_protocol"),
                from_port=backend_port,
                to_port=backend_port,
                source_addresses=(association["load_balancer_address"],),
            ),
        )
    conditions = _remaining_conditions(association)
    uncertainties = tuple(result["reasons"]) if state == "unknown" else ()
    relationship = RelationshipAssessment(
        source_address="internet",
        target_address=service.address,
        kind=RelationshipKind.EFFECTIVE_INGRESS,
        operation="accept_public_request",
        outcome=_relationship_outcome(state),
        traffic_scope=traffic_scope,
        resource_scope=RelationshipResourceScope(
            resource_addresses=resource_addresses,
            selectors=(
                f"container={association.get('container_name')}",
                f"container_port={association.get('container_port')}",
            ),
        ),
        evidence_sources=evidence,
        reference_resolutions=_reference_resolution_evidence(service, association, result, index),
        prerequisites=tuple(prerequisites),
        remaining_conditions=conditions,
        uncertainties=uncertainties,
    )
    return AwsEcsPublicIngressAssessment(relationship=relationship, _provider_record=deepcopy(result))


def _relationship_outcome(state: str) -> RelationshipOutcome:
    if state == "allowed":
        return RelationshipOutcome.ESTABLISHED
    if state == "blocked":
        return RelationshipOutcome.NOT_ESTABLISHED
    return RelationshipOutcome.UNKNOWN


def _unknown_prerequisite(name: str, reasons: list[str]) -> RelationshipPrerequisite:
    return RelationshipPrerequisite(
        name=name,
        outcome=RelationshipOutcome.UNKNOWN,
        uncertainties=tuple(reasons),
    )


def _address_evidence(
    values: dict[str, Any], fields: tuple[tuple[str, str], ...]
) -> tuple[RelationshipEvidenceSource, ...]:
    return tuple(
        RelationshipEvidenceSource(address, evidence_type)
        for key, evidence_type in fields
        if isinstance((address := values.get(key)), str) and address
    )


def _traffic_evidence(name: str, decision: TrafficDecision) -> tuple[RelationshipEvidenceSource, ...]:
    evidence: set[RelationshipEvidenceSource] = set()
    for proof in decision["evidence"]:
        for key, evidence_type in (
            ("task_definition_address", "ecs_task_definition"),
            ("security_group_address", "security_group"),
            ("rule_source_address", "security_group_rule"),
        ):
            address = proof.get(key)
            if isinstance(address, str) and address:
                evidence.add(RelationshipEvidenceSource(address, evidence_type, name))
        for address in proof.get("peer_security_group_addresses", []):
            if isinstance(address, str) and address:
                evidence.add(RelationshipEvidenceSource(address, "peer_security_group", name))
    return tuple(sorted(evidence, key=_evidence_sort_key))


def _relationship_evidence(
    service: NormalizedResource,
    association: dict[str, Any],
    result: dict[str, Any],
) -> tuple[RelationshipEvidenceSource, ...]:
    evidence = {
        RelationshipEvidenceSource(service.address, "ecs_service"),
        *_address_evidence(
            association,
            (
                ("load_balancer_address", "load_balancer"),
                ("listener_address", "load_balancer_listener"),
                ("action_source_address", "forwarding_action"),
                ("target_group_address", "load_balancer_target_group"),
            ),
        ),
    }
    for name, check in result.get("checks", {}).items():
        evidence.update(_traffic_evidence(name, check))
    return tuple(sorted(evidence, key=_evidence_sort_key))


def _evidence_sort_key(evidence: RelationshipEvidenceSource) -> tuple[str, str, str]:
    return (evidence.address, evidence.evidence_type, evidence.detail or "")


def _remaining_conditions(association: dict[str, Any]) -> tuple[str, ...]:
    conditions: list[str] = []
    if association.get("conditions"):
        conditions.append(f"listener_conditions={_compact_json(association['conditions'])}")
    if association.get("authentication_actions"):
        conditions.append(f"authentication_actions={_compact_json(association['authentication_actions'])}")
    return tuple(conditions)


def _compact_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


def _reference_resolution_evidence(
    service: NormalizedResource,
    association: dict[str, Any],
    result: dict[str, Any],
    index: AwsResourceIndex,
) -> tuple[RelationshipReferenceResolution, ...]:
    pairs: set[tuple[str, str]] = set()

    def add_pair(source_address: object, target_address: object) -> None:
        if isinstance(source_address, str) and isinstance(target_address, str):
            if source_address in index.resources_by_address and target_address in index.resources_by_address:
                pairs.add((source_address, target_address))

    add_pair(association.get("listener_address"), association.get("load_balancer_address"))
    if association.get("action_source_address") != association.get("listener_address"):
        add_pair(association.get("action_source_address"), association.get("listener_address"))
    add_pair(association.get("action_source_address"), association.get("target_group_address"))
    add_pair(service.address, association.get("target_group_address"))
    for name, check in result.get("checks", {}).items():
        for proof in check["evidence"]:
            task_address = proof.get("task_definition_address")
            add_pair(service.address, task_address)
            group_address = proof.get("security_group_address")
            if name in {"listener_ingress", "load_balancer_egress"}:
                add_pair(association.get("load_balancer_address"), group_address)
            elif name == "service_ingress":
                add_pair(service.address, group_address)
            for peer_address in proof.get("peer_security_group_addresses", []):
                add_pair(proof.get("rule_source_address"), peer_address)

    records: list[RelationshipReferenceResolution] = []
    for source_address, target_address in sorted(pairs):
        source = index.resources_by_address[source_address]
        matching = [
            resolution
            for resolution in source.reference_resolutions
            if target_address in {target.address for target in resolution.targets}
        ]
        records.extend(
            RelationshipReferenceResolution(
                source_address=source_address,
                target_addresses=tuple(sorted({target.address for target in resolution.targets})),
                expression_path=resolution.path,
                state=resolution.state,
                provenance=resolution.provenance,
                references=resolution.references,
                reason=resolution.reason,
            )
            for resolution in matching
        )
    return tuple(
        sorted(
            records,
            key=lambda item: (
                item.source_address,
                item.expression_path,
                item.target_addresses,
                item.state.value,
            ),
        )
    )


def _container_binding(
    service: NormalizedResource, association: dict[str, Any], index: AwsResourceIndex
) -> TrafficDecision:
    reference = aws_facts(service).task_definition_reference
    task = resolve_aws_network_reference(index.ecs_task_definitions, reference, service)
    if task is None:
        return traffic_decision("unknown", "task definition is unresolved or ambiguous")
    inputs = aws_facts(task).ecs_container_network
    if inputs.get("network_mode") != "awsvpc":
        return traffic_decision("unknown", f"{task.address}: awsvpc network mode is not established")
    if inputs.get("uncertainties"):
        return traffic_decision("unknown", *inputs["uncertainties"])
    containers = inputs.get("containers", [])
    matching = [container for container in containers if container["name"] == association["container_name"]]
    if len(matching) != 1 or any(container["name"] is None for container in containers):
        return traffic_decision("unknown", f"{task.address}: the bound container name is absent, unknown, or ambiguous")
    port = association["container_port"]
    for mapping in matching[0]["port_mappings"]:
        if mapping["protocol"] != "tcp":
            continue
        if not mapping["host_port_omitted"] and mapping["host_port"] != port:
            continue
        if (mapping["container_range_omitted"] and mapping["container_port"] == port) or (
            mapping["container_port_omitted"] and _port_in_range(port, mapping["container_port_range"])
        ):
            return traffic_decision(
                "allowed",
                evidence=[
                    {
                        "task_definition_address": task.address,
                        "container_name": association["container_name"],
                        "container_port": port,
                        "network_mode": "awsvpc",
                        "protocol": "tcp",
                    }
                ],
            )
    return traffic_decision("unknown", f"{task.address}: TCP port {port} has no established awsvpc container mapping")


def _port_in_range(port: int, value: str | None) -> bool:
    if value is None or re.fullmatch(r"[0-9]+-[0-9]+", value) is None:
        return False
    start, end = (int(part) for part in value.split("-"))
    return 1 <= start <= port <= end <= 65535
