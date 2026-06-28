from __future__ import annotations

from typing import Any

from tfstride.analysis.finding_factory import FindingFactory
from tfstride.analysis.finding_helpers import (
    build_severity_reasoning,
    collect_evidence,
    dedupe_addresses,
    evidence_item,
)
from tfstride.analysis.rule_definitions import RuleEvaluationContext
from tfstride.models import BoundaryType, Finding
from tfstride.providers.azure.resource_decoration.public_exposure import is_risky_public_compute_path
from tfstride.providers.azure.resource_facts import azure_facts
from tfstride.providers.azure.resource_types import AZURE_COMPUTE_RESOURCE_TYPES


class AzureComputeRuleDetectors:
    def __init__(self, finding_factory: FindingFactory) -> None:
        self._finding_factory = finding_factory

    def detect_public_compute_broad_ingress(
        self,
        context: RuleEvaluationContext,
        rule_id: str,
    ) -> list[Finding]:
        if context.inventory.provider != "azure":
            return []

        findings: list[Finding] = []
        for virtual_machine in context.inventory.by_type(*AZURE_COMPUTE_RESOURCE_TYPES):
            facts = azure_facts(virtual_machine)
            risky_paths = [path for path in facts.public_compute_exposure_paths if is_risky_public_compute_path(path)]
            if not virtual_machine.public_exposure or not risky_paths:
                continue
            boundary = context.boundary_index.get(
                (BoundaryType.INTERNET_TO_SERVICE, "internet", virtual_machine.address)
            )
            severity_reasoning = build_severity_reasoning(
                internet_exposure=True,
                privilege_breadth=0,
                data_sensitivity=0,
                lateral_movement=1,
                blast_radius=1,
            )
            network_interfaces = _path_values(risky_paths, "network_interfaces")
            public_ip_resources = _path_values(risky_paths, "public_ip_resources")
            public_ips = _path_values(risky_paths, "public_ips")
            network_security_groups = _path_values(risky_paths, "network_security_groups")
            network_security_rules = _path_values(risky_paths, "network_security_rules")
            findings.append(
                self._finding_factory.build(
                    rule_id=rule_id,
                    severity=severity_reasoning.severity,
                    affected_resources=dedupe_addresses(
                        [
                            virtual_machine.address,
                            *network_interfaces,
                            *public_ip_resources,
                            *network_security_groups,
                        ]
                    ),
                    trust_boundary_id=boundary.identifier if boundary else None,
                    rationale=(
                        f"{virtual_machine.display_name} has a public-IP path and the effective Azure NSG "
                        "decisions across its subnet and network interface permit administrative access or "
                        "all ports from internet sources. This exposes the guest to direct probing and "
                        "credential attacks."
                    ),
                    evidence=collect_evidence(
                        evidence_item(
                            "public_ip_path",
                            _public_ip_path_evidence(virtual_machine.address, network_interfaces, public_ips),
                        ),
                        evidence_item(
                            "network_security_path",
                            _network_security_path_evidence(
                                virtual_machine.address,
                                network_interfaces,
                                network_security_groups,
                            ),
                        ),
                        evidence_item("network_security_rules", network_security_rules),
                        evidence_item("public_exposure_reasons", virtual_machine.public_exposure_reasons),
                    ),
                    severity_reasoning=severity_reasoning,
                )
            )
        return findings


def _path_values(paths: list[dict[str, Any]], key: str) -> list[str]:
    values: list[str] = []
    seen: set[str] = set()
    for path in paths:
        for value in path.get(key, []):
            text = str(value)
            if not text or text in seen:
                continue
            seen.add(text)
            values.append(text)
    return values


def _public_ip_path_evidence(
    virtual_machine_address: str,
    network_interfaces: list[str],
    public_ips: list[str],
) -> list[str]:
    if not public_ips:
        return []
    nic_text = ", ".join(network_interfaces) if network_interfaces else "exported VM public IP"
    return [f"{virtual_machine_address} -> {nic_text} -> {public_ip}" for public_ip in public_ips]


def _network_security_path_evidence(
    virtual_machine_address: str,
    network_interfaces: list[str],
    network_security_groups: list[str],
) -> list[str]:
    if not network_security_groups:
        return []
    nic_text = ", ".join(network_interfaces) if network_interfaces else "virtual machine network path"
    return [
        f"{virtual_machine_address} -> {nic_text} -> {network_security_group}"
        for network_security_group in network_security_groups
    ]
