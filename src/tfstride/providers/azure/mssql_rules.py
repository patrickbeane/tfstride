from __future__ import annotations

from tfstride.analysis.finding_factory import FindingFactory
from tfstride.analysis.finding_helpers import (
    build_severity_reasoning,
    collect_evidence,
    dedupe_addresses,
    evidence_item,
)
from tfstride.analysis.rule_definitions import RuleEvaluationContext
from tfstride.models import Finding
from tfstride.providers.azure.resource_facts import azure_facts
from tfstride.providers.azure.resource_types import AzureResourceType
from tfstride.providers.azure.resource_utils import tls_version_below_1_2

_BROAD_IP_RANGES = frozenset(
    {
        ("0.0.0.0", "255.255.255.255"),
    }
)
_ALERT_DISABLED = "disabled"


class AzureMssqlRuleDetectors:
    def __init__(self, finding_factory: FindingFactory) -> None:
        self._finding_factory = finding_factory

    def detect_public_network_access_enabled(
        self,
        context: RuleEvaluationContext,
        rule_id: str,
    ) -> list[Finding]:
        if context.inventory.provider != "azure":
            return []

        findings: list[Finding] = []
        for server in context.inventory.by_type(AzureResourceType.MSSQL_SERVER):
            facts = azure_facts(server)
            if facts.public_network_access_enabled is not True:
                continue
            severity_reasoning = build_severity_reasoning(
                internet_exposure=True,
                privilege_breadth=0,
                data_sensitivity=2,
                lateral_movement=0,
                blast_radius=1,
            )
            findings.append(
                self._finding_factory.build(
                    rule_id=rule_id,
                    severity=severity_reasoning.severity,
                    affected_resources=[server.address],
                    trust_boundary_id=None,
                    rationale=(
                        f"{server.display_name} has public network access enabled. "
                        "The SQL Database public endpoint is enabled. Access is governed by firewall and "
                        "network rules, but the server is not restricted to private or VNet-only access."
                    ),
                    evidence=collect_evidence(
                        evidence_item(
                            "network_posture",
                            ["public_network_access_enabled is true"],
                        ),
                    ),
                    severity_reasoning=severity_reasoning,
                )
            )
        return findings

    def detect_broad_firewall_access(
        self,
        context: RuleEvaluationContext,
        rule_id: str,
    ) -> list[Finding]:
        if context.inventory.provider != "azure":
            return []

        findings: list[Finding] = []
        servers_by_id = _servers_by_id(context.inventory)
        for rule in context.inventory.by_type(AzureResourceType.MSSQL_FIREWALL_RULE):
            facts = azure_facts(rule)
            start_ip = facts.mssql_firewall_start_ip
            end_ip = facts.mssql_firewall_end_ip
            if not start_ip or not end_ip:
                continue
            if (start_ip.strip(), end_ip.strip()) not in _BROAD_IP_RANGES:
                continue
            server_id = facts.mssql_server_id
            server_address = servers_by_id.get(server_id)
            affected = dedupe_addresses([server_address, rule.address] if server_address else [rule.address])
            severity_reasoning = build_severity_reasoning(
                internet_exposure=True,
                privilege_breadth=0,
                data_sensitivity=2,
                lateral_movement=0,
                blast_radius=1,
            )
            findings.append(
                self._finding_factory.build(
                    rule_id=rule_id,
                    severity=severity_reasoning.severity,
                    affected_resources=affected,
                    trust_boundary_id=None,
                    rationale=(
                        f"{rule.display_name} allows access from {start_ip} to {end_ip}, "
                        "which is a broad public IP range. Any internet client can reach the "
                        "associated SQL Database server."
                    ),
                    evidence=collect_evidence(
                        evidence_item(
                            "firewall_rule",
                            [
                                f"start_ip_address is {start_ip}",
                                f"end_ip_address is {end_ip}",
                                f"server_id is {server_id}",
                            ],
                        ),
                    ),
                    severity_reasoning=severity_reasoning,
                )
            )
        return findings

    def detect_minimum_tls_below_1_2(
        self,
        context: RuleEvaluationContext,
        rule_id: str,
    ) -> list[Finding]:
        if context.inventory.provider != "azure":
            return []

        findings: list[Finding] = []
        for server in context.inventory.by_type(AzureResourceType.MSSQL_SERVER):
            facts = azure_facts(server)
            tls_version = facts.min_tls_version
            if not tls_version_below_1_2(tls_version):
                continue
            severity_reasoning = build_severity_reasoning(
                internet_exposure=server.direct_internet_reachable,
                privilege_breadth=0,
                data_sensitivity=2,
                lateral_movement=0,
                blast_radius=1,
            )
            findings.append(
                self._finding_factory.build(
                    rule_id=rule_id,
                    severity=severity_reasoning.severity,
                    affected_resources=[server.address],
                    trust_boundary_id=None,
                    rationale=(
                        f"{server.display_name} sets minimum TLS version to `{tls_version}`. "
                        "Deprecated TLS versions weaken transport protection for SQL data-plane requests."
                    ),
                    evidence=collect_evidence(
                        evidence_item("transport_posture", [f"minimum_tls_version is {tls_version}"]),
                    ),
                    severity_reasoning=severity_reasoning,
                )
            )
        return findings

    def detect_security_alert_policy_disabled(
        self,
        context: RuleEvaluationContext,
        rule_id: str,
    ) -> list[Finding]:
        if context.inventory.provider != "azure":
            return []

        findings: list[Finding] = []
        servers_by_id = _servers_by_id(context.inventory)
        for policy in context.inventory.by_type(AzureResourceType.MSSQL_SERVER_SECURITY_ALERT_POLICY):
            facts = azure_facts(policy)
            state = facts.mssql_security_alert_state
            if state is None or state.strip().lower() != _ALERT_DISABLED:
                continue
            server_id = facts.mssql_server_id
            server_address = servers_by_id.get(server_id)
            affected = dedupe_addresses([server_address, policy.address] if server_address else [policy.address])
            severity_reasoning = build_severity_reasoning(
                internet_exposure=False,
                privilege_breadth=0,
                data_sensitivity=2,
                lateral_movement=0,
                blast_radius=1,
            )
            findings.append(
                self._finding_factory.build(
                    rule_id=rule_id,
                    severity=severity_reasoning.severity,
                    affected_resources=affected,
                    trust_boundary_id=None,
                    rationale=(
                        f"{policy.display_name} has security alerting disabled. "
                        "Threat detection and SQL injection alerts will not be generated."
                    ),
                    evidence=collect_evidence(
                        evidence_item("alert_posture", [f"state is {state}"]),
                    ),
                    severity_reasoning=severity_reasoning,
                )
            )
        return findings


def _servers_by_id(inventory) -> dict[str, str]:
    servers: dict[str, str] = {}
    for server in inventory.by_type(AzureResourceType.MSSQL_SERVER):
        facts = azure_facts(server)
        server_id = facts.mssql_server_id
        if server_id:
            servers[server_id] = server.address
    return servers
