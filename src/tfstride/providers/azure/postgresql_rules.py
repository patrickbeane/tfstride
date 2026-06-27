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

_BROAD_IP_RANGES = frozenset(
    {
        ("0.0.0.0", "255.255.255.255"),
    }
)


class AzurePostgresqlRuleDetectors:
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
        for server in context.inventory.by_type(AzureResourceType.POSTGRESQL_FLEXIBLE_SERVER):
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
                        "The PostgreSQL Flexible Server public endpoint is enabled. Access is governed by "
                        "firewall and network rules, but the server is not restricted to private or "
                        "VNet-only access."
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
        for rule in context.inventory.by_type(AzureResourceType.POSTGRESQL_FLEXIBLE_SERVER_FIREWALL_RULE):
            facts = azure_facts(rule)
            start_ip = facts.postgresql_firewall_start_ip
            end_ip = facts.postgresql_firewall_end_ip
            if not start_ip or not end_ip:
                continue
            if (start_ip.strip(), end_ip.strip()) not in _BROAD_IP_RANGES:
                continue
            server_id = facts.postgresql_server_id
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
                        "which is a broad public IP range. This firewall rule permits a broad public IP range "
                        "for the referenced PostgreSQL Flexible Server when public endpoint access is enabled."
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

    def detect_weak_tls_or_ssl(
        self,
        context: RuleEvaluationContext,
        rule_id: str,
    ) -> list[Finding]:
        if context.inventory.provider != "azure":
            return []

        findings: list[Finding] = []
        configs_by_server = _configs_by_server(context.inventory)
        for server in context.inventory.by_type(AzureResourceType.POSTGRESQL_FLEXIBLE_SERVER):
            facts = azure_facts(server)
            evidence_parts: list[str] = []
            weak = False

            server_configs = configs_by_server.get(facts.postgresql_server_id, {})
            ssl_version = server_configs.get("ssl_min_protocol_version")
            if ssl_version is not None and _ssl_version_is_weak(ssl_version):
                weak = True
                evidence_parts.append(f"ssl_min_protocol_version is {ssl_version}")

            require_secure = server_configs.get("require_secure_transport")
            if require_secure is not None:
                if require_secure.strip().lower() in {"0", "off", "disabled", "false"}:
                    weak = True
                    evidence_parts.append(f"require_secure_transport is {require_secure}")

            if not weak:
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
                        f"{server.display_name} has a weak TLS or SSL posture. "
                        "Deprecated TLS versions or disabled secure transport weaken "
                        "transport protection for PostgreSQL data-plane requests."
                    ),
                    evidence=collect_evidence(
                        evidence_item("transport_posture", evidence_parts),
                    ),
                    severity_reasoning=severity_reasoning,
                )
            )
        return findings

    def detect_geo_backup_disabled(
        self,
        context: RuleEvaluationContext,
        rule_id: str,
    ) -> list[Finding]:
        if context.inventory.provider != "azure":
            return []

        findings: list[Finding] = []
        for server in context.inventory.by_type(AzureResourceType.POSTGRESQL_FLEXIBLE_SERVER):
            facts = azure_facts(server)
            if facts.postgresql_geo_redundant_backup_enabled is not False:
                continue
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
                    affected_resources=[server.address],
                    trust_boundary_id=None,
                    rationale=(
                        f"{server.display_name} has geo-redundant backup disabled. "
                        "Without geo-redundancy, a regional outage could cause data loss."
                    ),
                    evidence=collect_evidence(
                        evidence_item("backup_posture", ["geo_redundant_backup_enabled is false"]),
                    ),
                    severity_reasoning=severity_reasoning,
                )
            )
        return findings


def _servers_by_id(inventory) -> dict[str, str]:
    servers: dict[str, str] = {}
    for server in inventory.by_type(AzureResourceType.POSTGRESQL_FLEXIBLE_SERVER):
        facts = azure_facts(server)
        server_id = facts.postgresql_server_id
        if server_id:
            servers[server_id] = server.address
    return servers


def _configs_by_server(inventory) -> dict[str, dict[str, str]]:
    configs: dict[str, dict[str, str]] = {}
    for config in inventory.by_type(AzureResourceType.POSTGRESQL_FLEXIBLE_SERVER_CONFIGURATION):
        facts = azure_facts(config)
        server_id = facts.postgresql_config_server_id
        name = facts.postgresql_config_name
        value = facts.postgresql_config_value
        if server_id and name:
            configs.setdefault(server_id, {})[name] = value or ""
    return configs


def _ssl_version_is_weak(value: str | None) -> bool:
    if value is None:
        return False
    normalized = value.strip().lower().replace(".", "_")
    return normalized in {"tls1_0", "tls1_1", "1_0", "1_1", "tlsv1", "tlsv1_0", "tlsv1_1"}
