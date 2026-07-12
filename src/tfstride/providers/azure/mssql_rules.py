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
from tfstride.providers.coercion import STATE_DISABLED

_BROAD_IP_RANGES = frozenset(
    {
        ("0.0.0.0", "255.255.255.255"),
    }
)
_ALERT_DISABLED = STATE_DISABLED
_MIN_SQL_BACKUP_RETENTION_DAYS = 7
_GEO_REDUNDANT_BACKUP_STORAGE_TYPES = frozenset({"geo", "geozone", "grs", "gzrs"})
_LOCAL_BACKUP_STORAGE_TYPES = frozenset({"local", "zone", "lrs", "zrs"})
_DISABLED_RETENTION_VALUES = frozenset({"pt0s", "p0d", "p0w", "p0m", "p0y"})


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

    def detect_short_term_backup_retention_insufficient(
        self,
        context: RuleEvaluationContext,
        rule_id: str,
    ) -> list[Finding]:
        if context.inventory.provider != "azure":
            return []

        findings: list[Finding] = []
        for database in context.inventory.by_type(AzureResourceType.MSSQL_DATABASE):
            facts = azure_facts(database)
            retention_days = facts.mssql_short_term_retention_days
            unknown = _mssql_field_unknown(facts, "short_term_retention_policy.retention_days")
            if retention_days is not None and retention_days >= _MIN_SQL_BACKUP_RETENTION_DAYS:
                continue
            severity_reasoning = build_severity_reasoning(
                internet_exposure=False,
                privilege_breadth=0,
                data_sensitivity=1 if unknown else 2,
                lateral_movement=0,
                blast_radius=0 if unknown else 1,
            )
            findings.append(
                self._finding_factory.build(
                    rule_id=rule_id,
                    severity=severity_reasoning.severity,
                    affected_resources=[database.address],
                    trust_boundary_id=None,
                    rationale=_short_term_retention_rationale(database.display_name, retention_days, unknown=unknown),
                    evidence=collect_evidence(
                        evidence_item("target_resource", _mssql_database_target_evidence(database, facts)),
                        evidence_item(
                            "short_term_backup_posture",
                            _short_term_retention_evidence(facts, retention_days, unknown=unknown),
                        ),
                        evidence_item(
                            "posture_uncertainty",
                            _mssql_uncertainty_evidence(facts, "short_term_retention_policy"),
                        ),
                    ),
                    severity_reasoning=severity_reasoning,
                )
            )
        return findings

    def detect_long_term_backup_retention_not_configured(
        self,
        context: RuleEvaluationContext,
        rule_id: str,
    ) -> list[Finding]:
        if context.inventory.provider != "azure":
            return []

        findings: list[Finding] = []
        for database in context.inventory.by_type(AzureResourceType.MSSQL_DATABASE):
            facts = azure_facts(database)
            unknown = _mssql_field_unknown(facts, "long_term_retention_policy")
            if _has_meaningful_long_term_retention(facts):
                continue
            severity_reasoning = build_severity_reasoning(
                internet_exposure=False,
                privilege_breadth=0,
                data_sensitivity=1 if unknown else 2,
                lateral_movement=0,
                blast_radius=0 if unknown else 1,
            )
            findings.append(
                self._finding_factory.build(
                    rule_id=rule_id,
                    severity=severity_reasoning.severity,
                    affected_resources=[database.address],
                    trust_boundary_id=None,
                    rationale=(
                        f"{database.display_name} does not have deterministic long-term backup retention "
                        "configured. Without long-term retention, recovery from delayed destructive changes or "
                        "compliance-driven restore needs may be limited."
                    ),
                    evidence=collect_evidence(
                        evidence_item("target_resource", _mssql_database_target_evidence(database, facts)),
                        evidence_item(
                            "long_term_backup_posture", _long_term_retention_evidence(facts, unknown=unknown)
                        ),
                        evidence_item(
                            "posture_uncertainty",
                            _mssql_uncertainty_evidence(facts, "long_term_retention_policy"),
                        ),
                    ),
                    severity_reasoning=severity_reasoning,
                )
            )
        return findings

    def detect_backup_geo_redundancy_not_enabled(
        self,
        context: RuleEvaluationContext,
        rule_id: str,
    ) -> list[Finding]:
        if context.inventory.provider != "azure":
            return []

        findings: list[Finding] = []
        for database in context.inventory.by_type(AzureResourceType.MSSQL_DATABASE):
            facts = azure_facts(database)
            if not _mssql_geo_redundancy_reportable(facts):
                continue
            unknown = _mssql_field_unknown(facts, "geo_backup_enabled") or _mssql_field_unknown(
                facts, "storage_account_type"
            )
            severity_reasoning = build_severity_reasoning(
                internet_exposure=False,
                privilege_breadth=0,
                data_sensitivity=1 if unknown else 2,
                lateral_movement=0,
                blast_radius=0 if unknown else 1,
            )
            findings.append(
                self._finding_factory.build(
                    rule_id=rule_id,
                    severity=severity_reasoning.severity,
                    affected_resources=[database.address],
                    trust_boundary_id=None,
                    rationale=(
                        f"{database.display_name} does not have deterministic geo-redundant backup posture. "
                        "Local or unavailable backup redundancy can limit recovery options during regional "
                        "failures."
                    ),
                    evidence=collect_evidence(
                        evidence_item("target_resource", _mssql_database_target_evidence(database, facts)),
                        evidence_item("backup_redundancy_posture", _backup_redundancy_evidence(facts)),
                        evidence_item("posture_uncertainty", _mssql_geo_uncertainty_evidence(facts)),
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


def _mssql_database_target_evidence(database, facts) -> list[str]:
    values = [f"address={database.address}", f"type={database.resource_type}"]
    if facts.mssql_database_id:
        values.append(f"database_id={facts.mssql_database_id}")
    if facts.mssql_server_id:
        values.append(f"server_id={facts.mssql_server_id}")
    return values


def _short_term_retention_evidence(facts, retention_days: int | None, *, unknown: bool) -> list[str]:
    if unknown:
        state = "unknown"
    elif retention_days is None:
        state = facts.mssql_short_term_retention_state or "not_configured"
    elif retention_days < _MIN_SQL_BACKUP_RETENTION_DAYS:
        state = "short"
    else:
        state = "configured"
    values = [
        f"short_term_retention_policy.retention_days_state={state}",
        f"minimum_retention_days={_MIN_SQL_BACKUP_RETENTION_DAYS}",
    ]
    if retention_days is not None:
        values.insert(1, f"retention_days={retention_days}")
    if facts.mssql_backup_interval_hours is not None:
        values.append(f"backup_interval_in_hours={facts.mssql_backup_interval_hours}")
    return values


def _long_term_retention_evidence(facts, *, unknown: bool) -> list[str]:
    state = "unknown" if unknown else facts.mssql_long_term_retention_state or "not_configured"
    if _has_meaningful_long_term_retention(facts):
        state = "configured"
    elif state == "configured":
        state = "disabled_or_missing"
    values = [f"long_term_retention_policy_state={state}"]
    if facts.mssql_long_term_weekly_retention:
        values.append(f"weekly_retention={facts.mssql_long_term_weekly_retention}")
    if facts.mssql_long_term_monthly_retention:
        values.append(f"monthly_retention={facts.mssql_long_term_monthly_retention}")
    if facts.mssql_long_term_yearly_retention:
        values.append(f"yearly_retention={facts.mssql_long_term_yearly_retention}")
    if facts.mssql_long_term_week_of_year is not None:
        values.append(f"week_of_year={facts.mssql_long_term_week_of_year}")
    return values


def _backup_redundancy_evidence(facts) -> list[str]:
    values = [f"geo_backup_state={facts.mssql_geo_backup_state or 'unknown'}"]
    storage_type = facts.mssql_backup_storage_redundancy
    if storage_type:
        values.append(f"storage_account_type={storage_type}")
        values.append(f"backup_storage_redundancy_state={_backup_storage_redundancy_state(storage_type)}")
    else:
        values.append("storage_account_type is unset")
    return values


def _mssql_geo_redundancy_reportable(facts) -> bool:
    storage_type = facts.mssql_backup_storage_redundancy
    if storage_type is not None:
        return _backup_storage_redundancy_state(storage_type) != "geo_redundant"
    if facts.mssql_geo_backup_state == STATE_DISABLED:
        return True
    return bool(_mssql_geo_uncertainty_evidence(facts))


def _backup_storage_redundancy_state(storage_type: str) -> str:
    normalized = storage_type.strip().lower()
    if normalized in _GEO_REDUNDANT_BACKUP_STORAGE_TYPES:
        return "geo_redundant"
    if normalized in _LOCAL_BACKUP_STORAGE_TYPES:
        return "local_or_zone_redundant"
    return "unknown"


def _has_meaningful_long_term_retention(facts) -> bool:
    return any(
        _retention_duration_enabled(value)
        for value in (
            facts.mssql_long_term_weekly_retention,
            facts.mssql_long_term_monthly_retention,
            facts.mssql_long_term_yearly_retention,
        )
    )


def _retention_duration_enabled(value: str | None) -> bool:
    if value is None:
        return False
    normalized = value.strip().lower()
    return bool(normalized) and normalized not in _DISABLED_RETENTION_VALUES


def _mssql_uncertainty_evidence(facts, field_path: str) -> list[str]:
    return [uncertainty for uncertainty in facts.mssql_posture_uncertainties if field_path in uncertainty]


def _mssql_geo_uncertainty_evidence(facts) -> list[str]:
    return [
        uncertainty
        for uncertainty in facts.mssql_posture_uncertainties
        if "geo_backup_enabled" in uncertainty or "storage_account_type" in uncertainty
    ]


def _mssql_field_unknown(facts, field_path: str) -> bool:
    return bool(_mssql_uncertainty_evidence(facts, field_path))


def _short_term_retention_rationale(display_name: str, retention_days: int | None, *, unknown: bool) -> str:
    if unknown:
        return (
            f"{display_name} has unknown Azure SQL short-term backup retention after planning. "
            "tfSTRIDE cannot verify that the database meets the minimum recovery retention baseline."
        )
    if retention_days is None:
        return (
            f"{display_name} does not show deterministic Azure SQL short-term backup retention in the "
            "Terraform plan. Missing retention evidence can hide recovery posture gaps for destructive changes."
        )
    return (
        f"{display_name} keeps short-term SQL backups for {retention_days} days, below the "
        f"{_MIN_SQL_BACKUP_RETENTION_DAYS}-day baseline used by tfSTRIDE. Short retention can limit recovery "
        "after delayed detection of destructive changes."
    )
