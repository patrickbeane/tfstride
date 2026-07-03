from __future__ import annotations

from tfstride.analysis.finding_factory import FindingFactory
from tfstride.analysis.finding_helpers import (
    build_severity_reasoning,
    collect_evidence,
    evidence_item,
)
from tfstride.analysis.rule_definitions import RuleEvaluationContext
from tfstride.models import Finding
from tfstride.providers.gcp.private_connectivity_index import (
    GcpPrivateConnectivityCoverage,
    GcpPrivateConnectivityIndex,
    build_gcp_private_connectivity_index,
)
from tfstride.providers.gcp.resource_facts import GcpResourceFacts, gcp_facts
from tfstride.providers.gcp.resource_types import GcpResourceType


class GcpPrivateConnectivityRuleDetectors:
    def __init__(self, finding_factory: FindingFactory) -> None:
        self._finding_factory = finding_factory

    def detect_cloud_sql_private_connectivity_not_modeled(
        self,
        context: RuleEvaluationContext,
        rule_id: str,
    ) -> list[Finding]:
        if context.inventory.provider != "gcp":
            return []

        private_connectivity_index = build_gcp_private_connectivity_index(context.inventory)
        if _has_unresolved_private_connectivity(private_connectivity_index):
            return []

        findings: list[Finding] = []
        for database in context.inventory.by_type(GcpResourceType.SQL_DATABASE_INSTANCE):
            database_facts = gcp_facts(database)
            if not database_facts.private_network:
                continue
            coverage = private_connectivity_index.coverage_for_cloud_sql(database)
            if coverage.has_cloud_sql_private_connectivity:
                continue

            severity_reasoning = build_severity_reasoning(
                internet_exposure=bool(database_facts.ipv4_enabled),
                privilege_breadth=0,
                data_sensitivity=2,
                lateral_movement=1,
                blast_radius=0,
            )
            findings.append(
                self._finding_factory.build(
                    rule_id=rule_id,
                    severity=severity_reasoning.severity,
                    affected_resources=[database.address],
                    trust_boundary_id=None,
                    rationale=(
                        f"{database.display_name} is configured with Cloud SQL private network "
                        f"`{database_facts.private_network}`, but this Terraform plan does not model a "
                        "Private Service Access connection or Cloud SQL Private Service Connect policy for "
                        "that network. If private connectivity is managed outside this plan, include that "
                        "coverage in review evidence; otherwise clients may still rely on public Cloud SQL "
                        "endpoints or separately managed networking."
                    ),
                    evidence=collect_evidence(
                        evidence_item(
                            "cloud_sql_network_posture",
                            _cloud_sql_network_posture_evidence(database_facts),
                        ),
                        evidence_item(
                            "private_connectivity_coverage",
                            _private_connectivity_coverage_evidence(coverage),
                        ),
                    ),
                    severity_reasoning=severity_reasoning,
                )
            )
        return findings


def _has_unresolved_private_connectivity(index: GcpPrivateConnectivityIndex) -> bool:
    return any(
        (
            getattr(index, "unresolved_private_service_access_connections", ()),
            getattr(index, "unresolved_psc_service_connection_policies", ()),
        )
    )


def _cloud_sql_network_posture_evidence(database_facts: GcpResourceFacts) -> list[str]:
    return [
        f"private_network={database_facts.private_network}",
        f"ipv4_enabled={_bool_status(database_facts.ipv4_enabled)}",
    ]


def _private_connectivity_coverage_evidence(coverage: GcpPrivateConnectivityCoverage) -> list[str]:
    values = [
        "private_service_access_connections=0",
        "cloud_sql_psc_service_connection_policies=0",
    ]
    if coverage.reserved_range_addresses:
        values.append(f"reserved_ranges=[{', '.join(coverage.reserved_range_addresses)}]")
    if coverage.psc_forwarding_rule_addresses:
        values.append(f"psc_forwarding_rules=[{', '.join(coverage.psc_forwarding_rule_addresses)}]")
    if coverage.uncertainties:
        values.extend(f"uncertainty={uncertainty}" for uncertainty in coverage.uncertainties)
    return values


def _bool_status(value: bool | None) -> str:
    if value is None:
        return "unknown"
    return str(value).lower()
