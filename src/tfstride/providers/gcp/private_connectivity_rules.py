from __future__ import annotations

from tfstride.analysis.finding_factory import FindingFactory
from tfstride.analysis.finding_helpers import (
    build_severity_reasoning,
    collect_evidence,
    evidence_item,
)
from tfstride.analysis.resource_concepts import (
    is_database_resource,
    is_key_management_resource,
    is_object_storage_resource,
    is_secret_store_resource,
)
from tfstride.analysis.resource_facts import analysis_facts
from tfstride.analysis.rule_definitions import RuleEvaluationContext
from tfstride.models import BoundaryType, Finding, NormalizedResource
from tfstride.providers.gcp.private_connectivity_index import (
    GcpPrivateConnectivityCoverage,
    GcpPrivateConnectivityIndex,
    build_gcp_private_connectivity_index,
)
from tfstride.providers.gcp.resource_facts import GcpResourceFacts, gcp_facts
from tfstride.providers.gcp.resource_index import GcpResourceIndex, GcpResourceIndexBuilder, gcp_resource_references
from tfstride.providers.gcp.resource_types import GcpResourceType
from tfstride.providers.gcp.resource_utils import GCP_NETWORK_REFERENCE_SUFFIXES, dedupe, gcp_reference_key


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

    def detect_private_workload_private_google_access_disabled(
        self,
        context: RuleEvaluationContext,
        rule_id: str,
    ) -> list[Finding]:
        if context.inventory.provider != "gcp":
            return []

        resource_index = GcpResourceIndexBuilder().build(list(context.inventory.resources))
        private_connectivity_index = build_gcp_private_connectivity_index(context.inventory)
        findings: list[Finding] = []

        for workload, data_paths in _private_workload_google_api_data_paths(context):
            subnetworks = _disabled_private_google_access_subnetworks(workload, resource_index)
            if not subnetworks:
                continue
            relevant_data_paths = tuple(
                (data_store, boundary_id)
                for data_store, boundary_id in data_paths
                if not _has_better_private_connectivity(data_store, private_connectivity_index)
            )
            if not relevant_data_paths:
                continue

            data_store_addresses = [data_store.address for data_store, _ in relevant_data_paths]
            severity_reasoning = build_severity_reasoning(
                internet_exposure=False,
                privilege_breadth=1 if len(data_store_addresses) == 1 else 2,
                data_sensitivity=2,
                lateral_movement=1,
                blast_radius=1,
            )
            affected_resources = dedupe(
                (
                    workload.address,
                    *(subnetwork.address for subnetwork in subnetworks),
                    *data_store_addresses,
                )
            )
            findings.append(
                self._finding_factory.build(
                    rule_id=rule_id,
                    severity=severity_reasoning.severity,
                    affected_resources=list(affected_resources),
                    trust_boundary_id=relevant_data_paths[0][1] if len(relevant_data_paths) == 1 else None,
                    rationale=(
                        f"{workload.display_name} runs on a private GCP subnetwork where Private Google Access "
                        "is disabled, and its workload identity has deterministic access to "
                        f"{', '.join(data_store.display_name for data_store, _ in relevant_data_paths)}. "
                        "Without Private Google Access or service-specific private connectivity evidence, calls "
                        "to Google APIs may require NAT or other public egress paths. This does "
                        "not imply the target data service is publicly exposed."
                    ),
                    evidence=collect_evidence(
                        evidence_item(
                            "workload_subnetwork_posture",
                            _workload_subnetwork_posture_evidence(workload, subnetworks),
                        ),
                        evidence_item("workload_identity", analysis_facts(workload).workload.identity_members),
                        evidence_item(
                            "google_api_data_paths",
                            [
                                f"{workload.address} reaches {data_store.address}"
                                for data_store, _ in relevant_data_paths
                            ],
                        ),
                        evidence_item(
                            "private_connectivity_coverage",
                            _google_api_private_connectivity_coverage_evidence(private_connectivity_index, subnetworks),
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


def _private_workload_google_api_data_paths(
    context: RuleEvaluationContext,
) -> list[tuple[NormalizedResource, tuple[tuple[NormalizedResource, str], ...]]]:
    paths_by_workload: dict[str, list[tuple[NormalizedResource, str]]] = {}
    inventory = context.inventory
    for boundary in context.boundary_index.values():
        if boundary.boundary_type != BoundaryType.WORKLOAD_TO_DATA_STORE:
            continue
        workload = inventory.get_by_address(boundary.source)
        data_store = inventory.get_by_address(boundary.target)
        if workload is None or data_store is None:
            continue
        if workload.provider != "gcp" or data_store.provider != "gcp":
            continue
        if workload.public_exposure or not _is_supported_google_api_data_store(data_store):
            continue
        paths_by_workload.setdefault(workload.address, []).append((data_store, boundary.identifier))

    data_paths: list[tuple[NormalizedResource, tuple[tuple[NormalizedResource, str], ...]]] = []
    for workload_address in sorted(paths_by_workload):
        workload = inventory.get_by_address(workload_address)
        if workload is None:
            continue
        data_paths.append(
            (
                workload,
                tuple(sorted(paths_by_workload[workload_address], key=lambda item: item[0].address)),
            )
        )
    return data_paths


def _is_supported_google_api_data_store(resource: NormalizedResource) -> bool:
    return (
        is_object_storage_resource(resource)
        or is_secret_store_resource(resource)
        or is_key_management_resource(resource)
        or is_database_resource(resource)
    )


def _disabled_private_google_access_subnetworks(
    workload: NormalizedResource,
    resource_index: GcpResourceIndex,
) -> tuple[NormalizedResource, ...]:
    subnetworks: list[NormalizedResource] = []
    seen_addresses: set[str] = set()
    for subnet_reference in workload.subnet_ids:
        subnetwork = resource_index.subnetworks_by_reference.get(
            gcp_reference_key(subnet_reference, GCP_NETWORK_REFERENCE_SUFFIXES)
        )
        if subnetwork is None or subnetwork.address in seen_addresses:
            continue
        if gcp_facts(subnetwork).private_ip_google_access is False:
            subnetworks.append(subnetwork)
            seen_addresses.add(subnetwork.address)
    return tuple(subnetworks)


def _has_better_private_connectivity(
    data_store: NormalizedResource,
    private_connectivity_index: GcpPrivateConnectivityIndex,
) -> bool:
    if is_database_resource(data_store):
        return private_connectivity_index.has_cloud_sql_private_connectivity(data_store)
    return False


def _workload_subnetwork_posture_evidence(
    workload: NormalizedResource,
    subnetworks: tuple[NormalizedResource, ...],
) -> list[str]:
    values = [f"workload_subnet_references=[{', '.join(workload.subnet_ids)}]"]
    for subnetwork in subnetworks:
        facts = gcp_facts(subnetwork)
        references = ", ".join(gcp_resource_references(subnetwork))
        values.append(
            f"{subnetwork.address}: private_ip_google_access={_bool_status(facts.private_ip_google_access)}"
            f"; network={subnetwork.vpc_id or 'unknown'}; references=[{references}]"
        )
    return values


def _google_api_private_connectivity_coverage_evidence(
    private_connectivity_index: GcpPrivateConnectivityIndex,
    subnetworks: tuple[NormalizedResource, ...],
) -> list[str]:
    values: list[str] = []
    seen_networks: set[str] = set()
    for subnetwork in subnetworks:
        network = subnetwork.vpc_id
        if not network or network in seen_networks:
            continue
        seen_networks.add(network)
        coverage = private_connectivity_index.coverage_for_network(network)
        values.append(f"network={network}")
        values.append(f"private_service_access_connections={len(coverage.private_service_access_connections)}")
        values.append(f"psc_forwarding_rule_endpoints={len(coverage.psc_forwarding_rule_endpoints)}")
        values.append(f"psc_service_connection_policies={len(coverage.psc_service_connection_policies)}")
        values.extend(f"uncertainty={uncertainty}" for uncertainty in coverage.uncertainties)
    if not values:
        return ["network=unknown"]
    return values
