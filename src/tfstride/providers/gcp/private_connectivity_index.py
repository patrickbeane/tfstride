from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from types import MappingProxyType
from typing import Any

from tfstride.models import NormalizedResource, ResourceInventory
from tfstride.providers.coercion import dedupe_strings
from tfstride.providers.gcp.resource_facts import gcp_facts
from tfstride.providers.gcp.resource_index import (
    gcp_network_reference_key,
    gcp_resource_references,
)
from tfstride.providers.gcp.resource_types import GcpResourceType

_PRIVATE_SERVICE_ACCESS_SERVICE = "servicenetworking.googleapis.com"
_CLOUD_SQL_SERVICE_CLASS = "gcp-cloud-sql"


@dataclass(frozen=True, slots=True)
class GcpPrivateServiceAccessReservedRange:
    address: str
    name: str | None
    network: str | None
    purpose: str | None
    address_type: str | None
    ip_address: str | None
    prefix_length: int | None
    uncertainties: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class GcpPrivateServiceAccessConnection:
    address: str
    network: str | None
    service: str | None
    reserved_ranges: tuple[str, ...]
    peering: str | None
    uncertainties: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class GcpPscForwardingRuleEndpoint:
    address: str
    network: str | None
    subnetwork: str | None
    target: str | None
    connection_id: str | None
    connection_status: str | None
    service_label: str | None
    service_name: str | None


@dataclass(frozen=True, slots=True)
class GcpPscServiceAttachment:
    address: str
    target_service: str | None
    connection_preference: str | None
    nat_subnets: tuple[str, ...]
    domain_names: tuple[str, ...]
    consumer_accept_list: tuple[Mapping[str, Any], ...]
    consumer_reject_list: tuple[Mapping[str, Any], ...]
    uncertainties: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class GcpPscServiceConnectionPolicy:
    address: str
    network: str | None
    service_class: str | None
    psc_config: Mapping[str, Any]
    subnetworks: tuple[str, ...]
    uncertainties: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class GcpPrivateConnectivityCoverage:
    private_service_access_connections: tuple[GcpPrivateServiceAccessConnection, ...]
    private_service_access_reserved_ranges: tuple[GcpPrivateServiceAccessReservedRange, ...]
    psc_forwarding_rule_endpoints: tuple[GcpPscForwardingRuleEndpoint, ...]
    psc_service_connection_policies: tuple[GcpPscServiceConnectionPolicy, ...]

    @property
    def has_private_service_access(self) -> bool:
        return bool(self.private_service_access_connections)

    @property
    def has_cloud_sql_private_service_access(self) -> bool:
        return any(
            _is_private_service_access_connection(connection) for connection in self.private_service_access_connections
        )

    @property
    def has_cloud_sql_psc_policy(self) -> bool:
        return any(_is_cloud_sql_service_class(policy.service_class) for policy in self.psc_service_connection_policies)

    @property
    def has_cloud_sql_private_connectivity(self) -> bool:
        return self.has_cloud_sql_private_service_access or self.has_cloud_sql_psc_policy

    @property
    def private_service_access_connection_addresses(self) -> tuple[str, ...]:
        return tuple(dedupe_strings(connection.address for connection in self.private_service_access_connections))

    @property
    def reserved_range_addresses(self) -> tuple[str, ...]:
        return tuple(
            dedupe_strings(reserved_range.address for reserved_range in self.private_service_access_reserved_ranges)
        )

    @property
    def reserved_range_names(self) -> tuple[str, ...]:
        return tuple(
            dedupe_strings(reserved_range.name for reserved_range in self.private_service_access_reserved_ranges)
        )

    @property
    def psc_forwarding_rule_addresses(self) -> tuple[str, ...]:
        return tuple(dedupe_strings(endpoint.address for endpoint in self.psc_forwarding_rule_endpoints))

    @property
    def psc_service_connection_policy_addresses(self) -> tuple[str, ...]:
        return tuple(dedupe_strings(policy.address for policy in self.psc_service_connection_policies))

    @property
    def uncertainties(self) -> tuple[str, ...]:
        return tuple(
            dedupe_strings(
                uncertainty
                for record in (
                    *self.private_service_access_connections,
                    *self.private_service_access_reserved_ranges,
                    *self.psc_service_connection_policies,
                )
                for uncertainty in record.uncertainties
            )
        )


@dataclass(frozen=True, slots=True)
class GcpPrivateConnectivityIndex:
    private_service_access_connections_by_network: Mapping[str, tuple[GcpPrivateServiceAccessConnection, ...]]
    private_service_access_reserved_ranges_by_network: Mapping[str, tuple[GcpPrivateServiceAccessReservedRange, ...]]
    psc_forwarding_rule_endpoints_by_network: Mapping[str, tuple[GcpPscForwardingRuleEndpoint, ...]]
    psc_service_connection_policies_by_network: Mapping[str, tuple[GcpPscServiceConnectionPolicy, ...]]
    psc_service_attachments: tuple[GcpPscServiceAttachment, ...]
    unresolved_private_service_access_connections: tuple[GcpPrivateServiceAccessConnection, ...]
    unresolved_private_service_access_reserved_ranges: tuple[GcpPrivateServiceAccessReservedRange, ...]
    unresolved_psc_forwarding_rule_endpoints: tuple[GcpPscForwardingRuleEndpoint, ...]
    unresolved_psc_service_connection_policies: tuple[GcpPscServiceConnectionPolicy, ...]
    network_aliases: Mapping[str, str]

    def coverage_for_network(self, network: str | None) -> GcpPrivateConnectivityCoverage:
        if not network:
            return GcpPrivateConnectivityCoverage((), (), (), ())
        network_key = _canonical_network_key(network, self.network_aliases)
        if not network_key:
            return GcpPrivateConnectivityCoverage((), (), (), ())
        return GcpPrivateConnectivityCoverage(
            private_service_access_connections=self.private_service_access_connections_by_network.get(network_key, ()),
            private_service_access_reserved_ranges=self.private_service_access_reserved_ranges_by_network.get(
                network_key, ()
            ),
            psc_forwarding_rule_endpoints=self.psc_forwarding_rule_endpoints_by_network.get(network_key, ()),
            psc_service_connection_policies=self.psc_service_connection_policies_by_network.get(network_key, ()),
        )

    def coverage_for_cloud_sql(self, resource: NormalizedResource) -> GcpPrivateConnectivityCoverage:
        facts = gcp_facts(resource)
        return self.coverage_for_network(facts.private_network or resource.vpc_id)

    def has_cloud_sql_private_connectivity(self, resource: NormalizedResource) -> bool:
        return self.coverage_for_cloud_sql(resource).has_cloud_sql_private_connectivity


def build_gcp_private_connectivity_index(
    source: ResourceInventory | Iterable[NormalizedResource],
) -> GcpPrivateConnectivityIndex:
    resources = tuple(source.resources if isinstance(source, ResourceInventory) else source)
    network_aliases = _network_aliases(resources)
    pending_connections: dict[str, list[GcpPrivateServiceAccessConnection]] = {}
    pending_reserved_ranges: dict[str, list[GcpPrivateServiceAccessReservedRange]] = {}
    pending_psc_endpoints: dict[str, list[GcpPscForwardingRuleEndpoint]] = {}
    pending_psc_policies: dict[str, list[GcpPscServiceConnectionPolicy]] = {}
    service_attachments: list[GcpPscServiceAttachment] = []
    unresolved_connections: list[GcpPrivateServiceAccessConnection] = []
    unresolved_reserved_ranges: list[GcpPrivateServiceAccessReservedRange] = []
    unresolved_psc_endpoints: list[GcpPscForwardingRuleEndpoint] = []
    unresolved_psc_policies: list[GcpPscServiceConnectionPolicy] = []

    for resource in resources:
        if resource.resource_type == GcpResourceType.SERVICE_NETWORKING_CONNECTION:
            record = _private_service_access_connection(resource)
            _add_network_record(
                record,
                record.network,
                network_aliases,
                pending_connections,
                unresolved_connections,
            )
        elif resource.resource_type == GcpResourceType.COMPUTE_GLOBAL_ADDRESS:
            record = _private_service_access_reserved_range(resource)
            if record is None:
                continue
            _add_network_record(
                record,
                record.network,
                network_aliases,
                pending_reserved_ranges,
                unresolved_reserved_ranges,
            )
        elif resource.resource_type in {
            GcpResourceType.COMPUTE_FORWARDING_RULE,
            GcpResourceType.COMPUTE_GLOBAL_FORWARDING_RULE,
        }:
            record = _psc_forwarding_rule_endpoint(resource)
            if record is None:
                continue
            _add_network_record(
                record,
                record.network,
                network_aliases,
                pending_psc_endpoints,
                unresolved_psc_endpoints,
            )
        elif resource.resource_type == GcpResourceType.NETWORK_CONNECTIVITY_SERVICE_CONNECTION_POLICY:
            record = _psc_service_connection_policy(resource)
            _add_network_record(
                record,
                record.network,
                network_aliases,
                pending_psc_policies,
                unresolved_psc_policies,
            )
        elif resource.resource_type == GcpResourceType.COMPUTE_SERVICE_ATTACHMENT:
            service_attachments.append(_psc_service_attachment(resource))

    return GcpPrivateConnectivityIndex(
        private_service_access_connections_by_network=_freeze_record_mapping(pending_connections),
        private_service_access_reserved_ranges_by_network=_freeze_record_mapping(pending_reserved_ranges),
        psc_forwarding_rule_endpoints_by_network=_freeze_record_mapping(pending_psc_endpoints),
        psc_service_connection_policies_by_network=_freeze_record_mapping(pending_psc_policies),
        psc_service_attachments=tuple(service_attachments),
        unresolved_private_service_access_connections=tuple(unresolved_connections),
        unresolved_private_service_access_reserved_ranges=tuple(unresolved_reserved_ranges),
        unresolved_psc_forwarding_rule_endpoints=tuple(unresolved_psc_endpoints),
        unresolved_psc_service_connection_policies=tuple(unresolved_psc_policies),
        network_aliases=MappingProxyType(dict(sorted(network_aliases.items()))),
    )


def _private_service_access_connection(resource: NormalizedResource) -> GcpPrivateServiceAccessConnection:
    facts = gcp_facts(resource)
    return GcpPrivateServiceAccessConnection(
        address=resource.address,
        network=resource.vpc_id,
        service=facts.private_connectivity_service,
        reserved_ranges=tuple(facts.private_connectivity_reserved_ranges),
        peering=facts.private_connectivity_peering,
        uncertainties=tuple(facts.private_connectivity_uncertainties),
    )


def _private_service_access_reserved_range(
    resource: NormalizedResource,
) -> GcpPrivateServiceAccessReservedRange | None:
    facts = gcp_facts(resource)
    if not _is_private_service_access_range(
        facts.private_connectivity_purpose, facts.private_connectivity_uncertainties
    ):
        return None
    return GcpPrivateServiceAccessReservedRange(
        address=resource.address,
        name=facts.resource_name,
        network=resource.vpc_id,
        purpose=facts.private_connectivity_purpose,
        address_type=facts.private_connectivity_address_type,
        ip_address=facts.private_connectivity_address,
        prefix_length=facts.private_connectivity_prefix_length,
        uncertainties=tuple(facts.private_connectivity_uncertainties),
    )


def _psc_forwarding_rule_endpoint(resource: NormalizedResource) -> GcpPscForwardingRuleEndpoint | None:
    facts = gcp_facts(resource)
    if not any((facts.psc_connection_id, facts.psc_connection_status, facts.psc_service_label, facts.psc_service_name)):
        return None
    return GcpPscForwardingRuleEndpoint(
        address=resource.address,
        network=resource.vpc_id,
        subnetwork=resource.subnet_ids[0] if resource.subnet_ids else None,
        target=facts.forwarding_rule_target,
        connection_id=facts.psc_connection_id,
        connection_status=facts.psc_connection_status,
        service_label=facts.psc_service_label,
        service_name=facts.psc_service_name,
    )


def _psc_service_attachment(resource: NormalizedResource) -> GcpPscServiceAttachment:
    facts = gcp_facts(resource)
    return GcpPscServiceAttachment(
        address=resource.address,
        target_service=facts.private_connectivity_target_service,
        connection_preference=facts.psc_connection_preference,
        nat_subnets=tuple(facts.private_connectivity_nat_subnets),
        domain_names=tuple(facts.private_connectivity_domain_names),
        consumer_accept_list=tuple(MappingProxyType(dict(item)) for item in facts.psc_consumer_accept_list),
        consumer_reject_list=tuple(MappingProxyType(dict(item)) for item in facts.psc_consumer_reject_list),
        uncertainties=tuple(facts.private_connectivity_uncertainties),
    )


def _psc_service_connection_policy(resource: NormalizedResource) -> GcpPscServiceConnectionPolicy:
    facts = gcp_facts(resource)
    return GcpPscServiceConnectionPolicy(
        address=resource.address,
        network=resource.vpc_id,
        service_class=facts.psc_service_class,
        psc_config=MappingProxyType(dict(facts.psc_config)),
        subnetworks=tuple(facts.private_connectivity_subnetworks),
        uncertainties=tuple(facts.private_connectivity_uncertainties),
    )


def _network_aliases(resources: Iterable[NormalizedResource]) -> dict[str, str]:
    aliases: dict[str, str] = {}
    for resource in resources:
        if resource.resource_type != GcpResourceType.COMPUTE_NETWORK:
            continue
        primary_key = gcp_network_reference_key(resource.address)
        aliases.setdefault(primary_key, primary_key)
        for reference in gcp_resource_references(resource):
            aliases.setdefault(reference, primary_key)
            aliases.setdefault(gcp_network_reference_key(reference), primary_key)
    return aliases


def _add_network_record(
    record: Any,
    network: str | None,
    network_aliases: Mapping[str, str],
    records_by_network: dict[str, list[Any]],
    unresolved_records: list[Any],
) -> None:
    network_key = _canonical_network_key(network, network_aliases)
    if not network_key:
        unresolved_records.append(record)
        return
    records_by_network.setdefault(network_key, []).append(record)


def _canonical_network_key(network: str | None, network_aliases: Mapping[str, str]) -> str | None:
    if not network:
        return None
    network_key = gcp_network_reference_key(network)
    return network_aliases.get(network_key, network_key)


def _freeze_record_mapping(records_by_network: Mapping[str, list[Any]]) -> Mapping[str, tuple[Any, ...]]:
    return MappingProxyType({key: tuple(value) for key, value in sorted(records_by_network.items())})


def _is_private_service_access_connection(connection: GcpPrivateServiceAccessConnection) -> bool:
    return (connection.service or "").strip().lower() == _PRIVATE_SERVICE_ACCESS_SERVICE


def _is_cloud_sql_service_class(service_class: str | None) -> bool:
    normalized = (service_class or "").strip().lower()
    return normalized == _CLOUD_SQL_SERVICE_CLASS or "cloud-sql" in normalized


def _is_private_service_access_range(purpose: str | None, uncertainties: Iterable[str]) -> bool:
    normalized = (purpose or "").strip().lower()
    return normalized == "vpc_peering" or any("purpose is unknown" in uncertainty for uncertainty in uncertainties)
