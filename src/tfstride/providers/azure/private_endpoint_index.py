from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from types import MappingProxyType

from tfstride.models import NormalizedResource, ResourceInventory
from tfstride.providers.azure.resource_facts import azure_facts
from tfstride.providers.azure.resource_types import AzureResourceType
from tfstride.providers.azure.resource_utils import azure_reference_key, compact_strings
from tfstride.providers.coercion import dedupe_strings

_SUPPORTED_PRIVATE_ENDPOINT_TARGET_TYPES = frozenset(
    {
        AzureResourceType.STORAGE_ACCOUNT,
        AzureResourceType.KEY_VAULT,
        AzureResourceType.MSSQL_SERVER,
        AzureResourceType.SERVICE_BUS_NAMESPACE,
        AzureResourceType.CONTAINER_REGISTRY,
    }
)


@dataclass(frozen=True, slots=True)
class AzurePrivateEndpointConnection:
    private_endpoint_address: str
    target_resource_id: str
    subresource_names: tuple[str, ...]
    private_dns_zone_group_names: tuple[str, ...] = ()
    private_dns_zone_ids: tuple[str, ...] = ()
    private_dns_zone_uncertainties: tuple[str, ...] = ()
    private_dns_zone_group_state: str | None = None
    private_dns_zone_ids_state: str | None = None
    service_connection_name: str | None = None
    is_manual_connection: bool | None = None


@dataclass(frozen=True, slots=True)
class AzureUnresolvedPrivateEndpointTarget:
    private_endpoint_address: str
    target_resource_id: str
    subresource_names: tuple[str, ...]
    service_connection_name: str | None = None


@dataclass(frozen=True, slots=True)
class AzurePrivateEndpointCoverage:
    connections: tuple[AzurePrivateEndpointConnection, ...]

    @property
    def has_private_endpoint(self) -> bool:
        return bool(self.connections)

    @property
    def private_endpoint_addresses(self) -> tuple[str, ...]:
        return tuple(dedupe_strings(connection.private_endpoint_address for connection in self.connections))

    @property
    def subresource_names(self) -> tuple[str, ...]:
        return tuple(
            dedupe_strings(
                subresource_name for connection in self.connections for subresource_name in connection.subresource_names
            )
        )

    @property
    def private_dns_zone_group_names(self) -> tuple[str, ...]:
        return tuple(
            dedupe_strings(
                group_name for connection in self.connections for group_name in connection.private_dns_zone_group_names
            )
        )

    @property
    def private_dns_zone_ids(self) -> tuple[str, ...]:
        return tuple(
            dedupe_strings(zone_id for connection in self.connections for zone_id in connection.private_dns_zone_ids)
        )

    @property
    def private_dns_zone_uncertainties(self) -> tuple[str, ...]:
        return tuple(
            dedupe_strings(
                uncertainty
                for connection in self.connections
                for uncertainty in connection.private_dns_zone_uncertainties
            )
        )


@dataclass(frozen=True, slots=True)
class AzurePrivateEndpointIndex:
    connections_by_target_key: Mapping[str, tuple[AzurePrivateEndpointConnection, ...]]
    unresolved_targets: tuple[AzureUnresolvedPrivateEndpointTarget, ...]

    def coverage_for(self, resource: NormalizedResource) -> AzurePrivateEndpointCoverage:
        connections: list[AzurePrivateEndpointConnection] = []
        seen: set[tuple[str, str, str | None]] = set()
        for target_key in _target_resource_keys(resource):
            for connection in self.connections_by_target_key.get(target_key, ()):
                dedupe_key = (
                    connection.private_endpoint_address,
                    connection.target_resource_id,
                    connection.service_connection_name,
                )
                if dedupe_key in seen:
                    continue
                seen.add(dedupe_key)
                connections.append(connection)
        return AzurePrivateEndpointCoverage(tuple(connections))


def build_azure_private_endpoint_index(
    source: ResourceInventory | Iterable[NormalizedResource],
) -> AzurePrivateEndpointIndex:
    resources = tuple(source.resources if isinstance(source, ResourceInventory) else source)
    target_keys_by_lookup_key = _supported_target_keys_by_lookup_key(resources)
    pending_connections_by_key: dict[str, list[AzurePrivateEndpointConnection]] = {}
    unresolved_targets: list[AzureUnresolvedPrivateEndpointTarget] = []

    for private_endpoint in resources:
        if private_endpoint.resource_type != AzureResourceType.PRIVATE_ENDPOINT:
            continue
        for connection in _private_endpoint_connections(private_endpoint):
            lookup_key = azure_reference_key(connection.target_resource_id)
            target_key = target_keys_by_lookup_key.get(lookup_key)
            if target_key:
                pending_connections_by_key.setdefault(target_key, []).append(connection)
            else:
                unresolved_targets.append(
                    AzureUnresolvedPrivateEndpointTarget(
                        private_endpoint_address=connection.private_endpoint_address,
                        target_resource_id=connection.target_resource_id,
                        subresource_names=connection.subresource_names,
                        service_connection_name=connection.service_connection_name,
                    )
                )

    return AzurePrivateEndpointIndex(
        connections_by_target_key=MappingProxyType(
            {key: tuple(value) for key, value in sorted(pending_connections_by_key.items())}
        ),
        unresolved_targets=tuple(unresolved_targets),
    )


def _supported_target_keys_by_lookup_key(
    resources: Iterable[NormalizedResource],
) -> dict[str, str]:
    target_keys_by_lookup_key: dict[str, str] = {}
    for resource in resources:
        if resource.resource_type not in _SUPPORTED_PRIVATE_ENDPOINT_TARGET_TYPES:
            continue
        primary_key = _primary_target_resource_key(resource)
        for target_key in _target_resource_keys(resource):
            target_keys_by_lookup_key.setdefault(target_key, primary_key)
    return target_keys_by_lookup_key


def _primary_target_resource_key(resource: NormalizedResource) -> str:
    facts = azure_facts(resource)
    if resource.resource_type == AzureResourceType.STORAGE_ACCOUNT:
        target_id = facts.storage_account_id
    elif resource.resource_type == AzureResourceType.KEY_VAULT:
        target_id = facts.key_vault_id
    elif resource.resource_type == AzureResourceType.MSSQL_SERVER:
        target_id = facts.mssql_server_id
    elif resource.resource_type == AzureResourceType.SERVICE_BUS_NAMESPACE:
        target_id = facts.service_bus_namespace_id
    elif resource.resource_type == AzureResourceType.CONTAINER_REGISTRY:
        target_id = facts.container_registry_id
    else:
        target_id = None
    return azure_reference_key(target_id or f"{resource.address}.id")


def _target_resource_keys(resource: NormalizedResource) -> tuple[str, ...]:
    if resource.resource_type not in _SUPPORTED_PRIVATE_ENDPOINT_TARGET_TYPES:
        return ()

    facts = azure_facts(resource)
    target_ids = [f"{resource.address}.id"]
    if resource.resource_type == AzureResourceType.STORAGE_ACCOUNT:
        target_ids.append(facts.storage_account_id)
    elif resource.resource_type == AzureResourceType.KEY_VAULT:
        target_ids.append(facts.key_vault_id)
    elif resource.resource_type == AzureResourceType.MSSQL_SERVER:
        target_ids.append(facts.mssql_server_id)
    elif resource.resource_type == AzureResourceType.SERVICE_BUS_NAMESPACE:
        target_ids.append(facts.service_bus_namespace_id)
    elif resource.resource_type == AzureResourceType.CONTAINER_REGISTRY:
        target_ids.append(facts.container_registry_id)
    return tuple(azure_reference_key(value) for value in compact_strings(target_ids))


def _private_endpoint_connections(
    private_endpoint: NormalizedResource,
) -> tuple[AzurePrivateEndpointConnection, ...]:
    connections: list[AzurePrivateEndpointConnection] = []
    facts = azure_facts(private_endpoint)
    for record in facts.private_service_connections:
        target_resource_id = _connection_target_resource_id(record)
        if not target_resource_id:
            continue
        connections.append(
            AzurePrivateEndpointConnection(
                private_endpoint_address=private_endpoint.address,
                target_resource_id=target_resource_id,
                subresource_names=tuple(compact_strings(record.get("subresource_names", []))),
                private_dns_zone_group_names=tuple(facts.private_dns_zone_group_names),
                private_dns_zone_ids=tuple(facts.private_dns_zone_ids),
                private_dns_zone_uncertainties=tuple(
                    uncertainty
                    for uncertainty in facts.private_endpoint_uncertainties
                    if "private_dns_zone_group" in uncertainty
                ),
                private_dns_zone_group_state=facts.private_dns_zone_group_state,
                private_dns_zone_ids_state=facts.private_dns_zone_ids_state,
                service_connection_name=_optional_string(record.get("name")),
                is_manual_connection=_optional_bool(record.get("is_manual_connection")),
            )
        )
    return tuple(connections)


def _connection_target_resource_id(record: dict) -> str | None:
    return _optional_string(record.get("private_connection_resource_id"))


def _optional_string(value: object) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def _optional_bool(value: object) -> bool | None:
    return value if isinstance(value, bool) else None
