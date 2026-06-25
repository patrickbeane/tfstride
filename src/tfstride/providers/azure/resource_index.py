from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from types import MappingProxyType

from tfstride.models import NormalizedResource
from tfstride.providers.azure.resource_types import AzureResourceType
from tfstride.providers.azure.resource_utils import azure_reference_key, azure_resource_references


@dataclass(frozen=True, slots=True)
class AzureResourceIndex:
    resources_by_reference: Mapping[str, NormalizedResource]
    virtual_networks: Mapping[str, NormalizedResource]
    subnets: Mapping[str, NormalizedResource]
    network_security_groups: Mapping[str, NormalizedResource]
    network_interfaces: Mapping[str, NormalizedResource]
    public_ips: Mapping[str, NormalizedResource]
    network_security_rules: tuple[NormalizedResource, ...]
    subnet_nsg_associations: tuple[NormalizedResource, ...]
    nic_nsg_associations: tuple[NormalizedResource, ...]

    def resolve(self, reference: str | None) -> NormalizedResource | None:
        return self.resources_by_reference.get(azure_reference_key(reference))


@dataclass(slots=True)
class AzureDecorationContext:
    index: AzureResourceIndex


class AzureResourceIndexBuilder:
    def build(self, resources: list[NormalizedResource]) -> AzureResourceIndex:
        resources_by_reference: dict[str, NormalizedResource] = {}
        virtual_networks: dict[str, NormalizedResource] = {}
        subnets: dict[str, NormalizedResource] = {}
        network_security_groups: dict[str, NormalizedResource] = {}
        network_interfaces: dict[str, NormalizedResource] = {}
        public_ips: dict[str, NormalizedResource] = {}
        network_security_rules: list[NormalizedResource] = []
        subnet_nsg_associations: list[NormalizedResource] = []
        nic_nsg_associations: list[NormalizedResource] = []

        for resource in resources:
            references = azure_resource_references(resource)
            for reference in references:
                resources_by_reference.setdefault(reference, resource)
            target_index = _target_index(
                resource.resource_type,
                virtual_networks=virtual_networks,
                subnets=subnets,
                network_security_groups=network_security_groups,
                network_interfaces=network_interfaces,
                public_ips=public_ips,
            )
            if target_index is not None:
                for reference in references:
                    target_index.setdefault(reference, resource)
            if resource.resource_type == AzureResourceType.NETWORK_SECURITY_RULE:
                network_security_rules.append(resource)
            elif resource.resource_type == AzureResourceType.SUBNET_NETWORK_SECURITY_GROUP_ASSOCIATION:
                subnet_nsg_associations.append(resource)
            elif resource.resource_type == AzureResourceType.NETWORK_INTERFACE_SECURITY_GROUP_ASSOCIATION:
                nic_nsg_associations.append(resource)

        return AzureResourceIndex(
            resources_by_reference=MappingProxyType(resources_by_reference),
            virtual_networks=MappingProxyType(virtual_networks),
            subnets=MappingProxyType(subnets),
            network_security_groups=MappingProxyType(network_security_groups),
            network_interfaces=MappingProxyType(network_interfaces),
            public_ips=MappingProxyType(public_ips),
            network_security_rules=tuple(network_security_rules),
            subnet_nsg_associations=tuple(subnet_nsg_associations),
            nic_nsg_associations=tuple(nic_nsg_associations),
        )


def _target_index(
    resource_type: str,
    *,
    virtual_networks: dict[str, NormalizedResource],
    subnets: dict[str, NormalizedResource],
    network_security_groups: dict[str, NormalizedResource],
    network_interfaces: dict[str, NormalizedResource],
    public_ips: dict[str, NormalizedResource],
) -> dict[str, NormalizedResource] | None:
    return {
        AzureResourceType.VIRTUAL_NETWORK: virtual_networks,
        AzureResourceType.SUBNET: subnets,
        AzureResourceType.NETWORK_SECURITY_GROUP: network_security_groups,
        AzureResourceType.NETWORK_INTERFACE: network_interfaces,
        AzureResourceType.PUBLIC_IP: public_ips,
    }.get(resource_type)
