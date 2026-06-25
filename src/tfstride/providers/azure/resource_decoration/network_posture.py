from __future__ import annotations

from tfstride.models import NormalizedResource
from tfstride.providers.azure.resource_facts import azure_facts
from tfstride.providers.azure.resource_index import AzureDecorationContext
from tfstride.providers.azure.resource_types import AzureResourceType


class ResolveSubnetVirtualNetworkStage:
    name = "resolve_subnet_virtual_networks"

    def apply(self, resources: list[NormalizedResource], context: AzureDecorationContext) -> None:
        for subnet in resources:
            if subnet.resource_type != AzureResourceType.SUBNET:
                continue
            facts = azure_facts(subnet)
            virtual_network = context.index.resolve(facts.virtual_network_reference)
            if virtual_network is None:
                facts.add_unresolved_resource_reference("virtual_network", facts.virtual_network_reference)
                continue
            facts.set_resolved_virtual_network_address(virtual_network.address)


class ResolveNetworkInterfaceRelationshipsStage:
    name = "resolve_network_interface_relationships"

    def apply(self, resources: list[NormalizedResource], context: AzureDecorationContext) -> None:
        for network_interface in resources:
            if network_interface.resource_type != AzureResourceType.NETWORK_INTERFACE:
                continue
            facts = azure_facts(network_interface)
            original_subnet_references = tuple(network_interface.subnet_ids)
            effective_subnet_references: list[str] = []
            for subnet_reference in original_subnet_references:
                subnet = context.index.resolve(subnet_reference)
                if subnet is None:
                    facts.add_unresolved_resource_reference("subnet", subnet_reference)
                    effective_subnet_references.append(subnet_reference)
                    continue
                facts.add_resolved_subnet_address(subnet.address)
                effective_subnet_references.append(subnet.address)
                facts.inherit_network_relationships(subnet)
            facts.set_subnet_references(effective_subnet_references)
            public_ip_references = facts.public_ip_references
            for public_ip_reference in public_ip_references:
                public_ip = context.index.resolve(public_ip_reference)
                if public_ip is None:
                    facts.add_unresolved_resource_reference("public_ip", public_ip_reference)
                    continue
                facts.add_resolved_public_ip_address(public_ip.address)
                azure_facts(public_ip).add_associated_resource_address(network_interface.address)
            configured = bool(public_ip_references)
            facts.set_public_ip_attachment(
                configured=configured,
                reasons=["network interface references a public IP address"] if configured else [],
            )
