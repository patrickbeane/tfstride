from __future__ import annotations

from tfstride.models import NormalizedResource
from tfstride.providers.azure.resource_facts import azure_facts
from tfstride.providers.azure.resource_index import AzureDecorationContext
from tfstride.providers.azure.resource_types import AZURE_COMPUTE_RESOURCE_TYPES


class ResolveVirtualMachineRelationshipsStage:
    name = "resolve_virtual_machine_relationships"

    def apply(self, resources: list[NormalizedResource], context: AzureDecorationContext) -> None:
        for virtual_machine in resources:
            if virtual_machine.resource_type not in AZURE_COMPUTE_RESOURCE_TYPES:
                continue
            facts = azure_facts(virtual_machine)
            attached_public_ip = bool(facts.public_ip_address)
            for network_interface_reference in facts.network_interface_references:
                network_interface = context.index.resolve(network_interface_reference)
                if network_interface is None:
                    facts.add_unresolved_resource_reference("network_interface", network_interface_reference)
                    continue
                facts.add_resolved_network_interface_address(network_interface.address)
                facts.inherit_network_relationships(network_interface)
                for public_ip_address in azure_facts(network_interface).resolved_public_ip_addresses:
                    facts.add_resolved_public_ip_address(public_ip_address)
                attached_public_ip = attached_public_ip or network_interface.public_access_configured
            facts.set_public_ip_attachment(
                configured=attached_public_ip,
                reasons=["virtual machine is attached to a network interface with a public IP"]
                if attached_public_ip
                else [],
            )
