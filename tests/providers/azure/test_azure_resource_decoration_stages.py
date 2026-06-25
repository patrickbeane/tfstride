from __future__ import annotations

import unittest

from tfstride.models import NormalizedResource, ResourceCategory, SecurityGroupRule
from tfstride.providers.azure.metadata import AzureResourceMetadata
from tfstride.providers.azure.resource_decoration.compute import ResolveVirtualMachineRelationshipsStage
from tfstride.providers.azure.resource_decoration.network_posture import (
    ResolveNetworkInterfaceRelationshipsStage,
    ResolveSubnetVirtualNetworkStage,
)
from tfstride.providers.azure.resource_decoration.network_security import (
    MergeNetworkSecurityRulesStage,
    ResolveNetworkSecurityAssociationsStage,
)
from tfstride.providers.azure.resource_facts import azure_facts
from tfstride.providers.azure.resource_index import AzureDecorationContext, AzureResourceIndexBuilder
from tfstride.providers.azure.resource_types import AzureResourceType


def _resource(
    address: str,
    resource_type: str,
    category: ResourceCategory,
    *,
    identifier: str | None = None,
    vpc_id: str | None = None,
    subnet_ids: tuple[str, ...] = (),
    network_rules: list[SecurityGroupRule] | None = None,
    metadata: dict[object, object] | None = None,
) -> NormalizedResource:
    return NormalizedResource(
        address=address,
        provider="azure",
        resource_type=resource_type,
        name=address.rsplit(".", 1)[-1],
        category=category,
        identifier=identifier,
        vpc_id=vpc_id,
        subnet_ids=subnet_ids,
        network_rules=network_rules or [],
        metadata=metadata,
    )


def _context(resources: list[NormalizedResource]) -> AzureDecorationContext:
    return AzureDecorationContext(index=AzureResourceIndexBuilder().build(resources))


class AzureResourceDecorationStageTests(unittest.TestCase):
    def test_network_security_rule_stage_merges_standalone_rules(self) -> None:
        network_security_group = _resource(
            "azurerm_network_security_group.web",
            AzureResourceType.NETWORK_SECURITY_GROUP,
            ResourceCategory.NETWORK,
            identifier="/subscriptions/example/networkSecurityGroups/web",
            metadata={AzureResourceMetadata.NAME: "web"},
        )
        rule = SecurityGroupRule(
            direction="ingress",
            protocol="tcp",
            from_port=443,
            to_port=443,
            cidr_blocks=["0.0.0.0/0"],
        )
        standalone_rule = _resource(
            "azurerm_network_security_rule.https",
            AzureResourceType.NETWORK_SECURITY_RULE,
            ResourceCategory.NETWORK,
            network_rules=[rule],
            metadata={
                AzureResourceMetadata.NETWORK_SECURITY_GROUP_REFERENCE: "azurerm_network_security_group.web.name",
                AzureResourceMetadata.NETWORK_SECURITY_RULES: [{"name": "https", "access": "allow"}],
            },
        )
        resources = [network_security_group, standalone_rule]

        MergeNetworkSecurityRulesStage().apply(resources, _context(resources))

        self.assertEqual(len(network_security_group.network_rules), 1)
        self.assertIsNot(network_security_group.network_rules[0], rule)
        self.assertEqual(azure_facts(network_security_group).network_security_rules[0]["name"], "https")
        self.assertEqual(
            network_security_group.get_metadata_field(AzureResourceMetadata.STANDALONE_RULE_ADDRESSES),
            ["azurerm_network_security_rule.https"],
        )

    def test_subnet_and_nsg_association_stages_resolve_graph(self) -> None:
        virtual_network = _resource(
            "azurerm_virtual_network.main",
            AzureResourceType.VIRTUAL_NETWORK,
            ResourceCategory.NETWORK,
            identifier="/subscriptions/example/virtualNetworks/main",
            metadata={AzureResourceMetadata.NAME: "main"},
        )
        subnet = _resource(
            "azurerm_subnet.app",
            AzureResourceType.SUBNET,
            ResourceCategory.NETWORK,
            identifier="/subscriptions/example/subnets/app",
            vpc_id="azurerm_virtual_network.main.name",
            metadata={AzureResourceMetadata.VIRTUAL_NETWORK_REFERENCE: "azurerm_virtual_network.main.name"},
        )
        network_security_group = _resource(
            "azurerm_network_security_group.app",
            AzureResourceType.NETWORK_SECURITY_GROUP,
            ResourceCategory.NETWORK,
            metadata={AzureResourceMetadata.NAME: "app"},
        )
        association = _resource(
            "azurerm_subnet_network_security_group_association.app",
            AzureResourceType.SUBNET_NETWORK_SECURITY_GROUP_ASSOCIATION,
            ResourceCategory.NETWORK,
            metadata={
                AzureResourceMetadata.SUBNET_REFERENCE: "azurerm_subnet.app.id",
                AzureResourceMetadata.NETWORK_SECURITY_GROUP_REFERENCE: "azurerm_network_security_group.app.id",
            },
        )
        resources = [virtual_network, subnet, network_security_group, association]
        context = _context(resources)

        ResolveSubnetVirtualNetworkStage().apply(resources, context)
        ResolveNetworkSecurityAssociationsStage().apply(resources, context)

        self.assertEqual(subnet.vpc_id, virtual_network.address)
        self.assertEqual(subnet.security_group_ids, (network_security_group.address,))
        self.assertEqual(
            azure_facts(subnet).resolved_network_security_group_addresses,
            [network_security_group.address],
        )

    def test_nic_network_security_group_association_resolves_graph(self) -> None:
        network_interface = _resource(
            "azurerm_network_interface.web",
            AzureResourceType.NETWORK_INTERFACE,
            ResourceCategory.NETWORK,
        )
        network_security_group = _resource(
            "azurerm_network_security_group.web",
            AzureResourceType.NETWORK_SECURITY_GROUP,
            ResourceCategory.NETWORK,
            metadata={AzureResourceMetadata.NAME: "web"},
        )
        association = _resource(
            "azurerm_network_interface_security_group_association.web",
            AzureResourceType.NETWORK_INTERFACE_SECURITY_GROUP_ASSOCIATION,
            ResourceCategory.NETWORK,
            metadata={
                AzureResourceMetadata.NETWORK_INTERFACE_REFERENCE: "azurerm_network_interface.web.id",
                AzureResourceMetadata.NETWORK_SECURITY_GROUP_REFERENCE: "azurerm_network_security_group.web.id",
            },
        )
        resources = [network_interface, network_security_group, association]

        ResolveNetworkSecurityAssociationsStage().apply(resources, _context(resources))

        self.assertEqual(network_interface.security_group_ids, (network_security_group.address,))
        self.assertEqual(
            azure_facts(network_interface).resolved_network_security_group_addresses,
            [network_security_group.address],
        )
        self.assertEqual(
            network_security_group.get_metadata_field(AzureResourceMetadata.ASSOCIATED_RESOURCE_ADDRESSES),
            [network_interface.address],
        )

    def test_nic_and_vm_stages_propagate_relationships_without_exposure(self) -> None:
        subnet = _resource(
            "azurerm_subnet.app",
            AzureResourceType.SUBNET,
            ResourceCategory.NETWORK,
            identifier="/subscriptions/example/subnets/app",
            vpc_id="azurerm_virtual_network.main",
        )
        azure_facts(subnet).add_security_group_reference("azurerm_network_security_group.app")
        public_ip = _resource(
            "azurerm_public_ip.web",
            AzureResourceType.PUBLIC_IP,
            ResourceCategory.EDGE,
            identifier="/subscriptions/example/publicIPAddresses/web",
        )
        network_interface = _resource(
            "azurerm_network_interface.web",
            AzureResourceType.NETWORK_INTERFACE,
            ResourceCategory.NETWORK,
            subnet_ids=("azurerm_subnet.app.id",),
            metadata={AzureResourceMetadata.PUBLIC_IP_REFERENCES: ["azurerm_public_ip.web.id"]},
        )
        virtual_machine = _resource(
            "azurerm_linux_virtual_machine.web",
            AzureResourceType.LINUX_VIRTUAL_MACHINE,
            ResourceCategory.COMPUTE,
            metadata={AzureResourceMetadata.NETWORK_INTERFACE_REFERENCES: ["azurerm_network_interface.web.id"]},
        )
        resources = [subnet, public_ip, network_interface, virtual_machine]
        context = _context(resources)

        ResolveNetworkInterfaceRelationshipsStage().apply(resources, context)
        ResolveVirtualMachineRelationshipsStage().apply(resources, context)

        self.assertIn(subnet.address, network_interface.subnet_ids)
        self.assertIn("azurerm_network_security_group.app", network_interface.security_group_ids)
        self.assertEqual(network_interface.vpc_id, "azurerm_virtual_network.main")
        self.assertEqual(azure_facts(network_interface).resolved_public_ip_addresses, [public_ip.address])
        self.assertTrue(network_interface.public_access_configured)
        self.assertIn(subnet.address, virtual_machine.subnet_ids)
        self.assertIn("azurerm_network_security_group.app", virtual_machine.security_group_ids)
        self.assertEqual(virtual_machine.vpc_id, "azurerm_virtual_network.main")
        self.assertEqual(azure_facts(virtual_machine).resolved_network_interface_addresses, [network_interface.address])
        self.assertTrue(virtual_machine.public_access_configured)
        self.assertFalse(virtual_machine.public_exposure)
        self.assertFalse(virtual_machine.direct_internet_reachable)

    def test_unresolved_relationships_are_recorded(self) -> None:
        virtual_machine = _resource(
            "azurerm_linux_virtual_machine.web",
            AzureResourceType.LINUX_VIRTUAL_MACHINE,
            ResourceCategory.COMPUTE,
            metadata={AzureResourceMetadata.NETWORK_INTERFACE_REFERENCES: ["azurerm_network_interface.missing.id"]},
        )

        ResolveVirtualMachineRelationshipsStage().apply([virtual_machine], _context([virtual_machine]))

        self.assertEqual(
            virtual_machine.get_metadata_field(AzureResourceMetadata.UNRESOLVED_RESOURCE_REFERENCES),
            ["network_interface:azurerm_network_interface.missing.id"],
        )


if __name__ == "__main__":
    unittest.main()
