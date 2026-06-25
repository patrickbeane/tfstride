from __future__ import annotations

import unittest

from tfstride.analysis.boundaries import detect_trust_boundaries
from tfstride.analysis.stride_rules import StrideRuleEngine
from tfstride.models import TerraformResource
from tfstride.providers.azure.normalizer import AzureNormalizer
from tfstride.providers.azure.resource_facts import azure_facts
from tfstride.providers.azure.resource_types import AzureResourceType


def _resource(
    resource_type: str,
    name: str,
    values: dict[str, object],
) -> TerraformResource:
    return TerraformResource(
        address=f"{resource_type}.{name}",
        mode="managed",
        resource_type=resource_type,
        name=name,
        provider_name="registry.terraform.io/hashicorp/azurerm",
        values=values,
    )


def _account(
    *,
    allow_public: bool = True,
    public_network: bool = True,
    network_default_action: str | None = None,
) -> TerraformResource:
    values: dict[str, object] = {
        "id": "/subscriptions/example/resourceGroups/app/providers/Microsoft.Storage/storageAccounts/logs",
        "name": "tfstridelogs",
        "allow_nested_items_to_be_public": allow_public,
        "shared_access_key_enabled": False,
        "min_tls_version": "TLS1_2",
        "public_network_access_enabled": public_network,
    }
    if network_default_action is not None:
        values["network_rules"] = [{"default_action": network_default_action}]
    return _resource(AzureResourceType.STORAGE_ACCOUNT, "logs", values)


def _container(access_type: str = "blob") -> TerraformResource:
    return _resource(
        AzureResourceType.STORAGE_CONTAINER,
        "objects",
        {
            "name": "objects",
            "storage_account_id": "azurerm_storage_account.logs.id",
            "container_access_type": access_type,
        },
    )


class AzureResourceDecoratorTests(unittest.TestCase):
    def test_public_container_is_exposed_only_through_public_account(self) -> None:
        inventory = AzureNormalizer().normalize([_account(), _container()])
        account, container = inventory.resources

        self.assertTrue(account.direct_internet_reachable)
        self.assertTrue(account.public_exposure)
        self.assertTrue(container.public_access_configured)
        self.assertTrue(container.public_exposure)
        self.assertEqual(
            azure_facts(container).resolved_storage_account_address,
            "azurerm_storage_account.logs",
        )
        self.assertEqual(
            azure_facts(account).public_container_addresses,
            ["azurerm_storage_container.objects"],
        )

    def test_account_level_public_access_block_suppresses_container_exposure(self) -> None:
        inventory = AzureNormalizer().normalize([_account(allow_public=False), _container()])
        account, container = inventory.resources

        self.assertTrue(account.direct_internet_reachable)
        self.assertTrue(container.public_access_configured)
        self.assertFalse(container.public_exposure)
        self.assertEqual(azure_facts(account).public_container_addresses, [])

    def test_default_deny_network_rules_suppress_public_endpoint_and_container_exposure(self) -> None:
        inventory = AzureNormalizer().normalize([_account(network_default_action="Deny"), _container()])
        account, container = inventory.resources

        self.assertFalse(account.direct_internet_reachable)
        self.assertFalse(container.public_exposure)
        self.assertEqual(azure_facts(account).network_default_action, "Deny")

    def test_standalone_network_rules_replace_account_default(self) -> None:
        network_rules = _resource(
            AzureResourceType.STORAGE_ACCOUNT_NETWORK_RULES,
            "logs",
            {
                "storage_account_id": "azurerm_storage_account.logs.id",
                "default_action": "Deny",
            },
        )
        inventory = AzureNormalizer().normalize([_account(), network_rules, _container()])
        account, normalized_rules, container = inventory.resources

        self.assertFalse(account.direct_internet_reachable)
        self.assertFalse(container.public_exposure)
        self.assertEqual(azure_facts(account).network_default_action, "Deny")
        self.assertEqual(
            azure_facts(account).network_rule_source_address,
            "azurerm_storage_account_network_rules.logs",
        )
        self.assertEqual(
            azure_facts(normalized_rules).resolved_storage_account_address,
            account.address,
        )

    def test_compute_network_graph_is_resolved_end_to_end_without_exposure(self) -> None:
        resources = [
            _resource(
                AzureResourceType.VIRTUAL_NETWORK,
                "main",
                {"id": "/subscriptions/example/virtualNetworks/main", "name": "main", "address_space": ["10.0.0.0/16"]},
            ),
            _resource(
                AzureResourceType.SUBNET,
                "app",
                {
                    "id": "/subscriptions/example/subnets/app",
                    "name": "app",
                    "virtual_network_name": "azurerm_virtual_network.main.name",
                    "address_prefixes": ["10.0.1.0/24"],
                },
            ),
            _resource(
                AzureResourceType.NETWORK_SECURITY_GROUP,
                "web",
                {"id": "/subscriptions/example/networkSecurityGroups/web", "name": "web", "security_rule": []},
            ),
            _resource(
                AzureResourceType.NETWORK_SECURITY_RULE,
                "https",
                {
                    "name": "https",
                    "network_security_group_name": "azurerm_network_security_group.web.name",
                    "priority": 200,
                    "direction": "Inbound",
                    "access": "Allow",
                    "protocol": "Tcp",
                    "source_address_prefix": "Internet",
                    "destination_port_range": "443",
                },
            ),
            _resource(
                AzureResourceType.SUBNET_NETWORK_SECURITY_GROUP_ASSOCIATION,
                "app",
                {
                    "subnet_id": "azurerm_subnet.app.id",
                    "network_security_group_id": "azurerm_network_security_group.web.id",
                },
            ),
            _resource(
                AzureResourceType.PUBLIC_IP,
                "web",
                {"id": "/subscriptions/example/publicIPAddresses/web", "name": "web", "ip_address": "203.0.113.10"},
            ),
            _resource(
                AzureResourceType.NETWORK_INTERFACE,
                "web",
                {
                    "id": "/subscriptions/example/networkInterfaces/web",
                    "name": "web",
                    "ip_configuration": [
                        {
                            "name": "primary",
                            "subnet_id": "azurerm_subnet.app.id",
                            "public_ip_address_id": "azurerm_public_ip.web.id",
                        }
                    ],
                },
            ),
            _resource(
                AzureResourceType.LINUX_VIRTUAL_MACHINE,
                "web",
                {
                    "id": "/subscriptions/example/virtualMachines/web",
                    "name": "web",
                    "size": "Standard_B2s",
                    "network_interface_ids": ["azurerm_network_interface.web.id"],
                },
            ),
        ]

        inventory = AzureNormalizer().normalize(resources)
        by_address = {resource.address: resource for resource in inventory.resources}
        subnet = by_address["azurerm_subnet.app"]
        network_security_group = by_address["azurerm_network_security_group.web"]
        network_interface = by_address["azurerm_network_interface.web"]
        virtual_machine = by_address["azurerm_linux_virtual_machine.web"]

        self.assertEqual(subnet.vpc_id, "azurerm_virtual_network.main")
        self.assertEqual(subnet.security_group_ids, ("azurerm_network_security_group.web",))
        self.assertEqual(len(network_security_group.network_rules), 1)
        self.assertTrue(network_security_group.network_rules[0].allows_internet())
        self.assertIn("azurerm_subnet.app", network_interface.subnet_ids)
        self.assertIn("azurerm_network_security_group.web", network_interface.security_group_ids)
        self.assertEqual(azure_facts(network_interface).resolved_public_ip_addresses, ["azurerm_public_ip.web"])
        self.assertIn("azurerm_subnet.app", virtual_machine.subnet_ids)
        self.assertIn("azurerm_network_security_group.web", virtual_machine.security_group_ids)
        self.assertEqual(virtual_machine.vpc_id, "azurerm_virtual_network.main")
        self.assertTrue(virtual_machine.public_access_configured)
        self.assertFalse(virtual_machine.public_exposure)
        self.assertFalse(virtual_machine.direct_internet_reachable)
        boundaries = detect_trust_boundaries(inventory)
        self.assertEqual(boundaries, [])
        self.assertEqual(StrideRuleEngine().evaluate(inventory, boundaries), [])

    def test_unresolved_storage_account_references_are_recorded(self) -> None:
        inventory = AzureNormalizer().normalize([_container()])
        container = inventory.resources[0]

        self.assertFalse(container.public_exposure)
        self.assertEqual(
            container.metadata_snapshot()["unresolved_storage_account_references"],
            ["azurerm_storage_account.logs.id"],
        )


if __name__ == "__main__":
    unittest.main()
