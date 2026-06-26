from __future__ import annotations

import unittest

from tfstride.models import TerraformResource
from tfstride.providers.azure.normalizer import AzureNormalizer
from tfstride.providers.azure.resource_facts import azure_facts
from tfstride.providers.azure.resource_types import AzureResourceType


def _resource(
    resource_type: str,
    name: str,
    values: dict[str, object],
    *,
    unknown_values: dict[str, object] | None = None,
) -> TerraformResource:
    return TerraformResource(
        address=f"{resource_type}.{name}",
        mode="managed",
        resource_type=resource_type,
        name=name,
        provider_name="registry.terraform.io/hashicorp/azurerm",
        values=values,
        unknown_values=unknown_values or {},
    )


def _nsg(
    name: str,
    rules: list[dict[str, object]],
    *,
    unknown_values: dict[str, object] | None = None,
) -> TerraformResource:
    return _resource(
        AzureResourceType.NETWORK_SECURITY_GROUP,
        name,
        {
            "id": f"/subscriptions/sub-0001/resourceGroups/app/providers/Microsoft.Network/networkSecurityGroups/{name}",
            "name": name,
            "security_rule": rules,
        },
        unknown_values=unknown_values,
    )


def _ingress_rule(
    name: str,
    *,
    priority: int | None,
    access: str = "Allow",
    protocol: str = "Tcp",
    port: str = "22",
    source: str = "Internet",
) -> dict[str, object]:
    return {
        "name": name,
        "priority": priority,
        "direction": "Inbound",
        "access": access,
        "protocol": protocol,
        "source_address_prefix": source,
        "source_port_range": "*",
        "destination_address_prefix": "*",
        "destination_port_range": port,
    }


def _compute_graph(*nsgs: TerraformResource, attach_subnet_nsg: bool = False) -> list[TerraformResource]:
    resources = [
        _resource(
            AzureResourceType.SUBNET,
            "web",
            {
                "id": "/subscriptions/sub-0001/resourceGroups/app/providers/Microsoft.Network/virtualNetworks/main/subnets/web",
                "name": "web",
                "address_prefixes": ["10.0.1.0/24"],
            },
        ),
        *nsgs,
        _resource(
            AzureResourceType.PUBLIC_IP,
            "web",
            {
                "id": "/subscriptions/sub-0001/resourceGroups/app/providers/Microsoft.Network/publicIPAddresses/web",
                "name": "web",
                "ip_address": "203.0.113.20",
            },
        ),
        _resource(
            AzureResourceType.NETWORK_INTERFACE,
            "web",
            {
                "id": "/subscriptions/sub-0001/resourceGroups/app/providers/Microsoft.Network/networkInterfaces/web",
                "name": "web",
                "ip_configuration": [
                    {
                        "name": "primary",
                        "subnet_id": "azurerm_subnet.web.id",
                        "public_ip_address_id": "azurerm_public_ip.web.id",
                    }
                ],
            },
        ),
        _resource(
            AzureResourceType.NETWORK_INTERFACE_SECURITY_GROUP_ASSOCIATION,
            "web",
            {
                "network_interface_id": "azurerm_network_interface.web.id",
                "network_security_group_id": "azurerm_network_security_group.web_nic.id",
            },
        ),
        _resource(
            AzureResourceType.LINUX_VIRTUAL_MACHINE,
            "web",
            {
                "id": "/subscriptions/sub-0001/resourceGroups/app/providers/Microsoft.Compute/virtualMachines/web",
                "name": "web",
                "network_interface_ids": ["azurerm_network_interface.web.id"],
            },
        ),
    ]
    if attach_subnet_nsg:
        resources.append(
            _resource(
                AzureResourceType.SUBNET_NETWORK_SECURITY_GROUP_ASSOCIATION,
                "web",
                {
                    "subnet_id": "azurerm_subnet.web.id",
                    "network_security_group_id": "azurerm_network_security_group.web_subnet.id",
                },
            )
        )
    return resources


def _public_compute_paths(resources: list[TerraformResource]) -> list[dict]:
    inventory = AzureNormalizer().normalize(resources)
    virtual_machine = inventory.get_by_address("azurerm_linux_virtual_machine.web")
    assert virtual_machine is not None
    return azure_facts(virtual_machine).public_compute_exposure_paths


class AzureNsgIngressPrecedenceTests(unittest.TestCase):
    def test_broad_allow_creates_public_compute_path(self) -> None:
        paths = _public_compute_paths(_compute_graph(_nsg("web_nic", [_ingress_rule("allow-ssh", priority=200)])))

        self.assertEqual([(path["protocol"], path["from_port"], path["to_port"]) for path in paths], [("tcp", 22, 22)])
        self.assertTrue(any("allow-ssh priority 200" in rule for rule in paths[0]["network_security_rules"]))

    def test_deny_before_later_allow_blocks_comparable_public_ingress(self) -> None:
        paths = _public_compute_paths(
            _compute_graph(
                _nsg(
                    "web_nic",
                    [
                        _ingress_rule("allow-ssh", priority=200),
                        _ingress_rule("deny-ssh", priority=100, access="Deny"),
                    ],
                )
            )
        )

        self.assertEqual(paths, [])

    def test_allow_before_later_deny_keeps_public_ingress(self) -> None:
        paths = _public_compute_paths(
            _compute_graph(
                _nsg(
                    "web_nic",
                    [
                        _ingress_rule("deny-ssh", priority=200, access="Deny"),
                        _ingress_rule("allow-ssh", priority=100),
                    ],
                )
            )
        )

        self.assertEqual([(path["protocol"], path["from_port"], path["to_port"]) for path in paths], [("tcp", 22, 22)])
        self.assertTrue(any("allow-ssh priority 100" in rule for rule in paths[0]["network_security_rules"]))

    def test_unknown_priority_does_not_infer_public_ingress(self) -> None:
        inventory = AzureNormalizer().normalize(
            _compute_graph(
                _nsg(
                    "web_nic",
                    [_ingress_rule("allow-ssh", priority=None)],
                    unknown_values={"security_rule": [{"priority": True}]},
                )
            )
        )
        virtual_machine = inventory.get_by_address("azurerm_linux_virtual_machine.web")
        network_security_group = inventory.get_by_address("azurerm_network_security_group.web_nic")
        assert virtual_machine is not None
        assert network_security_group is not None

        self.assertEqual(azure_facts(virtual_machine).public_compute_exposure_paths, [])
        self.assertEqual(
            azure_facts(network_security_group).network_security_rules[0].get("unknown_decision_fields"),
            ["priority"],
        )
        self.assertEqual(network_security_group.network_rules, [])

    def test_subnet_and_nic_associations_are_both_required_for_effective_ingress(self) -> None:
        paths = _public_compute_paths(
            _compute_graph(
                _nsg("web_subnet", [_ingress_rule("allow-internet", priority=300, port="*")]),
                _nsg("web_nic", [_ingress_rule("allow-ssh", priority=200)]),
                attach_subnet_nsg=True,
            )
        )

        self.assertEqual([(path["protocol"], path["from_port"], path["to_port"]) for path in paths], [("tcp", 22, 22)])
        self.assertEqual(
            paths[0]["network_security_groups"],
            [
                "azurerm_network_security_group.web_nic",
                "azurerm_network_security_group.web_subnet",
            ],
        )


if __name__ == "__main__":
    unittest.main()
