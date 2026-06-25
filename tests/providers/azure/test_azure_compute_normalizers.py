from __future__ import annotations

import unittest

from tfstride.models import ResourceCategory, TerraformResource
from tfstride.providers.azure.compute_normalizers import (
    normalize_linux_virtual_machine,
    normalize_windows_virtual_machine,
)
from tfstride.providers.azure.resource_facts import azure_facts
from tfstride.providers.azure.resource_types import AzureResourceType


def _resource(resource_type: str, values: dict[str, object], *, name: str = "web") -> TerraformResource:
    return TerraformResource(
        address=f"{resource_type}.{name}",
        mode="managed",
        resource_type=resource_type,
        name=name,
        provider_name="registry.terraform.io/hashicorp/azurerm",
        values=values,
    )


class AzureComputeNormalizerTests(unittest.TestCase):
    def test_linux_virtual_machine_normalizes_network_interface_references(self) -> None:
        virtual_machine = normalize_linux_virtual_machine(
            _resource(
                AzureResourceType.LINUX_VIRTUAL_MACHINE,
                {
                    "id": "/subscriptions/example/virtualMachines/web",
                    "name": "web",
                    "size": "Standard_B2s",
                    "network_interface_ids": ["azurerm_network_interface.web.id"],
                },
            )
        )

        self.assertEqual(virtual_machine.category, ResourceCategory.COMPUTE)
        self.assertEqual(
            azure_facts(virtual_machine).network_interface_references, ["azurerm_network_interface.web.id"]
        )
        self.assertEqual(azure_facts(virtual_machine).vm_size, "Standard_B2s")
        self.assertEqual(azure_facts(virtual_machine).os_type, "linux")
        self.assertFalse(virtual_machine.public_access_configured)

    def test_windows_virtual_machine_preserves_exported_public_ip_without_inferring_exposure(self) -> None:
        virtual_machine = normalize_windows_virtual_machine(
            _resource(
                AzureResourceType.WINDOWS_VIRTUAL_MACHINE,
                {"name": "admin", "network_interface_ids": [], "public_ip_address": "203.0.113.20"},
                name="admin",
            )
        )

        self.assertEqual(azure_facts(virtual_machine).os_type, "windows")
        self.assertTrue(virtual_machine.public_access_configured)
        self.assertFalse(virtual_machine.public_exposure)
        self.assertFalse(virtual_machine.direct_internet_reachable)


if __name__ == "__main__":
    unittest.main()
