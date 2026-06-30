from __future__ import annotations

import unittest

from tests.helpers.paths import FIXTURES_DIR
from tfstride.app import TfStride
from tfstride.input.terraform_plan import load_terraform_plan
from tfstride.models import ResourceCategory, TerraformResource
from tfstride.providers.azure.network_normalizers import normalize_private_endpoint
from tfstride.providers.azure.normalizer import AzureNormalizer
from tfstride.providers.azure.resource_facts import azure_facts
from tfstride.providers.azure.resource_types import AzureResourceType

PRIVATE_ENDPOINT_FIXTURE_PATH = FIXTURES_DIR / "azure" / "sample_azure_private_endpoint_plan.json"


def _resource(
    values: dict[str, object],
    *,
    name: str = "storage",
    unknown_values: dict[str, object] | None = None,
) -> TerraformResource:
    return TerraformResource(
        address=f"azurerm_private_endpoint.{name}",
        mode="managed",
        resource_type=AzureResourceType.PRIVATE_ENDPOINT,
        name=name,
        provider_name="registry.terraform.io/hashicorp/azurerm",
        values=values,
        unknown_values=unknown_values or {},
    )


class AzurePrivateEndpointNormalizerTests(unittest.TestCase):
    def test_private_endpoint_preserves_storage_service_connection_evidence(self) -> None:
        normalized = normalize_private_endpoint(
            _resource(
                {
                    "id": "/subscriptions/example/privateEndpoints/storage",
                    "name": "storage-pe",
                    "location": "eastus",
                    "subnet_id": "azurerm_subnet.private.id",
                    "private_service_connection": [
                        {
                            "name": "storage-blob",
                            "private_connection_resource_id": "azurerm_storage_account.logs.id",
                            "subresource_names": ["blob"],
                            "is_manual_connection": False,
                        }
                    ],
                }
            )
        )
        facts = azure_facts(normalized)

        self.assertEqual(normalized.address, "azurerm_private_endpoint.storage")
        self.assertEqual(normalized.category, ResourceCategory.NETWORK)
        self.assertEqual(normalized.subnet_ids, ("azurerm_subnet.private.id",))
        self.assertEqual(facts.name, "storage-pe")
        self.assertEqual(facts.private_endpoint_id, "/subscriptions/example/privateEndpoints/storage")
        self.assertEqual(facts.private_connection_resource_ids, ["azurerm_storage_account.logs.id"])
        self.assertEqual(facts.private_endpoint_subresource_names, ["blob"])
        self.assertEqual(
            facts.private_service_connections,
            [
                {
                    "name": "storage-blob",
                    "private_connection_resource_id": "azurerm_storage_account.logs.id",
                    "subresource_names": ["blob"],
                    "is_manual_connection": False,
                }
            ],
        )

    def test_private_endpoint_preserves_multiple_subresources_and_dns_group_evidence(self) -> None:
        normalized = normalize_private_endpoint(
            _resource(
                {
                    "name": "storage-pe",
                    "subnet_id": "azurerm_subnet.private.id",
                    "private_service_connection": [
                        {
                            "name": "storage-services",
                            "private_connection_resource_id": "azurerm_storage_account.logs.id",
                            "subresource_names": ["blob", "file"],
                            "is_manual_connection": True,
                        }
                    ],
                    "private_dns_zone_group": [
                        {
                            "name": "storage-dns",
                            "private_dns_zone_ids": [
                                "azurerm_private_dns_zone.blob.id",
                                "azurerm_private_dns_zone.file.id",
                            ],
                        }
                    ],
                }
            )
        )
        facts = azure_facts(normalized)

        self.assertEqual(facts.private_endpoint_subresource_names, ["blob", "file"])
        self.assertEqual(facts.private_dns_zone_group_names, ["storage-dns"])
        self.assertEqual(
            facts.private_dns_zone_ids,
            ["azurerm_private_dns_zone.blob.id", "azurerm_private_dns_zone.file.id"],
        )
        self.assertTrue(facts.private_service_connections[0]["is_manual_connection"])
        self.assertEqual(
            facts.private_dns_zone_groups,
            [
                {
                    "name": "storage-dns",
                    "private_dns_zone_ids": [
                        "azurerm_private_dns_zone.blob.id",
                        "azurerm_private_dns_zone.file.id",
                    ],
                }
            ],
        )

    def test_unresolved_private_connection_resource_id_string_is_preserved(self) -> None:
        normalized = normalize_private_endpoint(
            _resource(
                {
                    "name": "storage-pe",
                    "private_service_connection": [
                        {
                            "name": "storage-blob",
                            "private_connection_resource_id": "${azurerm_storage_account.logs.id}",
                            "subresource_names": ["blob"],
                        }
                    ],
                }
            )
        )
        facts = azure_facts(normalized)

        self.assertEqual(facts.private_connection_resource_ids, ["${azurerm_storage_account.logs.id}"])
        self.assertEqual(
            facts.private_service_connections[0]["private_connection_resource_id"],
            "${azurerm_storage_account.logs.id}",
        )

    def test_unknown_private_endpoint_values_are_explicit_uncertainties(self) -> None:
        normalized = normalize_private_endpoint(
            _resource(
                {
                    "name": "pending",
                    "subnet_id": None,
                    "private_service_connection": [
                        {
                            "name": "pending",
                            "private_connection_resource_id": None,
                            "subresource_names": [],
                            "is_manual_connection": None,
                        }
                    ],
                    "private_dns_zone_group": [
                        {
                            "name": "pending-dns",
                            "private_dns_zone_ids": [],
                        }
                    ],
                },
                unknown_values={
                    "subnet_id": True,
                    "private_service_connection": [
                        {
                            "private_connection_resource_id": True,
                            "subresource_names": True,
                            "is_manual_connection": True,
                        }
                    ],
                    "private_dns_zone_group": [{"private_dns_zone_ids": True}],
                },
            )
        )
        facts = azure_facts(normalized)

        self.assertEqual(normalized.subnet_ids, ())
        self.assertEqual(
            facts.private_endpoint_uncertainties,
            [
                "subnet_id is unknown after planning",
                "private_service_connection[0].private_connection_resource_id is unknown after planning",
                "private_service_connection[0].subresource_names is unknown after planning",
                "private_service_connection[0].is_manual_connection is unknown after planning",
                "private_dns_zone_group[0].private_dns_zone_ids is unknown after planning",
            ],
        )
        self.assertEqual(
            facts.private_service_connections,
            [
                {
                    "name": "pending",
                    "subresource_names": [],
                    "unknown_fields": [
                        "private_connection_resource_id",
                        "subresource_names",
                        "is_manual_connection",
                    ],
                }
            ],
        )
        self.assertEqual(facts.private_dns_zone_group_names, ["pending-dns"])
        self.assertEqual(facts.private_dns_zone_ids, [])
        self.assertEqual(
            facts.private_dns_zone_groups,
            [{"name": "pending-dns", "private_dns_zone_ids": [], "unknown_fields": ["private_dns_zone_ids"]}],
        )

    def test_private_endpoint_fixture_normalizes_without_findings(self) -> None:
        plan = load_terraform_plan(PRIVATE_ENDPOINT_FIXTURE_PATH)
        inventory = AzureNormalizer().normalize(plan.resources)
        endpoint = inventory.get_by_address("azurerm_private_endpoint.storage")
        assert endpoint is not None
        facts = azure_facts(endpoint)

        self.assertEqual(inventory.provider, "azure")
        self.assertEqual(inventory.unsupported_resources, [])
        self.assertEqual(facts.private_connection_resource_ids, ["azurerm_storage_account.logs.id"])
        self.assertEqual(facts.private_endpoint_subresource_names, ["blob", "file"])
        self.assertEqual(
            facts.private_dns_zone_groups[0]["private_dns_zone_ids"],
            ["azurerm_private_dns_zone.blob.id", "azurerm_private_dns_zone.file.id"],
        )
        self.assertEqual(facts.private_dns_zone_group_names, ["storage-dns"])
        self.assertEqual(
            facts.private_dns_zone_ids,
            ["azurerm_private_dns_zone.blob.id", "azurerm_private_dns_zone.file.id"],
        )

        result = TfStride().analyze_plan(PRIVATE_ENDPOINT_FIXTURE_PATH)
        self.assertEqual(result.findings, [])
        self.assertEqual(result.trust_boundaries, [])


if __name__ == "__main__":
    unittest.main()
