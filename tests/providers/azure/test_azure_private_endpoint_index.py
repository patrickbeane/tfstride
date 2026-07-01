from __future__ import annotations

import unittest

from tfstride.models import TerraformResource
from tfstride.providers.azure.normalizer import AzureNormalizer
from tfstride.providers.azure.private_endpoint_index import (
    build_azure_private_endpoint_index,
)
from tfstride.providers.azure.resource_types import AzureResourceType

_STORAGE_ID = "/subscriptions/sub-0001/resourceGroups/app/providers/Microsoft.Storage/storageAccounts/logs"
_KEY_VAULT_ID = "/subscriptions/sub-0001/resourceGroups/app/providers/Microsoft.KeyVault/vaults/app"
_MSSQL_ID = "/subscriptions/sub-0001/resourceGroups/app/providers/Microsoft.Sql/servers/app-sql"


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


def _storage_account(
    *,
    name: str = "logs",
    storage_id: str = _STORAGE_ID,
    account_name: str = "logs",
) -> TerraformResource:
    return _resource(
        AzureResourceType.STORAGE_ACCOUNT,
        name,
        {
            "id": storage_id,
            "name": account_name,
            "allow_nested_items_to_be_public": False,
            "shared_access_key_enabled": False,
            "min_tls_version": "TLS1_2",
            "public_network_access_enabled": False,
        },
    )


def _key_vault(*, name: str = "app", vault_id: str = _KEY_VAULT_ID) -> TerraformResource:
    return _resource(
        AzureResourceType.KEY_VAULT,
        name,
        {
            "id": vault_id,
            "name": name,
            "public_network_access_enabled": False,
            "purge_protection_enabled": True,
        },
    )


def _mssql_server(*, name: str = "app", server_id: str = _MSSQL_ID) -> TerraformResource:
    return _resource(
        AzureResourceType.MSSQL_SERVER,
        name,
        {
            "id": server_id,
            "name": name,
            "public_network_access_enabled": False,
            "minimum_tls_version": "1.2",
        },
    )


def _private_endpoint(
    name: str,
    target_id: str,
    *,
    subresources: tuple[str, ...] = ("blob",),
    connection_name: str | None = None,
    dns_zone_ids: tuple[str, ...] = (),
    dns_group_name: str = "private-dns",
) -> TerraformResource:
    values: dict[str, object] = {
        "name": f"{name}-pe",
        "private_service_connection": [
            {
                "name": connection_name or f"{name}-connection",
                "private_connection_resource_id": target_id,
                "subresource_names": list(subresources),
                "is_manual_connection": False,
            }
        ],
    }
    if dns_zone_ids:
        values["private_dns_zone_group"] = [{"name": dns_group_name, "private_dns_zone_ids": list(dns_zone_ids)}]
    return _resource(AzureResourceType.PRIVATE_ENDPOINT, name, values)


def _normalized(*resources: TerraformResource):
    return AzureNormalizer().normalize(list(resources))


class AzurePrivateEndpointIndexTests(unittest.TestCase):
    def test_resolved_private_endpoint_targets_storage_account(self) -> None:
        inventory = _normalized(
            _storage_account(),
            _private_endpoint("logs_blob", _STORAGE_ID, subresources=("blob",)),
        )
        storage = inventory.get_by_address("azurerm_storage_account.logs")
        assert storage is not None

        index = build_azure_private_endpoint_index(inventory)
        coverage = index.coverage_for(storage)

        self.assertTrue(coverage.has_private_endpoint)
        self.assertTrue(index.has_private_endpoint(storage))
        self.assertEqual(tuple(index.connections_by_target_key), (_STORAGE_ID.lower(),))
        self.assertEqual(index.private_endpoint_addresses_for(storage), ("azurerm_private_endpoint.logs_blob",))
        self.assertEqual(index.subresource_names_for(storage), ("blob",))
        self.assertEqual(coverage.connections[0].target_resource_id, _STORAGE_ID)
        self.assertEqual(coverage.connections[0].subresource_names, ("blob",))
        self.assertEqual(coverage.connections[0].private_dns_zone_group_state, "not_configured")
        self.assertEqual(coverage.connections[0].private_dns_zone_ids_state, "not_configured")
        self.assertEqual(index.unresolved_targets, ())

    def test_resolved_private_endpoint_targets_key_vault(self) -> None:
        inventory = _normalized(
            _key_vault(),
            _private_endpoint("vault", _KEY_VAULT_ID, subresources=("vault",)),
        )
        vault = inventory.get_by_address("azurerm_key_vault.app")
        assert vault is not None

        coverage = build_azure_private_endpoint_index(inventory).coverage_for(vault)

        self.assertTrue(coverage.has_private_endpoint)
        self.assertEqual(coverage.private_endpoint_addresses, ("azurerm_private_endpoint.vault",))
        self.assertEqual(coverage.subresource_names, ("vault",))

    def test_resolved_private_endpoint_targets_mssql_server(self) -> None:
        inventory = _normalized(
            _mssql_server(),
            _private_endpoint("sql", _MSSQL_ID, subresources=("sqlServer",)),
        )
        server = inventory.get_by_address("azurerm_mssql_server.app")
        assert server is not None

        coverage = build_azure_private_endpoint_index(inventory).coverage_for(server)

        self.assertTrue(coverage.has_private_endpoint)
        self.assertEqual(coverage.private_endpoint_addresses, ("azurerm_private_endpoint.sql",))
        self.assertEqual(coverage.subresource_names, ("sqlServer",))

    def test_terraform_id_reference_target_resolves_deterministically(self) -> None:
        inventory = _normalized(
            _storage_account(),
            _private_endpoint("logs_blob", "azurerm_storage_account.logs.id"),
        )
        storage = inventory.get_by_address("azurerm_storage_account.logs")
        assert storage is not None

        coverage = build_azure_private_endpoint_index(inventory).coverage_for(storage)

        self.assertTrue(coverage.has_private_endpoint)
        self.assertEqual(coverage.connections[0].target_resource_id, "azurerm_storage_account.logs.id")

    def test_private_dns_zone_group_evidence_is_preserved(self) -> None:
        inventory = _normalized(
            _storage_account(),
            _private_endpoint(
                "logs_blob",
                _STORAGE_ID,
                subresources=("blob", "file"),
                dns_zone_ids=("azurerm_private_dns_zone.blob.id", "azurerm_private_dns_zone.file.id"),
                dns_group_name="storage-dns",
            ),
        )
        storage = inventory.get_by_address("azurerm_storage_account.logs")
        assert storage is not None

        coverage = build_azure_private_endpoint_index(inventory).coverage_for(storage)

        self.assertEqual(coverage.private_dns_zone_group_names, ("storage-dns",))
        self.assertEqual(
            coverage.private_dns_zone_ids,
            ("azurerm_private_dns_zone.blob.id", "azurerm_private_dns_zone.file.id"),
        )
        self.assertEqual(coverage.connections[0].private_dns_zone_group_names, ("storage-dns",))
        self.assertEqual(coverage.connections[0].private_dns_zone_group_state, "configured")
        self.assertEqual(coverage.connections[0].private_dns_zone_ids_state, "configured")
        self.assertEqual(
            coverage.connections[0].private_dns_zone_ids,
            ("azurerm_private_dns_zone.blob.id", "azurerm_private_dns_zone.file.id"),
        )

    def test_unresolved_private_connection_resource_id_is_retained(self) -> None:
        inventory = _normalized(
            _storage_account(),
            _private_endpoint("external", "${data.azurerm_storage_account.external.id}"),
        )
        storage = inventory.get_by_address("azurerm_storage_account.logs")
        assert storage is not None

        index = build_azure_private_endpoint_index(inventory)

        self.assertFalse(index.has_private_endpoint(storage))
        self.assertEqual(len(index.unresolved_targets), 1)
        self.assertEqual(index.unresolved_targets[0].private_endpoint_address, "azurerm_private_endpoint.external")
        self.assertEqual(
            index.unresolved_targets[0].target_resource_id,
            "${data.azurerm_storage_account.external.id}",
        )
        self.assertEqual(index.unresolved_targets[0].subresource_names, ("blob",))

    def test_similarly_named_resources_are_not_matched_by_name(self) -> None:
        inventory = _normalized(
            _storage_account(account_name="shared"),
            _private_endpoint("name_only", "shared"),
        )
        storage = inventory.get_by_address("azurerm_storage_account.logs")
        assert storage is not None

        index = build_azure_private_endpoint_index(inventory)

        self.assertFalse(index.has_private_endpoint(storage))
        self.assertEqual(len(index.unresolved_targets), 1)
        self.assertEqual(index.unresolved_targets[0].target_resource_id, "shared")

    def test_multiple_private_endpoints_targeting_same_resource_are_preserved(self) -> None:
        inventory = _normalized(
            _storage_account(),
            _private_endpoint("logs_blob", _STORAGE_ID, subresources=("blob",)),
            _private_endpoint("logs_file", _STORAGE_ID, subresources=("file",)),
        )
        storage = inventory.get_by_address("azurerm_storage_account.logs")
        assert storage is not None

        coverage = build_azure_private_endpoint_index(inventory).coverage_for(storage)

        self.assertEqual(
            coverage.private_endpoint_addresses,
            ("azurerm_private_endpoint.logs_blob", "azurerm_private_endpoint.logs_file"),
        )
        self.assertEqual(coverage.subresource_names, ("blob", "file"))
        self.assertEqual([connection.subresource_names for connection in coverage.connections], [("blob",), ("file",)])


if __name__ == "__main__":
    unittest.main()
