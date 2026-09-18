from __future__ import annotations

import unittest

from tfstride.models import TerraformResource
from tfstride.providers.azure.metadata import AzureResourceMetadata
from tfstride.providers.azure.normalizer import AzureNormalizer
from tfstride.providers.azure.private_endpoint_index import (
    build_azure_private_endpoint_index,
)
from tfstride.providers.azure.resource_facts import azure_facts
from tfstride.providers.azure.resource_types import AzureResourceType

_STORAGE_ID = "/subscriptions/sub-0001/resourceGroups/app/providers/Microsoft.Storage/storageAccounts/logs"
_KEY_VAULT_ID = "/subscriptions/sub-0001/resourceGroups/app/providers/Microsoft.KeyVault/vaults/app"
_MSSQL_ID = "/subscriptions/sub-0001/resourceGroups/app/providers/Microsoft.Sql/servers/app-sql"
_SERVICE_BUS_NAMESPACE_ID = (
    "/subscriptions/sub-0001/resourceGroups/app/providers/Microsoft.ServiceBus/namespaces/events"
)
_CONTAINER_REGISTRY_ID = (
    "/subscriptions/sub-0001/resourceGroups/app/providers/Microsoft.ContainerRegistry/registries/images"
)
_COSMOSDB_ID = "/subscriptions/sub-0001/resourceGroups/app/providers/Microsoft.DocumentDB/databaseAccounts/orders"


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


def _service_bus_namespace(
    *,
    name: str = "events",
    namespace_id: str = _SERVICE_BUS_NAMESPACE_ID,
    namespace_name: str = "events",
) -> TerraformResource:
    return _resource(
        AzureResourceType.SERVICE_BUS_NAMESPACE,
        name,
        {
            "id": namespace_id,
            "name": namespace_name,
            "sku": "Premium",
            "public_network_access_enabled": False,
        },
    )


def _container_registry(
    *,
    name: str = "images",
    registry_id: str = _CONTAINER_REGISTRY_ID,
    registry_name: str = "images",
) -> TerraformResource:
    return _resource(
        AzureResourceType.CONTAINER_REGISTRY,
        name,
        {
            "id": registry_id,
            "name": registry_name,
            "sku": "Premium",
            "public_network_access_enabled": False,
        },
    )


def _cosmosdb_account(
    *,
    name: str = "orders",
    account_id: str = _COSMOSDB_ID,
    account_name: str = "orders",
) -> TerraformResource:
    return _resource(
        AzureResourceType.COSMOSDB_ACCOUNT,
        name,
        {
            "id": account_id,
            "name": account_name,
            "location": "eastus",
            "offer_type": "Standard",
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
        self.assertEqual(tuple(index.connections_by_target_key), (_STORAGE_ID.lower(),))
        self.assertEqual(coverage.private_endpoint_addresses, ("azurerm_private_endpoint.logs_blob",))
        self.assertEqual(coverage.subresource_names, ("blob",))
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

    def test_resolved_private_endpoint_targets_service_bus_namespace(self) -> None:
        inventory = _normalized(
            _service_bus_namespace(),
            _private_endpoint(
                "events",
                _SERVICE_BUS_NAMESPACE_ID,
                subresources=("namespace",),
                dns_zone_ids=("azurerm_private_dns_zone.servicebus.id",),
                dns_group_name="servicebus-dns",
            ),
        )
        namespace = inventory.get_by_address("azurerm_servicebus_namespace.events")
        assert namespace is not None

        coverage = build_azure_private_endpoint_index(inventory).coverage_for(namespace)

        self.assertTrue(coverage.has_private_endpoint)
        self.assertEqual(coverage.private_endpoint_addresses, ("azurerm_private_endpoint.events",))
        self.assertEqual(coverage.subresource_names, ("namespace",))
        self.assertEqual(coverage.private_dns_zone_group_names, ("servicebus-dns",))
        self.assertEqual(coverage.private_dns_zone_ids, ("azurerm_private_dns_zone.servicebus.id",))
        self.assertEqual(coverage.connections[0].target_resource_id, _SERVICE_BUS_NAMESPACE_ID)

    def test_service_bus_terraform_address_reference_resolves_deterministically(self) -> None:
        inventory = _normalized(
            _service_bus_namespace(),
            _private_endpoint("events", "azurerm_servicebus_namespace.events.id", subresources=("namespace",)),
        )
        namespace = inventory.get_by_address("azurerm_servicebus_namespace.events")
        assert namespace is not None

        coverage = build_azure_private_endpoint_index(inventory).coverage_for(namespace)

        self.assertTrue(coverage.has_private_endpoint)
        self.assertEqual(coverage.connections[0].target_resource_id, "azurerm_servicebus_namespace.events.id")

    def test_unresolved_service_bus_namespace_id_is_retained(self) -> None:
        target_id = "${data.azurerm_servicebus_namespace.external.id}"
        inventory = _normalized(
            _service_bus_namespace(),
            _private_endpoint("external", target_id, subresources=("namespace",)),
        )
        namespace = inventory.get_by_address("azurerm_servicebus_namespace.events")
        assert namespace is not None

        index = build_azure_private_endpoint_index(inventory)

        self.assertFalse(index.coverage_for(namespace).has_private_endpoint)
        self.assertEqual(len(index.unresolved_targets), 1)
        self.assertEqual(index.unresolved_targets[0].target_resource_id, target_id)
        self.assertEqual(index.unresolved_targets[0].subresource_names, ("namespace",))

    def test_service_bus_namespace_name_does_not_create_private_endpoint_coverage(self) -> None:
        inventory = _normalized(
            _service_bus_namespace(namespace_name="shared"),
            _private_endpoint("name_only", "shared", subresources=("namespace",)),
        )
        namespace = inventory.get_by_address("azurerm_servicebus_namespace.events")
        assert namespace is not None

        index = build_azure_private_endpoint_index(inventory)

        self.assertFalse(index.coverage_for(namespace).has_private_endpoint)
        self.assertEqual(len(index.unresolved_targets), 1)
        self.assertEqual(index.unresolved_targets[0].target_resource_id, "shared")

    def test_resolved_private_endpoint_targets_container_registry(self) -> None:
        inventory = _normalized(
            _container_registry(),
            _private_endpoint(
                "images",
                _CONTAINER_REGISTRY_ID,
                subresources=("registry",),
                dns_zone_ids=("azurerm_private_dns_zone.registry.id",),
                dns_group_name="registry-dns",
            ),
        )
        registry = inventory.get_by_address("azurerm_container_registry.images")
        assert registry is not None

        coverage = build_azure_private_endpoint_index(inventory).coverage_for(registry)

        self.assertTrue(coverage.has_private_endpoint)
        self.assertEqual(coverage.private_endpoint_addresses, ("azurerm_private_endpoint.images",))
        self.assertEqual(coverage.subresource_names, ("registry",))
        self.assertEqual(coverage.private_dns_zone_group_names, ("registry-dns",))
        self.assertEqual(coverage.private_dns_zone_ids, ("azurerm_private_dns_zone.registry.id",))
        self.assertEqual(coverage.connections[0].target_resource_id, _CONTAINER_REGISTRY_ID)

    def test_container_registry_terraform_address_reference_resolves_deterministically(self) -> None:
        inventory = _normalized(
            _container_registry(),
            _private_endpoint(
                "images",
                "azurerm_container_registry.images.id",
                subresources=("registry",),
            ),
        )
        registry = inventory.get_by_address("azurerm_container_registry.images")
        assert registry is not None

        coverage = build_azure_private_endpoint_index(inventory).coverage_for(registry)

        self.assertTrue(coverage.has_private_endpoint)
        self.assertEqual(coverage.connections[0].target_resource_id, "azurerm_container_registry.images.id")

    def test_unresolved_container_registry_target_is_retained(self) -> None:
        target_id = "${data.azurerm_container_registry.external.id}"
        inventory = _normalized(
            _container_registry(),
            _private_endpoint("external", target_id, subresources=("registry",)),
        )
        registry = inventory.get_by_address("azurerm_container_registry.images")
        assert registry is not None

        index = build_azure_private_endpoint_index(inventory)

        self.assertFalse(index.coverage_for(registry).has_private_endpoint)
        self.assertEqual(len(index.unresolved_targets), 1)
        self.assertEqual(index.unresolved_targets[0].target_resource_id, target_id)
        self.assertEqual(index.unresolved_targets[0].subresource_names, ("registry",))

    def test_container_registry_name_does_not_create_private_endpoint_coverage(self) -> None:
        inventory = _normalized(
            _container_registry(registry_name="shared"),
            _private_endpoint("name_only", "shared", subresources=("registry",)),
        )
        registry = inventory.get_by_address("azurerm_container_registry.images")
        assert registry is not None

        index = build_azure_private_endpoint_index(inventory)

        self.assertFalse(index.coverage_for(registry).has_private_endpoint)
        self.assertEqual(len(index.unresolved_targets), 1)
        self.assertEqual(index.unresolved_targets[0].target_resource_id, "shared")

    def test_resolved_private_endpoint_targets_cosmos_db_account(self) -> None:
        inventory = _normalized(
            _cosmosdb_account(),
            _private_endpoint(
                "orders",
                _COSMOSDB_ID,
                subresources=("Sql",),
                dns_zone_ids=("azurerm_private_dns_zone.cosmos.id",),
                dns_group_name="cosmos-dns",
            ),
        )
        account = inventory.get_by_address("azurerm_cosmosdb_account.orders")
        assert account is not None

        index = build_azure_private_endpoint_index(inventory)
        coverage = index.coverage_for(account)

        self.assertTrue(coverage.has_private_endpoint)
        self.assertEqual(tuple(index.connections_by_target_key), (_COSMOSDB_ID.lower(),))
        self.assertEqual(coverage.private_endpoint_addresses, ("azurerm_private_endpoint.orders",))
        self.assertEqual(coverage.subresource_names, ("Sql",))
        self.assertEqual(coverage.private_dns_zone_group_names, ("cosmos-dns",))
        self.assertEqual(coverage.private_dns_zone_ids, ("azurerm_private_dns_zone.cosmos.id",))
        self.assertEqual(coverage.connections[0].target_resource_id, _COSMOSDB_ID)
        self.assertEqual(coverage.connections[0].subresource_names, ("Sql",))
        self.assertEqual(index.unresolved_targets, ())

    def test_cosmosdb_terraform_address_reference_resolves_deterministically(self) -> None:
        inventory = _normalized(
            _cosmosdb_account(),
            _private_endpoint(
                "orders",
                "azurerm_cosmosdb_account.orders.id",
                subresources=("Sql",),
            ),
        )
        account = inventory.get_by_address("azurerm_cosmosdb_account.orders")
        assert account is not None

        coverage = build_azure_private_endpoint_index(inventory).coverage_for(account)

        self.assertTrue(coverage.has_private_endpoint)
        self.assertEqual(
            coverage.connections[0].target_resource_id,
            "azurerm_cosmosdb_account.orders.id",
        )

    def test_unresolved_cosmosdb_target_is_retained(self) -> None:
        target_id = "${data.azurerm_cosmosdb_account.external.id}"
        inventory = _normalized(
            _cosmosdb_account(),
            _private_endpoint("external", target_id, subresources=("Sql",)),
        )
        account = inventory.get_by_address("azurerm_cosmosdb_account.orders")
        assert account is not None

        index = build_azure_private_endpoint_index(inventory)

        self.assertFalse(index.coverage_for(account).has_private_endpoint)
        self.assertEqual(len(index.unresolved_targets), 1)
        self.assertEqual(index.unresolved_targets[0].target_resource_id, target_id)
        self.assertEqual(index.unresolved_targets[0].subresource_names, ("Sql",))

    def test_cosmosdb_account_name_does_not_create_private_endpoint_coverage(self) -> None:
        inventory = _normalized(
            _cosmosdb_account(account_name="shared"),
            _private_endpoint("name_only", "shared", subresources=("Sql",)),
        )
        account = inventory.get_by_address("azurerm_cosmosdb_account.orders")
        assert account is not None

        index = build_azure_private_endpoint_index(inventory)

        self.assertFalse(index.coverage_for(account).has_private_endpoint)
        self.assertEqual(len(index.unresolved_targets), 1)
        self.assertEqual(index.unresolved_targets[0].target_resource_id, "shared")

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

        self.assertFalse(index.coverage_for(storage).has_private_endpoint)
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

        self.assertFalse(index.coverage_for(storage).has_private_endpoint)
        self.assertEqual(len(index.unresolved_targets), 1)
        self.assertEqual(index.unresolved_targets[0].target_resource_id, "shared")

    def test_exact_terraform_target_disambiguates_duplicate_arm_identity_by_input_order(
        self,
    ) -> None:
        first_account = _storage_account(
            name="first",
            storage_id=_STORAGE_ID,
            account_name="first",
        )
        second_account = _storage_account(
            name="second",
            storage_id=_STORAGE_ID,
            account_name="second",
        )

        for accounts in (
            (first_account, second_account),
            (second_account, first_account),
        ):
            inventory = _normalized(
                *accounts,
                _private_endpoint("first", _STORAGE_ID),
            )
            first = inventory.get_by_address(first_account.address)
            second = inventory.get_by_address(second_account.address)
            endpoint = inventory.get_by_address("azurerm_private_endpoint.first")
            assert first is not None
            assert second is not None
            assert endpoint is not None
            endpoint_facts = azure_facts(endpoint)
            connections = [dict(connection) for connection in endpoint_facts.private_service_connections]
            connections[0]["resolved_target_resource_address"] = first.address
            endpoint_facts.set(AzureResourceMetadata.PRIVATE_SERVICE_CONNECTIONS, connections)

            index = build_azure_private_endpoint_index(inventory)

            with self.subTest(order=[account.address for account in accounts]):
                self.assertTrue(index.coverage_for(first).has_private_endpoint)
                self.assertFalse(index.coverage_for(second).has_private_endpoint)
                self.assertEqual(index.unresolved_targets, ())

    def test_duplicate_arm_targets_do_not_receive_private_endpoint_coverage_by_input_order(
        self,
    ) -> None:
        first_account = _storage_account(
            name="first",
            storage_id=_STORAGE_ID,
            account_name="first",
        )
        second_account = _storage_account(
            name="second",
            storage_id=_STORAGE_ID,
            account_name="second",
        )

        for accounts in (
            (first_account, second_account),
            (second_account, first_account),
        ):
            inventory = _normalized(
                *accounts,
                _private_endpoint("shared", _STORAGE_ID),
            )
            first = inventory.get_by_address(first_account.address)
            second = inventory.get_by_address(second_account.address)
            assert first is not None
            assert second is not None

            index = build_azure_private_endpoint_index(inventory)

            with self.subTest(order=[account.address for account in accounts]):
                self.assertFalse(index.coverage_for(first).has_private_endpoint)
                self.assertFalse(index.coverage_for(second).has_private_endpoint)
                self.assertEqual(len(index.unresolved_targets), 1)
                self.assertEqual(index.unresolved_targets[0].target_resource_id, _STORAGE_ID)

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
