from __future__ import annotations

import unittest

from tfstride.models import TerraformResource
from tfstride.providers.azure.normalizer import AzureNormalizer
from tfstride.providers.azure.resource_facts import azure_facts
from tfstride.providers.azure.resource_types import AzureResourceType

_STORAGE_ACCOUNT_ID = (
    "/subscriptions/sub-0001/resourceGroups/app/providers/Microsoft.Storage/storageAccounts/ordersdata"
)
_STORAGE_CONTAINER_ID = f"{_STORAGE_ACCOUNT_ID}/blobServices/default/containers/orders"
_SYSTEM_PRINCIPAL_ID = "app-system-principal-id"
_USER_PRINCIPAL_ID = "app-user-principal-id"
_USER_IDENTITY_ID = (
    "/subscriptions/sub-0001/resourceGroups/app/providers/Microsoft.ManagedIdentity/"
    "userAssignedIdentities/orders-runtime"
)
_CUSTOM_ROLE_ID = "/subscriptions/sub-0001/providers/Microsoft.Authorization/roleDefinitions/custom-blob-writer"


def _resource(
    resource_type: str,
    values: dict[str, object],
    *,
    name: str,
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


def _storage_account() -> TerraformResource:
    return _resource(
        AzureResourceType.STORAGE_ACCOUNT,
        {
            "id": _STORAGE_ACCOUNT_ID,
            "name": "ordersdata",
            "public_network_access_enabled": False,
            "network_rules": [{"default_action": "Deny"}],
        },
        name="orders",
    )


def _storage_container() -> TerraformResource:
    return _resource(
        AzureResourceType.STORAGE_CONTAINER,
        {
            "id": _STORAGE_CONTAINER_ID,
            "name": "orders",
            "storage_account_id": "azurerm_storage_account.orders.id",
            "container_access_type": "private",
        },
        name="orders",
    )


def _web_app(
    *,
    identity_type: str = "SystemAssigned",
    principal_id: object = _SYSTEM_PRINCIPAL_ID,
    identity_ids: list[str] | None = None,
) -> TerraformResource:
    return _resource(
        AzureResourceType.LINUX_WEB_APP,
        {
            "id": "/subscriptions/sub-0001/resourceGroups/app/providers/Microsoft.Web/sites/orders",
            "name": "orders",
            "identity": [
                {
                    "type": identity_type,
                    "principal_id": principal_id,
                    "tenant_id": "tenant-id",
                    "identity_ids": identity_ids or [],
                }
            ],
        },
        name="orders",
    )


def _function_app() -> TerraformResource:
    return _resource(
        AzureResourceType.LINUX_FUNCTION_APP,
        {
            "id": "/subscriptions/sub-0001/resourceGroups/app/providers/Microsoft.Web/sites/orders-worker",
            "name": "orders-worker",
            "identity": [
                {
                    "type": "UserAssigned",
                    "identity_ids": ["azurerm_user_assigned_identity.orders_runtime.id"],
                }
            ],
        },
        name="orders_worker",
    )


def _user_assigned_identity() -> TerraformResource:
    return _resource(
        AzureResourceType.USER_ASSIGNED_IDENTITY,
        {
            "id": _USER_IDENTITY_ID,
            "name": "orders-runtime",
            "principal_id": _USER_PRINCIPAL_ID,
            "client_id": "orders-runtime-client-id",
            "tenant_id": "tenant-id",
        },
        name="orders_runtime",
    )


def _role_assignment(
    *,
    principal_id: object = _SYSTEM_PRINCIPAL_ID,
    scope: object = "azurerm_storage_account.orders.id",
    role_name: object = "Storage Blob Data Contributor",
    role_definition_id: object = (
        "/subscriptions/sub-0001/providers/Microsoft.Authorization/roleDefinitions/ba92f5b4-2d11-453d-a403-e96b0029c9fe"
    ),
    condition: object | None = None,
    unknown_values: dict[str, object] | None = None,
    name: str = "orders_blob",
) -> TerraformResource:
    values: dict[str, object] = {
        "scope": scope,
        "role_definition_name": role_name,
        "role_definition_id": role_definition_id,
        "principal_id": principal_id,
        "principal_type": "ServicePrincipal",
    }
    if condition is not None:
        values["condition"] = condition
    return _resource(
        AzureResourceType.ROLE_ASSIGNMENT,
        values,
        name=name,
        unknown_values=unknown_values,
    )


def _custom_role(
    *,
    data_actions: list[str],
    not_data_actions: list[str] | None = None,
    unknown_values: dict[str, object] | None = None,
) -> TerraformResource:
    return _resource(
        AzureResourceType.ROLE_DEFINITION,
        {
            "id": _CUSTOM_ROLE_ID,
            "name": "Custom Blob Writer",
            "scope": "/subscriptions/sub-0001",
            "assignable_scopes": ["/subscriptions/sub-0001"],
            "permissions": [
                {
                    "actions": [],
                    "not_actions": [],
                    "data_actions": data_actions,
                    "not_data_actions": not_data_actions or [],
                }
            ],
        },
        name="blob_writer",
        unknown_values=unknown_values,
    )


def _custom_role_assignment(*, scope: object = "azurerm_storage_account.orders.id") -> TerraformResource:
    return _role_assignment(
        scope=scope,
        role_name=None,
        role_definition_id="azurerm_role_definition.blob_writer.role_definition_resource_id",
    )


class AzureAppServiceStorageAccessPathTests(unittest.TestCase):
    def test_system_assigned_app_service_blob_contributor_path_is_modeled(self) -> None:
        inventory = AzureNormalizer().normalize([_storage_account(), _web_app(), _role_assignment()])
        workload = inventory.get_by_address("azurerm_linux_web_app.orders")
        assert workload is not None

        facts = azure_facts(workload)
        self.assertEqual(len(facts.app_service_storage_access_paths), 1)
        path = facts.app_service_storage_access_paths[0]
        self.assertEqual(path["workload_address"], workload.address)
        self.assertEqual(path["identity_address"], workload.address)
        self.assertEqual(path["identity_kind"], "system_assigned")
        self.assertEqual(path["principal_id"], _SYSTEM_PRINCIPAL_ID)
        self.assertEqual(path["storage_resource_address"], "azurerm_storage_account.orders")
        self.assertEqual(path["storage_resource_type"], AzureResourceType.STORAGE_ACCOUNT)
        self.assertEqual(path["storage_account_id"], _STORAGE_ACCOUNT_ID)
        self.assertIsNone(path["container_address"])
        self.assertEqual(path["role_kind"], "blob_data_contributor")
        self.assertEqual(path["access_classes"], ["read", "write", "delete"])
        self.assertEqual(path["resource_scope"], "exact_storage_account")
        self.assertEqual(path["access_state"], "granted")
        self.assertEqual(facts.app_service_storage_access_path_uncertainties, [])

    def test_user_assigned_function_identity_blob_owner_path_is_modeled(self) -> None:
        inventory = AzureNormalizer().normalize(
            [
                _storage_account(),
                _user_assigned_identity(),
                _function_app(),
                _role_assignment(
                    principal_id=_USER_PRINCIPAL_ID,
                    role_name="Storage Blob Data Owner",
                    role_definition_id=(
                        "/subscriptions/sub-0001/providers/Microsoft.Authorization/roleDefinitions/"
                        "b7e6dc6d-f1e8-4753-8033-0f276bb0955b"
                    ),
                ),
            ]
        )
        workload = inventory.get_by_address("azurerm_linux_function_app.orders_worker")
        assert workload is not None

        paths = azure_facts(workload).app_service_storage_access_paths
        self.assertEqual(len(paths), 1)
        self.assertEqual(paths[0]["identity_address"], "azurerm_user_assigned_identity.orders_runtime")
        self.assertEqual(paths[0]["identity_kind"], "user_assigned")
        self.assertEqual(paths[0]["principal_id"], _USER_PRINCIPAL_ID)
        self.assertEqual(paths[0]["role_kind"], "blob_data_owner")
        self.assertEqual(paths[0]["access_classes"], ["read", "write", "delete", "administrative"])

    def test_blob_reader_is_resolved_by_name_and_authoritative_role_id(self) -> None:
        by_name = AzureNormalizer().normalize(
            [
                _storage_account(),
                _web_app(),
                _role_assignment(
                    role_name="Storage Blob Data Reader",
                    role_definition_id="noncanonical-reader-id",
                ),
            ]
        )
        by_id = AzureNormalizer().normalize(
            [
                _storage_account(),
                _web_app(),
                _role_assignment(
                    role_name="Storage Blob Data Owner",
                    role_definition_id=(
                        "/subscriptions/sub-0001/providers/Microsoft.Authorization/roleDefinitions/"
                        "2a2b9908-6ea1-4ae2-8e65-a410df84e7d1"
                    ),
                ),
            ]
        )
        by_name_workload = by_name.get_by_address("azurerm_linux_web_app.orders")
        by_id_workload = by_id.get_by_address("azurerm_linux_web_app.orders")
        assert by_name_workload is not None
        assert by_id_workload is not None

        for workload in (by_name_workload, by_id_workload):
            paths = azure_facts(workload).app_service_storage_access_paths
            self.assertEqual(len(paths), 1)
            self.assertEqual(paths[0]["role_definition_name"], "Storage Blob Data Reader")
            self.assertEqual(paths[0]["role_kind"], "blob_data_reader")
            self.assertEqual(paths[0]["access_classes"], ["read"])

    def test_container_resource_manager_scope_is_resolved_exactly(self) -> None:
        inventory = AzureNormalizer().normalize(
            [
                _storage_account(),
                _storage_container(),
                _web_app(),
                _role_assignment(scope="azurerm_storage_container.orders.resource_manager_id"),
            ]
        )
        workload = inventory.get_by_address("azurerm_linux_web_app.orders")
        assert workload is not None

        paths = azure_facts(workload).app_service_storage_access_paths
        self.assertEqual(len(paths), 1)
        path = paths[0]
        self.assertEqual(path["storage_resource_address"], "azurerm_storage_container.orders")
        self.assertEqual(path["storage_resource_id"], _STORAGE_CONTAINER_ID)
        self.assertEqual(path["storage_account_address"], "azurerm_storage_account.orders")
        self.assertEqual(path["container_address"], "azurerm_storage_container.orders")
        self.assertEqual(path["resource_scope"], "exact_storage_container")

    def test_custom_blob_data_actions_and_not_data_actions_are_classified(self) -> None:
        permission = "Microsoft.Storage/storageAccounts/blobServices/containers/blobs/*"
        excluded = [
            "Microsoft.Storage/storageAccounts/blobServices/containers/blobs/delete",
            "Microsoft.Storage/storageAccounts/blobServices/containers/blobs/deleteBlobVersion/action",
            "Microsoft.Storage/storageAccounts/blobServices/containers/blobs/permanentDelete/action",
        ]
        inventory = AzureNormalizer().normalize(
            [
                _storage_account(),
                _web_app(),
                _custom_role(data_actions=[permission], not_data_actions=excluded),
                _custom_role_assignment(),
            ]
        )
        workload = inventory.get_by_address("azurerm_linux_web_app.orders")
        assert workload is not None

        paths = azure_facts(workload).app_service_storage_access_paths
        self.assertEqual(len(paths), 1)
        path = paths[0]
        self.assertEqual(path["role_kind"], "custom")
        self.assertEqual(path["grant_basis"], "azure_custom_role_storage_scoped_rbac")
        self.assertEqual(path["role_definition_address"], "azurerm_role_definition.blob_writer")
        self.assertEqual(path["custom_role_data_actions"], [permission])
        self.assertEqual(path["custom_role_not_data_actions"], excluded)
        self.assertEqual(path["access_classes"], ["read", "write", "administrative"])
        self.assertEqual(
            path["excluded_data_actions"],
            [
                "microsoft.storage/storageaccounts/blobservices/containers/blobs/delete",
                "microsoft.storage/storageaccounts/blobservices/containers/blobs/deleteblobversion/action",
                "microsoft.storage/storageaccounts/blobservices/containers/blobs/permanentdelete/action",
            ],
        )

    def test_custom_destructive_blob_data_actions_are_classified_as_delete(self) -> None:
        destructive_actions = [
            "Microsoft.Storage/storageAccounts/blobServices/containers/blobs/deleteBlobVersion/action",
            "Microsoft.Storage/storageAccounts/blobServices/containers/blobs/permanentDelete/action",
        ]
        inventory = AzureNormalizer().normalize(
            [
                _storage_account(),
                _web_app(),
                _custom_role(data_actions=destructive_actions),
                _custom_role_assignment(),
            ]
        )
        workload = inventory.get_by_address("azurerm_linux_web_app.orders")
        assert workload is not None

        path = azure_facts(workload).app_service_storage_access_paths[0]
        self.assertEqual(path["access_classes"], ["delete"])
        self.assertEqual(
            path["matched_data_actions"],
            [action.lower() for action in destructive_actions],
        )

    def test_control_plane_and_invalid_blob_actions_do_not_create_data_path(self) -> None:
        actions = (
            "Microsoft.Storage/storageAccounts/blobServices/containers/delete",
            "Microsoft.Storage/storageAccounts/blobServices/containers/blobs/restore/action",
        )
        for action in actions:
            with self.subTest(action=action):
                inventory = AzureNormalizer().normalize(
                    [
                        _storage_account(),
                        _web_app(),
                        _custom_role(data_actions=[action]),
                        _custom_role_assignment(),
                    ]
                )
                workload = inventory.get_by_address("azurerm_linux_web_app.orders")
                assert workload is not None

                self.assertEqual(azure_facts(workload).app_service_storage_access_paths, [])

    def test_conditional_assignment_is_preserved_as_conditional_access(self) -> None:
        condition = "@Resource[Microsoft.Storage/storageAccounts/blobServices/containers:name] StringEquals 'orders'"
        inventory = AzureNormalizer().normalize(
            [
                _storage_account(),
                _web_app(),
                _role_assignment(condition=condition),
            ]
        )
        workload = inventory.get_by_address("azurerm_linux_web_app.orders")
        assert workload is not None

        path = azure_facts(workload).app_service_storage_access_paths[0]
        self.assertEqual(path["condition"], condition)
        self.assertEqual(path["condition_state"], "configured")
        self.assertEqual(path["access_state"], "conditional")

    def test_unresolved_condition_scope_and_custom_actions_do_not_invent_access(self) -> None:
        unknown_condition = AzureNormalizer().normalize(
            [
                _storage_account(),
                _web_app(),
                _role_assignment(unknown_values={"condition": True}),
            ]
        )
        unresolved_scope = AzureNormalizer().normalize(
            [
                _storage_account(),
                _web_app(),
                _role_assignment(scope="azurerm_storage_account.orders_archive.id"),
            ]
        )
        unresolved_actions = AzureNormalizer().normalize(
            [
                _storage_account(),
                _web_app(),
                _custom_role(
                    data_actions=[],
                    unknown_values={"permissions": [{"data_actions": True}]},
                ),
                _custom_role_assignment(),
            ]
        )

        condition_workload = unknown_condition.get_by_address("azurerm_linux_web_app.orders")
        scope_workload = unresolved_scope.get_by_address("azurerm_linux_web_app.orders")
        actions_workload = unresolved_actions.get_by_address("azurerm_linux_web_app.orders")
        assert condition_workload is not None
        assert scope_workload is not None
        assert actions_workload is not None

        self.assertEqual(azure_facts(condition_workload).app_service_storage_access_paths, [])
        self.assertTrue(
            any(
                "condition is unresolved" in value
                for value in azure_facts(condition_workload).app_service_storage_access_path_uncertainties
            )
        )
        self.assertEqual(azure_facts(scope_workload).app_service_storage_access_paths, [])
        self.assertTrue(
            any(
                "does not resolve to an exact Storage Account or container" in value
                for value in azure_facts(scope_workload).app_service_storage_access_path_uncertainties
            )
        )
        self.assertEqual(azure_facts(actions_workload).app_service_storage_access_paths, [])
        self.assertTrue(
            any(
                "data actions are unresolved" in value
                for value in azure_facts(actions_workload).app_service_storage_access_path_uncertainties
            )
        )

    def test_non_blob_role_and_other_principal_stay_quiet(self) -> None:
        non_blob = AzureNormalizer().normalize(
            [
                _storage_account(),
                _web_app(),
                _role_assignment(role_name="Reader", role_definition_id="reader"),
            ]
        )
        other_principal = AzureNormalizer().normalize(
            [
                _storage_account(),
                _web_app(),
                _role_assignment(principal_id="other-principal-id"),
            ]
        )
        non_blob_workload = non_blob.get_by_address("azurerm_linux_web_app.orders")
        other_workload = other_principal.get_by_address("azurerm_linux_web_app.orders")
        assert non_blob_workload is not None
        assert other_workload is not None

        self.assertEqual(azure_facts(non_blob_workload).app_service_storage_access_paths, [])
        self.assertEqual(azure_facts(other_workload).app_service_storage_access_paths, [])


if __name__ == "__main__":
    unittest.main()
