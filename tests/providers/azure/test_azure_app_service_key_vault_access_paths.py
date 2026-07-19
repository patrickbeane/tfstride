from __future__ import annotations

import unittest

from tfstride.models import TerraformResource
from tfstride.providers.azure.normalizer import AzureNormalizer
from tfstride.providers.azure.resource_facts import azure_facts
from tfstride.providers.azure.resource_types import AzureResourceType

_VAULT_ID = "/subscriptions/sub-0001/resourceGroups/app/providers/Microsoft.KeyVault/vaults/orders"
_VAULT_URI = "https://orders.vault.azure.net"
_SECRET_URI = f"{_VAULT_URI}/secrets/database-password/secret-version"
_SECRET_VERSIONLESS_URI = f"{_VAULT_URI}/secrets/database-password"
_SECRET_RESOURCE_ID = f"{_VAULT_ID}/secrets/database-password"
_SYSTEM_PRINCIPAL_ID = "system-principal-id"
_USER_PRINCIPAL_ID = "user-principal-id"
_USER_IDENTITY_ID = (
    "/subscriptions/sub-0001/resourceGroups/app/providers/Microsoft.ManagedIdentity/userAssignedIdentities/runtime"
)


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


def _vault(*, rbac_enabled: bool = False, vault_uri: str = _VAULT_URI) -> TerraformResource:
    return _resource(
        AzureResourceType.KEY_VAULT,
        {
            "id": _VAULT_ID,
            "name": "orders",
            "vault_uri": vault_uri,
            "enable_rbac_authorization": rbac_enabled,
        },
        name="orders",
    )


def _secret() -> TerraformResource:
    return _resource(
        AzureResourceType.KEY_VAULT_SECRET,
        {
            "id": _SECRET_URI,
            "versionless_id": _SECRET_VERSIONLESS_URI,
            "resource_id": _SECRET_RESOURCE_ID,
            "name": "database-password",
            "version": "secret-version",
            "key_vault_id": "azurerm_key_vault.orders.id",
        },
        name="database_password",
    )


def _web_app(
    *,
    identity_type: str = "SystemAssigned",
    principal_id: object = _SYSTEM_PRINCIPAL_ID,
    identity_ids: list[str] | None = None,
    key_vault_reference_identity_id: object | None = None,
    secret_uri: str = _SECRET_URI,
    unknown_values: dict[str, object] | None = None,
) -> TerraformResource:
    values: dict[str, object] = {
        "id": "/subscriptions/sub-0001/resourceGroups/app/providers/Microsoft.Web/sites/api",
        "name": "api",
        "app_settings": {
            "DB_PASSWORD": f"@Microsoft.KeyVault(SecretUri={secret_uri})",
        },
        "identity": [
            {
                "type": identity_type,
                "principal_id": principal_id,
                "identity_ids": identity_ids or [],
            }
        ],
    }
    if key_vault_reference_identity_id is not None or (
        unknown_values and "key_vault_reference_identity_id" in unknown_values
    ):
        values["key_vault_reference_identity_id"] = key_vault_reference_identity_id
    return _resource(
        AzureResourceType.LINUX_WEB_APP,
        values,
        name="api",
        unknown_values=unknown_values,
    )


def _user_assigned_identity() -> TerraformResource:
    return _resource(
        AzureResourceType.USER_ASSIGNED_IDENTITY,
        {
            "id": _USER_IDENTITY_ID,
            "name": "runtime",
            "principal_id": _USER_PRINCIPAL_ID,
            "client_id": "runtime-client-id",
            "tenant_id": "tenant-id",
        },
        name="runtime",
    )


def _access_policy(
    *,
    object_id: str = _USER_PRINCIPAL_ID,
    secret_permissions: list[str] | None = None,
) -> TerraformResource:
    return _resource(
        AzureResourceType.KEY_VAULT_ACCESS_POLICY,
        {
            "key_vault_id": "azurerm_key_vault.orders.id",
            "tenant_id": "tenant-id",
            "object_id": object_id,
            "secret_permissions": secret_permissions or ["Get"],
        },
        name="runtime",
    )


def _role_assignment(
    *,
    principal_id: str = _SYSTEM_PRINCIPAL_ID,
    scope: str = "azurerm_key_vault.orders.id",
    role_name: str | None = "Key Vault Secrets User",
    role_definition_id: str = "/subscriptions/sub-0001/providers/Microsoft.Authorization/roleDefinitions/secrets-user",
    condition: object | None = None,
    unknown_values: dict[str, object] | None = None,
) -> TerraformResource:
    values: dict[str, object] = {
        "scope": scope,
        "role_definition_id": role_definition_id,
        "principal_id": principal_id,
        "principal_type": "ServicePrincipal",
    }
    if role_name is not None:
        values["role_definition_name"] = role_name
    if condition is not None:
        values["condition"] = condition
    return _resource(
        AzureResourceType.ROLE_ASSIGNMENT,
        values,
        name="secret_access",
        unknown_values=unknown_values,
    )


def _custom_role(*, not_data_actions: list[str] | None = None) -> TerraformResource:
    return _resource(
        AzureResourceType.ROLE_DEFINITION,
        {
            "id": "/subscriptions/sub-0001/providers/Microsoft.Authorization/roleDefinitions/custom-secret-reader",
            "name": "Custom Secret Reader",
            "scope": "/subscriptions/sub-0001",
            "assignable_scopes": ["/subscriptions/sub-0001"],
            "permissions": [
                {
                    "actions": [],
                    "not_actions": [],
                    "data_actions": ["Microsoft.KeyVault/vaults/secrets/*"],
                    "not_data_actions": not_data_actions or [],
                }
            ],
        },
        name="secret_reader",
    )


def _workload_facts(resources: list[TerraformResource]):
    inventory = AzureNormalizer().normalize(resources)
    workload = inventory.get_by_address("azurerm_linux_web_app.api")
    assert workload is not None
    return azure_facts(workload)


class AzureAppServiceKeyVaultAccessPathTests(unittest.TestCase):
    def test_explicit_user_assigned_identity_access_policy_path_is_modeled(self) -> None:
        facts = _workload_facts(
            [
                _vault(),
                _secret(),
                _user_assigned_identity(),
                _web_app(
                    identity_type="UserAssigned",
                    principal_id=None,
                    identity_ids=["azurerm_user_assigned_identity.runtime.id"],
                    key_vault_reference_identity_id="azurerm_user_assigned_identity.runtime.id",
                ),
                _access_policy(),
            ]
        )

        self.assertEqual(len(facts.app_service_key_vault_access_paths), 1)
        path = facts.app_service_key_vault_access_paths[0]
        self.assertEqual(path["identity_address"], "azurerm_user_assigned_identity.runtime")
        self.assertEqual(path["identity_kind"], "user_assigned")
        self.assertEqual(path["identity_resolution_basis"], "key_vault_reference_identity_id")
        self.assertEqual(path["key_vault_address"], "azurerm_key_vault.orders")
        self.assertEqual(path["secret_resource_address"], "azurerm_key_vault_secret.database_password")
        self.assertEqual(path["secret_uri"], _SECRET_URI)
        self.assertEqual(path["grant_kind"], "access_policy")
        self.assertEqual(path["grant_source_address"], "azurerm_key_vault_access_policy.runtime")
        self.assertEqual(path["secret_permissions"], ["get"])
        self.assertEqual(path["access_state"], "granted")
        self.assertEqual(facts.app_service_key_vault_access_path_uncertainties, [])

    def test_system_assigned_identity_vault_rbac_path_is_modeled(self) -> None:
        facts = _workload_facts(
            [
                _vault(rbac_enabled=True),
                _secret(),
                _web_app(),
                _role_assignment(),
            ]
        )

        self.assertEqual(len(facts.app_service_key_vault_access_paths), 1)
        path = facts.app_service_key_vault_access_paths[0]
        self.assertEqual(path["identity_address"], "azurerm_linux_web_app.api")
        self.assertEqual(path["identity_kind"], "system_assigned")
        self.assertEqual(path["identity_resolution_basis"], "system_assigned_identity")
        self.assertEqual(path["grant_kind"], "rbac")
        self.assertEqual(path["grant_scope_type"], "vault")
        self.assertEqual(path["role_definition_name"], "Key Vault Secrets User")
        self.assertEqual(path["role_kind"], "built_in")
        self.assertEqual(path["access_state"], "granted")

    def test_custom_role_secret_read_and_explicit_not_data_action_are_respected(self) -> None:
        custom_role_reference = "azurerm_role_definition.secret_reader.role_definition_resource_id"
        granted = _workload_facts(
            [
                _vault(rbac_enabled=True),
                _secret(),
                _web_app(),
                _custom_role(),
                _role_assignment(role_name=None, role_definition_id=custom_role_reference),
            ]
        )
        denied = _workload_facts(
            [
                _vault(rbac_enabled=True),
                _secret(),
                _web_app(),
                _custom_role(not_data_actions=["Microsoft.KeyVault/vaults/secrets/getSecret/action"]),
                _role_assignment(role_name=None, role_definition_id=custom_role_reference),
            ]
        )

        self.assertEqual(len(granted.app_service_key_vault_access_paths), 1)
        self.assertEqual(granted.app_service_key_vault_access_paths[0]["role_kind"], "custom")
        self.assertEqual(
            granted.app_service_key_vault_access_paths[0]["custom_role_address"],
            "azurerm_role_definition.secret_reader",
        )
        self.assertEqual(denied.app_service_key_vault_access_paths, [])

    def test_explicit_reference_identity_takes_precedence_over_system_identity(self) -> None:
        facts = _workload_facts(
            [
                _vault(rbac_enabled=True),
                _secret(),
                _user_assigned_identity(),
                _web_app(
                    identity_type="SystemAssigned, UserAssigned",
                    identity_ids=["azurerm_user_assigned_identity.runtime.id"],
                    key_vault_reference_identity_id=_USER_IDENTITY_ID,
                ),
                _role_assignment(principal_id=_SYSTEM_PRINCIPAL_ID),
            ]
        )

        self.assertEqual(facts.app_service_key_vault_access_paths, [])
        self.assertEqual(facts.app_service_key_vault_access_path_uncertainties, [])

    def test_list_only_access_policy_and_similarly_named_vault_do_not_create_paths(self) -> None:
        list_only = _workload_facts(
            [
                _vault(),
                _secret(),
                _web_app(),
                _access_policy(object_id=_SYSTEM_PRINCIPAL_ID, secret_permissions=["List"]),
            ]
        )
        wrong_vault = _workload_facts(
            [
                _vault(),
                _web_app(secret_uri="https://orders-copy.vault.azure.net/secrets/database-password"),
                _access_policy(object_id=_SYSTEM_PRINCIPAL_ID),
            ]
        )

        self.assertEqual(list_only.app_service_key_vault_access_paths, [])
        self.assertEqual(wrong_vault.app_service_key_vault_access_paths, [])
        self.assertEqual(
            wrong_vault.app_service_key_vault_access_path_uncertainties,
            ["azurerm_linux_web_app.api: Key Vault URI https://orders-copy.vault.azure.net is not modeled"],
        )

    def test_explicit_reference_identity_does_not_match_by_client_id(self) -> None:
        facts = _workload_facts(
            [
                _vault(),
                _secret(),
                _user_assigned_identity(),
                _web_app(
                    identity_type="UserAssigned",
                    principal_id=None,
                    identity_ids=["azurerm_user_assigned_identity.runtime.id"],
                    key_vault_reference_identity_id="runtime-client-id",
                ),
                _access_policy(),
            ]
        )

        self.assertEqual(facts.app_service_key_vault_access_paths, [])
        self.assertEqual(
            facts.app_service_key_vault_access_path_uncertainties,
            [
                "azurerm_linux_web_app.api: Key Vault reference identity runtime-client-id "
                "is not an exact user-assigned identity resource reference"
            ],
        )

    def test_unknown_explicit_reference_identity_does_not_fall_back_to_system_identity(self) -> None:
        facts = _workload_facts(
            [
                _vault(),
                _secret(),
                _web_app(
                    key_vault_reference_identity_id=None,
                    unknown_values={"key_vault_reference_identity_id": True},
                ),
                _access_policy(object_id=_SYSTEM_PRINCIPAL_ID),
            ]
        )

        self.assertEqual(facts.app_service_key_vault_access_paths, [])
        self.assertEqual(
            facts.app_service_key_vault_access_path_uncertainties,
            ["azurerm_linux_web_app.api: key_vault_reference_identity_id is unknown after planning"],
        )


if __name__ == "__main__":
    unittest.main()
