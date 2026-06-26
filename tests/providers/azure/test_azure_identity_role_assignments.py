from __future__ import annotations

import unittest

from tfstride.models import TerraformResource
from tfstride.providers.azure.normalizer import AzureNormalizer
from tfstride.providers.azure.observations import observe_azure_posture
from tfstride.providers.azure.resource_facts import azure_facts
from tfstride.providers.azure.resource_types import AzureResourceType


def _resource(
    resource_type: str,
    values: dict[str, object],
    *,
    name: str = "example",
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


def _user_assigned_identity(
    *,
    principal_id: str = "managed-principal-id",
    name: str = "deploy",
) -> TerraformResource:
    return _resource(
        AzureResourceType.USER_ASSIGNED_IDENTITY,
        {
            "name": name,
            "principal_id": principal_id,
            "client_id": f"{name}-client-id",
            "tenant_id": "tenant-id",
        },
        name=name,
    )


def _linux_virtual_machine(
    *,
    principal_id: str = "system-principal-id",
    name: str = "web",
) -> TerraformResource:
    return _resource(
        AzureResourceType.LINUX_VIRTUAL_MACHINE,
        {
            "name": name,
            "network_interface_ids": [],
            "identity": [
                {
                    "type": "SystemAssigned",
                    "principal_id": principal_id,
                    "tenant_id": "tenant-id",
                    "identity_ids": [],
                }
            ],
        },
        name=name,
    )


def _role_assignment(
    *,
    principal_id: object = "managed-principal-id",
    scope: object = "/subscriptions/sub-0001",
    role_definition_name: object = "Reader",
    role_definition_id: object = "/subscriptions/sub-0001/providers/Microsoft.Authorization/roleDefinitions/reader",
    name: str = "assignment",
    unknown_values: dict[str, object] | None = None,
) -> TerraformResource:
    return _resource(
        AzureResourceType.ROLE_ASSIGNMENT,
        {
            "scope": scope,
            "role_definition_name": role_definition_name,
            "role_definition_id": role_definition_id,
            "principal_id": principal_id,
            "principal_type": "ServicePrincipal",
        },
        name=name,
        unknown_values=unknown_values,
    )


def _storage_account() -> TerraformResource:
    return _resource(
        AzureResourceType.STORAGE_ACCOUNT,
        {
            "id": "/subscriptions/sub-0001/resourceGroups/app/providers/Microsoft.Storage/storageAccounts/logs",
            "name": "logs",
            "allow_nested_items_to_be_public": False,
            "shared_access_key_enabled": False,
            "min_tls_version": "TLS1_2",
            "public_network_access_enabled": False,
            "network_rules": [{"default_action": "Deny"}],
        },
        name="logs",
    )


class AzureManagedIdentityRoleAssignmentTests(unittest.TestCase):
    def test_role_assignment_matches_system_assigned_identity_principal_id(self) -> None:
        inventory = AzureNormalizer().normalize(
            [
                _linux_virtual_machine(principal_id="system-principal-id"),
                _role_assignment(
                    principal_id="system-principal-id",
                    role_definition_name="Reader",
                    name="vm_reader",
                ),
            ]
        )
        virtual_machine = inventory.get_by_address("azurerm_linux_virtual_machine.web")
        role_assignment = inventory.get_by_address("azurerm_role_assignment.vm_reader")
        assert virtual_machine is not None
        assert role_assignment is not None

        identity_facts = azure_facts(virtual_machine)
        assignment_facts = azure_facts(role_assignment)

        self.assertEqual(assignment_facts.resolved_managed_identity_address, virtual_machine.address)
        self.assertEqual(len(identity_facts.managed_identity_role_assignments), 1)
        self.assertEqual(
            identity_facts.managed_identity_role_assignments[0],
            {
                "source": role_assignment.address,
                "scope": "/subscriptions/sub-0001",
                "role_definition_name": "Reader",
                "role_definition_id": (
                    "/subscriptions/sub-0001/providers/Microsoft.Authorization/roleDefinitions/reader"
                ),
                "principal_id": "system-principal-id",
                "principal_type": "ServicePrincipal",
                "scope_kind": "subscription",
                "target_resource_address": None,
                "target_resource_type": None,
                "breadth_signals": ["subscription_scope"],
            },
        )
        self.assertIn(
            "azure-managed-identity-role-assignment-observed",
            [observation.observation_id for observation in observe_azure_posture(inventory)],
        )

    def test_unknown_principal_id_does_not_connect_role_assignment(self) -> None:
        inventory = AzureNormalizer().normalize(
            [
                _user_assigned_identity(principal_id="managed-principal-id"),
                _role_assignment(
                    principal_id=None,
                    role_definition_name="Contributor",
                    name="unknown_principal",
                    unknown_values={"principal_id": True},
                ),
            ]
        )
        identity = inventory.get_by_address("azurerm_user_assigned_identity.deploy")
        role_assignment = inventory.get_by_address("azurerm_role_assignment.unknown_principal")
        assert identity is not None
        assert role_assignment is not None

        identity_facts = azure_facts(identity)
        assignment_facts = azure_facts(role_assignment)

        self.assertEqual(identity_facts.managed_identity_role_assignments, [])
        self.assertIsNone(assignment_facts.resolved_managed_identity_address)
        self.assertEqual(assignment_facts.role_assignment_scope_kind, "subscription")
        self.assertEqual(
            assignment_facts.role_assignment_breadth_signals,
            ["subscription_scope", "broad_builtin_role"],
        )
        self.assertIn(
            "principal_id is unknown after planning",
            assignment_facts.key_vault_authorization_uncertainties,
        )

    def test_subscription_and_resource_group_scope_breadth_signals_are_preserved(self) -> None:
        inventory = AzureNormalizer().normalize(
            [
                _user_assigned_identity(principal_id="managed-principal-id"),
                _role_assignment(
                    scope="/subscriptions/sub-0001",
                    role_definition_name="Owner",
                    name="subscription_owner",
                ),
                _role_assignment(
                    scope="/subscriptions/sub-0001/resourceGroups/app",
                    role_definition_name="Contributor",
                    name="resource_group_contributor",
                ),
            ]
        )
        identity = inventory.get_by_address("azurerm_user_assigned_identity.deploy")
        subscription_assignment = inventory.get_by_address("azurerm_role_assignment.subscription_owner")
        resource_group_assignment = inventory.get_by_address("azurerm_role_assignment.resource_group_contributor")
        assert identity is not None
        assert subscription_assignment is not None
        assert resource_group_assignment is not None

        self.assertEqual(
            azure_facts(subscription_assignment).role_assignment_breadth_signals,
            ["subscription_scope", "broad_builtin_role"],
        )
        self.assertEqual(azure_facts(subscription_assignment).role_assignment_scope_kind, "subscription")
        self.assertEqual(
            azure_facts(resource_group_assignment).role_assignment_breadth_signals,
            ["resource_group_scope", "broad_builtin_role"],
        )
        self.assertEqual(azure_facts(resource_group_assignment).role_assignment_scope_kind, "resource_group")
        self.assertEqual(
            [assignment["scope_kind"] for assignment in azure_facts(identity).managed_identity_role_assignments],
            ["subscription", "resource_group"],
        )

    def test_sensitive_resource_scope_resolves_target_resource_context(self) -> None:
        inventory = AzureNormalizer().normalize(
            [
                _storage_account(),
                _user_assigned_identity(principal_id="managed-principal-id"),
                _role_assignment(
                    scope="azurerm_storage_account.logs.id",
                    role_definition_name="Storage Blob Data Owner",
                    name="storage_owner",
                ),
            ]
        )
        identity = inventory.get_by_address("azurerm_user_assigned_identity.deploy")
        role_assignment = inventory.get_by_address("azurerm_role_assignment.storage_owner")
        assert identity is not None
        assert role_assignment is not None

        assignment_facts = azure_facts(role_assignment)
        self.assertEqual(assignment_facts.resolved_managed_identity_address, identity.address)
        self.assertEqual(assignment_facts.role_assignment_scope_kind, "resource")
        self.assertEqual(
            assignment_facts.role_assignment_breadth_signals,
            ["broad_builtin_role", "sensitive_resource_scope"],
        )
        self.assertEqual(
            assignment_facts.role_assignment_target_resource_address,
            "azurerm_storage_account.logs",
        )
        self.assertEqual(
            assignment_facts.role_assignment_target_resource_type,
            AzureResourceType.STORAGE_ACCOUNT,
        )
        self.assertEqual(
            azure_facts(identity).managed_identity_role_assignments[0]["target_resource_address"],
            "azurerm_storage_account.logs",
        )


if __name__ == "__main__":
    unittest.main()
