from __future__ import annotations

import unittest

from tfstride.identity import AssignmentScopeKind, PrincipalType, PrivilegeCategory, PrivilegeConfidence
from tfstride.models import TerraformResource
from tfstride.providers.azure.metadata import AzureResourceMetadata
from tfstride.providers.azure.normalizer import AzureNormalizer
from tfstride.providers.azure.observations import observe_azure_posture
from tfstride.providers.azure.rbac_breadth import (
    AUTHORIZATION_MANAGEMENT,
    OWNER_LIKE_OR_WILDCARD,
    ROLE_ASSIGNMENT_CAPABLE,
    STORAGE_DATA_PLANE,
)
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


def _role_definition(
    *,
    role_definition_id: object = "/subscriptions/sub-0001/providers/Microsoft.Authorization/roleDefinitions/custom-role",
    name: str = "custom_role",
    role_name: object = "Custom Storage Operator",
    actions: list[str] | None = None,
    not_actions: list[str] | None = None,
    data_actions: list[str] | None = None,
    not_data_actions: list[str] | None = None,
) -> TerraformResource:
    return _resource(
        AzureResourceType.ROLE_DEFINITION,
        {
            "id": role_definition_id,
            "name": role_name,
            "scope": "/subscriptions/sub-0001",
            "assignable_scopes": ["/subscriptions/sub-0001"],
            "permissions": [
                {
                    "actions": actions or [],
                    "not_actions": not_actions or [],
                    "data_actions": data_actions or [],
                    "not_data_actions": not_data_actions or [],
                }
            ],
        },
        name=name,
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

        grants = azure_facts(identity).privileged_access_grants
        self.assertEqual(len(grants), 2)
        self.assertEqual([grant.role_name for grant in grants], ["Owner", "Contributor"])
        self.assertEqual(grants[0].provider, "azure")
        self.assertEqual(grants[0].principal.principal_type, PrincipalType.MANAGED_IDENTITY)
        self.assertEqual(grants[0].principal.identifier, "managed-principal-id")
        self.assertEqual(grants[0].principal.source_address, identity.address)
        self.assertEqual(grants[0].assignment_scope.scope_kind, AssignmentScopeKind.SUBSCRIPTION)
        self.assertEqual(grants[0].assignment_scope.value, "/subscriptions/sub-0001")
        self.assertEqual(
            grants[0].privilege_categories,
            (
                PrivilegeCategory.FULL_ADMIN,
                PrivilegeCategory.IAM_ADMIN,
                PrivilegeCategory.POLICY_ADMIN,
            ),
        )
        self.assertEqual(grants[0].confidence, PrivilegeConfidence.HIGH)
        self.assertIn("Owner", grants[0].permission_patterns)
        self.assertIn("breadth_signal=subscription_scope", grants[0].evidence)
        self.assertEqual(grants[1].assignment_scope.scope_kind, AssignmentScopeKind.RESOURCE_GROUP)
        self.assertEqual(
            grants[1].privilege_categories,
            (
                PrivilegeCategory.COMPUTE_ADMIN,
                PrivilegeCategory.NETWORK_ADMIN,
                PrivilegeCategory.DATA_ADMIN,
            ),
        )
        self.assertTrue(azure_facts(identity).privileged_access_posture.has_privileged_grants)

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

        assignment_grants = assignment_facts.privileged_access_grants
        identity_grants = azure_facts(identity).privileged_access_grants
        self.assertEqual(identity_grants, assignment_grants)
        self.assertEqual(len(assignment_grants), 1)
        grant = assignment_grants[0]
        self.assertEqual(grant.principal.principal_type, PrincipalType.MANAGED_IDENTITY)
        self.assertEqual(grant.assignment_scope.scope_kind, AssignmentScopeKind.RESOURCE)
        self.assertEqual(grant.assignment_scope.value, "azurerm_storage_account.logs.id")
        self.assertEqual(grant.assignment_scope.source_address, "azurerm_storage_account.logs")
        self.assertEqual(grant.privilege_categories, (PrivilegeCategory.DATA_ADMIN,))
        self.assertEqual(grant.role_name, "Storage Blob Data Owner")
        self.assertIn("Storage Blob Data Owner", grant.permission_patterns)
        self.assertIn("target_resource=azurerm_storage_account.logs", grant.evidence)

    def test_role_assignment_resolves_custom_role_definition_by_role_definition_id(self) -> None:
        role_definition_id = "/subscriptions/sub-0001/providers/Microsoft.Authorization/roleDefinitions/custom-role"
        inventory = AzureNormalizer().normalize(
            [
                _user_assigned_identity(principal_id="managed-principal-id"),
                _role_definition(
                    role_definition_id=role_definition_id,
                    actions=["Microsoft.Authorization/roleAssignments/write"],
                    not_actions=["Microsoft.Authorization/elevateAccess/Action"],
                    data_actions=["Microsoft.Storage/storageAccounts/blobServices/containers/blobs/*"],
                    not_data_actions=["Microsoft.Storage/storageAccounts/blobServices/containers/blobs/delete"],
                ),
                _role_assignment(
                    role_definition_name=None,
                    role_definition_id=role_definition_id,
                    name="custom_storage_operator",
                ),
            ]
        )
        identity = inventory.get_by_address("azurerm_user_assigned_identity.deploy")
        role_assignment = inventory.get_by_address("azurerm_role_assignment.custom_storage_operator")
        assert identity is not None
        assert role_assignment is not None

        assignment_facts = azure_facts(role_assignment)
        self.assertEqual(
            assignment_facts.resolved_role_definition_address,
            "azurerm_role_definition.custom_role",
        )
        self.assertEqual(assignment_facts.resolved_managed_identity_address, identity.address)
        self.assertEqual(
            assignment_facts.role_assignment_breadth_signals,
            [
                "subscription_scope",
                AUTHORIZATION_MANAGEMENT,
                ROLE_ASSIGNMENT_CAPABLE,
                STORAGE_DATA_PLANE,
            ],
        )
        self.assertEqual(
            assignment_facts.role_assignment_breadth_mitigations,
            [
                "not_action=Microsoft.Authorization/elevateAccess/Action",
                "not_data_action=Microsoft.Storage/storageAccounts/blobServices/containers/blobs/delete",
            ],
        )
        self.assertEqual(
            azure_facts(identity).managed_identity_role_assignments[0],
            {
                "source": "azurerm_role_assignment.custom_storage_operator",
                "scope": "/subscriptions/sub-0001",
                "role_definition_name": None,
                "role_definition_id": role_definition_id,
                "principal_id": "managed-principal-id",
                "principal_type": "ServicePrincipal",
                "scope_kind": "subscription",
                "target_resource_address": None,
                "target_resource_type": None,
                "breadth_signals": [
                    "subscription_scope",
                    AUTHORIZATION_MANAGEMENT,
                    ROLE_ASSIGNMENT_CAPABLE,
                    STORAGE_DATA_PLANE,
                ],
                "resolved_role_definition_address": "azurerm_role_definition.custom_role",
                "breadth_mitigations": [
                    "not_action=Microsoft.Authorization/elevateAccess/Action",
                    "not_data_action=Microsoft.Storage/storageAccounts/blobServices/containers/blobs/delete",
                ],
                "role_definition_breadth_signals": [
                    AUTHORIZATION_MANAGEMENT,
                    ROLE_ASSIGNMENT_CAPABLE,
                    STORAGE_DATA_PLANE,
                ],
                "role_definition_breadth_mitigations": [
                    "not_action=Microsoft.Authorization/elevateAccess/Action",
                    "not_data_action=Microsoft.Storage/storageAccounts/blobServices/containers/blobs/delete",
                ],
            },
        )

        grants = assignment_facts.privileged_access_grants
        self.assertEqual(grants, azure_facts(identity).privileged_access_grants)
        self.assertEqual(len(grants), 1)
        grant = grants[0]
        self.assertEqual(grant.principal.principal_type, PrincipalType.MANAGED_IDENTITY)
        self.assertEqual(grant.assignment_scope.scope_kind, AssignmentScopeKind.SUBSCRIPTION)
        self.assertEqual(
            grant.privilege_categories,
            (
                PrivilegeCategory.IAM_ADMIN,
                PrivilegeCategory.POLICY_ADMIN,
                PrivilegeCategory.ROLE_ASSIGNMENT,
                PrivilegeCategory.DATA_ADMIN,
            ),
        )
        self.assertEqual(grant.confidence, PrivilegeConfidence.HIGH)
        self.assertEqual(
            grant.permission_patterns,
            (
                "Microsoft.Authorization/roleAssignments/write",
                "Microsoft.Storage/storageAccounts/blobServices/containers/blobs/*",
            ),
        )
        self.assertIn("resolved_role_definition=azurerm_role_definition.custom_role", grant.evidence)

    def test_role_assignment_resolves_custom_role_definition_by_terraform_reference(self) -> None:
        inventory = AzureNormalizer().normalize(
            [
                _user_assigned_identity(principal_id="managed-principal-id"),
                _role_definition(
                    role_definition_id=None,
                    actions=["*"],
                ),
                _role_assignment(
                    role_definition_name=None,
                    role_definition_id="azurerm_role_definition.custom_role.role_definition_resource_id",
                    name="custom_owner",
                ),
            ]
        )
        role_assignment = inventory.get_by_address("azurerm_role_assignment.custom_owner")
        assert role_assignment is not None

        assignment_facts = azure_facts(role_assignment)
        self.assertEqual(
            assignment_facts.resolved_role_definition_address,
            "azurerm_role_definition.custom_role",
        )
        self.assertEqual(
            assignment_facts.role_assignment_breadth_signals,
            ["subscription_scope", OWNER_LIKE_OR_WILDCARD],
        )

    def test_unresolved_custom_role_definition_reference_is_preserved_without_relationship(self) -> None:
        inventory = AzureNormalizer().normalize(
            [
                _user_assigned_identity(principal_id="managed-principal-id"),
                _role_assignment(
                    role_definition_name=None,
                    role_definition_id="azurerm_role_definition.missing.role_definition_resource_id",
                    name="unresolved_custom_role",
                ),
            ]
        )
        identity = inventory.get_by_address("azurerm_user_assigned_identity.deploy")
        role_assignment = inventory.get_by_address("azurerm_role_assignment.unresolved_custom_role")
        assert identity is not None
        assert role_assignment is not None

        assignment_facts = azure_facts(role_assignment)
        self.assertIsNone(assignment_facts.resolved_role_definition_address)
        self.assertEqual(assignment_facts.resolved_managed_identity_address, identity.address)
        self.assertEqual(assignment_facts.role_assignment_breadth_signals, ["subscription_scope"])
        self.assertEqual(assignment_facts.role_assignment_breadth_mitigations, [])
        self.assertEqual(
            role_assignment.get_metadata_field(AzureResourceMetadata.UNRESOLVED_RESOURCE_REFERENCES),
            ["role_definition:azurerm_role_definition.missing.role_definition_resource_id"],
        )
        assignment = azure_facts(identity).managed_identity_role_assignments[0]
        self.assertNotIn("resolved_role_definition_address", assignment)
        self.assertNotIn("role_definition_breadth_signals", assignment)
        self.assertEqual(assignment_facts.privileged_access_grants, ())
        self.assertEqual(azure_facts(identity).privileged_access_grants, ())
        self.assertEqual(
            assignment_facts.iam_assignment_posture_uncertainties,
            [
                "azurerm_role_assignment.unresolved_custom_role: custom role "
                "azurerm_role_definition.missing.role_definition_resource_id was not resolved"
            ],
        )
        self.assertEqual(
            assignment_facts.privileged_access_posture.unresolved_assignments,
            (
                "azurerm_role_assignment.unresolved_custom_role: custom role "
                "azurerm_role_definition.missing.role_definition_resource_id was not resolved",
            ),
        )


if __name__ == "__main__":
    unittest.main()
