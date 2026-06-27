from __future__ import annotations

import unittest

from tfstride.analysis.boundaries import detect_trust_boundaries
from tfstride.analysis.indexes import build_analysis_indexes
from tfstride.analysis.role_helpers import resolve_workload_role
from tfstride.analysis.stride_rules import StrideRuleEngine
from tfstride.models import ResourceCategory, TerraformResource
from tfstride.providers.azure.compute_normalizers import normalize_linux_virtual_machine
from tfstride.providers.azure.identity_normalizers import normalize_role_definition, normalize_user_assigned_identity
from tfstride.providers.azure.normalizer import AzureNormalizer
from tfstride.providers.azure.observations import observe_azure_posture
from tfstride.providers.azure.rbac_breadth import (
    AUTHORIZATION_MANAGEMENT,
    OWNER_LIKE_OR_WILDCARD,
    RESOURCE_GROUP_SUBSCRIPTION_WIDE_MANAGEMENT,
    ROLE_ASSIGNMENT_CAPABLE,
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


class AzureRoleDefinitionNormalizerTests(unittest.TestCase):
    def test_role_definition_normalizes_custom_rbac_permissions(self) -> None:
        role_definition = normalize_role_definition(
            _resource(
                AzureResourceType.ROLE_DEFINITION,
                {
                    "id": ("/subscriptions/sub-0001/providers/Microsoft.Authorization/roleDefinitions/custom-role-id"),
                    "name": "Storage Operator",
                    "scope": "/subscriptions/sub-0001",
                    "assignable_scopes": [
                        "/subscriptions/sub-0001",
                        "/subscriptions/sub-0001/resourceGroups/app",
                    ],
                    "permissions": [
                        {
                            "actions": [
                                "*",
                                "Microsoft.Authorization/*",
                                "Microsoft.Resources/subscriptions/resourceGroups/*",
                            ],
                            "not_actions": ["Microsoft.Authorization/elevateAccess/Action"],
                            "data_actions": ["*"],
                            "not_data_actions": [
                                "Microsoft.Storage/storageAccounts/blobServices/containers/blobs/delete"
                            ],
                        }
                    ],
                },
                name="storage_operator",
            )
        )
        facts = azure_facts(role_definition)

        self.assertEqual(role_definition.category, ResourceCategory.IAM)
        self.assertEqual(
            role_definition.identifier,
            "/subscriptions/sub-0001/providers/Microsoft.Authorization/roleDefinitions/custom-role-id",
        )
        self.assertTrue(facts.is_custom_role_definition)
        self.assertEqual(facts.name, "Storage Operator")
        self.assertEqual(
            facts.role_definition_id,
            "/subscriptions/sub-0001/providers/Microsoft.Authorization/roleDefinitions/custom-role-id",
        )
        self.assertEqual(facts.role_definition_scope, "/subscriptions/sub-0001")
        self.assertEqual(
            facts.role_definition_assignable_scopes,
            [
                "/subscriptions/sub-0001",
                "/subscriptions/sub-0001/resourceGroups/app",
            ],
        )
        self.assertEqual(
            facts.role_definition_actions,
            [
                "*",
                "Microsoft.Authorization/*",
                "Microsoft.Resources/subscriptions/resourceGroups/*",
            ],
        )
        self.assertEqual(facts.role_definition_not_actions, ["Microsoft.Authorization/elevateAccess/Action"])
        self.assertEqual(facts.role_definition_data_actions, ["*"])
        self.assertEqual(
            facts.role_definition_not_data_actions,
            ["Microsoft.Storage/storageAccounts/blobServices/containers/blobs/delete"],
        )
        self.assertEqual(
            facts.role_definition_breadth_signals,
            [
                OWNER_LIKE_OR_WILDCARD,
                AUTHORIZATION_MANAGEMENT,
                ROLE_ASSIGNMENT_CAPABLE,
                RESOURCE_GROUP_SUBSCRIPTION_WIDE_MANAGEMENT,
            ],
        )
        self.assertEqual(
            facts.role_definition_breadth_mitigations,
            [
                "not_action=Microsoft.Authorization/elevateAccess/Action",
                "not_data_action=Microsoft.Storage/storageAccounts/blobServices/containers/blobs/delete",
            ],
        )
        self.assertEqual(
            facts.role_definition_permissions,
            [
                {
                    "actions": [
                        "*",
                        "Microsoft.Authorization/*",
                        "Microsoft.Resources/subscriptions/resourceGroups/*",
                    ],
                    "not_actions": ["Microsoft.Authorization/elevateAccess/Action"],
                    "data_actions": ["*"],
                    "not_data_actions": ["Microsoft.Storage/storageAccounts/blobServices/containers/blobs/delete"],
                }
            ],
        )
        self.assertEqual(facts.role_definition_uncertainties, [])

    def test_role_definition_preserves_computed_permission_uncertainty(self) -> None:
        role_definition = normalize_role_definition(
            _resource(
                AzureResourceType.ROLE_DEFINITION,
                {
                    "name": None,
                    "scope": None,
                    "assignable_scopes": [],
                    "permissions": [
                        {
                            "actions": [],
                            "not_actions": ["Microsoft.Authorization/*/Delete"],
                            "data_actions": [],
                            "not_data_actions": [],
                        }
                    ],
                },
                name="pending",
                unknown_values={
                    "name": True,
                    "scope": True,
                    "assignable_scopes": True,
                    "permissions": [{"actions": True, "data_actions": True}],
                },
            )
        )
        facts = azure_facts(role_definition)

        self.assertEqual(role_definition.identifier, "azurerm_role_definition.pending")
        self.assertTrue(facts.is_custom_role_definition)
        self.assertIsNone(facts.name)
        self.assertIsNone(facts.role_definition_scope)
        self.assertEqual(facts.role_definition_assignable_scopes, [])
        self.assertEqual(facts.role_definition_actions, [])
        self.assertEqual(facts.role_definition_not_actions, ["Microsoft.Authorization/*/Delete"])
        self.assertEqual(facts.role_definition_data_actions, [])
        self.assertEqual(facts.role_definition_not_data_actions, [])
        self.assertEqual(facts.role_definition_breadth_signals, [])
        self.assertEqual(facts.role_definition_breadth_mitigations, ["not_action=Microsoft.Authorization/*/Delete"])
        self.assertEqual(
            facts.role_definition_permissions,
            [
                {
                    "actions": [],
                    "not_actions": ["Microsoft.Authorization/*/Delete"],
                    "data_actions": [],
                    "not_data_actions": [],
                }
            ],
        )
        self.assertEqual(
            facts.role_definition_uncertainties,
            [
                "name is unknown after planning",
                "scope is unknown after planning",
                "assignable_scopes is unknown after planning",
                "permissions[0].actions is unknown after planning",
                "permissions[0].data_actions is unknown after planning",
            ],
        )

    def test_azure_normalizer_supports_role_definition_without_findings(self) -> None:
        inventory = AzureNormalizer().normalize(
            [
                _resource(
                    AzureResourceType.ROLE_DEFINITION,
                    {
                        "name": "Resource Group Operator",
                        "scope": "/subscriptions/sub-0001/resourceGroups/app",
                        "assignable_scopes": ["/subscriptions/sub-0001/resourceGroups/app"],
                        "permissions": [
                            {
                                "actions": ["Microsoft.Resources/subscriptions/resourceGroups/read"],
                                "not_actions": [],
                                "data_actions": [],
                                "not_data_actions": [],
                            }
                        ],
                    },
                    name="resource_group_operator",
                )
            ]
        )

        self.assertEqual(inventory.unsupported_resources, [])
        self.assertEqual(
            [resource.address for resource in inventory.resources],
            ["azurerm_role_definition.resource_group_operator"],
        )
        self.assertEqual(StrideRuleEngine().evaluate(inventory, []), [])


class AzureManagedIdentityNormalizerTests(unittest.TestCase):
    def test_user_assigned_identity_normalizes_principal_identifiers(self) -> None:
        identity = normalize_user_assigned_identity(
            _resource(
                AzureResourceType.USER_ASSIGNED_IDENTITY,
                {
                    "id": "/subscriptions/example/resourceGroups/app/providers/Microsoft.ManagedIdentity/userAssignedIdentities/deploy",
                    "name": "deploy",
                    "location": "eastus",
                    "principal_id": "principal-id",
                    "client_id": "client-id",
                    "tenant_id": "tenant-id",
                },
                name="deploy",
            )
        )
        facts = azure_facts(identity)

        self.assertEqual(identity.category, ResourceCategory.IAM)
        self.assertEqual(facts.identity_type, "UserAssigned")
        self.assertTrue(facts.has_user_assigned_identity)
        self.assertFalse(facts.has_system_assigned_identity)
        self.assertEqual(facts.principal_id, "principal-id")
        self.assertEqual(facts.client_id, "client-id")
        self.assertEqual(facts.tenant_id, "tenant-id")
        self.assertEqual(facts.attached_identity_references, [])
        self.assertEqual(facts.managed_identity_uncertainties, [])

    def test_user_assigned_identity_preserves_computed_identifiers_as_unknown(self) -> None:
        identity = normalize_user_assigned_identity(
            _resource(
                AzureResourceType.USER_ASSIGNED_IDENTITY,
                {
                    "id": None,
                    "name": "deploy",
                    "principal_id": None,
                    "client_id": None,
                    "tenant_id": None,
                },
                name="deploy",
                unknown_values={
                    "id": True,
                    "principal_id": True,
                    "client_id": True,
                    "tenant_id": True,
                },
            )
        )
        facts = azure_facts(identity)

        self.assertEqual(identity.identifier, "azurerm_user_assigned_identity.deploy")
        self.assertIsNone(facts.principal_id)
        self.assertIsNone(facts.client_id)
        self.assertIsNone(facts.tenant_id)
        self.assertEqual(
            facts.managed_identity_uncertainties,
            [
                "principal_id is unknown after planning",
                "client_id is unknown after planning",
                "tenant_id is unknown after planning",
            ],
        )

    def test_virtual_machine_detects_system_assigned_identity(self) -> None:
        virtual_machine = normalize_linux_virtual_machine(
            _resource(
                AzureResourceType.LINUX_VIRTUAL_MACHINE,
                {
                    "name": "web",
                    "network_interface_ids": [],
                    "identity": [
                        {
                            "type": "SystemAssigned",
                            "principal_id": "system-principal-id",
                            "tenant_id": "tenant-id",
                            "identity_ids": [],
                        }
                    ],
                },
                name="web",
            )
        )
        facts = azure_facts(virtual_machine)

        self.assertEqual(facts.identity_type, "SystemAssigned")
        self.assertTrue(facts.has_system_assigned_identity)
        self.assertFalse(facts.has_user_assigned_identity)
        self.assertEqual(facts.principal_id, "system-principal-id")
        self.assertEqual(facts.tenant_id, "tenant-id")
        self.assertIsNone(facts.client_id)
        self.assertEqual(facts.attached_identity_references, [])

    def test_virtual_machine_preserves_user_identity_references_and_computed_system_ids(self) -> None:
        virtual_machine = normalize_linux_virtual_machine(
            _resource(
                AzureResourceType.LINUX_VIRTUAL_MACHINE,
                {
                    "name": "web",
                    "network_interface_ids": [],
                    "identity": [
                        {
                            "type": "SystemAssigned, UserAssigned",
                            "principal_id": None,
                            "tenant_id": None,
                            "identity_ids": [
                                "azurerm_user_assigned_identity.deploy.id",
                                "/subscriptions/example/resourceGroups/app/providers/Microsoft.ManagedIdentity/userAssignedIdentities/runtime",
                            ],
                        }
                    ],
                },
                name="web",
                unknown_values={"identity": [{"principal_id": True, "tenant_id": True}]},
            )
        )
        facts = azure_facts(virtual_machine)

        self.assertTrue(facts.has_system_assigned_identity)
        self.assertTrue(facts.has_user_assigned_identity)
        self.assertEqual(
            facts.attached_identity_references,
            [
                "azurerm_user_assigned_identity.deploy.id",
                "/subscriptions/example/resourceGroups/app/providers/Microsoft.ManagedIdentity/userAssignedIdentities/runtime",
            ],
        )
        self.assertIsNone(facts.principal_id)
        self.assertIsNone(facts.tenant_id)
        self.assertEqual(
            facts.managed_identity_uncertainties,
            [
                "identity.principal_id is unknown after planning",
                "identity.tenant_id is unknown after planning",
            ],
        )

    def test_unknown_user_identity_attachments_are_not_inferred(self) -> None:
        virtual_machine = normalize_linux_virtual_machine(
            _resource(
                AzureResourceType.LINUX_VIRTUAL_MACHINE,
                {
                    "name": "web",
                    "network_interface_ids": [],
                    "identity": [{"type": "UserAssigned", "identity_ids": []}],
                },
                name="web",
                unknown_values={"identity": [{"identity_ids": [True]}]},
            )
        )
        facts = azure_facts(virtual_machine)

        self.assertTrue(facts.has_user_assigned_identity)
        self.assertEqual(facts.attached_identity_references, [])
        self.assertEqual(
            facts.managed_identity_uncertainties,
            ["identity.identity_ids is unknown after planning"],
        )

    def test_unknown_identity_block_does_not_infer_identity_type(self) -> None:
        virtual_machine = normalize_linux_virtual_machine(
            _resource(
                AzureResourceType.LINUX_VIRTUAL_MACHINE,
                {"name": "web", "network_interface_ids": [], "identity": None},
                name="web",
                unknown_values={"identity": True},
            )
        )
        facts = azure_facts(virtual_machine)

        self.assertIsNone(facts.identity_type)
        self.assertFalse(facts.has_system_assigned_identity)
        self.assertFalse(facts.has_user_assigned_identity)
        self.assertEqual(facts.attached_identity_references, [])
        self.assertEqual(facts.managed_identity_uncertainties, ["identity is unknown after planning"])

    def test_identity_principals_connect_role_assignments_without_transitive_findings(self) -> None:
        resources = [
            _resource(
                AzureResourceType.USER_ASSIGNED_IDENTITY,
                {
                    "name": "deploy",
                    "principal_id": "principal-id",
                    "client_id": "client-id",
                    "tenant_id": "tenant-id",
                },
                name="deploy",
            ),
            _resource(
                AzureResourceType.LINUX_VIRTUAL_MACHINE,
                {
                    "name": "web",
                    "network_interface_ids": [],
                    "identity": [
                        {
                            "type": "SystemAssigned, UserAssigned",
                            "principal_id": None,
                            "tenant_id": None,
                            "identity_ids": ["azurerm_user_assigned_identity.deploy.id"],
                        }
                    ],
                },
                name="web",
                unknown_values={"identity": [{"principal_id": True, "tenant_id": True}]},
            ),
            _resource(
                AzureResourceType.ROLE_ASSIGNMENT,
                {
                    "scope": "azurerm_user_assigned_identity.deploy.id",
                    "role_definition_name": "Reader",
                    "principal_id": "principal-id",
                    "principal_type": "ServicePrincipal",
                },
                name="deploy_contributor",
            ),
        ]
        inventory = AzureNormalizer().normalize(resources)
        virtual_machine = inventory.get_by_address("azurerm_linux_virtual_machine.web")
        identity = inventory.get_by_address("azurerm_user_assigned_identity.deploy")
        role_assignment = inventory.get_by_address("azurerm_role_assignment.deploy_contributor")
        assert virtual_machine is not None
        assert identity is not None
        assert role_assignment is not None

        observations = observe_azure_posture(inventory)
        indexes = build_analysis_indexes(inventory)

        self.assertIs(indexes.role_index[identity.address], identity)
        self.assertIsNone(resolve_workload_role(virtual_machine, indexes.role_index))
        self.assertEqual(virtual_machine.attached_role_arns, [])
        self.assertIsNone(azure_facts(role_assignment).resolved_key_vault_address)
        self.assertEqual(azure_facts(role_assignment).resolved_managed_identity_address, identity.address)
        self.assertEqual(azure_facts(identity).key_vault_role_assignments, [])
        self.assertEqual(
            azure_facts(identity).managed_identity_role_assignments,
            [
                {
                    "source": "azurerm_role_assignment.deploy_contributor",
                    "scope": "azurerm_user_assigned_identity.deploy.id",
                    "role_definition_name": "Reader",
                    "role_definition_id": None,
                    "principal_id": "principal-id",
                    "principal_type": "ServicePrincipal",
                    "scope_kind": "resource",
                    "target_resource_address": "azurerm_user_assigned_identity.deploy",
                    "target_resource_type": AzureResourceType.USER_ASSIGNED_IDENTITY,
                    "breadth_signals": [],
                }
            ],
        )
        self.assertEqual(detect_trust_boundaries(inventory), [])
        self.assertEqual(StrideRuleEngine().evaluate(inventory, []), [])
        self.assertEqual(
            [observation.observation_id for observation in observations],
            [
                "azure-managed-identity-principal-observed",
                "azure-managed-identity-role-assignment-observed",
                "azure-managed-identity-principal-observed",
                "azure-managed-identity-principal-unknown",
            ],
        )
        observed_evidence = {
            item.key: item.values
            for observation in observations
            if observation.affected_resources == ["azurerm_linux_virtual_machine.web"]
            and observation.observation_id == "azure-managed-identity-principal-observed"
            for item in observation.evidence
        }
        self.assertEqual(
            observed_evidence["analysis_scope"],
            [
                "managed identity role assignments are connected when principal IDs are deterministic",
                "transitive access findings are not emitted from managed identity assignments yet",
            ],
        )


if __name__ == "__main__":
    unittest.main()
