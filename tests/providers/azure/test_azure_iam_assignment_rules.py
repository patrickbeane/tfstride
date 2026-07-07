from __future__ import annotations

import unittest

from tfstride.analysis.rule_registry import RulePolicy
from tfstride.analysis.stride_rules import StrideRuleEngine
from tfstride.models import TerraformResource
from tfstride.providers.azure.normalizer import AzureNormalizer
from tfstride.providers.azure.resource_types import AzureResourceType

_RULE_ID = "azure-rbac-privileged-assignment"


def _resource(resource_type: str, name: str, values: dict[str, object]) -> TerraformResource:
    return TerraformResource(
        address=f"{resource_type}.{name}",
        mode="managed",
        resource_type=resource_type,
        name=name,
        provider_name="registry.terraform.io/hashicorp/azurerm",
        values=values,
    )


def _role_assignment(
    *,
    name: str = "assignment",
    principal_id: object = "external-principal-id",
    principal_type: object = "ServicePrincipal",
    role_definition_name: object = "Owner",
    role_definition_id: object = "/subscriptions/sub-0001/providers/Microsoft.Authorization/roleDefinitions/owner",
    scope: object = "/subscriptions/sub-0001",
) -> TerraformResource:
    return _resource(
        AzureResourceType.ROLE_ASSIGNMENT,
        name,
        {
            "scope": scope,
            "role_definition_name": role_definition_name,
            "role_definition_id": role_definition_id,
            "principal_id": principal_id,
            "principal_type": principal_type,
        },
    )


def _user_assigned_identity() -> TerraformResource:
    return _resource(
        AzureResourceType.USER_ASSIGNED_IDENTITY,
        "deploy",
        {
            "name": "deploy",
            "principal_id": "managed-principal-id",
            "client_id": "client-id",
            "tenant_id": "tenant-id",
        },
    )


def _role_definition() -> TerraformResource:
    return _resource(
        AzureResourceType.ROLE_DEFINITION,
        "custom_owner",
        {
            "id": "/subscriptions/sub-0001/providers/Microsoft.Authorization/roleDefinitions/custom-owner",
            "name": "Custom Owner",
            "scope": "/subscriptions/sub-0001",
            "assignable_scopes": ["/subscriptions/sub-0001"],
            "permissions": [
                {
                    "actions": ["*"],
                    "not_actions": [],
                    "data_actions": [],
                    "not_data_actions": [],
                }
            ],
        },
    )


def _storage_account() -> TerraformResource:
    return _resource(
        AzureResourceType.STORAGE_ACCOUNT,
        "logs",
        {
            "id": "/subscriptions/sub-0001/resourceGroups/app/providers/Microsoft.Storage/storageAccounts/logs",
            "name": "logs",
            "allow_nested_items_to_be_public": False,
            "shared_access_key_enabled": False,
            "min_tls_version": "TLS1_2",
            "public_network_access_enabled": False,
            "network_rules": [{"default_action": "Deny"}],
        },
    )


def _key_vault() -> TerraformResource:
    return _resource(
        AzureResourceType.KEY_VAULT,
        "application",
        {
            "id": "/subscriptions/sub-0001/resourceGroups/app/providers/Microsoft.KeyVault/vaults/application",
            "name": "application",
            "tenant_id": "tenant-id",
            "sku_name": "standard",
            "enable_rbac_authorization": True,
            "public_network_access_enabled": False,
            "network_acls": [{"default_action": "Deny"}],
            "purge_protection_enabled": True,
        },
    )


def _findings(resources: list[TerraformResource]):
    inventory = AzureNormalizer().normalize(resources)
    return StrideRuleEngine().evaluate(
        inventory,
        [],
        rule_policy=RulePolicy(enabled_rule_ids=frozenset({_RULE_ID})),
    )


def _evidence_by_key(finding):
    return {item.key: item.values for item in finding.evidence}


class AzureIamAssignmentRuleTests(unittest.TestCase):
    def test_subscription_owner_assignment_to_service_principal_is_detected(self) -> None:
        findings = _findings([_role_assignment()])

        self.assertEqual([finding.rule_id for finding in findings], [_RULE_ID])
        finding = findings[0]
        self.assertEqual(finding.severity.value, "high")
        self.assertEqual(finding.affected_resources, ["azurerm_role_assignment.assignment"])
        evidence = _evidence_by_key(finding)
        self.assertEqual(
            evidence["role_assignment"],
            [
                "address=azurerm_role_assignment.assignment",
                "type=azurerm_role_assignment",
                "role=Owner",
                "role_definition_id=/subscriptions/sub-0001/providers/Microsoft.Authorization/roleDefinitions/owner",
            ],
        )
        self.assertEqual(evidence["privilege_categories"], ["full-admin", "iam-admin", "policy-admin"])
        self.assertEqual(
            evidence["permission_patterns"],
            ["Owner", "/subscriptions/sub-0001/providers/Microsoft.Authorization/roleDefinitions/owner"],
        )
        self.assertEqual(
            evidence["grant_principals"],
            ["principal_type=service-principal; principal=external-principal-id"],
        )
        self.assertEqual(evidence["grant_scopes"], ["scope_kind=subscription; scope_value=/subscriptions/sub-0001"])
        self.assertEqual(evidence["grant_confidence"], ["high"])
        self.assertIn("breadth_signal=subscription_scope", evidence["assignment_facts"])

    def test_resource_scoped_storage_data_assignment_is_detected(self) -> None:
        findings = _findings(
            [
                _storage_account(),
                _role_assignment(
                    role_definition_name="Storage Blob Data Owner",
                    role_definition_id=(
                        "/subscriptions/sub-0001/providers/Microsoft.Authorization/roleDefinitions/storage-blob-owner"
                    ),
                    scope="azurerm_storage_account.logs.id",
                ),
            ]
        )

        self.assertEqual([finding.rule_id for finding in findings], [_RULE_ID])
        finding = findings[0]
        self.assertEqual(finding.severity.value, "medium")
        self.assertEqual(
            finding.affected_resources,
            ["azurerm_role_assignment.assignment", "azurerm_storage_account.logs"],
        )
        evidence = _evidence_by_key(finding)
        self.assertEqual(evidence["privilege_categories"], ["data-admin"])
        self.assertEqual(
            evidence["grant_scopes"],
            ["scope_kind=resource; scope_value=azurerm_storage_account.logs.id"],
        )
        self.assertIn("target_resource=azurerm_storage_account.logs", evidence["assignment_facts"])

    def test_resource_scoped_user_access_administrator_assignment_is_detected(self) -> None:
        findings = _findings(
            [
                _role_assignment(
                    role_definition_name="User Access Administrator",
                    role_definition_id=(
                        "/subscriptions/sub-0001/providers/Microsoft.Authorization/roleDefinitions/user-access-admin"
                    ),
                    scope="/subscriptions/sub-0001/resourceGroups/app/providers/Microsoft.Storage/storageAccounts/logs",
                )
            ]
        )

        self.assertEqual([finding.rule_id for finding in findings], [_RULE_ID])
        evidence = _evidence_by_key(findings[0])
        self.assertEqual(evidence["privilege_categories"], ["iam-admin", "role-assignment"])
        self.assertEqual(
            evidence["grant_scopes"],
            [
                "scope_kind=resource; "
                "scope_value=/subscriptions/sub-0001/resourceGroups/app/providers/Microsoft.Storage/storageAccounts/logs"
            ],
        )

    def test_managed_identity_assignment_stays_with_managed_identity_rule(self) -> None:
        findings = _findings(
            [
                _user_assigned_identity(),
                _role_assignment(principal_id="managed-principal-id"),
            ]
        )

        self.assertEqual(findings, [])

    def test_custom_role_assignment_stays_with_custom_role_rule(self) -> None:
        findings = _findings(
            [
                _role_definition(),
                _role_assignment(
                    role_definition_name=None,
                    role_definition_id=(
                        "/subscriptions/sub-0001/providers/Microsoft.Authorization/roleDefinitions/custom-owner"
                    ),
                ),
            ]
        )

        self.assertEqual(findings, [])

    def test_resource_scoped_key_vault_admin_stays_with_key_vault_rule(self) -> None:
        findings = _findings(
            [
                _key_vault(),
                _role_assignment(
                    role_definition_name="Key Vault Administrator",
                    role_definition_id=(
                        "/subscriptions/sub-0001/providers/Microsoft.Authorization/roleDefinitions/key-vault-admin"
                    ),
                    scope="azurerm_key_vault.application.id",
                ),
            ]
        )

        self.assertEqual(findings, [])

    def test_unresolved_resource_scoped_key_vault_admin_assignment_is_detected(self) -> None:
        findings = _findings(
            [
                _role_assignment(
                    role_definition_name="Key Vault Administrator",
                    role_definition_id=(
                        "/subscriptions/sub-0001/providers/Microsoft.Authorization/roleDefinitions/key-vault-admin"
                    ),
                    scope="azurerm_key_vault.application.id",
                )
            ]
        )

        self.assertEqual([finding.rule_id for finding in findings], [_RULE_ID])
        evidence = _evidence_by_key(findings[0])
        self.assertEqual(evidence["privilege_categories"], ["key-admin", "secrets-admin"])
        self.assertEqual(
            evidence["grant_scopes"],
            ["scope_kind=resource; scope_value=azurerm_key_vault.application.id"],
        )

    def test_reader_assignment_stays_quiet(self) -> None:
        findings = _findings(
            [
                _role_assignment(
                    role_definition_name="Reader",
                    role_definition_id="/subscriptions/sub-0001/providers/Microsoft.Authorization/roleDefinitions/reader",
                )
            ]
        )

        self.assertEqual(findings, [])


if __name__ == "__main__":
    unittest.main()
