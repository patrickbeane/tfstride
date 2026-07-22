from __future__ import annotations

import unittest
from collections import Counter

from tests.providers.azure.test_azure_app_service_storage_access_paths import (
    _SYSTEM_PRINCIPAL_ID,
    _USER_PRINCIPAL_ID,
    _custom_role,
    _custom_role_assignment,
    _function_app,
    _role_assignment,
    _storage_account,
    _storage_container,
    _user_assigned_identity,
    _web_app,
)
from tfstride.analysis.rule_registry import RulePolicy
from tfstride.analysis.stride_rules import StrideRuleEngine
from tfstride.models import TerraformResource
from tfstride.providers.azure.normalizer import AzureNormalizer
from tfstride.providers.azure.rules import AZURE_RULE_GROUP_IDS

_RULE_ID = "azure-public-app-service-storage-mutation-access"
_GENERAL_PUBLIC_SENSITIVE_RULE_ID = "azure-public-workload-sensitive-resource-access"


def _public(resource: TerraformResource) -> TerraformResource:
    resource.values["public_network_access_enabled"] = True
    return resource


def _evaluate(resources: list[TerraformResource], *rule_ids: str):
    inventory = AzureNormalizer().normalize(resources)
    return StrideRuleEngine().evaluate(
        inventory,
        [],
        rule_policy=RulePolicy(enabled_rule_ids=frozenset(rule_ids or {_RULE_ID})),
    )


def _evidence(finding):
    return {item.key: item.values for item in finding.evidence}


class AzurePublicAppServiceStorageMutationRuleTests(unittest.TestCase):
    def test_rule_is_registered(self) -> None:
        registered = {rule_id for group in AZURE_RULE_GROUP_IDS for rule_id in group}
        self.assertIn(_RULE_ID, registered)

    def test_public_system_assigned_app_with_exact_blob_contributor_is_detected(self) -> None:
        findings = _evaluate([_storage_account(), _public(_web_app()), _role_assignment()])

        self.assertEqual([finding.rule_id for finding in findings], [_RULE_ID])
        finding = findings[0]
        self.assertEqual(finding.severity.value, "high")
        self.assertEqual(
            finding.affected_resources,
            [
                "azurerm_linux_web_app.orders",
                "azurerm_storage_account.orders",
                "azurerm_role_assignment.orders_blob",
            ],
        )
        self.assertIn("does not mean that the Storage Account or container itself is public", finding.rationale)
        evidence = _evidence(finding)
        self.assertIn("public_network_access_enabled=true", evidence["public_endpoint"])
        self.assertTrue(
            any(
                f"principal_id={_SYSTEM_PRINCIPAL_ID}" in value and "role_kind=blob_data_contributor" in value
                for value in evidence["runtime_identity"]
            )
        )
        self.assertTrue(
            any(
                "storage_resource_address=azurerm_storage_account.orders" in value
                and "mutation_classes=write,delete" in value
                and "resource_scope=exact_storage_account" in value
                and "condition_state=not_configured" in value
                for value in evidence["storage_mutation_paths"]
            )
        )
        self.assertNotIn("custom_role_permissions", evidence)

    def test_public_function_user_identity_with_container_owner_is_detected(self) -> None:
        findings = _evaluate(
            [
                _storage_account(),
                _storage_container(),
                _user_assigned_identity(),
                _public(_function_app()),
                _role_assignment(
                    principal_id=_USER_PRINCIPAL_ID,
                    scope="azurerm_storage_container.orders.id",
                    role_name="Storage Blob Data Owner",
                    role_definition_id=(
                        "/subscriptions/sub-0001/providers/Microsoft.Authorization/roleDefinitions/"
                        "b7e6dc6d-f1e8-4753-8033-0f276bb0955b"
                    ),
                ),
            ]
        )

        self.assertEqual([finding.rule_id for finding in findings], [_RULE_ID])
        finding = findings[0]
        self.assertEqual(
            finding.affected_resources,
            [
                "azurerm_linux_function_app.orders_worker",
                "azurerm_user_assigned_identity.orders_runtime",
                "azurerm_storage_account.orders",
                "azurerm_storage_container.orders",
                "azurerm_role_assignment.orders_blob",
            ],
        )
        evidence = _evidence(finding)
        self.assertTrue(
            any(
                "identity_kind=user_assigned" in value and f"principal_id={_USER_PRINCIPAL_ID}" in value
                for value in evidence["runtime_identity"]
            )
        )
        self.assertTrue(
            any(
                "storage_resource_address=azurerm_storage_container.orders" in value
                and "resource_scope=exact_storage_container" in value
                and "mutation_classes=write,delete,administrative" in value
                for value in evidence["storage_mutation_paths"]
            )
        )

    def test_custom_write_only_role_is_reported_as_tampering_not_disclosure(self) -> None:
        findings = _evaluate(
            [
                _storage_account(),
                _public(_web_app()),
                _custom_role(
                    data_actions=[
                        "Microsoft.Storage/storageAccounts/blobServices/containers/blobs/write",
                    ]
                ),
                _custom_role_assignment(),
            ]
        )

        self.assertEqual([finding.rule_id for finding in findings], [_RULE_ID])
        finding = findings[0]
        self.assertIn("write-only", finding.rationale)
        self.assertIn("does not establish read access or information disclosure", finding.rationale)
        evidence = _evidence(finding)
        self.assertTrue(
            any(
                "role_definition_address=azurerm_role_definition.blob_writer" in value
                and "matched_data_actions=microsoft.storage/storageaccounts/blobservices/containers/blobs/write"
                in value.lower()
                for value in evidence["custom_role_permissions"]
            )
        )

    def test_private_unknown_read_only_and_conditional_paths_stay_quiet(self) -> None:
        private = _evaluate([_storage_account(), _web_app(), _role_assignment()])

        unknown_app = _web_app()
        unknown_app.values["public_network_access_enabled"] = None
        unknown_app.unknown_values["public_network_access_enabled"] = True
        unknown = _evaluate([_storage_account(), unknown_app, _role_assignment()])

        read_only = _evaluate(
            [
                _storage_account(),
                _public(_web_app()),
                _role_assignment(
                    role_name="Storage Blob Data Reader",
                    role_definition_id=(
                        "/subscriptions/sub-0001/providers/Microsoft.Authorization/roleDefinitions/"
                        "2a2b9908-6ea1-4ae2-8e65-a410df84e7d1"
                    ),
                ),
            ]
        )
        conditional = _evaluate(
            [
                _storage_account(),
                _public(_web_app()),
                _role_assignment(
                    condition=(
                        "@Resource[Microsoft.Storage/storageAccounts/blobServices/containers:name] "
                        "StringEquals 'orders'"
                    )
                ),
            ]
        )

        self.assertEqual(private, [])
        self.assertEqual(unknown, [])
        self.assertEqual(read_only, [])
        self.assertEqual(conditional, [])

    def test_custom_not_data_action_removing_mutation_stays_quiet(self) -> None:
        findings = _evaluate(
            [
                _storage_account(),
                _public(_web_app()),
                _custom_role(
                    data_actions=["Microsoft.Storage/storageAccounts/blobServices/containers/blobs/*"],
                    not_data_actions=[
                        "Microsoft.Storage/storageAccounts/blobServices/containers/blobs/write",
                        "Microsoft.Storage/storageAccounts/blobServices/containers/blobs/add/action",
                        "Microsoft.Storage/storageAccounts/blobServices/containers/blobs/move/action",
                        "Microsoft.Storage/storageAccounts/blobServices/containers/blobs/tags/write",
                        "Microsoft.Storage/storageAccounts/blobServices/containers/blobs/delete",
                        ("Microsoft.Storage/storageAccounts/blobServices/containers/blobs/deleteBlobVersion/action"),
                        ("Microsoft.Storage/storageAccounts/blobServices/containers/blobs/permanentDelete/action"),
                        ("Microsoft.Storage/storageAccounts/blobServices/containers/blobs/modifyPermissions/action"),
                        ("Microsoft.Storage/storageAccounts/blobServices/containers/blobs/manageOwnership/action"),
                        ("Microsoft.Storage/storageAccounts/blobServices/containers/blobs/runAsSuperUser/action"),
                        (
                            "Microsoft.Storage/storageAccounts/blobServices/containers/blobs/"
                            "immutableStorage/runAsSuperUser/action"
                        ),
                    ],
                ),
                _custom_role_assignment(),
            ]
        )

        self.assertEqual(findings, [])

    def test_mutation_path_finding_remains_distinct_from_general_sensitive_access(self) -> None:
        findings = _evaluate(
            [_storage_account(), _public(_web_app()), _role_assignment()],
            _GENERAL_PUBLIC_SENSITIVE_RULE_ID,
            _RULE_ID,
        )

        self.assertEqual(
            Counter(finding.rule_id for finding in findings),
            Counter({_GENERAL_PUBLIC_SENSITIVE_RULE_ID: 1, _RULE_ID: 1}),
        )


if __name__ == "__main__":
    unittest.main()
