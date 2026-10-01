from __future__ import annotations

import unittest

from tests.providers.azure.test_azure_app_service_blob_deletion_paths import (
    _storage_account,
    _storage_container,
)
from tests.providers.azure.test_azure_app_service_storage_access_paths import (
    _STORAGE_ACCOUNT_ID,
    _custom_role,
    _custom_role_assignment,
    _resource,
    _role_assignment,
    _web_app,
)
from tfstride.analysis.rule_registry import RulePolicy
from tfstride.analysis.stride_rules import StrideRuleEngine
from tfstride.models import TerraformResource
from tfstride.providers.azure.metadata import AzureResourceMetadata
from tfstride.providers.azure.normalizer import AzureNormalizer
from tfstride.providers.azure.resource_facts import azure_facts
from tfstride.providers.azure.resource_types import AzureResourceType

_RULE_ID = "azure-public-app-service-storage-blob-disruption"
_MUTATION_RULE_ID = "azure-public-app-service-storage-mutation-access"
_DELETE = "Microsoft.Storage/storageAccounts/blobServices/containers/blobs/delete"
_DELETE_VERSION = "Microsoft.Storage/storageAccounts/blobServices/containers/blobs/deleteBlobVersion/action"


def _public(resource: TerraformResource) -> TerraformResource:
    resource.values["public_network_access_enabled"] = True
    return resource


def _evaluate(resources: list[TerraformResource], *rule_ids: str):
    inventory = AzureNormalizer().normalize(resources)
    return inventory, StrideRuleEngine().evaluate(
        inventory,
        [],
        rule_policy=RulePolicy(enabled_rule_ids=frozenset(rule_ids or (_RULE_ID,))),
    )


def _evidence(finding) -> dict[str, list[str]]:
    return {item.key: item.values for item in finding.evidence}


class AzurePublicAppServiceBlobDisruptionRuleTests(unittest.TestCase):
    def test_delete_only_authority_belongs_to_disruption_rule(self) -> None:
        _, findings = _evaluate(
            [
                _storage_account(),
                _storage_container(),
                _public(_web_app()),
                _custom_role(
                    data_actions=[_DELETE],
                ),
                _custom_role_assignment(),
            ],
            _RULE_ID,
            _MUTATION_RULE_ID,
        )

        self.assertEqual([finding.rule_id for finding in findings], [_RULE_ID])

    def test_public_current_blob_delete_emits_dos_without_permanent_loss_claim(self) -> None:
        _, findings = _evaluate(
            [
                _storage_account(versioning_enabled=True, blob_delete_days=30),
                _storage_container(),
                _public(_web_app()),
                _role_assignment(),
            ]
        )

        self.assertEqual([finding.rule_id for finding in findings], [_RULE_ID])
        finding = findings[0]
        self.assertEqual(finding.severity.value, "high")
        evidence = _evidence(finding)
        self.assertTrue(
            any(
                f"operation={_DELETE}" in value
                and "operation_class=logical_blob_deletion" in value
                and "target_granularity=container_blob_namespace" in value
                for value in evidence["storage_blob_deletion_paths"]
            )
        )
        self.assertTrue(
            any(
                "recovery_state=live_blob_delete_may_leave_noncurrent_version" in value
                and "permanent_loss_established=false" in value
                for value in evidence["recovery_posture"]
            )
        )
        self.assertNotIn("permanent loss capability", finding.rationale)
        self.assertNotIn("permanent_loss_established=true", " ".join(evidence["recovery_posture"]))

    def test_container_label_does_not_replace_configured_azure_name(self) -> None:
        container = _resource(
            AzureResourceType.STORAGE_CONTAINER,
            {
                "id": "https://ordersdata.blob.core.windows.net/orders",
                "resource_manager_id": f"{_STORAGE_ACCOUNT_ID}/blobServices/default/containers/orders",
                "name": "orders",
                "storage_account_id": "azurerm_storage_account.orders.id",
                "container_access_type": "private",
            },
            name="application_data",
        )
        _, findings = _evaluate(
            [
                _storage_account(),
                container,
                _public(_web_app()),
                _role_assignment(scope="azurerm_storage_container.application_data.resource_manager_id"),
            ]
        )

        self.assertEqual([finding.rule_id for finding in findings], [_RULE_ID])

    def test_known_absent_blob_soft_delete_reports_no_observed_version_recovery(self) -> None:
        account = _storage_account()
        blob_properties = account.values["blob_properties"]
        assert isinstance(blob_properties, list)
        blob_property = blob_properties[0]
        assert isinstance(blob_property, dict)
        blob_property.pop("delete_retention_policy")

        _, findings = _evaluate(
            [
                account,
                _storage_container(),
                _public(_web_app()),
                _role_assignment(
                    role_name="Storage Blob Data Owner",
                    role_definition_id=(
                        "/subscriptions/sub-0001/providers/Microsoft.Authorization/roleDefinitions/"
                        "b7e6dc6d-f1e8-4753-8033-0f276bb0955b"
                    ),
                ),
            ]
        )

        self.assertEqual(len(findings), 1)
        self.assertTrue(
            any(
                f"operation={_DELETE_VERSION}" in value
                and "recovery_state=version_delete_recovery_not_observed" in value
                for value in _evidence(findings[0])["recovery_posture"]
            )
        )

    def test_unknown_blob_soft_delete_reports_unknown_version_recovery(self) -> None:
        account = _storage_account(blob_delete_days=None)
        account.unknown_values["blob_properties"] = [
            {
                "delete_retention_policy": [
                    {
                        "days": True,
                    }
                ],
            }
        ]

        _, findings = _evaluate(
            [
                account,
                _storage_container(),
                _public(_web_app()),
                _role_assignment(
                    role_name="Storage Blob Data Owner",
                    role_definition_id=(
                        "/subscriptions/sub-0001/providers/Microsoft.Authorization/roleDefinitions/"
                        "b7e6dc6d-f1e8-4753-8033-0f276bb0955b"
                    ),
                ),
            ]
        )

        self.assertEqual(len(findings), 1)
        self.assertTrue(
            any(
                f"operation={_DELETE_VERSION}" in value and "recovery_state=recovery_posture_unknown" in value
                for value in _evidence(findings[0])["recovery_posture"]
            )
        )

    def test_owner_emits_operation_exact_current_and_version_deletion_paths(self) -> None:
        _, findings = _evaluate(
            [
                _storage_account(versioning_enabled=True, blob_delete_days=30),
                _storage_container(),
                _public(_web_app()),
                _role_assignment(
                    role_name="Storage Blob Data Owner",
                    role_definition_id=(
                        "/subscriptions/sub-0001/providers/Microsoft.Authorization/roleDefinitions/"
                        "b7e6dc6d-f1e8-4753-8033-0f276bb0955b"
                    ),
                ),
            ]
        )

        self.assertEqual(len(findings), 1)
        evidence = _evidence(findings[0])
        paths = evidence["storage_blob_deletion_paths"]
        self.assertTrue(any(f"operation={_DELETE}" in value for value in paths))
        self.assertTrue(any(f"operation={_DELETE_VERSION}" in value for value in paths))
        recovery = evidence["recovery_posture"]
        self.assertTrue(
            any(
                f"operation={_DELETE}" in value
                and "recovery_state=live_blob_delete_may_leave_noncurrent_version" in value
                for value in recovery
            )
        )
        self.assertTrue(
            any(
                f"operation={_DELETE_VERSION}" in value
                and "recovery_state=soft_delete_recoverable_during_retention" in value
                for value in recovery
            )
        )
        self.assertNotIn("permanent_loss_established=true", " ".join(recovery))

    def test_hns_disables_version_deletion_but_current_delete_remains(self) -> None:
        _, findings = _evaluate(
            [
                _storage_account(hns_enabled=True),
                _storage_container(),
                _public(_web_app()),
                _role_assignment(
                    role_name="Storage Blob Data Owner",
                    role_definition_id=(
                        "/subscriptions/sub-0001/providers/Microsoft.Authorization/roleDefinitions/"
                        "b7e6dc6d-f1e8-4753-8033-0f276bb0955b"
                    ),
                ),
            ]
        )

        self.assertEqual(len(findings), 1)
        evidence = _evidence(findings[0])
        self.assertTrue(any(f"operation={_DELETE}" in value for value in evidence["storage_blob_deletion_paths"]))
        self.assertFalse(
            any(f"operation={_DELETE_VERSION}" in value for value in evidence["storage_blob_deletion_paths"])
        )

    def test_unknown_hns_keeps_version_authority_and_recovery_uncertain(self) -> None:
        _, findings = _evaluate(
            [
                _storage_account(unknown_recovery=True),
                _storage_container(),
                _public(_web_app()),
                _role_assignment(
                    role_name="Storage Blob Data Owner",
                    role_definition_id=(
                        "/subscriptions/sub-0001/providers/Microsoft.Authorization/roleDefinitions/"
                        "b7e6dc6d-f1e8-4753-8033-0f276bb0955b"
                    ),
                ),
            ]
        )

        self.assertEqual(len(findings), 1)
        evidence = _evidence(findings[0])
        recovery = " ".join(evidence["recovery_posture"])
        self.assertIn(f"operation={_DELETE_VERSION}", recovery)
        self.assertIn("recovery_state=recovery_posture_unknown", recovery)
        self.assertIn("lifecycle_compatibility_state=unknown", recovery)

    def test_private_app_service_stays_quiet(self) -> None:
        _, findings = _evaluate(
            [
                _storage_account(),
                _storage_container(),
                _web_app(),
                _role_assignment(),
            ]
        )
        self.assertEqual(findings, [])

    def test_stale_authorization_source_addresses_suppress_copied_path(self) -> None:
        inventory, _ = _evaluate(
            [
                _storage_account(),
                _storage_container(),
                _public(_web_app()),
                _role_assignment(),
            ]
        )
        app = inventory.get_by_address("azurerm_linux_web_app.orders")
        assert app is not None
        facts = azure_facts(app)
        path = dict(facts.app_service_blob_deletion_paths[0])
        path["authorization_source_addresses"] = []
        facts.set_app_service_blob_deletion_paths([path])

        findings = StrideRuleEngine().evaluate(
            inventory,
            [],
            rule_policy=RulePolicy(enabled_rule_ids=frozenset({_RULE_ID})),
        )
        self.assertEqual(findings, [])

    def test_removed_cached_storage_access_record_does_not_erase_current_authority(self) -> None:
        inventory, original_findings = _evaluate(
            [
                _storage_account(),
                _storage_container(),
                _public(_web_app()),
                _role_assignment(),
            ]
        )
        app = inventory.get_by_address("azurerm_linux_web_app.orders")
        assert app is not None
        facts = azure_facts(app)
        facts.set_app_service_storage_access_paths([])

        findings = StrideRuleEngine().evaluate(
            inventory,
            [],
            rule_policy=RulePolicy(enabled_rule_ids=frozenset({_RULE_ID})),
        )
        self.assertEqual(findings, original_findings)

    def test_current_public_state_is_revalidated_against_copied_path(self) -> None:
        inventory, _ = _evaluate(
            [
                _storage_account(),
                _storage_container(),
                _public(_web_app()),
                _role_assignment(),
            ]
        )
        app = inventory.get_by_address("azurerm_linux_web_app.orders")
        assert app is not None
        azure_facts(app).set(AzureResourceMetadata.PUBLIC_NETWORK_ACCESS_ENABLED, False)

        findings = StrideRuleEngine().evaluate(
            inventory,
            [],
            rule_policy=RulePolicy(enabled_rule_ids=frozenset({_RULE_ID})),
        )
        self.assertEqual(findings, [])


if __name__ == "__main__":
    unittest.main()
