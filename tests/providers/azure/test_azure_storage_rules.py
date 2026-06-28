from __future__ import annotations

import unittest

from tfstride.analysis.boundaries import detect_trust_boundaries
from tfstride.analysis.rule_registry import RulePolicy
from tfstride.analysis.stride_rules import StrideRuleEngine
from tfstride.models import TerraformResource
from tfstride.providers.azure.normalizer import AzureNormalizer
from tfstride.providers.azure.resource_types import AzureResourceType
from tfstride.providers.azure.rules import AZURE_RULE_GROUP_IDS


def _resource(
    resource_type: str,
    name: str,
    values: dict[str, object],
    *,
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


def _account(
    *,
    allow_public: bool = False,
    shared_key: bool = False,
    min_tls: str = "TLS1_2",
    public_network: bool = False,
    default_action: str | None = None,
    cmk_key_id: str | None = None,
    infrastructure_encryption: bool | None = None,
    blob_versioning: bool | None = None,
    blob_delete_days: int | None = None,
    container_delete_days: int | None = None,
    restore_days: int | None = None,
) -> TerraformResource:
    values: dict[str, object] = {
        "id": "/subscriptions/example/resourceGroups/app/providers/Microsoft.Storage/storageAccounts/logs",
        "name": "tfstridelogs",
        "allow_nested_items_to_be_public": allow_public,
        "shared_access_key_enabled": shared_key,
        "min_tls_version": min_tls,
        "public_network_access_enabled": public_network,
    }
    if default_action is not None:
        values["network_rules"] = [{"default_action": default_action}]
    if cmk_key_id is not None:
        values["customer_managed_key"] = [
            {
                "key_vault_key_id": cmk_key_id,
                "user_assigned_identity_id": "azurerm_user_assigned_identity.storage.id",
            }
        ]
    if infrastructure_encryption is not None:
        values["infrastructure_encryption_enabled"] = infrastructure_encryption

    blob_properties: dict[str, object] = {}
    if blob_versioning is not None:
        blob_properties["versioning_enabled"] = blob_versioning
    if blob_delete_days is not None:
        blob_properties["delete_retention_policy"] = [{"days": blob_delete_days}]
    if container_delete_days is not None:
        blob_properties["container_delete_retention_policy"] = [{"days": container_delete_days}]
    if restore_days is not None:
        blob_properties["restore_policy"] = [{"days": restore_days}]
    if blob_properties:
        values["blob_properties"] = [blob_properties]

    return _resource(AzureResourceType.STORAGE_ACCOUNT, "logs", values)


def _container(access_type: str = "private") -> TerraformResource:
    return _resource(
        AzureResourceType.STORAGE_CONTAINER,
        "objects",
        {
            "name": "objects",
            "storage_account_id": "azurerm_storage_account.logs.id",
            "container_access_type": access_type,
        },
    )


def _evaluate(resources: list[TerraformResource], *rule_ids: str):
    inventory = AzureNormalizer().normalize(resources)
    boundaries = detect_trust_boundaries(inventory)
    findings = StrideRuleEngine().evaluate(
        inventory,
        boundaries,
        rule_policy=RulePolicy(enabled_rule_ids=frozenset(rule_ids)),
    )
    return inventory, boundaries, findings


_STORAGE_ENCRYPTION_RECOVERY_RULE_IDS = (
    "azure-storage-account-customer-managed-key-missing",
    "azure-storage-account-infrastructure-encryption-not-enabled",
    "azure-storage-account-blob-versioning-disabled",
    "azure-storage-account-blob-soft-delete-insufficient",
    "azure-storage-account-container-soft-delete-insufficient",
    "azure-storage-account-point-in-time-restore-missing",
)


_STORAGE_SAFE_POSTURE = {
    "cmk_key_id": "azurerm_key_vault_key.storage.id",
    "infrastructure_encryption": True,
    "blob_versioning": True,
    "blob_delete_days": 30,
    "container_delete_days": 14,
    "restore_days": 7,
}


def _storage_safe_posture(**overrides: object) -> dict[str, object]:
    posture = dict(_STORAGE_SAFE_POSTURE)
    posture.update(overrides)
    return posture


def _finding_ids(findings) -> list[str]:
    return [finding.rule_id for finding in findings]


class AzureStorageRuleTests(unittest.TestCase):
    def test_public_container_access_is_detected_with_account_boundary(self) -> None:
        _, boundaries, findings = _evaluate(
            [
                _account(allow_public=True, public_network=True),
                _container("blob"),
            ],
            "azure-storage-container-public-access",
        )

        self.assertEqual(len(boundaries), 1)
        self.assertEqual(len(findings), 1)
        finding = findings[0]
        self.assertEqual(finding.rule_id, "azure-storage-container-public-access")
        self.assertEqual(finding.severity.value, "medium")
        self.assertEqual(
            finding.affected_resources,
            ["azurerm_storage_account.logs", "azurerm_storage_container.objects"],
        )
        self.assertEqual(
            finding.trust_boundary_id,
            "internet-to-service:internet->azurerm_storage_account.logs",
        )

    def test_public_container_is_not_flagged_when_account_blocks_nested_access(self) -> None:
        _, _, findings = _evaluate(
            [
                _account(allow_public=False, public_network=True),
                _container("container"),
            ],
            "azure-storage-container-public-access",
        )

        self.assertEqual(findings, [])

    def test_nested_public_access_setting_is_detected(self) -> None:
        _, _, findings = _evaluate(
            [_account(allow_public=True)],
            "azure-storage-account-nested-public-access-enabled",
        )

        self.assertEqual(
            [finding.rule_id for finding in findings], ["azure-storage-account-nested-public-access-enabled"]
        )

    def test_shared_key_authorization_is_detected(self) -> None:
        _, _, findings = _evaluate(
            [_account(shared_key=True)],
            "azure-storage-account-shared-key-enabled",
        )

        self.assertEqual([finding.rule_id for finding in findings], ["azure-storage-account-shared-key-enabled"])
        evidence = {item.key: item.values for item in findings[0].evidence}
        self.assertEqual(evidence["authorization_posture"], ["shared_access_key_enabled is true"])

    def test_tls_below_1_2_is_detected(self) -> None:
        _, _, findings = _evaluate(
            [_account(min_tls="TLS1_1")],
            "azure-storage-account-minimum-tls-below-1-2",
        )

        self.assertEqual([finding.rule_id for finding in findings], ["azure-storage-account-minimum-tls-below-1-2"])
        evidence = {item.key: item.values for item in findings[0].evidence}
        self.assertEqual(evidence["transport_posture"], ["min_tls_version is TLS1_1"])

    def test_tls_1_2_is_not_flagged(self) -> None:
        _, _, findings = _evaluate(
            [_account(min_tls="TLS1_2")],
            "azure-storage-account-minimum-tls-below-1-2",
        )

        self.assertEqual(findings, [])

    def test_unrestricted_public_network_is_detected(self) -> None:
        _, _, findings = _evaluate(
            [_account(public_network=True)],
            "azure-storage-account-public-network-unrestricted",
        )

        self.assertEqual(
            [finding.rule_id for finding in findings], ["azure-storage-account-public-network-unrestricted"]
        )
        evidence = {item.key: item.values for item in findings[0].evidence}
        self.assertEqual(
            evidence["network_posture"],
            [
                "public_network_access_enabled is true",
                "effective default_action is Allow",
                "network rule source is account default",
            ],
        )

    def test_disabled_public_network_suppresses_public_network_finding(self) -> None:
        _, boundaries, findings = _evaluate(
            [_account(public_network=False, default_action="Allow")],
            "azure-storage-account-public-network-unrestricted",
        )

        self.assertEqual(boundaries, [])
        self.assertEqual(findings, [])

    def test_restricted_standalone_default_deny_suppresses_public_network_finding(self) -> None:
        network_rules = _resource(
            AzureResourceType.STORAGE_ACCOUNT_NETWORK_RULES,
            "logs",
            {
                "storage_account_id": "azurerm_storage_account.logs.id",
                "default_action": "Deny",
                "ip_rules": ["198.51.100.10"],
            },
        )
        _, _, findings = _evaluate(
            [_account(public_network=True), network_rules],
            "azure-storage-account-public-network-unrestricted",
        )

        self.assertEqual(findings, [])

    def test_storage_encryption_and_recovery_gaps_are_detected(self) -> None:
        _, _, findings = _evaluate(
            [
                _account(
                    infrastructure_encryption=False,
                    blob_versioning=False,
                )
            ],
            *_STORAGE_ENCRYPTION_RECOVERY_RULE_IDS,
        )

        self.assertEqual(_finding_ids(findings), list(_STORAGE_ENCRYPTION_RECOVERY_RULE_IDS))
        evidence_by_rule = {
            finding.rule_id: {item.key: item.values for item in finding.evidence} for finding in findings
        }
        self.assertEqual(
            evidence_by_rule["azure-storage-account-customer-managed-key-missing"]["encryption_ownership"],
            [
                "customer_managed_key_state=not_configured",
                "key_vault_key_id is unset",
                "Azure Storage encryption by default is still enabled; this finding concerns customer key control",
            ],
        )
        self.assertEqual(
            evidence_by_rule["azure-storage-account-infrastructure-encryption-not-enabled"][
                "infrastructure_encryption"
            ],
            ["infrastructure_encryption_enabled is disabled"],
        )
        self.assertEqual(
            evidence_by_rule["azure-storage-account-blob-versioning-disabled"]["versioning_posture"],
            ["blob_properties.versioning_enabled is disabled"],
        )
        self.assertEqual(
            evidence_by_rule["azure-storage-account-blob-soft-delete-insufficient"]["blob_soft_delete_posture"],
            ["blob_properties.delete_retention_policy.days_state=disabled_or_missing", "minimum_retention_days=7"],
        )
        self.assertEqual(
            evidence_by_rule["azure-storage-account-container-soft-delete-insufficient"][
                "container_soft_delete_posture"
            ],
            [
                "blob_properties.container_delete_retention_policy.days_state=disabled_or_missing",
                "minimum_retention_days=7",
            ],
        )
        self.assertEqual(
            evidence_by_rule["azure-storage-account-point-in-time-restore-missing"]["point_in_time_restore_posture"],
            ["blob_properties.restore_policy.days_state=disabled_or_missing", "minimum_retention_days=7"],
        )

    def test_hardened_storage_recovery_posture_is_not_flagged(self) -> None:
        _, _, findings = _evaluate(
            [_account(**_storage_safe_posture())],
            *_STORAGE_ENCRYPTION_RECOVERY_RULE_IDS,
        )

        self.assertEqual(findings, [])

    def test_short_storage_retention_is_detected_with_threshold_evidence(self) -> None:
        _, _, findings = _evaluate(
            [
                _account(
                    **_storage_safe_posture(
                        blob_delete_days=3,
                        container_delete_days=5,
                    )
                )
            ],
            *_STORAGE_ENCRYPTION_RECOVERY_RULE_IDS,
        )

        self.assertEqual(
            _finding_ids(findings),
            [
                "azure-storage-account-blob-soft-delete-insufficient",
                "azure-storage-account-container-soft-delete-insufficient",
            ],
        )
        evidence_by_rule = {
            finding.rule_id: {item.key: item.values for item in finding.evidence} for finding in findings
        }
        self.assertEqual(
            evidence_by_rule["azure-storage-account-blob-soft-delete-insufficient"]["blob_soft_delete_posture"],
            [
                "blob_properties.delete_retention_policy.days_state=short",
                "retention_days=3",
                "minimum_retention_days=7",
            ],
        )
        self.assertEqual(
            evidence_by_rule["azure-storage-account-container-soft-delete-insufficient"][
                "container_soft_delete_posture"
            ],
            [
                "blob_properties.container_delete_retention_policy.days_state=short",
                "retention_days=5",
                "minimum_retention_days=7",
            ],
        )

    def test_unknown_storage_recovery_posture_is_reported_without_disabled_claims(self) -> None:
        unknown_account = _resource(
            AzureResourceType.STORAGE_ACCOUNT,
            "logs",
            {
                "name": "tfstridelogs",
                "infrastructure_encryption_enabled": None,
                "customer_managed_key": [
                    {
                        "key_vault_key_id": None,
                        "user_assigned_identity_id": None,
                    }
                ],
                "blob_properties": [
                    {
                        "versioning_enabled": None,
                        "delete_retention_policy": [{"days": None}],
                        "container_delete_retention_policy": [{"days": None}],
                        "restore_policy": [{"days": None}],
                    }
                ],
            },
            unknown_values={
                "infrastructure_encryption_enabled": True,
                "customer_managed_key": [
                    {
                        "key_vault_key_id": True,
                        "user_assigned_identity_id": True,
                    }
                ],
                "blob_properties": [
                    {
                        "versioning_enabled": True,
                        "delete_retention_policy": [{"days": True}],
                        "container_delete_retention_policy": [{"days": True}],
                        "restore_policy": [{"days": True}],
                    }
                ],
            },
        )
        _, _, findings = _evaluate([unknown_account], *_STORAGE_ENCRYPTION_RECOVERY_RULE_IDS)

        self.assertEqual(_finding_ids(findings), list(_STORAGE_ENCRYPTION_RECOVERY_RULE_IDS))
        evidence_values = [value for finding in findings for item in finding.evidence for value in item.values]
        self.assertIn("customer_managed_key_state=unknown", evidence_values)
        self.assertIn("infrastructure_encryption_enabled is unknown", evidence_values)
        self.assertIn("blob_properties.versioning_enabled is unknown", evidence_values)
        self.assertIn("blob_properties.delete_retention_policy.days_state=unknown", evidence_values)
        self.assertIn("blob_properties.container_delete_retention_policy.days_state=unknown", evidence_values)
        self.assertIn("blob_properties.restore_policy.days_state=unknown", evidence_values)
        self.assertNotIn("infrastructure_encryption_enabled is disabled", evidence_values)
        self.assertNotIn("blob_properties.versioning_enabled is disabled", evidence_values)

    def test_hardened_storage_account_has_no_azure_storage_findings(self) -> None:
        rule_ids = tuple(rule_id for group in AZURE_RULE_GROUP_IDS for rule_id in group)
        _, boundaries, findings = _evaluate(
            [
                _account(
                    allow_public=False,
                    shared_key=False,
                    min_tls="TLS1_2",
                    public_network=False,
                    default_action="Deny",
                    **_storage_safe_posture(),
                ),
                _container("private"),
            ],
            *rule_ids,
        )

        self.assertEqual(boundaries, [])
        self.assertEqual(findings, [])


if __name__ == "__main__":
    unittest.main()
