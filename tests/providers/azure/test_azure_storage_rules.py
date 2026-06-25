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
) -> TerraformResource:
    return TerraformResource(
        address=f"{resource_type}.{name}",
        mode="managed",
        resource_type=resource_type,
        name=name,
        provider_name="registry.terraform.io/hashicorp/azurerm",
        values=values,
    )


def _account(
    *,
    allow_public: bool = False,
    shared_key: bool = False,
    min_tls: str = "TLS1_2",
    public_network: bool = False,
    default_action: str | None = None,
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

    def test_standalone_default_deny_suppresses_public_network_finding(self) -> None:
        network_rules = _resource(
            AzureResourceType.STORAGE_ACCOUNT_NETWORK_RULES,
            "logs",
            {
                "storage_account_id": "azurerm_storage_account.logs.id",
                "default_action": "Deny",
            },
        )
        _, _, findings = _evaluate(
            [_account(public_network=True), network_rules],
            "azure-storage-account-public-network-unrestricted",
        )

        self.assertEqual(findings, [])

    def test_hardened_storage_account_has_no_azure_storage_findings(self) -> None:
        rule_ids = tuple(rule_id for group in AZURE_RULE_GROUP_IDS for rule_id in group)
        _, boundaries, findings = _evaluate(
            [
                _account(
                    allow_public=False,
                    shared_key=False,
                    min_tls="TLS1_2",
                    public_network=True,
                    default_action="Deny",
                ),
                _container("private"),
            ],
            *rule_ids,
        )

        self.assertEqual(boundaries, [])
        self.assertEqual(findings, [])


if __name__ == "__main__":
    unittest.main()
