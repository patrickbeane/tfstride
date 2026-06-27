from __future__ import annotations

import unittest

from tfstride.analysis.rule_registry import RulePolicy
from tfstride.analysis.stride_rules import StrideRuleEngine
from tfstride.models import TerraformResource
from tfstride.providers.azure.normalizer import AzureNormalizer
from tfstride.providers.azure.resource_types import AzureResourceType

_CUSTOM_ROLE_RULE_IDS = (
    "azure-custom-role-wildcard-management-plane",
    "azure-custom-role-authorization-management",
    "azure-custom-role-broad-management-plane",
    "azure-custom-role-broad-data-plane",
    "azure-custom-role-subscription-assignable-scope",
)


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


def _role_definition(
    *,
    name: str = "custom",
    role_name: str = "Custom Operator",
    scope: str = "/subscriptions/sub-0001",
    assignable_scopes: list[str] | None = None,
    actions: list[str] | None = None,
    not_actions: list[str] | None = None,
    data_actions: list[str] | None = None,
    not_data_actions: list[str] | None = None,
    unknown_values: dict[str, object] | None = None,
) -> TerraformResource:
    return _resource(
        AzureResourceType.ROLE_DEFINITION,
        name,
        {
            "id": f"/subscriptions/sub-0001/providers/Microsoft.Authorization/roleDefinitions/{name}",
            "name": role_name,
            "scope": scope,
            "assignable_scopes": [scope] if assignable_scopes is None else assignable_scopes,
            "permissions": [
                {
                    "actions": actions or [],
                    "not_actions": not_actions or [],
                    "data_actions": data_actions or [],
                    "not_data_actions": not_data_actions or [],
                }
            ],
        },
        unknown_values=unknown_values,
    )


def _evaluate(resources: list[TerraformResource], *rule_ids: str):
    inventory = AzureNormalizer().normalize(resources)
    return StrideRuleEngine().evaluate(
        inventory,
        [],
        rule_policy=RulePolicy(enabled_rule_ids=frozenset(rule_ids)),
    )


class AzureCustomRoleRuleTests(unittest.TestCase):
    def test_wildcard_management_plane_custom_role_is_detected_as_posture_risk(self) -> None:
        findings = _evaluate(
            [
                _role_definition(
                    role_name="Subscription Operator",
                    actions=["*"],
                    not_actions=["Microsoft.Authorization/elevateAccess/Action"],
                    assignable_scopes=["/subscriptions/sub-0001"],
                )
            ],
            "azure-custom-role-wildcard-management-plane",
        )

        self.assertEqual([finding.rule_id for finding in findings], ["azure-custom-role-wildcard-management-plane"])
        finding = findings[0]
        self.assertEqual(finding.severity.value, "high")
        self.assertEqual(finding.affected_resources, ["azurerm_role_definition.custom"])
        self.assertIn("role-definition posture only", finding.rationale)
        self.assertIn("not asserting that any principal currently has this access", finding.rationale)
        evidence = {item.key: item.values for item in finding.evidence}
        self.assertEqual(evidence["management_actions"], ["*"])
        self.assertEqual(evidence["assignable_scopes"], ["/subscriptions/sub-0001"])
        self.assertEqual(evidence["breadth_signals"], ["owner_like_or_wildcard"])
        self.assertEqual(
            evidence["mitigating_exclusions"],
            ["not_action=Microsoft.Authorization/elevateAccess/Action"],
        )

    def test_authorization_management_custom_role_is_detected(self) -> None:
        findings = _evaluate(
            [
                _role_definition(
                    name="role_admin",
                    role_name="Role Admin",
                    actions=["Microsoft.Authorization/roleAssignments/write"],
                    assignable_scopes=["/subscriptions/sub-0001/resourceGroups/app"],
                )
            ],
            "azure-custom-role-authorization-management",
        )

        self.assertEqual([finding.rule_id for finding in findings], ["azure-custom-role-authorization-management"])
        self.assertEqual(findings[0].severity.value, "medium")
        evidence = {item.key: item.values for item in findings[0].evidence}
        self.assertEqual(evidence["authorization_actions"], ["Microsoft.Authorization/roleAssignments/write"])
        self.assertEqual(
            evidence["breadth_signals"],
            ["authorization_management", "role_assignment_capable"],
        )

    def test_broad_management_plane_wildcard_custom_role_is_detected(self) -> None:
        findings = _evaluate(
            [
                _role_definition(
                    name="compute_admin",
                    role_name="Compute Admin",
                    actions=["Microsoft.Compute/virtualMachines/*"],
                    assignable_scopes=["/subscriptions/sub-0001/resourceGroups/app"],
                )
            ],
            "azure-custom-role-broad-management-plane",
        )

        self.assertEqual([finding.rule_id for finding in findings], ["azure-custom-role-broad-management-plane"])
        self.assertEqual(findings[0].severity.value, "medium")
        evidence = {item.key: item.values for item in findings[0].evidence}
        self.assertEqual(evidence["management_actions"], ["Microsoft.Compute/virtualMachines/*"])
        self.assertEqual(evidence["breadth_signals"], ["compute_management"])

    def test_broad_data_plane_custom_role_is_detected(self) -> None:
        findings = _evaluate(
            [
                _role_definition(
                    name="secret_reader",
                    role_name="Secret Reader",
                    data_actions=["Microsoft.KeyVault/vaults/secrets/*"],
                    not_data_actions=["Microsoft.KeyVault/vaults/secrets/delete"],
                    assignable_scopes=["/subscriptions/sub-0001"],
                )
            ],
            "azure-custom-role-broad-data-plane",
        )

        self.assertEqual([finding.rule_id for finding in findings], ["azure-custom-role-broad-data-plane"])
        self.assertEqual(findings[0].severity.value, "high")
        evidence = {item.key: item.values for item in findings[0].evidence}
        self.assertEqual(evidence["data_plane_actions"], ["Microsoft.KeyVault/vaults/secrets/*"])
        self.assertEqual(evidence["breadth_signals"], ["key_vault_data_plane"])
        self.assertEqual(
            evidence["mitigating_exclusions"],
            ["not_data_action=Microsoft.KeyVault/vaults/secrets/delete"],
        )

    def test_subscription_assignable_custom_role_is_detected_without_active_assignment_claim(self) -> None:
        findings = _evaluate(
            [
                _role_definition(
                    name="storage_reader",
                    role_name="Storage Reader",
                    actions=["Microsoft.Storage/storageAccounts/blobServices/containers/read"],
                    assignable_scopes=["/subscriptions/sub-0001"],
                )
            ],
            "azure-custom-role-subscription-assignable-scope",
        )

        self.assertEqual(
            [finding.rule_id for finding in findings],
            ["azure-custom-role-subscription-assignable-scope"],
        )
        self.assertEqual(findings[0].severity.value, "medium")
        self.assertNotIn("Principal has", findings[0].rationale)
        evidence = {item.key: item.values for item in findings[0].evidence}
        self.assertEqual(evidence["assignable_scopes"], ["/subscriptions/sub-0001"])
        self.assertEqual(evidence["breadth_signals"], ["storage_data_plane"])

    def test_least_privilege_resource_group_custom_role_stays_quiet(self) -> None:
        findings = _evaluate(
            [
                _role_definition(
                    name="reader",
                    role_name="Reader",
                    actions=["Microsoft.Storage/storageAccounts/blobServices/containers/read"],
                    assignable_scopes=["/subscriptions/sub-0001/resourceGroups/app"],
                )
            ],
            *_CUSTOM_ROLE_RULE_IDS,
        )

        self.assertEqual(findings, [])

    def test_unknown_permissions_do_not_infer_custom_role_breadth(self) -> None:
        findings = _evaluate(
            [
                _role_definition(
                    name="pending",
                    role_name="Pending",
                    assignable_scopes=[],
                    unknown_values={"permissions": [{"actions": True, "data_actions": True}]},
                )
            ],
            *_CUSTOM_ROLE_RULE_IDS,
        )

        self.assertEqual(findings, [])


if __name__ == "__main__":
    unittest.main()
