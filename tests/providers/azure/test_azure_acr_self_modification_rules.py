from __future__ import annotations

import unittest
from collections import Counter

from tests.providers.azure.test_azure_acr_write_paths import (
    _SYSTEM_PRINCIPAL_ID,
    _registry,
    _role_assignment,
    _role_definition,
    _web_app,
)
from tfstride.analysis.rule_registry import RulePolicy
from tfstride.analysis.stride_rules import StrideRuleEngine
from tfstride.models import TerraformResource
from tfstride.providers.azure.normalizer import AzureNormalizer
from tfstride.providers.azure.rules import AZURE_RULE_GROUP_IDS

_RULE_ID = "azure-app-service-can-modify-image-repository"
_IMAGE_PIN_RULE = "azure-app-service-image-not-digest-pinned"
_CUSTOM_ROLE_ID = "/subscriptions/sub-0001/providers/Microsoft.Authorization/roleDefinitions/custom-acr-writer"
_DIGEST = "sha256:" + "a" * 64


def _evaluate(resources: list[TerraformResource], *rule_ids: str):
    inventory = AzureNormalizer().normalize(resources)
    return StrideRuleEngine().evaluate(
        inventory,
        [],
        rule_policy=RulePolicy(enabled_rule_ids=frozenset(rule_ids or {_RULE_ID})),
    )


def _evidence(finding):
    return {item.key: item.values for item in finding.evidence}


class AzureAcrSelfModificationRuleTests(unittest.TestCase):
    def test_rule_is_registered(self) -> None:
        registered = {rule_id for group in AZURE_RULE_GROUP_IDS for rule_id in group}
        self.assertIn(_RULE_ID, registered)

    def test_system_assigned_identity_with_acr_push_is_detected(self) -> None:
        findings = _evaluate([_registry(), _web_app(), _role_assignment()])

        self.assertEqual([finding.rule_id for finding in findings], [_RULE_ID])
        finding = findings[0]
        self.assertEqual(finding.severity.value, "medium")
        self.assertEqual(
            finding.affected_resources,
            [
                "azurerm_linux_web_app.api",
                "azurerm_container_registry.images",
                "azurerm_role_assignment.push",
            ],
        )
        self.assertIn("self-modification and persistence path", finding.rationale)
        evidence = _evidence(finding)
        self.assertIn(
            "identity_address=azurerm_linux_web_app.api",
            evidence["runtime_identity"],
        )
        self.assertIn("identity_kind=system_assigned", evidence["runtime_identity"])
        self.assertIn(f"principal_id={_SYSTEM_PRINCIPAL_ID}", evidence["runtime_identity"])
        self.assertIn("role_definition_name=AcrPush", evidence["runtime_identity"])
        self.assertIn("grant_basis=azure_registry_scoped_rbac", evidence["acr_write_path"])
        self.assertIn("registry_scope=exact_container_registry", evidence["acr_write_path"])
        self.assertIn("login_server=images.azurecr.io", evidence["container_registry"])
        self.assertNotIn("custom_role_permissions", evidence)

    def test_deterministic_custom_role_content_write_is_detected(self) -> None:
        findings = _evaluate(
            [
                _registry(),
                _web_app(),
                _role_definition(
                    data_actions=["Microsoft.ContainerRegistry/registries/repositories/content/write"],
                    role_definition_id=_CUSTOM_ROLE_ID,
                ),
                _role_assignment(
                    role_name=None,
                    role_definition_id=_CUSTOM_ROLE_ID,
                ),
            ]
        )

        self.assertEqual([finding.rule_id for finding in findings], [_RULE_ID])
        finding = findings[0]
        self.assertEqual(
            finding.affected_resources,
            [
                "azurerm_linux_web_app.api",
                "azurerm_container_registry.images",
                "azurerm_role_assignment.push",
                "azurerm_role_definition.custom_acr_writer",
            ],
        )
        evidence = _evidence(finding)
        self.assertIn("role_kind=custom_writer", evidence["runtime_identity"])
        self.assertIn(
            "grant_basis=azure_custom_role_registry_scoped_rbac",
            evidence["acr_write_path"],
        )
        self.assertIn(
            "role_definition_address=azurerm_role_definition.custom_acr_writer",
            evidence["custom_role_permissions"],
        )
        self.assertTrue(
            any(
                "microsoft.containerregistry/registries/repositories/content/write" in value
                for value in evidence["custom_role_permissions"]
            )
        )

    def test_digest_pinned_image_is_quiet(self) -> None:
        findings = _evaluate(
            [
                _registry(),
                _web_app(image=f"team/api@{_DIGEST}"),
                _role_assignment(),
            ]
        )

        self.assertEqual(findings, [])

    def test_custom_role_deny_and_management_only_permissions_are_quiet(self) -> None:
        denied = _evaluate(
            [
                _registry(),
                _web_app(),
                _role_definition(
                    data_actions=["Microsoft.ContainerRegistry/registries/*"],
                    not_data_actions=["Microsoft.ContainerRegistry/registries/*"],
                    role_definition_id=_CUSTOM_ROLE_ID,
                ),
                _role_assignment(
                    role_name=None,
                    role_definition_id=_CUSTOM_ROLE_ID,
                ),
            ]
        )
        management_only = _evaluate(
            [
                _registry(),
                _web_app(),
                _role_definition(
                    actions=["Microsoft.ContainerRegistry/registries/write"],
                    data_actions=[],
                    role_definition_id=_CUSTOM_ROLE_ID,
                ),
                _role_assignment(
                    role_name=None,
                    role_definition_id=_CUSTOM_ROLE_ID,
                ),
            ]
        )

        self.assertEqual(denied, [])
        self.assertEqual(management_only, [])

    def test_conditional_or_nonexact_assignment_is_quiet(self) -> None:
        conditional = _evaluate(
            [
                _registry(),
                _web_app(),
                _role_assignment(
                    condition=(
                        "@Resource[Microsoft.ContainerRegistry/registries/repositories:name] stringEquals 'team/api'"
                    )
                ),
            ]
        )
        broad_scope = _evaluate(
            [
                _registry(),
                _web_app(),
                _role_assignment(scope="/subscriptions/sub-0001/resourceGroups/app"),
            ]
        )

        self.assertEqual(conditional, [])
        self.assertEqual(broad_scope, [])

    def test_self_modification_finding_remains_distinct_from_digest_pin_finding(self) -> None:
        findings = _evaluate(
            [_registry(), _web_app(), _role_assignment()],
            _IMAGE_PIN_RULE,
            _RULE_ID,
        )

        self.assertEqual(
            Counter(finding.rule_id for finding in findings),
            Counter({_IMAGE_PIN_RULE: 1, _RULE_ID: 1}),
        )


if __name__ == "__main__":
    unittest.main()
