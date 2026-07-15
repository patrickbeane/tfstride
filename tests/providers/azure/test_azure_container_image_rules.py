from __future__ import annotations

import unittest

from tfstride.analysis.rule_registry import RulePolicy
from tfstride.analysis.stride_rules import StrideRuleEngine
from tfstride.models import TerraformResource
from tfstride.providers.azure.normalizer import AzureNormalizer
from tfstride.providers.azure.resource_types import AzureResourceType
from tfstride.providers.azure.rules import AZURE_RULE_GROUP_IDS

_RULE_ID = "azure-app-service-image-not-digest-pinned"
_DIGEST = "sha256:" + "a" * 64


def _resource(
    resource_type: str,
    values: dict[str, object],
    *,
    name: str = "app",
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


def _web_app(
    image: object,
    *,
    registry_url: object = "https://images.azurecr.io",
    unknown_values: dict[str, object] | None = None,
) -> TerraformResource:
    return _resource(
        AzureResourceType.LINUX_WEB_APP,
        {
            "name": "api",
            "site_config": [
                {
                    "application_stack": [
                        {
                            "docker_image_name": image,
                            "docker_registry_url": registry_url,
                        }
                    ]
                }
            ],
        },
        name="api",
        unknown_values=unknown_values,
    )


def _linux_function_app() -> TerraformResource:
    return _resource(
        AzureResourceType.LINUX_FUNCTION_APP,
        {
            "name": "worker",
            "site_config": [
                {
                    "application_stack": [
                        {
                            "docker": [
                                {
                                    "registry_url": "https://images.azurecr.io",
                                    "image_name": "jobs/worker",
                                    "image_tag": "2026.07",
                                }
                            ]
                        }
                    ]
                }
            ],
        },
        name="worker",
    )


def _evaluate(resources: list[TerraformResource]):
    inventory = AzureNormalizer().normalize(resources)
    return StrideRuleEngine().evaluate(
        inventory,
        [],
        rule_policy=RulePolicy(enabled_rule_ids=frozenset({_RULE_ID})),
    )


def _evidence(finding):
    return {item.key: item.values for item in finding.evidence}


class AzureContainerImageRuleTests(unittest.TestCase):
    def test_rule_is_registered(self) -> None:
        registered = {rule_id for group in AZURE_RULE_GROUP_IDS for rule_id in group}
        self.assertIn(_RULE_ID, registered)

    def test_resolved_app_service_image_without_digest_pin_is_detected(self) -> None:
        findings = _evaluate([_web_app("team/api:stable")])

        self.assertEqual([finding.rule_id for finding in findings], [_RULE_ID])
        self.assertEqual(findings[0].severity.value, "low")
        self.assertEqual(findings[0].affected_resources, ["azurerm_linux_web_app.api"])
        self.assertIn("without a digest pin", findings[0].rationale)
        evidence = _evidence(findings[0])
        self.assertEqual(
            evidence["target_resource"],
            ["address=azurerm_linux_web_app.api", "type=azurerm_linux_web_app"],
        )
        self.assertIn("raw=images.azurecr.io/team/api:stable", evidence["image_reference"])
        self.assertIn("digest_pinned=False", evidence["image_reference"])
        self.assertIn(
            "container_registry_login_server=images.azurecr.io",
            evidence["image_reference"],
        )
        self.assertNotIn("container_registry_posture", evidence)

    def test_linux_function_app_image_without_digest_pin_is_detected(self) -> None:
        findings = _evaluate([_linux_function_app()])

        self.assertEqual([finding.rule_id for finding in findings], [_RULE_ID])
        self.assertEqual(findings[0].affected_resources, ["azurerm_linux_function_app.worker"])

    def test_digest_pinned_image_is_quiet(self) -> None:
        self.assertEqual(_evaluate([_web_app(f"team/api@{_DIGEST}")]), [])

    def test_computed_image_is_not_overclaimed(self) -> None:
        self.assertEqual(
            _evaluate(
                [
                    _web_app(
                        None,
                        unknown_values={
                            "site_config": [
                                {
                                    "application_stack": [
                                        {"docker_image_name": True},
                                    ]
                                }
                            ]
                        },
                    )
                ]
            ),
            [],
        )

    def test_registry_mismatch_is_not_treated_as_resolved(self) -> None:
        self.assertEqual(
            _evaluate([_web_app("other.example.com/team/api:stable")]),
            [],
        )


if __name__ == "__main__":
    unittest.main()
