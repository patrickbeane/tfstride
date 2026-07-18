from __future__ import annotations

import unittest

from tfstride.analysis.rule_registry import RulePolicy
from tfstride.analysis.stride_rules import StrideRuleEngine
from tfstride.models import TerraformResource
from tfstride.providers.azure.normalizer import AzureNormalizer
from tfstride.providers.azure.resource_types import AzureResourceType
from tfstride.providers.azure.rules import AZURE_RULE_GROUP_IDS

_RULE_ID = "azure-app-service-sensitive-app-setting-inline"


def _app(
    app_settings: dict[str, object],
    *,
    resource_type: str = AzureResourceType.LINUX_WEB_APP,
    unknown_values: dict[str, object] | None = None,
) -> TerraformResource:
    return TerraformResource(
        address=f"{resource_type}.app",
        mode="managed",
        resource_type=resource_type,
        name="app",
        provider_name="registry.terraform.io/hashicorp/azurerm",
        values={
            "id": "/subscriptions/example/resourceGroups/app/providers/Microsoft.Web/sites/app",
            "name": "app",
            "app_settings": app_settings,
        },
        unknown_values=unknown_values or {},
    )


def _evaluate(resource: TerraformResource):
    return StrideRuleEngine().evaluate(
        AzureNormalizer().normalize([resource]),
        [],
        rule_policy=RulePolicy(enabled_rule_ids=frozenset({_RULE_ID})),
    )


def _evidence_by_key(finding):
    return {item.key: item.values for item in finding.evidence}


class AzureAppServiceSecretDeliveryRuleTests(unittest.TestCase):
    def test_rule_id_is_registered(self) -> None:
        registered = {rule_id for group in AZURE_RULE_GROUP_IDS for rule_id in group}

        self.assertIn(_RULE_ID, registered)

    def test_sensitive_literal_app_setting_is_reported_without_its_value(self) -> None:
        literal = "do-not-leak-this-password"
        findings = _evaluate(
            _app(
                {
                    "DB_PASSWORD": literal,
                    "LOG_LEVEL": "info",
                }
            )
        )

        self.assertEqual([finding.rule_id for finding in findings], [_RULE_ID])
        finding = findings[0]
        self.assertEqual(finding.severity.value, "medium")
        self.assertEqual(finding.affected_resources, ["azurerm_linux_web_app.app"])
        evidence = _evidence_by_key(finding)
        self.assertEqual(
            evidence["sensitive_setting"],
            ["path=app_settings['DB_PASSWORD']; setting=db_password; category=password; value=<redacted>"],
        )
        self.assertEqual(
            evidence["delivery_posture"],
            ["source=azurerm_linux_web_app", "setting_key=DB_PASSWORD", "state=literal"],
        )
        self.assertNotIn(literal, repr(finding))

    def test_function_app_sensitive_literal_is_reported(self) -> None:
        literal = "do-not-leak-this-token"
        findings = _evaluate(
            _app(
                {"AUTH_TOKEN": literal},
                resource_type=AzureResourceType.WINDOWS_FUNCTION_APP,
            )
        )

        self.assertEqual([finding.rule_id for finding in findings], [_RULE_ID])
        self.assertEqual(findings[0].affected_resources, ["azurerm_windows_function_app.app"])
        self.assertNotIn(literal, repr(findings[0]))

    def test_key_vault_secret_uri_references_remain_quiet(self) -> None:
        references = (
            "@Microsoft.KeyVault(SecretUri=https://app-vault.vault.azure.net/secrets/database-password)",
            ("@Microsoft.KeyVault(SecretUri=https://app-vault.vault.azure.net/secrets/database-password/abc123)"),
        )

        for reference in references:
            with self.subTest(reference=reference):
                self.assertEqual(_evaluate(_app({"DB_PASSWORD": reference})), [])

    def test_unresolved_key_vault_reference_remains_quiet(self) -> None:
        findings = _evaluate(
            _app({"DB_PASSWORD": ("@Microsoft.KeyVault(VaultName=app-vault;SecretName=database-password)")})
        )

        self.assertEqual(findings, [])

    def test_unknown_sensitive_value_remains_quiet(self) -> None:
        findings = _evaluate(
            _app(
                {"API_KEY": None},
                unknown_values={"app_settings": {"API_KEY": True}},
            )
        )

        self.assertEqual(findings, [])

    def test_non_sensitive_literal_settings_remain_quiet(self) -> None:
        findings = _evaluate(
            _app(
                {
                    "LOG_LEVEL": "debug",
                    "SECRET_URI": "not-secret-material",
                }
            )
        )

        self.assertEqual(findings, [])


if __name__ == "__main__":
    unittest.main()
