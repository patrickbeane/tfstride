from __future__ import annotations

import unittest
from collections import Counter

from tests.providers.aws.test_aws_secret_delivery_rules import _task_definition
from tests.providers.azure.test_azure_secret_delivery_rules import _app
from tests.providers.gcp.test_gcp_secret_delivery_rules import _service
from tfstride.analysis.rule_registry import RulePolicy
from tfstride.analysis.stride_rules import StrideRuleEngine
from tfstride.models import AnalysisResult, Finding, ResourceInventory, TerraformResource
from tfstride.providers.aws.normalizer import AwsNormalizer
from tfstride.providers.aws.rules import AWS_RULE_GROUP_IDS
from tfstride.providers.azure.normalizer import AzureNormalizer
from tfstride.providers.azure.rules import AZURE_RULE_GROUP_IDS
from tfstride.providers.base import ProviderNormalizer
from tfstride.providers.gcp.normalizer import GcpNormalizer
from tfstride.providers.gcp.rules import GCP_RULE_GROUP_IDS
from tfstride.reporting.json_report import render_json

AWS_SECRET_DELIVERY_RULE = "aws-ecs-sensitive-environment-value-inline"
GCP_SECRET_DELIVERY_RULE = "gcp-cloud-run-sensitive-environment-value-inline"
AZURE_SECRET_DELIVERY_RULE = "azure-app-service-sensitive-app-setting-inline"

ALL_SECRET_DELIVERY_RULE_IDS = frozenset(
    {
        AWS_SECRET_DELIVERY_RULE,
        GCP_SECRET_DELIVERY_RULE,
        AZURE_SECRET_DELIVERY_RULE,
    }
)


def _flatten(rule_groups: tuple[tuple[str, ...], ...]) -> frozenset[str]:
    return frozenset(rule_id for rule_group in rule_groups for rule_id in rule_group)


def _evaluate(
    normalizer: ProviderNormalizer,
    resources: list[TerraformResource],
) -> tuple[ResourceInventory, list[Finding]]:
    inventory = normalizer.normalize(resources)
    findings = StrideRuleEngine().evaluate(
        inventory,
        [],
        rule_policy=RulePolicy(enabled_rule_ids=ALL_SECRET_DELIVERY_RULE_IDS),
    )
    return inventory, findings


def _report_payload(inventory: ResourceInventory, findings: list[Finding]) -> str:
    return render_json(
        AnalysisResult(
            title="Workload secret delivery parity",
            analyzed_file="synthetic-plan.json",
            analyzed_path="synthetic-plan.json",
            inventory=inventory,
            trust_boundaries=[],
            findings=findings,
        )
    )


def _rule_counts(findings: list[Finding]) -> Counter[str]:
    return Counter(finding.rule_id for finding in findings)


class WorkloadSecretDeliveryPostureParityTests(unittest.TestCase):
    def test_workload_secret_delivery_rule_families_are_registered(self) -> None:
        self.assertIn(AWS_SECRET_DELIVERY_RULE, _flatten(AWS_RULE_GROUP_IDS))
        self.assertIn(GCP_SECRET_DELIVERY_RULE, _flatten(GCP_RULE_GROUP_IDS))
        self.assertIn(AZURE_SECRET_DELIVERY_RULE, _flatten(AZURE_RULE_GROUP_IDS))

    def test_deterministic_inline_sensitive_values_emit_provider_local_findings(self) -> None:
        cases = (
            (
                "aws",
                AwsNormalizer(),
                _task_definition(
                    {
                        "name": "orders",
                        "environment": [{"name": "DB_PASSWORD", "value": "aws-literal-password"}],
                    }
                ),
                AWS_SECRET_DELIVERY_RULE,
                "aws-literal-password",
            ),
            (
                "gcp",
                GcpNormalizer(),
                _service([{"name": "DB_PASSWORD", "value": "gcp-literal-password"}]),
                GCP_SECRET_DELIVERY_RULE,
                "gcp-literal-password",
            ),
            (
                "azure",
                AzureNormalizer(),
                _app({"DB_PASSWORD": "azure-literal-password"}),
                AZURE_SECRET_DELIVERY_RULE,
                "azure-literal-password",
            ),
        )

        for provider, normalizer, resource, expected_rule, literal in cases:
            with self.subTest(provider=provider):
                inventory, findings = _evaluate(normalizer, [resource])

                self.assertEqual(_rule_counts(findings), Counter({expected_rule: 1}))
                self.assertTrue(all(finding.rule_id.startswith(f"{provider}-") for finding in findings))
                evidence = {item.key: item.values for item in findings[0].evidence}
                self.assertIn("sensitive_setting", evidence)
                self.assertTrue(any("setting=db_password" in value for value in evidence["sensitive_setting"]))
                self.assertTrue(any("path=" in value for value in evidence["sensitive_setting"]))
                self.assertNotIn(literal, repr(findings))
                self.assertNotIn(literal, _report_payload(inventory, findings))

    def test_provider_native_secret_references_remain_quiet(self) -> None:
        cases = (
            (
                AwsNormalizer(),
                _task_definition(
                    {
                        "name": "orders",
                        "secrets": [
                            {
                                "name": "DB_PASSWORD",
                                "valueFrom": ("arn:aws:secretsmanager:us-east-1:111122223333:secret:orders-db-abc123"),
                            }
                        ],
                    }
                ),
            ),
            (
                GcpNormalizer(),
                _service(
                    [
                        {
                            "name": "DB_PASSWORD",
                            "value_source": [
                                {
                                    "secret_key_ref": [
                                        {
                                            "secret": "projects/tfstride-demo/secrets/orders-db",
                                            "version": "latest",
                                        }
                                    ]
                                }
                            ],
                        }
                    ]
                ),
            ),
            (
                AzureNormalizer(),
                _app(
                    {
                        "DB_PASSWORD": (
                            "@Microsoft.KeyVault(SecretUri="
                            "https://app-vault.vault.azure.net/secrets/database-password/abc123)"
                        )
                    }
                ),
            ),
        )

        for normalizer, resource in cases:
            with self.subTest(provider=normalizer.provider):
                _, findings = _evaluate(normalizer, [resource])
                self.assertEqual(findings, [])

    def test_unknown_or_computed_sensitive_values_remain_quiet(self) -> None:
        cases = (
            (
                AwsNormalizer(),
                _task_definition(
                    {
                        "name": "orders",
                        "environment": [{"name": "API_KEY", "value": "computed"}],
                    },
                    unknown_values={"container_definitions": [{"environment": [{"value": True}]}]},
                ),
            ),
            (
                GcpNormalizer(),
                _service(
                    [{"name": "API_KEY", "value": "computed"}],
                    unknown_values={"template": [{"containers": [{"env": [{"value": True}]}]}]},
                ),
            ),
            (
                AzureNormalizer(),
                _app(
                    {"API_KEY": None},
                    unknown_values={"app_settings": {"API_KEY": True}},
                ),
            ),
        )

        for normalizer, resource in cases:
            with self.subTest(provider=normalizer.provider):
                _, findings = _evaluate(normalizer, [resource])
                self.assertEqual(findings, [])

    def test_secret_delivery_findings_cannot_leak_between_provider_inventories(self) -> None:
        cases = (
            (
                "aws",
                AwsNormalizer(),
                _task_definition(
                    {
                        "name": "orders",
                        "environment": [{"name": "CLIENT_SECRET", "value": "aws-secret"}],
                    }
                ),
                frozenset({AWS_SECRET_DELIVERY_RULE}),
            ),
            (
                "gcp",
                GcpNormalizer(),
                _service([{"name": "CLIENT_SECRET", "value": "gcp-secret"}]),
                frozenset({GCP_SECRET_DELIVERY_RULE}),
            ),
            (
                "azure",
                AzureNormalizer(),
                _app({"CLIENT_SECRET": "azure-secret"}),
                frozenset({AZURE_SECRET_DELIVERY_RULE}),
            ),
        )

        for provider, normalizer, resource, provider_rule_ids in cases:
            with self.subTest(provider=provider):
                _, findings = _evaluate(normalizer, [resource])
                self.assertEqual(set(_rule_counts(findings)), provider_rule_ids)
                self.assertTrue(
                    set(_rule_counts(findings)).isdisjoint(ALL_SECRET_DELIVERY_RULE_IDS - provider_rule_ids)
                )


if __name__ == "__main__":
    unittest.main()
