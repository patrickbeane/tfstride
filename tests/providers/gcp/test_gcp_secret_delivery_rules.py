from __future__ import annotations

import unittest
from typing import Any

from tests.providers.gcp.normalizer_support import _terraform_resource
from tfstride.analysis.rule_registry import RulePolicy
from tfstride.analysis.stride_rules import StrideRuleEngine
from tfstride.models import TerraformResource
from tfstride.providers.gcp.normalizer import GcpNormalizer
from tfstride.providers.gcp.rules import GCP_RULE_GROUP_IDS

_RULE_ID = "gcp-cloud-run-sensitive-environment-value-inline"


def _service(
    env: list[dict[str, Any]],
    *,
    v2: bool = True,
    unknown_values: dict[str, Any] | None = None,
) -> TerraformResource:
    if v2:
        resource_type = "google_cloud_run_v2_service"
        address = "google_cloud_run_v2_service.api"
        template = [{"containers": [{"name": "api", "env": env}]}]
    else:
        resource_type = "google_cloud_run_service"
        address = "google_cloud_run_service.api"
        template = [{"spec": [{"containers": [{"name": "api", "env": env}]}]}]
    return _terraform_resource(
        address,
        resource_type,
        {
            "name": "api",
            "project": "tfstride-demo",
            "location": "us-central1",
            "template": template,
        },
        unknown_values=unknown_values,
    )


def _evaluate(resource: TerraformResource):
    inventory = GcpNormalizer().normalize([resource])
    return StrideRuleEngine().evaluate(
        inventory,
        [],
        rule_policy=RulePolicy(enabled_rule_ids=frozenset({_RULE_ID})),
    )


def _evidence_by_key(finding):
    return {item.key: item.values for item in finding.evidence}


class GcpCloudRunSecretDeliveryRuleTests(unittest.TestCase):
    def test_rule_id_is_registered(self) -> None:
        registered = {rule_id for group in GCP_RULE_GROUP_IDS for rule_id in group}

        self.assertIn(_RULE_ID, registered)

    def test_v2_sensitive_literal_is_reported_without_its_value(self) -> None:
        literal = "do-not-leak-this-password"
        findings = _evaluate(
            _service(
                [
                    {"name": "DB_PASSWORD", "value": literal},
                    {"name": "LOG_LEVEL", "value": "info"},
                ]
            )
        )

        self.assertEqual([finding.rule_id for finding in findings], [_RULE_ID])
        finding = findings[0]
        self.assertEqual(finding.severity.value, "medium")
        self.assertEqual(finding.affected_resources, ["google_cloud_run_v2_service.api"])
        evidence = _evidence_by_key(finding)
        self.assertEqual(
            evidence["sensitive_setting"],
            ["path=template[0].containers[0].env[0].value; setting=db_password; category=password; value=<redacted>"],
        )
        self.assertEqual(
            evidence["delivery_posture"],
            ["source=google_cloud_run_v2_service", "container_name=api", "state=literal"],
        )
        self.assertNotIn(literal, repr(finding))

    def test_v1_sensitive_literal_is_reported(self) -> None:
        findings = _evaluate(
            _service(
                [{"name": "CLIENT_SECRET", "value": "redacted-by-normalizer"}],
                v2=False,
            )
        )

        self.assertEqual([finding.rule_id for finding in findings], [_RULE_ID])
        self.assertEqual(findings[0].affected_resources, ["google_cloud_run_service.api"])
        self.assertNotIn("redacted-by-normalizer", repr(findings[0]))

    def test_secret_manager_references_remain_quiet_even_when_target_is_unresolved(self) -> None:
        resources = (
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
            _service(
                [
                    {
                        "name": "DB_PASSWORD",
                        "value_source": [
                            {
                                "secret_key_ref": [
                                    {
                                        "secret": "$" + "{google_secret_manager_secret.orders.id}",
                                        "version": "latest",
                                    }
                                ]
                            }
                        ],
                    }
                ]
            ),
            _service(
                [
                    {
                        "name": "DB_PASSWORD",
                        "value_from": [
                            {
                                "secret_key_ref": [
                                    {
                                        "name": "projects/tfstride-demo/secrets/orders-db",
                                        "key": "7",
                                    }
                                ]
                            }
                        ],
                    }
                ],
                v2=False,
            ),
        )

        for resource in resources:
            with self.subTest(resource=resource.resource_type, values=resource.values):
                self.assertEqual(_evaluate(resource), [])

    def test_unknown_secret_reference_is_not_treated_as_plaintext_or_missing(self) -> None:
        findings = _evaluate(
            _service(
                [
                    {
                        "name": "DB_PASSWORD",
                        "value_source": [
                            {
                                "secret_key_ref": [
                                    {
                                        "secret": "computed",
                                        "version": "latest",
                                    }
                                ]
                            }
                        ],
                    }
                ],
                unknown_values={
                    "template": [
                        {
                            "containers": [
                                {
                                    "env": [
                                        {
                                            "value_source": [
                                                {
                                                    "secret_key_ref": [
                                                        {
                                                            "secret": True,
                                                        }
                                                    ]
                                                }
                                            ]
                                        }
                                    ]
                                }
                            ]
                        }
                    ]
                },
            )
        )

        self.assertEqual(findings, [])

    def test_unknown_sensitive_literal_and_non_sensitive_literals_remain_quiet(self) -> None:
        unknown_findings = _evaluate(
            _service(
                [{"name": "API_KEY", "value": "computed"}],
                unknown_values={"template": [{"containers": [{"env": [{"value": True}]}]}]},
            )
        )
        non_sensitive_findings = _evaluate(
            _service(
                [
                    {"name": "LOG_LEVEL", "value": "debug"},
                    {"name": "SECRET_ARN", "value": "not-secret-material"},
                ]
            )
        )

        self.assertEqual(unknown_findings, [])
        self.assertEqual(non_sensitive_findings, [])


if __name__ == "__main__":
    unittest.main()
