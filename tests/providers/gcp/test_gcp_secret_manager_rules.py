from __future__ import annotations

import unittest

from tfstride.analysis.rule_registry import RulePolicy
from tfstride.analysis.stride_rules import StrideRuleEngine
from tfstride.models import TerraformResource
from tfstride.providers.gcp.normalizer import GcpNormalizer

_RULE_ID = "gcp-secret-manager-customer-managed-encryption-missing"
_MISSING = object()
_CMEK_KEY = "projects/tfstride-demo/locations/global/keyRings/app/cryptoKeys/secrets"


def _secret(
    *,
    replication: object = _MISSING,
    unknown_values: dict[str, object] | None = None,
) -> TerraformResource:
    values: dict[str, object] = {
        "secret_id": "tfstride-api-key",
        "id": "projects/tfstride-demo/secrets/tfstride-api-key",
        "project": "tfstride-demo",
    }
    if replication is _MISSING:
        values["replication"] = [{"auto": [{}]}]
    elif replication is not None:
        values["replication"] = replication
    return TerraformResource(
        address="google_secret_manager_secret.api_key",
        mode="managed",
        resource_type="google_secret_manager_secret",
        name="api_key",
        provider_name="registry.terraform.io/hashicorp/google",
        values=values,
        unknown_values=unknown_values or {},
    )


def _findings(resources: list[TerraformResource]):
    inventory = GcpNormalizer().normalize(resources)
    return StrideRuleEngine().evaluate(
        inventory,
        [],
        rule_policy=RulePolicy(enabled_rule_ids=frozenset({_RULE_ID})),
    )


class GcpSecretManagerRuleTests(unittest.TestCase):
    def test_secret_manager_secret_missing_cmek_is_detected_when_replication_is_deterministic(self) -> None:
        findings = _findings([_secret()])

        self.assertEqual(len(findings), 1)
        finding = findings[0]
        self.assertEqual(finding.rule_id, _RULE_ID)
        self.assertEqual(finding.severity.value, "medium")
        self.assertEqual(finding.affected_resources, ["google_secret_manager_secret.api_key"])
        evidence = {item.key: item.values for item in finding.evidence}
        self.assertEqual(
            evidence["target_resource"],
            [
                "address=google_secret_manager_secret.api_key",
                "type=google_secret_manager_secret",
                "identifier=projects/tfstride-demo/secrets/tfstride-api-key",
            ],
        )
        self.assertEqual(
            evidence["encryption_ownership"],
            [
                "customer_managed_encryption is false",
                "secret_manager_replication_mode=automatic",
                "secret_manager_kms_key_names is empty",
            ],
        )
        self.assertEqual(evidence["replication_posture"], ["replication.mode=automatic"])

    def test_secret_manager_secret_with_auto_cmek_is_not_flagged(self) -> None:
        findings = _findings(
            [
                _secret(
                    replication=[
                        {
                            "auto": [
                                {
                                    "customer_managed_encryption": [
                                        {"kms_key_name": _CMEK_KEY},
                                    ]
                                }
                            ]
                        }
                    ]
                )
            ]
        )

        self.assertEqual(findings, [])

    def test_secret_manager_secret_with_user_managed_replica_cmek_is_not_flagged(self) -> None:
        findings = _findings(
            [
                _secret(
                    replication=[
                        {
                            "user_managed": [
                                {
                                    "replicas": [
                                        {
                                            "location": "us-east1",
                                            "customer_managed_encryption": [{"kms_key_name": _CMEK_KEY}],
                                        }
                                    ]
                                }
                            ]
                        }
                    ]
                )
            ]
        )

        self.assertEqual(findings, [])

    def test_secret_manager_secret_unknown_cmek_is_not_overclaimed(self) -> None:
        findings = _findings(
            [
                _secret(
                    replication=[{"auto": [{"customer_managed_encryption": [{}]}]}],
                    unknown_values={
                        "replication": [
                            {
                                "auto": [
                                    {
                                        "customer_managed_encryption": [
                                            {"kms_key_name": True},
                                        ]
                                    }
                                ]
                            }
                        ]
                    },
                )
            ]
        )

        self.assertEqual(findings, [])

    def test_secret_manager_secret_missing_replication_is_not_overclaimed(self) -> None:
        findings = _findings([_secret(replication=None)])

        self.assertEqual(findings, [])


if __name__ == "__main__":
    unittest.main()
