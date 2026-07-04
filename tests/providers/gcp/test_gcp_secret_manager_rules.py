from __future__ import annotations

import unittest

from tfstride.analysis.rule_registry import RulePolicy
from tfstride.analysis.stride_rules import StrideRuleEngine
from tfstride.models import TerraformResource
from tfstride.providers.gcp.normalizer import GcpNormalizer

_CMEK_RULE_ID = "gcp-secret-manager-customer-managed-encryption-missing"
_LIFECYCLE_RULE_ID = "gcp-secret-manager-lifecycle-posture-incomplete"
_MISSING = object()
_CMEK_KEY = "projects/tfstride-demo/locations/global/keyRings/app/cryptoKeys/secrets"


def _secret(
    *,
    replication: object = _MISSING,
    unknown_values: dict[str, object] | None = None,
    ttl: object = _MISSING,
    expire_time: object = _MISSING,
    version_destroy_ttl: object = _MISSING,
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
    if ttl is not _MISSING:
        values["ttl"] = ttl
    if expire_time is not _MISSING:
        values["expire_time"] = expire_time
    if version_destroy_ttl is not _MISSING:
        values["version_destroy_ttl"] = version_destroy_ttl
    return TerraformResource(
        address="google_secret_manager_secret.api_key",
        mode="managed",
        resource_type="google_secret_manager_secret",
        name="api_key",
        provider_name="registry.terraform.io/hashicorp/google",
        values=values,
        unknown_values=unknown_values or {},
    )


def _findings(resources: list[TerraformResource], *rule_ids: str):
    inventory = GcpNormalizer().normalize(resources)
    enabled_rule_ids = frozenset(rule_ids or (_CMEK_RULE_ID,))
    return StrideRuleEngine().evaluate(
        inventory,
        [],
        rule_policy=RulePolicy(enabled_rule_ids=enabled_rule_ids),
    )


class GcpSecretManagerRuleTests(unittest.TestCase):
    def test_secret_manager_secret_missing_cmek_is_detected_when_replication_is_deterministic(self) -> None:
        findings = _findings([_secret()])

        self.assertEqual(len(findings), 1)
        finding = findings[0]
        self.assertEqual(finding.rule_id, _CMEK_RULE_ID)
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

    def test_secret_manager_secret_missing_lifecycle_is_detected(self) -> None:
        findings = _findings([_secret()], _LIFECYCLE_RULE_ID)

        self.assertEqual([finding.rule_id for finding in findings], [_LIFECYCLE_RULE_ID])
        finding = findings[0]
        self.assertEqual(finding.severity.value, "medium")
        evidence = {item.key: item.values for item in finding.evidence}
        self.assertEqual(
            evidence["lifecycle_issues"],
            [
                "secret has no ttl, expire_time, or version_destroy_ttl lifecycle guardrail",
                "version_destroy_ttl is missing",
            ],
        )
        self.assertEqual(
            evidence["lifecycle_posture"],
            [
                "ttl=unset",
                "expire_time=unset",
                "version_destroy_ttl=unset",
                "minimum_version_destroy_ttl_days=7",
                "minimum_version_destroy_ttl_seconds=604800",
            ],
        )

    def test_secret_manager_secret_with_lifecycle_and_destroy_ttl_is_quiet(self) -> None:
        findings = _findings(
            [_secret(ttl="2592000s", version_destroy_ttl="604800s")],
            _LIFECYCLE_RULE_ID,
        )

        self.assertEqual(findings, [])

    def test_secret_manager_secret_short_destroy_ttl_is_detected(self) -> None:
        findings = _findings(
            [_secret(ttl="2592000s", version_destroy_ttl="3600s")],
            _LIFECYCLE_RULE_ID,
        )

        self.assertEqual([finding.rule_id for finding in findings], [_LIFECYCLE_RULE_ID])
        evidence = {item.key: item.values for item in findings[0].evidence}
        self.assertEqual(
            evidence["lifecycle_issues"],
            ["version_destroy_ttl is 3600 seconds; minimum is 604800 seconds"],
        )
        self.assertIn("version_destroy_ttl_seconds=3600", evidence["lifecycle_posture"])

    def test_secret_manager_secret_missing_destroy_ttl_is_detected_even_with_expiry(self) -> None:
        findings = _findings(
            [_secret(expire_time="2026-12-31T00:00:00Z")],
            _LIFECYCLE_RULE_ID,
        )

        self.assertEqual([finding.rule_id for finding in findings], [_LIFECYCLE_RULE_ID])
        evidence = {item.key: item.values for item in findings[0].evidence}
        self.assertEqual(evidence["lifecycle_issues"], ["version_destroy_ttl is missing"])

    def test_secret_manager_secret_unknown_lifecycle_is_not_overclaimed(self) -> None:
        findings = _findings(
            [
                _secret(
                    unknown_values={
                        "ttl": True,
                        "version_destroy_ttl": True,
                    }
                )
            ],
            _LIFECYCLE_RULE_ID,
        )

        self.assertEqual(findings, [])


if __name__ == "__main__":
    unittest.main()
