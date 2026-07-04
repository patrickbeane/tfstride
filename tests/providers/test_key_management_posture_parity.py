from __future__ import annotations

import unittest

from tests.providers.aws.test_aws_kms_rules import _KMS_ROTATION_RULE as _AWS_KMS_ROTATION_RULE
from tests.providers.aws.test_aws_kms_rules import _findings as _aws_kms_findings
from tests.providers.aws.test_aws_kms_rules import _kms_key as _aws_kms_key
from tests.providers.azure.test_azure_key_vault_rules import _evaluate as _azure_findings
from tests.providers.azure.test_azure_key_vault_rules import _key as _azure_key
from tests.providers.azure.test_azure_key_vault_rules import _rotation_policy as _azure_rotation_policy
from tests.providers.gcp.test_gcp_kms_rules import _KMS_ROTATION_RULE_ID as _GCP_KMS_ROTATION_RULE
from tests.providers.gcp.test_gcp_kms_rules import _findings as _gcp_kms_findings
from tests.providers.gcp.test_gcp_kms_rules import _kms_key as _gcp_kms_key
from tfstride.analysis.rule_registry import RulePolicy
from tfstride.analysis.stride_rules import StrideRuleEngine
from tfstride.providers.aws.normalizer import AwsNormalizer
from tfstride.providers.aws.rules import AWS_RULE_GROUP_IDS
from tfstride.providers.azure.normalizer import AzureNormalizer
from tfstride.providers.azure.rules import AZURE_RULE_GROUP_IDS
from tfstride.providers.gcp.normalizer import GcpNormalizer
from tfstride.providers.gcp.rules import GCP_RULE_GROUP_IDS

_AZURE_KEY_ROTATION_RULE = "azure-key-vault-key-rotation-policy-incomplete"
AWS_KEY_MANAGEMENT_RULE_IDS = frozenset({_AWS_KMS_ROTATION_RULE})
GCP_KEY_MANAGEMENT_RULE_IDS = frozenset({_GCP_KMS_ROTATION_RULE})
AZURE_KEY_MANAGEMENT_RULE_IDS = frozenset({_AZURE_KEY_ROTATION_RULE})
ALL_KEY_MANAGEMENT_RULE_IDS = AWS_KEY_MANAGEMENT_RULE_IDS | GCP_KEY_MANAGEMENT_RULE_IDS | AZURE_KEY_MANAGEMENT_RULE_IDS


def _flatten(rule_groups: tuple[tuple[str, ...], ...]) -> frozenset[str]:
    return frozenset(rule_id for rule_group in rule_groups for rule_id in rule_group)


def _finding_ids(findings) -> frozenset[str]:
    return frozenset(finding.rule_id for finding in findings)


def _evaluate_aws(resources, rule_ids: frozenset[str]):
    inventory = AwsNormalizer().normalize(resources)
    return StrideRuleEngine().evaluate(
        inventory,
        [],
        rule_policy=RulePolicy(enabled_rule_ids=rule_ids),
    )


def _evaluate_gcp(resources, rule_ids: frozenset[str]):
    inventory = GcpNormalizer().normalize(resources)
    return StrideRuleEngine().evaluate(
        inventory,
        [],
        rule_policy=RulePolicy(enabled_rule_ids=rule_ids),
    )


def _evaluate_azure(resources, rule_ids: frozenset[str]):
    inventory = AzureNormalizer().normalize(resources)
    return StrideRuleEngine().evaluate(
        inventory,
        [],
        rule_policy=RulePolicy(enabled_rule_ids=rule_ids),
    )


class KeyManagementPostureParityTests(unittest.TestCase):
    def test_provider_key_management_rule_families_are_registered(self) -> None:
        self.assertLessEqual(AWS_KEY_MANAGEMENT_RULE_IDS, _flatten(AWS_RULE_GROUP_IDS))
        self.assertLessEqual(GCP_KEY_MANAGEMENT_RULE_IDS, _flatten(GCP_RULE_GROUP_IDS))
        self.assertLessEqual(AZURE_KEY_MANAGEMENT_RULE_IDS, _flatten(AZURE_RULE_GROUP_IDS))

    def test_missing_or_disabled_key_rotation_findings_are_pinned_by_provider(self) -> None:
        aws_findings = _aws_kms_findings([_aws_kms_key(enable_key_rotation=False)])
        gcp_findings = _gcp_kms_findings([_gcp_kms_key()])
        _, _, azure_findings = _azure_findings(
            [_azure_key()],
            _AZURE_KEY_ROTATION_RULE,
        )

        self.assertEqual(_finding_ids(aws_findings), AWS_KEY_MANAGEMENT_RULE_IDS)
        self.assertEqual(_finding_ids(gcp_findings), GCP_KEY_MANAGEMENT_RULE_IDS)
        self.assertEqual(_finding_ids(azure_findings), AZURE_KEY_MANAGEMENT_RULE_IDS)
        self.assertIn("rotation", aws_findings[0].rationale.lower())
        self.assertIn("rotation", gcp_findings[0].rationale.lower())
        self.assertIn("rotation", azure_findings[0].rationale.lower())

    def test_configured_key_rotation_posture_stays_quiet_across_providers(self) -> None:
        aws_findings = _aws_kms_findings([_aws_kms_key(key_spec="SYMMETRIC_DEFAULT", enable_key_rotation=True)])
        gcp_findings = _gcp_kms_findings([_gcp_kms_key(rotation_period="7776000s")])
        _, _, azure_findings = _azure_findings(
            [
                _azure_key(
                    rotation_policy=_azure_rotation_policy(),
                    not_before_date="2026-01-01T00:00:00Z",
                    expiration_date="2026-12-31T00:00:00Z",
                )
            ],
            _AZURE_KEY_ROTATION_RULE,
        )

        self.assertEqual(aws_findings, [])
        self.assertEqual(gcp_findings, [])
        self.assertEqual(azure_findings, [])

    def test_asymmetric_or_unknown_key_shapes_are_not_overclaimed(self) -> None:
        aws_findings = _aws_kms_findings(
            [
                _aws_kms_key(name="signing", key_usage="SIGN_VERIFY", key_spec="ECC_NIST_P256"),
                _aws_kms_key(name="unknown", unknown_values={"key_spec": True, "enable_key_rotation": True}),
            ]
        )
        gcp_findings = _gcp_kms_findings(
            [
                _gcp_kms_key(name="signing", purpose="ASYMMETRIC_SIGN"),
                _gcp_kms_key(name="pending", unknown_values={"rotation_period": True}),
            ]
        )
        _, _, azure_findings = _azure_findings(
            [
                _azure_key(
                    rotation_policy=[{"automatic": [{}]}],
                    unknown_values={
                        "rotation_policy": [
                            {
                                "expire_after": True,
                                "automatic": [{"time_after_creation": True}],
                            }
                        ]
                    },
                )
            ],
            _AZURE_KEY_ROTATION_RULE,
        )

        self.assertEqual(aws_findings, [])
        self.assertEqual(gcp_findings, [])
        self.assertEqual(azure_findings, [])

    def test_key_management_posture_rules_remain_provider_local(self) -> None:
        findings_by_provider = {
            "aws": _evaluate_aws(
                [_aws_kms_key(enable_key_rotation=False)],
                ALL_KEY_MANAGEMENT_RULE_IDS,
            ),
            "gcp": _evaluate_gcp(
                [_gcp_kms_key()],
                ALL_KEY_MANAGEMENT_RULE_IDS,
            ),
            "azure": _evaluate_azure(
                [_azure_key()],
                ALL_KEY_MANAGEMENT_RULE_IDS,
            ),
        }

        for provider, findings in findings_by_provider.items():
            with self.subTest(provider=provider):
                self.assertTrue(findings)
                self.assertTrue(all(finding.rule_id.startswith(f"{provider}-") for finding in findings))


if __name__ == "__main__":
    unittest.main()
