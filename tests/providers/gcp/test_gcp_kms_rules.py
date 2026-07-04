from __future__ import annotations

import unittest

from tests.providers.gcp.normalizer_support import _terraform_resource
from tfstride.analysis.rule_registry import RulePolicy
from tfstride.analysis.stride_rules import StrideRuleEngine
from tfstride.models import TerraformResource
from tfstride.providers.gcp.normalizer import GcpNormalizer

_KMS_ROTATION_RULE_ID = "gcp-kms-key-rotation-not-configured-or-too-long"
_MISSING = object()


def _kms_key(
    *,
    name: str = "customer",
    purpose: object = "ENCRYPT_DECRYPT",
    rotation_period: object = _MISSING,
    unknown_values: dict[str, object] | None = None,
) -> TerraformResource:
    values: dict[str, object] = {
        "name": f"tfstride-{name}-key",
        "id": f"projects/tfstride-demo/locations/global/keyRings/tfstride-app/cryptoKeys/tfstride-{name}-key",
        "key_ring": "projects/tfstride-demo/locations/global/keyRings/tfstride-app",
    }
    if purpose is not _MISSING:
        values["purpose"] = purpose
    if rotation_period is not _MISSING:
        values["rotation_period"] = rotation_period
    return _terraform_resource(
        f"google_kms_crypto_key.{name}",
        "google_kms_crypto_key",
        values,
        unknown_values=unknown_values,
    )


def _findings(resources: list[TerraformResource]):
    inventory = GcpNormalizer().normalize(resources)
    return StrideRuleEngine().evaluate(
        inventory,
        [],
        rule_policy=RulePolicy(enabled_rule_ids=frozenset({_KMS_ROTATION_RULE_ID})),
    )


def _evidence_by_key(finding):
    return {item.key: item.values for item in finding.evidence}


class GcpKmsRuleTests(unittest.TestCase):
    def test_kms_crypto_key_missing_rotation_period_is_detected(self) -> None:
        findings = _findings([_kms_key()])

        self.assertEqual([finding.rule_id for finding in findings], [_KMS_ROTATION_RULE_ID])
        self.assertEqual(findings[0].severity.value, "medium")
        evidence = _evidence_by_key(findings[0])
        self.assertEqual(evidence["rotation_issues"], ["rotation_period is missing"])
        self.assertEqual(
            evidence["rotation_posture"],
            [
                "purpose=ENCRYPT_DECRYPT",
                "rotation_period=unset",
                "rotation_period_state=missing",
                "maximum_rotation_period_days=90",
                "maximum_rotation_period_seconds=7776000",
            ],
        )

    def test_kms_crypto_key_long_rotation_period_is_detected(self) -> None:
        findings = _findings([_kms_key(rotation_period="15552000s")])

        self.assertEqual([finding.rule_id for finding in findings], [_KMS_ROTATION_RULE_ID])
        evidence = _evidence_by_key(findings[0])
        self.assertEqual(
            evidence["rotation_issues"],
            ["rotation_period is 15552000 seconds; maximum is 7776000 seconds"],
        )
        self.assertIn("rotation_period_state=too_long", evidence["rotation_posture"])
        self.assertIn("rotation_period_seconds=15552000", evidence["rotation_posture"])

    def test_kms_crypto_key_acceptable_rotation_period_is_quiet(self) -> None:
        findings = _findings([_kms_key(rotation_period="7776000s")])

        self.assertEqual(findings, [])

    def test_kms_crypto_key_unknown_rotation_period_is_not_overclaimed(self) -> None:
        findings = _findings([_kms_key(unknown_values={"rotation_period": True})])

        self.assertEqual(findings, [])

    def test_kms_crypto_key_asymmetric_purpose_is_not_flagged_for_symmetric_rotation(self) -> None:
        findings = _findings([_kms_key(purpose="ASYMMETRIC_SIGN")])

        self.assertEqual(findings, [])


if __name__ == "__main__":
    unittest.main()
