from __future__ import annotations

import unittest

from tests.providers.gcp.normalizer_support import _terraform_resource
from tfstride.analysis.rule_registry import RulePolicy
from tfstride.analysis.stride_rules import StrideRuleEngine
from tfstride.models import TerraformResource
from tfstride.providers.gcp.normalizer import GcpNormalizer

_KMS_ROTATION_RULE_ID = "gcp-kms-key-rotation-not-configured-or-too-long"
_KMS_DESTROY_RULE_ID = "gcp-kms-key-destroy-scheduled-duration-too-short"
_MISSING = object()


def _kms_key(
    *,
    name: str = "customer",
    purpose: object = "ENCRYPT_DECRYPT",
    rotation_period: object = _MISSING,
    destroy_scheduled_duration: object = _MISSING,
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
    if destroy_scheduled_duration is not _MISSING:
        values["destroy_scheduled_duration"] = destroy_scheduled_duration
    return _terraform_resource(
        f"google_kms_crypto_key.{name}",
        "google_kms_crypto_key",
        values,
        unknown_values=unknown_values,
    )


def _findings(resources: list[TerraformResource], *rule_ids: str):
    inventory = GcpNormalizer().normalize(resources)
    return StrideRuleEngine().evaluate(
        inventory,
        [],
        rule_policy=RulePolicy(enabled_rule_ids=frozenset(rule_ids or {_KMS_ROTATION_RULE_ID})),
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

    def test_kms_crypto_key_short_destroy_scheduled_duration_is_detected(self) -> None:
        findings = _findings(
            [_kms_key(rotation_period="7776000s", destroy_scheduled_duration="86400s")],
            _KMS_DESTROY_RULE_ID,
        )

        self.assertEqual([finding.rule_id for finding in findings], [_KMS_DESTROY_RULE_ID])
        self.assertEqual(findings[0].severity.value, "medium")
        self.assertEqual(findings[0].affected_resources, ["google_kms_crypto_key.customer"])
        self.assertIn("key recovery governance", findings[0].rationale)
        evidence = _evidence_by_key(findings[0])
        self.assertEqual(
            evidence["destruction_lifecycle_issues"],
            ["destroy_scheduled_duration is 86400 seconds; minimum is 604800 seconds"],
        )
        self.assertEqual(
            evidence["destruction_lifecycle_posture"],
            [
                "purpose=ENCRYPT_DECRYPT",
                "destroy_scheduled_duration=86400s",
                "destroy_scheduled_duration_state=too_short",
                "minimum_destroy_scheduled_duration_days=7",
                "minimum_destroy_scheduled_duration_seconds=604800",
                "destroy_scheduled_duration_seconds=86400",
            ],
        )

    def test_kms_crypto_key_missing_or_acceptable_destroy_duration_is_quiet(self) -> None:
        findings = _findings(
            [
                _kms_key(name="missing", rotation_period="7776000s"),
                _kms_key(name="baseline", rotation_period="7776000s", destroy_scheduled_duration="604800s"),
                _kms_key(name="long", rotation_period="7776000s", destroy_scheduled_duration="2592000s"),
            ],
            _KMS_DESTROY_RULE_ID,
        )

        self.assertEqual(findings, [])

    def test_kms_crypto_key_unknown_destroy_duration_is_not_overclaimed(self) -> None:
        findings = _findings(
            [
                _kms_key(
                    rotation_period="7776000s",
                    destroy_scheduled_duration="86400s",
                    unknown_values={"destroy_scheduled_duration": True},
                )
            ],
            _KMS_DESTROY_RULE_ID,
        )

        self.assertEqual(findings, [])


if __name__ == "__main__":
    unittest.main()
