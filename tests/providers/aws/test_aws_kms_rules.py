from __future__ import annotations

import unittest
from typing import Any

from tfstride.analysis.rule_registry import RulePolicy
from tfstride.analysis.stride_rules import StrideRuleEngine
from tfstride.models import TerraformResource
from tfstride.providers.aws.normalizer import AwsNormalizer

_KMS_ROTATION_RULE = "aws-kms-key-rotation-disabled-or-unknown"
_KMS_DELETION_WINDOW_RULE = "aws-kms-key-deletion-window-too-short"
_MISSING = object()


def _kms_key(
    *,
    name: str = "customer",
    key_usage: object = _MISSING,
    key_spec: object = _MISSING,
    customer_master_key_spec: object = _MISSING,
    enable_key_rotation: object = _MISSING,
    deletion_window_in_days: object = _MISSING,
    unknown_values: dict[str, Any] | None = None,
) -> TerraformResource:
    values: dict[str, object] = {
        "id": f"key/{name}",
        "key_id": name,
        "arn": f"arn:aws:kms:us-east-1:111122223333:key/{name}",
    }
    if key_usage is not _MISSING:
        values["key_usage"] = key_usage
    if key_spec is not _MISSING:
        values["key_spec"] = key_spec
    if customer_master_key_spec is not _MISSING:
        values["customer_master_key_spec"] = customer_master_key_spec
    if enable_key_rotation is not _MISSING:
        values["enable_key_rotation"] = enable_key_rotation
    if deletion_window_in_days is not _MISSING:
        values["deletion_window_in_days"] = deletion_window_in_days
    return TerraformResource(
        address=f"aws_kms_key.{name}",
        mode="managed",
        resource_type="aws_kms_key",
        name=name,
        provider_name="registry.terraform.io/hashicorp/aws",
        values=values,
        unknown_values=unknown_values or {},
    )


def _findings(resources: list[TerraformResource], *rule_ids: str):
    inventory = AwsNormalizer().normalize(resources)
    return StrideRuleEngine().evaluate(
        inventory,
        [],
        rule_policy=RulePolicy(enabled_rule_ids=frozenset(rule_ids or {_KMS_ROTATION_RULE})),
    )


def _evidence_by_key(finding):
    return {item.key: item.values for item in finding.evidence}


class AwsKmsRuleTests(unittest.TestCase):
    def test_symmetric_customer_key_with_rotation_disabled_is_detected(self) -> None:
        findings = _findings([_kms_key(enable_key_rotation=False)])

        self.assertEqual([finding.rule_id for finding in findings], [_KMS_ROTATION_RULE])
        self.assertEqual(findings[0].severity.value, "medium")
        self.assertEqual(findings[0].affected_resources, ["aws_kms_key.customer"])
        evidence = _evidence_by_key(findings[0])
        self.assertEqual(
            evidence["key_posture"],
            [
                "key_usage=ENCRYPT_DECRYPT",
                "key_spec=unset",
                "customer_master_key_spec=unset",
            ],
        )
        self.assertEqual(
            evidence["rotation_posture"],
            [
                "enable_key_rotation_state=disabled",
                "enable_key_rotation is false",
                "automatic annual rotation is evaluated for customer-managed symmetric KMS keys",
            ],
        )

    def test_missing_rotation_field_uses_terraform_default_disabled_posture(self) -> None:
        findings = _findings([_kms_key(customer_master_key_spec="SYMMETRIC_DEFAULT")])

        self.assertEqual([finding.rule_id for finding in findings], [_KMS_ROTATION_RULE])
        evidence = _evidence_by_key(findings[0])
        self.assertIn("enable_key_rotation_state=disabled", evidence["rotation_posture"])
        self.assertNotIn("posture_uncertainty", evidence)

    def test_unknown_rotation_is_reported_without_claiming_disabled(self) -> None:
        findings = _findings([_kms_key(unknown_values={"enable_key_rotation": True})])

        self.assertEqual([finding.rule_id for finding in findings], [_KMS_ROTATION_RULE])
        self.assertEqual(findings[0].severity.value, "low")
        self.assertNotIn("disabled", findings[0].rationale.lower())
        evidence = _evidence_by_key(findings[0])
        self.assertEqual(
            evidence["rotation_posture"],
            [
                "enable_key_rotation_state=unknown",
                "enable_key_rotation is unknown",
                "automatic annual rotation is evaluated for customer-managed symmetric KMS keys",
            ],
        )
        self.assertEqual(evidence["posture_uncertainty"], ["enable_key_rotation is unknown after planning"])

    def test_rotation_enabled_is_quiet(self) -> None:
        findings = _findings([_kms_key(key_spec="SYMMETRIC_DEFAULT", enable_key_rotation=True)])

        self.assertEqual(findings, [])

    def test_non_symmetric_or_non_encrypt_decrypt_keys_are_not_flagged(self) -> None:
        findings = _findings(
            [
                _kms_key(name="signing", key_usage="SIGN_VERIFY", key_spec="ECC_NIST_P256"),
                _kms_key(name="rsa", key_usage="ENCRYPT_DECRYPT", key_spec="RSA_2048"),
            ]
        )

        self.assertEqual(findings, [])

    def test_short_deletion_window_is_detected_as_recovery_governance_risk(self) -> None:
        findings = _findings(
            [_kms_key(enable_key_rotation=True, deletion_window_in_days=7)],
            _KMS_DELETION_WINDOW_RULE,
        )

        self.assertEqual([finding.rule_id for finding in findings], [_KMS_DELETION_WINDOW_RULE])
        self.assertEqual(findings[0].severity.value, "medium")
        self.assertEqual(findings[0].affected_resources, ["aws_kms_key.customer"])
        self.assertIn("key recovery governance", findings[0].rationale)
        self.assertIn("does not inspect key policies or grants", findings[0].rationale)
        evidence = _evidence_by_key(findings[0])
        self.assertEqual(
            evidence["deletion_window_posture"],
            [
                "deletion_window_in_days=7",
                "minimum_deletion_window_days=14",
                "default_deletion_window_days=30",
            ],
        )

    def test_default_or_long_deletion_window_stays_quiet(self) -> None:
        findings = _findings(
            [
                _kms_key(name="default", enable_key_rotation=True),
                _kms_key(name="baseline", enable_key_rotation=True, deletion_window_in_days=14),
                _kms_key(name="long", enable_key_rotation=True, deletion_window_in_days=30),
            ],
            _KMS_DELETION_WINDOW_RULE,
        )

        self.assertEqual(findings, [])

    def test_unknown_deletion_window_is_not_overclaimed_as_short(self) -> None:
        findings = _findings(
            [
                _kms_key(
                    enable_key_rotation=True,
                    deletion_window_in_days=7,
                    unknown_values={"deletion_window_in_days": True},
                )
            ],
            _KMS_DELETION_WINDOW_RULE,
        )

        self.assertEqual(findings, [])

    def test_unknown_key_shape_is_not_overclaimed_as_symmetric_rotation_applicable(self) -> None:
        findings = _findings([_kms_key(unknown_values={"key_spec": True, "enable_key_rotation": True})])

        self.assertEqual(findings, [])


if __name__ == "__main__":
    unittest.main()
