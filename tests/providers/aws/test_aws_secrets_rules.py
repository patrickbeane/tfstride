from __future__ import annotations

import unittest
from typing import Any

from tfstride.analysis.rule_registry import RulePolicy
from tfstride.analysis.stride_rules import StrideRuleEngine
from tfstride.models import TerraformResource
from tfstride.providers.aws.normalizer import AwsNormalizer

_SECRET_CMK_RULE = "aws-secretsmanager-customer-managed-kms-key-missing"
_SECRET_RECOVERY_RULE = "aws-secretsmanager-recovery-window-too-short"
_SECRET_ROTATION_RULE = "aws-secretsmanager-rotation-not-configured-or-too-long"
_SECRET_RULE_IDS = (_SECRET_CMK_RULE, _SECRET_RECOVERY_RULE)
_MISSING = object()


def _secret(
    *,
    name: str = "app",
    kms_key_id: object = _MISSING,
    recovery_window_in_days: object = _MISSING,
    replica: object = _MISSING,
    unknown_values: dict[str, Any] | None = None,
) -> TerraformResource:
    values: dict[str, Any] = {
        "id": name,
        "name": name,
        "arn": f"arn:aws:secretsmanager:us-east-1:111122223333:secret:{name}",
    }
    if kms_key_id is not _MISSING:
        values["kms_key_id"] = kms_key_id
    if recovery_window_in_days is not _MISSING:
        values["recovery_window_in_days"] = recovery_window_in_days
    if replica is not _MISSING:
        values["replica"] = replica
    return TerraformResource(
        address=f"aws_secretsmanager_secret.{name}",
        mode="managed",
        resource_type="aws_secretsmanager_secret",
        name=name,
        provider_name="registry.terraform.io/hashicorp/aws",
        values=values,
        unknown_values=unknown_values or {},
    )


def _safe_secret(*, name: str = "safe", **overrides: object) -> TerraformResource:
    defaults: dict[str, object] = {
        "name": name,
        "kms_key_id": "arn:aws:kms:us-east-1:111122223333:key/secrets",
        "recovery_window_in_days": 30,
    }
    defaults.update(overrides)
    return _secret(**defaults)


def _rotation(
    *,
    name: str = "app",
    secret_id: str | None = None,
    automatically_after_days: object = _MISSING,
    duration: object = _MISSING,
    schedule_expression: object = _MISSING,
    unknown_values: dict[str, Any] | None = None,
) -> TerraformResource:
    rotation_rules: dict[str, object] = {}
    if automatically_after_days is not _MISSING:
        rotation_rules["automatically_after_days"] = automatically_after_days
    if duration is not _MISSING:
        rotation_rules["duration"] = duration
    if schedule_expression is not _MISSING:
        rotation_rules["schedule_expression"] = schedule_expression
    values: dict[str, object] = {
        "id": f"{name}-rotation",
        "secret_id": secret_id or f"aws_secretsmanager_secret.{name}.id",
        "rotation_lambda_arn": "arn:aws:lambda:us-east-1:111122223333:function:rotate-secret",
        "rotation_rules": [rotation_rules],
    }
    return TerraformResource(
        address=f"aws_secretsmanager_secret_rotation.{name}",
        mode="managed",
        resource_type="aws_secretsmanager_secret_rotation",
        name=name,
        provider_name="registry.terraform.io/hashicorp/aws",
        values=values,
        unknown_values=unknown_values or {},
    )


def _secret_policy() -> TerraformResource:
    return TerraformResource(
        address="aws_secretsmanager_secret_policy.app",
        mode="managed",
        resource_type="aws_secretsmanager_secret_policy",
        name="app",
        provider_name="registry.terraform.io/hashicorp/aws",
        values={
            "id": "policy",
            "secret_arn": "arn:aws:secretsmanager:us-east-1:111122223333:secret:app",
            "policy": '{"Statement":[{"Effect":"Allow","Principal":"*","Action":"secretsmanager:GetSecretValue","Resource":"*"}]}',
        },
    )


def _findings(resources: list[TerraformResource], *rule_ids: str):
    inventory = AwsNormalizer().normalize(resources)
    return StrideRuleEngine().evaluate(
        inventory,
        [],
        rule_policy=RulePolicy(enabled_rule_ids=frozenset(rule_ids)),
    )


def _evidence_by_key(finding):
    return {item.key: item.values for item in finding.evidence}


class AwsSecretsManagerPostureRuleTests(unittest.TestCase):
    def test_secret_missing_cmk_and_immediate_recovery_window_are_detected(self) -> None:
        findings = _findings(
            [_secret(kms_key_id=_MISSING, recovery_window_in_days=0)],
            *_SECRET_RULE_IDS,
        )

        self.assertEqual([finding.rule_id for finding in findings], list(_SECRET_RULE_IDS))
        findings_by_rule = {finding.rule_id: finding for finding in findings}
        self.assertEqual(findings_by_rule[_SECRET_CMK_RULE].severity.value, "medium")
        self.assertEqual(findings_by_rule[_SECRET_RECOVERY_RULE].severity.value, "medium")

        cmk_finding = findings_by_rule[_SECRET_CMK_RULE]
        self.assertNotIn("unencrypted", cmk_finding.rationale.lower())
        cmk_evidence = _evidence_by_key(cmk_finding)
        self.assertEqual(
            cmk_evidence["encryption_ownership"],
            [
                "customer_managed_kms_state=not_configured",
                "kms_key_id is unset",
                "AWS-managed encryption may still apply; this finding concerns customer key control",
            ],
        )

        recovery_evidence = _evidence_by_key(findings_by_rule[_SECRET_RECOVERY_RULE])
        self.assertEqual(
            recovery_evidence["recovery_posture"],
            [
                "recovery_window_state=immediate_delete",
                "recovery_window_in_days=0",
                "minimum_recovery_window_days=7",
            ],
        )

    def test_secret_with_customer_key_and_long_recovery_window_is_quiet(self) -> None:
        findings = _findings([_safe_secret()], *_SECRET_RULE_IDS)

        self.assertEqual(findings, [])

    def test_short_recovery_window_is_reported_with_threshold_evidence(self) -> None:
        findings = _findings([_safe_secret(recovery_window_in_days=3)], _SECRET_RECOVERY_RULE)

        self.assertEqual([finding.rule_id for finding in findings], [_SECRET_RECOVERY_RULE])
        evidence = _evidence_by_key(findings[0])
        self.assertEqual(
            evidence["recovery_posture"],
            [
                "recovery_window_state=short_recovery_window",
                "recovery_window_in_days=3",
                "minimum_recovery_window_days=7",
            ],
        )

    def test_unknown_cmk_is_reported_without_claiming_explicit_absence(self) -> None:
        findings = _findings(
            [
                _secret(
                    recovery_window_in_days=30,
                    unknown_values={"kms_key_id": True, "recovery_window_in_days": True},
                )
            ],
            *_SECRET_RULE_IDS,
        )

        self.assertEqual([finding.rule_id for finding in findings], [_SECRET_CMK_RULE])
        self.assertEqual(findings[0].severity.value, "low")
        evidence = _evidence_by_key(findings[0])
        self.assertEqual(
            evidence["encryption_ownership"],
            [
                "customer_managed_kms_state=unknown",
                "kms_key_id is unset",
                "AWS-managed encryption may still apply; this finding concerns customer key control",
            ],
        )
        self.assertEqual(evidence["posture_uncertainty"], ["kms_key_id is unknown after planning"])

    def test_absent_recovery_window_is_not_overclaimed_as_short(self) -> None:
        findings = _findings([_secret(kms_key_id="arn:aws:kms:us-east-1:111122223333:key/secrets")], *_SECRET_RULE_IDS)

        self.assertEqual(findings, [])

    def test_secret_resource_policy_is_not_expanded_by_posture_rules(self) -> None:
        findings = _findings([_safe_secret(name="app"), _secret_policy()], *_SECRET_RULE_IDS)

        self.assertEqual(findings, [])

    def test_secret_rotation_missing_is_detected(self) -> None:
        findings = _findings([_safe_secret(name="app")], _SECRET_ROTATION_RULE)

        self.assertEqual([finding.rule_id for finding in findings], [_SECRET_ROTATION_RULE])
        self.assertEqual(findings[0].severity.value, "medium")
        evidence = _evidence_by_key(findings[0])
        self.assertEqual(
            evidence["rotation_posture"],
            [
                "rotation_state=not_configured",
                "maximum_rotation_interval_days=90",
                "aws_secretsmanager_secret_rotation resource was not resolved for this secret",
            ],
        )

    def test_secret_rotation_with_acceptable_interval_is_quiet(self) -> None:
        findings = _findings(
            [_safe_secret(name="app"), _rotation(name="app", automatically_after_days=30)],
            _SECRET_ROTATION_RULE,
        )

        self.assertEqual(findings, [])

    def test_secret_rotation_interval_above_baseline_is_detected(self) -> None:
        findings = _findings(
            [_safe_secret(name="app"), _rotation(name="app", automatically_after_days=120)],
            _SECRET_ROTATION_RULE,
        )

        self.assertEqual([finding.rule_id for finding in findings], [_SECRET_ROTATION_RULE])
        self.assertEqual(findings[0].severity.value, "medium")
        evidence = _evidence_by_key(findings[0])
        self.assertEqual(
            evidence["rotation_posture"],
            [
                "rotation_state=too_long",
                "maximum_rotation_interval_days=90",
                "rotation_source=aws_secretsmanager_secret_rotation.app",
                "rotation_lambda_arn=arn:aws:lambda:us-east-1:111122223333:function:rotate-secret",
                "automatically_after_days=120",
                "effective_rotation_interval_days=120",
            ],
        )

    def test_secret_rotation_rate_expression_is_compared_when_deterministic(self) -> None:
        findings = _findings(
            [_safe_secret(name="app"), _rotation(name="app", schedule_expression="rate(16 weeks)")],
            _SECRET_ROTATION_RULE,
        )

        self.assertEqual([finding.rule_id for finding in findings], [_SECRET_ROTATION_RULE])
        evidence = _evidence_by_key(findings[0])
        self.assertIn("schedule_expression=rate(16 weeks)", evidence["rotation_posture"])
        self.assertIn("effective_rotation_interval_days=112", evidence["rotation_posture"])

    def test_secret_rotation_unknown_interval_is_reported_without_overclaiming(self) -> None:
        findings = _findings(
            [
                _safe_secret(name="app"),
                _rotation(
                    name="app",
                    unknown_values={
                        "rotation_rules": [
                            {
                                "automatically_after_days": True,
                                "schedule_expression": True,
                            }
                        ]
                    },
                ),
            ],
            _SECRET_ROTATION_RULE,
        )

        self.assertEqual([finding.rule_id for finding in findings], [_SECRET_ROTATION_RULE])
        self.assertEqual(findings[0].severity.value, "low")
        evidence = _evidence_by_key(findings[0])
        self.assertEqual(
            evidence["rotation_posture"],
            [
                "rotation_state=unknown",
                "maximum_rotation_interval_days=90",
                "rotation_source=aws_secretsmanager_secret_rotation.app",
                "rotation_lambda_arn=arn:aws:lambda:us-east-1:111122223333:function:rotate-secret",
                "effective_rotation_interval_days=unknown",
            ],
        )
        self.assertEqual(
            evidence["posture_uncertainty"],
            [
                "aws_secretsmanager_secret_rotation.app: "
                "rotation_rules.automatically_after_days is unknown after planning",
                "aws_secretsmanager_secret_rotation.app: rotation_rules.schedule_expression is unknown after planning",
            ],
        )

    def test_unresolved_rotation_target_does_not_suppress_secret_rotation_finding(self) -> None:
        findings = _findings(
            [
                _safe_secret(name="app"),
                _rotation(name="other", secret_id="aws_secretsmanager_secret.missing.id", automatically_after_days=30),
            ],
            _SECRET_ROTATION_RULE,
        )

        self.assertEqual([finding.rule_id for finding in findings], [_SECRET_ROTATION_RULE])
        evidence = _evidence_by_key(findings[0])
        self.assertIn(
            "aws_secretsmanager_secret_rotation resource was not resolved for this secret",
            evidence["rotation_posture"],
        )


if __name__ == "__main__":
    unittest.main()
