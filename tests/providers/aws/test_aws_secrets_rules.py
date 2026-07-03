from __future__ import annotations

import unittest
from typing import Any

from tfstride.analysis.rule_registry import RulePolicy
from tfstride.analysis.stride_rules import StrideRuleEngine
from tfstride.models import TerraformResource
from tfstride.providers.aws.normalizer import AwsNormalizer

_SECRET_CMK_RULE = "aws-secretsmanager-customer-managed-kms-key-missing"
_SECRET_RECOVERY_RULE = "aws-secretsmanager-recovery-window-too-short"
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


if __name__ == "__main__":
    unittest.main()
