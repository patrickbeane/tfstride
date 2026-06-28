from __future__ import annotations

import unittest
from typing import Any

from tfstride.analysis.rule_registry import RulePolicy
from tfstride.analysis.stride_rules import StrideRuleEngine
from tfstride.models import TerraformResource
from tfstride.providers.aws.normalizer import AwsNormalizer

_S3_ENCRYPTION_RULE = "aws-s3-customer-managed-encryption-missing"
_S3_VERSIONING_RULE = "aws-s3-versioning-disabled"


def _resource(
    address: str,
    resource_type: str,
    values: dict[str, Any],
    *,
    unknown_values: dict[str, Any] | None = None,
) -> TerraformResource:
    return TerraformResource(
        address=address,
        mode="managed",
        resource_type=resource_type,
        name=address.rsplit(".", 1)[-1],
        provider_name="registry.terraform.io/hashicorp/aws",
        values=values,
        unknown_values=unknown_values or {},
    )


def _bucket(*, bucket: str = "logs", acl: str = "private") -> TerraformResource:
    return _resource(
        "aws_s3_bucket.logs",
        "aws_s3_bucket",
        {
            "id": bucket,
            "bucket": bucket,
            "arn": f"arn:aws:s3:::{bucket}",
            "acl": acl,
        },
    )


def _versioning(status: str | None, *, unknown: bool = False) -> TerraformResource:
    values = {"bucket": "logs", "versioning_configuration": [{} if status is None else {"status": status}]}
    unknown_values = {"versioning_configuration": [{"status": True}]} if unknown else None
    return _resource(
        "aws_s3_bucket_versioning.logs",
        "aws_s3_bucket_versioning",
        values,
        unknown_values=unknown_values,
    )


def _encryption(
    *,
    algorithm: str | None,
    kms_master_key_id: str | None = None,
    unknown: bool = False,
) -> TerraformResource:
    encryption_default: dict[str, Any] = {}
    if algorithm is not None:
        encryption_default["sse_algorithm"] = algorithm
    if kms_master_key_id is not None:
        encryption_default["kms_master_key_id"] = kms_master_key_id
    unknown_values = (
        {"rule": [{"apply_server_side_encryption_by_default": [{"sse_algorithm": True, "kms_master_key_id": True}]}]}
        if unknown
        else None
    )
    return _resource(
        "aws_s3_bucket_server_side_encryption_configuration.logs",
        "aws_s3_bucket_server_side_encryption_configuration",
        {
            "bucket": "logs",
            "rule": [{"apply_server_side_encryption_by_default": [encryption_default]}],
        },
        unknown_values=unknown_values,
    )


def _findings(resources: list[TerraformResource], rule_ids: set[str]) -> list:
    inventory = AwsNormalizer().normalize(resources)
    return StrideRuleEngine().evaluate(
        inventory,
        [],
        rule_policy=RulePolicy(enabled_rule_ids=frozenset(rule_ids)),
    )


class AwsStorageRuleTests(unittest.TestCase):
    def test_s3_sse_s3_and_suspended_versioning_are_detected(self) -> None:
        findings = _findings(
            [
                _bucket(),
                _encryption(algorithm="AES256"),
                _versioning("Suspended"),
            ],
            {_S3_ENCRYPTION_RULE, _S3_VERSIONING_RULE},
        )

        findings_by_rule = {finding.rule_id: finding for finding in findings}

        self.assertEqual(set(findings_by_rule), {_S3_ENCRYPTION_RULE, _S3_VERSIONING_RULE})
        encryption_finding = findings_by_rule[_S3_ENCRYPTION_RULE]
        self.assertEqual(encryption_finding.severity.value, "medium")
        self.assertEqual(encryption_finding.affected_resources, ["aws_s3_bucket.logs"])
        self.assertNotIn("unencrypted", encryption_finding.rationale.lower())
        encryption_evidence = {item.key: item.values for item in encryption_finding.evidence}
        self.assertEqual(
            encryption_evidence["encryption_ownership"],
            [
                "s3_encryption_state=provider_managed_sse_s3",
                "sse_algorithm=AES256",
                "kms_master_key_id is unset",
                "source=aws_s3_bucket_server_side_encryption_configuration.logs",
                "S3 provider-managed encryption may still apply; this finding concerns customer key control",
            ],
        )

        versioning_finding = findings_by_rule[_S3_VERSIONING_RULE]
        self.assertEqual(versioning_finding.severity.value, "medium")
        versioning_evidence = {item.key: item.values for item in versioning_finding.evidence}
        self.assertEqual(
            versioning_evidence["versioning_posture"],
            [
                "s3_versioning_state=disabled",
                "versioning_configuration.status=Suspended",
                "source=aws_s3_bucket_versioning.logs",
            ],
        )

    def test_s3_kms_customer_key_and_enabled_versioning_are_not_flagged(self) -> None:
        findings = _findings(
            [
                _bucket(),
                _encryption(
                    algorithm="aws:kms",
                    kms_master_key_id="arn:aws:kms:us-east-1:111122223333:key/storage",
                ),
                _versioning("Enabled"),
            ],
            {_S3_ENCRYPTION_RULE, _S3_VERSIONING_RULE},
        )

        self.assertEqual(findings, [])

    def test_s3_kms_without_customer_key_is_detected(self) -> None:
        findings = _findings(
            [
                _bucket(),
                _encryption(algorithm="aws:kms"),
                _versioning("Enabled"),
            ],
            {_S3_ENCRYPTION_RULE, _S3_VERSIONING_RULE},
        )

        self.assertEqual([finding.rule_id for finding in findings], [_S3_ENCRYPTION_RULE])
        evidence = {item.key: item.values for item in findings[0].evidence}
        self.assertIn("s3_encryption_state=sse_kms_without_customer_key", evidence["encryption_ownership"])
        self.assertIn("kms_master_key_id is unset", evidence["encryption_ownership"])

    def test_s3_unknown_encryption_and_versioning_are_reported_as_uncertain(self) -> None:
        findings = _findings(
            [
                _bucket(),
                _encryption(algorithm=None, unknown=True),
                _versioning(None, unknown=True),
            ],
            {_S3_ENCRYPTION_RULE, _S3_VERSIONING_RULE},
        )

        findings_by_rule = {finding.rule_id: finding for finding in findings}

        self.assertEqual(set(findings_by_rule), {_S3_ENCRYPTION_RULE, _S3_VERSIONING_RULE})
        self.assertEqual(findings_by_rule[_S3_ENCRYPTION_RULE].severity.value, "low")
        self.assertEqual(findings_by_rule[_S3_VERSIONING_RULE].severity.value, "low")
        encryption_evidence = {item.key: item.values for item in findings_by_rule[_S3_ENCRYPTION_RULE].evidence}
        self.assertIn("s3_encryption_state=unknown", encryption_evidence["encryption_ownership"])
        self.assertEqual(
            encryption_evidence["posture_uncertainty"],
            [
                "aws_s3_bucket_server_side_encryption_configuration.logs: "
                "rule.apply_server_side_encryption_by_default.sse_algorithm is unknown after planning",
                "aws_s3_bucket_server_side_encryption_configuration.logs: "
                "rule.apply_server_side_encryption_by_default.kms_master_key_id is unknown after planning",
            ],
        )
        versioning_evidence = {item.key: item.values for item in findings_by_rule[_S3_VERSIONING_RULE].evidence}
        self.assertIn("s3_versioning_state=unknown", versioning_evidence["versioning_posture"])
        self.assertEqual(
            versioning_evidence["posture_uncertainty"],
            ["aws_s3_bucket_versioning.logs: versioning_configuration.status is unknown after planning"],
        )

    def test_absent_s3_posture_resources_are_not_overstated_as_findings(self) -> None:
        findings = _findings([_bucket()], {_S3_ENCRYPTION_RULE, _S3_VERSIONING_RULE})

        self.assertEqual(findings, [])

    def test_existing_s3_public_access_rule_is_unchanged(self) -> None:
        findings = _findings([_bucket(acl="public-read")], {"aws-s3-public-access"})

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].rule_id, "aws-s3-public-access")
        self.assertEqual(findings[0].affected_resources, ["aws_s3_bucket.logs"])


if __name__ == "__main__":
    unittest.main()
