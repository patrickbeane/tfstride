from __future__ import annotations

import unittest
from typing import Any

from tfstride.analysis.rule_registry import RulePolicy
from tfstride.analysis.stride_rules import StrideRuleEngine
from tfstride.models import TerraformResource
from tfstride.providers.aws.normalizer import AwsNormalizer

_SNS_ENCRYPTION_RULE = "aws-sns-customer-managed-encryption-missing"
_SQS_ENCRYPTION_RULE = "aws-sqs-customer-managed-encryption-missing"
_SQS_RETENTION_RULE = "aws-sqs-message-retention-insufficient"
_SQS_DEAD_LETTER_RULE = "aws-sqs-dead-letter-queue-not-configured"
_GENERIC_POLICY_RULE = "aws-service-resource-policy-external-access"
_QUEUE_URL = "https://sqs.us-east-1.amazonaws.com/111122223333/jobs"
_QUEUE_ARN = "arn:aws:sqs:us-east-1:111122223333:jobs"
_DLQ_ARN = "arn:aws:sqs:us-east-1:111122223333:jobs-dead-letter"
_MISSING = object()


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


def _topic(
    *,
    kms_master_key_id: object = _MISSING,
    unknown_values: dict[str, Any] | None = None,
) -> TerraformResource:
    values: dict[str, Any] = {"name": "events", "id": "events"}
    if kms_master_key_id is not _MISSING:
        values["kms_master_key_id"] = kms_master_key_id
    return _resource("aws_sns_topic.events", "aws_sns_topic", values, unknown_values=unknown_values)


def _queue(
    *,
    kms_master_key_id: object = _MISSING,
    sqs_managed_sse_enabled: object = _MISSING,
    message_retention_seconds: object = _MISSING,
    redrive_policy: object = _MISSING,
    policy: object = _MISSING,
    unknown_values: dict[str, Any] | None = None,
) -> TerraformResource:
    values: dict[str, Any] = {
        "name": "jobs",
        "id": _QUEUE_URL,
        "url": _QUEUE_URL,
        "arn": _QUEUE_ARN,
    }
    if kms_master_key_id is not _MISSING:
        values["kms_master_key_id"] = kms_master_key_id
    if sqs_managed_sse_enabled is not _MISSING:
        values["sqs_managed_sse_enabled"] = sqs_managed_sse_enabled
    if message_retention_seconds is not _MISSING:
        values["message_retention_seconds"] = message_retention_seconds
    if redrive_policy is not _MISSING:
        values["redrive_policy"] = redrive_policy
    if policy is not _MISSING:
        values["policy"] = policy
    return _resource("aws_sqs_queue.jobs", "aws_sqs_queue", values, unknown_values=unknown_values)


def _standalone_redrive_policy() -> TerraformResource:
    return _resource(
        "aws_sqs_queue_redrive_policy.jobs",
        "aws_sqs_queue_redrive_policy",
        {
            "queue_url": "aws_sqs_queue.jobs.url",
            "redrive_policy": (
                '{"deadLetterTargetArn":"arn:aws:sqs:us-east-1:111122223333:jobs-dead-letter","maxReceiveCount":"5"}'
            ),
        },
    )


def _findings(resources: list[TerraformResource], *rule_ids: str):
    inventory = AwsNormalizer().normalize(resources)
    return StrideRuleEngine().evaluate(
        inventory,
        [],
        rule_policy=RulePolicy(
            enabled_rule_ids=frozenset(
                rule_ids
                or {
                    _SNS_ENCRYPTION_RULE,
                    _SQS_ENCRYPTION_RULE,
                    _SQS_RETENTION_RULE,
                    _SQS_DEAD_LETTER_RULE,
                }
            )
        ),
    )


def _evidence(finding):
    return {item.key: item.values for item in finding.evidence}


class AwsMessagingRuleTests(unittest.TestCase):
    def test_sns_and_sqs_provider_managed_encryption_are_ownership_findings(self) -> None:
        findings = _findings(
            [
                _topic(kms_master_key_id="alias/aws/sns"),
                _queue(kms_master_key_id="alias/aws/sqs"),
            ],
            _SNS_ENCRYPTION_RULE,
            _SQS_ENCRYPTION_RULE,
        )

        self.assertEqual([finding.rule_id for finding in findings], [_SNS_ENCRYPTION_RULE, _SQS_ENCRYPTION_RULE])
        self.assertTrue(all(finding.severity.value == "medium" for finding in findings))
        self.assertIn("does not claim that the topic is unencrypted", findings[0].rationale)
        self.assertEqual(
            _evidence(findings[0])["encryption_ownership"],
            [
                "encryption_ownership_state=service_managed",
                "kms_master_key_id=alias/aws/sns",
                "finding_scope=customer-managed key ownership and control posture",
            ],
        )
        self.assertEqual(
            _evidence(findings[1])["encryption_ownership"],
            [
                "encryption_ownership_state=service_managed",
                "kms_master_key_id=alias/aws/sqs",
                "sqs_managed_sse_enabled_state=not_configured",
                "finding_scope=customer-managed key ownership and control posture",
            ],
        )

    def test_missing_messaging_encryption_configuration_is_an_ownership_finding(self) -> None:
        findings = _findings(
            [_topic(), _queue()],
            _SNS_ENCRYPTION_RULE,
            _SQS_ENCRYPTION_RULE,
        )

        self.assertEqual([finding.rule_id for finding in findings], [_SNS_ENCRYPTION_RULE, _SQS_ENCRYPTION_RULE])
        self.assertEqual(
            _evidence(findings[0])["encryption_ownership"][:2],
            ["encryption_ownership_state=absent", "kms_master_key_id=unset"],
        )
        self.assertEqual(
            _evidence(findings[1])["encryption_ownership"][:2],
            ["encryption_ownership_state=absent", "kms_master_key_id=unset"],
        )

    def test_customer_managed_messaging_encryption_is_quiet(self) -> None:
        findings = _findings(
            [
                _topic(kms_master_key_id="arn:aws:kms:us-east-1:111122223333:key/topic"),
                _queue(kms_master_key_id="arn:aws:kms:us-east-1:111122223333:key/queue"),
            ],
            _SNS_ENCRYPTION_RULE,
            _SQS_ENCRYPTION_RULE,
        )

        self.assertEqual(findings, [])

    def test_short_sqs_retention_includes_exact_threshold(self) -> None:
        findings = _findings([_queue(message_retention_seconds=86_400)], _SQS_RETENTION_RULE)

        self.assertEqual([finding.rule_id for finding in findings], [_SQS_RETENTION_RULE])
        self.assertEqual(findings[0].severity.value, "medium")
        self.assertEqual(
            _evidence(findings[0])["message_retention_posture"],
            [
                "message_retention_seconds=86400",
                "minimum_message_retention_days=4",
                "minimum_message_retention_seconds=345600",
            ],
        )

    def test_sqs_retention_at_baseline_is_quiet(self) -> None:
        findings = _findings([_queue(message_retention_seconds=345_600)], _SQS_RETENTION_RULE)

        self.assertEqual(findings, [])

    def test_sqs_without_dead_letter_queue_includes_exact_posture(self) -> None:
        findings = _findings([_queue()], _SQS_DEAD_LETTER_RULE)

        self.assertEqual([finding.rule_id for finding in findings], [_SQS_DEAD_LETTER_RULE])
        self.assertEqual(findings[0].severity.value, "medium")
        self.assertEqual(
            _evidence(findings[0])["dead_letter_posture"],
            [
                "redrive_state=not_configured",
                "dead_letter_target_arn=unset",
                "max_receive_count=unset",
                "redrive_source_address=aws_sqs_queue.jobs",
            ],
        )

    def test_inline_and_standalone_dead_letter_queues_are_quiet(self) -> None:
        inline_findings = _findings(
            [
                _queue(
                    redrive_policy={
                        "deadLetterTargetArn": _DLQ_ARN,
                        "maxReceiveCount": 5,
                    }
                )
            ],
            _SQS_DEAD_LETTER_RULE,
        )
        standalone_findings = _findings([_queue(), _standalone_redrive_policy()], _SQS_DEAD_LETTER_RULE)

        self.assertEqual(inline_findings, [])
        self.assertEqual(standalone_findings, [])

    def test_unknown_messaging_posture_does_not_claim_missing_controls(self) -> None:
        findings = _findings(
            [
                _topic(kms_master_key_id="alias/aws/sns", unknown_values={"kms_master_key_id": True}),
                _queue(
                    kms_master_key_id="alias/aws/sqs",
                    message_retention_seconds=86_400,
                    redrive_policy={
                        "deadLetterTargetArn": _DLQ_ARN,
                        "maxReceiveCount": 5,
                    },
                    unknown_values={
                        "kms_master_key_id": True,
                        "message_retention_seconds": True,
                        "redrive_policy": True,
                    },
                ),
            ],
            _SNS_ENCRYPTION_RULE,
            _SQS_ENCRYPTION_RULE,
            _SQS_RETENTION_RULE,
            _SQS_DEAD_LETTER_RULE,
        )

        self.assertEqual(findings, [])

    def test_broad_sqs_policy_keeps_only_generic_policy_finding_when_messaging_posture_is_safe(self) -> None:
        findings = _findings(
            [
                _queue(
                    kms_master_key_id="arn:aws:kms:us-east-1:111122223333:key/queue",
                    message_retention_seconds=345_600,
                    redrive_policy={
                        "deadLetterTargetArn": _DLQ_ARN,
                        "maxReceiveCount": 5,
                    },
                    policy={
                        "Version": "2012-10-17",
                        "Statement": [
                            {
                                "Effect": "Allow",
                                "Principal": "*",
                                "Action": "sqs:SendMessage",
                                "Resource": "*",
                            }
                        ],
                    },
                )
            ],
            _SNS_ENCRYPTION_RULE,
            _SQS_ENCRYPTION_RULE,
            _SQS_RETENTION_RULE,
            _SQS_DEAD_LETTER_RULE,
            _GENERIC_POLICY_RULE,
        )

        self.assertEqual([finding.rule_id for finding in findings], [_GENERIC_POLICY_RULE])


if __name__ == "__main__":
    unittest.main()
