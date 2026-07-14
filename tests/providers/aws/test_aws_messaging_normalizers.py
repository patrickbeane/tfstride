from __future__ import annotations

import unittest

from tfstride.models import TerraformResource
from tfstride.providers.aws.data_normalizers import normalize_sns_topic, normalize_sqs_queue
from tfstride.providers.aws.normalizer import AwsNormalizer
from tfstride.providers.aws.resource_facts import aws_facts

_QUEUE_URL = "https://sqs.us-east-1.amazonaws.com/111122223333/jobs"
_QUEUE_ARN = "arn:aws:sqs:us-east-1:111122223333:jobs"
_DLQ_ARN = "arn:aws:sqs:us-east-1:111122223333:jobs-dead-letter"


def _resource(
    address: str,
    resource_type: str,
    values: dict[str, object],
    *,
    unknown_values: dict[str, object] | None = None,
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


def _queue(
    *,
    kms_master_key_id: object | None = None,
    sqs_managed_sse_enabled: object | None = None,
    message_retention_seconds: object | None = None,
    redrive_policy: object | None = None,
    unknown_values: dict[str, object] | None = None,
) -> TerraformResource:
    values: dict[str, object] = {
        "name": "jobs",
        "id": _QUEUE_URL,
        "url": _QUEUE_URL,
        "arn": _QUEUE_ARN,
    }
    if kms_master_key_id is not None:
        values["kms_master_key_id"] = kms_master_key_id
    if sqs_managed_sse_enabled is not None:
        values["sqs_managed_sse_enabled"] = sqs_managed_sse_enabled
    if message_retention_seconds is not None:
        values["message_retention_seconds"] = message_retention_seconds
    if redrive_policy is not None:
        values["redrive_policy"] = redrive_policy
    return _resource(
        "aws_sqs_queue.jobs",
        "aws_sqs_queue",
        values,
        unknown_values=unknown_values,
    )


class AwsMessagingNormalizerTests(unittest.TestCase):
    def test_sns_encryption_ownership_states_are_distinct(self) -> None:
        customer_managed = aws_facts(
            normalize_sns_topic(
                _resource(
                    "aws_sns_topic.customer",
                    "aws_sns_topic",
                    {
                        "name": "customer",
                        "kms_master_key_id": "arn:aws:kms:us-east-1:111122223333:key/customer",
                    },
                )
            )
        )
        service_managed = aws_facts(
            normalize_sns_topic(
                _resource(
                    "aws_sns_topic.service",
                    "aws_sns_topic",
                    {"name": "service", "kms_master_key_id": "alias/aws/sns"},
                )
            )
        )
        absent = aws_facts(normalize_sns_topic(_resource("aws_sns_topic.absent", "aws_sns_topic", {"name": "absent"})))
        unknown = aws_facts(
            normalize_sns_topic(
                _resource(
                    "aws_sns_topic.unknown",
                    "aws_sns_topic",
                    {"name": "unknown", "kms_master_key_id": "alias/aws/sns"},
                    unknown_values={"kms_master_key_id": True},
                )
            )
        )

        self.assertEqual(customer_managed.sns_encryption_ownership_state, "customer_managed")
        self.assertEqual(service_managed.sns_encryption_ownership_state, "service_managed")
        self.assertEqual(absent.sns_encryption_ownership_state, "absent")
        self.assertEqual(unknown.sns_encryption_ownership_state, "unknown")
        self.assertEqual(unknown.sns_posture_uncertainties, ["kms_master_key_id is unknown after planning"])

    def test_sqs_encryption_ownership_states_and_retention_are_distinct(self) -> None:
        customer_managed = aws_facts(
            normalize_sqs_queue(
                _queue(
                    kms_master_key_id="arn:aws:kms:us-east-1:111122223333:key/customer",
                    message_retention_seconds="604800",
                )
            )
        )
        service_managed = aws_facts(normalize_sqs_queue(_queue(sqs_managed_sse_enabled=True)))
        absent = aws_facts(normalize_sqs_queue(_queue(sqs_managed_sse_enabled=False)))
        unknown = aws_facts(
            normalize_sqs_queue(
                _queue(
                    sqs_managed_sse_enabled=True,
                    unknown_values={"sqs_managed_sse_enabled": True},
                )
            )
        )

        self.assertEqual(customer_managed.sqs_encryption_ownership_state, "customer_managed")
        self.assertEqual(customer_managed.sqs_message_retention_seconds, 604800)
        self.assertEqual(service_managed.sqs_encryption_ownership_state, "service_managed")
        self.assertTrue(service_managed.sqs_managed_sse_enabled)
        self.assertEqual(absent.sqs_encryption_ownership_state, "absent")
        self.assertFalse(absent.sqs_managed_sse_enabled)
        self.assertEqual(unknown.sqs_encryption_ownership_state, "unknown")
        self.assertIsNone(unknown.sqs_managed_sse_enabled)
        self.assertEqual(
            unknown.sqs_posture_uncertainties,
            ["sqs_managed_sse_enabled is unknown after planning"],
        )

    def test_inline_redrive_policy_normalizes_target_and_max_receive_count(self) -> None:
        facts = aws_facts(
            normalize_sqs_queue(
                _queue(
                    redrive_policy=(
                        '{"deadLetterTargetArn":"arn:aws:sqs:us-east-1:111122223333:jobs-dead-letter",'
                        '"maxReceiveCount":"5"}'
                    )
                )
            )
        )

        self.assertEqual(facts.sqs_redrive_state, "configured")
        self.assertEqual(facts.sqs_redrive_target_arn, _DLQ_ARN)
        self.assertEqual(facts.sqs_redrive_max_receive_count, 5)
        self.assertEqual(facts.sqs_redrive_source_address, "aws_sqs_queue.jobs")
        self.assertEqual(facts.sqs_posture_uncertainties, [])

    def test_malformed_and_unknown_inline_redrive_policy_remain_unknown(self) -> None:
        malformed = aws_facts(normalize_sqs_queue(_queue(redrive_policy="{")))
        unknown = aws_facts(
            normalize_sqs_queue(
                _queue(
                    redrive_policy={
                        "deadLetterTargetArn": _DLQ_ARN,
                        "maxReceiveCount": 5,
                    },
                    unknown_values={"redrive_policy": True},
                )
            )
        )

        self.assertEqual(malformed.sqs_redrive_state, "unknown")
        self.assertEqual(malformed.sqs_posture_uncertainties, ["redrive_policy is not valid JSON"])
        self.assertEqual(unknown.sqs_redrive_state, "unknown")
        self.assertEqual(unknown.sqs_posture_uncertainties, ["redrive_policy is unknown after planning"])

    def test_standalone_redrive_policy_resolves_only_exact_queue_references(self) -> None:
        standalone = _resource(
            "aws_sqs_queue_redrive_policy.jobs",
            "aws_sqs_queue_redrive_policy",
            {
                "queue_url": "aws_sqs_queue.jobs.url",
                "redrive_policy": (
                    '{"deadLetterTargetArn":"arn:aws:sqs:us-east-1:111122223333:jobs-dead-letter",'
                    '"maxReceiveCount":"5"}'
                ),
            },
        )
        inventory = AwsNormalizer().normalize([_queue(), standalone])
        queue = inventory.get_by_address("aws_sqs_queue.jobs")
        standalone_resource = inventory.get_by_address("aws_sqs_queue_redrive_policy.jobs")
        queue_facts = aws_facts(queue)
        standalone_facts = aws_facts(standalone_resource)

        self.assertEqual(queue_facts.sqs_redrive_state, "configured")
        self.assertEqual(queue_facts.sqs_redrive_target_arn, _DLQ_ARN)
        self.assertEqual(queue_facts.sqs_redrive_max_receive_count, 5)
        self.assertEqual(queue_facts.sqs_redrive_source_address, standalone.address)
        self.assertEqual(standalone_facts.unresolved_sqs_queue_references, [])

        unresolved = _resource(
            "aws_sqs_queue_redrive_policy.unresolved",
            "aws_sqs_queue_redrive_policy",
            {
                "queue_url": "jobs",
                "redrive_policy": {
                    "deadLetterTargetArn": _DLQ_ARN,
                    "maxReceiveCount": 5,
                },
            },
        )
        unresolved_inventory = AwsNormalizer().normalize([_queue(), unresolved])
        unresolved_resource = unresolved_inventory.get_by_address("aws_sqs_queue_redrive_policy.unresolved")

        self.assertEqual(
            aws_facts(unresolved_resource).unresolved_sqs_queue_references,
            ["jobs"],
        )
        self.assertEqual(
            aws_facts(unresolved_inventory.get_by_address("aws_sqs_queue.jobs")).sqs_redrive_state,
            "not_configured",
        )

    def test_unknown_standalone_redrive_policy_updates_queue_to_unknown(self) -> None:
        standalone = _resource(
            "aws_sqs_queue_redrive_policy.jobs",
            "aws_sqs_queue_redrive_policy",
            {"queue_url": "aws_sqs_queue.jobs.url", "redrive_policy": ""},
            unknown_values={"redrive_policy": True},
        )

        inventory = AwsNormalizer().normalize([_queue(), standalone])
        facts = aws_facts(inventory.get_by_address("aws_sqs_queue.jobs"))

        self.assertEqual(facts.sqs_redrive_state, "unknown")
        self.assertEqual(facts.sqs_redrive_source_address, standalone.address)
        self.assertEqual(
            facts.sqs_posture_uncertainties,
            [f"{standalone.address}: redrive_policy is unknown after planning"],
        )

    def test_sqs_policy_normalization_remains_available(self) -> None:
        queue = normalize_sqs_queue(
            _resource(
                "aws_sqs_queue.policy",
                "aws_sqs_queue",
                {
                    "name": "policy",
                    "policy": {
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
                },
            )
        )
        self.assertEqual([statement.actions for statement in queue.policy_statements], [["sqs:SendMessage"]])
