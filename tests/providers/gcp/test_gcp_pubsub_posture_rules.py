from __future__ import annotations

import unittest

from tests.providers.gcp.normalizer_support import _terraform_resource
from tfstride.analysis.rule_registry import RulePolicy
from tfstride.analysis.stride_rules import StrideRuleEngine
from tfstride.models import TerraformResource
from tfstride.providers.gcp.normalizer import GcpNormalizer

_CMEK_RULE_ID = "gcp-pubsub-topic-customer-managed-encryption-missing"
_RETENTION_RULE_ID = "gcp-pubsub-message-retention-insufficient"
_DEAD_LETTER_RULE_ID = "gcp-pubsub-subscription-dead-letter-policy-missing"
_MISSING = object()


def _topic(
    *,
    kms_key_name: object = _MISSING,
    message_retention_duration: object = _MISSING,
    unknown_values: dict[str, object] | None = None,
) -> TerraformResource:
    values: dict[str, object] = {
        "name": "events",
        "project": "tfstride-demo",
    }
    if kms_key_name is not _MISSING:
        values["kms_key_name"] = kms_key_name
    if message_retention_duration is not _MISSING:
        values["message_retention_duration"] = message_retention_duration
    return _terraform_resource(
        "google_pubsub_topic.events",
        "google_pubsub_topic",
        values,
        unknown_values=unknown_values,
    )


def _subscription(
    *,
    message_retention_duration: object = _MISSING,
    dead_letter_policy: object = _MISSING,
    unknown_values: dict[str, object] | None = None,
) -> TerraformResource:
    values: dict[str, object] = {
        "name": "events",
        "project": "tfstride-demo",
        "topic": "google_pubsub_topic.events.id",
    }
    if message_retention_duration is not _MISSING:
        values["message_retention_duration"] = message_retention_duration
    if dead_letter_policy is not _MISSING:
        values["dead_letter_policy"] = dead_letter_policy
    return _terraform_resource(
        "google_pubsub_subscription.events",
        "google_pubsub_subscription",
        values,
        unknown_values=unknown_values,
    )


def _findings(resources: list[TerraformResource], *rule_ids: str):
    inventory = GcpNormalizer().normalize(resources)
    return StrideRuleEngine().evaluate(
        inventory,
        [],
        rule_policy=RulePolicy(
            enabled_rule_ids=frozenset(rule_ids or {_CMEK_RULE_ID, _RETENTION_RULE_ID, _DEAD_LETTER_RULE_ID})
        ),
    )


def _evidence(finding):
    return {item.key: item.values for item in finding.evidence}


class GcpPubSubPostureRuleTests(unittest.TestCase):
    def test_topic_without_cmek_is_detected_as_encryption_ownership_posture(self) -> None:
        findings = _findings([_topic()], _CMEK_RULE_ID)

        self.assertEqual([finding.rule_id for finding in findings], [_CMEK_RULE_ID])
        self.assertEqual(findings[0].severity.value, "medium")
        self.assertIn("Google-managed Pub/Sub encryption", findings[0].rationale)
        self.assertEqual(
            _evidence(findings[0])["encryption_ownership"],
            ["cmek_state=not_configured", "kms_key_name=unset"],
        )

    def test_topic_with_cmek_is_quiet(self) -> None:
        findings = _findings(
            [_topic(kms_key_name=("projects/tfstride-demo/locations/global/keyRings/app/cryptoKeys/pubsub"))],
            _CMEK_RULE_ID,
        )

        self.assertEqual(findings, [])

    def test_short_topic_and_subscription_retention_are_detected(self) -> None:
        findings = _findings(
            [
                _topic(
                    kms_key_name=("projects/tfstride-demo/locations/global/keyRings/app/cryptoKeys/pubsub"),
                    message_retention_duration="3600s",
                ),
                _subscription(
                    message_retention_duration="3600s",
                    dead_letter_policy=[
                        {
                            "dead_letter_topic": "projects/tfstride-demo/topics/events-dead-letter",
                            "max_delivery_attempts": 5,
                        }
                    ],
                ),
            ],
            _RETENTION_RULE_ID,
        )

        self.assertEqual([finding.rule_id for finding in findings], [_RETENTION_RULE_ID, _RETENTION_RULE_ID])
        evidence = [_evidence(finding)["message_retention_posture"] for finding in findings]
        self.assertEqual(
            evidence,
            [
                [
                    "message_retention_duration=3600s",
                    "message_retention_seconds=3600",
                    "minimum_message_retention_days=7",
                    "minimum_message_retention_seconds=604800",
                ],
                [
                    "message_retention_duration=3600s",
                    "message_retention_seconds=3600",
                    "minimum_message_retention_days=7",
                    "minimum_message_retention_seconds=604800",
                ],
            ],
        )

    def test_baseline_retention_is_quiet(self) -> None:
        findings = _findings(
            [
                _topic(message_retention_duration="604800s"),
                _subscription(
                    message_retention_duration="604800s",
                    dead_letter_policy=[
                        {
                            "dead_letter_topic": "projects/tfstride-demo/topics/events-dead-letter",
                            "max_delivery_attempts": 5,
                        }
                    ],
                ),
            ],
            _RETENTION_RULE_ID,
        )

        self.assertEqual(findings, [])

    def test_subscription_without_dead_letter_policy_is_detected(self) -> None:
        findings = _findings([_subscription()], _DEAD_LETTER_RULE_ID)

        self.assertEqual([finding.rule_id for finding in findings], [_DEAD_LETTER_RULE_ID])
        self.assertEqual(findings[0].severity.value, "medium")
        self.assertEqual(
            _evidence(findings[0])["dead_letter_posture"],
            ["dead_letter_policy_state=not_configured", "dead_letter_topic=unset"],
        )

    def test_subscription_with_dead_letter_policy_is_quiet(self) -> None:
        findings = _findings(
            [
                _subscription(
                    dead_letter_policy=[
                        {
                            "dead_letter_topic": "projects/tfstride-demo/topics/events-dead-letter",
                            "max_delivery_attempts": 5,
                        }
                    ]
                )
            ],
            _DEAD_LETTER_RULE_ID,
        )

        self.assertEqual(findings, [])

    def test_unknown_pubsub_posture_is_not_overclaimed(self) -> None:
        findings = _findings(
            [
                _topic(
                    kms_key_name="projects/tfstride-demo/locations/global/keyRings/app/cryptoKeys/pubsub",
                    message_retention_duration="3600s",
                    unknown_values={"kms_key_name": True, "message_retention_duration": True},
                ),
                _subscription(
                    message_retention_duration="3600s",
                    dead_letter_policy=[
                        {
                            "dead_letter_topic": "projects/tfstride-demo/topics/events-dead-letter",
                            "max_delivery_attempts": 5,
                        }
                    ],
                    unknown_values={
                        "message_retention_duration": True,
                        "dead_letter_policy": [{"dead_letter_topic": True, "max_delivery_attempts": True}],
                    },
                ),
            ]
        )

        self.assertEqual(findings, [])


if __name__ == "__main__":
    unittest.main()
