from __future__ import annotations

import unittest
from collections import Counter

from tests.providers.aws.test_aws_messaging_rules import _findings as _aws_findings
from tests.providers.aws.test_aws_messaging_rules import _queue as _aws_queue
from tests.providers.aws.test_aws_messaging_rules import _topic as _aws_topic
from tests.providers.azure.test_azure_service_bus_rules import _evaluate as _azure_findings
from tests.providers.azure.test_azure_service_bus_rules import _namespace as _azure_namespace
from tests.providers.azure.test_azure_service_bus_rules import _private_endpoint as _azure_private_endpoint
from tests.providers.gcp.test_gcp_pubsub_posture_rules import _findings as _gcp_findings
from tests.providers.gcp.test_gcp_pubsub_posture_rules import _subscription as _gcp_subscription
from tests.providers.gcp.test_gcp_pubsub_posture_rules import _topic as _gcp_topic
from tfstride.models import Finding
from tfstride.providers.aws.rules import AWS_RULE_GROUP_IDS
from tfstride.providers.azure.rules import AZURE_RULE_GROUP_IDS
from tfstride.providers.gcp.rules import GCP_RULE_GROUP_IDS

AWS_MESSAGING_RULE_IDS = frozenset(
    {
        "aws-sns-customer-managed-encryption-missing",
        "aws-sqs-customer-managed-encryption-missing",
        "aws-sqs-message-retention-insufficient",
        "aws-sqs-dead-letter-queue-not-configured",
    }
)
GCP_MESSAGING_RULE_IDS = frozenset(
    {
        "gcp-pubsub-topic-customer-managed-encryption-missing",
        "gcp-pubsub-message-retention-insufficient",
        "gcp-pubsub-subscription-dead-letter-policy-missing",
    }
)
AZURE_SERVICE_BUS_RULE_IDS = frozenset(
    {
        "azure-service-bus-public-network-access-not-disabled",
        "azure-service-bus-minimum-tls-below-1-2",
        "azure-service-bus-minimum-tls-unknown",
        "azure-service-bus-local-auth-enabled",
        "azure-service-bus-customer-managed-key-missing",
        "azure-service-bus-missing-private-endpoint",
    }
)
AZURE_PRIVATE_CONNECTIVITY_RULE_IDS = frozenset(
    {
        "azure-private-endpoint-public-fallback",
        "azure-private-endpoint-dns-posture-incomplete",
    }
)
AZURE_MESSAGING_RULE_IDS = AZURE_SERVICE_BUS_RULE_IDS | AZURE_PRIVATE_CONNECTIVITY_RULE_IDS
ALL_MESSAGING_RULE_IDS = AWS_MESSAGING_RULE_IDS | GCP_MESSAGING_RULE_IDS | AZURE_MESSAGING_RULE_IDS

_AWS_TOPIC_KMS_KEY = "arn:aws:kms:us-east-1:111122223333:key/topic"
_AWS_QUEUE_KMS_KEY = "arn:aws:kms:us-east-1:111122223333:key/queue"
_AWS_DLQ_ARN = "arn:aws:sqs:us-east-1:111122223333:jobs-dead-letter"
_GCP_PUBSUB_KMS_KEY = "projects/tfstride-demo/locations/global/keyRings/app/cryptoKeys/pubsub"
_GCP_DLQ_TOPIC = "projects/tfstride-demo/topics/events-dead-letter"
_AZURE_SERVICE_BUS_KMS_KEY = "azurerm_key_vault_key.service_bus.id"


def _flatten(rule_groups: tuple[tuple[str, ...], ...]) -> frozenset[str]:
    return frozenset(rule_id for rule_group in rule_groups for rule_id in rule_group)


def _rule_counts(findings: list[Finding]) -> Counter[str]:
    return Counter(finding.rule_id for finding in findings)


def _finding_ids(findings: list[Finding]) -> frozenset[str]:
    return frozenset(finding.rule_id for finding in findings)


def _aws_unsafe_findings(*rule_ids: str) -> list[Finding]:
    return _aws_findings(
        [
            _aws_topic(kms_master_key_id="alias/aws/sns"),
            _aws_queue(
                kms_master_key_id="alias/aws/sqs",
                message_retention_seconds=86_400,
            ),
        ],
        *rule_ids,
    )


def _gcp_unsafe_findings(*rule_ids: str) -> list[Finding]:
    return _gcp_findings(
        [
            _gcp_topic(message_retention_duration="3600s"),
            _gcp_subscription(message_retention_duration="3600s"),
        ],
        *rule_ids,
    )


def _azure_unsafe_findings(*rule_ids: str) -> list[Finding]:
    return _azure_findings(
        [
            _azure_namespace(
                public_network=True,
                default_action="Allow",
                minimum_tls_version="1.0",
                local_auth_enabled=True,
            )
        ],
        *rule_ids,
    )


class ManagedMessagingPostureParityTests(unittest.TestCase):
    def test_managed_messaging_rule_families_are_registered(self) -> None:
        aws_registered = _flatten(AWS_RULE_GROUP_IDS)
        gcp_registered = _flatten(GCP_RULE_GROUP_IDS)
        azure_registered = _flatten(AZURE_RULE_GROUP_IDS)

        self.assertLessEqual(AWS_MESSAGING_RULE_IDS, aws_registered)
        self.assertLessEqual(GCP_MESSAGING_RULE_IDS, gcp_registered)
        self.assertLessEqual(AZURE_SERVICE_BUS_RULE_IDS, azure_registered)
        self.assertLessEqual(AZURE_PRIVATE_CONNECTIVITY_RULE_IDS, azure_registered)

    def test_unsafe_provider_local_messaging_concepts_are_pinned(self) -> None:
        aws_findings = _aws_unsafe_findings(*AWS_MESSAGING_RULE_IDS)
        gcp_findings = _gcp_unsafe_findings(*GCP_MESSAGING_RULE_IDS)
        azure_findings = _azure_unsafe_findings(*AZURE_MESSAGING_RULE_IDS)

        self.assertEqual(
            _rule_counts(aws_findings),
            Counter(
                {
                    "aws-sns-customer-managed-encryption-missing": 1,
                    "aws-sqs-customer-managed-encryption-missing": 1,
                    "aws-sqs-message-retention-insufficient": 1,
                    "aws-sqs-dead-letter-queue-not-configured": 1,
                }
            ),
        )
        self.assertEqual(
            _rule_counts(gcp_findings),
            Counter(
                {
                    "gcp-pubsub-topic-customer-managed-encryption-missing": 1,
                    "gcp-pubsub-message-retention-insufficient": 2,
                    "gcp-pubsub-subscription-dead-letter-policy-missing": 1,
                }
            ),
        )
        self.assertEqual(
            _rule_counts(azure_findings),
            Counter(
                {
                    "azure-service-bus-public-network-access-not-disabled": 1,
                    "azure-service-bus-minimum-tls-below-1-2": 1,
                    "azure-service-bus-local-auth-enabled": 1,
                    "azure-service-bus-customer-managed-key-missing": 1,
                    "azure-service-bus-missing-private-endpoint": 1,
                }
            ),
        )

    def test_hardened_managed_messaging_posture_is_quiet(self) -> None:
        aws_findings = _aws_findings(
            [
                _aws_topic(kms_master_key_id=_AWS_TOPIC_KMS_KEY),
                _aws_queue(
                    kms_master_key_id=_AWS_QUEUE_KMS_KEY,
                    message_retention_seconds=345_600,
                    redrive_policy={
                        "deadLetterTargetArn": _AWS_DLQ_ARN,
                        "maxReceiveCount": 5,
                    },
                ),
            ],
            *AWS_MESSAGING_RULE_IDS,
        )
        gcp_findings = _gcp_findings(
            [
                _gcp_topic(
                    kms_key_name=_GCP_PUBSUB_KMS_KEY,
                    message_retention_duration="604800s",
                ),
                _gcp_subscription(
                    message_retention_duration="604800s",
                    dead_letter_policy=[
                        {
                            "dead_letter_topic": _GCP_DLQ_TOPIC,
                            "max_delivery_attempts": 5,
                        }
                    ],
                ),
            ],
            *GCP_MESSAGING_RULE_IDS,
        )
        azure_findings = _azure_findings(
            [
                _azure_namespace(
                    public_network=False,
                    default_action="Deny",
                    minimum_tls_version="1.2",
                    local_auth_enabled=False,
                    cmk_key_id=_AZURE_SERVICE_BUS_KMS_KEY,
                ),
                _azure_private_endpoint(),
            ],
            *AZURE_MESSAGING_RULE_IDS,
        )

        self.assertEqual(aws_findings, [])
        self.assertEqual(gcp_findings, [])
        self.assertEqual(azure_findings, [])

    def test_unknown_messaging_values_do_not_become_explicit_unsafe_claims(self) -> None:
        aws_findings = _aws_findings(
            [
                _aws_topic(
                    kms_master_key_id="alias/aws/sns",
                    unknown_values={"kms_master_key_id": True},
                ),
                _aws_queue(
                    kms_master_key_id="alias/aws/sqs",
                    message_retention_seconds=86_400,
                    redrive_policy={
                        "deadLetterTargetArn": _AWS_DLQ_ARN,
                        "maxReceiveCount": 5,
                    },
                    unknown_values={
                        "kms_master_key_id": True,
                        "message_retention_seconds": True,
                        "redrive_policy": True,
                    },
                ),
            ],
            *AWS_MESSAGING_RULE_IDS,
        )
        gcp_findings = _gcp_findings(
            [
                _gcp_topic(
                    kms_key_name=_GCP_PUBSUB_KMS_KEY,
                    message_retention_duration="3600s",
                    unknown_values={
                        "kms_key_name": True,
                        "message_retention_duration": True,
                    },
                ),
                _gcp_subscription(
                    message_retention_duration="3600s",
                    dead_letter_policy=[
                        {
                            "dead_letter_topic": _GCP_DLQ_TOPIC,
                            "max_delivery_attempts": 5,
                        }
                    ],
                    unknown_values={
                        "message_retention_duration": True,
                        "dead_letter_policy": [
                            {
                                "dead_letter_topic": True,
                                "max_delivery_attempts": True,
                            }
                        ],
                    },
                ),
            ],
            *GCP_MESSAGING_RULE_IDS,
        )
        azure_findings = _azure_findings(
            [
                _azure_namespace(
                    public_network=None,
                    default_action="Deny",
                    minimum_tls_version=None,
                    local_auth_enabled=None,
                    cmk_key_id=_AZURE_SERVICE_BUS_KMS_KEY,
                    unknown_values={
                        "public_network_access_enabled": True,
                        "minimum_tls_version": True,
                        "local_auth_enabled": True,
                    },
                ),
                _azure_private_endpoint(),
            ],
            *AZURE_MESSAGING_RULE_IDS,
        )

        self.assertEqual(aws_findings, [])
        self.assertEqual(gcp_findings, [])
        self.assertEqual(
            _finding_ids(azure_findings),
            frozenset(
                {
                    "azure-service-bus-public-network-access-not-disabled",
                    "azure-service-bus-minimum-tls-unknown",
                    "azure-private-endpoint-public-fallback",
                }
            ),
        )
        self.assertNotIn("azure-service-bus-minimum-tls-below-1-2", _finding_ids(azure_findings))
        self.assertNotIn("azure-service-bus-local-auth-enabled", _finding_ids(azure_findings))
        evidence_values = [value for finding in azure_findings for item in finding.evidence for value in item.values]
        self.assertIn("public_network_access_enabled is unknown", evidence_values)
        self.assertIn("minimum_tls_version is unknown", evidence_values)
        self.assertNotIn("local_auth_enabled is true", evidence_values)

    def test_messaging_findings_do_not_leak_across_provider_inventories(self) -> None:
        aws_findings = _aws_unsafe_findings(*ALL_MESSAGING_RULE_IDS)
        gcp_findings = _gcp_unsafe_findings(*ALL_MESSAGING_RULE_IDS)
        azure_findings = _azure_unsafe_findings(*ALL_MESSAGING_RULE_IDS)

        self.assertLessEqual(_finding_ids(aws_findings), AWS_MESSAGING_RULE_IDS)
        self.assertLessEqual(_finding_ids(gcp_findings), GCP_MESSAGING_RULE_IDS)
        self.assertLessEqual(_finding_ids(azure_findings), AZURE_MESSAGING_RULE_IDS)
        self.assertTrue(all(finding.rule_id.startswith("aws-") for finding in aws_findings))
        self.assertTrue(all(finding.rule_id.startswith("gcp-") for finding in gcp_findings))
        self.assertTrue(all(finding.rule_id.startswith("azure-") for finding in azure_findings))


if __name__ == "__main__":
    unittest.main()
