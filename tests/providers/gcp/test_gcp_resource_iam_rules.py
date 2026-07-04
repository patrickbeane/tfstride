from __future__ import annotations

import unittest

from tests.providers.gcp.rule_support.data import (
    _bigquery_dataset,
    _bigquery_dataset_iam_member,
    _bigquery_table,
    _bigquery_table_iam_binding,
    _kms_crypto_key,
    _kms_crypto_key_iam_member,
    _kms_key_ring_iam_member,
    _pubsub_subscription,
    _pubsub_subscription_iam_binding,
    _pubsub_topic,
    _pubsub_topic_iam_member,
    _secret_manager_secret,
    _secret_manager_secret_iam_member,
)
from tfstride.analysis.rule_registry import RulePolicy
from tfstride.analysis.stride_rules import StrideRuleEngine
from tfstride.providers.gcp.normalizer import GcpNormalizer


class GcpResourceIamRuleTests(unittest.TestCase):
    def test_sensitive_secret_public_iam_binding_is_detected(self) -> None:
        inventory = GcpNormalizer().normalize([_secret_manager_secret(), _secret_manager_secret_iam_member()])

        findings = StrideRuleEngine().evaluate(
            inventory,
            [],
            rule_policy=RulePolicy(enabled_rule_ids=frozenset({"gcp-sensitive-resource-iam-external-access"})),
        )

        self.assertEqual(len(findings), 1)
        finding = findings[0]
        self.assertEqual(finding.rule_id, "gcp-sensitive-resource-iam-external-access")
        self.assertEqual(finding.severity.value, "high")
        self.assertEqual(
            finding.affected_resources,
            [
                "google_secret_manager_secret.api_key",
                "google_secret_manager_secret_iam_member.public_accessor",
            ],
        )
        evidence = {item.key: item.values for item in finding.evidence}
        self.assertEqual(
            evidence["iam_binding"],
            [
                "source=google_secret_manager_secret_iam_member.public_accessor",
                "role=roles/secretmanager.secretAccessor",
                "member=allAuthenticatedUsers",
            ],
        )
        self.assertEqual(evidence["trust_scope"], ["member is public GCP principal `allAuthenticatedUsers`"])

    def test_sensitive_kms_foreign_service_account_binding_is_detected(self) -> None:
        inventory = GcpNormalizer().normalize([_kms_crypto_key(), _kms_crypto_key_iam_member()])

        findings = StrideRuleEngine().evaluate(inventory, [])

        self.assertEqual(len(findings), 1)
        finding = findings[0]
        self.assertEqual(finding.rule_id, "gcp-sensitive-resource-iam-external-access")
        self.assertEqual(finding.severity.value, "medium")
        self.assertEqual(
            finding.affected_resources,
            ["google_kms_crypto_key.customer", "google_kms_crypto_key_iam_member.partner_decrypter"],
        )
        evidence = {item.key: item.values for item in finding.evidence}
        self.assertEqual(
            evidence["trust_scope"],
            ["service account belongs to project `partner-project`, outside resource project `tfstride-demo`"],
        )

    def test_sensitive_kms_key_ring_foreign_service_account_binding_is_detected(self) -> None:
        inventory = GcpNormalizer().normalize([_kms_crypto_key(), _kms_key_ring_iam_member()])

        findings = StrideRuleEngine().evaluate(inventory, [])

        self.assertEqual(len(findings), 1)
        finding = findings[0]
        self.assertEqual(finding.rule_id, "gcp-sensitive-resource-iam-external-access")
        self.assertEqual(finding.severity.value, "medium")
        self.assertEqual(
            finding.affected_resources,
            ["google_kms_crypto_key.customer", "google_kms_key_ring_iam_member.partner_decrypter"],
        )
        evidence = {item.key: item.values for item in finding.evidence}
        self.assertEqual(
            evidence["iam_binding"],
            [
                "source=google_kms_key_ring_iam_member.partner_decrypter",
                "role=roles/cloudkms.cryptoKeyDecrypter",
                "member=serviceAccount:decryptor@partner-project.iam.gserviceaccount.com",
            ],
        )
        self.assertEqual(
            evidence["trust_scope"],
            ["service account belongs to project `partner-project`, outside resource project `tfstride-demo`"],
        )

    def test_pubsub_public_topic_publisher_is_detected(self) -> None:
        inventory = GcpNormalizer().normalize([_pubsub_topic(), _pubsub_topic_iam_member()])

        findings = StrideRuleEngine().evaluate(
            inventory,
            [],
            rule_policy=RulePolicy(enabled_rule_ids=frozenset({"gcp-pubsub-public-access"})),
        )

        self.assertEqual(len(findings), 1)
        finding = findings[0]
        self.assertEqual(finding.rule_id, "gcp-pubsub-public-access")
        self.assertEqual(finding.severity.value, "high")
        self.assertEqual(
            finding.affected_resources,
            ["google_pubsub_topic.events", "google_pubsub_topic_iam_member.public_publisher"],
        )
        evidence = {item.key: item.values for item in finding.evidence}
        self.assertEqual(
            evidence["iam_binding"],
            [
                "source=google_pubsub_topic_iam_member.public_publisher",
                "role=roles/pubsub.publisher",
                "member=allUsers",
            ],
        )

    def test_pubsub_broad_subscription_subscriber_is_detected(self) -> None:
        inventory = GcpNormalizer().normalize([_pubsub_subscription(), _pubsub_subscription_iam_binding()])

        findings = StrideRuleEngine().evaluate(
            inventory,
            [],
            rule_policy=RulePolicy(enabled_rule_ids=frozenset({"gcp-pubsub-public-access"})),
        )

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].affected_resources[0], "google_pubsub_subscription.events")
        evidence = {item.key: item.values for item in findings[0].evidence}
        self.assertEqual(evidence["trust_scope"], ["member grants a whole Google Workspace domain"])

    def test_pubsub_non_broad_member_is_not_flagged(self) -> None:
        inventory = GcpNormalizer().normalize(
            [
                _pubsub_topic(),
                _pubsub_topic_iam_member(member="serviceAccount:publisher@tfstride-demo.iam.gserviceaccount.com"),
            ]
        )

        findings = StrideRuleEngine().evaluate(
            inventory,
            [],
            rule_policy=RulePolicy(enabled_rule_ids=frozenset({"gcp-pubsub-public-access"})),
        )

        self.assertEqual(findings, [])

    def test_bigquery_public_dataset_viewer_is_detected(self) -> None:
        inventory = GcpNormalizer().normalize([_bigquery_dataset(), _bigquery_dataset_iam_member()])

        findings = StrideRuleEngine().evaluate(
            inventory,
            [],
            rule_policy=RulePolicy(enabled_rule_ids=frozenset({"gcp-bigquery-public-access"})),
        )

        self.assertEqual(len(findings), 1)
        finding = findings[0]
        self.assertEqual(finding.rule_id, "gcp-bigquery-public-access")
        self.assertEqual(finding.severity.value, "high")
        self.assertEqual(
            finding.affected_resources,
            ["google_bigquery_dataset.analytics", "google_bigquery_dataset_iam_member.public_viewer"],
        )
        evidence = {item.key: item.values for item in finding.evidence}
        self.assertEqual(evidence["trust_scope"], ["member is public GCP principal `allUsers`"])

    def test_bigquery_table_domain_owner_is_detected(self) -> None:
        inventory = GcpNormalizer().normalize([_bigquery_table(), _bigquery_table_iam_binding()])

        findings = StrideRuleEngine().evaluate(
            inventory,
            [],
            rule_policy=RulePolicy(enabled_rule_ids=frozenset({"gcp-bigquery-public-access"})),
        )

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].affected_resources[0], "google_bigquery_table.events")
        evidence = {item.key: item.values for item in findings[0].evidence}
        self.assertEqual(evidence["trust_scope"], ["member grants a whole Google Workspace domain"])

    def test_bigquery_non_broad_member_is_not_flagged(self) -> None:
        inventory = GcpNormalizer().normalize(
            [_bigquery_dataset(), _bigquery_dataset_iam_member(member="group:analytics@example.com")]
        )

        findings = StrideRuleEngine().evaluate(
            inventory,
            [],
            rule_policy=RulePolicy(enabled_rule_ids=frozenset({"gcp-bigquery-public-access"})),
        )

        self.assertEqual(findings, [])

    def test_sensitive_same_project_service_account_binding_is_not_flagged(self) -> None:
        inventory = GcpNormalizer().normalize(
            [
                _kms_crypto_key(),
                _kms_crypto_key_iam_member(member="serviceAccount:decryptor@tfstride-demo.iam.gserviceaccount.com"),
            ]
        )

        findings = StrideRuleEngine().evaluate(inventory, [])

        self.assertEqual(findings, [])


if __name__ == "__main__":
    unittest.main()
