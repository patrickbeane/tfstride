from __future__ import annotations

import unittest

from tests.providers.gcp.rule_support.common import _org_policy_policy
from tests.providers.gcp.rule_support.data import (
    _storage_bucket,
    _storage_bucket_iam_member,
)
from tfstride.analysis.rule_registry import RulePolicy
from tfstride.analysis.stride_rules import StrideRuleEngine
from tfstride.providers.gcp.normalizer import GcpNormalizer


class GcpStorageRuleTests(unittest.TestCase):
    def test_gcs_public_bucket_iam_member_is_detected(self) -> None:
        inventory = GcpNormalizer().normalize([_storage_bucket(), _storage_bucket_iam_member()])

        findings = StrideRuleEngine().evaluate(
            inventory,
            [],
            rule_policy=RulePolicy(enabled_rule_ids=frozenset({"gcp-gcs-public-access"})),
        )

        self.assertEqual(len(findings), 1)
        finding = findings[0]
        self.assertEqual(finding.rule_id, "gcp-gcs-public-access")
        self.assertEqual(finding.severity.value, "medium")
        self.assertEqual(finding.affected_resources, ["google_storage_bucket.logs"])
        self.assertIsNone(finding.trust_boundary_id)
        evidence = {item.key: item.values for item in finding.evidence}
        self.assertEqual(
            evidence["public_exposure_reasons"],
            ["google_storage_bucket_iam_member.public_logs_reader grants roles/storage.objectViewer to allUsers"],
        )

    def test_gcs_all_authenticated_users_bucket_iam_member_is_detected(self) -> None:
        inventory = GcpNormalizer().normalize(
            [_storage_bucket(), _storage_bucket_iam_member(member="allAuthenticatedUsers")]
        )

        findings = StrideRuleEngine().evaluate(
            inventory,
            [],
            rule_policy=RulePolicy(enabled_rule_ids=frozenset({"gcp-gcs-public-access"})),
        )

        self.assertEqual([finding.rule_id for finding in findings], ["gcp-gcs-public-access"])

    def test_gcs_public_access_prevention_suppresses_public_iam_grant(self) -> None:
        inventory = GcpNormalizer().normalize(
            [_storage_bucket(public_access_prevention="enforced"), _storage_bucket_iam_member()]
        )

        findings = StrideRuleEngine().evaluate(
            inventory,
            [],
            rule_policy=RulePolicy(enabled_rule_ids=frozenset({"gcp-gcs-public-access"})),
        )

        self.assertEqual(findings, [])

    def test_gcs_non_public_member_is_not_flagged(self) -> None:
        inventory = GcpNormalizer().normalize(
            [
                _storage_bucket(),
                _storage_bucket_iam_member(member="serviceAccount:reader@example.iam.gserviceaccount.com"),
            ]
        )

        findings = StrideRuleEngine().evaluate(
            inventory,
            [],
            rule_policy=RulePolicy(enabled_rule_ids=frozenset({"gcp-gcs-public-access"})),
        )

        self.assertEqual(findings, [])

    def test_gcs_uniform_bucket_level_access_disabled_is_detected(self) -> None:
        inventory = GcpNormalizer().normalize([_storage_bucket(uniform_bucket_level_access=False)])

        findings = StrideRuleEngine().evaluate(
            inventory,
            [],
            rule_policy=RulePolicy(enabled_rule_ids=frozenset({"gcp-gcs-uniform-bucket-level-access-disabled"})),
        )

        self.assertEqual(len(findings), 1)
        finding = findings[0]
        self.assertEqual(finding.rule_id, "gcp-gcs-uniform-bucket-level-access-disabled")
        self.assertEqual(finding.severity.value, "medium")
        self.assertEqual(finding.affected_resources, ["google_storage_bucket.logs"])
        evidence = {item.key: item.values for item in finding.evidence}
        self.assertEqual(evidence["access_control_posture"], ["uniform_bucket_level_access is false"])

    def test_gcs_public_access_prevention_not_enforced_is_detected(self) -> None:
        inventory = GcpNormalizer().normalize([_storage_bucket(public_access_prevention="inherited")])

        findings = StrideRuleEngine().evaluate(
            inventory,
            [],
            rule_policy=RulePolicy(enabled_rule_ids=frozenset({"gcp-gcs-public-access-prevention-not-enforced"})),
        )

        self.assertEqual(len(findings), 1)
        finding = findings[0]
        self.assertEqual(finding.rule_id, "gcp-gcs-public-access-prevention-not-enforced")
        self.assertEqual(finding.severity.value, "medium")
        evidence = {item.key: item.values for item in finding.evidence}
        self.assertEqual(evidence["access_control_posture"], ["public_access_prevention is inherited"])

    def test_gcs_public_access_prevention_finding_includes_organization_guardrail_evidence(self) -> None:
        inventory = GcpNormalizer().normalize(
            [
                _org_policy_policy(
                    "google_org_policy_policy.storage_pap",
                    constraint="constraints/storage.publicAccessPrevention",
                    enforced=True,
                ),
                _storage_bucket(public_access_prevention="inherited"),
            ]
        )

        findings = StrideRuleEngine().evaluate(
            inventory,
            [],
            rule_policy=RulePolicy(enabled_rule_ids=frozenset({"gcp-gcs-public-access-prevention-not-enforced"})),
        )

        finding = findings[0]
        self.assertEqual(finding.severity.value, "low")
        self.assertIsNotNone(finding.severity_reasoning)
        assert finding.severity_reasoning is not None
        self.assertEqual(finding.severity_reasoning.final_score, 2)
        evidence = {item.key: item.values for item in finding.evidence}
        self.assertEqual(
            evidence["organization_guardrails"],
            [
                "constraint=constraints/storage.publicAccessPrevention; "
                "scope=project:tfstride-demo; "
                "source=google_org_policy_policy.storage_pap; "
                "enforced=true"
            ],
        )

    def test_gcs_public_access_prevention_enforced_is_not_flagged(self) -> None:
        inventory = GcpNormalizer().normalize([_storage_bucket(public_access_prevention="enforced")])

        findings = StrideRuleEngine().evaluate(
            inventory,
            [],
            rule_policy=RulePolicy(enabled_rule_ids=frozenset({"gcp-gcs-public-access-prevention-not-enforced"})),
        )

        self.assertEqual(findings, [])

    def test_gcs_versioning_disabled_is_detected_for_sensitive_bucket(self) -> None:
        inventory = GcpNormalizer().normalize([_storage_bucket(versioning_enabled=False)])

        findings = StrideRuleEngine().evaluate(
            inventory,
            [],
            rule_policy=RulePolicy(enabled_rule_ids=frozenset({"gcp-gcs-versioning-disabled"})),
        )

        self.assertEqual(len(findings), 1)
        finding = findings[0]
        self.assertEqual(finding.rule_id, "gcp-gcs-versioning-disabled")
        self.assertEqual(finding.severity.value, "medium")
        evidence = {item.key: item.values for item in finding.evidence}
        self.assertEqual(
            evidence["data_protection_posture"],
            ["versioning.enabled is false", "data_sensitivity is sensitive"],
        )

    def test_gcs_customer_managed_encryption_missing_is_detected(self) -> None:
        inventory = GcpNormalizer().normalize([_storage_bucket(default_kms_key_name=None)])

        findings = StrideRuleEngine().evaluate(
            inventory,
            [],
            rule_policy=RulePolicy(enabled_rule_ids=frozenset({"gcp-gcs-customer-managed-encryption-missing"})),
        )

        self.assertEqual(len(findings), 1)
        finding = findings[0]
        self.assertEqual(finding.rule_id, "gcp-gcs-customer-managed-encryption-missing")
        self.assertEqual(finding.severity.value, "medium")
        evidence = {item.key: item.values for item in finding.evidence}
        self.assertEqual(
            evidence["encryption_posture"],
            ["default_kms_key_name is unset", "customer_managed_encryption is false"],
        )

    def test_gcs_customer_managed_encryption_is_not_flagged_when_kms_key_is_configured(self) -> None:
        inventory = GcpNormalizer().normalize([_storage_bucket()])

        findings = StrideRuleEngine().evaluate(
            inventory,
            [],
            rule_policy=RulePolicy(enabled_rule_ids=frozenset({"gcp-gcs-customer-managed-encryption-missing"})),
        )

        self.assertEqual(findings, [])


if __name__ == "__main__":
    unittest.main()
