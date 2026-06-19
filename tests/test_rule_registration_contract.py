from __future__ import annotations

import unittest

from tfstride.analysis import stride_rules
from tfstride.analysis.rule_registry import DEFAULT_RULE_REGISTRY
from tfstride.analysis.stride_rules import StrideRuleEngine

EXPECTED_DEFAULT_RULE_GROUP_IDS = (
    (
        "aws-public-compute-broad-ingress",
        "aws-rds-storage-encryption-disabled",
        "aws-s3-public-access",
        "gcp-sensitive-resource-iam-external-access",
        "gcp-pubsub-public-access",
        "gcp-bigquery-public-access",
        "gcp-cloud-sql-public-authorized-network",
        "gcp-cloud-sql-backup-disabled",
        "gcp-cloud-sql-public-ip-without-private-network",
        "gcp-cloud-sql-ssl-not-required",
        "gcp-cloud-sql-point-in-time-recovery-disabled",
        "gcp-cloud-sql-deletion-protection-disabled",
        "gcp-gcs-public-access",
        "gcp-gcs-uniform-bucket-level-access-disabled",
        "gcp-gcs-public-access-prevention-not-enforced",
        "gcp-gcs-versioning-disabled",
        "gcp-gcs-customer-managed-encryption-missing",
        "gcp-public-compute-broad-ingress",
        "gcp-public-load-balanced-workload",
        "gcp-compute-os-login-disabled",
        "gcp-gke-public-control-plane",
        "gcp-gke-broad-authorized-networks",
        "gcp-gke-workload-identity-disabled",
        "gcp-gke-legacy-metadata-endpoints-enabled",
        "gcp-gke-broad-node-service-account",
        "gcp-cloud-run-public-invoker",
        "gcp-cloud-functions-public-invoker",
    ),
    (
        "aws-database-permissive-ingress",
        "aws-missing-tier-segmentation",
    ),
    (
        "aws-sensitive-resource-policy-external-access",
        "aws-service-resource-policy-external-access",
    ),
    (
        "aws-iam-wildcard-permissions",
        "aws-workload-role-sensitive-permissions",
        "gcp-service-account-iam-broad-principal",
        "gcp-service-account-iam-privileged-role",
        "gcp-service-account-key-hygiene",
        "gcp-service-account-key-effective-access",
        "gcp-org-folder-iam-broad-principal",
        "gcp-org-folder-iam-privileged-role",
        "gcp-project-iam-broad-principal",
        "gcp-project-iam-privileged-role",
        "gcp-inherited-iam-sensitive-resource-access",
        "gcp-inherited-iam-blast-radius",
    ),
    (
        "aws-private-data-transitive-exposure",
        "aws-control-plane-sensitive-workload-chain",
        "gcp-public-workload-sensitive-data-access",
    ),
    (
        "aws-role-trust-expansion",
        "aws-role-trust-missing-narrowing",
    ),
)


def _flatten(rule_groups: tuple[tuple[str, ...], ...]) -> tuple[str, ...]:
    return tuple(rule_id for rule_group in rule_groups for rule_id in rule_group)


def _engine_rule_group_ids(engine: StrideRuleEngine) -> tuple[tuple[str, ...], ...]:
    return tuple(tuple(rule.metadata.rule_id for rule in rule_group) for rule_group in engine._rule_groups())


class DefaultRuleRegistrationContractTests(unittest.TestCase):
    def test_default_rule_group_ids_match_locked_stage_order(self) -> None:
        self.assertEqual(stride_rules._RULE_GROUP_IDS, EXPECTED_DEFAULT_RULE_GROUP_IDS)
        self.assertEqual(
            _engine_rule_group_ids(StrideRuleEngine()),
            EXPECTED_DEFAULT_RULE_GROUP_IDS,
        )

    def test_default_rule_group_count_and_lengths_are_stable(self) -> None:
        self.assertEqual(len(stride_rules._RULE_GROUP_IDS), 6)
        self.assertEqual(tuple(len(rule_group) for rule_group in stride_rules._RULE_GROUP_IDS), (27, 2, 2, 12, 3, 2))

    def test_default_rule_ids_are_unique(self) -> None:
        rule_ids = _flatten(stride_rules._RULE_GROUP_IDS)

        self.assertEqual(len(rule_ids), len(set(rule_ids)))

    def test_default_configured_rule_ids_exist_in_default_registry(self) -> None:
        configured_rule_ids = set(_flatten(_engine_rule_group_ids(StrideRuleEngine())))

        self.assertLessEqual(configured_rule_ids, DEFAULT_RULE_REGISTRY.known_rule_ids())

    def test_default_configured_rule_ids_match_default_registry(self) -> None:
        self.assertEqual(
            StrideRuleEngine().configured_rule_ids(),
            DEFAULT_RULE_REGISTRY.known_rule_ids(),
        )


if __name__ == "__main__":
    unittest.main()
