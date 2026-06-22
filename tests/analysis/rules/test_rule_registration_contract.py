from __future__ import annotations

import inspect
import unittest

from tfstride.analysis import stride_rules
from tfstride.analysis.finding_factory import FindingFactory
from tfstride.analysis.rule_definitions import RuleContribution
from tfstride.analysis.rule_registry import DEFAULT_RULE_REGISTRY
from tfstride.analysis.stride_rules import StrideRuleEngine
from tfstride.providers.aws import rules as aws_rules
from tfstride.providers.gcp import rules as gcp_rules

EXPECTED_AWS_RULE_GROUP_IDS = (
    (
        "aws-public-compute-broad-ingress",
        "aws-rds-storage-encryption-disabled",
        "aws-s3-public-access",
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
    ),
    (
        "aws-private-data-transitive-exposure",
        "aws-control-plane-sensitive-workload-chain",
    ),
    (
        "aws-role-trust-expansion",
        "aws-role-trust-missing-narrowing",
    ),
)

EXPECTED_GCP_RULE_GROUP_IDS = (
    (
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
    (),
    (),
    (
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
    ("gcp-public-workload-sensitive-data-access",),
    (),
)


def _flatten(rule_groups: tuple[tuple[str, ...], ...]) -> tuple[str, ...]:
    return tuple(rule_id for rule_group in rule_groups for rule_id in rule_group)


def _merge_stage_rule_groups(*rule_group_sets: tuple[tuple[str, ...], ...]) -> tuple[tuple[str, ...], ...]:
    stage_counts = {len(rule_groups) for rule_groups in rule_group_sets}
    if len(stage_counts) != 1:
        raise AssertionError("Expected rule group sets to share a stage count.")

    return tuple(
        tuple(rule_id for rule_groups in rule_group_sets for rule_id in rule_groups[stage_index])
        for stage_index in range(len(rule_group_sets[0]))
    )


EXPECTED_DEFAULT_RULE_GROUP_IDS = _merge_stage_rule_groups(
    EXPECTED_AWS_RULE_GROUP_IDS,
    EXPECTED_GCP_RULE_GROUP_IDS,
)


def _engine_rule_group_ids(engine: StrideRuleEngine) -> tuple[tuple[str, ...], ...]:
    return tuple(tuple(rule.metadata.rule_id for rule in rule_group) for rule_group in engine._rule_groups())


class DefaultRuleRegistrationContractTests(unittest.TestCase):
    def test_provider_rule_group_ids_match_locked_stage_order(self) -> None:
        self.assertEqual(aws_rules.AWS_RULE_GROUP_IDS, EXPECTED_AWS_RULE_GROUP_IDS)
        self.assertEqual(gcp_rules.GCP_RULE_GROUP_IDS, EXPECTED_GCP_RULE_GROUP_IDS)

    def test_provider_rule_ids_stay_in_provider_domains(self) -> None:
        self.assertTrue(all(rule_id.startswith("aws-") for rule_id in _flatten(aws_rules.AWS_RULE_GROUP_IDS)))
        self.assertTrue(all(rule_id.startswith("gcp-") for rule_id in _flatten(gcp_rules.GCP_RULE_GROUP_IDS)))

    def test_aws_rule_contribution_matches_provider_rule_groups(self) -> None:
        contribution = aws_rules.build_aws_rule_contribution(
            FindingFactory(DEFAULT_RULE_REGISTRY),
            DEFAULT_RULE_REGISTRY,
        )

        self.assertEqual(
            tuple(tuple(rule.metadata.rule_id for rule in rule_group) for rule_group in contribution.rule_groups),
            EXPECTED_AWS_RULE_GROUP_IDS,
        )

    def test_gcp_rule_contribution_matches_provider_rule_groups(self) -> None:
        contribution = gcp_rules.build_gcp_rule_contribution(
            FindingFactory(DEFAULT_RULE_REGISTRY),
            DEFAULT_RULE_REGISTRY,
        )

        self.assertEqual(
            tuple(tuple(rule.metadata.rule_id for rule in rule_group) for rule_group in contribution.rule_groups),
            EXPECTED_GCP_RULE_GROUP_IDS,
        )

    def test_stride_rule_engine_does_not_own_provider_rule_ids_or_detector_maps(self) -> None:
        source = inspect.getsource(stride_rules)

        self.assertNotIn("_RULE_GROUP_IDS", source)
        self.assertNotIn("detectors_by_rule_id", source)
        self.assertNotIn("aws-", source)
        self.assertNotIn("gcp-", source)

    def test_default_rule_group_ids_match_locked_stage_order(self) -> None:
        self.assertEqual(
            _engine_rule_group_ids(StrideRuleEngine()),
            EXPECTED_DEFAULT_RULE_GROUP_IDS,
        )

    def test_default_rule_groups_are_backed_by_rule_contribution(self) -> None:
        engine = StrideRuleEngine()

        self.assertIsInstance(engine._rule_contribution, RuleContribution)
        self.assertIs(engine._rule_groups(), engine._rule_contribution.rule_groups)

    def test_default_rule_registry_is_derived_from_rule_contribution_metadata(self) -> None:
        engine = StrideRuleEngine()

        for rule_group in engine._rule_contribution.rule_groups:
            for rule in rule_group:
                self.assertIs(engine._rule_registry.get(rule.metadata.rule_id), rule.metadata)

    def test_default_rule_group_count_and_lengths_are_stable(self) -> None:
        self.assertEqual(len(EXPECTED_DEFAULT_RULE_GROUP_IDS), 6)
        self.assertEqual(tuple(len(rule_group) for rule_group in EXPECTED_DEFAULT_RULE_GROUP_IDS), (27, 2, 2, 12, 3, 2))
        self.assertEqual(tuple(len(rule_group) for rule_group in aws_rules.AWS_RULE_GROUP_IDS), (3, 2, 2, 2, 2, 2))
        self.assertEqual(tuple(len(rule_group) for rule_group in gcp_rules.GCP_RULE_GROUP_IDS), (24, 0, 0, 10, 1, 0))

    def test_default_rule_ids_are_unique(self) -> None:
        rule_ids = _flatten(EXPECTED_DEFAULT_RULE_GROUP_IDS)

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
