from __future__ import annotations

import inspect
import unittest

from tfstride.analysis import stride_rules
from tfstride.analysis.finding_factory import FindingFactory
from tfstride.analysis.rule_definitions import RuleContribution
from tfstride.analysis.rule_registry import default_rule_registry
from tfstride.analysis.stride_rules import StrideRuleEngine
from tfstride.providers.aws import rules as aws_rules
from tfstride.providers.azure import rules as azure_rules
from tfstride.providers.gcp import rules as gcp_rules

EXPECTED_AWS_RULE_GROUP_IDS = (
    (
        "aws-public-compute-broad-ingress",
        "aws-lambda-public-invocation",
        "aws-load-balancer-http-public-listener",
        "aws-load-balancer-listener-tls-certificate-missing",
        "aws-load-balancer-listener-ssl-policy-weak-or-unknown",
        "aws-public-alb-waf-missing",
        "aws-cloudtrail-multi-region-disabled",
        "aws-cloudtrail-log-file-validation-disabled",
        "aws-cloudtrail-management-events-disabled",
        "aws-cloudtrail-data-events-not-modeled",
        "aws-cloudtrail-insight-selectors-missing",
        "aws-guardduty-detector-disabled-or-missing",
        "aws-securityhub-account-missing",
        "aws-rds-storage-encryption-disabled",
        "aws-rds-public-endpoint-enabled",
        "aws-rds-backup-retention-insufficient",
        "aws-rds-deletion-protection-disabled",
        "aws-rds-customer-managed-kms-key-missing",
        "aws-s3-public-access",
        "aws-s3-customer-managed-encryption-missing",
        "aws-s3-versioning-disabled",
        "aws-secretsmanager-customer-managed-kms-key-missing",
        "aws-secretsmanager-recovery-window-too-short",
        "aws-secretsmanager-rotation-not-configured-or-too-long",
        "aws-kms-key-rotation-disabled-or-unknown",
        "aws-kms-key-deletion-window-too-short",
        "aws-workload-secretsmanager-vpc-endpoint-missing",
        "aws-workload-kms-vpc-endpoint-missing",
        "aws-workload-s3-vpc-endpoint-missing",
        "aws-vpc-endpoint-policy-broad-access",
        "aws-vpc-flow-logs-not-configured",
        "aws-vpc-flow-log-traffic-type-incomplete",
        "aws-vpc-flow-log-destination-missing",
        "aws-eks-api-endpoint-public-unrestricted",
        "aws-eks-private-endpoint-not-enabled",
        "aws-eks-secrets-encryption-not-configured",
        "aws-eks-control-plane-logging-incomplete",
        "aws-eks-authentication-mode-weak-or-unknown",
        "aws-eks-vpc-cni-network-policy-not-enabled",
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
        "aws-iam-privileged-role-assignment",
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

EXPECTED_AZURE_RULE_GROUP_IDS = (
    (
        "azure-public-compute-broad-ingress",
        "azure-load-balancer-public-frontend",
        "azure-application-gateway-public-listener",
        "azure-nsg-flow-logs-not-configured",
        "azure-nsg-flow-log-disabled",
        "azure-nsg-flow-log-destination-missing",
        "azure-nsg-flow-log-retention-insufficient",
        "azure-storage-container-public-access",
        "azure-storage-account-nested-public-access-enabled",
        "azure-storage-account-shared-key-enabled",
        "azure-storage-account-minimum-tls-below-1-2",
        "azure-storage-account-public-network-unrestricted",
        "azure-storage-account-customer-managed-key-missing",
        "azure-storage-account-infrastructure-encryption-not-enabled",
        "azure-storage-account-blob-versioning-disabled",
        "azure-storage-account-blob-soft-delete-insufficient",
        "azure-storage-account-container-soft-delete-insufficient",
        "azure-storage-account-point-in-time-restore-missing",
        "azure-storage-account-missing-private-endpoint",
        "azure-key-vault-public-network-access",
        "azure-key-vault-missing-private-endpoint",
        "azure-key-vault-privileged-access",
        "azure-key-vault-purge-protection-disabled",
        "azure-key-vault-secret-certificate-lifecycle-incomplete",
        "azure-key-vault-key-strength-weak",
        "azure-key-vault-key-rotation-policy-incomplete",
        "azure-custom-role-wildcard-management-plane",
        "azure-custom-role-authorization-management",
        "azure-custom-role-broad-management-plane",
        "azure-custom-role-broad-data-plane",
        "azure-custom-role-subscription-assignable-scope",
        "azure-custom-role-assignment-blast-radius",
        "azure-rbac-privileged-assignment",
        "azure-managed-identity-broad-rbac",
        "azure-public-workload-sensitive-resource-access",
        "azure-app-service-public-network-access-not-disabled",
        "azure-app-service-minimum-tls-below-1-2",
        "azure-app-service-minimum-tls-unknown",
        "azure-app-service-managed-identity-missing",
        "azure-app-service-vnet-integration-missing",
        "azure-app-service-access-restrictions-not-default-deny",
        "azure-app-service-broad-access-restriction-allow",
        "azure-app-service-scm-access-unrestricted",
        "azure-diagnostic-settings-missing",
        "azure-diagnostic-setting-no-log-destination",
        "azure-diagnostic-setting-audit-logs-incomplete",
        "azure-defender-pricing-tier-not-standard",
        "azure-security-center-auto-provisioning-disabled",
        "azure-aks-api-server-public-unrestricted",
        "azure-aks-private-cluster-not-enabled",
        "azure-aks-local-accounts-not-disabled",
        "azure-aks-rbac-posture-weak",
        "azure-aks-network-policy-missing",
        "azure-aks-workload-identity-not-enabled",
        "azure-aks-key-management-service-not-configured",
        "azure-aks-monitoring-agent-not-enabled",
        "azure-aks-defender-not-enabled",
        "azure-aks-azure-policy-not-enabled",
        "azure-sql-public-network-access-enabled",
        "azure-sql-missing-private-endpoint",
        "azure-sql-firewall-broad-public-access",
        "azure-sql-minimum-tls-below-1-2",
        "azure-sql-security-alert-policy-disabled",
        "azure-sql-short-term-backup-retention-insufficient",
        "azure-sql-long-term-backup-retention-not-configured",
        "azure-sql-backup-geo-redundancy-not-enabled",
        "azure-private-endpoint-public-fallback",
        "azure-private-endpoint-dns-posture-incomplete",
        "azure-postgresql-public-network-access-enabled",
        "azure-postgresql-firewall-broad-public-access",
        "azure-postgresql-weak-tls-or-ssl",
        "azure-postgresql-geo-backup-disabled",
    ),
    (),
    (),
    (),
    (),
    (),
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
        "gcp-cloud-sql-private-connectivity-not-modeled",
        "gcp-private-workload-private-google-access-disabled",
        "gcp-gcs-public-access",
        "gcp-gcs-uniform-bucket-level-access-disabled",
        "gcp-gcs-public-access-prevention-not-enforced",
        "gcp-gcs-versioning-disabled",
        "gcp-gcs-customer-managed-encryption-missing",
        "gcp-gcs-retention-policy-insufficient",
        "gcp-secret-manager-customer-managed-encryption-missing",
        "gcp-secret-manager-lifecycle-posture-incomplete",
        "gcp-kms-key-rotation-not-configured-or-too-long",
        "gcp-kms-key-destroy-scheduled-duration-too-short",
        "gcp-public-compute-broad-ingress",
        "gcp-public-load-balanced-workload",
        "gcp-load-balancer-http-public-proxy",
        "gcp-load-balancer-ssl-policy-missing-or-weak",
        "gcp-public-load-balancer-cloud-armor-missing",
        "gcp-compute-os-login-disabled",
        "gcp-gke-public-control-plane",
        "gcp-gke-broad-authorized-networks",
        "gcp-gke-workload-identity-disabled",
        "gcp-gke-legacy-metadata-endpoints-enabled",
        "gcp-gke-broad-node-service-account",
        "gcp-gke-control-plane-logging-incomplete",
        "gcp-scc-asset-discovery-disabled",
        "gcp-logging-exclusion-drops-audit-security-logs",
        "gcp-logging-sink-audit-export-incomplete",
        "gcp-central-audit-sink-not-modeled",
        "gcp-subnetwork-flow-logs-not-configured",
        "gcp-subnetwork-flow-log-capture-incomplete",
        "gcp-gke-network-policy-disabled",
        "gcp-gke-secrets-encryption-not-configured",
        "gcp-gke-legacy-abac-enabled-or-unknown",
        "gcp-gke-client-certificate-auth-enabled-or-unknown",
        "gcp-gke-shielded-nodes-disabled-or-unknown",
        "gcp-gke-binary-authorization-not-enabled",
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
        "gcp-iam-privileged-assignment",
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
    EXPECTED_AZURE_RULE_GROUP_IDS,
)


def _engine_rule_group_ids(engine: StrideRuleEngine) -> tuple[tuple[str, ...], ...]:
    return tuple(tuple(rule.metadata.rule_id for rule in rule_group) for rule_group in engine._rule_groups())


class DefaultRuleRegistrationContractTests(unittest.TestCase):
    def test_provider_rule_group_ids_match_locked_stage_order(self) -> None:
        self.assertEqual(aws_rules.AWS_RULE_GROUP_IDS, EXPECTED_AWS_RULE_GROUP_IDS)
        self.assertEqual(gcp_rules.GCP_RULE_GROUP_IDS, EXPECTED_GCP_RULE_GROUP_IDS)
        self.assertEqual(azure_rules.AZURE_RULE_GROUP_IDS, EXPECTED_AZURE_RULE_GROUP_IDS)

    def test_provider_rule_ids_stay_in_provider_domains(self) -> None:
        self.assertTrue(all(rule_id.startswith("aws-") for rule_id in _flatten(aws_rules.AWS_RULE_GROUP_IDS)))
        self.assertTrue(all(rule_id.startswith("gcp-") for rule_id in _flatten(gcp_rules.GCP_RULE_GROUP_IDS)))
        self.assertTrue(all(rule_id.startswith("azure-") for rule_id in _flatten(azure_rules.AZURE_RULE_GROUP_IDS)))

    def test_aws_rule_contribution_matches_provider_rule_groups(self) -> None:
        registry = default_rule_registry()
        contribution = aws_rules.build_aws_rule_contribution(
            FindingFactory(registry),
            registry,
        )

        self.assertEqual(
            tuple(tuple(rule.metadata.rule_id for rule in rule_group) for rule_group in contribution.rule_groups),
            EXPECTED_AWS_RULE_GROUP_IDS,
        )

    def test_gcp_rule_contribution_matches_provider_rule_groups(self) -> None:
        registry = default_rule_registry()
        contribution = gcp_rules.build_gcp_rule_contribution(
            FindingFactory(registry),
            registry,
        )

        self.assertEqual(
            tuple(tuple(rule.metadata.rule_id for rule in rule_group) for rule_group in contribution.rule_groups),
            EXPECTED_GCP_RULE_GROUP_IDS,
        )

    def test_azure_rule_contribution_matches_provider_rule_groups(self) -> None:
        registry = default_rule_registry()
        contribution = azure_rules.build_azure_rule_contribution(
            FindingFactory(registry),
            registry,
        )

        self.assertEqual(
            tuple(tuple(rule.metadata.rule_id for rule in rule_group) for rule_group in contribution.rule_groups),
            EXPECTED_AZURE_RULE_GROUP_IDS,
        )

    def test_stride_rule_engine_does_not_own_provider_rule_ids_or_detector_maps(self) -> None:
        source = inspect.getsource(stride_rules)

        self.assertNotIn("_RULE_GROUP_IDS", source)
        self.assertNotIn("detectors_by_rule_id", source)
        self.assertNotIn("aws-", source)
        self.assertNotIn("gcp-", source)
        self.assertNotIn("azure-", source)

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
        self.assertEqual(
            tuple(len(rule_group) for rule_group in EXPECTED_DEFAULT_RULE_GROUP_IDS), (158, 2, 2, 14, 3, 2)
        )
        self.assertEqual(tuple(len(rule_group) for rule_group in aws_rules.AWS_RULE_GROUP_IDS), (39, 2, 2, 3, 2, 2))
        self.assertEqual(tuple(len(rule_group) for rule_group in gcp_rules.GCP_RULE_GROUP_IDS), (47, 0, 0, 11, 1, 0))
        self.assertEqual(tuple(len(rule_group) for rule_group in azure_rules.AZURE_RULE_GROUP_IDS), (72, 0, 0, 0, 0, 0))

    def test_default_rule_ids_are_unique(self) -> None:
        rule_ids = _flatten(EXPECTED_DEFAULT_RULE_GROUP_IDS)

        self.assertEqual(len(rule_ids), len(set(rule_ids)))

    def test_default_configured_rule_ids_exist_in_default_registry(self) -> None:
        configured_rule_ids = set(_flatten(_engine_rule_group_ids(StrideRuleEngine())))

        self.assertLessEqual(configured_rule_ids, default_rule_registry().known_rule_ids())

    def test_default_configured_rule_ids_match_default_registry(self) -> None:
        self.assertEqual(
            StrideRuleEngine().configured_rule_ids(),
            default_rule_registry().known_rule_ids(),
        )


if __name__ == "__main__":
    unittest.main()
