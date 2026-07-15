from __future__ import annotations

import subprocess
import sys
import unittest

from tests.helpers import engine_configured_rule_ids
from tfstride.analysis import rule_registry as rule_registry_module
from tfstride.analysis.rule_registry import (
    RuleMetadata,
    RulePolicy,
    RuleRegistry,
    apply_severity_overrides,
    default_rule_metadata,
    default_rule_registry,
)
from tfstride.analysis.stride_rules import StrideRuleEngine
from tfstride.models import Finding, Severity, SeverityReasoning, StrideCategory
from tfstride.providers.aws.rules import AWS_RULE_GROUP_IDS
from tfstride.providers.azure.rules import AZURE_RULE_GROUP_IDS
from tfstride.providers.gcp.rules import GCP_RULE_GROUP_IDS

EXPECTED_DEFAULT_RULE_METADATA_IDS = (
    "aws-public-compute-broad-ingress",
    "aws-lambda-public-invocation",
    "aws-load-balancer-http-public-listener",
    "aws-load-balancer-listener-tls-certificate-missing",
    "aws-load-balancer-listener-ssl-policy-weak-or-unknown",
    "aws-public-alb-waf-missing",
    "aws-cloudfront-viewer-http-allowed",
    "aws-cloudfront-viewer-tls-policy-weak-or-unknown",
    "aws-cloudfront-access-logging-not-configured",
    "aws-public-cloudfront-waf-missing",
    "aws-api-gateway-cors-permissive",
    "aws-public-api-gateway-waf-missing",
    "aws-api-gateway-public-route-authorization-none",
    "aws-api-gateway-stage-access-logs-missing",
    "aws-cloudtrail-multi-region-disabled",
    "aws-cloudtrail-log-file-validation-disabled",
    "aws-cloudtrail-management-events-disabled",
    "aws-cloudtrail-data-events-not-modeled",
    "aws-cloudtrail-insight-selectors-missing",
    "aws-guardduty-detector-disabled-or-missing",
    "aws-securityhub-account-missing",
    "aws-config-recorder-disabled-or-missing",
    "aws-config-delivery-channel-missing",
    "aws-access-analyzer-not-configured",
    "aws-macie-not-enabled-for-sensitive-storage",
    "aws-database-permissive-ingress",
    "aws-rds-storage-encryption-disabled",
    "aws-rds-public-endpoint-enabled",
    "aws-rds-backup-retention-insufficient",
    "aws-rds-deletion-protection-disabled",
    "aws-rds-customer-managed-kms-key-missing",
    "aws-rds-multi-az-disabled",
    "aws-rds-performance-insights-disabled",
    "aws-rds-cloudwatch-log-exports-missing",
    "aws-rds-iam-auth-disabled",
    "aws-s3-public-access",
    "aws-s3-customer-managed-encryption-missing",
    "aws-s3-versioning-disabled",
    "aws-s3-object-lock-retention-missing",
    "aws-s3-lifecycle-noncurrent-retention-insufficient",
    "aws-ecr-image-tag-mutability-enabled",
    "aws-ecr-customer-managed-encryption-missing",
    "aws-ecr-repository-scanning-disabled",
    "aws-sns-customer-managed-encryption-missing",
    "aws-sqs-customer-managed-encryption-missing",
    "aws-sqs-message-retention-insufficient",
    "aws-sqs-dead-letter-queue-not-configured",
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
    "aws-sensitive-resource-policy-external-access",
    "aws-service-resource-policy-external-access",
    "aws-iam-wildcard-permissions",
    "aws-iam-privileged-role-assignment",
    "aws-workload-role-sensitive-permissions",
    "aws-missing-tier-segmentation",
    "aws-private-data-transitive-exposure",
    "aws-control-plane-sensitive-workload-chain",
    "aws-role-trust-expansion",
    "aws-role-trust-missing-narrowing",
    "gcp-sensitive-resource-iam-external-access",
    "gcp-pubsub-public-access",
    "gcp-pubsub-topic-customer-managed-encryption-missing",
    "gcp-pubsub-message-retention-insufficient",
    "gcp-pubsub-subscription-dead-letter-policy-missing",
    "gcp-bigquery-public-access",
    "gcp-public-workload-sensitive-data-access",
    "gcp-cloud-sql-public-authorized-network",
    "gcp-cloud-sql-backup-disabled",
    "gcp-cloud-sql-public-ip-without-private-network",
    "gcp-cloud-sql-ssl-not-required",
    "gcp-cloud-sql-point-in-time-recovery-disabled",
    "gcp-cloud-sql-deletion-protection-disabled",
    "gcp-cloud-sql-zonal-availability",
    "gcp-cloud-sql-query-insights-disabled",
    "gcp-cloud-sql-connector-enforcement-not-required",
    "gcp-cloud-sql-private-connectivity-not-modeled",
    "gcp-private-workload-private-google-access-disabled",
    "gcp-gcs-public-access",
    "gcp-gcs-uniform-bucket-level-access-disabled",
    "gcp-gcs-public-access-prevention-not-enforced",
    "gcp-gcs-versioning-disabled",
    "gcp-gcs-customer-managed-encryption-missing",
    "gcp-gcs-retention-policy-insufficient",
    "gcp-artifact-registry-docker-tags-mutable",
    "gcp-artifact-registry-customer-managed-encryption-missing",
    "gcp-artifact-registry-vulnerability-scanning-disabled",
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
    "azure-public-compute-broad-ingress",
    "azure-load-balancer-public-frontend",
    "azure-application-gateway-public-listener",
    "azure-public-application-gateway-waf-missing",
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
    "azure-service-bus-public-network-access-not-disabled",
    "azure-service-bus-minimum-tls-below-1-2",
    "azure-service-bus-minimum-tls-unknown",
    "azure-service-bus-local-auth-enabled",
    "azure-service-bus-customer-managed-key-missing",
    "azure-service-bus-missing-private-endpoint",
    "azure-container-registry-public-network-access-not-disabled",
    "azure-container-registry-admin-account-enabled",
    "azure-container-registry-anonymous-pull-enabled",
    "azure-container-registry-customer-managed-key-missing",
    "azure-container-registry-missing-private-endpoint",
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
    "azure-app-service-platform-authentication-disabled",
    "azure-app-service-anonymous-platform-access-allowed",
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
)


def _flatten_rule_groups(rule_groups: tuple[tuple[str, ...], ...]) -> tuple[str, ...]:
    return tuple(rule_id for rule_group in rule_groups for rule_id in rule_group)


class RuleRegistryTests(unittest.TestCase):
    def test_import_does_not_load_provider_catalog(self) -> None:
        result = subprocess.run(
            [
                sys.executable,
                "-c",
                (
                    "import sys; "
                    "import tfstride.analysis.rule_registry; "
                    "assert 'tfstride.providers.catalog' not in sys.modules"
                ),
            ],
            check=False,
            capture_output=True,
            text=True,
        )

        self.assertEqual(result.returncode, 0, result.stderr)

    def test_eager_default_rule_singletons_are_not_exposed(self) -> None:
        self.assertFalse(hasattr(rule_registry_module, "DEFAULT_RULE_METADATA"))
        self.assertFalse(hasattr(rule_registry_module, "DEFAULT_RULE_METADATA_BY_ID"))
        self.assertFalse(hasattr(rule_registry_module, "DEFAULT_RULE_REGISTRY"))

    def test_default_registry_is_derived_from_shared_metadata(self) -> None:
        registry = default_rule_registry()

        self.assertEqual(
            registry.rules(),
            tuple(default_rule_metadata(rule_id) for rule_id in EXPECTED_DEFAULT_RULE_METADATA_IDS),
        )

    def test_default_rule_metadata_ids_match_locked_order(self) -> None:
        metadata = default_rule_registry().rules()

        self.assertEqual(
            tuple(item.rule_id for item in metadata),
            EXPECTED_DEFAULT_RULE_METADATA_IDS,
        )
        self.assertEqual(len(metadata), 229)

    def test_default_rule_metadata_is_partitioned_by_provider(self) -> None:
        metadata_ids = tuple(metadata.rule_id for metadata in default_rule_registry().rules())
        aws_metadata_ids = tuple(rule_id for rule_id in metadata_ids if rule_id.startswith("aws-"))
        gcp_metadata_ids = tuple(rule_id for rule_id in metadata_ids if rule_id.startswith("gcp-"))
        azure_metadata_ids = tuple(rule_id for rule_id in metadata_ids if rule_id.startswith("azure-"))

        self.assertEqual(metadata_ids, aws_metadata_ids + gcp_metadata_ids + azure_metadata_ids)
        self.assertEqual(len(aws_metadata_ids), 75)
        self.assertEqual(len(gcp_metadata_ids), 68)
        self.assertEqual(len(azure_metadata_ids), 86)
        self.assertEqual(set(aws_metadata_ids), set(_flatten_rule_groups(AWS_RULE_GROUP_IDS)))
        self.assertEqual(set(gcp_metadata_ids), set(_flatten_rule_groups(GCP_RULE_GROUP_IDS)))
        self.assertEqual(set(azure_metadata_ids), set(_flatten_rule_groups(AZURE_RULE_GROUP_IDS)))
        self.assertEqual(
            set(metadata_ids),
            set(aws_metadata_ids) | set(gcp_metadata_ids) | set(azure_metadata_ids),
        )

    def test_default_registry_rule_ids_match_configured_rules(self) -> None:
        self.assertEqual(default_rule_registry().known_rule_ids(), engine_configured_rule_ids(StrideRuleEngine()))

    def test_provider_rule_ids_have_default_metadata(self) -> None:
        registry = default_rule_registry()

        provider_rule_ids = (
            _flatten_rule_groups(AWS_RULE_GROUP_IDS)
            + _flatten_rule_groups(GCP_RULE_GROUP_IDS)
            + _flatten_rule_groups(AZURE_RULE_GROUP_IDS)
        )
        for rule_id in provider_rule_ids:
            self.assertIs(registry.get(rule_id), default_rule_metadata(rule_id))

    def test_default_registry_factory_returns_distinct_registries_from_cached_metadata(self) -> None:
        first_registry = default_rule_registry()
        second_registry = default_rule_registry()

        self.assertIsNot(first_registry, second_registry)
        self.assertEqual(first_registry.rules(), second_registry.rules())
        for first, second in zip(first_registry.rules(), second_registry.rules(), strict=True):
            self.assertIs(first, second)

    def test_default_rule_metadata_lookup_is_cached(self) -> None:
        first = default_rule_metadata("aws-s3-public-access")
        second = default_rule_metadata("aws-s3-public-access")

        self.assertIs(first, second)
        self.assertIs(first, default_rule_registry().get("aws-s3-public-access"))

    def test_rules_preserves_registry_order(self) -> None:
        first = RuleMetadata(
            rule_id="aws-first-rule",
            title="First rule",
            category=StrideCategory.SPOOFING,
            recommended_mitigation="Fix the first issue.",
        )
        second = RuleMetadata(
            rule_id="aws-second-rule",
            title="Second rule",
            category=StrideCategory.TAMPERING,
            recommended_mitigation="Fix the second issue.",
        )

        registry = RuleRegistry([first, second])

        self.assertEqual(registry.rules(), (first, second))


class SeverityOverridePolicyTests(unittest.TestCase):
    def test_rule_policy_defensively_freezes_severity_overrides(self) -> None:
        overrides = {"aws-test-rule": Severity.LOW}

        policy = RulePolicy(severity_overrides=overrides)
        overrides["aws-test-rule"] = Severity.HIGH

        self.assertEqual(policy.severity_overrides["aws-test-rule"], Severity.LOW)
        with self.assertRaises(TypeError):
            policy.severity_overrides["aws-other-rule"] = Severity.MEDIUM

    def test_apply_severity_overrides_updates_finding_and_preserves_computed_severity(self) -> None:
        finding = _finding(
            rule_id="aws-test-rule",
            severity=Severity.HIGH,
            severity_reasoning=SeverityReasoning(
                internet_exposure=2,
                privilege_breadth=1,
                data_sensitivity=1,
                lateral_movement=1,
                blast_radius=1,
                final_score=6,
                severity=Severity.HIGH,
            ),
        )

        adjusted = apply_severity_overrides(
            [finding],
            RulePolicy(severity_overrides={"aws-test-rule": Severity.LOW}),
        )

        self.assertEqual(len(adjusted), 1)
        self.assertEqual(adjusted[0].severity, Severity.LOW)
        self.assertIsNotNone(adjusted[0].severity_reasoning)
        self.assertEqual(adjusted[0].severity_reasoning.severity, Severity.LOW)
        self.assertEqual(adjusted[0].severity_reasoning.computed_severity, Severity.HIGH)

    def test_apply_severity_overrides_does_not_filter_disabled_rules(self) -> None:
        finding = _finding(rule_id="aws-test-rule", severity=Severity.MEDIUM)

        adjusted = apply_severity_overrides(
            [finding],
            RulePolicy(enabled_rule_ids=frozenset()),
        )

        self.assertEqual(adjusted, [finding])


def _finding(
    *,
    rule_id: str,
    severity: Severity,
    severity_reasoning: SeverityReasoning | None = None,
) -> Finding:
    return Finding(
        title="Test finding",
        category=StrideCategory.ELEVATION_OF_PRIVILEGE,
        severity=severity,
        affected_resources=["aws_resource.example"],
        trust_boundary_id=None,
        rationale="Test rationale.",
        recommended_mitigation="Test mitigation.",
        rule_id=rule_id,
        severity_reasoning=severity_reasoning,
    )


if __name__ == "__main__":
    unittest.main()
