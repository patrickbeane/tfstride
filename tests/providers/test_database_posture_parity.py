from __future__ import annotations

import unittest

from tests.providers.aws.test_aws_rds_rules import _db_instance as _aws_db_instance
from tests.providers.aws.test_aws_rds_rules import _safe_db_instance as _aws_safe_db_instance
from tests.providers.azure.test_azure_postgresql_rules import _firewall_rule as _azure_postgresql_firewall_rule
from tests.providers.azure.test_azure_postgresql_rules import _server as _azure_postgresql_server
from tests.providers.azure.test_azure_sql_rules import _firewall_rule as _azure_sql_firewall_rule
from tests.providers.azure.test_azure_sql_rules import _server as _azure_sql_server
from tests.providers.gcp.rule_support.data import _cloud_sql_instance as _gcp_cloud_sql_instance
from tfstride.analysis.rule_registry import RulePolicy
from tfstride.analysis.stride_rules import StrideRuleEngine
from tfstride.analysis.trust_boundaries import detect_trust_boundaries
from tfstride.models import TerraformResource
from tfstride.providers.aws.normalizer import AwsNormalizer
from tfstride.providers.aws.rules import AWS_RULE_GROUP_IDS
from tfstride.providers.azure.normalizer import AzureNormalizer
from tfstride.providers.azure.rules import AZURE_RULE_GROUP_IDS
from tfstride.providers.gcp.normalizer import GcpNormalizer
from tfstride.providers.gcp.rules import GCP_RULE_GROUP_IDS

AWS_DATABASE_RULE_IDS = frozenset(
    {
        "aws-rds-storage-encryption-disabled",
        "aws-rds-public-endpoint-enabled",
        "aws-rds-backup-retention-insufficient",
        "aws-rds-deletion-protection-disabled",
        "aws-rds-customer-managed-kms-key-missing",
    }
)
GCP_DATABASE_RULE_IDS = frozenset(
    {
        "gcp-cloud-sql-public-authorized-network",
        "gcp-cloud-sql-backup-disabled",
        "gcp-cloud-sql-public-ip-without-private-network",
        "gcp-cloud-sql-point-in-time-recovery-disabled",
        "gcp-cloud-sql-deletion-protection-disabled",
    }
)
AZURE_DATABASE_RULE_IDS = frozenset(
    {
        "azure-sql-public-network-access-enabled",
        "azure-sql-missing-private-endpoint",
        "azure-sql-firewall-broad-public-access",
        "azure-postgresql-public-network-access-enabled",
        "azure-postgresql-firewall-broad-public-access",
        "azure-postgresql-geo-backup-disabled",
    }
)
ALL_DATABASE_RULE_IDS = AWS_DATABASE_RULE_IDS | GCP_DATABASE_RULE_IDS | AZURE_DATABASE_RULE_IDS

DATABASE_CONCEPT_RULE_IDS = {
    "public_endpoint_or_network_access": {
        "aws": frozenset({"aws-rds-public-endpoint-enabled"}),
        "gcp": frozenset(
            {
                "gcp-cloud-sql-public-authorized-network",
                "gcp-cloud-sql-public-ip-without-private-network",
            }
        ),
        "azure": frozenset(
            {
                "azure-sql-public-network-access-enabled",
                "azure-sql-missing-private-endpoint",
                "azure-sql-firewall-broad-public-access",
                "azure-postgresql-public-network-access-enabled",
                "azure-postgresql-firewall-broad-public-access",
            }
        ),
    },
    "backup_pitr_or_recovery": {
        "aws": frozenset({"aws-rds-backup-retention-insufficient"}),
        "gcp": frozenset(
            {
                "gcp-cloud-sql-backup-disabled",
                "gcp-cloud-sql-point-in-time-recovery-disabled",
            }
        ),
        "azure": frozenset({"azure-postgresql-geo-backup-disabled"}),
    },
    "deletion_protection": {
        "aws": frozenset({"aws-rds-deletion-protection-disabled"}),
        "gcp": frozenset({"gcp-cloud-sql-deletion-protection-disabled"}),
    },
    "encryption_ownership": {
        "aws": frozenset(
            {
                "aws-rds-storage-encryption-disabled",
                "aws-rds-customer-managed-kms-key-missing",
            }
        ),
    },
}


def _flatten(rule_groups: tuple[tuple[str, ...], ...]) -> frozenset[str]:
    return frozenset(rule_id for rule_group in rule_groups for rule_id in rule_group)


def _evaluate_aws(resources: list[TerraformResource], rule_ids=ALL_DATABASE_RULE_IDS):
    inventory = AwsNormalizer().normalize(resources)
    return StrideRuleEngine().evaluate(
        inventory,
        detect_trust_boundaries(inventory),
        rule_policy=RulePolicy(enabled_rule_ids=frozenset(rule_ids)),
    )


def _evaluate_gcp(resources: list[TerraformResource], rule_ids=ALL_DATABASE_RULE_IDS):
    inventory = GcpNormalizer().normalize(resources)
    return StrideRuleEngine().evaluate(
        inventory,
        detect_trust_boundaries(inventory),
        rule_policy=RulePolicy(enabled_rule_ids=frozenset(rule_ids)),
    )


def _evaluate_azure(resources: list[TerraformResource], rule_ids=ALL_DATABASE_RULE_IDS):
    inventory = AzureNormalizer().normalize(resources)
    return StrideRuleEngine().evaluate(
        inventory,
        detect_trust_boundaries(inventory),
        rule_policy=RulePolicy(enabled_rule_ids=frozenset(rule_ids)),
    )


def _finding_ids(findings) -> frozenset[str]:
    return frozenset(finding.rule_id for finding in findings)


class DatabasePostureParityTests(unittest.TestCase):
    def test_provider_database_rule_families_are_registered(self) -> None:
        self.assertLessEqual(AWS_DATABASE_RULE_IDS, _flatten(AWS_RULE_GROUP_IDS))
        self.assertLessEqual(GCP_DATABASE_RULE_IDS, _flatten(GCP_RULE_GROUP_IDS))
        self.assertLessEqual(AZURE_DATABASE_RULE_IDS, _flatten(AZURE_RULE_GROUP_IDS))

    def test_unsafe_database_posture_findings_are_pinned_by_concept(self) -> None:
        aws_findings = _evaluate_aws(
            [
                _aws_db_instance(
                    name="unsafe",
                    publicly_accessible=True,
                    backup_retention_period=0,
                    deletion_protection=False,
                    storage_encrypted=False,
                ),
                _aws_db_instance(
                    name="encrypted_without_cmk",
                    publicly_accessible=False,
                    backup_retention_period=14,
                    deletion_protection=True,
                    storage_encrypted=True,
                ),
            ]
        )
        gcp_findings = _evaluate_gcp(
            [
                _gcp_cloud_sql_instance(
                    ipv4_enabled=True,
                    authorized_networks=[{"name": "anywhere", "value": "0.0.0.0/0"}],
                    backup_enabled=False,
                    pitr_enabled=False,
                    private_network=None,
                    deletion_protection=False,
                )
            ]
        ) + _evaluate_gcp(
            [
                _gcp_cloud_sql_instance(
                    ipv4_enabled=False,
                    backup_enabled=True,
                    pitr_enabled=False,
                    private_network="google_compute_network.main.id",
                )
            ]
        )
        azure_findings = _evaluate_azure(
            [
                _azure_sql_server(public_network=True),
                _azure_sql_firewall_rule(),
                _azure_postgresql_server(public_network=True, geo_backup=False),
                _azure_postgresql_firewall_rule(),
            ]
        )

        findings_by_provider = {
            "aws": _finding_ids(aws_findings),
            "gcp": _finding_ids(gcp_findings),
            "azure": _finding_ids(azure_findings),
        }
        self.assertEqual(findings_by_provider["aws"], AWS_DATABASE_RULE_IDS)
        self.assertEqual(findings_by_provider["gcp"], GCP_DATABASE_RULE_IDS)
        self.assertEqual(findings_by_provider["azure"], AZURE_DATABASE_RULE_IDS)
        for concept, provider_expectations in DATABASE_CONCEPT_RULE_IDS.items():
            for provider, expected_rule_ids in provider_expectations.items():
                with self.subTest(concept=concept, provider=provider):
                    self.assertLessEqual(expected_rule_ids, findings_by_provider[provider])

    def test_hardened_database_posture_stays_quiet_across_providers(self) -> None:
        aws_findings = _evaluate_aws([_aws_safe_db_instance()])
        gcp_findings = _evaluate_gcp(
            [
                _gcp_cloud_sql_instance(
                    ipv4_enabled=False,
                    authorized_networks=[],
                    backup_enabled=True,
                    pitr_enabled=True,
                    private_network="google_compute_network.main.id",
                    deletion_protection=True,
                )
            ]
        )
        azure_findings = _evaluate_azure(
            [
                _azure_sql_server(public_network=False),
                _azure_sql_firewall_rule(start_ip="198.51.100.10", end_ip="198.51.100.10"),
                _azure_postgresql_server(public_network=False, geo_backup=True),
                _azure_postgresql_firewall_rule(start_ip="198.51.100.10", end_ip="198.51.100.10"),
            ]
        )

        self.assertEqual(aws_findings, [])
        self.assertEqual(gcp_findings, [])
        self.assertEqual(azure_findings, [])

    def test_database_posture_rules_remain_provider_local(self) -> None:
        findings_by_provider = {
            "aws": _evaluate_aws(
                [
                    _aws_db_instance(
                        name="unsafe",
                        publicly_accessible=True,
                        backup_retention_period=0,
                        deletion_protection=False,
                        storage_encrypted=False,
                    ),
                    _aws_db_instance(name="encrypted_without_cmk", storage_encrypted=True),
                ]
            ),
            "gcp": _evaluate_gcp(
                [
                    _gcp_cloud_sql_instance(
                        ipv4_enabled=True,
                        authorized_networks=[{"name": "anywhere", "value": "0.0.0.0/0"}],
                        backup_enabled=False,
                        pitr_enabled=False,
                        deletion_protection=False,
                    )
                ]
            ),
            "azure": _evaluate_azure(
                [
                    _azure_sql_server(public_network=True),
                    _azure_sql_firewall_rule(),
                    _azure_postgresql_server(public_network=True, geo_backup=False),
                    _azure_postgresql_firewall_rule(),
                ]
            ),
        }

        for provider, findings in findings_by_provider.items():
            with self.subTest(provider=provider):
                self.assertTrue(findings)
                self.assertTrue(all(finding.rule_id.startswith(f"{provider}-") for finding in findings))


if __name__ == "__main__":
    unittest.main()
