from __future__ import annotations

import unittest

from tests.providers.aws.test_aws_sensitive_endpoint_rules import (
    _KMS_RULE as AWS_KMS_ENDPOINT_RULE,
)
from tests.providers.aws.test_aws_sensitive_endpoint_rules import (
    _S3_RULE as AWS_S3_ENDPOINT_RULE,
)
from tests.providers.aws.test_aws_sensitive_endpoint_rules import (
    _SECRETS_RULE as AWS_SECRETS_ENDPOINT_RULE,
)
from tests.providers.aws.test_aws_sensitive_endpoint_rules import (
    _findings as _aws_findings,
)
from tests.providers.aws.test_aws_sensitive_endpoint_rules import (
    _lambda_function as _aws_lambda_function,
)
from tests.providers.aws.test_aws_sensitive_endpoint_rules import (
    _role as _aws_role,
)
from tests.providers.aws.test_aws_sensitive_endpoint_rules import (
    _subnet as _aws_subnet,
)
from tests.providers.aws.test_aws_sensitive_endpoint_rules import (
    _vpc_endpoint as _aws_vpc_endpoint,
)
from tests.providers.azure.test_azure_private_endpoint_rules import (
    _KEY_VAULT_ID as AZURE_KEY_VAULT_ID,
)
from tests.providers.azure.test_azure_private_endpoint_rules import (
    _STORAGE_ID as AZURE_STORAGE_ID,
)
from tests.providers.azure.test_azure_private_endpoint_rules import (
    _evaluate as _azure_findings,
)
from tests.providers.azure.test_azure_private_endpoint_rules import (
    _key_vault as _azure_key_vault,
)
from tests.providers.azure.test_azure_private_endpoint_rules import (
    _private_endpoint as _azure_private_endpoint,
)
from tests.providers.azure.test_azure_private_endpoint_rules import (
    _storage_account as _azure_storage_account,
)
from tests.providers.gcp.test_gcp_private_connectivity_rules import (
    _RULE_ID as GCP_CLOUD_SQL_PRIVATE_CONNECTIVITY_RULE,
)
from tests.providers.gcp.test_gcp_private_connectivity_rules import (
    _cloud_sql as _gcp_cloud_sql,
)
from tests.providers.gcp.test_gcp_private_connectivity_rules import (
    _cloud_sql_psc_policy as _gcp_cloud_sql_psc_policy,
)
from tests.providers.gcp.test_gcp_private_connectivity_rules import (
    _evaluate as _gcp_findings,
)
from tests.providers.gcp.test_gcp_private_connectivity_rules import (
    _network as _gcp_network,
)
from tests.providers.gcp.test_gcp_private_connectivity_rules import (
    _service_networking_connection as _gcp_service_networking_connection,
)
from tfstride.providers.aws.rules import AWS_RULE_GROUP_IDS
from tfstride.providers.azure.rules import AZURE_RULE_GROUP_IDS
from tfstride.providers.gcp.rules import GCP_RULE_GROUP_IDS

AWS_PRIVATE_CONNECTIVITY_RULE_IDS = frozenset(
    {
        AWS_SECRETS_ENDPOINT_RULE,
        AWS_KMS_ENDPOINT_RULE,
        AWS_S3_ENDPOINT_RULE,
    }
)
AZURE_PRIVATE_CONNECTIVITY_RULE_IDS = frozenset(
    {
        "azure-storage-account-missing-private-endpoint",
        "azure-key-vault-missing-private-endpoint",
        "azure-sql-missing-private-endpoint",
        "azure-private-endpoint-public-fallback",
        "azure-private-endpoint-dns-posture-incomplete",
    }
)
GCP_PRIVATE_CONNECTIVITY_RULE_IDS = frozenset({GCP_CLOUD_SQL_PRIVATE_CONNECTIVITY_RULE})


def _flatten(rule_groups: tuple[tuple[str, ...], ...]) -> frozenset[str]:
    return frozenset(rule_id for rule_group in rule_groups for rule_id in rule_group)


def _rule_ids(findings) -> frozenset[str]:
    return frozenset(finding.rule_id for finding in findings)


class PrivateConnectivityPostureParityTests(unittest.TestCase):
    def test_private_connectivity_rule_families_are_registered(self) -> None:
        self.assertLessEqual(AWS_PRIVATE_CONNECTIVITY_RULE_IDS, _flatten(AWS_RULE_GROUP_IDS))
        self.assertLessEqual(AZURE_PRIVATE_CONNECTIVITY_RULE_IDS, _flatten(AZURE_RULE_GROUP_IDS))
        self.assertLessEqual(GCP_PRIVATE_CONNECTIVITY_RULE_IDS, _flatten(GCP_RULE_GROUP_IDS))

    def test_missing_private_connectivity_findings_are_pinned_by_provider(self) -> None:
        aws_findings = _aws_findings(
            [
                _aws_subnet(),
                _aws_lambda_function(),
                _aws_role(["secretsmanager:GetSecretValue", "kms:Decrypt", "s3:GetObject"]),
            ],
            *AWS_PRIVATE_CONNECTIVITY_RULE_IDS,
        )
        azure_findings = _azure_findings(
            [_azure_storage_account(public_network=True)],
            "azure-storage-account-missing-private-endpoint",
        )
        gcp_findings = _gcp_findings(_gcp_network(), _gcp_cloud_sql())

        self.assertEqual(
            _rule_ids(aws_findings),
            AWS_PRIVATE_CONNECTIVITY_RULE_IDS,
        )
        self.assertEqual(
            _rule_ids(azure_findings),
            frozenset({"azure-storage-account-missing-private-endpoint"}),
        )
        self.assertEqual(
            _rule_ids(gcp_findings),
            GCP_PRIVATE_CONNECTIVITY_RULE_IDS,
        )

    def test_provider_specific_private_connectivity_controls_suppress_findings(self) -> None:
        aws_findings = _aws_findings(
            [
                _aws_subnet(),
                _aws_lambda_function(),
                _aws_role(["secretsmanager:GetSecretValue", "kms:Decrypt", "s3:GetObject"]),
                _aws_vpc_endpoint("secrets", "com.amazonaws.us-east-1.secretsmanager"),
                _aws_vpc_endpoint("kms", "com.amazonaws.us-east-1.kms"),
                _aws_vpc_endpoint("s3", "com.amazonaws.us-east-1.s3", endpoint_type="Gateway"),
            ],
            *AWS_PRIVATE_CONNECTIVITY_RULE_IDS,
        )
        azure_findings = _azure_findings(
            [
                _azure_storage_account(public_network=False, default_action="Deny"),
                _azure_private_endpoint("logs_blob", AZURE_STORAGE_ID, subresources=("blob",)),
            ],
            "azure-storage-account-missing-private-endpoint",
            "azure-private-endpoint-public-fallback",
        )
        gcp_psa_findings = _gcp_findings(
            _gcp_network(),
            _gcp_service_networking_connection(),
            _gcp_cloud_sql(),
        )
        gcp_psc_findings = _gcp_findings(
            _gcp_network(),
            _gcp_cloud_sql_psc_policy(),
            _gcp_cloud_sql(),
        )

        self.assertEqual(aws_findings, [])
        self.assertEqual(azure_findings, [])
        self.assertEqual(gcp_psa_findings, [])
        self.assertEqual(gcp_psc_findings, [])

    def test_provider_specific_private_connectivity_semantics_are_preserved(self) -> None:
        aws_s3_findings = _aws_findings(
            [
                _aws_subnet(),
                _aws_lambda_function(),
                _aws_role(["s3:GetObject"]),
            ],
            AWS_S3_ENDPOINT_RULE,
        )
        azure_fallback_findings = _azure_findings(
            [
                _azure_key_vault(public_network=True),
                _azure_private_endpoint("vault", AZURE_KEY_VAULT_ID, subresources=("vault",)),
            ],
            "azure-private-endpoint-public-fallback",
        )
        gcp_no_private_network_findings = _gcp_findings(
            _gcp_network(),
            _gcp_cloud_sql(private_network=None),
        )

        self.assertEqual(_rule_ids(aws_s3_findings), frozenset({AWS_S3_ENDPOINT_RULE}))
        self.assertIn("does not imply the bucket itself is public", aws_s3_findings[0].rationale)
        self.assertEqual(_rule_ids(azure_fallback_findings), frozenset({"azure-private-endpoint-public-fallback"}))
        self.assertEqual(gcp_no_private_network_findings, [])


if __name__ == "__main__":
    unittest.main()
