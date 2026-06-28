from __future__ import annotations

import unittest

from tests.providers.aws.test_aws_storage_rules import (
    _bucket as _aws_bucket,
)
from tests.providers.aws.test_aws_storage_rules import (
    _encryption as _aws_encryption,
)
from tests.providers.aws.test_aws_storage_rules import (
    _findings as _aws_findings,
)
from tests.providers.aws.test_aws_storage_rules import (
    _versioning as _aws_versioning,
)
from tests.providers.azure.test_azure_storage_rules import (
    _account as _azure_storage_account,
)
from tests.providers.azure.test_azure_storage_rules import (
    _container as _azure_storage_container,
)
from tests.providers.azure.test_azure_storage_rules import (
    _evaluate as _azure_findings,
)
from tests.providers.azure.test_azure_storage_rules import (
    _storage_safe_posture as _azure_storage_safe_posture,
)
from tests.providers.gcp.rule_support.data import (
    _storage_bucket as _gcp_storage_bucket,
)
from tests.providers.gcp.rule_support.data import (
    _storage_bucket_iam_member as _gcp_storage_bucket_iam_member,
)
from tfstride.analysis.rule_registry import RulePolicy
from tfstride.analysis.stride_rules import StrideRuleEngine
from tfstride.providers.aws.rules import AWS_RULE_GROUP_IDS
from tfstride.providers.azure.rules import AZURE_RULE_GROUP_IDS
from tfstride.providers.gcp.normalizer import GcpNormalizer
from tfstride.providers.gcp.rules import GCP_RULE_GROUP_IDS

AWS_STORAGE_RULE_IDS = frozenset(
    {
        "aws-s3-public-access",
        "aws-s3-customer-managed-encryption-missing",
        "aws-s3-versioning-disabled",
    }
)
GCP_STORAGE_RULE_IDS = frozenset(
    {
        "gcp-gcs-public-access",
        "gcp-gcs-uniform-bucket-level-access-disabled",
        "gcp-gcs-public-access-prevention-not-enforced",
        "gcp-gcs-versioning-disabled",
        "gcp-gcs-customer-managed-encryption-missing",
        "gcp-gcs-retention-policy-insufficient",
    }
)
AZURE_STORAGE_RULE_IDS = frozenset(
    {
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
    }
)


def _flatten(rule_groups: tuple[tuple[str, ...], ...]) -> frozenset[str]:
    return frozenset(rule_id for rule_group in rule_groups for rule_id in rule_group)


def _gcp_findings(resources, rule_ids: frozenset[str]):
    inventory = GcpNormalizer().normalize(resources)
    return StrideRuleEngine().evaluate(
        inventory,
        [],
        rule_policy=RulePolicy(enabled_rule_ids=rule_ids),
    )


def _finding_ids(findings) -> frozenset[str]:
    return frozenset(finding.rule_id for finding in findings)


class StoragePostureParityTests(unittest.TestCase):
    def test_provider_storage_rule_families_are_registered(self) -> None:
        self.assertEqual(
            AWS_STORAGE_RULE_IDS,
            frozenset(rule_id for rule_id in _flatten(AWS_RULE_GROUP_IDS) if rule_id.startswith("aws-s3-")),
        )
        self.assertEqual(
            GCP_STORAGE_RULE_IDS,
            frozenset(rule_id for rule_id in _flatten(GCP_RULE_GROUP_IDS) if rule_id.startswith("gcp-gcs-")),
        )
        self.assertEqual(
            AZURE_STORAGE_RULE_IDS,
            frozenset(rule_id for rule_id in _flatten(AZURE_RULE_GROUP_IDS) if rule_id.startswith("azure-storage-")),
        )

    def test_unsafe_storage_posture_exercises_each_provider_family(self) -> None:
        aws_findings = _aws_findings(
            [
                _aws_bucket(acl="public-read"),
                _aws_encryption(algorithm="AES256"),
                _aws_versioning("Suspended"),
            ],
            set(AWS_STORAGE_RULE_IDS),
        )
        gcp_findings = _gcp_findings(
            [
                _gcp_storage_bucket(
                    public_access_prevention="inherited",
                    uniform_bucket_level_access=False,
                    versioning_enabled=False,
                    default_kms_key_name=None,
                ),
                _gcp_storage_bucket_iam_member(),
            ],
            GCP_STORAGE_RULE_IDS,
        )
        _, _, azure_findings = _azure_findings(
            [
                _azure_storage_account(
                    allow_public=True,
                    shared_key=True,
                    min_tls="TLS1_1",
                    public_network=True,
                    infrastructure_encryption=False,
                    blob_versioning=False,
                ),
                _azure_storage_container("blob"),
            ],
            *AZURE_STORAGE_RULE_IDS,
        )

        self.assertEqual(_finding_ids(aws_findings), AWS_STORAGE_RULE_IDS)
        self.assertEqual(_finding_ids(gcp_findings), GCP_STORAGE_RULE_IDS)
        self.assertEqual(_finding_ids(azure_findings), AZURE_STORAGE_RULE_IDS)

    def test_hardened_storage_posture_stays_quiet_across_providers(self) -> None:
        aws_findings = _aws_findings(
            [
                _aws_bucket(),
                _aws_encryption(
                    algorithm="aws:kms",
                    kms_master_key_id="arn:aws:kms:us-east-1:111122223333:key/storage",
                ),
                _aws_versioning("Enabled"),
            ],
            set(AWS_STORAGE_RULE_IDS),
        )
        gcp_findings = _gcp_findings(
            [
                _gcp_storage_bucket(
                    public_access_prevention="enforced",
                    uniform_bucket_level_access=True,
                    versioning_enabled=True,
                    retention_policy={"retention_period": 2_592_000, "is_locked": True},
                )
            ],
            GCP_STORAGE_RULE_IDS,
        )
        _, _, azure_findings = _azure_findings(
            [
                _azure_storage_account(
                    allow_public=False,
                    shared_key=False,
                    min_tls="TLS1_2",
                    public_network=False,
                    default_action="Deny",
                    **_azure_storage_safe_posture(),
                ),
                _azure_storage_container("private"),
            ],
            *AZURE_STORAGE_RULE_IDS,
        )

        self.assertEqual(aws_findings, [])
        self.assertEqual(gcp_findings, [])
        self.assertEqual(azure_findings, [])


if __name__ == "__main__":
    unittest.main()
