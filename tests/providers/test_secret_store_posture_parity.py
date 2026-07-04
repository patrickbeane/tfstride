from __future__ import annotations

import unittest

from tests.providers.aws.test_aws_secrets_rules import _findings as _aws_findings
from tests.providers.aws.test_aws_secrets_rules import _rotation as _aws_rotation
from tests.providers.aws.test_aws_secrets_rules import _safe_secret as _aws_safe_secret
from tests.providers.aws.test_aws_secrets_rules import _secret as _aws_secret
from tests.providers.azure.test_azure_key_vault_rules import _certificate as _azure_certificate
from tests.providers.azure.test_azure_key_vault_rules import _evaluate as _azure_findings
from tests.providers.azure.test_azure_key_vault_rules import _secret as _azure_secret
from tests.providers.azure.test_azure_key_vault_rules import _vault as _azure_vault
from tests.providers.gcp.test_gcp_secret_manager_rules import _CMEK_KEY as _GCP_CMEK_KEY
from tests.providers.gcp.test_gcp_secret_manager_rules import _findings as _gcp_findings
from tests.providers.gcp.test_gcp_secret_manager_rules import _secret as _gcp_secret
from tfstride.providers.aws.rules import AWS_RULE_GROUP_IDS
from tfstride.providers.azure.rules import AZURE_RULE_GROUP_IDS
from tfstride.providers.gcp.rules import GCP_RULE_GROUP_IDS

AWS_SECRET_STORE_RULE_IDS = frozenset(
    {
        "aws-secretsmanager-customer-managed-kms-key-missing",
        "aws-secretsmanager-recovery-window-too-short",
        "aws-secretsmanager-rotation-not-configured-or-too-long",
    }
)
GCP_SECRET_STORE_RULE_IDS = frozenset(
    {
        "gcp-secret-manager-customer-managed-encryption-missing",
        "gcp-secret-manager-lifecycle-posture-incomplete",
    }
)
AZURE_SECRET_STORE_RULE_IDS = frozenset(
    {
        "azure-key-vault-purge-protection-disabled",
        "azure-key-vault-secret-certificate-lifecycle-incomplete",
    }
)
ALL_SECRET_STORE_RULE_IDS = AWS_SECRET_STORE_RULE_IDS | GCP_SECRET_STORE_RULE_IDS | AZURE_SECRET_STORE_RULE_IDS

SECRET_STORE_CONCEPT_RULE_IDS = {
    "customer_managed_encryption_or_key_ownership": {
        "aws": frozenset({"aws-secretsmanager-customer-managed-kms-key-missing"}),
        "gcp": frozenset({"gcp-secret-manager-customer-managed-encryption-missing"}),
    },
    "recovery_or_delete_protection": {
        "aws": frozenset({"aws-secretsmanager-recovery-window-too-short"}),
        "azure": frozenset({"azure-key-vault-purge-protection-disabled"}),
    },
    "rotation_expiry_or_lifecycle": {
        "aws": frozenset({"aws-secretsmanager-rotation-not-configured-or-too-long"}),
        "gcp": frozenset({"gcp-secret-manager-lifecycle-posture-incomplete"}),
        "azure": frozenset({"azure-key-vault-secret-certificate-lifecycle-incomplete"}),
    },
}


def _flatten(rule_groups: tuple[tuple[str, ...], ...]) -> frozenset[str]:
    return frozenset(rule_id for rule_group in rule_groups for rule_id in rule_group)


def _finding_ids(findings) -> frozenset[str]:
    return frozenset(finding.rule_id for finding in findings)


class SecretStorePostureParityTests(unittest.TestCase):
    def test_provider_secret_store_rule_families_are_registered(self) -> None:
        self.assertLessEqual(AWS_SECRET_STORE_RULE_IDS, _flatten(AWS_RULE_GROUP_IDS))
        self.assertLessEqual(GCP_SECRET_STORE_RULE_IDS, _flatten(GCP_RULE_GROUP_IDS))
        self.assertLessEqual(AZURE_SECRET_STORE_RULE_IDS, _flatten(AZURE_RULE_GROUP_IDS))

    def test_unsafe_secret_store_posture_findings_are_pinned_by_concept(self) -> None:
        aws_findings = _aws_findings(
            [_aws_secret(kms_key_id=None, recovery_window_in_days=0)],
            *AWS_SECRET_STORE_RULE_IDS,
        )
        gcp_findings = _gcp_findings(
            [_gcp_secret()],
            *GCP_SECRET_STORE_RULE_IDS,
        )
        _, _, azure_findings = _azure_findings(
            [
                _azure_vault(public_network=False, purge_protection=False),
                _azure_secret(),
                _azure_certificate(),
            ],
            *AZURE_SECRET_STORE_RULE_IDS,
        )

        findings_by_provider = {
            "aws": _finding_ids(aws_findings),
            "gcp": _finding_ids(gcp_findings),
            "azure": _finding_ids(azure_findings),
        }
        self.assertEqual(findings_by_provider["aws"], AWS_SECRET_STORE_RULE_IDS)
        self.assertEqual(findings_by_provider["gcp"], GCP_SECRET_STORE_RULE_IDS)
        self.assertEqual(findings_by_provider["azure"], AZURE_SECRET_STORE_RULE_IDS)
        for concept, provider_expectations in SECRET_STORE_CONCEPT_RULE_IDS.items():
            for provider, expected_rule_ids in provider_expectations.items():
                with self.subTest(concept=concept, provider=provider):
                    self.assertLessEqual(expected_rule_ids, findings_by_provider[provider])

    def test_hardened_secret_store_posture_stays_quiet_across_providers(self) -> None:
        aws_findings = _aws_findings(
            [_aws_safe_secret(name="app"), _aws_rotation(name="app", automatically_after_days=30)],
            *AWS_SECRET_STORE_RULE_IDS,
        )
        gcp_findings = _gcp_findings(
            [
                _gcp_secret(
                    replication=[
                        {
                            "auto": [
                                {
                                    "customer_managed_encryption": [
                                        {"kms_key_name": _GCP_CMEK_KEY},
                                    ]
                                }
                            ]
                        }
                    ],
                    ttl="2592000s",
                    version_destroy_ttl="604800s",
                )
            ],
            *GCP_SECRET_STORE_RULE_IDS,
        )
        _, _, azure_findings = _azure_findings(
            [
                _azure_vault(public_network=False, purge_protection=True),
                _azure_secret(
                    not_before_date="2026-01-01T00:00:00Z",
                    expiration_date="2026-12-31T00:00:00Z",
                ),
                _azure_certificate(validity_months=12),
            ],
            *AZURE_SECRET_STORE_RULE_IDS,
        )

        self.assertEqual(aws_findings, [])
        self.assertEqual(gcp_findings, [])
        self.assertEqual(azure_findings, [])

    def test_secret_store_posture_rules_remain_provider_local(self) -> None:
        findings_by_provider = {
            "aws": _aws_findings(
                [_aws_secret(kms_key_id=None, recovery_window_in_days=0)],
                *ALL_SECRET_STORE_RULE_IDS,
            ),
            "gcp": _gcp_findings([_gcp_secret()], *ALL_SECRET_STORE_RULE_IDS),
            "azure": _azure_findings(
                [_azure_vault(public_network=False, purge_protection=False), _azure_secret()],
                *ALL_SECRET_STORE_RULE_IDS,
            )[2],
        }

        for provider, findings in findings_by_provider.items():
            with self.subTest(provider=provider):
                self.assertTrue(findings)
                self.assertTrue(all(finding.rule_id.startswith(f"{provider}-") for finding in findings))


if __name__ == "__main__":
    unittest.main()
