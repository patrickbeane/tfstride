from __future__ import annotations

import unittest
from collections import Counter

from tests.providers.aws.test_aws_ecr_rules import _evaluate as _aws_findings
from tests.providers.aws.test_aws_ecr_rules import _repository as _aws_repository
from tests.providers.azure.test_azure_container_registry_rules import _evaluate as _azure_findings
from tests.providers.azure.test_azure_container_registry_rules import _private_endpoint as _azure_private_endpoint
from tests.providers.azure.test_azure_container_registry_rules import _registry as _azure_registry
from tests.providers.gcp.test_gcp_artifact_registry_rules import _evaluate as _gcp_findings
from tests.providers.gcp.test_gcp_artifact_registry_rules import _repository as _gcp_repository
from tfstride.models import Finding
from tfstride.providers.aws.rules import AWS_RULE_GROUP_IDS
from tfstride.providers.azure.rules import AZURE_RULE_GROUP_IDS
from tfstride.providers.gcp.rules import GCP_RULE_GROUP_IDS

AWS_CONTAINER_REGISTRY_RULE_IDS = frozenset(
    {
        "aws-ecr-image-tag-mutability-enabled",
        "aws-ecr-customer-managed-encryption-missing",
        "aws-ecr-repository-scanning-disabled",
    }
)
GCP_CONTAINER_REGISTRY_RULE_IDS = frozenset(
    {
        "gcp-artifact-registry-docker-tags-mutable",
        "gcp-artifact-registry-customer-managed-encryption-missing",
        "gcp-artifact-registry-vulnerability-scanning-disabled",
    }
)
AZURE_CONTAINER_REGISTRY_RULE_IDS = frozenset(
    {
        "azure-container-registry-public-network-access-not-disabled",
        "azure-container-registry-admin-account-enabled",
        "azure-container-registry-anonymous-pull-enabled",
        "azure-container-registry-customer-managed-key-missing",
        "azure-container-registry-missing-private-endpoint",
    }
)
AZURE_PRIVATE_ENDPOINT_RULE_IDS = frozenset(
    {
        "azure-private-endpoint-public-fallback",
        "azure-private-endpoint-dns-posture-incomplete",
    }
)
AZURE_CONTAINER_REGISTRY_POSTURE_RULE_IDS = AZURE_CONTAINER_REGISTRY_RULE_IDS | AZURE_PRIVATE_ENDPOINT_RULE_IDS
ALL_CONTAINER_REGISTRY_RULE_IDS = (
    AWS_CONTAINER_REGISTRY_RULE_IDS | GCP_CONTAINER_REGISTRY_RULE_IDS | AZURE_CONTAINER_REGISTRY_POSTURE_RULE_IDS
)

_AWS_KMS_KEY_ARN = "arn:aws:kms:us-east-1:111122223333:key/ecr"
_GCP_KMS_KEY = "projects/tfstride-demo/locations/us-central1/keyRings/app/cryptoKeys/images"
_AZURE_KMS_KEY = "azurerm_key_vault_key.registry.id"


def _flatten(rule_groups: tuple[tuple[str, ...], ...]) -> frozenset[str]:
    return frozenset(rule_id for rule_group in rule_groups for rule_id in rule_group)


def _registered_with_prefix(
    rule_groups: tuple[tuple[str, ...], ...],
    prefix: str,
) -> frozenset[str]:
    return frozenset(rule_id for rule_id in _flatten(rule_groups) if rule_id.startswith(prefix))


def _rule_ids(findings: list[Finding]) -> frozenset[str]:
    return frozenset(finding.rule_id for finding in findings)


def _rule_counts(findings: list[Finding]) -> Counter[str]:
    return Counter(finding.rule_id for finding in findings)


def _unsafe_aws_findings(*rule_ids: str) -> list[Finding]:
    return _aws_findings(
        [
            _aws_repository(
                encryption_configuration=[{"encryption_type": "AES256"}],
                image_tag_mutability="MUTABLE",
                scan_on_push=False,
            )
        ],
        *rule_ids,
    )


def _unsafe_gcp_findings(*rule_ids: str) -> list[Finding]:
    return _gcp_findings(
        [
            _gcp_repository(
                format="DOCKER",
                docker_config=[{"immutable_tags": False}],
                vulnerability_scanning_config=[{"enablement_config": "DISABLED"}],
            )
        ],
        *rule_ids,
    )


def _unsafe_azure_findings(*rule_ids: str) -> list[Finding]:
    return _azure_findings(
        [
            _azure_registry(
                public_network_access_enabled=True,
                default_action="Allow",
                admin_enabled=True,
                anonymous_pull_enabled=True,
            )
        ],
        *rule_ids,
    )


class ContainerRegistryPostureParityTests(unittest.TestCase):
    def test_container_registry_rule_families_are_registered(self) -> None:
        self.assertEqual(
            _registered_with_prefix(AWS_RULE_GROUP_IDS, "aws-ecr-"),
            AWS_CONTAINER_REGISTRY_RULE_IDS,
        )
        self.assertEqual(
            _registered_with_prefix(GCP_RULE_GROUP_IDS, "gcp-artifact-registry-"),
            GCP_CONTAINER_REGISTRY_RULE_IDS,
        )
        self.assertEqual(
            _registered_with_prefix(AZURE_RULE_GROUP_IDS, "azure-container-registry-"),
            AZURE_CONTAINER_REGISTRY_RULE_IDS,
        )
        self.assertLessEqual(AZURE_PRIVATE_ENDPOINT_RULE_IDS, _flatten(AZURE_RULE_GROUP_IDS))

    def test_unsafe_provider_local_container_registry_concepts_are_pinned(self) -> None:
        self.assertEqual(
            _rule_counts(_unsafe_aws_findings(*AWS_CONTAINER_REGISTRY_RULE_IDS)),
            Counter({rule_id: 1 for rule_id in AWS_CONTAINER_REGISTRY_RULE_IDS}),
        )
        self.assertEqual(
            _rule_counts(_unsafe_gcp_findings(*GCP_CONTAINER_REGISTRY_RULE_IDS)),
            Counter({rule_id: 1 for rule_id in GCP_CONTAINER_REGISTRY_RULE_IDS}),
        )
        self.assertEqual(
            _rule_counts(_unsafe_azure_findings(*AZURE_CONTAINER_REGISTRY_RULE_IDS)),
            Counter({rule_id: 1 for rule_id in AZURE_CONTAINER_REGISTRY_RULE_IDS}),
        )

    def test_customer_managed_encryption_ownership_is_pinned_across_providers(self) -> None:
        aws_findings = _aws_findings(
            [_aws_repository(encryption_configuration=[{"encryption_type": "AES256"}])],
            "aws-ecr-customer-managed-encryption-missing",
        )
        gcp_findings = _gcp_findings(
            [_gcp_repository(format="DOCKER")],
            "gcp-artifact-registry-customer-managed-encryption-missing",
        )
        azure_findings = _azure_findings(
            [_azure_registry()],
            "azure-container-registry-customer-managed-key-missing",
        )

        self.assertEqual(_rule_ids(aws_findings), {"aws-ecr-customer-managed-encryption-missing"})
        self.assertEqual(_rule_ids(gcp_findings), {"gcp-artifact-registry-customer-managed-encryption-missing"})
        self.assertEqual(_rule_ids(azure_findings), {"azure-container-registry-customer-managed-key-missing"})
        for finding in [*aws_findings, *gcp_findings, *azure_findings]:
            rationale = finding.rationale.lower()
            if "unencrypted" in rationale:
                self.assertIn("does not claim", rationale)

    def test_hardened_container_registry_posture_is_quiet(self) -> None:
        aws_findings = _aws_findings(
            [
                _aws_repository(
                    encryption_configuration=[{"encryption_type": "KMS", "kms_key": _AWS_KMS_KEY_ARN}],
                    image_tag_mutability="IMMUTABLE",
                    scan_on_push=True,
                )
            ],
            *AWS_CONTAINER_REGISTRY_RULE_IDS,
        )
        gcp_findings = _gcp_findings(
            [
                _gcp_repository(
                    format="DOCKER",
                    kms_key_name=_GCP_KMS_KEY,
                    docker_config=[{"immutable_tags": True}],
                    vulnerability_scanning_config=[{"enablement_config": "INHERITED", "enablement_state": "SCANNING"}],
                )
            ],
            *GCP_CONTAINER_REGISTRY_RULE_IDS,
        )
        azure_findings = _azure_findings(
            [_azure_registry(cmk_key_id=_AZURE_KMS_KEY), _azure_private_endpoint()],
            *AZURE_CONTAINER_REGISTRY_POSTURE_RULE_IDS,
        )

        self.assertEqual(aws_findings, [])
        self.assertEqual(gcp_findings, [])
        self.assertEqual(azure_findings, [])

    def test_unknown_values_do_not_become_explicit_registry_access_claims(self) -> None:
        aws_findings = _aws_findings(
            [
                _aws_repository(
                    image_tag_mutability="MUTABLE",
                    scan_on_push=False,
                    unknown_values={
                        "encryption_configuration": True,
                        "image_tag_mutability": True,
                        "image_scanning_configuration": True,
                    },
                )
            ],
            *AWS_CONTAINER_REGISTRY_RULE_IDS,
        )
        gcp_findings = _gcp_findings(
            [
                _gcp_repository(
                    format="DOCKER",
                    docker_config=[{"immutable_tags": False}],
                    vulnerability_scanning_config=[{"enablement_config": "DISABLED"}],
                    unknown_values={
                        "kms_key_name": True,
                        "docker_config": True,
                        "vulnerability_scanning_config": True,
                    },
                )
            ],
            *GCP_CONTAINER_REGISTRY_RULE_IDS,
        )
        azure_findings = _azure_findings(
            [
                _azure_registry(
                    public_network_access_enabled=None,
                    default_action=None,
                    admin_enabled=None,
                    anonymous_pull_enabled=None,
                    unknown_values={
                        "public_network_access_enabled": True,
                        "admin_enabled": True,
                        "anonymous_pull_enabled": True,
                        "encryption": True,
                    },
                )
            ],
            *AZURE_CONTAINER_REGISTRY_RULE_IDS,
        )

        self.assertEqual(aws_findings, [])
        self.assertEqual(gcp_findings, [])
        self.assertEqual(
            _rule_ids(azure_findings),
            {
                "azure-container-registry-public-network-access-not-disabled",
                "azure-container-registry-customer-managed-key-missing",
                "azure-container-registry-missing-private-endpoint",
            },
        )
        self.assertNotIn("azure-container-registry-admin-account-enabled", _rule_ids(azure_findings))
        self.assertNotIn("azure-container-registry-anonymous-pull-enabled", _rule_ids(azure_findings))
        evidence_values = [value for finding in azure_findings for item in finding.evidence for value in item.values]
        self.assertIn("public_network_access_enabled is unknown after planning", evidence_values)
        self.assertNotIn("admin_enabled is true", evidence_values)
        self.assertNotIn("anonymous_pull_enabled is true", evidence_values)

    def test_provider_specific_controls_are_preserved_without_forced_analogs(self) -> None:
        aws_registered = _registered_with_prefix(AWS_RULE_GROUP_IDS, "aws-ecr-")
        gcp_registered = _registered_with_prefix(GCP_RULE_GROUP_IDS, "gcp-artifact-registry-")
        azure_registered = _registered_with_prefix(AZURE_RULE_GROUP_IDS, "azure-container-registry-")

        self.assertIn("aws-ecr-image-tag-mutability-enabled", aws_registered)
        self.assertIn("aws-ecr-repository-scanning-disabled", aws_registered)
        self.assertIn("gcp-artifact-registry-docker-tags-mutable", gcp_registered)
        self.assertIn("gcp-artifact-registry-vulnerability-scanning-disabled", gcp_registered)
        self.assertIn("azure-container-registry-admin-account-enabled", azure_registered)
        self.assertIn("azure-container-registry-anonymous-pull-enabled", azure_registered)
        self.assertIn("azure-container-registry-missing-private-endpoint", azure_registered)
        self.assertFalse(any("immutable" in rule_id or "scanning" in rule_id for rule_id in azure_registered))
        self.assertFalse(any("private-endpoint" in rule_id for rule_id in aws_registered))
        self.assertFalse(any("private-endpoint" in rule_id for rule_id in gcp_registered))

    def test_container_registry_findings_do_not_leak_across_provider_inventories(self) -> None:
        aws_findings = _unsafe_aws_findings(*ALL_CONTAINER_REGISTRY_RULE_IDS)
        gcp_findings = _unsafe_gcp_findings(*ALL_CONTAINER_REGISTRY_RULE_IDS)
        azure_findings = _unsafe_azure_findings(*ALL_CONTAINER_REGISTRY_RULE_IDS)

        self.assertLessEqual(_rule_ids(aws_findings), AWS_CONTAINER_REGISTRY_RULE_IDS)
        self.assertLessEqual(_rule_ids(gcp_findings), GCP_CONTAINER_REGISTRY_RULE_IDS)
        self.assertLessEqual(_rule_ids(azure_findings), AZURE_CONTAINER_REGISTRY_POSTURE_RULE_IDS)
        self.assertTrue(all(finding.rule_id.startswith("aws-") for finding in aws_findings))
        self.assertTrue(all(finding.rule_id.startswith("gcp-") for finding in gcp_findings))
        self.assertTrue(all(finding.rule_id.startswith("azure-") for finding in azure_findings))


if __name__ == "__main__":
    unittest.main()
