from __future__ import annotations

from tests.providers.gcp.normalizer_support import GcpNormalizerTestCase, _terraform_resource
from tfstride.providers.coercion import (
    STATE_CONFIGURED,
    STATE_DISABLED,
    STATE_ENABLED,
    STATE_NOT_CONFIGURED,
    STATE_UNKNOWN,
)
from tfstride.providers.gcp.artifact_registry_normalizers import normalize_artifact_registry_repository
from tfstride.providers.gcp.normalizer import SUPPORTED_GCP_TYPES, GcpNormalizer
from tfstride.providers.gcp.resource_facts import gcp_facts
from tfstride.providers.gcp.resource_types import GcpResourceType


class GcpArtifactRegistryNormalizerTests(GcpNormalizerTestCase):
    def test_repository_normalizes_docker_cmek_scanning_and_cleanup_posture(self) -> None:
        normalized = normalize_artifact_registry_repository(
            _terraform_resource(
                "google_artifact_registry_repository.images",
                GcpResourceType.ARTIFACT_REGISTRY_REPOSITORY,
                {
                    "id": "projects/tfstride-demo/locations/us-central1/repositories/images",
                    "name": "projects/tfstride-demo/locations/us-central1/repositories/images",
                    "project": "tfstride-demo",
                    "location": "us-central1",
                    "repository_id": "images",
                    "format": "DOCKER",
                    "mode": "STANDARD_REPOSITORY",
                    "kms_key_name": "projects/tfstride-demo/locations/us-central1/keyRings/app/cryptoKeys/images",
                    "docker_config": [{"immutable_tags": True}],
                    "vulnerability_scanning_config": [
                        {
                            "enablement_config": "INHERITED",
                            "enablement_state": "SCANNING",
                            "enablement_state_reason": "Inherited from project policy",
                        }
                    ],
                    "cleanup_policies": [
                        {
                            "id": "delete-untagged",
                            "action": "DELETE",
                            "condition": [{"tag_state": "UNTAGGED", "older_than": "2592000s"}],
                        }
                    ],
                    "cleanup_policy_dry_run": False,
                    "deletion_policy": "PREVENT",
                    "labels": {"environment": "prod"},
                },
            )
        )
        facts = gcp_facts(normalized)

        self.assertEqual(normalized.identifier, "projects/tfstride-demo/locations/us-central1/repositories/images")
        self.assertTrue(normalized.storage_encrypted)
        self.assertEqual(facts.project, "tfstride-demo")
        self.assertEqual(facts.artifact_registry_repository_id, "images")
        self.assertEqual(facts.artifact_registry_format, "DOCKER")
        self.assertEqual(facts.artifact_registry_mode, "STANDARD_REPOSITORY")
        self.assertEqual(
            facts.artifact_registry_kms_key_name,
            "projects/tfstride-demo/locations/us-central1/keyRings/app/cryptoKeys/images",
        )
        self.assertEqual(facts.artifact_registry_encryption_state, STATE_CONFIGURED)
        self.assertEqual(facts.artifact_registry_docker_immutable_tags_state, STATE_ENABLED)
        self.assertTrue(facts.artifact_registry_docker_immutable_tags)
        self.assertEqual(facts.artifact_registry_docker_config, {"immutable_tags": True})
        self.assertEqual(
            facts.artifact_registry_vulnerability_scanning_enablement_config,
            "INHERITED",
        )
        self.assertEqual(facts.artifact_registry_vulnerability_scanning_enablement_state, "SCANNING")
        self.assertEqual(facts.artifact_registry_vulnerability_scanning_state, STATE_ENABLED)
        self.assertEqual(
            facts.artifact_registry_vulnerability_scanning_state_reason,
            "Inherited from project policy",
        )
        self.assertEqual(
            facts.artifact_registry_cleanup_policies,
            [
                {
                    "id": "delete-untagged",
                    "action": "DELETE",
                    "condition": [{"tag_state": "UNTAGGED", "older_than": "2592000s"}],
                }
            ],
        )
        self.assertEqual(facts.artifact_registry_cleanup_policy_state, STATE_CONFIGURED)
        self.assertEqual(facts.artifact_registry_cleanup_policy_dry_run_state, STATE_DISABLED)
        self.assertFalse(facts.artifact_registry_cleanup_policy_dry_run)
        self.assertEqual(facts.artifact_registry_deletion_policy, "PREVENT")
        self.assertEqual(facts.artifact_registry_deletion_policy_state, STATE_CONFIGURED)
        self.assertEqual(facts.artifact_registry_posture_uncertainties, [])

    def test_non_docker_repository_preserves_applicability_and_explicit_scanning_state(self) -> None:
        facts = gcp_facts(
            normalize_artifact_registry_repository(
                _terraform_resource(
                    "google_artifact_registry_repository.maven",
                    GcpResourceType.ARTIFACT_REGISTRY_REPOSITORY,
                    {
                        "repository_id": "maven",
                        "format": "MAVEN",
                        "mode": "STANDARD_REPOSITORY",
                        "vulnerability_scanning_config": [{"enablement_config": "DISABLED"}],
                        "cleanup_policies": [],
                        "cleanup_policy_dry_run": True,
                        "deletion_policy": "DELETE",
                    },
                )
            )
        )

        self.assertEqual(facts.artifact_registry_encryption_state, STATE_NOT_CONFIGURED)
        self.assertEqual(facts.artifact_registry_docker_immutable_tags_state, "not_applicable")
        self.assertIsNone(facts.artifact_registry_docker_immutable_tags)
        self.assertEqual(facts.artifact_registry_vulnerability_scanning_state, STATE_DISABLED)
        self.assertEqual(facts.artifact_registry_cleanup_policy_state, STATE_NOT_CONFIGURED)
        self.assertEqual(facts.artifact_registry_cleanup_policy_dry_run_state, STATE_ENABLED)
        self.assertTrue(facts.artifact_registry_cleanup_policy_dry_run)
        self.assertEqual(facts.artifact_registry_deletion_policy_state, STATE_CONFIGURED)
        self.assertEqual(facts.artifact_registry_posture_uncertainties, [])

    def test_minimal_repository_keeps_optional_posture_explicit(self) -> None:
        facts = gcp_facts(
            normalize_artifact_registry_repository(
                _terraform_resource(
                    "google_artifact_registry_repository.minimal",
                    GcpResourceType.ARTIFACT_REGISTRY_REPOSITORY,
                    {"repository_id": "minimal"},
                )
            )
        )

        self.assertEqual(facts.artifact_registry_encryption_state, STATE_NOT_CONFIGURED)
        self.assertEqual(facts.artifact_registry_docker_immutable_tags_state, STATE_UNKNOWN)
        self.assertEqual(facts.artifact_registry_vulnerability_scanning_state, STATE_NOT_CONFIGURED)
        self.assertEqual(facts.artifact_registry_cleanup_policy_state, STATE_NOT_CONFIGURED)
        self.assertEqual(facts.artifact_registry_cleanup_policy_dry_run_state, STATE_NOT_CONFIGURED)
        self.assertEqual(facts.artifact_registry_deletion_policy_state, STATE_NOT_CONFIGURED)
        self.assertEqual(facts.artifact_registry_posture_uncertainties, [])

    def test_unknown_repository_posture_is_preserved_as_uncertainty(self) -> None:
        facts = gcp_facts(
            normalize_artifact_registry_repository(
                _terraform_resource(
                    "google_artifact_registry_repository.unknown",
                    GcpResourceType.ARTIFACT_REGISTRY_REPOSITORY,
                    {
                        "repository_id": "unknown",
                        "format": "DOCKER",
                        "kms_key_name": "projects/tfstride-demo/locations/us-central1/keyRings/app/cryptoKeys/images",
                        "docker_config": [{"immutable_tags": True}],
                        "vulnerability_scanning_config": [{"enablement_config": "INHERITED"}],
                        "cleanup_policies": [{"id": "cleanup", "action": "DELETE"}],
                        "cleanup_policy_dry_run": False,
                        "deletion_policy": "PREVENT",
                    },
                    unknown_values={
                        "kms_key_name": True,
                        "docker_config": True,
                        "vulnerability_scanning_config": True,
                        "cleanup_policies": True,
                        "cleanup_policy_dry_run": True,
                        "deletion_policy": True,
                    },
                )
            )
        )

        self.assertEqual(facts.artifact_registry_encryption_state, STATE_UNKNOWN)
        self.assertEqual(facts.artifact_registry_docker_immutable_tags_state, STATE_UNKNOWN)
        self.assertEqual(facts.artifact_registry_vulnerability_scanning_state, STATE_UNKNOWN)
        self.assertEqual(facts.artifact_registry_cleanup_policy_state, STATE_UNKNOWN)
        self.assertEqual(facts.artifact_registry_cleanup_policy_dry_run_state, STATE_UNKNOWN)
        self.assertEqual(facts.artifact_registry_deletion_policy_state, STATE_UNKNOWN)
        self.assertIn("kms_key_name is unknown after planning", facts.artifact_registry_posture_uncertainties)
        self.assertIn(
            "docker_config.immutable_tags is unknown after planning",
            facts.artifact_registry_posture_uncertainties,
        )
        self.assertIn(
            "vulnerability_scanning_config.enablement_config is unknown after planning",
            facts.artifact_registry_posture_uncertainties,
        )
        self.assertIn("cleanup_policies is unknown after planning", facts.artifact_registry_posture_uncertainties)
        self.assertIn("cleanup_policy_dry_run is unknown after planning", facts.artifact_registry_posture_uncertainties)
        self.assertIn("deletion_policy is unknown after planning", facts.artifact_registry_posture_uncertainties)

    def test_artifact_registry_repository_is_registered_as_supported(self) -> None:
        inventory = GcpNormalizer().normalize(
            [
                _terraform_resource(
                    "google_artifact_registry_repository.images",
                    GcpResourceType.ARTIFACT_REGISTRY_REPOSITORY,
                    {"repository_id": "images", "format": "DOCKER"},
                )
            ]
        )

        self.assertIn(GcpResourceType.ARTIFACT_REGISTRY_REPOSITORY, SUPPORTED_GCP_TYPES)
        self.assertEqual(inventory.unsupported_resources, [])
        self.assertEqual(
            [resource.address for resource in inventory.resources],
            ["google_artifact_registry_repository.images"],
        )
