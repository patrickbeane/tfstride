from __future__ import annotations

import unittest

from tfstride.analysis.gcp.iam_inheritance import (
    GCP_IAM_SCOPE_FOLDER,
    GCP_IAM_SCOPE_ORGANIZATION,
    GCP_IAM_SCOPE_PROJECT,
    GCP_IAM_SCOPE_RESOURCE,
    GcpIamScopeKey,
)
from tfstride.analysis.indexes import build_analysis_indexes
from tfstride.models import NormalizedResource, ResourceCategory, ResourceInventory
from tfstride.providers.gcp.analysis_indexes import gcp_iam_inheritance_index
from tfstride.providers.gcp.metadata import GcpResourceMetadata


def _gcp_resource(
    address: str,
    resource_type: str,
    category: ResourceCategory,
    *,
    identifier: str | None = None,
    metadata: dict[str, object] | None = None,
) -> NormalizedResource:
    return NormalizedResource(
        address=address,
        provider="gcp",
        resource_type=resource_type,
        name=address.rsplit(".", 1)[-1],
        category=category,
        identifier=identifier,
        metadata=metadata,
    )


def _inheritance_index(resources: list[NormalizedResource]):
    return gcp_iam_inheritance_index(build_analysis_indexes(ResourceInventory(provider="gcp", resources=resources)))


class GcpIamInheritanceIndexTests(unittest.TestCase):
    def test_project_scope_indexes_iam_grant_and_descendant_resources(self) -> None:
        instance = _gcp_resource(
            "google_compute_instance.web",
            "google_compute_instance",
            ResourceCategory.COMPUTE,
            metadata={GcpResourceMetadata.PROJECT: "tfstride-demo"},
        )
        secret = _gcp_resource(
            "google_secret_manager_secret.api",
            "google_secret_manager_secret",
            ResourceCategory.DATA,
            identifier="projects/tfstride-demo/secrets/api",
            metadata={GcpResourceMetadata.PROJECT: "tfstride-demo"},
        )
        other_project_bucket = _gcp_resource(
            "google_storage_bucket.logs",
            "google_storage_bucket",
            ResourceCategory.DATA,
            metadata={GcpResourceMetadata.PROJECT: "other-project"},
        )
        project_iam = _gcp_resource(
            "google_project_iam_member.owner",
            "google_project_iam_member",
            ResourceCategory.IAM,
            metadata={GcpResourceMetadata.PROJECT: "projects/tfstride-demo"},
        )

        index = _inheritance_index([instance, secret, other_project_bucket, project_iam])
        project_scope = GcpIamScopeKey(GCP_IAM_SCOPE_PROJECT, "tfstride-demo")

        self.assertEqual(index.scopes_for_iam_resource(project_iam), (project_scope,))
        self.assertEqual(index.iam_resources_by_scope[project_scope], (project_iam,))
        self.assertEqual(
            [resource.address for resource in index.descendant_resources_for_scope(project_scope)],
            ["google_compute_instance.web", "google_secret_manager_secret.api"],
        )
        self.assertEqual(
            [resource.address for resource in index.resources_by_project["tfstride-demo"]],
            ["google_compute_instance.web", "google_secret_manager_secret.api"],
        )

    def test_org_and_folder_scopes_use_normalized_hierarchy_ids(self) -> None:
        folder_workload = _gcp_resource(
            "google_compute_instance.folder_web",
            "google_compute_instance",
            ResourceCategory.COMPUTE,
            metadata={GcpResourceMetadata.FOLDER_ID: "folders/456"},
        )
        org_key = _gcp_resource(
            "google_kms_crypto_key.org_key",
            "google_kms_crypto_key",
            ResourceCategory.DATA,
            metadata={GcpResourceMetadata.ORGANIZATION_ID: "organizations/123"},
        )
        folder_iam = _gcp_resource(
            "google_folder_iam_binding.viewer",
            "google_folder_iam_binding",
            ResourceCategory.IAM,
            metadata={GcpResourceMetadata.FOLDER_ID: "folders/456"},
        )
        organization_iam = _gcp_resource(
            "google_organization_iam_member.owner",
            "google_organization_iam_member",
            ResourceCategory.IAM,
            metadata={GcpResourceMetadata.ORGANIZATION_ID: "organizations/123"},
        )

        index = _inheritance_index([folder_workload, org_key, folder_iam, organization_iam])
        folder_scope = GcpIamScopeKey(GCP_IAM_SCOPE_FOLDER, "456")
        organization_scope = GcpIamScopeKey(GCP_IAM_SCOPE_ORGANIZATION, "123")

        self.assertEqual(index.scopes_for_iam_resource(folder_iam), (folder_scope,))
        self.assertEqual(index.scopes_for_iam_resource(organization_iam), (organization_scope,))
        self.assertEqual(index.descendant_resources_for_scope(folder_scope), (folder_workload,))
        self.assertEqual(index.descendant_resources_for_scope(organization_scope), (org_key,))

    def test_resource_iam_scope_resolves_target_resource(self) -> None:
        secret = _gcp_resource(
            "google_secret_manager_secret.api",
            "google_secret_manager_secret",
            ResourceCategory.DATA,
            identifier="projects/tfstride-demo/secrets/api",
            metadata={GcpResourceMetadata.SECRET_ID: "api"},
        )
        secret_iam = _gcp_resource(
            "google_secret_manager_secret_iam_member.reader",
            "google_secret_manager_secret_iam_member",
            ResourceCategory.IAM,
            metadata={GcpResourceMetadata.SECRET_REFERENCE: "google_secret_manager_secret.api.id"},
        )

        index = _inheritance_index([secret, secret_iam])
        resource_scope = GcpIamScopeKey(GCP_IAM_SCOPE_RESOURCE, "google_secret_manager_secret.api")

        self.assertEqual(index.scopes_for_iam_resource(secret_iam), (resource_scope,))
        self.assertEqual(index.target_resources_for_iam_resource(secret_iam), (secret,))
        self.assertEqual(index.descendant_resources_for_iam_resource(secret_iam), (secret,))

    def test_key_ring_iam_scope_targets_downstream_crypto_keys(self) -> None:
        first_key = _gcp_resource(
            "google_kms_crypto_key.first",
            "google_kms_crypto_key",
            ResourceCategory.DATA,
            metadata={GcpResourceMetadata.KMS_KEY_RING: "projects/tfstride-demo/locations/global/keyRings/app"},
        )
        second_key = _gcp_resource(
            "google_kms_crypto_key.second",
            "google_kms_crypto_key",
            ResourceCategory.DATA,
            metadata={GcpResourceMetadata.KMS_KEY_RING: "projects/tfstride-demo/locations/global/keyRings/app"},
        )
        key_ring_iam = _gcp_resource(
            "google_kms_key_ring_iam_member.decryptor",
            "google_kms_key_ring_iam_member",
            ResourceCategory.IAM,
            metadata={GcpResourceMetadata.KMS_KEY_RING: "projects/tfstride-demo/locations/global/keyRings/app"},
        )

        index = _inheritance_index([first_key, second_key, key_ring_iam])

        self.assertEqual(index.target_resources_for_iam_resource(key_ring_iam), (first_key, second_key))
        self.assertEqual(
            index.scopes_for_iam_resource(key_ring_iam),
            (
                GcpIamScopeKey(GCP_IAM_SCOPE_RESOURCE, "google_kms_crypto_key.first"),
                GcpIamScopeKey(GCP_IAM_SCOPE_RESOURCE, "google_kms_crypto_key.second"),
            ),
        )

    def test_unresolved_iam_resources_track_missing_scope_context(self) -> None:
        project_iam = _gcp_resource(
            "google_project_iam_member.missing_project",
            "google_project_iam_member",
            ResourceCategory.IAM,
        )
        secret_iam = _gcp_resource(
            "google_secret_manager_secret_iam_member.missing_secret",
            "google_secret_manager_secret_iam_member",
            ResourceCategory.IAM,
            metadata={GcpResourceMetadata.SECRET_REFERENCE: "google_secret_manager_secret.missing.id"},
        )

        index = _inheritance_index([project_iam, secret_iam])

        self.assertEqual(index.scopes_for_iam_resource(project_iam), ())
        self.assertEqual(index.scopes_for_iam_resource(secret_iam), ())
        self.assertEqual(index.unresolved_iam_resources, (project_iam, secret_iam))

    def test_non_gcp_inventory_uses_empty_inheritance_index(self) -> None:
        aws_resource = NormalizedResource(
            address="aws_instance.web",
            provider="aws",
            resource_type="aws_instance",
            name="web",
            category=ResourceCategory.COMPUTE,
        )

        index = gcp_iam_inheritance_index(
            build_analysis_indexes(ResourceInventory(provider="aws", resources=[aws_resource]))
        )

        self.assertEqual(index.resources_by_project, {})
        self.assertEqual(index.unresolved_iam_resources, ())


if __name__ == "__main__":
    unittest.main()
