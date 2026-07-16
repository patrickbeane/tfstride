from __future__ import annotations

import unittest

from tests.providers.gcp.normalizer_support import _terraform_resource
from tfstride.models import ResourceCategory
from tfstride.providers.gcp.iam_normalizers import (
    normalize_artifact_registry_repository_iam_binding,
    normalize_artifact_registry_repository_iam_member,
    normalize_artifact_registry_repository_iam_policy,
)
from tfstride.providers.gcp.metadata import GcpResourceMetadata
from tfstride.providers.gcp.normalizer import GcpNormalizer
from tfstride.providers.gcp.resource_facts import gcp_facts
from tfstride.providers.gcp.resource_types import (
    GCP_ARTIFACT_REGISTRY_REPOSITORY_IAM_RESOURCE_TYPES,
    GcpResourceType,
)

_REPOSITORY_REFERENCE = "google_artifact_registry_repository.images.id"


class GcpArtifactRegistryIamNormalizerTests(unittest.TestCase):
    def test_member_preserves_repository_role_member_condition_and_binding(self) -> None:
        normalized = normalize_artifact_registry_repository_iam_member(
            _terraform_resource(
                "google_artifact_registry_repository_iam_member.reader",
                GcpResourceType.ARTIFACT_REGISTRY_REPOSITORY_IAM_MEMBER,
                {
                    "repository": _REPOSITORY_REFERENCE,
                    "project": "tfstride-demo",
                    "role": "roles/artifactregistry.reader",
                    "member": "serviceAccount:reader@tfstride-demo.iam.gserviceaccount.com",
                    "condition": [
                        {
                            "title": "release-window",
                            "expression": "request.time < timestamp('2027-01-01T00:00:00Z')",
                        }
                    ],
                },
            )
        )

        self.assertEqual(normalized.category, ResourceCategory.IAM)
        self.assertEqual(
            normalized.get_metadata_field(GcpResourceMetadata.ARTIFACT_REGISTRY_REPOSITORY_REFERENCE),
            _REPOSITORY_REFERENCE,
        )
        self.assertEqual(normalized.get_metadata_field(GcpResourceMetadata.PROJECT), "tfstride-demo")
        self.assertEqual(normalized.get_metadata_field(GcpResourceMetadata.IAM_ROLE), "roles/artifactregistry.reader")
        self.assertEqual(
            normalized.get_metadata_field(GcpResourceMetadata.IAM_MEMBER),
            "serviceAccount:reader@tfstride-demo.iam.gserviceaccount.com",
        )
        self.assertEqual(
            normalized.get_metadata_field(GcpResourceMetadata.IAM_CONDITION),
            {
                "title": "release-window",
                "expression": "request.time < timestamp('2027-01-01T00:00:00Z')",
            },
        )
        self.assertEqual(
            normalized.get_metadata_field(GcpResourceMetadata.IAM_BINDINGS),
            [
                {
                    "role": "roles/artifactregistry.reader",
                    "members": ["serviceAccount:reader@tfstride-demo.iam.gserviceaccount.com"],
                    "condition": {
                        "title": "release-window",
                        "expression": "request.time < timestamp('2027-01-01T00:00:00Z')",
                    },
                }
            ],
        )
        self.assertEqual(
            gcp_facts(normalized).target_reference,
            _REPOSITORY_REFERENCE,
        )
        self.assertEqual(
            normalized.get_metadata_field(GcpResourceMetadata.ARTIFACT_REGISTRY_IAM_POSTURE_UNCERTAINTIES),
            [],
        )

    def test_binding_preserves_repository_members_and_scope(self) -> None:
        normalized = normalize_artifact_registry_repository_iam_binding(
            _terraform_resource(
                "google_artifact_registry_repository_iam_binding.writers",
                GcpResourceType.ARTIFACT_REGISTRY_REPOSITORY_IAM_BINDING,
                {
                    "repository": _REPOSITORY_REFERENCE,
                    "role": "roles/artifactregistry.writer",
                    "members": [
                        "serviceAccount:writer@tfstride-demo.iam.gserviceaccount.com",
                        "group:release@example.com",
                    ],
                },
            )
        )

        self.assertEqual(
            normalized.get_metadata_field(GcpResourceMetadata.IAM_MEMBERS),
            [
                "serviceAccount:writer@tfstride-demo.iam.gserviceaccount.com",
                "group:release@example.com",
            ],
        )
        self.assertEqual(
            normalized.get_metadata_field(GcpResourceMetadata.IAM_BINDINGS),
            [
                {
                    "role": "roles/artifactregistry.writer",
                    "members": [
                        "serviceAccount:writer@tfstride-demo.iam.gserviceaccount.com",
                        "group:release@example.com",
                    ],
                }
            ],
        )
        self.assertEqual(gcp_facts(normalized).target_reference, _REPOSITORY_REFERENCE)

    def test_policy_preserves_repository_scope_policy_bindings_and_conditions(self) -> None:
        normalized = normalize_artifact_registry_repository_iam_policy(
            _terraform_resource(
                "google_artifact_registry_repository_iam_policy.policy",
                GcpResourceType.ARTIFACT_REGISTRY_REPOSITORY_IAM_POLICY,
                {
                    "repository": _REPOSITORY_REFERENCE,
                    "policy_data": {
                        "bindings": [
                            {
                                "role": "roles/artifactregistry.writer",
                                "members": ["serviceAccount:publisher@tfstride-demo.iam.gserviceaccount.com"],
                                "condition": {
                                    "title": "publisher-window",
                                    "expression": "resource.name.startsWith('projects/tfstride-demo')",
                                },
                            }
                        ]
                    },
                },
            )
        )

        self.assertEqual(
            normalized.get_metadata_field(GcpResourceMetadata.POLICY_DOCUMENT),
            {
                "bindings": [
                    {
                        "role": "roles/artifactregistry.writer",
                        "members": ["serviceAccount:publisher@tfstride-demo.iam.gserviceaccount.com"],
                        "condition": {
                            "title": "publisher-window",
                            "expression": "resource.name.startsWith('projects/tfstride-demo')",
                        },
                    }
                ]
            },
        )
        self.assertEqual(
            normalized.get_metadata_field(GcpResourceMetadata.IAM_BINDINGS),
            [
                {
                    "role": "roles/artifactregistry.writer",
                    "members": ["serviceAccount:publisher@tfstride-demo.iam.gserviceaccount.com"],
                    "condition": {
                        "title": "publisher-window",
                        "expression": "resource.name.startsWith('projects/tfstride-demo')",
                    },
                }
            ],
        )

    def test_unknown_repository_iam_values_are_retained_as_uncertainty(self) -> None:
        normalized = normalize_artifact_registry_repository_iam_member(
            _terraform_resource(
                "google_artifact_registry_repository_iam_member.unknown",
                GcpResourceType.ARTIFACT_REGISTRY_REPOSITORY_IAM_MEMBER,
                {},
                unknown_values={
                    "repository": True,
                    "role": True,
                    "member": True,
                    "condition": True,
                },
            )
        )

        self.assertIsNone(normalized.get_metadata_field(GcpResourceMetadata.ARTIFACT_REGISTRY_REPOSITORY_REFERENCE))
        self.assertEqual(
            normalized.get_metadata_field(GcpResourceMetadata.ARTIFACT_REGISTRY_IAM_POSTURE_UNCERTAINTIES),
            [
                "repository is unknown after planning",
                "role is unknown after planning",
                "member is unknown after planning",
                "condition is unknown after planning",
            ],
        )
        self.assertEqual(gcp_facts(normalized).target_reference, None)

    def test_unresolved_repository_expression_is_preserved(self) -> None:
        normalized = normalize_artifact_registry_repository_iam_member(
            _terraform_resource(
                "google_artifact_registry_repository_iam_member.expression",
                GcpResourceType.ARTIFACT_REGISTRY_REPOSITORY_IAM_MEMBER,
                {
                    "repository": "${google_artifact_registry_repository.images.id}",
                    "role": "roles/artifactregistry.reader",
                    "member": "group:readers@example.com",
                },
            )
        )

        self.assertEqual(
            normalized.get_metadata_field(GcpResourceMetadata.ARTIFACT_REGISTRY_REPOSITORY_REFERENCE),
            "${google_artifact_registry_repository.images.id}",
        )

    def test_artifact_registry_iam_types_are_supported_and_normalized(self) -> None:
        resources = [
            _terraform_resource(
                f"google_artifact_registry_repository_iam_{kind}.example",
                resource_type,
                {
                    "repository": _REPOSITORY_REFERENCE,
                    "role": "roles/artifactregistry.reader",
                    "member": "user:a@example.com",
                }
                if kind == "member"
                else {
                    "repository": _REPOSITORY_REFERENCE,
                    "role": "roles/artifactregistry.reader",
                    "members": ["user:a@example.com"],
                }
                if kind == "binding"
                else {"repository": _REPOSITORY_REFERENCE, "policy_data": {"bindings": []}},
            )
            for kind, resource_type in (
                ("member", GcpResourceType.ARTIFACT_REGISTRY_REPOSITORY_IAM_MEMBER),
                ("binding", GcpResourceType.ARTIFACT_REGISTRY_REPOSITORY_IAM_BINDING),
                ("policy", GcpResourceType.ARTIFACT_REGISTRY_REPOSITORY_IAM_POLICY),
            )
        ]
        inventory = GcpNormalizer().normalize(resources)

        self.assertEqual(inventory.unsupported_resources, [])
        self.assertEqual(
            {resource.resource_type for resource in inventory.resources},
            set(GCP_ARTIFACT_REGISTRY_REPOSITORY_IAM_RESOURCE_TYPES),
        )
