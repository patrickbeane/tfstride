from __future__ import annotations

import json
import unittest

from tests.providers.gcp.normalizer_support import (
    GcpNormalizerTestCase,
    _terraform_resource,
)
from tfstride.models import ResourceCategory
from tfstride.providers.gcp.iam_normalizers import (
    normalize_folder_iam_binding,
    normalize_folder_iam_member,
    normalize_folder_iam_policy,
    normalize_organization_iam_binding,
    normalize_organization_iam_custom_role,
    normalize_organization_iam_member,
    normalize_organization_iam_policy,
    normalize_project_iam_binding,
    normalize_project_iam_custom_role,
    normalize_project_iam_member,
    normalize_project_iam_policy,
)
from tfstride.providers.gcp.metadata import GcpResourceMetadata


class GcpHierarchicalIamNormalizerTests(GcpNormalizerTestCase):
    def test_project_iam_custom_role_normalizer_preserves_permissions(self) -> None:
        normalized = normalize_project_iam_custom_role(
            _terraform_resource(
                "google_project_iam_custom_role.deployer",
                "google_project_iam_custom_role",
                {
                    "project": "tfstride-demo",
                    "role_id": "deployAdmin",
                    "title": "Deploy Admin",
                    "permissions": [
                        "iam.serviceAccounts.actAs",
                        "cloudfunctions.functions.update",
                    ],
                    "stage": "GA",
                },
            )
        )

        self.assertEqual(normalized.category, ResourceCategory.IAM)
        self.assertEqual(normalized.identifier, "projects/tfstride-demo/roles/deployAdmin")
        self.assertEqual(
            normalized.get_metadata_field(GcpResourceMetadata.NAME),
            "projects/tfstride-demo/roles/deployAdmin",
        )
        self.assertEqual(normalized.get_metadata_field(GcpResourceMetadata.PROJECT), "tfstride-demo")
        self.assertEqual(normalized.get_metadata_field(GcpResourceMetadata.CUSTOM_ROLE_ID), "deployAdmin")
        self.assertEqual(
            normalized.get_metadata_field(GcpResourceMetadata.CUSTOM_ROLE_PERMISSIONS),
            ["iam.serviceAccounts.actAs", "cloudfunctions.functions.update"],
        )
        self.assertEqual(normalized.get_metadata_field(GcpResourceMetadata.CUSTOM_ROLE_STAGE), "GA")

    def test_organization_iam_custom_role_normalizer_preserves_permissions(self) -> None:
        normalized = normalize_organization_iam_custom_role(
            _terraform_resource(
                "google_organization_iam_custom_role.audit",
                "google_organization_iam_custom_role",
                {
                    "org_id": "1234567890",
                    "role_id": "secretAudit",
                    "permissions": ["secretmanager.versions.access"],
                },
            )
        )

        self.assertEqual(normalized.category, ResourceCategory.IAM)
        self.assertEqual(normalized.identifier, "organizations/1234567890/roles/secretAudit")
        self.assertEqual(
            normalized.get_metadata_field(GcpResourceMetadata.NAME),
            "organizations/1234567890/roles/secretAudit",
        )
        self.assertEqual(normalized.get_metadata_field(GcpResourceMetadata.ORGANIZATION_ID), "1234567890")
        self.assertEqual(normalized.get_metadata_field(GcpResourceMetadata.CUSTOM_ROLE_ID), "secretAudit")
        self.assertEqual(
            normalized.get_metadata_field(GcpResourceMetadata.CUSTOM_ROLE_PERMISSIONS),
            ["secretmanager.versions.access"],
        )

    def test_organization_iam_member_normalizer_preserves_scope_and_binding(self) -> None:
        normalized = normalize_organization_iam_member(
            _terraform_resource(
                "google_organization_iam_member.owner",
                "google_organization_iam_member",
                {
                    "org_id": "1234567890",
                    "role": "roles/resourcemanager.organizationAdmin",
                    "member": "group:platform-admins@example.com",
                },
            )
        )

        self.assertEqual(normalized.category, ResourceCategory.IAM)
        self.assertEqual(normalized.get_metadata_field(GcpResourceMetadata.ORGANIZATION_ID), "1234567890")
        self.assertEqual(
            normalized.get_metadata_field(GcpResourceMetadata.IAM_BINDINGS),
            [
                {
                    "role": "roles/resourcemanager.organizationAdmin",
                    "members": ["group:platform-admins@example.com"],
                }
            ],
        )

    def test_organization_iam_binding_normalizer_preserves_member_list(self) -> None:
        normalized = normalize_organization_iam_binding(
            _terraform_resource(
                "google_organization_iam_binding.viewer",
                "google_organization_iam_binding",
                {
                    "org_id": "1234567890",
                    "role": "roles/viewer",
                    "members": ["allAuthenticatedUsers", "group:ops@example.com"],
                },
            )
        )

        self.assertEqual(normalized.get_metadata_field(GcpResourceMetadata.ORGANIZATION_ID), "1234567890")
        self.assertEqual(
            normalized.get_metadata_field(GcpResourceMetadata.IAM_MEMBERS),
            ["allAuthenticatedUsers", "group:ops@example.com"],
        )

    def test_organization_iam_policy_normalizer_parses_policy_bindings(self) -> None:
        normalized = normalize_organization_iam_policy(
            _terraform_resource(
                "google_organization_iam_policy.policy",
                "google_organization_iam_policy",
                {
                    "org_id": "1234567890",
                    "policy_data": json.dumps(
                        {"bindings": [{"role": "roles/owner", "members": ["group:admins@example.com"]}]}
                    ),
                },
            )
        )

        self.assertEqual(normalized.get_metadata_field(GcpResourceMetadata.ORGANIZATION_ID), "1234567890")
        self.assertEqual(
            normalized.get_metadata_field(GcpResourceMetadata.IAM_BINDINGS),
            [{"role": "roles/owner", "members": ["group:admins@example.com"]}],
        )

    def test_folder_iam_normalizers_preserve_scope_and_bindings(self) -> None:
        member = normalize_folder_iam_member(
            _terraform_resource(
                "google_folder_iam_member.owner",
                "google_folder_iam_member",
                {
                    "folder": "folders/12345",
                    "role": "roles/resourcemanager.folderAdmin",
                    "member": "group:folder-admins@example.com",
                },
            )
        )
        binding = normalize_folder_iam_binding(
            _terraform_resource(
                "google_folder_iam_binding.viewer",
                "google_folder_iam_binding",
                {
                    "folder": "folders/12345",
                    "role": "roles/viewer",
                    "members": ["domain:example.com"],
                },
            )
        )
        policy = normalize_folder_iam_policy(
            _terraform_resource(
                "google_folder_iam_policy.policy",
                "google_folder_iam_policy",
                {
                    "folder": "folders/12345",
                    "policy_data": {"bindings": [{"role": "roles/editor", "members": ["group:admins@example.com"]}]},
                },
            )
        )

        self.assertEqual(member.get_metadata_field(GcpResourceMetadata.FOLDER_ID), "folders/12345")
        self.assertEqual(binding.get_metadata_field(GcpResourceMetadata.FOLDER_ID), "folders/12345")
        self.assertEqual(policy.get_metadata_field(GcpResourceMetadata.FOLDER_ID), "folders/12345")
        self.assertEqual(
            binding.get_metadata_field(GcpResourceMetadata.IAM_BINDINGS),
            [{"role": "roles/viewer", "members": ["domain:example.com"]}],
        )
        self.assertEqual(
            policy.get_metadata_field(GcpResourceMetadata.IAM_BINDINGS),
            [{"role": "roles/editor", "members": ["group:admins@example.com"]}],
        )

    def test_project_iam_member_normalizer_preserves_binding_parts(self) -> None:
        normalized = normalize_project_iam_member(self.resources["google_project_iam_member.web_viewer"])

        self.assertEqual(normalized.category, ResourceCategory.IAM)
        self.assertEqual(
            normalized.identifier, "roles/viewer:serviceAccount:tfstride-web@example.iam.gserviceaccount.com"
        )
        self.assertEqual(normalized.get_metadata_field(GcpResourceMetadata.PROJECT), "tfstride-demo")
        self.assertEqual(normalized.get_metadata_field(GcpResourceMetadata.IAM_ROLE), "roles/viewer")
        self.assertEqual(
            normalized.get_metadata_field(GcpResourceMetadata.IAM_MEMBER),
            "serviceAccount:tfstride-web@example.iam.gserviceaccount.com",
        )
        self.assertEqual(
            normalized.get_metadata_field(GcpResourceMetadata.IAM_BINDINGS),
            [
                {
                    "role": "roles/viewer",
                    "members": ["serviceAccount:tfstride-web@example.iam.gserviceaccount.com"],
                }
            ],
        )

    def test_project_iam_binding_normalizer_preserves_member_list(self) -> None:
        normalized = normalize_project_iam_binding(
            _terraform_resource(
                "google_project_iam_binding.viewer",
                "google_project_iam_binding",
                {
                    "project": "tfstride-demo",
                    "role": "roles/viewer",
                    "members": ["allUsers", "group:ops@example.com"],
                },
            )
        )

        self.assertEqual(normalized.category, ResourceCategory.IAM)
        self.assertEqual(normalized.get_metadata_field(GcpResourceMetadata.PROJECT), "tfstride-demo")
        self.assertEqual(normalized.get_metadata_field(GcpResourceMetadata.IAM_ROLE), "roles/viewer")
        self.assertEqual(
            normalized.get_metadata_field(GcpResourceMetadata.IAM_MEMBERS),
            ["allUsers", "group:ops@example.com"],
        )
        self.assertEqual(
            normalized.get_metadata_field(GcpResourceMetadata.IAM_BINDINGS),
            [{"role": "roles/viewer", "members": ["allUsers", "group:ops@example.com"]}],
        )

    def test_project_iam_policy_normalizer_parses_policy_bindings(self) -> None:
        normalized = normalize_project_iam_policy(
            _terraform_resource(
                "google_project_iam_policy.policy",
                "google_project_iam_policy",
                {
                    "project": "tfstride-demo",
                    "policy_data": json.dumps(
                        {
                            "bindings": [
                                {"role": "roles/viewer", "members": ["allUsers"]},
                                {"role": "roles/owner", "members": ["group:admins@example.com"]},
                            ]
                        }
                    ),
                },
            )
        )

        self.assertEqual(normalized.category, ResourceCategory.IAM)
        self.assertEqual(normalized.get_metadata_field(GcpResourceMetadata.PROJECT), "tfstride-demo")
        self.assertEqual(
            normalized.get_metadata_field(GcpResourceMetadata.IAM_BINDINGS),
            [
                {"role": "roles/viewer", "members": ["allUsers"]},
                {"role": "roles/owner", "members": ["group:admins@example.com"]},
            ],
        )


if __name__ == "__main__":
    unittest.main()
