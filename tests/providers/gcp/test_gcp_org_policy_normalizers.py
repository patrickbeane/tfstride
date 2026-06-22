from __future__ import annotations

import unittest

from tests.providers.gcp.normalizer_support import (
    GcpNormalizerTestCase,
    _terraform_resource,
)
from tfstride.models import ResourceCategory
from tfstride.providers.gcp.metadata import GcpResourceMetadata
from tfstride.providers.gcp.org_policy_normalizers import (
    normalize_folder_organization_policy,
    normalize_org_policy_policy,
    normalize_organization_policy,
    normalize_project_organization_policy,
)


class GcpOrgPolicyNormalizerTests(GcpNormalizerTestCase):
    def test_org_policy_policy_normalizer_preserves_guardrail_rules(self) -> None:
        normalized = normalize_org_policy_policy(
            _terraform_resource(
                "google_org_policy_policy.storage_pap",
                "google_org_policy_policy",
                {
                    "name": "projects/tfstride-demo/policies/constraints/storage.publicAccessPrevention",
                    "parent": "projects/tfstride-demo",
                    "spec": [
                        {
                            "inherit_from_parent": False,
                            "rules": [
                                {
                                    "enforce": True,
                                    "condition": [{"expression": "resource.matchTag('env', 'prod')"}],
                                }
                            ],
                        }
                    ],
                },
            )
        )

        self.assertEqual(normalized.category, ResourceCategory.IAM)
        self.assertEqual(
            normalized.get_metadata_field(GcpResourceMetadata.ORG_POLICY_CONSTRAINT),
            "constraints/storage.publicAccessPrevention",
        )
        self.assertEqual(normalized.get_metadata_field(GcpResourceMetadata.ORG_POLICY_SCOPE), "projects/tfstride-demo")
        self.assertEqual(normalized.get_metadata_field(GcpResourceMetadata.ORG_POLICY_SCOPE_TYPE), "project")
        self.assertEqual(normalized.get_metadata_field(GcpResourceMetadata.PROJECT), "tfstride-demo")
        self.assertTrue(normalized.get_metadata_field(GcpResourceMetadata.ORG_POLICY_ENFORCED))
        self.assertFalse(normalized.get_metadata_field(GcpResourceMetadata.ORG_POLICY_INHERIT_FROM_PARENT))
        self.assertEqual(
            normalized.get_metadata_field(GcpResourceMetadata.ORG_POLICY_RULES),
            [
                {
                    "enforced": True,
                    "condition": {"expression": "resource.matchTag('env', 'prod')"},
                }
            ],
        )

    def test_legacy_organization_policy_normalizers_preserve_guardrail_parts(self) -> None:
        org_policy = normalize_organization_policy(
            _terraform_resource(
                "google_organization_policy.allowed_domains",
                "google_organization_policy",
                {
                    "org_id": "1234567890",
                    "constraint": "constraints/iam.allowedPolicyMemberDomains",
                    "list_policy": [
                        {
                            "inherit_from_parent": False,
                            "allow": [{"values": ["C01abcd", "C02wxyz"]}],
                        }
                    ],
                },
            )
        )
        folder_policy = normalize_folder_organization_policy(
            _terraform_resource(
                "google_folder_organization_policy.disable_keys",
                "google_folder_organization_policy",
                {
                    "folder": "folders/12345",
                    "constraint": "constraints/iam.disableServiceAccountKeyCreation",
                    "boolean_policy": [{"enforced": True}],
                },
            )
        )
        project_policy = normalize_project_organization_policy(
            _terraform_resource(
                "google_project_organization_policy.external_ip",
                "google_project_organization_policy",
                {
                    "project": "tfstride-demo",
                    "constraint": "constraints/compute.vmExternalIpAccess",
                    "list_policy": [{"deny": [{"all": True}]}],
                },
            )
        )

        self.assertEqual(org_policy.get_metadata_field(GcpResourceMetadata.ORGANIZATION_ID), "1234567890")
        self.assertEqual(org_policy.get_metadata_field(GcpResourceMetadata.ORG_POLICY_SCOPE_TYPE), "organization")
        self.assertEqual(
            org_policy.get_metadata_field(GcpResourceMetadata.ORG_POLICY_ALLOWED_VALUES),
            ["C01abcd", "C02wxyz"],
        )
        self.assertFalse(org_policy.get_metadata_field(GcpResourceMetadata.ORG_POLICY_INHERIT_FROM_PARENT))
        self.assertEqual(folder_policy.get_metadata_field(GcpResourceMetadata.FOLDER_ID), "folders/12345")
        self.assertTrue(folder_policy.get_metadata_field(GcpResourceMetadata.ORG_POLICY_ENFORCED))
        self.assertEqual(project_policy.get_metadata_field(GcpResourceMetadata.PROJECT), "tfstride-demo")
        self.assertEqual(
            project_policy.get_metadata_field(GcpResourceMetadata.ORG_POLICY_RULES),
            [{"deny_all": True}],
        )


if __name__ == "__main__":
    unittest.main()
