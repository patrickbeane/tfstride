from __future__ import annotations

import unittest

from tests.providers.gcp.rule_support.iam import (
    _folder_iam_member,
    _organization_iam_binding,
    _organization_iam_custom_role,
    _organization_iam_member,
    _organization_iam_policy,
)
from tfstride.analysis.stride_rules import StrideRuleEngine
from tfstride.models import TerraformResource
from tfstride.providers.gcp.normalizer import GcpNormalizer


class GcpHierarchicalIamRuleTests(unittest.TestCase):
    def test_organization_iam_broad_principal_is_detected(self) -> None:
        inventory = GcpNormalizer().normalize(
            [_organization_iam_binding("roles/viewer", members=["domain:example.com", "group:ops@example.com"])]
        )

        findings = StrideRuleEngine().evaluate(inventory, [])

        self.assertEqual(len(findings), 1)
        finding = findings[0]
        self.assertEqual(finding.rule_id, "gcp-org-folder-iam-broad-principal")
        self.assertEqual(finding.affected_resources, ["google_organization_iam_binding.binding"])
        evidence = {item.key: item.values for item in finding.evidence}
        self.assertEqual(evidence["iam_binding"], ["member=domain:example.com", "role=roles/viewer"])
        self.assertEqual(evidence["scope"], ["organization scope `1234567890`"])

    def test_folder_iam_public_principal_is_detected(self) -> None:
        inventory = GcpNormalizer().normalize([_folder_iam_member("roles/viewer", member="allUsers")])

        findings = StrideRuleEngine().evaluate(inventory, [])

        self.assertEqual(len(findings), 1)
        finding = findings[0]
        self.assertEqual(finding.rule_id, "gcp-org-folder-iam-broad-principal")
        self.assertEqual(finding.severity.value, "high")
        evidence = {item.key: item.values for item in finding.evidence}
        self.assertEqual(evidence["scope"], ["folder scope `folders/12345`"])

    def test_organization_iam_privileged_role_is_detected(self) -> None:
        inventory = GcpNormalizer().normalize([_organization_iam_member("roles/resourcemanager.organizationAdmin")])

        findings = StrideRuleEngine().evaluate(inventory, [])

        self.assertEqual(len(findings), 1)
        finding = findings[0]
        self.assertEqual(finding.rule_id, "gcp-org-folder-iam-privileged-role")
        self.assertEqual(finding.affected_resources, ["google_organization_iam_member.binding"])
        evidence = {item.key: item.values for item in finding.evidence}
        self.assertEqual(evidence["role_risk"], ["organization-level resource administration"])
        self.assertEqual(evidence["scope"], ["organization scope `1234567890`"])

    def test_folder_iam_policy_privileged_role_is_detected(self) -> None:
        inventory = GcpNormalizer().normalize(
            [
                _organization_iam_policy([{"role": "roles/viewer", "members": ["group:ops@example.com"]}]),
                TerraformResource(
                    address="google_folder_iam_policy.policy",
                    mode="managed",
                    resource_type="google_folder_iam_policy",
                    name="policy",
                    provider_name="registry.terraform.io/hashicorp/google",
                    values={
                        "folder": "folders/12345",
                        "policy_data": {
                            "bindings": [
                                {"role": "roles/resourcemanager.folderAdmin", "members": ["group:admins@example.com"]}
                            ]
                        },
                    },
                ),
            ]
        )

        findings = StrideRuleEngine().evaluate(inventory, [])

        self.assertEqual([finding.rule_id for finding in findings], ["gcp-org-folder-iam-privileged-role"])
        self.assertEqual(findings[0].affected_resources, ["google_folder_iam_policy.policy"])

    def test_organization_iam_custom_role_privileged_permissions_are_detected(self) -> None:
        inventory = GcpNormalizer().normalize(
            [
                _organization_iam_custom_role(
                    role_id="orgAdmin",
                    permissions=["resourcemanager.projects.setIamPolicy", "iam.serviceAccounts.actAs"],
                ),
                _organization_iam_member("organizations/1234567890/roles/orgAdmin"),
            ]
        )

        findings = StrideRuleEngine().evaluate(inventory, [])

        self.assertEqual([finding.rule_id for finding in findings], ["gcp-org-folder-iam-privileged-role"])
        evidence = {item.key: item.values for item in findings[0].evidence}
        self.assertEqual(
            evidence["role_risk"],
            [
                "custom role includes high-impact permissions: iam.serviceAccounts.actAs, resourcemanager.projects.setIamPolicy"
            ],
        )
        self.assertEqual(
            evidence["custom_role_permissions"],
            ["iam.serviceAccounts.actAs", "resourcemanager.projects.setIamPolicy"],
        )

    def test_organization_iam_viewer_group_is_not_flagged(self) -> None:
        inventory = GcpNormalizer().normalize([_organization_iam_member("roles/viewer")])

        findings = StrideRuleEngine().evaluate(inventory, [])

        self.assertEqual(findings, [])


if __name__ == "__main__":
    unittest.main()
