from __future__ import annotations

import unittest

from tests.providers.gcp.rule_support.iam import (
    _project_iam_custom_role,
    _project_iam_member,
    _service_account_iam_member,
)
from tfstride.identity import AssignmentScopeKind, PrincipalType, PrivilegeCategory, PrivilegeConfidence
from tfstride.providers.gcp.normalizer import GcpNormalizer
from tfstride.providers.gcp.resource_facts import gcp_facts


class GcpIamAssignmentPostureTests(unittest.TestCase):
    def test_project_owner_assignment_is_normalized_as_privileged_access(self) -> None:
        inventory = GcpNormalizer().normalize([_project_iam_member("roles/owner")])
        binding = inventory.get_by_address("google_project_iam_member.binding")
        self.assertIsNotNone(binding)
        assert binding is not None

        grants = gcp_facts(binding).privileged_access_grants

        self.assertEqual(len(grants), 1)
        grant = grants[0]
        self.assertEqual(grant.provider, "gcp")
        self.assertEqual(grant.principal.principal_type, PrincipalType.SERVICE_ACCOUNT)
        self.assertEqual(grant.principal.identifier, "serviceAccount:deploy@example.iam.gserviceaccount.com")
        self.assertEqual(grant.assignment_scope.scope_kind, AssignmentScopeKind.PROJECT)
        self.assertEqual(grant.assignment_scope.value, "tfstride-demo")
        self.assertEqual(
            grant.privilege_categories,
            (
                PrivilegeCategory.FULL_ADMIN,
                PrivilegeCategory.IAM_ADMIN,
                PrivilegeCategory.POLICY_ADMIN,
            ),
        )
        self.assertEqual(grant.confidence, PrivilegeConfidence.HIGH)
        self.assertEqual(grant.permission_patterns, ("roles/owner",))
        self.assertIn("role=roles/owner", grant.evidence)
        self.assertEqual(gcp_facts(binding).iam_assignment_posture_uncertainties, [])
        self.assertTrue(gcp_facts(binding).privileged_access_posture.has_privileged_grants)

    def test_service_account_token_creator_assignment_is_normalized(self) -> None:
        inventory = GcpNormalizer().normalize([_service_account_iam_member()])
        binding = inventory.get_by_address("google_service_account_iam_member.deploy_token_creator")
        self.assertIsNotNone(binding)
        assert binding is not None

        grants = gcp_facts(binding).privileged_access_grants

        self.assertEqual(len(grants), 1)
        grant = grants[0]
        self.assertEqual(grant.principal.principal_type, PrincipalType.GROUP)
        self.assertEqual(grant.principal.identifier, "group:deploy@example.com")
        self.assertEqual(grant.assignment_scope.scope_kind, AssignmentScopeKind.RESOURCE)
        self.assertEqual(grant.assignment_scope.value, "google_service_account.deploy.name")
        self.assertEqual(grant.privilege_categories, (PrivilegeCategory.PRIVILEGE_ESCALATION,))
        self.assertEqual(grant.permission_patterns, ("roles/iam.serviceAccountTokenCreator",))

    def test_custom_role_assignment_uses_in_plan_permissions(self) -> None:
        inventory = GcpNormalizer().normalize(
            [
                _project_iam_custom_role(
                    role_id="deployAdmin",
                    permissions=["iam.serviceAccounts.actAs", "cloudfunctions.functions.update"],
                ),
                _project_iam_member("projects/tfstride-demo/roles/deployAdmin"),
            ]
        )
        binding = inventory.get_by_address("google_project_iam_member.binding")
        self.assertIsNotNone(binding)
        assert binding is not None

        grants = gcp_facts(binding).privileged_access_grants

        self.assertEqual(len(grants), 1)
        grant = grants[0]
        self.assertEqual(
            grant.privilege_categories,
            (PrivilegeCategory.COMPUTE_ADMIN, PrivilegeCategory.PRIVILEGE_ESCALATION),
        )
        self.assertEqual(
            grant.permission_patterns,
            ("cloudfunctions.functions.update", "iam.serviceAccounts.actAs"),
        )
        self.assertEqual(grant.role_name, "projects/tfstride-demo/roles/deployAdmin")
        self.assertEqual(gcp_facts(binding).iam_assignment_posture_uncertainties, [])

    def test_unresolved_custom_role_reference_is_preserved_without_grant(self) -> None:
        inventory = GcpNormalizer().normalize([_project_iam_member("projects/tfstride-demo/roles/missing")])
        binding = inventory.get_by_address("google_project_iam_member.binding")
        self.assertIsNotNone(binding)
        assert binding is not None

        self.assertEqual(gcp_facts(binding).privileged_access_grants, ())
        self.assertEqual(
            gcp_facts(binding).iam_assignment_posture_uncertainties,
            ["google_project_iam_member.binding: custom role projects/tfstride-demo/roles/missing was not resolved"],
        )
        self.assertEqual(
            gcp_facts(binding).privileged_access_posture.unresolved_assignments,
            ("google_project_iam_member.binding: custom role projects/tfstride-demo/roles/missing was not resolved",),
        )

    def test_non_privileged_project_viewer_assignment_stays_quiet(self) -> None:
        inventory = GcpNormalizer().normalize([_project_iam_member("roles/viewer")])
        binding = inventory.get_by_address("google_project_iam_member.binding")
        self.assertIsNotNone(binding)
        assert binding is not None

        self.assertEqual(gcp_facts(binding).privileged_access_grants, ())
        self.assertEqual(gcp_facts(binding).iam_assignment_posture_uncertainties, [])


if __name__ == "__main__":
    unittest.main()
