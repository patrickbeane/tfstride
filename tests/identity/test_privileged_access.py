from __future__ import annotations

import unittest
from dataclasses import FrozenInstanceError

from tfstride.identity import (
    AssignmentScopeKind,
    PrincipalType,
    PrivilegeCategory,
    PrivilegeConfidence,
    PrivilegedAccessGrant,
    PrivilegedAccessPosture,
    PrivilegedAssignmentScope,
    PrivilegedPrincipal,
)


class PrivilegedAccessContractTests(unittest.TestCase):
    def test_shared_vocabulary_is_provider_neutral(self) -> None:
        enum_values = {
            *(value.value for value in PrincipalType),
            *(value.value for value in AssignmentScopeKind),
            *(value.value for value in PrivilegeCategory),
        }

        for provider_name in ("aws", "gcp", "azure"):
            with self.subTest(provider_name=provider_name):
                self.assertTrue(all(provider_name not in value for value in enum_values))

    def test_principal_and_scope_accept_enum_or_string_values(self) -> None:
        principal = PrivilegedPrincipal(
            principal_type="managed-identity",
            identifier="principal-123",
            display_name="deploy identity",
            source_address="azurerm_user_assigned_identity.deploy",
        )
        scope = PrivilegedAssignmentScope(
            scope_kind="subscription",
            value="/subscriptions/00000000-0000-0000-0000-000000000000",
        )

        self.assertEqual(principal.principal_type, PrincipalType.MANAGED_IDENTITY)
        self.assertEqual(scope.scope_kind, AssignmentScopeKind.SUBSCRIPTION)
        self.assertTrue(scope.is_broad)

    def test_grant_normalizes_provider_categories_and_evidence_stably(self) -> None:
        grant = PrivilegedAccessGrant(
            provider=" AWS ",
            principal=PrivilegedPrincipal(PrincipalType.ROLE, identifier="arn:aws:iam::123456789012:role/app"),
            assignment_scope=PrivilegedAssignmentScope(AssignmentScopeKind.ACCOUNT, value="123456789012"),
            privilege_categories=(
                PrivilegeCategory.FULL_ADMIN,
                "iam-admin",
                PrivilegeCategory.FULL_ADMIN,
            ),
            confidence="medium",
            assignment_source_address="aws_iam_role_policy_attachment.admin",
            role_name="AdministratorAccess",
            permission_patterns=("*", "iam:*", "*", None, ""),
            evidence=("policy=AdministratorAccess", "policy=AdministratorAccess", "scope=account"),
            uncertainties=("policy document was not fully expanded", "policy document was not fully expanded"),
        )

        self.assertEqual(grant.provider, "aws")
        self.assertEqual(
            grant.privilege_categories,
            (PrivilegeCategory.FULL_ADMIN, PrivilegeCategory.IAM_ADMIN),
        )
        self.assertEqual(grant.confidence, PrivilegeConfidence.MEDIUM)
        self.assertEqual(grant.permission_patterns, ("*", "iam:*"))
        self.assertEqual(grant.evidence, ("policy=AdministratorAccess", "scope=account"))
        self.assertEqual(grant.uncertainties, ("policy document was not fully expanded",))
        self.assertTrue(grant.has_broad_scope)
        self.assertTrue(grant.has_uncertainty)

    def test_grant_requires_at_least_one_privilege_category(self) -> None:
        with self.assertRaisesRegex(ValueError, "privilege_categories"):
            PrivilegedAccessGrant(
                provider="gcp",
                principal=PrivilegedPrincipal(PrincipalType.SERVICE_ACCOUNT),
                assignment_scope=PrivilegedAssignmentScope(AssignmentScopeKind.PROJECT),
                privilege_categories=(),
            )

    def test_posture_is_provider_scoped_and_tracks_unresolved_assignments(self) -> None:
        grant = PrivilegedAccessGrant(
            provider="gcp",
            principal=PrivilegedPrincipal(
                PrincipalType.SERVICE_ACCOUNT, identifier="deploy@example.iam.gserviceaccount.com"
            ),
            assignment_scope=PrivilegedAssignmentScope(AssignmentScopeKind.PROJECT, value="example-project"),
            privilege_categories=(PrivilegeCategory.DATA_ADMIN,),
        )

        posture = PrivilegedAccessPosture(
            provider=" GCP ",
            grants=(grant,),
            unresolved_assignments=("google_project_iam_member.pending", "google_project_iam_member.pending", None),
        )

        self.assertEqual(posture.provider, "gcp")
        self.assertEqual(posture.grants, (grant,))
        self.assertEqual(posture.unresolved_assignments, ("google_project_iam_member.pending",))
        self.assertTrue(posture.has_privileged_grants)
        self.assertTrue(posture.has_unresolved_assignments)

    def test_posture_rejects_cross_provider_grants(self) -> None:
        grant = PrivilegedAccessGrant(
            provider="azure",
            principal=PrivilegedPrincipal(PrincipalType.MANAGED_IDENTITY),
            assignment_scope=PrivilegedAssignmentScope(AssignmentScopeKind.SUBSCRIPTION),
            privilege_categories=(PrivilegeCategory.ROLE_ASSIGNMENT,),
        )

        with self.assertRaisesRegex(ValueError, "posture provider"):
            PrivilegedAccessPosture(provider="aws", grants=(grant,))

    def test_contract_objects_are_immutable(self) -> None:
        principal = PrivilegedPrincipal(PrincipalType.HUMAN_USER, identifier="alice@example.com")

        with self.assertRaises(FrozenInstanceError):
            principal.identifier = "bob@example.com"


if __name__ == "__main__":
    unittest.main()
