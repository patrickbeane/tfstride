from __future__ import annotations

import unittest

from tfstride.identity import AssignmentScopeKind, PrincipalType, PrivilegeCategory, PrivilegeConfidence
from tfstride.models import IAMPolicyStatement, NormalizedResource, ResourceCategory
from tfstride.providers.aws.iam_assignment_posture import build_aws_privileged_access_posture
from tfstride.providers.aws.resource_decorator import AwsResourceDecorator
from tfstride.providers.aws.resource_facts import aws_facts


def _role(*, statements: list[IAMPolicyStatement] | None = None) -> NormalizedResource:
    return NormalizedResource(
        address="aws_iam_role.app",
        provider="aws",
        resource_type="aws_iam_role",
        name="app",
        category=ResourceCategory.IAM,
        identifier="app-role",
        arn="arn:aws:iam::111122223333:role/app",
        policy_statements=statements or [],
    )


def _policy_statement(
    actions: list[str],
    resources: list[str] | None = None,
    *,
    effect: str = "Allow",
) -> IAMPolicyStatement:
    return IAMPolicyStatement(effect=effect, actions=actions, resources=resources or ["*"])


def _resource(
    address: str,
    resource_type: str,
    *,
    identifier: str | None = None,
    arn: str | None = None,
    policy_statements: list[IAMPolicyStatement] | None = None,
    metadata: dict[str, object] | None = None,
) -> NormalizedResource:
    return NormalizedResource(
        address=address,
        provider="aws",
        resource_type=resource_type,
        name=address.rsplit(".", 1)[-1],
        category=ResourceCategory.IAM,
        identifier=identifier,
        arn=arn,
        policy_statements=policy_statements or [],
        metadata=metadata,
    )


class AwsIamAssignmentPostureTests(unittest.TestCase):
    def test_builds_privileged_access_grants_for_high_impact_role_permissions(self) -> None:
        role = _role(
            statements=[
                _policy_statement(["*"], ["*"]),
                _policy_statement(["iam:PassRole", "sts:AssumeRole"], ["arn:aws:iam::111122223333:role/admin"]),
                _policy_statement(["s3:GetObject"], ["arn:aws:s3:::logs/*"]),
                _policy_statement(["iam:GetRole"], ["*"]),
                _policy_statement(["secretsmanager:GetSecretValue", "kms:Decrypt"], ["*"]),
                _policy_statement(["ec2:AuthorizeSecurityGroupIngress"], ["*"]),
                _policy_statement(["cloudtrail:StopLogging"], ["*"]),
            ]
        )

        posture = build_aws_privileged_access_posture(role)

        self.assertTrue(posture.has_privileged_grants)
        categories = [grant.privilege_categories for grant in posture.grants]
        self.assertIn((PrivilegeCategory.FULL_ADMIN,), categories)
        self.assertIn((PrivilegeCategory.PRIVILEGE_ESCALATION,), categories)
        self.assertIn((PrivilegeCategory.SECRETS_ADMIN, PrivilegeCategory.KEY_ADMIN), categories)
        self.assertIn((PrivilegeCategory.NETWORK_ADMIN,), categories)
        self.assertIn((PrivilegeCategory.AUDIT_ADMIN,), categories)
        evidence = {item for grant in posture.grants for item in grant.evidence}
        self.assertNotIn("action=iam:GetRole", evidence)
        self.assertNotIn("action=s3:GetObject", evidence)

        full_admin = posture.grants[0]
        self.assertEqual(full_admin.provider, "aws")
        self.assertEqual(full_admin.principal.principal_type, PrincipalType.ROLE)
        self.assertEqual(full_admin.principal.source_address, "aws_iam_role.app")
        self.assertEqual(full_admin.assignment_scope.scope_kind, AssignmentScopeKind.ACCOUNT)
        self.assertEqual(full_admin.assignment_scope.value, "*")
        self.assertEqual(full_admin.confidence, PrivilegeConfidence.HIGH)
        self.assertEqual(full_admin.permission_patterns, ("*",))
        self.assertEqual(full_admin.evidence, ("action=*", "resource=*"))

    def test_scoped_privilege_grant_is_medium_confidence(self) -> None:
        role = _role(
            statements=[
                _policy_statement(
                    ["iam:AttachRolePolicy"],
                    ["arn:aws:iam::111122223333:role/deploy"],
                )
            ]
        )

        posture = build_aws_privileged_access_posture(role)

        self.assertEqual(len(posture.grants), 1)
        grant = posture.grants[0]
        self.assertEqual(
            grant.privilege_categories,
            (PrivilegeCategory.IAM_ADMIN, PrivilegeCategory.ROLE_ASSIGNMENT),
        )
        self.assertEqual(grant.assignment_scope.scope_kind, AssignmentScopeKind.RESOURCE)
        self.assertEqual(grant.assignment_scope.value, "arn:aws:iam::111122223333:role/deploy")
        self.assertEqual(grant.confidence, PrivilegeConfidence.MEDIUM)

    def test_decorator_persists_posture_after_customer_managed_policy_merge(self) -> None:
        role = _resource(
            "aws_iam_role.app",
            "aws_iam_role",
            identifier="app-role",
            arn="arn:aws:iam::111122223333:role/app",
        )
        policy = _resource(
            "aws_iam_policy.admin",
            "aws_iam_policy",
            identifier="admin",
            arn="arn:aws:iam::111122223333:policy/admin",
            policy_statements=[_policy_statement(["iam:AttachRolePolicy", "iam:PassRole"], ["*"])],
        )
        attachment = _resource(
            "aws_iam_role_policy_attachment.app_admin",
            "aws_iam_role_policy_attachment",
            metadata={
                "role": "app-role",
                "policy_arn": "arn:aws:iam::111122223333:policy/admin",
            },
        )

        AwsResourceDecorator().decorate([role, policy, attachment])

        grants = aws_facts(role).privileged_access_grants
        self.assertEqual(len(grants), 1)
        self.assertEqual(
            grants[0].privilege_categories,
            (PrivilegeCategory.IAM_ADMIN, PrivilegeCategory.ROLE_ASSIGNMENT, PrivilegeCategory.PRIVILEGE_ESCALATION),
        )
        self.assertEqual(grants[0].permission_patterns, ("iam:AttachRolePolicy", "iam:PassRole"))
        self.assertIn("privileged_access_grants", role.metadata)
        self.assertEqual(aws_facts(role).iam_assignment_posture_uncertainties, [])

    def test_unresolved_policy_attachment_is_preserved_as_posture_uncertainty(self) -> None:
        role = _resource("aws_iam_role.app", "aws_iam_role", identifier="app-role")
        attachment = _resource(
            "aws_iam_role_policy_attachment.unresolved",
            "aws_iam_role_policy_attachment",
            metadata={
                "role": "app-role",
                "policy_arn": "arn:aws:iam::111122223333:policy/missing",
            },
        )

        AwsResourceDecorator().decorate([role, attachment])

        self.assertEqual(
            aws_facts(role).iam_assignment_posture_uncertainties,
            ["arn:aws:iam::111122223333:policy/missing"],
        )
        self.assertEqual(
            aws_facts(role).privileged_access_posture.unresolved_assignments,
            ("arn:aws:iam::111122223333:policy/missing",),
        )


if __name__ == "__main__":
    unittest.main()
