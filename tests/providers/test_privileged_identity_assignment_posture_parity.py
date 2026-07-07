from __future__ import annotations

import unittest

from tests.providers.aws.test_aws_iam_assignment_rules import _attachment as _aws_attachment
from tests.providers.aws.test_aws_iam_assignment_rules import _policy as _aws_policy
from tests.providers.aws.test_aws_iam_assignment_rules import _role as _aws_role
from tests.providers.azure.test_azure_iam_assignment_rules import _role_assignment as _azure_role_assignment
from tests.providers.azure.test_azure_iam_assignment_rules import _storage_account as _azure_storage_account
from tests.providers.gcp.rule_support.data import _secret_manager_secret_iam_member as _gcp_secret_iam_member
from tfstride.analysis.rule_registry import RulePolicy
from tfstride.analysis.stride_rules import StrideRuleEngine
from tfstride.models import TerraformResource
from tfstride.providers.aws.normalizer import AwsNormalizer
from tfstride.providers.aws.rules import AWS_RULE_GROUP_IDS
from tfstride.providers.azure.normalizer import AzureNormalizer
from tfstride.providers.azure.rules import AZURE_RULE_GROUP_IDS
from tfstride.providers.gcp.normalizer import GcpNormalizer
from tfstride.providers.gcp.rules import GCP_RULE_GROUP_IDS

AWS_PRIVILEGED_ASSIGNMENT_RULE_IDS = frozenset({"aws-iam-privileged-role-assignment"})
GCP_PRIVILEGED_ASSIGNMENT_RULE_IDS = frozenset({"gcp-iam-privileged-assignment"})
AZURE_PRIVILEGED_ASSIGNMENT_RULE_IDS = frozenset({"azure-rbac-privileged-assignment"})
ALL_PRIVILEGED_ASSIGNMENT_RULE_IDS = (
    AWS_PRIVILEGED_ASSIGNMENT_RULE_IDS | GCP_PRIVILEGED_ASSIGNMENT_RULE_IDS | AZURE_PRIVILEGED_ASSIGNMENT_RULE_IDS
)


def _flatten(rule_groups: tuple[tuple[str, ...], ...]) -> frozenset[str]:
    return frozenset(rule_id for rule_group in rule_groups for rule_id in rule_group)


def _finding_ids(findings) -> frozenset[str]:
    return frozenset(finding.rule_id for finding in findings)


def _evidence_by_key(finding) -> dict[str, list[str]]:
    return {item.key: item.values for item in finding.evidence}


def _evaluate_aws(resources: list[TerraformResource], rule_ids=ALL_PRIVILEGED_ASSIGNMENT_RULE_IDS):
    return StrideRuleEngine().evaluate(
        AwsNormalizer().normalize(resources),
        [],
        rule_policy=RulePolicy(enabled_rule_ids=frozenset(rule_ids)),
    )


def _evaluate_gcp(resources: list[TerraformResource], rule_ids=ALL_PRIVILEGED_ASSIGNMENT_RULE_IDS):
    return StrideRuleEngine().evaluate(
        GcpNormalizer().normalize(resources),
        [],
        rule_policy=RulePolicy(enabled_rule_ids=frozenset(rule_ids)),
    )


def _evaluate_azure(resources: list[TerraformResource], rule_ids=ALL_PRIVILEGED_ASSIGNMENT_RULE_IDS):
    return StrideRuleEngine().evaluate(
        AzureNormalizer().normalize(resources),
        [],
        rule_policy=RulePolicy(enabled_rule_ids=frozenset(rule_ids)),
    )


class PrivilegedIdentityAssignmentPostureParityTests(unittest.TestCase):
    def test_provider_privileged_assignment_rule_families_are_registered(self) -> None:
        self.assertLessEqual(AWS_PRIVILEGED_ASSIGNMENT_RULE_IDS, _flatten(AWS_RULE_GROUP_IDS))
        self.assertLessEqual(GCP_PRIVILEGED_ASSIGNMENT_RULE_IDS, _flatten(GCP_RULE_GROUP_IDS))
        self.assertLessEqual(AZURE_PRIVILEGED_ASSIGNMENT_RULE_IDS, _flatten(AZURE_RULE_GROUP_IDS))

    def test_privileged_identity_assignment_findings_are_pinned_by_provider(self) -> None:
        aws_findings = _evaluate_aws(
            [
                _aws_role(),
                _aws_policy(["iam:AttachRolePolicy", "iam:PassRole"]),
                _aws_attachment(),
            ]
        )
        gcp_findings = _evaluate_gcp(
            [
                _gcp_secret_iam_member(
                    member="serviceAccount:deploy@example.iam.gserviceaccount.com",
                    role="roles/secretmanager.admin",
                )
            ]
        )
        azure_findings = _evaluate_azure([_azure_role_assignment()])

        self.assertEqual(_finding_ids(aws_findings), AWS_PRIVILEGED_ASSIGNMENT_RULE_IDS)
        self.assertEqual(_finding_ids(gcp_findings), GCP_PRIVILEGED_ASSIGNMENT_RULE_IDS)
        self.assertEqual(_finding_ids(azure_findings), AZURE_PRIVILEGED_ASSIGNMENT_RULE_IDS)
        self.assertEqual(
            _evidence_by_key(aws_findings[0])["privilege_categories"],
            ["iam-admin", "privilege-escalation", "role-assignment"],
        )
        self.assertEqual(_evidence_by_key(gcp_findings[0])["privilege_categories"], ["secrets-admin"])
        self.assertEqual(
            _evidence_by_key(azure_findings[0])["privilege_categories"],
            ["full-admin", "iam-admin", "policy-admin"],
        )

    def test_provider_specific_data_or_sensitive_scope_assignments_are_pinned(self) -> None:
        aws_findings = _evaluate_aws(
            [
                _aws_role(),
                _aws_policy(["secretsmanager:GetSecretValue", "kms:Decrypt"]),
                _aws_attachment(),
            ]
        )
        gcp_findings = _evaluate_gcp(
            [
                _gcp_secret_iam_member(
                    member="serviceAccount:deploy@example.iam.gserviceaccount.com",
                    role="roles/secretmanager.admin",
                )
            ]
        )
        azure_findings = _evaluate_azure(
            [
                _azure_storage_account(),
                _azure_role_assignment(
                    role_definition_name="Storage Blob Data Owner",
                    role_definition_id=(
                        "/subscriptions/sub-0001/providers/Microsoft.Authorization/roleDefinitions/storage-blob-owner"
                    ),
                    scope="azurerm_storage_account.logs.id",
                ),
            ]
        )

        self.assertEqual(_finding_ids(aws_findings), AWS_PRIVILEGED_ASSIGNMENT_RULE_IDS)
        self.assertEqual(_finding_ids(gcp_findings), GCP_PRIVILEGED_ASSIGNMENT_RULE_IDS)
        self.assertEqual(_finding_ids(azure_findings), AZURE_PRIVILEGED_ASSIGNMENT_RULE_IDS)
        self.assertEqual(
            _evidence_by_key(aws_findings[0])["privilege_categories"],
            ["key-admin", "secrets-admin"],
        )
        self.assertEqual(_evidence_by_key(gcp_findings[0])["privilege_categories"], ["secrets-admin"])
        self.assertEqual(_evidence_by_key(azure_findings[0])["privilege_categories"], ["data-admin"])

    def test_non_privileged_assignment_posture_stays_quiet_across_providers(self) -> None:
        aws_findings = _evaluate_aws(
            [
                _aws_role(),
                _aws_policy(["iam:GetRole", "s3:GetObject"], resources=["arn:aws:s3:::logs/*"]),
                _aws_attachment(),
            ]
        )
        gcp_findings = _evaluate_gcp([_gcp_secret_iam_member()])
        azure_findings = _evaluate_azure(
            [
                _azure_role_assignment(
                    role_definition_name="Reader",
                    role_definition_id="/subscriptions/sub-0001/providers/Microsoft.Authorization/roleDefinitions/reader",
                )
            ]
        )

        self.assertEqual(aws_findings, [])
        self.assertEqual(gcp_findings, [])
        self.assertEqual(azure_findings, [])

    def test_privileged_assignment_rules_remain_provider_local(self) -> None:
        findings_by_provider = {
            "aws": _evaluate_aws(
                [_aws_role(inline_policy={"Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]})]
            ),
            "gcp": _evaluate_gcp([_gcp_secret_iam_member(role="roles/secretmanager.admin")]),
            "azure": _evaluate_azure([_azure_role_assignment()]),
        }

        for provider, findings in findings_by_provider.items():
            with self.subTest(provider=provider):
                self.assertTrue(findings)
                self.assertTrue(all(finding.rule_id.startswith(f"{provider}-") for finding in findings))


if __name__ == "__main__":
    unittest.main()
